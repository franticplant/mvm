// l7proxy: mvm's request-level egress policy for image pulls (stdlib only).
//
// It accepts CONNECT host:443 from the microVM, terminates TLS with a leaf signed by an
// ephemeral ECDSA P-256 CA created in memory for this run (the private key is never
// written anywhere; only the CA certificate is, for the guest to trust), and checks
// every request: GET/HEAD only, SNI == Host == the CONNECT host, the path against the
// run's rules, and redirect targets pinned to the exact host+path the registry named.
// Allowed requests go upstream through Smokescreen (CONNECT) with Go's crypto/tls
// verifying the real server against the host CA bundle.
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type CA struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	PEM   []byte
	mu    sync.Mutex
	leafs map[string]*tls.Certificate
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n
}

// newCA makes the run's CA, name-constrained to the given hosts.
func newCA(hosts []string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	var permitted []string
	for _, h := range hosts {
		permitted = append(permitted, strings.TrimPrefix(strings.ToLower(h), "*."))
	}
	if len(permitted) == 0 {
		return nil, errors.New("no hosts for the CA's name constraints")
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:                serial(),
		Subject:                     pkix.Name{CommonName: "mvm ephemeral pull CA"},
		NotBefore:                   now.Add(-time.Minute),
		NotAfter:                    now.Add(24 * time.Hour),
		IsCA:                        true,
		BasicConstraintsValid:       true,
		MaxPathLenZero:              true,
		KeyUsage:                    x509.KeyUsageCertSign,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         permitted,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, leafs: map[string]*tls.Certificate{},
		PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}

func (ca *CA) leaf(host string) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if c, ok := ca.leafs[host]; ok {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	ca.leafs[host] = c
	return c, nil
}

type Proxy struct {
	policy    *Policy
	ca        *CA
	transport *http.Transport
	logMu     sync.Mutex
	out       io.Writer
}

func newProxy(policy *Policy, ca *CA, roots *x509.CertPool, upstream string) *Proxy {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   false,
		DisableCompression:  true, // pass the client's Accept-Encoding through unchanged
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 20 * time.Second,
	}
	if upstream != "" {
		tr.Proxy = http.ProxyURL(&url.URL{Scheme: "http", Host: upstream})
	}
	return &Proxy{policy: policy, ca: ca, transport: tr, out: os.Stdout}
}

func (px *Proxy) log(fields map[string]any) {
	px.logMu.Lock()
	defer px.logMu.Unlock()
	b, _ := json.Marshal(fields)
	fmt.Fprintln(px.out, string(b))
}

func deny(w io.Writer, why string) {
	body := "mvm l7proxy: denied: " + why + "\n"
	fmt.Fprintf(w, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

var hopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authorization",
	"Proxy-Authenticate", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func (px *Proxy) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		px.log(map[string]any{"msg": "L7", "allow": false, "method": req.Method, "host": req.Host, "reason": "not a CONNECT tunnel"})
		deny(c, "only CONNECT tunnels")
		return
	}
	host, port, err := net.SplitHostPort(req.Host)
	host = strings.ToLower(host)
	if err != nil || port != "443" || host == "" {
		px.log(map[string]any{"msg": "L7", "allow": false, "method": "CONNECT", "host": req.Host, "reason": "CONNECT to a port other than 443"})
		deny(c, "CONNECT host:443 only")
		return
	}
	if !px.policy.HostAllowed(host) { // before any leaf is minted for it
		px.log(map[string]any{"msg": "L7", "allow": false, "method": "CONNECT", "host": host, "reason": "host not in the allowlist"})
		deny(c, "host not in the allowlist")
		return
	}
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if !strings.EqualFold(h.ServerName, host) {
				return nil, fmt.Errorf("SNI %q is not the CONNECT host %q", h.ServerName, host)
			}
			return px.ca.leaf(host)
		},
	}
	tc := tls.Server(&bufConn{c, br}, cfg)
	if err := tc.Handshake(); err != nil {
		px.log(map[string]any{"msg": "L7", "allow": false, "method": "CONNECT", "host": host, "reason": "TLS: " + err.Error()})
		return
	}
	tbr := bufio.NewReader(tc)
	for {
		_ = c.SetDeadline(time.Now().Add(120 * time.Second))
		r, err := http.ReadRequest(tbr)
		if err != nil {
			return
		}
		if !px.serve(tc, host, r) {
			return
		}
	}
}

// serve handles one request in the tunnel; false closes the connection.
func (px *Proxy) serve(w io.Writer, host string, r *http.Request) bool {
	entry := map[string]any{"msg": "L7", "host": host, "method": r.Method, "path": r.URL.Path}
	reqHost := strings.ToLower(r.Host)
	if h, p, err := net.SplitHostPort(reqHost); err == nil && p == "443" {
		reqHost = h
	}
	why := ""
	switch {
	case reqHost != host:
		why = "Host " + r.Host + " is not the tunnel host " + host
	case r.ContentLength > 0 || len(r.TransferEncoding) > 0:
		why = "request with a body"
	case r.URL.IsAbs() && !strings.EqualFold(r.URL.Hostname(), host):
		why = "absolute URL to another host"
	}
	if why == "" {
		if ok, reason := px.policy.Check(r.Method, host, r.URL); !ok {
			why = reason
		}
	}
	if why != "" {
		entry["allow"], entry["reason"] = false, why
		px.log(entry)
		deny(w, why)
		return false
	}
	out := r.Clone(context.Background())
	out.URL = &url.URL{Scheme: "https", Host: host, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	out.RequestURI, out.Host = "", host
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}
	resp, err := px.transport.RoundTrip(out)
	if err != nil {
		entry["allow"], entry["reason"], entry["status"] = true, "upstream: "+err.Error(), 502
		px.log(entry)
		msg := "upstream error\n"
		fmt.Fprintf(w, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(msg), msg)
		return false
	}
	defer resp.Body.Close()
	entry["allow"], entry["status"] = true, resp.StatusCode
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc := resp.Header.Get("Location"); loc != "" {
			if pin, ok := px.policy.Pin(out.URL, loc); ok {
				entry["pinned"] = pin
			}
		}
	}
	px.log(entry)
	for _, h := range hopHeaders {
		if h != "Transfer-Encoding" {
			resp.Header.Del(h)
		}
	}
	if err := resp.Write(w); err != nil {
		return false
	}
	return !resp.Close && !r.Close
}

func main() {
	listen := flag.String("listen", "0.0.0.0:4751", "address to accept CONNECT on")
	upstream := flag.String("upstream", "127.0.0.1:4750", "Smokescreen (host:port); empty dials directly (tests)")
	rules := flag.String("rules", "", "policy JSON")
	rootsPath := flag.String("roots", "", "CA bundle for upstream servers (PEM)")
	caOut := flag.String("ca-out", "", "where to write the ephemeral CA certificate (PEM)")
	flag.Parse()
	fail := func(err error) {
		fmt.Fprintln(os.Stderr, "l7proxy:", err)
		os.Exit(1)
	}
	policy, err := loadPolicy(*rules)
	if err != nil {
		fail(err)
	}
	pemRoots, err := os.ReadFile(*rootsPath)
	if err != nil {
		fail(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemRoots) {
		fail(errors.New("no certificates in " + *rootsPath))
	}
	ca, err := newCA(policy.Hosts)
	if err != nil {
		fail(err)
	}
	if *caOut == "" {
		fail(errors.New("-ca-out is required"))
	}
	tmp := *caOut + ".tmp"
	if err := os.WriteFile(tmp, ca.PEM, 0o644); err != nil {
		fail(err)
	}
	if err := os.Rename(tmp, *caOut); err != nil {
		fail(err)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fail(err)
	}
	px := newProxy(policy, ca, roots, *upstream)
	px.log(map[string]any{"msg": "L7-READY", "listen": *listen})
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go px.handle(c)
	}
}
