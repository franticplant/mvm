package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func pol(t *testing.T) *Policy {
	t.Helper()
	return &Policy{Redirects: true, Hosts: []string{"registry.test", "auth.test", "cdn.test"},
		pinned: map[string]bool{}, Rules: []Rule{
			{Host: "registry.test", Exact: []string{"/v2/"}, Prefix: []string{"/v2/library/busybox/"}},
			{Host: "auth.test", Exact: []string{"/token"}, Scope: "repository:library/busybox:pull"},
		}}
}

func u(s string) *url.URL {
	x, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return x
}

func TestPolicy(t *testing.T) {
	p := pol(t)
	cases := []struct {
		method, host, url string
		ok                bool
	}{
		{"GET", "registry.test", "/v2/", true},
		{"HEAD", "registry.test", "/v2/library/busybox/manifests/1.37", true},
		{"GET", "REGISTRY.test", "/v2/library/busybox/blobs/sha256:ab", true},
		{"POST", "registry.test", "/v2/library/busybox/blobs/uploads/", false},
		{"PUT", "registry.test", "/v2/library/busybox/manifests/x", false},
		{"GET", "registry.test", "/v2/library/other/manifests/x", false},
		{"GET", "registry.test", "/v2/library/busybox", false},
		{"GET", "registry.test", "/v2/library/busybox/../other/manifests/x", false},
		{"GET", "registry.test", "/v2/library/busybox/%2e%2e/other", false},
		{"GET", "registry.test", "/v2/library/busybox//x", false},
		{"GET", "registry.test", "/v2", false},
		{"GET", "auth.test", "/token?scope=repository:library/busybox:pull&service=x", true},
		{"GET", "auth.test", "/token?scope=repository:library/other:pull", false},
		{"GET", "auth.test", "/token?scope=repository:library/busybox:pull&scope=repository:x:push", false},
		{"GET", "auth.test", "/token", false},
		{"GET", "cdn.test", "/blob/abc", false},
	}
	for _, c := range cases {
		ok, why := p.Check(c.method, c.host, u(c.url))
		if ok != c.ok {
			t.Errorf("%s %s%s: got %v (%s), want %v", c.method, c.host, c.url, ok, why, c.ok)
		}
	}
	if _, ok := p.Pin(u("https://registry.test/v2/library/busybox/blobs/x"), "https://cdn.test/blob/abc?sig=1"); !ok {
		t.Fatal("redirect not pinned")
	}
	if ok, _ := p.Check("GET", "cdn.test", u("/blob/abc?sig=other")); !ok {
		t.Error("pinned redirect path not allowed")
	}
	if ok, _ := p.Check("GET", "cdn.test", u("/blob/abd")); ok {
		t.Error("an unpinned CDN path was allowed")
	}
	if ok, _ := p.Check("POST", "cdn.test", u("/blob/abc")); ok {
		t.Error("POST to a pinned path was allowed")
	}
	for _, bad := range []string{"http://cdn.test/plain", "https://cdn.test:8443/p", "https://u@cdn.test/p"} {
		if _, ok := p.Pin(u("https://registry.test/v2/"), bad); ok {
			t.Errorf("pinned %s", bad)
		}
	}
	if pin, ok := p.Pin(u("https://registry.test/v2/library/busybox/blobs/x"), "/v2/rel/target"); !ok || pin != "registry.test/v2/rel/target" {
		t.Errorf("relative redirect: %q %v", pin, ok)
	}
	if _, ok := p.Pin(u("https://registry.test/v2/"), "https://evil.example/x"); ok {
		t.Error("pinned a host outside the allowlist")
	}
	full := pol(t)
	for i := 0; i < MaxPins+5; i++ {
		full.Pin(u("https://registry.test/v2/"), "https://cdn.test/b/"+strings.Repeat("x", 1)+string(rune('a'+i%26))+"/"+itoa(i))
	}
	if len(full.pinned) != MaxPins {
		t.Errorf("pins not capped: %d", len(full.pinned))
	}
	if !p.HostAllowed("CDN.test.") || p.HostAllowed("evil.example") {
		t.Error("HostAllowed")
	}
	off := pol(t)
	off.Redirects = false
	if _, ok := off.Pin(u("https://registry.test/"), "https://cdn.test/x"); ok {
		t.Error("pinned with redirects off")
	}
}

// upstream: one TLS server answering for registry.test, auth.test and cdn.test.
func upstream(t *testing.T) (*x509.CertPool, string, *[]string) {
	t.Helper()
	ca, err := newCA([]string{"registry.test", "auth.test", "cdn.test"})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	seen := []string{}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return ca.leaf(h.ServerName)
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.Host+r.URL.Path)
		mu.Unlock()
		switch {
		case r.Host == "registry.test" && strings.HasSuffix(r.URL.Path, "/blobs/sha256:aa"):
			http.Redirect(w, r, "https://cdn.test/blobs/aa?sig=1", http.StatusTemporaryRedirect)
		default:
			io.WriteString(w, "ok "+r.Host+r.URL.Path)
		}
	}))
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return pool, ln.Addr().String(), &seen
}

func start(t *testing.T) (*http.Client, *Proxy, *bytes.Buffer, *[]string) {
	t.Helper()
	roots, addr, seen := upstream(t)
	p := pol(t)
	ca, err := newCA(p.Hosts)
	if err != nil {
		t.Fatal(err)
	}
	px := newProxy(p, ca, roots, "")
	px.transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr) // every host is the test server
	}
	logs := &bytes.Buffer{}
	px.out = logs
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go px.handle(c)
		}
	}()
	trust := x509.NewCertPool()
	trust.AddCert(ca.cert)
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: ln.Addr().String()}),
		TLSClientConfig: &tls.Config{RootCAs: trust},
	}}
	return client, px, logs, seen
}

func status(t *testing.T, c *http.Client, method, target string) int {
	t.Helper()
	req, _ := http.NewRequest(method, target, nil)
	resp, err := c.Do(req)
	if err != nil {
		return -1
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func itoa(i int) string {
	const d = "0123456789"
	if i < 10 {
		return d[i : i+1]
	}
	return itoa(i/10) + d[i%10:i%10+1]
}

func TestEndToEnd(t *testing.T) {
	c, _, logs, seen := start(t)
	if s := status(t, c, "GET", "https://registry.test/v2/"); s != 200 {
		t.Fatalf("GET /v2/: %d\n%s", s, logs)
	}
	if s := status(t, c, "GET", "https://auth.test/token?scope=repository:library/busybox:pull"); s != 200 {
		t.Errorf("token: %d", s)
	}
	// the registry redirects the blob; the client follows to the exact pinned CDN URL
	if s := status(t, c, "GET", "https://registry.test/v2/library/busybox/blobs/sha256:aa"); s != 200 {
		t.Errorf("redirected blob: %d\n%s", s, logs)
	}
	for _, x := range []struct{ method, url string }{
		{"POST", "https://registry.test/v2/library/busybox/blobs/uploads/"},
		{"GET", "https://registry.test/v2/library/other/manifests/1"},
		{"GET", "https://cdn.test/blobs/bb"},
		{"GET", "https://auth.test/token?scope=repository:library/other:pull"},
	} {
		if s := status(t, c, x.method, x.url); s != 403 {
			t.Errorf("%s %s: %d, want 403", x.method, x.url, s)
		}
	}
	for _, s := range *seen {
		if strings.HasPrefix(s, "POST") || strings.Contains(s, "other") || strings.Contains(s, "/bb") {
			t.Errorf("a denied request reached upstream: %s", s)
		}
	}
	if !strings.Contains(logs.String(), `"pinned":"cdn.test/blobs/aa"`) || !strings.Contains(logs.String(), `"allow":false`) {
		t.Errorf("log lacks the pin or the denials:\n%s", logs)
	}
}

func TestTunnelIdentity(t *testing.T) {
	_, px, logs, _ := start(t)
	_ = px
	// SNI other than the CONNECT host: the handshake fails, nothing is served.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			px.handle(c)
		}
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(raw, "CONNECT registry.test:443 HTTP/1.1\r\nHost: registry.test:443\r\n\r\n")
	buf := make([]byte, 64)
	n, _ := raw.Read(buf)
	if !strings.Contains(string(buf[:n]), "200") {
		t.Fatalf("CONNECT: %q", buf[:n])
	}
	tc := tls.Client(raw, &tls.Config{ServerName: "cdn.test", InsecureSkipVerify: true}) // test only
	if err := tc.Handshake(); err == nil {
		t.Error("handshake with an SNI other than the CONNECT host succeeded")
	}
	raw.Close()
	// Host header other than the tunnel host.
	var w bytes.Buffer
	r, _ := http.NewRequest("GET", "/v2/", nil)
	r.Host = "cdn.test"
	if px.serve(&w, "registry.test", r) || !strings.Contains(w.String(), "403") {
		t.Errorf("Host mismatch served: %q", w.String())
	}
	// A plain-HTTP proxy request (no tunnel) and CONNECT to port 80 are refused.
	for _, line := range []string{"GET http://registry.test/v2/ HTTP/1.1\r\nHost: registry.test\r\n\r\n",
		"CONNECT registry.test:80 HTTP/1.1\r\nHost: registry.test:80\r\n\r\n",
		"CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n"} {
		a, b := net.Pipe()
		go px.handle(b)
		go io.WriteString(a, line)
		out, _ := io.ReadAll(a)
		if !strings.Contains(string(out), "403") {
			t.Errorf("%q: %q", line, out)
		}
	}
	if !strings.Contains(logs.String(), "SNI") {
		t.Errorf("no SNI denial logged:\n%s", logs)
	}
}

func TestCANameConstraints(t *testing.T) {
	ca, err := newCA([]string{"registry.test"})
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	for host, want := range map[string]bool{"registry.test": true, "evil.example": false} {
		lc, err := ca.leaf(host)
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := x509.ParseCertificate(lc.Certificate[0])
		_, err = cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: host})
		if (err == nil) != want {
			t.Errorf("%s: verify err=%v, want ok=%v", host, err, want)
		}
	}
	if _, err := newCA(nil); err == nil {
		t.Error("a CA without name constraints was made")
	}
}
