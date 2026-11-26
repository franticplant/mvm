package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
)

// Rule allows GET and HEAD on one host for exact paths or path prefixes. With Scope set,
// every `scope` query value must equal it (at least one): registry token endpoints.
type Rule struct {
	Host   string   `json:"host"`
	Exact  []string `json:"exact"`
	Prefix []string `json:"prefix"`
	Scope  string   `json:"scope"`
}

// Policy is the per-run request policy. Hosts are the names the ephemeral CA may sign
// (its name constraints): the run's egress allowlist.
type Policy struct {
	Rules     []Rule   `json:"rules"`
	Redirects bool     `json:"redirects"` // pin the exact host+path of 3xx Location targets
	Hosts     []string `json:"hosts"`

	mu     sync.Mutex
	pinned map[string]bool // "host" + "\x00" + path
}

func loadPolicy(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Policy
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	for i, r := range p.Rules {
		if r.Host == "" {
			return nil, fmt.Errorf("rule %d: no host", i)
		}
		for _, x := range append(append([]string{}, r.Exact...), r.Prefix...) {
			if !strings.HasPrefix(x, "/") {
				return nil, fmt.Errorf("rule %d: path %q must start with /", i, x)
			}
		}
		p.Rules[i].Host = strings.ToLower(r.Host)
	}
	p.pinned = map[string]bool{}
	return &p, nil
}

// cleanPath refuses paths a server might read differently from us: escapes (%2f, %2e),
// dot segments, empty segments, and anything not starting with /.
func cleanPath(u *url.URL) (string, error) {
	if u.RawPath != "" || u.Opaque != "" {
		return "", fmt.Errorf("escaped path")
	}
	p := u.Path
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "//") || strings.Contains(p, "\\") {
		return "", fmt.Errorf("unusual path")
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return "", fmt.Errorf("dot segment")
		}
	}
	if strings.ContainsAny(p, "\x00\r\n") {
		return "", fmt.Errorf("control character")
	}
	return p, nil
}

// Check decides one request inside a tunnel to host.
func (p *Policy) Check(method, host string, u *url.URL) (bool, string) {
	if method != "GET" && method != "HEAD" {
		return false, "method " + method + " (GET and HEAD only)"
	}
	path, err := cleanPath(u)
	if err != nil {
		return false, err.Error()
	}
	host = strings.ToLower(host)
	for _, r := range p.Rules {
		if r.Host != host || !matchPath(r, path) {
			continue
		}
		if r.Scope != "" {
			scopes := u.Query()["scope"]
			if len(scopes) == 0 {
				return false, "token request without a scope"
			}
			for _, s := range scopes {
				if s != r.Scope {
					return false, "token scope " + s + " (allowed: " + r.Scope + ")"
				}
			}
		}
		return true, "rule"
	}
	p.mu.Lock()
	ok := p.pinned[host+"\x00"+path]
	p.mu.Unlock()
	if ok {
		return true, "redirect"
	}
	return false, "no rule for " + host + path
}

func matchPath(r Rule, path string) bool {
	for _, e := range r.Exact {
		if path == e {
			return true
		}
	}
	for _, pre := range r.Prefix {
		if strings.HasPrefix(path, pre) {
			return true
		}
	}
	return false
}

// Pin records a redirect target (https only) so a later GET to exactly it is allowed.
func (p *Policy) Pin(base *url.URL, location string) (string, bool) {
	if !p.Redirects {
		return "", false
	}
	loc, err := url.Parse(location)
	if err != nil {
		return "", false
	}
	t := base.ResolveReference(loc)
	if t.Scheme != "https" || t.User != nil || (t.Port() != "" && t.Port() != "443") {
		return "", false
	}
	path, err := cleanPath(t)
	if err != nil {
		return "", false
	}
	h := strings.ToLower(t.Hostname())
	p.mu.Lock()
	p.pinned[h+"\x00"+path] = true
	p.mu.Unlock()
	return h + path, true
}
