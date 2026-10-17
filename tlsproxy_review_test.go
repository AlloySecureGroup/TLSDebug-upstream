package main

/*
Tests for the bugs fixed in the review: leaf names on IP addresses, hop-by-hop
headers, the CA private key mode, request-body buffering, the dashboard
duration, the token cap, [server] defaults, and bytes replayed after CONNECT.
*/

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type countingBody struct {
	r     io.Reader
	reads int
}

func (b *countingBody) Read(p []byte) (int, error) {
	b.reads++
	return b.r.Read(p)
}

func (b *countingBody) Close() error { return nil }

func TestLeafNamesSkipWildcardForIP(t *testing.T) {
	prev := certConfig
	t.Cleanup(func() { certConfig = prev })
	certConfig = defaultCertConfig()

	dns, ips := leafNames("192.168.1.1")
	for _, name := range dns {
		if strings.HasPrefix(name, "*.") {
			t.Fatalf("IP host got DNS wildcard %s", name)
		}
	}
	foundIP := false
	for _, ip := range ips {
		if ip.Equal(net.ParseIP("192.168.1.1")) {
			foundIP = true
		}
	}
	if !foundIP {
		t.Fatalf("IP SAN missing: %v", ips)
	}

	dns, _ = leafNames("a.b.example.com")
	if !containsString(dns, "*.b.example.com") {
		t.Fatalf("hostname SANs = %v", dns)
	}
	dns, _ = leafNames("example.com")
	for _, name := range dns {
		if strings.HasPrefix(name, "*.") {
			t.Fatalf("apex host got wildcard %s", name)
		}
	}
}

func TestGenerateCertForHostRequiresCA(t *testing.T) {
	prevCert, prevKey, prevCfg := caCert, caKey, certConfig
	t.Cleanup(func() {
		caCert, caKey, certConfig = prevCert, prevKey, prevCfg
	})
	caCert, caKey = nil, nil
	certConfig = defaultCertConfig()

	if _, err := generateCertForHost("example.com"); err == nil {
		t.Fatal("expected an error when the CA is not loaded")
	}
}

func TestGenerateCAKeyIsOwnerReadOnly(t *testing.T) {
	prevCert, prevKey, prevCfg := caCert, caKey, certConfig
	t.Cleanup(func() {
		caCert, caKey, certConfig = prevCert, prevKey, prevCfg
	})
	certConfig = defaultCertConfig()

	dir := t.TempDir()
	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)
	if err := generateCA(certPath, keyPath, true); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("CA key mode = %o", info.Mode().Perm())
	}
}

func TestStripHopByHopRemovesConnectionAndListedHeaders(t *testing.T) {
	h := make(http.Header)
	h.Set("Connection", "close, X-Foo")
	h.Set("X-Foo", "1")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("Proxy-Connection", "keep-alive")
	h.Set("Proxy-Authorization", "Basic abc")
	h.Set("Proxy-Authenticate", "Basic")
	h.Set("Transfer-Encoding", "chunked")
	h.Set("Upgrade", "websocket")
	h.Set("Te", "trailers")
	h.Set("Trailers", "X-Trail")
	h.Set("Content-Type", "text/plain")
	h.Set("Accept-Encoding", "gzip")

	stripHopByHop(h)

	for _, name := range []string{
		"Connection", "X-Foo", "Keep-Alive", "Proxy-Connection",
		"Proxy-Authorization", "Proxy-Authenticate", "Transfer-Encoding",
		"Upgrade", "Te", "Trailers",
	} {
		if h.Get(name) != "" {
			t.Fatalf("%s was forwarded: %v", name, h)
		}
	}
	if h.Get("Content-Type") != "text/plain" || h.Get("Accept-Encoding") != "gzip" {
		t.Fatalf("end-to-end headers = %v", h)
	}
}

func TestRequestAndResponseBodiesAreReadOnce(t *testing.T) {
	payload := bytes.Repeat([]byte("a"), 2048)
	body := &countingBody{r: bytes.NewReader(payload)}
	req := httptest.NewRequest(http.MethodPost, "https://example.com/form", nil)
	req.Body = body

	first, err := readAndRestoreRequestBody(req)
	if err != nil {
		t.Fatal(err)
	}
	reads := body.reads
	if reads == 0 {
		t.Fatal("request body was not read")
	}
	second, err := readAndRestoreRequestBody(req)
	if err != nil {
		t.Fatal(err)
	}
	if body.reads != reads {
		t.Fatalf("request source read again: %d then %d", reads, body.reads)
	}
	if !bytes.Equal(first, payload) || !bytes.Equal(second, payload) {
		t.Fatal("request buffer mismatch")
	}
	replayed, err := io.ReadAll(req.Body)
	if err != nil || !bytes.Equal(replayed, payload) {
		t.Fatalf("replayed request = %d bytes, err=%v", len(replayed), err)
	}

	respBody := &countingBody{r: bytes.NewReader(payload)}
	resp := &http.Response{Header: make(http.Header), Body: respBody}
	if _, err := readAndRestoreResponseBody(resp); err != nil {
		t.Fatal(err)
	}
	respReads := respBody.reads
	if _, err := readAndRestoreResponseBody(resp); err != nil {
		t.Fatal(err)
	}
	if respBody.reads != respReads {
		t.Fatalf("response source read again: %d then %d", respReads, respBody.reads)
	}
	replayed, err = io.ReadAll(resp.Body)
	if err != nil || !bytes.Equal(replayed, payload) {
		t.Fatalf("replayed response = %d bytes, err=%v", len(replayed), err)
	}
}

func TestMonitorDurationIncludesForwardTime(t *testing.T) {
	trafficStore.Clear()
	t.Cleanup(trafficStore.Clear)

	req := httptest.NewRequest(http.MethodGet, "https://example.com/slow", nil)
	started := time.Now().Add(-200 * time.Millisecond)
	req = req.WithContext(context.WithValue(req.Context(), forwardStartKey{}, started))
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     make(http.Header),
		Request:    req,
		Body:       io.NopCloser(strings.NewReader("ok")),
	}
	if err := NewMonitoringModule().ProcessResponse(resp); err != nil {
		t.Fatal(err)
	}
	entries := trafficStore.GetEntries()
	if len(entries) != 1 {
		t.Fatalf("entries = %d", len(entries))
	}
	if entries[0].Duration < 150*time.Millisecond {
		t.Fatalf("duration = %s", entries[0].Duration)
	}
}

func TestApplyServerFileConfigRespectsExplicitFlags(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxy-config.ini")
	contents := []byte(`
[server]
port = 9090
cert_dir = /tmp/certs
skip_install = true

[ca_certificate]
organization = Example Org
`)
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}

	prev := certConfig
	t.Cleanup(func() { certConfig = prev })

	loaded, server := loadConfig(path)
	if loaded.Organization != "Example Org" {
		t.Fatalf("organization = %q", loaded.Organization)
	}
	if server.port == nil || *server.port != 9090 {
		t.Fatalf("port = %v", server.port)
	}
	if server.certDir == nil || *server.certDir != "/tmp/certs" {
		t.Fatalf("cert dir = %v", server.certDir)
	}
	if server.skipInstall == nil || !*server.skipInstall {
		t.Fatalf("skip install = %v", server.skipInstall)
	}

	cfg := &ProxyConfig{Port: 8080, CertDir: ".", LogFile: filepath.Join(".", logFile), SkipInstall: false}
	applyServerFileConfig(map[string]bool{}, cfg, server)
	if cfg.Port != 9090 || cfg.CertDir != "/tmp/certs" || !cfg.SkipInstall {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
	if cfg.LogFile != filepath.Join("/tmp/certs", logFile) {
		t.Fatalf("log file = %s", cfg.LogFile)
	}

	cfg = &ProxyConfig{Port: 8080, CertDir: ".", LogFile: filepath.Join(".", logFile), SkipInstall: false}
	applyServerFileConfig(map[string]bool{"port": true, "certdir": true, "skip-install": true}, cfg, server)
	if cfg.Port != 8080 || cfg.CertDir != "." || cfg.SkipInstall {
		t.Fatalf("explicit flags were overridden: %+v", cfg)
	}
}

func TestTokenExportDropsOldestPastCap(t *testing.T) {
	resetTokenExport(t)
	for i := 0; i < maxStoredTokens+2; i++ {
		addJWTToken(&JWTToken{
			Raw:     fmt.Sprintf("raw-%d", i),
			Header:  map[string]interface{}{},
			Payload: map[string]interface{}{},
		})
	}
	tokenExportMutex.Lock()
	defer tokenExportMutex.Unlock()
	if len(tokenExport.JWTTokens) != maxStoredTokens {
		t.Fatalf("kept %d tokens", len(tokenExport.JWTTokens))
	}
	if tokenExport.JWTTokens[0].Raw != "raw-2" {
		t.Fatalf("oldest kept = %s", tokenExport.JWTTokens[0].Raw)
	}
	last := tokenExport.JWTTokens[len(tokenExport.JWTTokens)-1].Raw
	wantLast := fmt.Sprintf("raw-%d", maxStoredTokens+1)
	if last != wantLast {
		t.Fatalf("newest = %s", last)
	}
}

func TestPrefixConnReplaysBufferedBytes(t *testing.T) {
	left, right := net.Pipe()
	t.Cleanup(func() {
		left.Close()
		right.Close()
	})
	done := make(chan struct{})
	go func() {
		right.Write([]byte("world"))
		right.Close()
		close(done)
	}()
	pc := &prefixConn{Conn: left, prefix: []byte("hello ")}
	got, err := io.ReadAll(pc)
	<-done
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello world" {
		t.Fatalf("got %q", got)
	}
}
