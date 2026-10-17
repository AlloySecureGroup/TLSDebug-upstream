package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func resetTokenExport(t *testing.T) {
	t.Helper()
	tokenExportMutex.Lock()
	defer tokenExportMutex.Unlock()
	exportDir = t.TempDir()
	tokenExport = &TokenExport{
		JWTTokens:   make([]JWTToken, 0),
		OAuthTokens: make([]OAuthToken, 0),
		Cookies:     make([]EditThisCookieExport, 0),
	}
	nextCookieID = 1
}

func testJWT(payload string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return header + "." + body + ".sig"
}

func responseWithCookies(raw ...string) *http.Response {
	header := make(http.Header)
	for _, cookie := range raw {
		header.Add("Set-Cookie", cookie)
	}
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/api/session", nil)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     header,
		Request:    req,
		Body:       io.NopCloser(bytes.NewReader(nil)),
	}
}

func TestExtractJWTFromCompactJSON(t *testing.T) {
	raw := testJWT(`{"sub":"user-1","exp":1893456000}`)
	body := `{"access_token":"` + raw + `","token_type":"bearer"}`
	tokens := extractJWTFromString(body, "test", "https://example.com/token")
	if len(tokens) != 1 {
		t.Fatalf("expected 1 JWT, got %d", len(tokens))
	}
	if tokens[0].Subject != "user-1" {
		t.Fatalf("subject = %q", tokens[0].Subject)
	}
	if tokens[0].Expiry == nil || tokens[0].Expiry.Unix() != 1893456000 {
		t.Fatalf("expiry = %v", tokens[0].Expiry)
	}
}

func TestBearerTokenCaseInsensitive(t *testing.T) {
	resetTokenExport(t)
	raw := testJWT(`{"sub":"bearer-user"}`)
	req := httptest.NewRequest(http.MethodGet, "https://example.com/me", nil)
	req.Header.Set("Authorization", "bearer "+raw)

	if err := NewTokenExportModule().ProcessRequest(req); err != nil {
		t.Fatal(err)
	}
	tokenExportMutex.Lock()
	defer tokenExportMutex.Unlock()
	if len(tokenExport.JWTTokens) != 1 || tokenExport.JWTTokens[0].Subject != "bearer-user" {
		t.Fatalf("tokens = %+v", tokenExport.JWTTokens)
	}
}

func TestRecordOAuthTokenDecodesEmbeddedJWT(t *testing.T) {
	resetTokenExport(t)
	raw := testJWT(`{"sub":"from-access"}`)
	recordOAuthToken(&OAuthToken{
		AccessToken: raw,
		IDToken:     testJWT(`{"sub":"from-id"}`),
		Source:      "test",
		URL:         "https://example.com/token",
		Timestamp:   time.Now(),
	})

	tokenExportMutex.Lock()
	defer tokenExportMutex.Unlock()
	if len(tokenExport.OAuthTokens) != 1 {
		t.Fatalf("oauth tokens = %d", len(tokenExport.OAuthTokens))
	}
	if len(tokenExport.JWTTokens) != 2 {
		t.Fatalf("jwt tokens = %+v", tokenExport.JWTTokens)
	}
}

func TestExportCookiesMaxAgePathAndDeletion(t *testing.T) {
	resetTokenExport(t)
	exportResponseCookies(responseWithCookies(
		"sid=root; Max-Age=3600; Path=/",
		"sid=api; Max-Age=3600; Path=/api",
		"shared=1; Domain=example.com; Path=/",
	))

	tokenExportMutex.Lock()
	if len(tokenExport.Cookies) != 3 {
		t.Fatalf("cookies = %+v", tokenExport.Cookies)
	}
	var root, domain EditThisCookieExport
	for _, cookie := range tokenExport.Cookies {
		switch {
		case cookie.Name == "sid" && cookie.Path == "/":
			root = cookie
		case cookie.Name == "shared":
			domain = cookie
		}
	}
	tokenExportMutex.Unlock()

	if root.Session {
		t.Fatal("Max-Age cookie exported as a session cookie")
	}
	if root.ExpirationDate < float64(time.Now().Add(59*time.Minute).Unix()) {
		t.Fatalf("expirationDate = %v", root.ExpirationDate)
	}
	if domain.HostOnly || domain.Domain != ".example.com" {
		t.Fatalf("domain cookie = %+v", domain)
	}

	exportResponseCookies(responseWithCookies("sid=root; Max-Age=0; Path=/"))

	tokenExportMutex.Lock()
	defer tokenExportMutex.Unlock()
	for _, cookie := range tokenExport.Cookies {
		if cookie.Name == "sid" && cookie.Path == "/" {
			t.Fatalf("deleted cookie still present: %+v", cookie)
		}
	}
	if len(tokenExport.Cookies) != 2 {
		t.Fatalf("expected remaining cookies, got %+v", tokenExport.Cookies)
	}
}

func TestTokenExportRoundTripPermissionsAndReload(t *testing.T) {
	resetTokenExport(t)
	exportResponseCookies(responseWithCookies("sid=abc; Path=/; HttpOnly"))

	tokensPath := exportFilePath(capturedTokensFile)
	cookiesPath := exportFilePath(cookieExportFile)
	for _, path := range []string{tokensPath, cookiesPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode = %o", path, info.Mode().Perm())
		}
	}

	var exported []EditThisCookieExport
	data, err := os.ReadFile(cookiesPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &exported); err != nil {
		t.Fatal(err)
	}
	if len(exported) != 1 || !exported[0].Session || exported[0].ID == 0 {
		t.Fatalf("cookie export = %+v", exported)
	}

	tokenExportMutex.Lock()
	tokenExport = &TokenExport{
		JWTTokens:   make([]JWTToken, 0),
		OAuthTokens: make([]OAuthToken, 0),
		Cookies:     make([]EditThisCookieExport, 0),
	}
	tokenExportMutex.Unlock()

	loadTokenExport()
	tokenExportMutex.Lock()
	defer tokenExportMutex.Unlock()
	if len(tokenExport.Cookies) != 1 || tokenExport.Cookies[0].Value != "abc" {
		t.Fatalf("reloaded cookies = %+v", tokenExport.Cookies)
	}
}

func TestCompressedResponseKeepsBodyAndStillExportsCookies(t *testing.T) {
	resetTokenExport(t)
	raw := testJWT(`{"sub":"gzip-user"}`)
	payload := []byte(`{"access_token":"` + raw + `"}`)
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), compressed.Bytes()...)

	header := make(http.Header)
	header.Set("Content-Encoding", "gzip")
	header.Set("Content-Type", "application/json")
	header.Add("Set-Cookie", "sid=kept; Path=/")
	req := httptest.NewRequest(http.MethodPost, "https://app.example.com/token", nil)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     header,
		Request:    req,
		Body:       io.NopCloser(bytes.NewReader(original)),
	}

	if err := NewTokenExportModule().ProcessResponse(resp); err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("Content-Encoding = %q", resp.Header.Get("Content-Encoding"))
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("gzip body was rewritten")
	}

	tokenExportMutex.Lock()
	defer tokenExportMutex.Unlock()
	if len(tokenExport.Cookies) != 1 || len(tokenExport.OAuthTokens) != 1 || len(tokenExport.JWTTokens) != 1 {
		t.Fatalf("export = %+v jwt=%+v", tokenExport.OAuthTokens, tokenExport.JWTTokens)
	}
}

func TestBrotliResponseStillExportsCookies(t *testing.T) {
	resetTokenExport(t)
	body := []byte{0x01, 0x02, 0x03}
	header := make(http.Header)
	header.Set("Content-Encoding", "br")
	header.Add("Set-Cookie", "sid=br; Path=/")
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     header,
		Request:    req,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	if err := NewTokenExportModule().ProcessResponse(resp); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("body = %v", got)
	}
	if resp.Header.Get("Content-Encoding") != "br" {
		t.Fatalf("Content-Encoding = %q", resp.Header.Get("Content-Encoding"))
	}
	tokenExportMutex.Lock()
	defer tokenExportMutex.Unlock()
	if len(tokenExport.Cookies) != 1 || tokenExport.Cookies[0].Value != "br" {
		t.Fatalf("cookies = %+v", tokenExport.Cookies)
	}
}

func TestMonitorCapturesRequestBodyWithoutMutatingGzipResponse(t *testing.T) {
	trafficStore.Clear()
	t.Cleanup(trafficStore.Clear)

	req := httptest.NewRequest(http.MethodPost, "https://example.com/login", strings.NewReader(`{"user":"ada"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:1234"
	monitor := NewMonitoringModule()
	if err := monitor.ProcessRequest(req); err != nil {
		t.Fatal(err)
	}
	restored, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != `{"user":"ada"}` {
		t.Fatalf("request body = %q", restored)
	}

	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	_, _ = gz.Write([]byte(`{"ok":true}`))
	_ = gz.Close()
	original := append([]byte(nil), compressed.Bytes()...)

	header := make(http.Header)
	header.Set("Content-Encoding", "gzip")
	header.Set("Content-Type", "application/json")
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     header,
		Request:    req,
		Body:       io.NopCloser(bytes.NewReader(original)),
	}
	if err := monitor.ProcessResponse(resp); err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("Content-Encoding = %q", resp.Header.Get("Content-Encoding"))
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("monitor rewrote gzip body")
	}

	entries := trafficStore.GetEntries()
	if len(entries) != 1 {
		t.Fatalf("entries = %d", len(entries))
	}
	if entries[0].RequestBody != `{"user":"ada"}` {
		t.Fatalf("request body = %q", entries[0].RequestBody)
	}
	if entries[0].ClientAddr != "127.0.0.1:1234" {
		t.Fatalf("client = %q", entries[0].ClientAddr)
	}
	if !strings.Contains(entries[0].ResponseBody, `"ok":true`) {
		t.Fatalf("response body = %q", entries[0].ResponseBody)
	}
}

func TestOpenProxyLogRestrictsExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.log")
	if err := os.WriteFile(path, []byte("old\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := openProxyLog(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
}
