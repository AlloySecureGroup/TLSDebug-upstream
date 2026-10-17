package main

/*
TLS Intercepting Proxy with Web Monitor - Educational Overview

This proxy acts as a "man-in-the-middle" to inspect HTTPS traffic. Here's how TLS normally works:
1. Client connects to server and they establish an encrypted tunnel using TLS
2. All data is encrypted so nobody in between can read it
3. This is great for security but makes debugging difficult

This proxy solves the debugging problem by:
1. Acting as a fake server to the client (using certificates we generate)
2. Acting as a real client to the actual server
3. Decrypting traffic from client, inspecting it, then re-encrypting to server
4. This only works if the client trusts our Certificate Authority (CA)

NEW: Web-based monitor on port 4040 shows all intercepted traffic in real-time!
NEW: Extracts and logs JWT tokens, OAuth tokens, and session cookies!
Protocol: HTTP/1.1 only (no HTTP/2 support)
*/

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	caCertFile = "proxy-ca.crt"
	caKeyFile  = "proxy-ca.key"
	logFile    = "proxy.log"
)

type ProxyConfig struct {
	Port        int
	CertDir     string
	LogFile     string
	SkipInstall bool
}

type CertConfig struct {
	Organization      string
	CommonName        string
	ValidityYears     int
	AIAURLs           string
	CRLDistPoints     []string
	OCSPServer        string
	DefaultSANs       []string
	HostValidityDays  int
	IncludeAIAInHosts bool
	IncludeCDPInHosts bool
}

func defaultCertConfig() *CertConfig {
	return &CertConfig{
		Organization:      "TLS Proxy CA",
		CommonName:        "TLS Proxy Root CA",
		ValidityYears:     10,
		AIAURLs:           "",
		CRLDistPoints:     []string{},
		OCSPServer:        "",
		DefaultSANs:       []string{"localhost", "127.0.0.1"},
		HostValidityDays:  365,
		IncludeAIAInHosts: false,
		IncludeCDPInHosts: false,
	}
}

type CertCache struct {
	sync.RWMutex
	certs map[string]*tls.Certificate
}

var (
	caCert      *x509.Certificate
	caKey       *rsa.PrivateKey
	certCache   = &CertCache{certs: make(map[string]*tls.Certificate)}
	certConfig  *CertConfig
	logMutex    sync.Mutex
	logWriter   *os.File
	logModules  []LogModule
	verboseMode bool
)

type LogModule interface {
	Name() string
	ShouldLog(req *http.Request) bool
	ProcessRequest(req *http.Request) error
	ProcessResponse(resp *http.Response) error
}

func RegisterModule(module LogModule) {
	logModules = append(logModules, module)
	log.Printf("[MODULE] Registered: %s", module.Name())
}

func executeModules(req *http.Request) bool {
	shouldLog := false
	for _, module := range logModules {
		if module.ShouldLog(req) {
			shouldLog = true
		}
		if err := module.ProcessRequest(req); err != nil {
			log.Printf("[%s] Error processing request: %v", module.Name(), err)
		}
	}
	return shouldLog
}

func executeModulesResponse(resp *http.Response) error {
	for _, module := range logModules {
		if err := module.ProcessResponse(resp); err != nil {
			log.Printf("[%s] Error processing response: %v", module.Name(), err)
		}
	}
	return nil
}

// ============================================================================
// TOKEN STRUCTURES AND EXPORTS
// ============================================================================

type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

type JWTToken struct {
	Raw       string                 `json:"raw"`
	Header    map[string]interface{} `json:"header"`
	Payload   map[string]interface{} `json:"payload"`
	Signature string                 `json:"signature"`
	Source    string                 `json:"source"`
	URL       string                 `json:"url"`
	Timestamp time.Time              `json:"timestamp"`
	Expiry    *time.Time             `json:"expiry,omitempty"`
	IssuedAt  *time.Time             `json:"issuedAt,omitempty"`
	NotBefore *time.Time             `json:"notBefore,omitempty"`
	Issuer    string                 `json:"issuer,omitempty"`
	Subject   string                 `json:"subject,omitempty"`
	Audience  interface{}            `json:"audience,omitempty"`
}

type OAuthToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	ExpiresIn    int       `json:"expires_in,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	Source       string    `json:"source"`
	URL          string    `json:"url"`
	Timestamp    time.Time `json:"timestamp"`
}

type EditThisCookieExport struct {
	Domain         string  `json:"domain"`
	ExpirationDate float64 `json:"expirationDate"`
	HostOnly       bool    `json:"hostOnly"`
	HttpOnly       bool    `json:"httpOnly"`
	Name           string  `json:"name"`
	Path           string  `json:"path"`
	SameSite       string  `json:"sameSite"`
	Secure         bool    `json:"secure"`
	Session        bool    `json:"session"`
	StoreId        string  `json:"storeId"`
	Value          string  `json:"value"`
	ID             int     `json:"id"`
}

type TokenExport struct {
	JWTTokens   []JWTToken             `json:"jwt_tokens"`
	OAuthTokens []OAuthToken           `json:"oauth_tokens"`
	Cookies     []EditThisCookieExport `json:"cookies"`
	LastUpdated time.Time              `json:"last_updated"`
}

const (
	capturedTokensFile = "captured_tokens.json"
	cookieExportFile   = "EditThisCookie_Sessions.json"
)

var (
	tokenExportMutex sync.Mutex
	tokenExport      = &TokenExport{
		JWTTokens:   make([]JWTToken, 0),
		OAuthTokens: make([]OAuthToken, 0),
		Cookies:     make([]EditThisCookieExport, 0),
	}
	// exportDir is the certificate directory, so session files sit next to proxy.log.
	exportDir    = "."
	nextCookieID = 1
)

var jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)

// ============================================================================
// JWT PARSING
// ============================================================================

func parseJWT(tokenString string, source string, requestURL string) *JWTToken {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil
	}

	// Decode header
	headerBytes, err := base64DecodeSegment(parts[0])
	if err != nil {
		return nil
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil
	}

	// Decode payload
	payloadBytes, err := base64DecodeSegment(parts[1])
	if err != nil {
		return nil
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil
	}

	jwt := &JWTToken{
		Raw:       tokenString,
		Header:    header,
		Payload:   payload,
		Signature: parts[2],
		Source:    source,
		URL:       requestURL,
		Timestamp: time.Now(),
	}

	// Extract standard claims
	if exp, ok := payload["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		jwt.Expiry = &expTime
	}
	if iat, ok := payload["iat"].(float64); ok {
		iatTime := time.Unix(int64(iat), 0)
		jwt.IssuedAt = &iatTime
	}
	if nbf, ok := payload["nbf"].(float64); ok {
		nbfTime := time.Unix(int64(nbf), 0)
		jwt.NotBefore = &nbfTime
	}
	if iss, ok := payload["iss"].(string); ok {
		jwt.Issuer = iss
	}
	if sub, ok := payload["sub"].(string); ok {
		jwt.Subject = sub
	}
	if aud, ok := payload["aud"]; ok {
		jwt.Audience = aud
	}

	return jwt
}

func base64DecodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}
	return base64.URLEncoding.DecodeString(seg)
}

// ============================================================================
// TOKEN EXTRACTION
// ============================================================================

func extractJWTFromString(text string, source string, requestURL string) []*JWTToken {
	var tokens []*JWTToken
	seen := make(map[string]struct{})
	for _, match := range jwtPattern.FindAllString(text, -1) {
		if _, ok := seen[match]; ok {
			continue
		}
		seen[match] = struct{}{}
		if jwt := parseJWT(match, source, requestURL); jwt != nil {
			tokens = append(tokens, jwt)
		}
	}
	return tokens
}

func bearerToken(header string) string {
	fields := strings.SplitN(strings.TrimSpace(header), " ", 2)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(fields[1])
}

func tryAddJWT(raw string, source string, requestURL string) {
	raw = strings.TrimSpace(raw)
	if jwt := parseJWT(raw, source, requestURL); jwt != nil {
		addJWTToken(jwt)
	}
}

func recordOAuthToken(token *OAuthToken) {
	if token == nil {
		return
	}
	addOAuthToken(token)
	tryAddJWT(token.AccessToken, token.Source+" (access_token)", token.URL)
	tryAddJWT(token.IDToken, token.Source+" (id_token)", token.URL)
}

func extractOAuthTokensFromJSON(body string, source string, requestURL string) *OAuthToken {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return nil
	}

	token := &OAuthToken{
		Source:    source,
		URL:       requestURL,
		Timestamp: time.Now(),
	}

	hasToken := false

	if at, ok := data["access_token"].(string); ok && at != "" {
		token.AccessToken = at
		hasToken = true
	}
	if rt, ok := data["refresh_token"].(string); ok && rt != "" {
		token.RefreshToken = rt
		hasToken = true
	}
	if tt, ok := data["token_type"].(string); ok {
		token.TokenType = tt
	}
	if exp, ok := data["expires_in"].(float64); ok {
		token.ExpiresIn = int(exp)
	}
	if scope, ok := data["scope"].(string); ok {
		token.Scope = scope
	}
	if idt, ok := data["id_token"].(string); ok && idt != "" {
		token.IDToken = idt
		hasToken = true
	}

	if !hasToken {
		return nil
	}

	return token
}

func extractOAuthTokensFromForm(body string, source string, requestURL string) *OAuthToken {
	values, err := url.ParseQuery(body)
	if err != nil {
		return nil
	}

	token := &OAuthToken{
		Source:    source,
		URL:       requestURL,
		Timestamp: time.Now(),
	}

	hasToken := false

	if at := values.Get("access_token"); at != "" {
		token.AccessToken = at
		hasToken = true
	}
	if rt := values.Get("refresh_token"); rt != "" {
		token.RefreshToken = rt
		hasToken = true
	}
	if tt := values.Get("token_type"); tt != "" {
		token.TokenType = tt
	}
	if exp := values.Get("expires_in"); exp != "" {
		var expInt int
		fmt.Sscanf(exp, "%d", &expInt)
		token.ExpiresIn = expInt
	}
	if scope := values.Get("scope"); scope != "" {
		token.Scope = scope
	}
	if idt := values.Get("id_token"); idt != "" {
		token.IDToken = idt
		hasToken = true
	}

	if !hasToken {
		return nil
	}

	return token
}

// ============================================================================
// TOKEN EXPORT MODULE
// ============================================================================

type TokenExportModule struct{}

func NewTokenExportModule() *TokenExportModule {
	return &TokenExportModule{}
}

func (m *TokenExportModule) Name() string {
	return "TokenExport"
}

func (m *TokenExportModule) ShouldLog(req *http.Request) bool {
	return true
}

func (m *TokenExportModule) ProcessRequest(req *http.Request) error {
	if req == nil {
		return nil
	}

	reqURL := req.URL.String()

	// Extract JWT from Authorization header (scheme is case-insensitive)
	if tokenString := bearerToken(req.Header.Get("Authorization")); tokenString != "" {
		tryAddJWT(tokenString, "Request Authorization Header", reqURL)
	}

	// Extract JWT from cookies
	for _, cookie := range req.Cookies() {
		tryAddJWT(cookie.Value, fmt.Sprintf("Request Cookie: %s", cookie.Name), reqURL)
	}

	// Extract from request body (POST/PUT)
	if req.Body != nil && (req.Method == "POST" || req.Method == "PUT" || req.Method == "PATCH") {
		bodyBytes, err := readAndRestoreRequestBody(req)
		if err == nil && bodyBytes != nil {
			// Try to decompress if gzip encoded
			displayBytes := bodyBytes
			if strings.EqualFold(req.Header.Get("Content-Encoding"), "gzip") && len(bodyBytes) > 0 {
				if decompressed, err := gunzipBytes(bodyBytes); err == nil {
					displayBytes = decompressed
				}
			}

			if !isBinaryContent(displayBytes) {
				bodyStr := string(displayBytes)
				contentType := strings.ToLower(req.Header.Get("Content-Type"))

				// Try JSON OAuth tokens
				if strings.Contains(contentType, "application/json") {
					if token := extractOAuthTokensFromJSON(bodyStr, "Request Body (JSON)", reqURL); token != nil {
						recordOAuthToken(token)
					}
				}

				// Try form-encoded OAuth tokens
				if strings.Contains(contentType, "application/x-www-form-urlencoded") {
					if token := extractOAuthTokensFromForm(bodyStr, "Request Body (Form)", reqURL); token != nil {
						recordOAuthToken(token)
					}
				}

				// Extract JWTs from body text
				jwts := extractJWTFromString(bodyStr, "Request Body", reqURL)
				for _, jwt := range jwts {
					addJWTToken(jwt)
				}
			}
		}
	}

	// Extract from URL parameters
	if req.URL.RawQuery != "" {
		values := req.URL.Query()

		// Check for access_token in URL
		if at := values.Get("access_token"); at != "" {
			token := &OAuthToken{
				AccessToken: at,
				Source:      "URL Parameter",
				URL:         reqURL,
				Timestamp:   time.Now(),
			}
			if rt := values.Get("refresh_token"); rt != "" {
				token.RefreshToken = rt
			}
			if idt := values.Get("id_token"); idt != "" {
				token.IDToken = idt
			}
			recordOAuthToken(token)
		}

		// Check for JWT in URL parameters
		for key, vals := range values {
			for _, value := range vals {
				tryAddJWT(value, fmt.Sprintf("URL Parameter: %s", key), reqURL)
			}
		}
	}

	return nil
}

func (m *TokenExportModule) ProcessResponse(resp *http.Response) error {
	if resp == nil {
		return nil
	}

	// Cookies are independent of whether the body can be decoded.
	exportResponseCookies(resp)

	respURL := ""
	if resp.Request != nil && resp.Request.URL != nil {
		respURL = resp.Request.URL.String()
	}

	if tokenString := bearerToken(resp.Header.Get("Authorization")); tokenString != "" {
		tryAddJWT(tokenString, "Response Authorization Header", respURL)
	}

	for _, cookie := range resp.Cookies() {
		tryAddJWT(cookie.Value, fmt.Sprintf("Response Cookie: %s", cookie.Name), respURL)
	}

	if resp.Body == nil {
		return nil
	}

	// Inspect a copy. The bytes and Content-Encoding forwarded to the client stay intact.
	bodyBytes, err := readAndRestoreResponseBody(resp)
	if err != nil || len(bodyBytes) == 0 {
		return nil
	}

	displayBytes := bodyBytes
	switch strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))) {
	case "gzip":
		decompressed, err := gunzipBytes(bodyBytes)
		if err != nil {
			return nil
		}
		displayBytes = decompressed
	case "br", "zstd", "deflate":
		return nil
	}

	if isBinaryContent(displayBytes) {
		return nil
	}

	bodyStr := string(displayBytes)
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(contentType, "application/json") {
		if token := extractOAuthTokensFromJSON(bodyStr, "Response Body (JSON)", respURL); token != nil {
			recordOAuthToken(token)
		}
	}
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		if token := extractOAuthTokensFromForm(bodyStr, "Response Body (Form)", respURL); token != nil {
			recordOAuthToken(token)
		}
	}

	for _, jwt := range extractJWTFromString(bodyStr, "Response Body", respURL) {
		addJWTToken(jwt)
	}

	return nil
}

func addJWTToken(jwt *JWTToken) {
	if jwt == nil {
		return
	}

	tokenExportMutex.Lock()
	defer tokenExportMutex.Unlock()

	// Check for duplicates
	for _, existing := range tokenExport.JWTTokens {
		if existing.Raw == jwt.Raw {
			return
		}
	}

	tokenExport.JWTTokens = append(tokenExport.JWTTokens, *jwt)
	tokenExport.LastUpdated = time.Now()

	log.Printf("[JWT] Captured JWT from %s", jwt.Source)
	if jwt.Expiry != nil {
		log.Printf("[JWT]   Expires: %s", jwt.Expiry.Format(time.RFC3339))
	}
	if jwt.Subject != "" {
		log.Printf("[JWT]   Subject: %s", jwt.Subject)
	}
	if jwt.Issuer != "" {
		log.Printf("[JWT]   Issuer: %s", jwt.Issuer)
	}

	saveTokenExport()
}

func addOAuthToken(token *OAuthToken) {
	if token == nil {
		return
	}

	tokenExportMutex.Lock()
	defer tokenExportMutex.Unlock()

	// Check for duplicates
	for _, existing := range tokenExport.OAuthTokens {
		if existing.AccessToken == token.AccessToken && existing.RefreshToken == token.RefreshToken && existing.IDToken == token.IDToken {
			return
		}
	}

	tokenExport.OAuthTokens = append(tokenExport.OAuthTokens, *token)
	tokenExport.LastUpdated = time.Now()

	log.Printf("[OAuth] Captured OAuth token from %s", token.Source)
	if token.TokenType != "" {
		log.Printf("[OAuth]   Type: %s", token.TokenType)
	}
	if token.ExpiresIn > 0 {
		log.Printf("[OAuth]   Expires in: %d seconds", token.ExpiresIn)
	}
	if token.Scope != "" {
		log.Printf("[OAuth]   Scope: %s", token.Scope)
	}

	saveTokenExport()
}

func exportFilePath(name string) string {
	return filepath.Join(exportDir, name)
}

func loadTokenExport() {
	tokenExportMutex.Lock()
	defer tokenExportMutex.Unlock()

	path := exportFilePath(capturedTokensFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[EXPORT] ERROR: Failed to read existing tokens: %v", err)
		}
		return
	}

	var loaded TokenExport
	if err := json.Unmarshal(data, &loaded); err != nil {
		log.Printf("[EXPORT] ERROR: Failed to parse existing tokens from %s: %v", path, err)
		return
	}
	if loaded.JWTTokens == nil {
		loaded.JWTTokens = make([]JWTToken, 0)
	}
	if loaded.OAuthTokens == nil {
		loaded.OAuthTokens = make([]OAuthToken, 0)
	}
	if loaded.Cookies == nil {
		loaded.Cookies = make([]EditThisCookieExport, 0)
	}
	tokenExport = &loaded
	nextCookieID = 1
	normalizeLoadedCookies()
	log.Printf("[EXPORT] Loaded %d JWTs, %d OAuth tokens, %d cookies from %s",
		len(tokenExport.JWTTokens), len(tokenExport.OAuthTokens), len(tokenExport.Cookies), path)
}

func normalizeLoadedCookies() {
	for i := range tokenExport.Cookies {
		cookie := &tokenExport.Cookies[i]
		if cookie.Path == "" {
			cookie.Path = "/"
		}
		if !cookie.HostOnly && cookie.Domain != "" && !strings.HasPrefix(cookie.Domain, ".") {
			cookie.Domain = "." + cookie.Domain
		}
		if cookie.ID == 0 {
			cookie.ID = nextCookieID
			nextCookieID++
		} else if cookie.ID >= nextCookieID {
			nextCookieID = cookie.ID + 1
		}
	}
}

// saveTokenExport writes both JSON exports. Caller must hold tokenExportMutex.
func saveTokenExport() {
	sort.Slice(tokenExport.Cookies, func(i, j int) bool {
		a, b := tokenExport.Cookies[i], tokenExport.Cookies[j]
		if a.Domain != b.Domain {
			return a.Domain < b.Domain
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.ID < b.ID
	})

	jsonData, err := json.MarshalIndent(tokenExport, "", "    ")
	if err != nil {
		log.Printf("[EXPORT] ERROR: Failed to marshal tokens JSON: %v", err)
		return
	}
	tokensPath := exportFilePath(capturedTokensFile)
	if err := writeRestrictedFile(tokensPath, jsonData); err != nil {
		log.Printf("[EXPORT] ERROR: Failed to write tokens file %s: %v", tokensPath, err)
		return
	}

	cookieData, err := json.MarshalIndent(tokenExport.Cookies, "", "    ")
	if err != nil {
		log.Printf("[EXPORT] ERROR: Failed to marshal cookies JSON: %v", err)
		return
	}
	cookiePath := exportFilePath(cookieExportFile)
	if err := writeRestrictedFile(cookiePath, cookieData); err != nil {
		log.Printf("[EXPORT] ERROR: Failed to write cookies file %s: %v", cookiePath, err)
		return
	}

	log.Printf("[EXPORT] Saved %d JWTs, %d OAuth tokens, %d cookies to %s",
		len(tokenExport.JWTTokens), len(tokenExport.OAuthTokens), len(tokenExport.Cookies), tokensPath)
}

func writeRestrictedFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tlsdebug-export-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	success := false
	defer func() {
		if !success {
			os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		// Windows cannot rename over an existing file.
		if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
			return err
		}
		if err := os.Rename(tmpName, path); err != nil {
			return err
		}
	}
	success = true
	return os.Chmod(path, 0600)
}

func openProxyLog(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// ============================================================================
// COOKIE EXPORT (Enhanced)
// ============================================================================

func exportResponseCookies(resp *http.Response) {
	if resp == nil || resp.Header == nil {
		return
	}

	setCookies := resp.Cookies()
	if len(setCookies) == 0 {
		return
	}

	tokenExportMutex.Lock()
	defer tokenExportMutex.Unlock()

	cookieMap := make(map[string]EditThisCookieExport, len(tokenExport.Cookies)+len(setCookies))
	for _, existing := range tokenExport.Cookies {
		cookieMap[cookieIdentity(existing.Name, existing.Domain, existing.Path)] = existing
	}

	changed := false
	for _, cookie := range setCookies {
		domain, hostOnly := cookieExportDomain(cookie, resp)
		path := cookie.Path
		if path == "" {
			path = "/"
		}
		key := cookieIdentity(cookie.Name, domain, path)

		if cookie.MaxAge < 0 {
			if _, ok := cookieMap[key]; ok {
				delete(cookieMap, key)
				changed = true
			}
			continue
		}

		existing, exists := cookieMap[key]
		id := existing.ID
		if !exists {
			id = nextCookieID
			nextCookieID++
		}

		etcCookie := EditThisCookieExport{
			Domain:         domain,
			ExpirationDate: cookieExpiration(cookie),
			HostOnly:       hostOnly,
			HttpOnly:       cookie.HttpOnly,
			Name:           cookie.Name,
			Path:           path,
			SameSite:       sameSiteValue(cookie.SameSite),
			Secure:         cookie.Secure,
			Session:        cookie.MaxAge == 0 && cookie.Expires.IsZero(),
			StoreId:        "0",
			Value:          cookie.Value,
			ID:             id,
		}
		if !exists || etcCookie != existing {
			cookieMap[key] = etcCookie
			changed = true
		}
	}
	if !changed {
		return
	}

	tokenExport.Cookies = make([]EditThisCookieExport, 0, len(cookieMap))
	for _, cookie := range cookieMap {
		tokenExport.Cookies = append(tokenExport.Cookies, cookie)
	}
	tokenExport.LastUpdated = time.Now()
	saveTokenExport()
}

func cookieIdentity(name, domain, path string) string {
	return name + "|" + domain + "|" + path
}

func cookieExportDomain(cookie *http.Cookie, resp *http.Response) (string, bool) {
	if cookie.Domain == "" {
		domain := ""
		if resp.Request != nil && resp.Request.URL != nil {
			domain = resp.Request.URL.Hostname()
		}
		if domain == "" && resp.Request != nil {
			domain = resp.Request.Host
			if host, _, err := net.SplitHostPort(domain); err == nil {
				domain = host
			}
		}
		return domain, true
	}
	domain := cookie.Domain
	if !strings.HasPrefix(domain, ".") {
		domain = "." + domain
	}
	return domain, false
}

func cookieExpiration(cookie *http.Cookie) float64 {
	if !cookie.Expires.IsZero() {
		return float64(cookie.Expires.UnixNano()) / 1e9
	}
	if cookie.MaxAge > 0 {
		exp := time.Now().Add(time.Duration(cookie.MaxAge) * time.Second)
		return float64(exp.UnixNano()) / 1e9
	}
	return 0
}

func sameSiteValue(mode http.SameSite) string {
	switch mode {
	case http.SameSiteStrictMode:
		return "strict"
	case http.SameSiteLaxMode:
		return "lax"
	case http.SameSiteNoneMode:
		return "no_restriction"
	default:
		return "unspecified"
	}
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

// readAndRestoreRequestBody reads the request body and restores it,
// properly setting Content-Length headers
func readAndRestoreRequestBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	// Restore the body
	req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Fix Content-Length header to prevent 411 errors
	req.ContentLength = int64(len(bodyBytes))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyBytes)))

	// Remove Transfer-Encoding: chunked if present, since we now have Content-Length
	// Note: This is different from Content-Encoding (gzip, br, etc.)
	req.Header.Del("Transfer-Encoding")

	return bodyBytes, nil
}

// readAndRestoreResponseBody buffers the response body and puts the same
// bytes back. Callers may decompress a copy; the forwarded body is unchanged.
func readAndRestoreResponseBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}
	original := resp.Body
	bodyBytes, err := io.ReadAll(original)
	original.Close()
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return bodyBytes, err
}

func gunzipBytes(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

func formatCapturedBody(data []byte, max int) string {
	if isBinaryContent(data) {
		return fmt.Sprintf("[Binary content, %d bytes]", len(data))
	}
	if max > 0 && len(data) > max {
		return string(data[:max]) + fmt.Sprintf("... [truncated, %d more bytes]", len(data)-max)
	}
	return string(data)
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		if version == 0 {
			return ""
		}
		return fmt.Sprintf("0x%04x", version)
	}
}

func sanitizeForConsole(data string) string {
	// If the data looks like it contains a lot of escape sequences, it's probably binary
	escapeCount := strings.Count(data, "\\x")
	if escapeCount > 50 {
		return "[Binary/encoded data, " + fmt.Sprintf("%d", len(data)) + " bytes - use log file to view]"
	}

	var result strings.Builder
	result.Grow(len(data))
	consecutiveEscapes := 0
	maxConsecutiveEscapes := 10

	for _, r := range data {
		if r == '\n' || r == '\r' || r == '\t' {
			result.WriteRune(r)
			consecutiveEscapes = 0
		} else if r >= 32 && r < 127 {
			result.WriteRune(r)
			consecutiveEscapes = 0
		} else if r >= 128 {
			result.WriteRune(r)
			consecutiveEscapes = 0
		} else {
			if consecutiveEscapes < maxConsecutiveEscapes {
				result.WriteString(fmt.Sprintf("\\x%02x", r))
				consecutiveEscapes++
			} else if consecutiveEscapes == maxConsecutiveEscapes {
				result.WriteString("...[binary data truncated]")
				consecutiveEscapes++
			}
			// Skip further escapes after truncation message
		}
	}

	return result.String()
}

func isBinaryContent(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Check for common binary file signatures
	if len(data) >= 4 {
		// PNG signature
		if data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47 {
			return true
		}
		// JPEG signature
		if data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
			return true
		}
		// PDF signature
		if data[0] == 0x25 && data[1] == 0x50 && data[2] == 0x44 && data[3] == 0x46 {
			return true
		}
		// ZIP signature
		if data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04 {
			return true
		}
		// GIF signature
		if data[0] == 0x47 && data[1] == 0x49 && data[2] == 0x46 {
			return true
		}
		// Gzip signature
		if data[0] == 0x1F && data[1] == 0x8B {
			return true
		}
	}

	// Sample first 512 bytes or entire content if smaller
	sampleSize := 512
	if len(data) < sampleSize {
		sampleSize = len(data)
	}

	nullCount := 0
	controlCount := 0
	nonPrintableCount := 0

	for i := 0; i < sampleSize; i++ {
		b := data[i]
		if b == 0 {
			nullCount++
		}
		// Count control characters (except common text ones)
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			controlCount++
		}
		// Count bytes outside printable ASCII and common UTF-8 ranges
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			nonPrintableCount++
		} else if b == 127 || (b >= 128 && b < 160) {
			nonPrintableCount++
		}
	}

	// If more than 10% null bytes, it's binary
	if nullCount > sampleSize/10 {
		return true
	}

	// If more than 30% control characters, it's binary
	if controlCount > sampleSize*3/10 {
		return true
	}

	// If more than 20% non-printable characters, it's binary
	if nonPrintableCount > sampleSize/5 {
		return true
	}

	return false
}

// ============================================================================
// TRAFFIC MONITORING (existing code)
// ============================================================================

type TrafficEntry struct {
	ID              int
	Timestamp       time.Time
	Method          string
	URL             string
	Host            string
	Path            string
	StatusCode      int
	StatusText      string
	RequestHeaders  map[string][]string
	ResponseHeaders map[string][]string
	RequestBody     string
	ResponseBody    string
	ContentType     string
	Duration        time.Duration
	TLSVersion      string
	ClientAddr      string
}

type TrafficStore struct {
	sync.RWMutex
	entries    []TrafficEntry
	nextID     int
	maxEntries int
}

var trafficStore = &TrafficStore{
	entries:    make([]TrafficEntry, 0),
	nextID:     1,
	maxEntries: 1000,
}

// monitorRequestBodies holds request bodies captured before the upstream
// client consumes them, keyed by the request URL pointer shared with the
// forwarded request.
var monitorRequestBodies sync.Map

func (ts *TrafficStore) AddEntry(entry TrafficEntry) {
	ts.Lock()
	defer ts.Unlock()

	entry.ID = ts.nextID
	ts.nextID++

	ts.entries = append(ts.entries, entry)

	if len(ts.entries) > ts.maxEntries {
		ts.entries = ts.entries[len(ts.entries)-ts.maxEntries:]
	}
}

func (ts *TrafficStore) GetEntries() []TrafficEntry {
	ts.RLock()
	defer ts.RUnlock()

	result := make([]TrafficEntry, len(ts.entries))
	for i, entry := range ts.entries {
		result[len(ts.entries)-1-i] = entry
	}

	return result
}

func (ts *TrafficStore) GetEntry(id int) *TrafficEntry {
	ts.RLock()
	defer ts.RUnlock()

	for _, entry := range ts.entries {
		if entry.ID == id {
			return &entry
		}
	}
	return nil
}

func (ts *TrafficStore) Clear() {
	ts.Lock()
	defer ts.Unlock()

	ts.entries = make([]TrafficEntry, 0)
}

type MonitoringModule struct {
	captureRequestBodies  bool
	captureResponseBodies bool
	maxBodySize           int
}

func NewMonitoringModule() *MonitoringModule {
	return &MonitoringModule{
		captureRequestBodies:  true,
		captureResponseBodies: true,
		maxBodySize:           10240,
	}
}

func (m *MonitoringModule) Name() string {
	return "Monitor"
}

func (m *MonitoringModule) ShouldLog(req *http.Request) bool {
	return true
}

func (m *MonitoringModule) ProcessRequest(req *http.Request) error {
	if req == nil || req.URL == nil || !m.captureRequestBodies || req.Body == nil {
		return nil
	}

	bodyBytes, err := readAndRestoreRequestBody(req)
	if err != nil || len(bodyBytes) == 0 {
		return nil
	}

	display := bodyBytes
	if strings.EqualFold(req.Header.Get("Content-Encoding"), "gzip") {
		if decompressed, err := gunzipBytes(bodyBytes); err == nil {
			display = decompressed
		}
	}
	monitorRequestBodies.Store(req.URL, formatCapturedBody(display, m.maxBodySize))
	// Drop oldest-looking extras if forwarding fails and entries are never consumed.
	n := 0
	monitorRequestBodies.Range(func(key, _ any) bool {
		n++
		if n > 2000 {
			monitorRequestBodies.Delete(key)
		}
		return true
	})
	return nil
}

func (m *MonitoringModule) ProcessResponse(resp *http.Response) error {
	if resp == nil || resp.Request == nil || resp.Request.URL == nil {
		return nil
	}

	startTime := time.Now()

	entry := TrafficEntry{
		Timestamp:       startTime,
		Method:          resp.Request.Method,
		URL:             resp.Request.URL.String(),
		Host:            resp.Request.URL.Hostname(),
		Path:            resp.Request.URL.Path,
		StatusCode:      resp.StatusCode,
		StatusText:      resp.Status,
		RequestHeaders:  cloneHeaders(resp.Request.Header),
		ResponseHeaders: cloneHeaders(resp.Header),
		ContentType:     resp.Header.Get("Content-Type"),
		ClientAddr:      resp.Request.RemoteAddr,
	}
	if resp.Request.TLS != nil {
		entry.TLSVersion = tlsVersionName(resp.Request.TLS.Version)
	}
	if body, ok := monitorRequestBodies.LoadAndDelete(resp.Request.URL); ok {
		entry.RequestBody, _ = body.(string)
	}

	if m.captureResponseBodies && resp.Body != nil {
		encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
		bodyBytes, err := readAndRestoreResponseBody(resp)
		if err != nil {
			log.Printf("[Monitor] Warning: Failed to read response body: %v", err)
		} else {
			switch encoding {
			case "br", "zstd", "deflate":
				entry.ResponseBody = fmt.Sprintf("[Content compressed with %s - cannot display]", encoding)
			case "gzip":
				decompressed, gunzipErr := gunzipBytes(bodyBytes)
				if gunzipErr != nil {
					log.Printf("[Monitor] Warning: Failed to decompress gzip response: %v", gunzipErr)
					entry.ResponseBody = formatCapturedBody(bodyBytes, m.maxBodySize)
				} else {
					entry.ResponseBody = formatCapturedBody(decompressed, m.maxBodySize)
				}
			default:
				entry.ResponseBody = formatCapturedBody(bodyBytes, m.maxBodySize)
			}
		}
	}

	entry.Duration = time.Since(startTime)
	trafficStore.AddEntry(entry)

	return nil
}

func cloneHeaders(h http.Header) map[string][]string {
	clone := make(map[string][]string)
	for k, v := range h {
		clone[k] = append([]string{}, v...)
	}
	return clone
}

// ============================================================================
// WEB MONITOR SERVER (existing code - keeping it the same)
// ============================================================================

func StartMonitorServer(port int) {
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/entries", handleAPIEntries)
	http.HandleFunc("/api/entry/", handleAPIEntry)
	http.HandleFunc("/api/clear", handleAPIClear)
	http.HandleFunc("/api/stats", handleAPIStats)
	http.HandleFunc("/ca-cert", handleCACertDownload)
	http.HandleFunc("/ca.crt", handleCACertDownload)
	http.HandleFunc("/install-ca", handleInstallCAPage)

	addr := fmt.Sprintf(":%d", port)
	log.Printf("[MONITOR] Starting monitor server on http://localhost%s", addr)

	go func() {
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Printf("[MONITOR] Server error: %v", err)
		}
	}()
}

// handleCACertDownload serves the CA certificate as a downloadable .crt
// file so it can be exported with a single request (curl/Invoke-WebRequest,
// or opening the URL in a browser) instead of copying PEM text by hand.
// It re-encodes the in-memory certificate rather than reading proxy-ca.crt
// off disk, so it works the same regardless of -certdir.
func handleCACertDownload(w http.ResponseWriter, r *http.Request) {
	if caCert == nil {
		http.Error(w, "CA certificate not yet initialized", http.StatusServiceUnavailable)
		return
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="tlsproxy-ca.crt"`)
	w.Write(pemBytes)
}

// handleInstallCAPage serves a self-service, OS-aware HTML page that lets a
// *remote* client (any device whose traffic is being intercepted, not just
// the machine running the proxy) download the CA certificate and get
// copy/paste-able instructions for trusting it on their own device -
// Windows, macOS, Linux, Android, or iOS. The download link is built from
// the request's own Host header, so it works correctly no matter which
// address/port the client used to reach the monitor (localhost, LAN IP, or
// a hostname), unlike the fixed "localhost" URL printed on the server console.
func handleInstallCAPage(w http.ResponseWriter, r *http.Request) {
	if caCert == nil {
		http.Error(w, "CA certificate not yet initialized", http.StatusServiceUnavailable)
		return
	}

	downloadURL := fmt.Sprintf("http://%s/ca-cert", r.Host)
	subject := "TLS Proxy Root CA"
	if certConfig != nil {
		subject = fmt.Sprintf("CN=%s, O=%s", certConfig.CommonName, certConfig.Organization)
	}
	expiry := caCert.NotAfter.Format("2006-01-02")

	page := strings.NewReplacer(
		"{{DOWNLOAD_URL}}", downloadURL,
		"{{SUBJECT}}", subject,
		"{{EXPIRY}}", expiry,
	).Replace(installCAPageHTML)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, page)
}

const installCAPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Install CA Certificate</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f5f5f5;
            color: #333;
            padding: 0 0 40px;
        }
        .header {
            background: #fff;
            padding: 20px 30px;
            border-bottom: 1px solid #e0e0e0;
        }
        .header h1 { font-size: 20px; font-weight: 600; margin-bottom: 6px; }
        .header p { color: #666; font-size: 13px; }
        .container { max-width: 760px; margin: 0 auto; padding: 0 20px; }
        .card {
            background: #fff;
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            padding: 24px;
            margin-top: 24px;
        }
        .card h2 { font-size: 15px; margin-bottom: 10px; }
        .meta { font-size: 13px; color: #555; line-height: 1.8; }
        .meta code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; }
        .download-btn {
            display: inline-block;
            margin-top: 14px;
            padding: 10px 20px;
            background: #1976d2;
            color: #fff;
            text-decoration: none;
            border-radius: 4px;
            font-size: 14px;
            font-weight: 600;
        }
        .download-btn:hover { background: #1558a8; }
        .tabs {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            margin-top: 24px;
            border-bottom: 1px solid #e0e0e0;
            padding-bottom: 0;
        }
        .tab-btn {
            padding: 8px 14px;
            border: 1px solid #e0e0e0;
            border-bottom: none;
            border-radius: 4px 4px 0 0;
            background: #fafafa;
            color: #555;
            cursor: pointer;
            font-size: 13px;
        }
        .tab-btn.active { background: #fff; color: #1976d2; font-weight: 600; }
        .tab-panel { display: none; background: #fff; border: 1px solid #e0e0e0; border-top: none; padding: 20px; border-radius: 0 0 6px 6px; }
        .tab-panel.active { display: block; }
        .tab-panel h3 { font-size: 14px; margin: 14px 0 6px; }
        .tab-panel h3:first-child { margin-top: 0; }
        .tab-panel ol, .tab-panel ul { margin-left: 20px; margin-bottom: 10px; font-size: 13px; line-height: 1.7; }
        .tab-panel p { font-size: 13px; line-height: 1.6; margin-bottom: 10px; color: #444; }
        pre {
            background: #272822;
            color: #f8f8f2;
            padding: 12px 14px;
            border-radius: 4px;
            font-size: 12.5px;
            overflow-x: auto;
            margin-bottom: 10px;
        }
        .note {
            background: #fff8e1;
            border: 1px solid #ffe082;
            border-radius: 4px;
            padding: 10px 14px;
            font-size: 12.5px;
            color: #7a5c00;
            margin-top: 16px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Install the TLS Proxy CA Certificate</h1>
        <p>Trust this certificate on your device so intercepted HTTPS connections don't show warnings.</p>
    </div>
    <div class="container">
        <div class="card">
            <h2>1. Download the certificate</h2>
            <div class="meta">
                Subject: <code>{{SUBJECT}}</code><br>
                Valid until: <code>{{EXPIRY}}</code><br>
                Download URL: <code>{{DOWNLOAD_URL}}</code>
            </div>
            <a class="download-btn" href="{{DOWNLOAD_URL}}" download="tlsproxy-ca.crt">Download CA Certificate</a>
        </div>

        <h2 style="margin-top:28px; font-size:15px;">2. Install it on your device</h2>
        <div class="tabs" id="tabs">
            <button class="tab-btn" data-tab="windows">Windows</button>
            <button class="tab-btn" data-tab="macos">macOS</button>
            <button class="tab-btn" data-tab="linux">Linux</button>
            <button class="tab-btn" data-tab="android">Android</button>
            <button class="tab-btn" data-tab="ios">iOS</button>
        </div>

        <div class="tab-panel" data-tab="windows">
            <h3>Option A - PowerShell (one command)</h3>
            <pre>Invoke-WebRequest {{DOWNLOAD_URL}} -OutFile "$env:TEMP\tlsproxy-ca.crt"; Import-Certificate -FilePath "$env:TEMP\tlsproxy-ca.crt" -CertStoreLocation Cert:\CurrentUser\Root</pre>
            <h3>Option B - GUI</h3>
            <ol>
                <li>Download the certificate using the button above.</li>
                <li>Double-click the downloaded <code>tlsproxy-ca.crt</code> file.</li>
                <li>Click <b>Install Certificate</b>.</li>
                <li>Store Location: <b>Current User</b> (or Local Machine, needs admin).</li>
                <li>Choose <b>Place all certificates in the following store</b> &rarr; <b>Trusted Root Certification Authorities</b>.</li>
                <li>Click <b>Next</b>, then <b>Finish</b>, and accept the security warning.</li>
            </ol>
        </div>

        <div class="tab-panel" data-tab="macos">
            <h3>Option A - Terminal</h3>
            <pre>curl -o ~/Downloads/tlsproxy-ca.crt {{DOWNLOAD_URL}}
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/Downloads/tlsproxy-ca.crt</pre>
            <h3>Option B - GUI</h3>
            <ol>
                <li>Download the certificate using the button above.</li>
                <li>Double-click it to open it in <b>Keychain Access</b>.</li>
                <li>Find it under the <b>System</b> keychain, double-click it.</li>
                <li>Expand <b>Trust</b> and set <b>When using this certificate</b> to <b>Always Trust</b>.</li>
                <li>Close the window and enter your password to confirm.</li>
            </ol>
        </div>

        <div class="tab-panel" data-tab="linux">
            <h3>Debian / Ubuntu</h3>
            <pre>curl -o tlsproxy-ca.crt {{DOWNLOAD_URL}}
sudo cp tlsproxy-ca.crt /usr/local/share/ca-certificates/tlsproxy.crt
sudo update-ca-certificates</pre>
            <h3>Fedora / RHEL / CentOS</h3>
            <pre>curl -o tlsproxy-ca.crt {{DOWNLOAD_URL}}
sudo cp tlsproxy-ca.crt /etc/pki/ca-trust/source/anchors/tlsproxy.crt
sudo update-ca-trust</pre>
        </div>

        <div class="tab-panel" data-tab="android">
            <ol>
                <li>Open this page in your device's browser and tap the <b>Download CA Certificate</b> button above (or visit <code>{{DOWNLOAD_URL}}</code> directly).</li>
                <li>Go to <b>Settings &rarr; Security &rarr; Encryption &amp; credentials &rarr; Install a certificate &rarr; CA certificate</b> (path varies by Android version/OEM).</li>
                <li>Tap <b>Install anyway</b>, then select the downloaded file.</li>
                <li>Name it (e.g. "TLS Proxy CA") and confirm.</li>
            </ol>
            <div class="note">Android 7+ only trusts user-installed CAs for apps that explicitly opt in via their network security config. The system browser (Chrome) respects the user CA store, but many apps will still reject the intercepted connection.</div>
        </div>

        <div class="tab-panel" data-tab="ios">
            <ol>
                <li>Open <code>{{DOWNLOAD_URL}}</code> in <b>Safari</b> on the device (must be Safari, not another browser).</li>
                <li>Tap <b>Allow</b> when prompted that this site is trying to download a configuration profile.</li>
                <li>Go to <b>Settings &rarr; General &rarr; VPN &amp; Device Management</b>, tap the downloaded profile, then <b>Install</b> (enter your passcode).</li>
                <li>Go to <b>Settings &rarr; General &rarr; About &rarr; Certificate Trust Settings</b> and enable <b>Full Trust</b> for this certificate.</li>
            </ol>
            <div class="note">Installing the profile alone is not enough - you must also enable full trust in Certificate Trust Settings, or TLS connections will still fail.</div>
        </div>

        <div class="note">
            This CA can decrypt and inspect any HTTPS traffic from a device that trusts it. Only install it on devices you intend to have monitored, and remove it when you're done (reverse the steps above, or delete it from the certificate/keychain manager).
        </div>
    </div>

    <script>
        var tabs = document.querySelectorAll('.tab-btn');
        var panels = document.querySelectorAll('.tab-panel');
        function activate(name) {
            tabs.forEach(function(b) { b.classList.toggle('active', b.dataset.tab === name); });
            panels.forEach(function(p) { p.classList.toggle('active', p.dataset.tab === name); });
        }
        tabs.forEach(function(b) {
            b.addEventListener('click', function() { activate(b.dataset.tab); });
        });
        var ua = navigator.userAgent || '';
        var guess = 'windows';
        if (/Android/i.test(ua)) guess = 'android';
        else if (/iPhone|iPad|iPod/i.test(ua)) guess = 'ios';
        else if (/Macintosh|Mac OS X/i.test(ua)) guess = 'macos';
        else if (/Linux/i.test(ua) && !/Android/i.test(ua)) guess = 'linux';
        activate(guess);
    </script>
</body>
</html>`

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	htmlPage := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Proxy Monitor</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f5f5f5;
            color: #333;
            padding: 0;
        }
        
        .header {
            background: #fff;
            padding: 20px 30px;
            border-bottom: 1px solid #e0e0e0;
        }
        
        .header h1 {
            color: #333;
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 15px;
        }
        
        .stats {
            display: flex;
            gap: 30px;
            flex-wrap: wrap;
        }
        
        .stat-box {
            display: flex;
            flex-direction: column;
        }
        
        .stat-box .label {
            font-size: 11px;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }
        
        .stat-box .value {
            font-size: 18px;
            font-weight: 600;
            color: #333;
        }
        
        .controls {
            background: #fff;
            padding: 15px 30px;
            border-bottom: 1px solid #e0e0e0;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .controls input[type="text"] {
            flex: 1;
            min-width: 250px;
            padding: 8px 12px;
            border: 1px solid #d0d0d0;
            border-radius: 4px;
            background: #fff;
            color: #333;
            font-size: 13px;
        }
        
        .controls input[type="text"]:focus {
            outline: none;
            border-color: #999;
        }
        
        .controls button {
            padding: 8px 16px;
            border: 1px solid #d0d0d0;
            border-radius: 4px;
            background: #fff;
            color: #333;
            cursor: pointer;
            font-size: 13px;
            font-weight: 500;
        }
        
        .controls button:hover {
            background: #f5f5f5;
        }
        
        .controls button.danger {
            color: #d32f2f;
            border-color: #d32f2f;
        }
        
        .controls button.danger:hover {
            background: #ffebee;
        }
        
        .controls label {
            display: flex;
            align-items: center;
            gap: 6px;
            cursor: pointer;
            user-select: none;
            font-size: 13px;
            color: #666;
        }
        
        .table-container {
            background: #fff;
            margin: 0;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        thead {
            background: #fafafa;
            border-top: 1px solid #e0e0e0;
            border-bottom: 1px solid #e0e0e0;
        }
        
        th {
            padding: 12px 20px;
            text-align: left;
            font-weight: 600;
            color: #666;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        tbody tr {
            border-bottom: 1px solid #f0f0f0;
            cursor: pointer;
        }
        
        tbody tr:hover {
            background: #fafafa;
        }
        
        td {
            padding: 12px 20px;
            font-size: 13px;
            color: #333;
            max-width: 300px;
            word-break: break-word;
            overflow-wrap: anywhere;
        }
        
        .method {
            font-weight: 600;
            font-size: 11px;
            color: #666;
        }
        
        .method.GET { color: #2e7d32; }
        .method.POST { color: #f57c00; }
        .method.PUT { color: #1976d2; }
        .method.DELETE { color: #d32f2f; }
        .method.PATCH { color: #7b1fa2; }
        
        .status {
            font-weight: 600;
            font-size: 12px;
        }
        
        .status.success { color: #2e7d32; }
        .status.redirect { color: #1976d2; }
        .status.client-error { color: #f57c00; }
        .status.server-error { color: #d32f2f; }
        
        .url {
            color: #1976d2;
            word-break: break-all;
            font-size: 13px;
            max-width: 400px;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .timestamp {
            color: #999;
            font-size: 12px;
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
            padding: 20px;
            overflow-y: auto;
            overflow-x: hidden;
        }
        
        .modal-content {
            background: #fff;
            max-width: 1200px;
            width: calc(100vw - 40px);
            margin: 40px auto;
            border-radius: 4px;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            max-height: 90vh;
            overflow-y: auto;
            overflow-x: hidden;
            box-sizing: border-box;
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 1px solid #e0e0e0;
        }
        
        .modal-header h2 {
            color: #333;
            font-size: 18px;
            font-weight: 600;
            word-break: break-word;
            overflow-wrap: anywhere;
            flex: 1;
            margin-right: 15px;
        }
        
        .close-btn {
            background: none;
            border: none;
            color: #999;
            font-size: 28px;
            cursor: pointer;
            line-height: 1;
        }
        
        .close-btn:hover {
            color: #333;
        }
        
        .detail-section {
            margin-bottom: 25px;
            max-width: 100%;
            position: relative;
        }
        
        .detail-section h3 {
            color: #333;
            margin-bottom: 12px;
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .section-copy-btn {
            padding: 4px 10px;
            background: #fff;
            border: 1px solid #d0d0d0;
            border-radius: 3px;
            cursor: pointer;
            font-size: 11px;
            color: #666;
            text-transform: none;
            letter-spacing: normal;
            font-weight: normal;
            transition: all 0.2s;
        }
        
        .section-copy-btn:hover {
            background: #e8e8e8;
            border-color: #999;
        }
        
        .section-copy-btn.copied {
            background: #4caf50;
            color: white;
            border-color: #4caf50;
        }
        
        #modalBody {
            max-width: 100%;
            overflow-x: hidden;
        }
        
        .detail-grid {
            background: #fafafa;
            border-radius: 4px;
            border: 1px solid #e0e0e0;
            max-width: 100%;
            width: 100%;
            box-sizing: border-box;
            overflow: hidden;
        }
        
        .detail-grid > div {
            padding: 12px 15px;
            border-bottom: 1px solid #e0e0e0;
            display: grid;
            grid-template-columns: 150px 1fr;
            gap: 15px;
            align-items: start;
        }
        
        .detail-grid > div:last-child,
        .detail-grid > div:nth-last-child(2):nth-child(odd) {
            border-bottom: none;
        }
        
        .detail-grid .label {
            color: #666;
            font-weight: 600;
            font-size: 12px;
            padding-top: 2px;
        }
        
        .detail-grid .value {
            color: #333;
            font-size: 13px;
            word-break: break-word;
            overflow-wrap: anywhere;
            white-space: pre-wrap;
            max-width: 100%;
            font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
            line-height: 1.5;
        }
        
        .headers-list {
            background: #fafafa;
            padding: 0;
            border-radius: 4px;
            border: 1px solid #e0e0e0;
            max-width: 100%;
            width: 100%;
            box-sizing: border-box;
            overflow: hidden;
        }
        
        .header-item {
            margin: 0;
            padding: 12px 15px;
            border-bottom: 1px solid #e0e0e0;
            background: #fafafa;
            display: flex;
            align-items: flex-start;
            gap: 10px;
            position: relative;
        }
        
        .header-item:hover {
            background: #f0f0f0;
        }
        
        .header-item:last-child {
            border-bottom: none;
        }
        
        .header-content {
            flex: 1;
            min-width: 0;
            font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
            font-size: 12px;
            word-break: break-word;
            overflow-wrap: anywhere;
        }
        
        .header-name {
            color: #1976d2;
            font-weight: 600;
            display: block;
            margin-bottom: 4px;
        }
        
        .header-value {
            color: #666;
            word-break: break-word;
            overflow-wrap: anywhere;
            white-space: pre-wrap;
            display: block;
            line-height: 1.5;
        }
        
        .copy-btn {
            padding: 4px 8px;
            background: #fff;
            border: 1px solid #d0d0d0;
            border-radius: 3px;
            cursor: pointer;
            font-size: 11px;
            color: #666;
            white-space: nowrap;
            flex-shrink: 0;
            transition: all 0.2s;
        }
        
        .copy-btn:hover {
            background: #e8e8e8;
            border-color: #999;
        }
        
        .copy-btn:active {
            background: #d0d0d0;
        }
        
        .copy-btn.copied {
            background: #4caf50;
            color: white;
            border-color: #4caf50;
        }
        
        .body-content {
            background: #1e1e1e;
            padding: 20px;
            border-radius: 4px;
            border: 1px solid #e0e0e0;
            font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
            font-size: 12px;
            line-height: 1.6;
            max-height: 600px;
            overflow-y: auto;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-word;
            overflow-wrap: anywhere;
            color: #d4d4d4;
            max-width: 100%;
            width: 100%;
            box-sizing: border-box;
        }
        
        .body-content.json {
            background: #1e1e1e;
        }
        
        .body-content.html {
            background: #fafafa;
            color: #333;
        }
        
        .body-content.text {
            background: #fafafa;
            color: #333;
        }
        
        .json-key {
            color: #9cdcfe;
        }
        
        .json-string {
            color: #ce9178;
        }
        
        .json-number {
            color: #b5cea8;
        }
        
        .json-boolean {
            color: #569cd6;
        }
        
        .json-null {
            color: #569cd6;
        }
        
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #999;
        }
        
        .empty-state-icon {
            font-size: 48px;
            margin-bottom: 15px;
            opacity: 0.3;
        }
        
        @media (max-width: 768px) {
            .controls {
                flex-direction: column;
            }
            
            .controls input[type="text"] {
                width: 100%;
            }
            
            .stats {
                flex-direction: column;
                gap: 15px;
            }
            
            .detail-grid > div {
                grid-template-columns: 1fr;
                gap: 5px;
            }
            
            .detail-grid .label {
                font-weight: 700;
                padding-top: 0;
            }
            
            .modal-content {
                margin: 10px;
                padding: 20px;
                width: calc(100vw - 20px);
            }
            
            .header-item {
                flex-direction: column;
                gap: 8px;
            }
            
            .copy-btn,
            .section-copy-btn {
                align-self: flex-start;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>TLS Proxy Monitor</h1>
        <div class="stats">
            <div class="stat-box">
                <div class="label">Total Requests</div>
                <div class="value" id="totalRequests">0</div>
            </div>
            <div class="stat-box">
                <div class="label">Success Rate</div>
                <div class="value" id="successRate">0%</div>
            </div>
            <div class="stat-box">
                <div class="label">Avg Response Time</div>
                <div class="value" id="avgTime">0ms</div>
            </div>
        </div>
    </div>
    
    <div class="controls">
        <input type="text" id="searchBox" placeholder="Filter by URL, host, method, or status...">
        <label>
            <input type="checkbox" id="autoRefresh" checked>
            Auto-refresh
        </label>
        <button onclick="loadEntries()">Refresh</button>
        <button class="danger" onclick="clearEntries()">Clear All</button>
        <a href="/install-ca" target="_blank" rel="noopener" style="margin-left:auto; padding:8px 16px; border:1px solid #1976d2; border-radius:4px; background:#1976d2; color:#fff; font-size:13px; font-weight:500; text-decoration:none;">Install CA Certificate</a>
    </div>
    
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Method</th>
                    <th>Host</th>
                    <th>Path</th>
                    <th>Status</th>
                    <th>Duration</th>
                    <th>Type</th>
                </tr>
            </thead>
            <tbody id="trafficTable">
                <tr>
                    <td colspan="7" class="empty-state">
                        <div class="empty-state-icon">—</div>
                        <div>No requests captured yet</div>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>
    
    <div id="detailModal" class="modal" onclick="closeModal(event)">
        <div class="modal-content" onclick="event.stopPropagation()">
            <div class="modal-header">
                <h2>Request Details</h2>
                <button class="close-btn" onclick="closeModal()">×</button>
            </div>
            <div id="modalBody"></div>
        </div>
    </div>
    
    <script>
        let searchTerm = '';
        let autoRefreshInterval = null;
        
        document.getElementById('searchBox').addEventListener('input', (e) => {
            searchTerm = e.target.value.toLowerCase();
            loadEntries();
        });
        
        document.getElementById('autoRefresh').addEventListener('change', (e) => {
            if (e.target.checked) {
                startAutoRefresh();
            } else {
                stopAutoRefresh();
            }
        });
        
        function startAutoRefresh() {
            if (!autoRefreshInterval) {
                autoRefreshInterval = setInterval(loadEntries, 2000);
            }
        }
        
        function stopAutoRefresh() {
            if (autoRefreshInterval) {
                clearInterval(autoRefreshInterval);
                autoRefreshInterval = null;
            }
        }
        
        async function loadEntries() {
            try {
                const response = await fetch('/api/entries');
                const entries = await response.json();
                
                const filtered = entries.filter(entry => {
                    if (!searchTerm) return true;
                    return entry.URL.toLowerCase().includes(searchTerm) ||
                           entry.Host.toLowerCase().includes(searchTerm) ||
                           entry.Method.toLowerCase().includes(searchTerm) ||
                           entry.StatusCode.toString().includes(searchTerm);
                });
                
                renderTable(filtered);
                updateStats(entries);
            } catch (error) {
                console.error('Failed to load entries:', error);
            }
        }
        
        function renderTable(entries) {
            const tbody = document.getElementById('trafficTable');
            
            if (entries.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="empty-state"><div class="empty-state-icon">—</div><div>No requests captured yet</div></td></tr>';
                return;
            }
            
            tbody.innerHTML = entries.map(entry => {
                const time = new Date(entry.Timestamp).toLocaleTimeString();
                const statusClass = getStatusClass(entry.StatusCode);
                const duration = entry.Duration ? (entry.Duration / 1000000).toFixed(0) + 'ms' : '-';
                
                return '<tr onclick="showDetails(' + entry.ID + ')"><td class="timestamp">' + time + '</td><td><span class="method ' + entry.Method + '">' + entry.Method + '</span></td><td>' + escapeHtml(entry.Host) + '</td><td class="url">' + escapeHtml(entry.Path) + '</td><td><span class="status ' + statusClass + '">' + (entry.StatusCode || '-') + '</span></td><td>' + duration + '</td><td>' + (entry.ContentType || '-') + '</td></tr>';
            }).join('');
        }
        
        function getStatusClass(code) {
            if (code >= 200 && code < 300) return 'success';
            if (code >= 300 && code < 400) return 'redirect';
            if (code >= 400 && code < 500) return 'client-error';
            if (code >= 500) return 'server-error';
            return '';
        }
        
        async function updateStats(entries) {
            document.getElementById('totalRequests').textContent = entries.length;
            
            const successCount = entries.filter(e => e.StatusCode >= 200 && e.StatusCode < 300).length;
            const successRate = entries.length > 0 ? ((successCount / entries.length) * 100).toFixed(1) : 0;
            document.getElementById('successRate').textContent = successRate + '%';
            
            const avgDuration = entries.length > 0
                ? entries.reduce((sum, e) => sum + (e.Duration || 0), 0) / entries.length / 1000000
                : 0;
            document.getElementById('avgTime').textContent = avgDuration.toFixed(0) + 'ms';
        }
        
        function formatResponseBody(body, contentType) {
            if (!body) return '<div style="color: #999;">No response body</div>';
            
            const isJSON = contentType && (contentType.includes('application/json') || contentType.includes('application/javascript'));
            const isHTML = contentType && contentType.includes('text/html');
            const isXML = contentType && contentType.includes('xml');
            
            let formatted = body;
            let className = 'text';
            
            if (isJSON) {
                try {
                    const parsed = JSON.parse(body);
                    formatted = JSON.stringify(parsed, null, 2);
                    formatted = syntaxHighlightJSON(formatted);
                    className = 'json';
                } catch (e) {
                    formatted = escapeHtml(body);
                }
            } else if (isHTML || isXML) {
                formatted = escapeHtml(body);
                className = 'html';
            } else {
                formatted = escapeHtml(body);
            }
            
            return '<div class="body-content ' + className + '">' + formatted + '</div>';
        }
        
        function syntaxHighlightJSON(json) {
            json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
                let cls = 'json-number';
                if (/^"/.test(match)) {
                    if (/:$/.test(match)) {
                        cls = 'json-key';
                    } else {
                        cls = 'json-string';
                    }
                } else if (/true|false/.test(match)) {
                    cls = 'json-boolean';
                } else if (/null/.test(match)) {
                    cls = 'json-null';
                }
                return '<span class="' + cls + '">' + match + '</span>';
            });
        }
        
        async function showDetails(id) {
            try {
                const response = await fetch('/api/entry/' + id);
                const entry = await response.json();
                
                if (!entry) {
                    alert('Entry not found');
                    return;
                }
                
                const modalBody = document.getElementById('modalBody');
                let html = '<div class="detail-section"><h3>Request Information</h3><div class="detail-grid">';
                html += '<div><div class="label">Method:</div><div class="value"><span class="method ' + entry.Method + '">' + entry.Method + '</span></div></div>';
                html += '<div><div class="label">URL:</div><div class="value">' + escapeHtml(entry.URL) + '</div></div>';
                html += '<div><div class="label">Host:</div><div class="value">' + escapeHtml(entry.Host) + '</div></div>';
                html += '<div><div class="label">Path:</div><div class="value">' + escapeHtml(entry.Path) + '</div></div>';
                html += '<div><div class="label">Timestamp:</div><div class="value">' + new Date(entry.Timestamp).toLocaleString() + '</div></div>';
                html += '</div></div>';
                
                if (entry.StatusCode) {
                    html += '<div class="detail-section"><h3>Response Information</h3><div class="detail-grid">';
                    html += '<div><div class="label">Status:</div><div class="value"><span class="status ' + getStatusClass(entry.StatusCode) + '">' + entry.StatusCode + ' ' + escapeHtml(entry.StatusText) + '</span></div></div>';
                    html += '<div><div class="label">Content-Type:</div><div class="value">' + escapeHtml(entry.ContentType || 'N/A') + '</div></div>';
                    html += '<div><div class="label">Duration:</div><div class="value">' + (entry.Duration ? (entry.Duration / 1000000).toFixed(2) + 'ms' : 'N/A') + '</div></div>';
                    html += '</div></div>';
                }
                
                html += '<div class="detail-section"><h3>Request Headers <button class="section-copy-btn" onclick="copyAllHeaders(' + id + ', \'request\', this)">Copy All</button></h3><div class="headers-list" id="req-headers-' + id + '">' + formatHeaders(entry.RequestHeaders) + '</div></div>';
                
                if (entry.ResponseHeaders) {
                    html += '<div class="detail-section"><h3>Response Headers <button class="section-copy-btn" onclick="copyAllHeaders(' + id + ', \'response\', this)">Copy All</button></h3><div class="headers-list" id="resp-headers-' + id + '">' + formatHeaders(entry.ResponseHeaders) + '</div></div>';
                }
                
                if (entry.ResponseBody) {
                    html += '<div class="detail-section"><h3>Response Body <button class="section-copy-btn" onclick="copyResponseBody(' + id + ', this)">Copy</button></h3><div id="resp-body-' + id + '">' + formatResponseBody(entry.ResponseBody, entry.ContentType) + '</div></div>';
                }
                
                modalBody.innerHTML = html;
                document.getElementById('detailModal').style.display = 'block';
            } catch (error) {
                console.error('Failed to load entry details:', error);
                alert('Failed to load entry details');
            }
        }
        
        function copyAllHeaders(entryId, type, button) {
            const headersDiv = document.getElementById(type + '-headers-' + entryId);
            if (!headersDiv) return;
            
            const headers = [];
            headersDiv.querySelectorAll('.header-item').forEach(item => {
                const name = item.querySelector('.header-name').textContent;
                const value = item.querySelector('.header-value').textContent;
                headers.push(name + ' ' + value);
            });
            
            const text = headers.join('\n');
            navigator.clipboard.writeText(text).then(() => {
                button.textContent = '✓ Copied';
                button.classList.add('copied');
                setTimeout(() => {
                    button.textContent = 'Copy All';
                    button.classList.remove('copied');
                }, 2000);
            }).catch(err => {
                console.error('Failed to copy:', err);
            });
        }
        
        function copyResponseBody(entryId, button) {
            const bodyDiv = document.getElementById('resp-body-' + entryId);
            if (!bodyDiv) return;
            
            const bodyContent = bodyDiv.querySelector('.body-content');
            const text = bodyContent ? bodyContent.textContent : bodyDiv.textContent;
            
            navigator.clipboard.writeText(text).then(() => {
                button.textContent = '✓ Copied';
                button.classList.add('copied');
                setTimeout(() => {
                    button.textContent = 'Copy';
                    button.classList.remove('copied');
                }, 2000);
            }).catch(err => {
                console.error('Failed to copy:', err);
            });
        }
        
        function formatHeaders(headers) {
            if (!headers) return '<div style="color: #999;">No headers</div>';
            
            return Object.entries(headers).map(([name, values]) => {
                const valueStr = Array.isArray(values) ? values.join(', ') : values;
                const headerId = 'header-' + Math.random().toString(36).substr(2, 9);
                return '<div class="header-item">' +
                    '<div class="header-content">' +
                        '<span class="header-name">' + escapeHtml(name) + '</span>' +
                        '<span class="header-value" id="' + headerId + '">' + escapeHtml(valueStr) + '</span>' +
                    '</div>' +
                    '<button class="copy-btn" onclick="copyHeaderValue(\'' + headerId + '\', this); event.stopPropagation();">Copy</button>' +
                '</div>';
            }).join('');
        }
        
        function copyHeaderValue(elementId, button) {
            const element = document.getElementById(elementId);
            if (!element) return;
            
            const text = element.textContent;
            navigator.clipboard.writeText(text).then(() => {
                const originalText = button.textContent;
                button.textContent = '✓ Copied';
                button.classList.add('copied');
                
                setTimeout(() => {
                    button.textContent = originalText;
                    button.classList.remove('copied');
                }, 2000);
            }).catch(err => {
                console.error('Failed to copy:', err);
                button.textContent = '✗ Failed';
                setTimeout(() => {
                    button.textContent = 'Copy';
                }, 2000);
            });
        }
        
        function closeModal(event) {
            if (!event || event.target.id === 'detailModal') {
                document.getElementById('detailModal').style.display = 'none';
            }
        }
        
        async function clearEntries() {
            if (!confirm('Are you sure you want to clear all captured traffic?')) {
                return;
            }
            
            try {
                await fetch('/api/clear', { method: 'POST' });
                loadEntries();
            } catch (error) {
                console.error('Failed to clear entries:', error);
                alert('Failed to clear entries');
            }
        }
        
        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        startAutoRefresh();
        loadEntries();
    </script>
</body>
</html>`

	fmt.Fprint(w, htmlPage)
}

func handleAPIEntries(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	entries := trafficStore.GetEntries()
	json.NewEncoder(w).Encode(entries)
}

func handleAPIEntry(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	idStr := strings.TrimPrefix(r.URL.Path, "/api/entry/")
	var id int
	fmt.Sscanf(idStr, "%d", &id)

	entry := trafficStore.GetEntry(id)
	if entry == nil {
		http.NotFound(w, r)
		return
	}

	json.NewEncoder(w).Encode(entry)
}

func handleAPIClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	trafficStore.Clear()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleAPIStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	entries := trafficStore.GetEntries()

	stats := map[string]interface{}{
		"total":       len(entries),
		"methods":     countByMethod(entries),
		"statusCodes": countByStatusCode(entries),
		"hosts":       countByHost(entries),
	}

	json.NewEncoder(w).Encode(stats)
}

func countByMethod(entries []TrafficEntry) map[string]int {
	counts := make(map[string]int)
	for _, entry := range entries {
		counts[entry.Method]++
	}
	return counts
}

func countByStatusCode(entries []TrafficEntry) map[int]int {
	counts := make(map[int]int)
	for _, entry := range entries {
		if entry.StatusCode > 0 {
			counts[entry.StatusCode]++
		}
	}
	return counts
}

func countByHost(entries []TrafficEntry) []map[string]interface{} {
	counts := make(map[string]int)
	for _, entry := range entries {
		counts[entry.Host]++
	}

	type hostCount struct {
		host  string
		count int
	}
	var hosts []hostCount
	for host, count := range counts {
		hosts = append(hosts, hostCount{host, count})
	}
	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].count > hosts[j].count
	})

	result := make([]map[string]interface{}, 0)
	for i, hc := range hosts {
		if i >= 10 {
			break
		}
		result = append(result, map[string]interface{}{
			"host":  hc.host,
			"count": hc.count,
		})
	}

	return result
}

// ============================================================================
// OTHER MODULES
// ============================================================================

type AllTrafficModule struct{}

func (m *AllTrafficModule) Name() string {
	return "AllTraffic"
}

func (m *AllTrafficModule) ShouldLog(req *http.Request) bool {
	return true
}

func (m *AllTrafficModule) ProcessRequest(req *http.Request) error {
	return nil
}

func (m *AllTrafficModule) ProcessResponse(resp *http.Response) error {
	return nil
}

type OAuthModule struct{}

func (m *OAuthModule) Name() string {
	return "OAuth"
}

func (m *OAuthModule) ShouldLog(req *http.Request) bool {
	url := req.URL.String()
	path := strings.ToLower(req.URL.Path)

	oauthPatterns := []string{
		"/oauth", "/auth", "/login", "/token", "/authorize",
		"access_token", "refresh_token", "client_id", "client_secret",
		"/connect", "/callback", "/.well-known/openid",
	}

	for _, pattern := range oauthPatterns {
		if strings.Contains(strings.ToLower(url), pattern) ||
			strings.Contains(path, pattern) {
			log.Printf("[OAuth] Detected OAuth flow: %s", url)
			return true
		}
	}

	if authHeader := req.Header.Get("Authorization"); authHeader != "" {
		log.Printf("[OAuth] Detected Authorization header")
		return true
	}

	return false
}

func (m *OAuthModule) ProcessRequest(req *http.Request) error {
	return nil
}

func (m *OAuthModule) ProcessResponse(resp *http.Response) error {
	return nil
}

// ... (rest of the existing modules: DomainFilter, RequestModifier, etc.) ...

// ============================================================================
// MAIN FUNCTION
// ============================================================================

func main() {
	port := flag.Int("port", 8080, "Proxy port")
	cleanup := flag.Bool("cleanup", false, "Remove CA certificates and exit")
	certDir := flag.String("certdir", ".", "Certificate directory")
	skipInstall := flag.Bool("skip-install", false, "Skip automatic certificate installation")
	configFile := flag.String("config", "proxy-config.ini", "Configuration file path")
	monitorPort := flag.Int("monitor-port", 4040, "Monitor web interface port")
	verbose := flag.Bool("verbose", false, "Enable verbose logging (log all traffic to console)")
	exportCA := flag.String("export-ca", "", "Export the CA certificate PEM to this path ('-' for stdout) and exit, without starting the proxy")
	flag.Parse()

	verboseMode = *verbose

	certConfig = loadConfig(*configFile)

	config := &ProxyConfig{
		Port:        *port,
		CertDir:     *certDir,
		LogFile:     filepath.Join(*certDir, logFile),
		SkipInstall: *skipInstall,
	}

	if *cleanup {
		cleanupCerts(config)
		return
	}

	if err := initCA(config); err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}

	if *exportCA != "" {
		if err := exportCACert(*exportCA); err != nil {
			log.Fatalf("Failed to export CA certificate: %v", err)
		}
		return
	}

	var err error
	logWriter, err = openProxyLog(config.LogFile)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logWriter.Close()

	exportDir = config.CertDir
	loadTokenExport()

	initializeModules()

	StartMonitorServer(*monitorPort)

	printCACertExportImportInfo(*monitorPort)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", config.Port))
	if err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
	defer listener.Close()

	log.Printf("Proxy listening on port %d", config.Port)
	log.Printf("Monitor interface: http://localhost:%d", *monitorPort)
	log.Printf("CA certificate: %s", filepath.Join(config.CertDir, caCertFile))
	log.Printf("Log file: %s", config.LogFile)
	log.Printf("⚠️  TOKEN CAPTURE: JWT and OAuth tokens will be exported to %s", exportFilePath(capturedTokensFile))
	log.Printf("⚠️  COOKIE EXPORT: Sessions will be exported to %s", exportFilePath(cookieExportFile))
	log.Printf("WARNING: These files contain sensitive authentication data!")
	log.Printf("WARNING: proxy.log and token exports are restricted to mode 0600")

	if verboseMode {
		log.Printf("Verbose mode: ENABLED (all traffic logged to console)")
	} else {
		log.Printf("Verbose mode: DISABLED (use -verbose flag to enable console logging)")
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleConnection(conn, config)
	}
}

func initializeModules() {
	log.Println("Initializing logging modules...")

	RegisterModule(&AllTrafficModule{})
	RegisterModule(NewMonitoringModule())
	RegisterModule(NewTokenExportModule())

	log.Printf("Total modules registered: %d", len(logModules))
}

func loadConfig(configPath string) *CertConfig {
	config := defaultCertConfig()

	if !fileExists(configPath) {
		log.Printf("Config file not found: %s (using defaults)", configPath)
		return config
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("Failed to read config file: %v (using defaults)", err)
		return config
	}

	lines := strings.Split(string(data), "\n")
	currentSection := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.Trim(line, "[]")
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if value == "" {
			continue
		}

		switch currentSection {
		case "ca_certificate":
			switch key {
			case "organization":
				config.Organization = value
			case "common_name":
				config.CommonName = value
			case "validity_years":
				if v, err := parseInt(value); err == nil {
					config.ValidityYears = v
				}
			}
		case "certificate_extensions":
			switch key {
			case "aia_urls":
				config.AIAURLs = value
			case "crl_distribution_points":
				if value != "" {
					config.CRLDistPoints = strings.Split(value, ",")
					for i := range config.CRLDistPoints {
						config.CRLDistPoints[i] = strings.TrimSpace(config.CRLDistPoints[i])
					}
				}
			case "ocsp_url":
				config.OCSPServer = value
			}
		case "host_certificates":
			switch key {
			case "default_san_entries":
				if value != "" {
					config.DefaultSANs = strings.Split(value, ",")
					for i := range config.DefaultSANs {
						config.DefaultSANs[i] = strings.TrimSpace(config.DefaultSANs[i])
					}
				}
			case "validity_days":
				if v, err := parseInt(value); err == nil {
					config.HostValidityDays = v
				}
			case "include_aia_in_host_certs":
				config.IncludeAIAInHosts = parseBool(value)
			case "include_cdp_in_host_certs":
				config.IncludeCDPInHosts = parseBool(value)
			}
		}
	}

	log.Printf("Loaded configuration from: %s", configPath)
	return config
}

func parseInt(s string) (int, error) {
	var result int
	_, err := fmt.Sscanf(s, "%d", &result)
	return result, err
}

func parseBool(s string) bool {
	s = strings.ToLower(s)
	return s == "true" || s == "yes" || s == "1" || s == "on"
}

func initCA(config *ProxyConfig) error {
	certPath := filepath.Join(config.CertDir, caCertFile)
	keyPath := filepath.Join(config.CertDir, caKeyFile)

	if fileExists(certPath) && fileExists(keyPath) {
		if err := loadCA(certPath, keyPath); err != nil {
			return err
		}
		if !config.SkipInstall {
			if err := installCertificate(certPath); err != nil {
				log.Printf("WARNING: Failed to verify or install existing CA: %v", err)
				printManualInstallInstructions(certPath)
			}
		}
		return nil
	}

	return generateCA(certPath, keyPath, config.SkipInstall)
}

func generateCA(certPath, keyPath string, skipInstall bool) error {
	log.Println("Generating new CA certificate...")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{certConfig.Organization},
			CommonName:   certConfig.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(certConfig.ValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	if len(certConfig.CRLDistPoints) > 0 {
		template.CRLDistributionPoints = certConfig.CRLDistPoints
		log.Printf("CA CRL Distribution Points: %v", certConfig.CRLDistPoints)
	}

	if certConfig.AIAURLs != "" {
		parts := strings.Split(certConfig.AIAURLs, "|")
		if len(parts) == 2 {
			ocspURL := strings.TrimSpace(parts[0])
			caIssuerURL := strings.TrimSpace(parts[1])

			if ocspURL != "" {
				template.OCSPServer = []string{ocspURL}
				log.Printf("CA OCSP Server: %s", ocspURL)
			}
			if caIssuerURL != "" {
				template.IssuingCertificateURL = []string{caIssuerURL}
				log.Printf("CA Issuer URL: %s", caIssuerURL)
			}
		}
	} else if certConfig.OCSPServer != "" {
		template.OCSPServer = []string{certConfig.OCSPServer}
		log.Printf("CA OCSP Server: %s", certConfig.OCSPServer)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()

	keyOut, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	keyOut.Close()

	log.Printf("CA certificate generated: %s", certPath)
	log.Printf("CA Organization: %s", certConfig.Organization)
	log.Printf("CA Common Name: %s", certConfig.CommonName)
	log.Printf("CA Validity: %d years", certConfig.ValidityYears)

	if skipInstall {
		log.Println("Skipping automatic certificate installation (--skip-install flag)")
		printManualInstallInstructions(certPath)
	} else {
		if err := installCertificate(certPath); err != nil {
			log.Printf("WARNING: Failed to install certificate automatically: %v", err)
			log.Printf("Please install manually: %s", certPath)
			printManualInstallInstructions(certPath)
		} else {
			log.Printf("CA certificate installed successfully")
			log.Printf("You may need to restart your browser for changes to take effect")
		}
	}

	return loadCA(certPath, keyPath)
}

func loadCA(certPath, keyPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	caCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}

	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode key PEM")
	}

	caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	log.Println("Loaded existing CA certificate")
	return nil
}

func cleanupCerts(config *ProxyConfig) {
	certPath := filepath.Join(config.CertDir, caCertFile)
	keyPath := filepath.Join(config.CertDir, caKeyFile)

	log.Println("Removing certificate from system trust store...")
	if err := uninstallCertificate(); err != nil {
		log.Printf("WARNING: Failed to uninstall certificate: %v", err)
		log.Println("You may need to remove it manually")
	} else {
		log.Println("Certificate uninstalled from system")
	}

	removed := false
	if fileExists(certPath) {
		os.Remove(certPath)
		log.Printf("Removed: %s", certPath)
		removed = true
	}
	if fileExists(keyPath) {
		os.Remove(keyPath)
		log.Printf("Removed: %s", keyPath)
		removed = true
	}
	if !removed {
		log.Println("No certificate files found to remove")
	}
}

func handleConnection(clientConn net.Conn, config *ProxyConfig) {
	defer clientConn.Close()

	clientAddr := clientConn.RemoteAddr().String()
	log.Printf("[CONNECTION] New connection from %s", clientAddr)

	reader := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Printf("[ERROR] Failed to read request from %s: %v", clientAddr, err)
		return
	}

	if req.Method == "PRI" {
		log.Printf("[REJECT] Invalid request method PRI from %s", clientAddr)
		clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\nInvalid request method.\r\n"))
		return
	}

	if req.Method == http.MethodConnect {
		log.Printf("[CONNECT] %s -> %s", clientAddr, req.Host)
		handleConnect(clientConn, req, config)
	} else {
		log.Printf("[HTTP] %s %s", req.Method, req.URL.String())
		handleHTTP(clientConn, req, config)
	}
}

func handleConnect(clientConn net.Conn, req *http.Request, config *ProxyConfig) {
	host := req.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	cert := getCertForHost(host)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,

		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,

			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},

		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},

		PreferServerCipherSuites: false,
	}

	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "tls: client offered only unsupported versions") {
			log.Printf("[TLS] Client using unsupported TLS version for %s", host)
		} else if strings.Contains(errMsg, "first record does not look like a TLS handshake") {
			log.Printf("[TLS] Client sent non-TLS data to %s (possibly plain HTTP)", host)
		} else if strings.Contains(errMsg, "remote error") || strings.Contains(errMsg, "EOF") {
			log.Printf("[TLS] Client aborted handshake with %s", host)
		} else {
			log.Printf("[TLS] Handshake failed with %s: %v", host, err)
		}
		return
	}
	defer tlsClientConn.Close()

	state := tlsClientConn.ConnectionState()
	tlsVersion := tlsVersionName(state.Version)
	if tlsVersion == "" {
		tlsVersion = "unknown"
	}
	log.Printf("[TLS] %s using %s with cipher %s", host, tlsVersion, tls.CipherSuiteName(state.CipherSuite))

	reader := bufio.NewReader(tlsClientConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err == io.EOF {
				return
			}

			errMsg := err.Error()
			if strings.Contains(errMsg, "use of closed network connection") ||
				strings.Contains(errMsg, "connection reset") ||
				strings.Contains(errMsg, "broken pipe") {
				return
			}

			if strings.Contains(errMsg, "malformed HTTP") {
				log.Printf("[TLS] Client %s sent non-HTTP data (likely clean close): %v", host, err)
				return
			}

			log.Printf("[TLS] Error reading HTTPS request from %s: %v", host, err)
			return
		}

		req.URL.Scheme = "https"
		req.URL.Host = req.Host
		req.RemoteAddr = clientConn.RemoteAddr().String()
		req.TLS = &state

		logRequest(req, config)

		resp, err := forwardRequest(req)
		if err != nil {
			log.Printf("Failed to forward request: %v", err)
			tlsClientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}

		if err := resp.Write(tlsClientConn); err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "broken pipe") {
				log.Printf("Failed to write response: %v", err)
			}
			resp.Body.Close()
			return
		}
		resp.Body.Close()
	}
}

func handleHTTP(clientConn net.Conn, req *http.Request, config *ProxyConfig) {
	defer clientConn.Close()

	if !req.URL.IsAbs() {
		if req.Host == "" {
			log.Printf("[ERROR] Invalid HTTP request: no host specified")
			clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\nNo host specified in request\r\n"))
			return
		}
		req.URL.Scheme = "http"
		req.URL.Host = req.Host
	}

	req.RemoteAddr = clientConn.RemoteAddr().String()
	logRequest(req, config)

	resp, err := forwardRequest(req)
	if err != nil {
		log.Printf("Failed to forward HTTP request: %v", err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer resp.Body.Close()

	resp.Write(clientConn)
}

func forwardRequest(req *http.Request) (*http.Response, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,

		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,

			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},

		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
	}

	transport := &http.Transport{
		TLSClientConfig:   tlsConfig,
		Proxy:             http.ProxyFromEnvironment,
		ForceAttemptHTTP2: false,
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
	}

	outReq := &http.Request{
		Method:        req.Method,
		URL:           req.URL,
		Header:        req.Header.Clone(),
		Body:          req.Body,
		ContentLength: req.ContentLength,
		Host:          req.Host,
	}

	outReq.RequestURI = ""
	outReq.Header.Del("Proxy-Connection")
	outReq.RemoteAddr = req.RemoteAddr
	outReq.TLS = req.TLS

	resp, err := client.Do(outReq)
	if err != nil {
		return nil, err
	}

	executeModulesResponse(resp)

	return resp, nil
}

func logRequest(req *http.Request, config *ProxyConfig) {
	shouldLog := executeModules(req)

	if !shouldLog {
		return
	}

	logMutex.Lock()
	defer logMutex.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("\n=== %s ===\n", timestamp)

	reqURL := req.URL.String()
	if reqURL == "" || reqURL == "*" {
		reqURL = fmt.Sprintf("%s (malformed)", req.RequestURI)
	}

	logEntry = logEntry + fmt.Sprintf("%s %s\n", req.Method, reqURL)

	logEntry = logEntry + "Headers:\n"
	for name, values := range req.Header {
		for _, value := range values {
			logEntry = logEntry + fmt.Sprintf("  %s: %s\n", name, value)
		}
	}

	if req.Method == http.MethodPost || req.Method == http.MethodPut || req.Method == http.MethodPatch {
		bodyBytes, err := readAndRestoreRequestBody(req)
		if err == nil && bodyBytes != nil {
			contentType := req.Header.Get("Content-Type")
			contentEncoding := req.Header.Get("Content-Encoding")

			// Try to decompress if gzip encoded
			displayBytes := bodyBytes
			if contentEncoding == "gzip" && len(bodyBytes) > 0 {
				gzipReader, err := gzip.NewReader(bytes.NewReader(bodyBytes))
				if err == nil {
					decompressed, err := io.ReadAll(gzipReader)
					gzipReader.Close()
					if err == nil {
						displayBytes = decompressed
						logEntry = logEntry + fmt.Sprintf("Body (decompressed from gzip, original size: %d bytes):\n", len(bodyBytes))
					}
				}
			}

			if isBinaryContent(displayBytes) {
				logEntry = logEntry + fmt.Sprintf("Body: [Binary data, %d bytes]\n", len(displayBytes))
			} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
				params, err := url.ParseQuery(string(displayBytes))
				if err == nil && len(params) > 0 {
					logEntry = logEntry + "POST Parameters:\n"
					for key, values := range params {
						for _, value := range values {
							logEntry = logEntry + fmt.Sprintf("  %s: %s\n", key, value)
						}
					}
				}
			} else if len(displayBytes) > 0 {
				logEntry = logEntry + fmt.Sprintf("Body: %s\n", string(displayBytes))
			}
		}
	}

	if verboseMode {
		consoleEntry := logEntry
		const maxConsole = 10240
		if len(consoleEntry) > maxConsole {
			consoleEntry = consoleEntry[:maxConsole] + fmt.Sprintf("\n... [truncated, %d more bytes]\n", len(logEntry)-maxConsole)
		}
		fmt.Print(sanitizeForConsole(consoleEntry))
	}

	if logWriter != nil {
		if _, err := logWriter.WriteString(logEntry); err != nil {
			log.Printf("Failed to write log entry: %v", err)
		}
	}
}

func getCertForHost(host string) *tls.Certificate {
	hostname := strings.Split(host, ":")[0]

	certCache.RLock()
	cert, exists := certCache.certs[hostname]
	certCache.RUnlock()

	if exists {
		return cert
	}

	certCache.Lock()
	defer certCache.Unlock()

	if cert, exists := certCache.certs[hostname]; exists {
		return cert
	}

	cert = generateCertForHost(hostname)
	certCache.certs[hostname] = cert
	return cert
}

func generateCertForHost(hostname string) *tls.Certificate {
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	sanDNSNames := []string{hostname}
	sanIPAddresses := []net.IP{}

	for _, san := range certConfig.DefaultSANs {
		if ip := net.ParseIP(san); ip != nil {
			sanIPAddresses = append(sanIPAddresses, ip)
		} else {
			isDuplicate := false
			for _, existing := range sanDNSNames {
				if existing == san {
					isDuplicate = true
					break
				}
			}
			if !isDuplicate {
				sanDNSNames = append(sanDNSNames, san)
			}
		}
	}

	if ip := net.ParseIP(hostname); ip != nil {
		sanIPAddresses = append(sanIPAddresses, ip)
	}

	if strings.Count(hostname, ".") > 1 {
		parts := strings.SplitN(hostname, ".", 2)
		wildcard := fmt.Sprintf("*.%s", parts[1])
		sanDNSNames = append(sanDNSNames, wildcard)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{certConfig.Organization},
			CommonName:   hostname,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(0, 0, certConfig.HostValidityDays),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    sanDNSNames,
		IPAddresses: sanIPAddresses,
	}

	if certConfig.IncludeCDPInHosts && len(certConfig.CRLDistPoints) > 0 {
		template.CRLDistributionPoints = certConfig.CRLDistPoints
	}

	if certConfig.IncludeAIAInHosts {
		if certConfig.AIAURLs != "" {
			parts := strings.Split(certConfig.AIAURLs, "|")
			if len(parts) == 2 {
				ocspURL := strings.TrimSpace(parts[0])
				caIssuerURL := strings.TrimSpace(parts[1])

				if ocspURL != "" {
					template.OCSPServer = []string{ocspURL}
				}
				if caIssuerURL != "" {
					template.IssuingCertificateURL = []string{caIssuerURL}
				}
			}
		} else if certConfig.OCSPServer != "" {
			template.OCSPServer = []string{certConfig.OCSPServer}
		}
	}

	certPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER, _ := x509.CreateCertificate(rand.Reader, template, caCert, &certPrivKey.PublicKey, caKey)

	cert := &tls.Certificate{
		Certificate: [][]byte{certDER, caCert.Raw},
		PrivateKey:  certPrivKey,
	}

	return cert
}

func installCertificate(certPath string) error {
	absPath, err := filepath.Abs(certPath)
	if err != nil {
		return err
	}

	installed, err := certificateInstalled(absPath)
	if err != nil {
		return fmt.Errorf("failed to check certificate trust: %w", err)
	}
	if installed {
		log.Printf("Matching CA certificate is already installed")
		return nil
	}

	switch runtime.GOOS {
	case "windows":
		err = installCertWindows(absPath)
	case "darwin":
		err = installCertMacOS(absPath)
	case "linux":
		err = installCertLinux(absPath)
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
	if err != nil {
		return err
	}

	installed, err = certificateInstalled(absPath)
	if err != nil {
		return fmt.Errorf("failed to verify certificate trust: %w", err)
	}
	if !installed {
		return fmt.Errorf("certificate installation completed but the exact CA fingerprint was not found")
	}
	return nil
}

func certificateInstalled(certPath string) (bool, error) {
	expected, err := certificateFingerprintFile(certPath)
	if err != nil {
		return false, err
	}

	switch runtime.GOOS {
	case "windows":
		return certificateInstalledWindows(expected)
	case "darwin":
		return certificateInstalledMacOS(expected)
	case "linux":
		return certificateInstalledLinux(expected)
	default:
		return false, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

func certificateFingerprintFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("failed to decode certificate PEM: %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	return certificateFingerprint(cert), nil
}

func certificateFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", sum)
}

func pemContainsFingerprint(data []byte, expected string) bool {
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			return false
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil && certificateFingerprint(cert) == expected {
			return true
		}
	}
	return false
}

func certificateInstalledWindows(expected string) (bool, error) {
	powerShell, err := exec.LookPath("powershell.exe")
	if err != nil {
		return false, fmt.Errorf("powershell.exe not found: %w", err)
	}
	script := fmt.Sprintf(
		`$sha=[Security.Cryptography.SHA256]::Create(); $match=Get-ChildItem Cert:\CurrentUser\Root | Where-Object { ([BitConverter]::ToString($sha.ComputeHash($_.RawData))).Replace('-','').ToLowerInvariant() -eq '%s' }; if ($match) { exit 0 } else { exit 1 }`,
		expected,
	)
	err = exec.Command(powerShell, "-NoProfile", "-NonInteractive", "-Command", script).Run()
	if err == nil {
		return true, nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
		return false, nil
	}
	return false, err
}

func certificateInstalledMacOS(expected string) (bool, error) {
	output, err := exec.Command(
		"security", "find-certificate", "-a", "-p", "/Library/Keychains/System.keychain",
	).Output()
	if err != nil {
		return false, err
	}
	return pemContainsFingerprint(output, expected), nil
}

func certificateInstalledLinux(expected string) (bool, error) {
	const trustedCertPath = "/usr/local/share/ca-certificates/tlsproxy.crt"
	if !fileExists(trustedCertPath) {
		return false, nil
	}
	actual, err := certificateFingerprintFile(trustedCertPath)
	if err != nil {
		return false, nil
	}
	return actual == expected, nil
}

func installCertWindows(certPath string) error {
	_, err := exec.LookPath("certutil")
	if err != nil {
		return fmt.Errorf("certutil not found in PATH - manual installation required")
	}

	log.Printf("Installing certificate to Windows trust store...")
	log.Printf("Running: certutil -addstore -user Root \"%s\"", certPath)

	cmd := exec.Command("certutil", "-addstore", "-user", "Root", certPath)
	output, err := cmd.CombinedOutput()

	if len(output) > 0 {
		log.Printf("certutil output: %s", string(output))
	}

	if err != nil {
		return fmt.Errorf("certutil failed: %v - %s", err, string(output))
	}

	return nil
}

func installCertMacOS(certPath string) error {
	cmd := exec.Command("sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot",
		"-k", "/Library/Keychains/System.keychain", certPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}
	return nil
}

func installCertLinux(certPath string) error {
	destPath := "/usr/local/share/ca-certificates/tlsproxy.crt"

	input, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}

	cmd := exec.Command("sudo", "tee", destPath)
	cmd.Stdin = bytes.NewReader(input)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to copy certificate: %v", err)
	}

	cmd = exec.Command("sudo", "update-ca-certificates")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}

	return nil
}

func uninstallCertificate() error {
	switch runtime.GOOS {
	case "windows":
		return uninstallCertWindows()
	case "darwin":
		return uninstallCertMacOS()
	case "linux":
		return uninstallCertLinux()
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

func uninstallCertWindows() error {
	cmd := exec.Command("certutil", "-delstore", "-user", "Root", "TLS Proxy Root CA")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}
	return nil
}

func uninstallCertMacOS() error {
	cmd := exec.Command("sudo", "security", "delete-certificate", "-c", "TLS Proxy Root CA",
		"/Library/Keychains/System.keychain")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}
	return nil
}

func uninstallCertLinux() error {
	destPath := "/usr/local/share/ca-certificates/tlsproxy.crt"

	cmd := exec.Command("sudo", "rm", "-f", destPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove certificate: %v", err)
	}

	cmd = exec.Command("sudo", "update-ca-certificates")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}

	return nil
}

// exportCACert writes the loaded CA certificate as PEM to the given path,
// or to stdout when path is "-". It's the scriptable counterpart to the
// download endpoint and console printout below, for e.g. pulling the cert
// out of a running/remote instance in an automated setup step:
//
//	./tlsproxy -export-ca ca.crt
//	./tlsproxy -export-ca - > ca.crt
func exportCACert(path string) error {
	if caCert == nil {
		return fmt.Errorf("CA certificate not loaded")
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	if path == "-" {
		_, err := os.Stdout.Write(pemBytes)
		return err
	}
	if err := os.WriteFile(path, pemBytes, 0644); err != nil {
		return err
	}
	log.Printf("CA certificate exported to %s", path)
	return nil
}

// printCACertExportImportInfo prints the CA certificate as copy/paste-able
// PEM text, the URL it can be downloaded from while the proxy is running,
// and ready-to-run Windows import commands (PowerShell and certutil). This
// covers the case where the proxy runs somewhere the operator's Windows
// workstation can't reach the filesystem directly (a remote host, a
// container, etc.), so everything needed to export and import the CA is
// copyable straight out of the console/log output.
func printCACertExportImportInfo(monitorPort int) {
	if caCert == nil {
		return
	}
	pemText := strings.TrimRight(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})), "\r\n")
	downloadURL := fmt.Sprintf("http://localhost:%d/ca-cert", monitorPort)
	installURL := fmt.Sprintf("http://localhost:%d/install-ca", monitorPort)

	log.Println("")
	log.Println("================================================================")
	log.Println(" CA CERTIFICATE - export & import on a Windows workstation")
	log.Println("================================================================")
	if certConfig != nil {
		log.Printf(" Subject: CN=%s, O=%s", certConfig.CommonName, certConfig.Organization)
	}
	log.Println(" NOTE: if this host's certificate storage isn't persisted")
	log.Println(" (e.g. an ephemeral container), a restart generates a NEW CA")
	log.Println(" and you'll need to export/import it again.")
	log.Println("")
	log.Printf(" Remote clients: send them to %s for a self-service", installURL)
	log.Println(" download + OS-specific install instructions (Windows, macOS,")
	log.Println(" Linux, Android, iOS) - substitute this host's real address")
	log.Println(" if they're connecting over the network instead of localhost.")
	log.Println("")
	log.Printf(" Export while the proxy is running: %s", downloadURL)
	log.Println(" (substitute this host's real address if connecting remotely)")
	log.Println("")
	log.Println("---- Easiest: download + import in one PowerShell command ----")
	log.Printf(`Invoke-WebRequest %s -OutFile "$env:TEMP\tlsproxy-ca.crt"; Import-Certificate -FilePath "$env:TEMP\tlsproxy-ca.crt" -CertStoreLocation Cert:\CurrentUser\Root`, downloadURL)
	log.Println("")
	log.Println("---- Or paste the certificate PEM directly (no network needed) ----")
	log.Println(pemText)
	log.Println("")
	log.Println("$pem = @'")
	log.Println(pemText)
	log.Println("'@")
	log.Println(`$path = Join-Path $env:TEMP 'tlsproxy-ca.crt'`)
	log.Println("Set-Content -Path $path -Value $pem -Encoding ascii")
	log.Println(`Import-Certificate -FilePath $path -CertStoreLocation Cert:\CurrentUser\Root`)
	log.Println("")
	log.Println("---- Or certutil (Command Prompt, after saving the PEM above) ----")
	log.Println("  certutil -addstore -user Root tlsproxy-ca.crt")
	log.Println("  (drop -user and run elevated to install machine-wide instead)")
	log.Println("================================================================")
	log.Println("")
}

func printManualInstallInstructions(certPath string) {
	absPath, _ := filepath.Abs(certPath)

	switch runtime.GOOS {
	case "windows":
		log.Println("")
		log.Println("=== Manual Windows Installation ===")
		log.Println("Option 1 - Command Line (User Store):")
		log.Printf("  certutil -addstore -user Root \"%s\"", absPath)
		log.Println("")
		log.Println("Option 2 - Command Line (System Store, requires Admin):")
		log.Printf("  certutil -addstore Root \"%s\"", absPath)
		log.Println("")
		log.Println("Option 3 - GUI:")
		log.Printf("  1. Double-click: %s", absPath)
		log.Println("  2. Click 'Install Certificate'")
		log.Println("  3. Store Location: 'Current User'")
		log.Println("  4. Place in: 'Trusted Root Certification Authorities'")
		log.Println("  5. Click 'Next' and 'Finish'")
		log.Println("")
	case "darwin":
		log.Println("")
		log.Println("=== Manual macOS Installation ===")
		log.Printf("  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain \"%s\"", absPath)
		log.Println("")
		log.Println("OR double-click the certificate and set to 'Always Trust'")
		log.Println("")
	case "linux":
		log.Println("")
		log.Println("=== Manual Linux Installation ===")
		log.Printf("  sudo cp \"%s\" /usr/local/share/ca-certificates/tlsproxy.crt", absPath)
		log.Println("  sudo update-ca-certificates")
		log.Println("")
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
