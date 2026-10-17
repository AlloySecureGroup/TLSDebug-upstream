package main

/*
Captured tokens and cookies.

TokenExportModule reads every request and response looking for credentials:

  - JWTs in Authorization: Bearer, cookies, query parameters, and bodies.
    A JWT is three base64url segments. The header and payload are decoded
    and a few registered claims (exp, iat, nbf, iss, sub, aud) are copied
    out. The signature is stored and not verified. This proxy is recording
    what it saw, not deciding whether the token is authentic.
  - OAuth token responses, JSON or form-encoded, with access_token,
    refresh_token, and id_token. An access token or id token that is itself
    a JWT is also recorded as a JWT.
  - Set-Cookie on responses, rewritten into the EditThisCookie import shape.
    Max-Age=0 deletes a cookie previously captured for the same name,
    domain, and path. A Domain attribute is stored with a leading dot so
    EditThisCookie treats it as a domain cookie. A cookie with no Domain
    is host-only and keeps the response host.

The bytes scanned may be a gzip copy. The response forwarded to the client
keeps its original body and Content-Encoding. Brotli, zstd, and deflate
bodies are not scanned; Set-Cookie is still recorded because it lives in
the headers.

captured_tokens.json and EditThisCookie_Sessions.json are written in
-certdir, mode 0600. They contain live secrets. Writes are atomic (temp
file, then rename) so a crash mid-write does not leave a truncated JSON
file for the next start to fail on.

The in-memory lists are capped at maxStoredTokens, the same bound as the
dashboard's traffic list. The newest entries are kept. Cookies are not
capped: a cap would drop a session cookie that is still valid.
Disk IO happens outside tokenExportMutex. A generation counter drops a
stale snapshot if a newer capture already won the write.
*/

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// JWTHeader is the decoded JOSE header. The raw header is also kept on
// JWTToken.Header so unknown fields are not dropped.
type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

// JWTToken is one decoded JSON Web Token. Raw is the three-segment string
// exactly as it appeared, which is also the duplicate key.
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

// OAuthToken is one token response. AccessToken, RefreshToken, and IDToken
// together are the duplicate key. An empty access token is allowed when
// the response only carried a refresh token or an id token.
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

// EditThisCookieExport matches the JSON EditThisCookie imports. Field names
// and the leading-dot domain convention are that extension's, not a
// general cookie model. ExpirationDate is Unix time in seconds with a
// fractional part, which is why it is a float.
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

// TokenExport is the on-disk document and the in-memory store.
type TokenExport struct {
	JWTTokens   []JWTToken             `json:"jwt_tokens"`
	OAuthTokens []OAuthToken           `json:"oauth_tokens"`
	Cookies     []EditThisCookieExport `json:"cookies"`
	LastUpdated time.Time              `json:"last_updated"`
}

const (
	capturedTokensFile = "captured_tokens.json"
	cookieExportFile   = "EditThisCookie_Sessions.json"

	// maxStoredTokens matches the dashboard cap in monitor.go. Newest wins.
	maxStoredTokens = 1000
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

	// tokenWriteMu serializes file writes. exportSeq increases under
	// tokenExportMutex on every mutation. lastPersistedSeq is the newest
	// generation that has been written. A writer that lost the race drops
	// its snapshot instead of overwriting a newer file.
	tokenWriteMu     sync.Mutex
	exportSeq        uint64
	lastPersistedSeq uint64
)

// jwtPattern finds compact JWTs inside a larger body. The first segment of
// a JWT header is base64url for JSON that starts with "{", which is "eyJ".
var jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)

// parseJWT decodes a compact JWT. It returns nil when the string is not
// three segments of JSON. It does not check the signature.
func parseJWT(tokenString string, source string, requestURL string) *JWTToken {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil
	}

	headerBytes, err := base64DecodeSegment(parts[0])
	if err != nil {
		return nil
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil
	}

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

// base64DecodeSegment decodes one JWT segment. JWT uses raw base64url
// (no padding). The padded decoder is used after padding is restored so
// both padded and unpadded input work.
func base64DecodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}
	return base64.URLEncoding.DecodeString(seg)
}

// extractJWTFromString returns every distinct JWT matched in text.
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

// bearerToken returns the credential from an Authorization header when the
// scheme is Bearer, compared case-insensitively. Other schemes are ignored.
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

// recordOAuthToken stores the OAuth token and, when the access token or
// id token is itself a JWT, stores those too.
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

// TokenExportModule is the credential observer. ShouldLog returns true,
// but AllTrafficModule already forces proxy.log on, so this vote is not
// what causes logging. ProcessRequest and ProcessResponse are the work.
type TokenExportModule struct{}

func NewTokenExportModule() *TokenExportModule { return &TokenExportModule{} }

func (m *TokenExportModule) Name() string { return "TokenExport" }

func (m *TokenExportModule) ShouldLog(req *http.Request) bool { return true }

func (m *TokenExportModule) ProcessRequest(req *http.Request) error {
	if req == nil {
		return nil
	}

	reqURL := req.URL.String()

	if tokenString := bearerToken(req.Header.Get("Authorization")); tokenString != "" {
		tryAddJWT(tokenString, "Request Authorization Header", reqURL)
	}

	for _, cookie := range req.Cookies() {
		tryAddJWT(cookie.Value, fmt.Sprintf("Request Cookie: %s", cookie.Name), reqURL)
	}

	if req.Body != nil && (req.Method == "POST" || req.Method == "PUT" || req.Method == "PATCH") {
		bodyBytes, err := readAndRestoreRequestBody(req)
		if err == nil && bodyBytes != nil {
			displayBytes := bodyBytes
			if strings.EqualFold(req.Header.Get("Content-Encoding"), "gzip") && len(bodyBytes) > 0 {
				if decompressed, err := gunzipBytes(bodyBytes); err == nil {
					displayBytes = decompressed
				}
			}

			if !isBinaryContent(displayBytes) {
				bodyStr := string(displayBytes)
				contentType := strings.ToLower(req.Header.Get("Content-Type"))

				if strings.Contains(contentType, "application/json") {
					if token := extractOAuthTokensFromJSON(bodyStr, "Request Body (JSON)", reqURL); token != nil {
						recordOAuthToken(token)
					}
				}
				if strings.Contains(contentType, "application/x-www-form-urlencoded") {
					if token := extractOAuthTokensFromForm(bodyStr, "Request Body (Form)", reqURL); token != nil {
						recordOAuthToken(token)
					}
				}

				for _, jwt := range extractJWTFromString(bodyStr, "Request Body", reqURL) {
					addJWTToken(jwt)
				}
			}
		}
	}

	if req.URL.RawQuery != "" {
		values := req.URL.Query()
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

	// Cookies live in the headers, so they are recorded even when the
	// body encoding is one this proxy cannot decompress.
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
	for _, existing := range tokenExport.JWTTokens {
		if existing.Raw == jwt.Raw {
			tokenExportMutex.Unlock()
			return
		}
	}
	tokenExport.JWTTokens = append(tokenExport.JWTTokens, *jwt)
	tokenExport.JWTTokens = trimTail(tokenExport.JWTTokens, maxStoredTokens)
	snap, gen := snapshotForPersist()
	tokenExportMutex.Unlock()

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

	persistTokenExport(gen, snap)
}

func addOAuthToken(token *OAuthToken) {
	if token == nil {
		return
	}

	tokenExportMutex.Lock()
	for _, existing := range tokenExport.OAuthTokens {
		if existing.AccessToken == token.AccessToken && existing.RefreshToken == token.RefreshToken && existing.IDToken == token.IDToken {
			tokenExportMutex.Unlock()
			return
		}
	}
	tokenExport.OAuthTokens = append(tokenExport.OAuthTokens, *token)
	tokenExport.OAuthTokens = trimTail(tokenExport.OAuthTokens, maxStoredTokens)
	snap, gen := snapshotForPersist()
	tokenExportMutex.Unlock()

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

	persistTokenExport(gen, snap)
}

func exportFilePath(name string) string {
	return filepath.Join(exportDir, name)
}

// loadTokenExport restores a previous session file. A missing file is the
// normal first-run case. A corrupt file is logged and left unused so a bad
// write cannot block the proxy from starting.
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
	loaded.JWTTokens = trimTail(loaded.JWTTokens, maxStoredTokens)
	loaded.OAuthTokens = trimTail(loaded.OAuthTokens, maxStoredTokens)
	tokenExport = &loaded
	nextCookieID = 1
	normalizeLoadedCookies()
	log.Printf("[EXPORT] Loaded %d JWTs, %d OAuth tokens, %d cookies from %s",
		len(tokenExport.JWTTokens), len(tokenExport.OAuthTokens), len(tokenExport.Cookies), path)
}

// normalizeLoadedCookies fills defaults the capture path would have set,
// and advances nextCookieID past any id already on disk so new cookies do
// not reuse an id.
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

// snapshotForPersist copies the store and assigns a generation. The caller
// holds tokenExportMutex. The copy is what gets written, so a later append
// cannot race the JSON encoder.
func snapshotForPersist() (TokenExport, uint64) {
	tokenExport.LastUpdated = time.Now()
	exportSeq++
	snap := TokenExport{
		JWTTokens:   append([]JWTToken(nil), tokenExport.JWTTokens...),
		OAuthTokens: append([]OAuthToken(nil), tokenExport.OAuthTokens...),
		Cookies:     append([]EditThisCookieExport(nil), tokenExport.Cookies...),
		LastUpdated: tokenExport.LastUpdated,
	}
	return snap, exportSeq
}

func persistTokenExport(gen uint64, snap TokenExport) {
	tokenWriteMu.Lock()
	defer tokenWriteMu.Unlock()
	if gen < lastPersistedSeq {
		return
	}

	sort.Slice(snap.Cookies, func(i, j int) bool {
		a, b := snap.Cookies[i], snap.Cookies[j]
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

	jsonData, err := json.MarshalIndent(snap, "", "    ")
	if err != nil {
		log.Printf("[EXPORT] ERROR: Failed to marshal tokens JSON: %v", err)
		return
	}
	tokensPath := exportFilePath(capturedTokensFile)
	if err := writeRestrictedFile(tokensPath, jsonData); err != nil {
		log.Printf("[EXPORT] ERROR: Failed to write tokens file %s: %v", tokensPath, err)
		return
	}

	cookieData, err := json.MarshalIndent(snap.Cookies, "", "    ")
	if err != nil {
		log.Printf("[EXPORT] ERROR: Failed to marshal cookies JSON: %v", err)
		return
	}
	cookiePath := exportFilePath(cookieExportFile)
	if err := writeRestrictedFile(cookiePath, cookieData); err != nil {
		log.Printf("[EXPORT] ERROR: Failed to write cookies file %s: %v", cookiePath, err)
		return
	}

	lastPersistedSeq = gen
	log.Printf("[EXPORT] Saved %d JWTs, %d OAuth tokens, %d cookies to %s",
		len(snap.JWTTokens), len(snap.OAuthTokens), len(snap.Cookies), tokensPath)
}

func trimTail[T any](items []T, max int) []T {
	if max <= 0 || len(items) <= max {
		return items
	}
	return append([]T(nil), items[len(items)-max:]...)
}

// writeRestrictedFile replaces path atomically and leaves it mode 0600.
// The temporary file is created in the same directory so rename does not
// cross filesystems. On Windows, rename will not replace an existing file,
// so the destination is removed and the rename is retried.
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

// exportResponseCookies merges Set-Cookie into the captured cookie list.
// Identity is name, domain, and path. Max-Age < 0 is a deletion. An
// unchanged cookie does not cause a rewrite of the files.
func exportResponseCookies(resp *http.Response) {
	if resp == nil || resp.Header == nil {
		return
	}

	setCookies := resp.Cookies()
	if len(setCookies) == 0 {
		return
	}

	tokenExportMutex.Lock()

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
		tokenExportMutex.Unlock()
		return
	}

	tokenExport.Cookies = make([]EditThisCookieExport, 0, len(cookieMap))
	for _, cookie := range cookieMap {
		tokenExport.Cookies = append(tokenExport.Cookies, cookie)
	}
	snap, gen := snapshotForPersist()
	tokenExportMutex.Unlock()
	persistTokenExport(gen, snap)
}

func cookieIdentity(name, domain, path string) string {
	return name + "|" + domain + "|" + path
}

// cookieExportDomain returns the domain string EditThisCookie expects and
// whether the cookie is host-only. A Set-Cookie without Domain is host-only
// and belongs to the response URL's host. A Domain attribute is a domain
// cookie and is stored with a leading dot.
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

// cookieExpiration converts Expires or Max-Age into the fractional Unix
// time EditThisCookie stores. A session cookie (no expiry) returns 0.
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
