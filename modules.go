package main

/*
Logging modules.

Every decrypted HTTP exchange is shown to each registered LogModule. The
interface is observational:

  - ShouldLog votes on whether the exchange is appended to proxy.log.
    One true vote is enough. The vote does not decide whether the other
    methods run.
  - ProcessRequest runs before the request is forwarded. It may read the
    body; readAndRestoreRequestBody puts the same bytes back so the origin
    still receives them.
  - ProcessResponse runs after the origin answers. The same restore rule
    applies to the response body.

An error from ProcessRequest or ProcessResponse is logged and then ignored.
Modules cannot block, rewrite, or redirect traffic. That keeps a buggy
observer from breaking the connection the operator is trying to debug.

AllTrafficModule is registered by default and always votes true, so
proxy.log receives every exchange until that module is removed.
OAuthModule shows what a selective vote looks like. It is not registered.
*/

import (
	"log"
	"net/http"
	"strings"
)

// LogModule is one observer of decrypted traffic.
type LogModule interface {
	Name() string
	ShouldLog(req *http.Request) bool
	ProcessRequest(req *http.Request) error
	ProcessResponse(resp *http.Response) error
}

// logModules is append-only after startup. The proxy does not register
// modules from requests, so the slice is read without a lock.
var logModules []LogModule

// RegisterModule appends module and logs its name. Call it from
// initializeModules before the accept loop starts.
func RegisterModule(module LogModule) {
	logModules = append(logModules, module)
	log.Printf("[MODULE] Registered: %s", module.Name())
}

// executeModules runs every module's request hook. The returned bool is
// true when any module voted to write proxy.log. ProcessRequest runs even
// when that module voted false: token export and the dashboard are side
// effects, not log filters.
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

// executeModulesResponse runs every module's response hook. The error
// return is always nil; per-module failures are logged here so a caller
// cannot accidentally abort the response by checking the result.
func executeModulesResponse(resp *http.Response) error {
	for _, module := range logModules {
		if err := module.ProcessResponse(resp); err != nil {
			log.Printf("[%s] Error processing response: %v", module.Name(), err)
		}
	}
	return nil
}

// AllTrafficModule votes to log every exchange and has no side effects.
// It is what makes proxy.log a full transcript. Remove it from
// initializeModules to let a selective module such as OAuthModule decide.
type AllTrafficModule struct{}

func (m *AllTrafficModule) Name() string { return "AllTraffic" }

func (m *AllTrafficModule) ShouldLog(req *http.Request) bool { return true }

func (m *AllTrafficModule) ProcessRequest(req *http.Request) error { return nil }

func (m *AllTrafficModule) ProcessResponse(resp *http.Response) error { return nil }

// OAuthModule votes to log requests that look like an OAuth or OpenID
// Connect exchange, or that carry an Authorization header. It does not
// extract tokens; TokenExportModule does that for every request.
//
// This module is not registered. With AllTrafficModule registered, its
// vote would not change proxy.log. Copy the RegisterModule line into
// initializeModules only after removing AllTrafficModule, if you want
// proxy.log limited to these requests.
type OAuthModule struct{}

func (m *OAuthModule) Name() string { return "OAuth" }

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

func (m *OAuthModule) ProcessRequest(req *http.Request) error { return nil }

func (m *OAuthModule) ProcessResponse(resp *http.Response) error { return nil }
