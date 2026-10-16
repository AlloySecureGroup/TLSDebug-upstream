# Logging Modules

TLSDebug's traffic inspection is built around a small plugin system:
every decrypted request/response that passes through the proxy is handed
to a list of registered **modules**, each of which decides whether to log
it and what to do with it. This document describes that system as it
exists today in [tlsproxy.go](tlsproxy.go).

## The `LogModule` interface

```go
type LogModule interface {
    Name() string
    ShouldLog(req *http.Request) bool
    ProcessRequest(req *http.Request) error
    ProcessResponse(resp *http.Response) error
}
```
([tlsproxy.go:110](tlsproxy.go#L110))

| Method | Called with | Purpose |
| --- | --- | --- |
| `Name()` | — | Short identifier used in log lines (`[MODULE] Registered: ...`) and error messages. |
| `ShouldLog(req)` | the decrypted request | Vote on whether this request/response pair should be written to the plain-text `proxy.log`. If **any** registered module returns `true`, the exchange is logged. |
| `ProcessRequest(req)` | the decrypted request, before it's forwarded upstream | Side-effect hook — inspect/extract data from the request. |
| `ProcessResponse(resp)` | the decrypted response, after it comes back from the real server | Side-effect hook — inspect/extract data from the response. |

Modules are **not** able to block, mutate, or redirect traffic — the
interface is purely observational (`ProcessRequest`/`ProcessResponse`
return only an `error`, which is logged but never stops the exchange).

## Registering modules

```go
func RegisterModule(module LogModule) {
    logModules = append(logModules, module)
    log.Printf("[MODULE] Registered: %s", module.Name())
}
```
([tlsproxy.go:117](tlsproxy.go#L117))

Modules are added to the global `logModules` slice at startup in
`initializeModules()`:

```go
func initializeModules() {
    RegisterModule(&AllTrafficModule{})
    RegisterModule(NewMonitoringModule())
    RegisterModule(NewTokenExportModule())
}
```
([tlsproxy.go:2529](tlsproxy.go#L2529))

There is no config-file or flag-driven way to enable/disable individual
modules today — the registered set is fixed in code.

## Execution pipeline

For every proxied HTTP(S) exchange:

1. **`forwardRequest()`** sends the request upstream and, immediately after
   receiving the response, calls `executeModulesResponse(resp)` — running
   every module's `ProcessResponse` ([tlsproxy.go:3038](tlsproxy.go#L3038)).
2. **`logRequest()`** then calls `executeModules(req)`, which runs every
   module's `ShouldLog` + `ProcessRequest` and returns `true` if any module
   voted to log; if so, a plain-text entry is appended to `proxy.log`
   ([tlsproxy.go:3043-3044](tlsproxy.go#L3043)).

```go
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
```
([tlsproxy.go:122](tlsproxy.go#L122))

> **Note:** `ProcessRequest`/`ProcessResponse` run for *every* module
> regardless of its own `ShouldLog` vote — `ShouldLog` only affects whether
> the exchange is written to `proxy.log`, not whether a module's own
> side effects (token extraction, dashboard capture, etc.) happen.

## Registered modules

### `AllTrafficModule` — `"AllTraffic"`
([tlsproxy.go:2383](tlsproxy.go#L2383))

Always votes `true` on `ShouldLog`; no `ProcessRequest`/`ProcessResponse`
side effects. Its only job is to guarantee that **all** traffic is written
to `proxy.log`, independent of what any other module decides. Because this
module is always registered, every other module's `ShouldLog` vote is
currently redundant — removing `AllTrafficModule` is the only way to get
selective logging based on another module's `ShouldLog` logic (e.g. `OAuthModule`, below).

### `MonitoringModule` — `"Monitor"`
([tlsproxy.go:1003](tlsproxy.go#L1003))

Feeds the web dashboard. On `ProcessResponse`, it builds a `TrafficEntry`
(method, URL, host, path, status, headers, truncated request/response
bodies up to `maxBodySize` = 10 KB, duration, TLS version, client address)
and appends it to the in-memory `trafficStore` (capped at the most recent
1000 entries, [tlsproxy.go:952](tlsproxy.go#L952)).

The monitor's HTTP server (`StartMonitorServer`, default port `4040`)
reads straight from `trafficStore` to serve:

| Route | Purpose |
| --- | --- |
| `GET /` | Dashboard UI (`handleIndex`) |
| `GET /api/entries` | JSON list of captured traffic |
| `GET /api/entry/{id}` | JSON detail for one entry |
| `POST /api/clear` | Clears `trafficStore` |
| `GET /api/stats` | Summary stats |
| `GET /ca-cert`, `GET /ca.crt` | Download the proxy's CA certificate |
| `GET /install-ca` | Self-service, OS-aware CA install page for remote clients |

([tlsproxy.go:1110-1118](tlsproxy.go#L1110))

### `TokenExportModule` — `"TokenExport"`
([tlsproxy.go:402](tlsproxy.go#L402))

The most active module — always votes `true` on `ShouldLog` and extracts
credentials from both requests and responses:

- **JWTs**: from `Authorization: Bearer ...` headers (request and
  response), `Set-Cookie` values that look like a JWT, and JSON/text
  response bodies. Parsed JWTs (header, payload, expiry, issuer, subject,
  audience, etc.) are appended to `captured_tokens.json` via
  `addJWTToken()` / `saveTokenExport()`.
- **OAuth tokens**: access/refresh tokens and related fields extracted
  from JSON or form-encoded request/response bodies
  (`extractOAuthTokensFromJSON`, `extractOAuthTokensFromForm`), appended
  via `addOAuthToken()`.
- **Cookies**: every `Set-Cookie` on a response is captured via
  `exportResponseCookies()` ([tlsproxy.go:693](tlsproxy.go#L693)) and
  written in [EditThisCookie](https://github.com/ETCExtension/EditThisCookie)-compatible
  format.

Output files (written to the current working directory, `0600`/`0644`
permissions, **contain live secrets** — see
[.gitignore](.gitignore)):

| File | Written by | Contents |
| --- | --- | --- |
| `captured_tokens.json` | `saveTokenExport()` | All captured JWTs, OAuth tokens, *and* cookies |
| `EditThisCookie_Sessions.json` | `exportResponseCookies()` | Cookies only, in EditThisCookie's import format |

## Defined but not registered

### `OAuthModule` — `"OAuth"`
([tlsproxy.go:2401](tlsproxy.go#L2401))

A selective module whose `ShouldLog` only returns `true` when the request
URL/path matches common OAuth/OIDC patterns (`/oauth`, `/token`,
`/authorize`, `/.well-known/openid`, `access_token`, etc.) or carries an
`Authorization` header — otherwise it just logs a detection message via
`log.Printf` and has no `ProcessRequest`/`ProcessResponse` side effects.

**This module exists in the code but is never passed to `RegisterModule`
in `initializeModules()`**, so it currently has no effect at runtime. It
looks like scaffolding for a future selective-logging mode (see the note
under `AllTrafficModule` above on why it's a no-op while `AllTrafficModule`
stays registered).

## Referenced but not implemented

A stray comment in the source —
`// ... (rest of the existing modules: DomainFilter, RequestModifier, etc.) ...`
([tlsproxy.go:2441](tlsproxy.go#L2441)) — references a `DomainFilter` and
a `RequestModifier` module. **Neither exists in the codebase.** Treat this
as an aspirational note left over from an earlier draft, not a feature
that's currently available.

## Adding a new module

1. Define a type implementing `LogModule`:

   ```go
   type MyModule struct{}

   func (m *MyModule) Name() string { return "MyModule" }
   func (m *MyModule) ShouldLog(req *http.Request) bool { return true }
   func (m *MyModule) ProcessRequest(req *http.Request) error { return nil }
   func (m *MyModule) ProcessResponse(resp *http.Response) error { return nil }
   ```

2. Register it in `initializeModules()`:

   ```go
   RegisterModule(&MyModule{})
   ```

3. Remember that `ProcessRequest`/`ProcessResponse` run on every request
   regardless of `ShouldLog`, and that with `AllTrafficModule` registered,
   every exchange is logged to `proxy.log` no matter what your module's
   `ShouldLog` returns — if you want genuinely selective logging, you'd
   need to remove `AllTrafficModule` from `initializeModules()` first.
