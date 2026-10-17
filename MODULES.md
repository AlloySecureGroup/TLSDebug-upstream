# Logging Modules

TLSDebug's traffic inspection is built around a small plugin system:
every decrypted request/response that passes through the proxy is handed
to a list of registered **modules**, each of which decides whether to log
it and what to do with it. This document describes that system as it
exists today. The implementation lives in [modules.go](modules.go),
[main.go](main.go) (`initializeModules`), [monitor.go](monitor.go),
[tokens.go](tokens.go), [proxy.go](proxy.go), and [logging.go](logging.go).

## The `LogModule` interface

```go
type LogModule interface {
    Name() string
    ShouldLog(req *http.Request) bool
    ProcessRequest(req *http.Request) error
    ProcessResponse(resp *http.Response) error
}
```
([modules.go](modules.go))

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
([modules.go](modules.go))

Modules are added to the global `logModules` slice at startup in
`initializeModules()` in [main.go](main.go):

```go
func initializeModules() {
    RegisterModule(&AllTrafficModule{})
    RegisterModule(NewMonitoringModule())
    RegisterModule(NewTokenExportModule())
}
```
([main.go](main.go))

There is no config-file or flag-driven way to enable/disable individual
modules today — the registered set is fixed in code.

## Execution pipeline

For every proxied HTTP(S) exchange:

1. **`logRequest()`** in [logging.go](logging.go) buffers the request body
   once, then calls `executeModules(req)`. That runs every module's
   `ShouldLog` and `ProcessRequest`, and returns true if any module voted
   to log. If so, a plain-text entry is appended to `proxy.log`.
   Later readers rewind the same buffer, so the origin still receives the
   original bytes.
2. **`forwardRequest()`** in [proxy.go](proxy.go) strips hop-by-hop headers,
   stamps the start time, and sends the request on a shared HTTP client.
   When the origin answers, it calls `executeModulesResponse(resp)`, which
   runs every module's `ProcessResponse`. Response bodies are buffered once
   the same way and rewound before the bytes are written to the client.
   The dashboard duration includes this origin round trip.

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
([modules.go](modules.go))

> **Note:** `ProcessRequest`/`ProcessResponse` run for *every* module
> regardless of its own `ShouldLog` vote — `ShouldLog` only affects whether
> the exchange is written to `proxy.log`, not whether a module's own
> side effects (token extraction, dashboard capture, etc.) happen.

## Registered modules

### `AllTrafficModule` — `"AllTraffic"`
([modules.go](modules.go))

Always votes `true` on `ShouldLog`; no `ProcessRequest`/`ProcessResponse`
side effects. Its only job is to guarantee that **all** traffic is written
to `proxy.log`, independent of what any other module decides. Because this
module is always registered, every other module's `ShouldLog` vote is
currently redundant — removing `AllTrafficModule` is the only way to get
selective logging based on another module's `ShouldLog` logic (e.g. `OAuthModule`, below).

### `MonitoringModule` — `"Monitor"`
([monitor.go](monitor.go))

Feeds the web dashboard. On `ProcessRequest` it captures the request body
(the upstream client consumes the body later). On `ProcessResponse` it builds a `TrafficEntry`
(method, URL, host, path, status, headers, truncated request/response
bodies up to `maxBodySize` = 10 KiB, duration, TLS version, client address)
and appends it to the in-memory `trafficStore` (capped at the most recent
1000 entries). `Duration` starts just before the origin request is sent.
Response bodies are copied for display; `Content-Encoding` is not removed.
Gzip is decompressed for that copy. Brotli, zstd, and deflate are labeled
and left compressed.

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

([monitor.go](monitor.go))

### `TokenExportModule` — `"TokenExport"`
([tokens.go](tokens.go))

The most active module — always votes `true` on `ShouldLog` and extracts
credentials from both requests and responses:

- **JWTs**: from `Authorization: Bearer ...` headers (request and
  response), `Set-Cookie` values that look like a JWT, and JSON/text
  response bodies, including compact JSON. Parsed JWTs (header, payload, expiry, issuer, subject,
  audience, etc.) are appended to `captured_tokens.json` via
  `addJWTToken()` / `persistTokenExport()`. Access tokens and ID tokens that are themselves JWTs are decoded too.
- **OAuth tokens**: access/refresh tokens and related fields extracted
  from JSON or form-encoded request/response bodies
  (`extractOAuthTokensFromJSON`, `extractOAuthTokensFromForm`), appended
  via `recordOAuthToken()`.
- **Cookies**: every `Set-Cookie` on a response is captured via
  `exportResponseCookies()`, including when the body uses brotli, zstd, or deflate.
  Cookies are keyed by name, domain, and path. `Max-Age` becomes `expirationDate`;
  `Max-Age=0` removes a previously captured cookie. Domain cookies keep a leading dot for EditThisCookie.

Inspection decompresses a copy of gzip bodies. The response forwarded to the client keeps its original bytes and `Content-Encoding`.

Output files are written to `-certdir` (the same directory as `proxy.log`), mode `0600`, and reloaded on startup. Writes are atomic and happen outside the in-memory lock. JWTs and OAuth tokens are capped at the newest 1000; cookies are not capped. The files **contain live secrets** — see
[.gitignore](.gitignore):

| File | Written by | Contents |
| --- | --- | --- |
| `captured_tokens.json` | `persistTokenExport()` | All captured JWTs, OAuth tokens, *and* cookies |
| `EditThisCookie_Sessions.json` | `persistTokenExport()` | Cookies only, in EditThisCookie's import format |

## Defined but not registered

### `OAuthModule` — `"OAuth"`
([modules.go](modules.go))

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

## Not implemented

`DomainFilter` and `RequestModifier` are not part of this proxy. An old
comment in the single-file source mentioned them; that comment is gone.
A module still cannot change the request. `ProcessRequest` and
`ProcessResponse` are observed and their errors are logged.

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
