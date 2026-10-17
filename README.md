# TLS Debugging Proxy

A minimalist TLS intercepting proxy written in Go. One module, no external dependencies, cross-platform. The source is split by job (`main.go`, `proxy.go`, `ca.go`, `certs.go`, `tokens.go`, `monitor.go`, and the files next to them) so each piece can be read on its own.

## Features

- Automatic CA certificate generation and system installation
- TLS 1.2 and TLS 1.3 support
- Request/response logging with headers and POST parameters
- Console output sanitization (prevents terminal beeping)
- Extensible logging module system
- Configurable certificate extensions (SAN, AIA, CDP, OCSP)
- Single binary, no dependencies
- Cross-platform (Windows, macOS, Linux)

## Quick Start

```bash
# Build the package in this directory.
go build -o tlsproxy .

# Run (attempts automatic certificate installation)
./tlsproxy

# Skip automatic installation
./tlsproxy --skip-install
```

`go build` compiles the module in the current directory. The source is several
`package main` files, so the argument is `.`.

The proxy listens on `localhost:8080` by default.

## Certificate Installation

The proxy generates `proxy-ca.crt` and `proxy-ca.key` only when a pair is not
already present in `-certdir`. On every native start it compares the exact
SHA-256 fingerprint with the relevant Windows, macOS, or Linux trust store.
It reuses a matching CA without changing the trust store and invokes the
platform installer only when that exact CA is absent.

Keep both files together and protect `proxy-ca.key`. The key is written mode
`0600`. Copying only one file or replacing either file creates an unusable pair.

### Windows

**Command Line:**
```cmd
# User store
certutil -addstore -user Root proxy-ca.crt

# System store (requires Admin)
certutil -addstore Root proxy-ca.crt
```

**GUI Method:**
1. Double-click `proxy-ca.crt`
2. Install Certificate → Current User
3. Place in "Trusted Root Certification Authorities"

**Verify:**
```cmd
certutil -user -verifystore Root "TLS Proxy Root CA"
```

### macOS

**Command Line:**
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain proxy-ca.crt
```

**GUI Method:**
Double-click `proxy-ca.crt` → Keychain Access → Always Trust

### Linux

**System-Wide:**
```bash
# Ubuntu/Debian
sudo cp proxy-ca.crt /usr/local/share/ca-certificates/tlsproxy.crt
sudo update-ca-certificates

# RHEL/CentOS/Fedora
sudo cp proxy-ca.crt /etc/pki/ca-trust/source/anchors/tlsproxy.crt
sudo update-ca-trust
```

### Chrome/Chromium on Linux

Chrome requires the certificate in its own NSS database:

```bash
# Install certutil if needed
sudo apt install libnss3-tools

# Add certificate to Chrome's certificate database
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "TLSDebug CA" -i proxy-ca.crt
```

**Verify installation:**
```bash
certutil -d sql:$HOME/.pki/nssdb -L
```

**Important:** Restart Chrome completely after installation.

### Firefox

Firefox uses its own certificate store:

1. Settings → Privacy & Security → Certificates → View Certificates
2. Authorities → Import
3. Select `proxy-ca.crt`
4. Check "Trust this CA to identify websites"

## Exporting the CA Certificate to Another Machine

If the proxy runs somewhere your browser doesn't have filesystem access to — a
remote host, a container, a VM — you don't need to `docker cp` or `scp`
`proxy-ca.crt` around. There are three ways to get it out, in order of
convenience:

**1. Download it while the proxy is running:**
```bash
curl -o proxy-ca.crt http://<proxy-host>:4040/ca-cert
```
or on Windows:
```powershell
Invoke-WebRequest http://<proxy-host>:4040/ca-cert -OutFile proxy-ca.crt
```
This serves the certificate from memory (whatever `-certdir` is set to
doesn't matter) on the same port as the web monitor.

**2. Export it without starting the proxy:**
```bash
./tlsproxy -export-ca proxy-ca.crt   # write to a file
./tlsproxy -export-ca -              # print PEM to stdout
```

**3. Copy it from the console output:** every startup logs the full CA
certificate PEM plus ready-to-run Windows import commands (see next
section) — useful when you only have log access (e.g. `docker logs`) and no
network path to the monitor port at all.

### One-step import on a Windows workstation

Combine method 1 with PowerShell's `Import-Certificate` to fetch and install
in a single command (no admin rights needed for the current-user store):
```powershell
Invoke-WebRequest http://<proxy-host>:4040/ca-cert -OutFile "$env:TEMP\tlsproxy-ca.crt"
Import-Certificate -FilePath "$env:TEMP\tlsproxy-ca.crt" -CertStoreLocation Cert:\CurrentUser\Root
```
Replace `<proxy-host>` with `localhost` if the proxy is local, or the
machine's actual address/port-forward target otherwise.

## Usage

### Configure Your Client

**Browser:**
- Proxy: `localhost`
- Port: `8080`

**Command Line:**
```bash
# Environment variables
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080

# Test with curl
curl -x http://localhost:8080 https://example.com
```

**Python:**
```python
import requests
proxies = {
    'http': 'http://localhost:8080',
    'https': 'http://localhost:8080'
}
requests.get('https://api.example.com', proxies=proxies, verify='proxy-ca.crt')
```

### Command Line Options

```
-port int          Proxy port (default 8080)
-monitor-port int  Web monitor port, also serves /ca-cert (default 4040)
-certdir string    Certificate directory (default ".")
-config string     Configuration file (default "proxy-config.ini")
-export-ca string  Export the CA certificate PEM to this path ('-' for stdout) and exit
-cleanup          Remove CA certificates and exit
-skip-install     Skip automatic certificate installation
```

### Cleanup

Remove CA certificate from system:
```bash
./tlsproxy -cleanup
```

## Logging Modules

The proxy includes an extensible, **observational** module system: every
request/response is handed to each registered module, which votes on
whether to log it to `proxy.log` and can extract/export data as a side
effect. Modules cannot filter, block, or modify traffic itself.

### Built-in Modules (registered by default)

**AllTrafficModule** - Always votes to log every exchange

**MonitoringModule** - Feeds the web dashboard (port 4040) with captured traffic

**TokenExportModule** - Extracts JWTs, OAuth tokens, and cookies to `captured_tokens.json` / `EditThisCookie_Sessions.json` in `-certdir` (mode `0600`)

### Available but not registered

**OAuthModule** - Only votes to log OAuth/authentication-looking requests; defined in `modules.go` but not added in `initializeModules()` today (with `AllTrafficModule` also registered, logging is effectively "log everything" regardless).

### Enable Modules

Edit `initializeModules()` in `main.go`:
```go
func initializeModules() {
    RegisterModule(&AllTrafficModule{})
    RegisterModule(NewMonitoringModule())
    RegisterModule(NewTokenExportModule())

    // Also available:
    // RegisterModule(&OAuthModule{})
}
```

See `MODULES.md` for the full module reference and a guide to writing custom modules.

## Configuration File

Optional `proxy-config.ini` for advanced settings.

`[server]` is a default for the matching flag. `-port`, `-certdir`, and
`-skip-install` win when they are present on the command line, even if the
value typed is the flag's own default. Omit the flag to take the value from
the file.

```ini
[server]
port = 8080
cert_dir = .
skip_install = false

[ca_certificate]
organization = TLS Proxy CA
common_name = TLS Proxy Root CA
validity_years = 10

[certificate_extensions]
# Authority Information Access
aia_urls = http://ocsp.proxy.local|http://ca.issuer.local/ca.crt

# CRL Distribution Points
crl_distribution_points = http://crl.proxy.local/proxy-ca.crl

# OCSP Server
ocsp_url = http://ocsp.proxy.local

[host_certificates]
# Default SAN entries
default_san_entries = localhost,127.0.0.1,*.local

# Validity period (days)
validity_days = 365

# Include extensions in host certificates
include_aia_in_host_certs = false
include_cdp_in_host_certs = false
```

## Log Format

Traffic is logged to console and `proxy.log`:

```
2025/01/13 14:30:45 Proxy listening on port 8080
2025/01/13 14:30:45 CA certificate: ./proxy-ca.crt
2025/01/13 14:30:50 [CONNECTION] New connection from 127.0.0.1:54321
2025/01/13 14:30:50 [CONNECT] 127.0.0.1:54321 -> example.com:443
2025/01/13 14:30:50 [TLS] example.com:443 using TLS 1.3 with cipher TLS_AES_128_GCM_SHA256

=== 2025-01-13 14:30:45 ===
GET https://example.com/api/data
Headers:
  User-Agent: Mozilla/5.0
  Accept: application/json
```

**Output Sanitization:**
- Control characters are escaped to prevent terminal beeping
- Binary content shown as `[Binary data, N bytes]`
- Large bodies (>10KB) truncated in console output only
- Full text bodies are written to `proxy.log`
- `proxy.log`, `captured_tokens.json`, and `EditThisCookie_Sessions.json` are created in `-certdir` with mode `0600`

## Troubleshooting

### Certificate Errors in Chrome (Linux)

If you see certificate errors in Chrome after system installation:

1. **Install to Chrome's NSS database:**
   ```bash
   sudo apt install libnss3-tools
   certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "TLSDebug CA" -i proxy-ca.crt
   ```

2. **Verify installation:**
   ```bash
   certutil -d sql:$HOME/.pki/nssdb -L | grep "TLSDebug CA"
   ```

3. **Restart Chrome completely** (close all windows and background processes)

### Other Issues

**Certificate installation failed (Windows):**
- Run `install-cert-windows.bat` as Administrator
- Or use GUI: double-click `proxy-ca.crt`

**Certificate installation failed (macOS/Linux):**
- Enter sudo password when prompted
- Check console for error messages

**Connection refused:**
- Verify proxy is running: `netstat -an | grep 8080`
- Check firewall settings
- Try different port: `./tlsproxy -port 9090`

**TLS handshake failures:**
- Check console for TLS version logs
- Proxy supports both TLS 1.2 and 1.3
- Some servers may require specific versions

**Nothing in logs:**
- Verify client proxy settings
- Check `proxy.log` permissions
- Look for connection errors in console

**Terminal beeping:**
- Console output is automatically sanitized
- Control characters shown as `\xHH`
- Binary data shown as `[Binary data, N bytes]`
- Raw data available in `proxy.log`

## Technical Details

### HTTP and compression

The proxy speaks HTTP/1.1 only. A cleartext HTTP/2 preface (`PRI`) is rejected, the TLS listener does not advertise `h2`, and the connection to the origin is HTTP/1.1 as well. Browsers fall back to HTTP/1.1 inside the tunnel.

Gzip bodies are decompressed for the dashboard, `proxy.log` request bodies, and token scanning. The bytes and `Content-Encoding` forwarded to the client are the originals. Brotli, zstd, and deflate are not decoded; `Set-Cookie` is still captured, and the dashboard says the body could not be displayed.

One shared HTTP client talks to origin servers, so connections are reused. Redirects are returned to the browser rather than followed by the proxy. Hop-by-hop headers (`Connection`, `Keep-Alive`, `Proxy-Authorization`, `Transfer-Encoding`, `Upgrade`, and the names listed in `Connection`) are removed before a message is forwarded.

### TLS Support

**Versions:** TLS 1.2, TLS 1.3

**Cipher Suites:**
- TLS 1.3: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
- TLS 1.2: ECDHE-RSA/ECDSA with AES-GCM and ChaCha20-Poly1305

### Certificate Extensions

**SAN (Subject Alternative Names):**
- Auto-includes target hostname
- Adds wildcards (e.g., `*.example.com`)
- Supports DNS names and IP addresses

**AIA (Authority Information Access):**
- OCSP responder and CA issuer locations
- Optional for host certificates

**CDP (CRL Distribution Points):**
- Certificate revocation list URLs
- Optional for host certificates

**OCSP (Online Certificate Status Protocol):**
- Real-time revocation checking

View certificate details:
```bash
openssl x509 -in proxy-ca.crt -text -noout
```

## Security Notes

**This tool performs man-in-the-middle TLS interception:**
- Only use on networks/applications you own or control
- Keep `proxy-ca.key` secure (never share)
- Remove CA certificate when done testing
- Never use in production environments
- The monitor (port 4040 by default) has no authentication and listens on all interfaces, because `/install-ca` is how a remote client downloads the CA. Anyone who can reach that port can read captured traffic and download the CA certificate. Do not expose it beyond a network you control.

## Build for Other Platforms

Each command builds this directory as one package. On Apple Silicon the
native binary is `tlsproxy-mac-arm`.

```bash
# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w" -o tlsproxy-mac-arm .

# macOS (Intel)
GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o tlsproxy-mac .

# Linux
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o tlsproxy-linux .

# Windows (PowerShell)
$env:GOOS="windows"; $env:GOARCH="amd64"; go build -ldflags "-s -w" -o tlsproxy.exe .

# Windows (CMD)
set GOOS=windows&& set GOARCH=amd64&& go build -ldflags "-s -w" -o tlsproxy.exe .
```

## Files

Source, still `package main`:

- `go.mod` - Module path `tlsdebug`, standard library only
- `main.go` - Flags, startup, module registration
- `config.go` - `proxy-config.ini`
- `ca.go` - CA generate, load, trust-store check, install
- `certs.go` - Per-host leaf certificates
- `proxy.go` - Accept loop, CONNECT, forwarding
- `modules.go` - `LogModule`, AllTraffic, OAuth example
- `logging.go` - `proxy.log` and body buffering
- `tokens.go` - JWT, OAuth, and cookie export
- `monitor.go` - Dashboard store and JSON API
- `monitor_page.go` - Dashboard and CA install pages
- `tlsproxy_test.go` - CA fingerprint tests (`go test .`)

Runtime:

- `proxy-config.ini` - Configuration (optional)
- `proxy-ca.crt` - CA certificate (install this)
- `proxy-ca.key` - CA private key (mode `0600`, keep secure)
- `proxy.log` - Traffic logs (mode `0600`, in `-certdir`)
- `captured_tokens.json` - Captured JWTs, OAuth tokens, and cookies (mode `0600`, in `-certdir`). JWTs and OAuth tokens are capped at the newest 1000.
- `EditThisCookie_Sessions.json` - Cookie import file (mode `0600`, in `-certdir`)
- `MODULES.md` - Module development guide

## License

MIT - Use at your own risk for legitimate debugging/testing purposes only.
