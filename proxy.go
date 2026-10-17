package main

/*
The accept loop and the origin client.

A browser configured to use this proxy speaks two dialects:

  - CONNECT host:443 opens a tunnel. The proxy answers "200 Connection
    Established", then does a TLS handshake as if it were that host. The
    decrypted bytes inside the tunnel are ordinary HTTP/1.1.
  - Anything else is plain HTTP. The absolute URL is forwarded as-is.

HTTP/2 is refused. PRI is the cleartext HTTP/2 preface. The server TLS
config does not advertise ALPN "h2", so a browser negotiates HTTP/1.1.
The origin client also stays on HTTP/1.1: a custom TLS config disables
HTTP/2 unless ForceAttemptHTTP2 is set, and it is not.

One http.Client is shared by every forwarded request. A client (and its
Transport) per request never reuses connections and abandons the
Transport's dialer until garbage collection. Redirects are not followed
here; the 3xx is returned to the browser, which decides what to do.
The client timeout is 30 seconds, including the response body.

Hop-by-hop headers describe this TCP connection, not the next one. They
are removed from the request before it is sent and from the response
before it is written to the client. End-to-end headers, including
Accept-Encoding and Content-Encoding, are kept.
*/

import (
	"bufio"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// mitmCipherSuites is what we are willing to speak. crypto/tls ignores the
// TLS 1.3 entries in CipherSuites; TLS 1.3 suite choice is built in
// (AES-GCM and ChaCha20). The TLS 1.2 names are the ones this list actually
// selects. The same list is used toward the browser and toward the origin.
func mitmCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_AES_256_GCM_SHA384,

		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}
}

func mitmCurves() []tls.CurveID {
	return []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	}
}

// originClient is the shared HTTP/1.1 client used for every forwarded
// request. Timeout covers the dial, the headers, and the body.
var originClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:       tls.VersionTLS12,
			MaxVersion:       tls.VersionTLS13,
			CipherSuites:     mitmCipherSuites(),
			CurvePreferences: mitmCurves(),
		},
		Proxy:             http.ProxyFromEnvironment,
		ForceAttemptHTTP2: false,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Timeout: 30 * time.Second,
}

// handleConnection reads one proxy request from a freshly accepted socket.
// CONNECT stays on this connection for many inner requests. Plain HTTP
// handles the one request ReadRequest already parsed. The deferred Close
// is the only close of clientConn; helpers must not close it again.
func handleConnection(clientConn net.Conn, config *ProxyConfig) {
	defer clientConn.Close()

	clientAddr := clientConn.RemoteAddr().String()
	log.Printf("[CONNECTION] New connection from %s", clientAddr)

	// The buffered reader may pull bytes past the end of the HTTP headers.
	// For CONNECT those extra bytes are the start of the TLS handshake and
	// have to be put back. See prependBuffered.
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
		handleConnect(reader, clientConn, req, config)
		return
	}

	log.Printf("[HTTP] %s %s", req.Method, req.URL.String())
	handleHTTP(clientConn, req, config)
}

// handleConnect finishes the tunnel: tell the client the tunnel is up,
// handshake TLS with a leaf for that host, then proxy HTTP/1.1 both ways
// until the client closes.
func handleConnect(reader *bufio.Reader, clientConn net.Conn, req *http.Request, config *ProxyConfig) {
	host := req.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		log.Printf("[CONNECT] Failed to accept tunnel to %s: %v", host, err)
		return
	}

	cert, err := getCertForHost(host)
	if err != nil {
		log.Printf("[TLS] Failed to generate certificate for %s: %v", host, err)
		return
	}

	tlsConfig := &tls.Config{
		Certificates:     []tls.Certificate{*cert},
		MinVersion:       tls.VersionTLS12,
		MaxVersion:       tls.VersionTLS13,
		CipherSuites:     mitmCipherSuites(),
		CurvePreferences: mitmCurves(),
		// Ignored since Go 1.17. TLS 1.3 does not use this preference bit,
		// and the TLS 1.2 suites above are already in the order we want.
		PreferServerCipherSuites: false,
	}

	tlsClientConn := tls.Server(prependBuffered(clientConn, reader), tlsConfig)
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

	tlsReader := bufio.NewReader(tlsClientConn)
	for {
		inner, err := http.ReadRequest(tlsReader)
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

		inner.URL.Scheme = "https"
		inner.URL.Host = inner.Host
		inner.RemoteAddr = clientConn.RemoteAddr().String()
		inner.TLS = &state

		logRequest(inner, config)

		resp, err := forwardRequest(inner)
		if err != nil {
			log.Printf("Failed to forward request: %v", err)
			tlsClientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}

		stripHopByHop(resp.Header)
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

// handleHTTP forwards one plaintext request. The connection close belongs
// to handleConnection.
func handleHTTP(clientConn net.Conn, req *http.Request, config *ProxyConfig) {
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

	stripHopByHop(resp.Header)
	resp.Write(clientConn)
}

// forwardRequest sends req to the origin and runs response modules before
// returning. The caller writes the body to the client after that, so the
// modules must rewind the body (see readAndRestoreResponseBody).
func forwardRequest(req *http.Request) (*http.Response, error) {
	outReq := &http.Request{
		Method:        req.Method,
		URL:           req.URL,
		Header:        req.Header.Clone(),
		Body:          req.Body,
		ContentLength: req.ContentLength,
		Host:          req.Host,
		GetBody:       req.GetBody,
	}

	outReq.RequestURI = ""
	outReq.RemoteAddr = req.RemoteAddr
	outReq.TLS = req.TLS
	stripHopByHop(outReq.Header)

	// The dashboard's Duration is measured from this stamp, not from when
	// the response body happens to be copied into the traffic store.
	outReq = stampForwardStart(outReq)

	resp, err := originClient.Do(outReq)
	if err != nil {
		return nil, err
	}

	executeModulesResponse(resp)
	return resp, nil
}

// stripHopByHop removes headers that belong to a single connection.
// Connection's own value is a list of extra hop-by-hop names the peer
// declared; those are removed too. End-to-end headers are left in place.
func stripHopByHop(h http.Header) {
	if h == nil {
		return
	}
	if connection := h.Get("Connection"); connection != "" {
		for _, field := range strings.Split(connection, ",") {
			name := strings.TrimSpace(field)
			if name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	} {
		h.Del(name)
	}
}

// prefixConn replays bytes a bufio.Reader already took off the socket.
// ReadRequest stops at the end of the headers, but the reader fills its
// buffer in chunks and may have consumed the first bytes of the TLS
// ClientHello. Those bytes are no longer available from a Read on the raw
// connection. The handshake has to see them first.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func prependBuffered(conn net.Conn, reader *bufio.Reader) net.Conn {
	n := reader.Buffered()
	if n == 0 {
		return conn
	}
	peeked, err := reader.Peek(n)
	if err != nil {
		return conn
	}
	prefix := make([]byte, n)
	copy(prefix, peeked)
	return &prefixConn{Conn: conn, prefix: prefix}
}
