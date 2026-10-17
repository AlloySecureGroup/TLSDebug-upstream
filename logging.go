package main

/*
Body buffering, proxy.log, and console sanitizing.

An HTTP body is a stream. The proxy has to show it to several readers (the
token module, the dashboard, proxy.log, and then the real destination) but
the socket can only produce those bytes once. bufferRequestBody and
readAndRestoreResponseBody read the stream into a cachedBody. Later readers
rewind that buffer and see the same bytes. The destination therefore gets
the original body, not a summary and not a decompressed replacement.

Gzip is decompressed only into the copy that is displayed or scanned.
Content-Encoding on the wire is left alone. Brotli, zstd, and deflate are
not decoded; the dashboard says so instead of printing compressed bytes
as if they were text.

proxy.log is opened mode 0600 because it contains request headers, cookies,
and bodies. Console output is a separate, truncated, sanitized view so a
binary body cannot ring the terminal bell.
*/

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	logMutex  sync.Mutex
	logWriter *os.File
)

// cachedBody is a body that has already been pulled off the network.
// pos is the next byte a Read will return. rewind sets pos back to the
// start so the next consumer sees the full body. Close does not discard
// the bytes: the HTTP stack closes a body when it is done reading, and a
// later stage may still need it.
type cachedBody struct {
	data []byte
	pos  int
}

func newCachedBody(data []byte) *cachedBody {
	return &cachedBody{data: data}
}

func (b *cachedBody) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.pos:])
	b.pos += n
	return n, nil
}

func (b *cachedBody) Close() error { return nil }

func (b *cachedBody) rewind() { b.pos = 0 }

// bufferRequestBody reads req.Body once and replaces it with a cachedBody.
// A second call is a no-op, which is what makes the token module, the
// dashboard, and proxy.log share one read.
//
// Content-Length is set to the buffered size and Transfer-Encoding is
// removed. The body is no longer chunked; it is a known number of bytes.
// GetBody lets the shared origin client retry without finding the body
// already consumed.
func bufferRequestBody(req *http.Request) error {
	if req == nil || req.Body == nil {
		return nil
	}
	if _, ok := req.Body.(*cachedBody); ok {
		return nil
	}

	data, err := io.ReadAll(req.Body)
	closeErr := req.Body.Close()
	req.Body = newCachedBody(data)
	req.ContentLength = int64(len(data))
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))
	req.Header.Del("Transfer-Encoding")
	req.GetBody = func() (io.ReadCloser, error) {
		return newCachedBody(data), nil
	}
	if err != nil {
		return err
	}
	return closeErr
}

// readAndRestoreRequestBody returns the request body and leaves req.Body
// positioned at the first byte. Callers may inspect the slice. They must
// not keep it and assume a later rewrite of req.Body will update it.
func readAndRestoreRequestBody(req *http.Request) ([]byte, error) {
	if req == nil || req.Body == nil {
		return nil, nil
	}
	if err := bufferRequestBody(req); err != nil {
		if cached, ok := req.Body.(*cachedBody); ok {
			cached.rewind()
			return cached.data, err
		}
		return nil, err
	}
	cached := req.Body.(*cachedBody)
	cached.rewind()
	return cached.data, nil
}

// readAndRestoreResponseBody buffers resp.Body the same way. The first
// caller pays for the network read. The monitor and the token module both
// call this, and resp.Write is the last reader. Rewinding on every call
// is what keeps that last reader from seeing EOF.
func readAndRestoreResponseBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}
	if cached, ok := resp.Body.(*cachedBody); ok {
		cached.rewind()
		return cached.data, nil
	}
	original := resp.Body
	data, err := io.ReadAll(original)
	original.Close()
	resp.Body = newCachedBody(data)
	return data, err
}

func gunzipBytes(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// formatCapturedBody prepares a body for the dashboard. Binary signatures
// and non-text samples are replaced with a length note. Text longer than
// max is cut; the connection still carries the full body.
func formatCapturedBody(data []byte, max int) string {
	if isBinaryContent(data) {
		return fmt.Sprintf("[Binary content, %d bytes]", len(data))
	}
	if max > 0 && len(data) > max {
		return string(data[:max]) + fmt.Sprintf("... [truncated, %d more bytes]", len(data)-max)
	}
	return string(data)
}

// tlsVersionName renders a crypto/tls version number for logs and the
// dashboard. Unknown non-zero values are shown as hex so a future version
// is visible instead of being dropped.
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

// sanitizeForConsole strips the bytes that ring a terminal bell or move
// the cursor. Printable ASCII, newlines, tabs, and non-ASCII runes pass
// through. Other control bytes become \xHH, and a long run of them is
// collapsed so one binary body cannot flood the terminal.
func sanitizeForConsole(data string) string {
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
		}
	}

	return result.String()
}

// isBinaryContent is a heuristic, not a MIME parser. It recognizes a few
// file signatures (including gzip, so a still-compressed body is not
// printed as text) and otherwise samples the first 512 bytes for NULs
// and control characters.
func isBinaryContent(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	if len(data) >= 4 {
		if data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47 {
			return true
		}
		if data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
			return true
		}
		if data[0] == 0x25 && data[1] == 0x50 && data[2] == 0x44 && data[3] == 0x46 {
			return true
		}
		if data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04 {
			return true
		}
		if data[0] == 0x47 && data[1] == 0x49 && data[2] == 0x46 {
			return true
		}
		if data[0] == 0x1F && data[1] == 0x8B {
			return true
		}
	}

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
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			controlCount++
		}
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			nonPrintableCount++
		} else if b == 127 || (b >= 128 && b < 160) {
			nonPrintableCount++
		}
	}

	if nullCount > sampleSize/10 {
		return true
	}
	if controlCount > sampleSize*3/10 {
		return true
	}
	if nonPrintableCount > sampleSize/5 {
		return true
	}
	return false
}

// openProxyLog appends to the transcript. O_CREATE uses 0600, and Chmod
// tightens a file that already existed with a looser mode.
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

// logRequest buffers the body, runs the modules, and appends a text
// transcript when any module voted to log. The transcript records the
// request, not the response. Response bodies are on the dashboard.
func logRequest(req *http.Request, config *ProxyConfig) {
	// Buffer before the modules run so every observer shares one read
	// and the origin client still has a body to send.
	if err := bufferRequestBody(req); err != nil {
		log.Printf("Failed to buffer request body: %v", err)
	}

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
