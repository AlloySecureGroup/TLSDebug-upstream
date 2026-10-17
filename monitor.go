package main

/*
Traffic dashboard.

MonitoringModule records each exchange in an in-memory ring of
maxTrafficEntries. The monitor HTTP server on the monitor port reads that
store. Nothing is authenticated: anyone who can open the port can read
captured headers, bodies, and the CA certificate. The listen address is
every interface because /install-ca is how a remote client downloads the
CA. The startup log says so.

Duration is the time from just before the origin request is sent until the
entry is stored, which includes the origin round trip. It is not the time
spent copying the body. stampForwardStart writes the start onto the
outgoing request's context; http.Client copies that request onto
resp.Request, which is what ProcessResponse sees.

Request bodies are stashed in monitorRequestBodies under the *url.URL
pointer. forwardRequest passes that same pointer through to the origin
client, and the response's Request.URL is that pointer again. The body is
taken back when the response is recorded. A failed forward leaks the entry
until the map exceeds 2000 keys, at which point the sweep drops some.

Response bodies are copied for display and truncated. Content-Encoding is
not removed. Gzip is decompressed for the copy. Brotli, zstd, and deflate
are labeled and left compressed.
*/

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// maxTrafficEntries is how many exchanges the dashboard keeps. Older rows
// fall off the front. Token export uses the same number for JWTs and
// OAuth tokens.
const maxTrafficEntries = 1000

// forwardStartKey is the context key for the time forwardRequest began.
// An empty struct as a key avoids colliding with any other package's
// context values.
type forwardStartKey struct{}

// stampForwardStart returns a shallow copy of req whose context records
// time.Now. The caller must use the returned request; WithContext does not
// modify req in place.
func stampForwardStart(req *http.Request) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), forwardStartKey{}, time.Now()))
}

func forwardStartedAt(req *http.Request) (time.Time, bool) {
	if req == nil {
		return time.Time{}, false
	}
	started, ok := req.Context().Value(forwardStartKey{}).(time.Time)
	return started, ok
}

// TrafficEntry is one row in the dashboard and one object in /api/entries.
// Duration is serialized as nanoseconds, which is what the page divides by
// 1e6 to show milliseconds.
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

// TrafficStore is the ring buffer behind the dashboard. GetEntries returns
// a reversed copy so the page sees newest first without the store itself
// being reordered under a writer.
type TrafficStore struct {
	sync.RWMutex
	entries    []TrafficEntry
	nextID     int
	maxEntries int
}

var trafficStore = &TrafficStore{
	entries:    make([]TrafficEntry, 0),
	nextID:     1,
	maxEntries: maxTrafficEntries,
}

// monitorRequestBodies holds request bodies captured before the origin
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
			copy := entry
			return &copy
		}
	}
	return nil
}

func (ts *TrafficStore) Clear() {
	ts.Lock()
	defer ts.Unlock()

	ts.entries = make([]TrafficEntry, 0)
}

// MonitoringModule feeds the dashboard. Both capture flags default on.
// maxBodySize is 10 KiB of text kept per body; the connection still carries
// the rest.
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

func (m *MonitoringModule) Name() string { return "Monitor" }

func (m *MonitoringModule) ShouldLog(req *http.Request) bool { return true }

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
	// Drop extras if forwarding fails and entries are never consumed.
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

	started, ok := forwardStartedAt(resp.Request)
	if !ok {
		started = time.Now()
	}

	entry := TrafficEntry{
		Timestamp:       time.Now(),
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

	entry.Duration = time.Since(started)
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

// StartMonitorServer listens on every interface at port and serves the
// dashboard, the JSON API, and the CA download. It returns immediately;
// the server runs until the process exits. There is no authentication.
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
	log.Printf("[MONITOR] WARNING: the dashboard has no authentication and listens on all interfaces")

	go func() {
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Printf("[MONITOR] Server error: %v", err)
		}
	}()
}

// handleCACertDownload serves the CA certificate from memory, so -certdir
// does not have to be readable by the client. The private key is not served.
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
