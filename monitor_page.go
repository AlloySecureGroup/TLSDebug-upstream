package main

/*
Web monitor pages.

Two HTML documents are served by the monitor:

  - "/" is the traffic dashboard. It polls /api/entries and renders rows in
    the browser. Values that came from the network (method, host, path,
    headers, bodies) are escaped before they are concatenated into HTML.
    A hostile site, or a client sending a weird method, must not be able
    to run script in the operator's browser.

  - "/install-ca" is the self-service page a remote client opens to
    download this proxy's CA and trust it. The download link is built from
    the request Host so it works for localhost, a LAN address, or a port
    forward. Those substituted strings are HTML-escaped for the same reason.

The pages are raw strings so the proxy stays one binary with no embedded
file system and no extra dependencies.
*/

import (
	"fmt"
	"html"
	"net/http"
	"strings"
)

// handleInstallCAPage serves OS-specific instructions for trusting the CA.
// The certificate bytes themselves are downloaded from /ca-cert.
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

	// Host and the certificate subject are attacker-influenced (a client
	// chooses the Host header; the ini file chooses the subject). Both are
	// inserted into HTML and into shell snippets, so they are escaped.
	page := strings.NewReplacer(
		"{{DOWNLOAD_URL}}", html.EscapeString(downloadURL),
		"{{SUBJECT}}", html.EscapeString(subject),
		"{{EXPIRY}}", html.EscapeString(expiry),
	).Replace(installCAPageHTML)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, page)
}

// handleIndex serves the dashboard shell. The traffic itself arrives later
// as JSON from /api/entries; this response is static.
func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, dashboardHTML)
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

const dashboardHTML = `<!DOCTYPE html>
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
                
                return '<tr onclick="showDetails(' + entry.ID + ')"><td class="timestamp">' + time + '</td><td><span class="method ' + escapeHtml(entry.Method) + '">' + escapeHtml(entry.Method) + '</span></td><td>' + escapeHtml(entry.Host) + '</td><td class="url">' + escapeHtml(entry.Path) + '</td><td><span class="status ' + statusClass + '">' + (entry.StatusCode || '-') + '</span></td><td>' + duration + '</td><td>' + escapeHtml(entry.ContentType || '-') + '</td></tr>';
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
                html += '<div><div class="label">Method:</div><div class="value"><span class="method ' + escapeHtml(entry.Method) + '">' + escapeHtml(entry.Method) + '</span></div></div>';
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
            div.textContent = String(text);
            return div.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
        }
        
        startAutoRefresh();
        loadEntries();
    </script>
</body>
</html>`
