package main

/*
TLS intercepting proxy.

A normal HTTPS connection is encrypted end to end, so a proxy on the path
cannot read it. This program is a debugging proxy that the client has been
told to trust. For each connection it does three things:

  1. Terminates TLS with a certificate it signed itself. The client accepts
     that certificate only because it trusts this proxy's private CA.
  2. Reads the decrypted HTTP/1.1 request, hands it to the logging modules,
     and opens its own HTTP/1.1 connection to the real site.
  3. Writes the site's response back to the client, re-encrypted with the
     certificate from step 1.

HTTP/2 is not implemented. A cleartext HTTP/2 preface (method PRI) is
rejected. The TLS listener does not advertise "h2", so browsers fall back
to HTTP/1.1 inside the tunnel. The connection to the origin is HTTP/1.1 too.

Gzip bodies are decompressed only for the dashboard, proxy.log, and token
scanning. The bytes and Content-Encoding forwarded to the client stay as
the origin sent them. Brotli, zstd, and deflate are not decoded.

The rest of this package is split by job: CA and leaf certificates, the
accept loop, logging modules, token export, and the web monitor. It is
still one binary with no external dependencies.
*/

import (
	"flag"
	"fmt"
	"log"
	"net"
	"path/filepath"
)

const (
	caCertFile = "proxy-ca.crt"
	caKeyFile  = "proxy-ca.key"
	logFile    = "proxy.log"
)

// verboseMode prints each logged exchange to the terminal, truncated and
// sanitized. The full text still goes to proxy.log either way.
var verboseMode bool

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

	// Flags win over the ini file. loadConfig records [server] values, and
	// applyServerFileConfig copies them in only for flags the operator did
	// not set on the command line. certConfig is package state: leaf
	// generation and the CA writer read it from other files.
	var serverFile serverFileConfig
	certConfig, serverFile = loadConfig(*configFile)
	config := &ProxyConfig{
		Port:        *port,
		CertDir:     *certDir,
		LogFile:     filepath.Join(*certDir, logFile),
		SkipInstall: *skipInstall,
	}
	applyServerFileConfig(explicitFlags(), config, serverFile)

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

// initializeModules registers the observers that see every decrypted
// exchange. Registration order is the order ProcessRequest and
// ProcessResponse run.
//
// AllTrafficModule always votes to log. While it is registered, every
// other module's ShouldLog vote is redundant: one true vote is enough.
// OAuthModule is the example of a selective vote and is left unregistered
// on purpose. Registering it next to AllTraffic would not change what is
// written to proxy.log.
func initializeModules() {
	log.Println("Initializing logging modules...")

	RegisterModule(&AllTrafficModule{})
	RegisterModule(NewMonitoringModule())
	RegisterModule(NewTokenExportModule())

	log.Printf("Total modules registered: %d", len(logModules))
}
