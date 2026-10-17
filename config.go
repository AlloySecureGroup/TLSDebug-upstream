package main

/*
Certificate and server configuration.

proxy-config.ini is optional. A missing file means the built-in defaults.
The parser is a small INI reader, not a general one: it understands [sections],
"key = value" lines, and comments that start with # or ;.

Two kinds of settings live in the file:

  - CA and leaf certificate fields (names, lifetime, SAN, AIA, CRL, OCSP).
    These are read whenever the file exists. They affect certificates
    minted after the file is loaded. An existing CA on disk is reused and
    is not rewritten to match a changed name.

  - [server] port, cert_dir, and skip_install. These are defaults for the
    matching command-line flags. An explicit flag always wins, including
    when the operator passes the flag's own default. flag.Visit reports
    which flags were present on the command line.

The proxy port, certificate directory, and skip-install switch are not
stored on CertConfig. They belong to ProxyConfig, which is the runtime
choice for this process.
*/

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// ProxyConfig is the runtime choice for this process: where to listen,
// where to put the CA and the logs, and whether to touch the OS trust store.
type ProxyConfig struct {
	Port        int
	CertDir     string
	LogFile     string
	SkipInstall bool
}

// CertConfig describes the CA certificate and the per-host leaves minted
// from it. AIA, CRL, and OCSP URLs are optional extensions some enterprise
// TLS stacks expect to see; leaving them empty omits the extensions.
type CertConfig struct {
	Organization      string
	CommonName        string
	ValidityYears     int
	AIAURLs           string
	CRLDistPoints     []string
	OCSPServer        string
	DefaultSANs       []string
	HostValidityDays  int
	IncludeAIAInHosts bool
	IncludeCDPInHosts bool
}

// serverFileConfig holds the [server] keys that were present in the ini
// file. A nil pointer means the key was absent, which is different from an
// explicit false or zero.
type serverFileConfig struct {
	port        *int
	certDir     *string
	skipInstall *bool
}

// certConfig is the CA and leaf settings for this process. main loads it
// before any certificate is minted. Nil means those settings were not
// loaded, and leaf generation fails instead of signing a half-configured
// certificate.
var certConfig *CertConfig

func defaultCertConfig() *CertConfig {
	return &CertConfig{
		Organization:      "TLS Proxy CA",
		CommonName:        "TLS Proxy Root CA",
		ValidityYears:     10,
		AIAURLs:           "",
		CRLDistPoints:     []string{},
		OCSPServer:        "",
		DefaultSANs:       []string{"localhost", "127.0.0.1"},
		HostValidityDays:  365,
		IncludeAIAInHosts: false,
		IncludeCDPInHosts: false,
	}
}

// loadConfig reads proxy-config.ini. A missing or unreadable file is not
// fatal: the proxy starts with defaultCertConfig and no server overrides.
func loadConfig(configPath string) (*CertConfig, serverFileConfig) {
	config := defaultCertConfig()
	var server serverFileConfig

	if !fileExists(configPath) {
		log.Printf("Config file not found: %s (using defaults)", configPath)
		return config, server
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("Failed to read config file: %v (using defaults)", err)
		return config, server
	}

	lines := strings.Split(string(data), "\n")
	currentSection := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.Trim(line, "[]")
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if value == "" {
			continue
		}

		switch currentSection {
		case "server":
			applyServerKey(&server, key, value)
		case "ca_certificate":
			switch key {
			case "organization":
				config.Organization = value
			case "common_name":
				config.CommonName = value
			case "validity_years":
				if v, err := parseInt(value); err == nil {
					config.ValidityYears = v
				}
			}
		case "certificate_extensions":
			switch key {
			case "aia_urls":
				// Two URLs separated by "|": OCSP responder, then CA issuer.
				config.AIAURLs = value
			case "crl_distribution_points":
				config.CRLDistPoints = splitCSV(value)
			case "ocsp_url":
				config.OCSPServer = value
			}
		case "host_certificates":
			switch key {
			case "default_san_entries":
				config.DefaultSANs = splitCSV(value)
			case "validity_days":
				if v, err := parseInt(value); err == nil {
					config.HostValidityDays = v
				}
			case "include_aia_in_host_certs":
				config.IncludeAIAInHosts = parseBool(value)
			case "include_cdp_in_host_certs":
				config.IncludeCDPInHosts = parseBool(value)
			}
		}
	}

	log.Printf("Loaded configuration from: %s", configPath)
	return config, server
}

func applyServerKey(server *serverFileConfig, key, value string) {
	switch key {
	case "port":
		if v, err := parseInt(value); err == nil {
			server.port = &v
		}
	case "cert_dir":
		server.certDir = &value
	case "skip_install":
		v := parseBool(value)
		server.skipInstall = &v
	}
}

// explicitFlags is the set of flag names the operator actually typed.
// Visiting the default flag set is how we tell "omitted" from "passed the
// default value".
func explicitFlags() map[string]bool {
	set := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		set[f.Name] = true
	})
	return set
}

// applyServerFileConfig copies [server] into cfg for flags that were not
// present on the command line. LogFile is rebuilt when cert_dir changes so
// proxy.log stays next to the CA.
func applyServerFileConfig(explicit map[string]bool, cfg *ProxyConfig, file serverFileConfig) {
	if cfg == nil {
		return
	}
	if file.port != nil && !explicit["port"] {
		cfg.Port = *file.port
	}
	if file.certDir != nil && !explicit["certdir"] {
		cfg.CertDir = *file.certDir
		cfg.LogFile = filepath.Join(*file.certDir, logFile)
	}
	if file.skipInstall != nil && !explicit["skip-install"] {
		cfg.SkipInstall = *file.skipInstall
	}
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseInt(s string) (int, error) {
	var result int
	_, err := fmt.Sscanf(s, "%d", &result)
	return result, err
}

func parseBool(s string) bool {
	switch strings.ToLower(s) {
	case "true", "yes", "1", "on":
		return true
	default:
		return false
	}
}

// fileExists reports whether path is an existing file or directory.
// A permission error is reported as "does not exist", which makes the
// caller try to create or skip the path rather than treat it as present.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
