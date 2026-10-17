package main

/*
Leaf certificates.

The CA is long-lived and trusted by the client. A leaf is minted per
hostname the first time that host is seen, signed by the CA, and cached
for the life of the process. The client checks the leaf name against the
host in the URL, so the leaf's Subject Alternative Name has to contain
that host. The CA subject is not what the client compares.

Names:

  - The requested host is always included.
  - default_san_entries from the ini file are added to every leaf. That is
    how localhost and 127.0.0.1 work on a certificate that was minted for
    some other site.
  - A DNS wildcard is added only for a hostname with more than one dot
    (a.b.example.com gets *.b.example.com). example.com does not become
    *.com. An IP address does not get a wildcard either: 192.168.1.1 would
    otherwise be treated as a DNS name and produce *.168.1.1.

Leaf keys are RSA-2048, same as the CA. Generation is the slow part, which
is why the cache is there. Entries are not expired; the process restart
that rotates nothing still regenerates leaves because they are not written
to disk.
*/

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// CertCache stores one leaf per hostname. The first request for a host
// generates; later requests reuse. The double-checked lock keeps the fast
// path on a read lock.
type CertCache struct {
	sync.RWMutex
	certs map[string]*tls.Certificate
}

var certCache = &CertCache{certs: make(map[string]*tls.Certificate)}

// getCertForHost returns the cached leaf for host, generating one on a
// miss. host may be "example.com:443"; the port is not part of the
// certificate name. A generation failure is not cached, so the next
// request can try again.
func getCertForHost(host string) (*tls.Certificate, error) {
	hostname := strings.Split(host, ":")[0]

	certCache.RLock()
	cert, exists := certCache.certs[hostname]
	certCache.RUnlock()
	if exists {
		return cert, nil
	}

	certCache.Lock()
	defer certCache.Unlock()

	if cert, exists := certCache.certs[hostname]; exists {
		return cert, nil
	}

	cert, err := generateCertForHost(hostname)
	if err != nil {
		return nil, err
	}
	certCache.certs[hostname] = cert
	log.Printf("[CERT] Minted leaf certificate for %s", hostname)
	return cert, nil
}

// generateCertForHost signs a new leaf with the loaded CA. The certificate
// chain presented to the client is the leaf followed by the CA, so the
// client can build a path to the trust anchor it installed.
func generateCertForHost(hostname string) (*tls.Certificate, error) {
	if caCert == nil || caKey == nil {
		return nil, fmt.Errorf("CA is not loaded")
	}
	if certConfig == nil {
		return nil, fmt.Errorf("certificate configuration is not loaded")
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	dnsNames, ipAddresses := leafNames(hostname)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{certConfig.Organization},
			CommonName:   hostname,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(0, 0, certConfig.HostValidityDays),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
	}

	if certConfig.IncludeCDPInHosts && len(certConfig.CRLDistPoints) > 0 {
		template.CRLDistributionPoints = certConfig.CRLDistPoints
	}

	if certConfig.IncludeAIAInHosts {
		applyAIA(template, certConfig)
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &certPrivKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER, caCert.Raw},
		PrivateKey:  certPrivKey,
	}, nil
}

// leafNames builds the SAN lists for one leaf. IP hosts are detected with
// ParseIP so they are recorded as IP addresses and do not receive a DNS
// wildcard. The host string is still also placed in DNSNames, matching the
// certificate shape this proxy has always produced for IP literals.
func leafNames(hostname string) (dnsNames []string, ips []net.IP) {
	dnsNames = []string{hostname}

	sans := []string{"localhost", "127.0.0.1"}
	if certConfig != nil && len(certConfig.DefaultSANs) > 0 {
		sans = certConfig.DefaultSANs
	}
	for _, san := range sans {
		if ip := net.ParseIP(san); ip != nil {
			ips = append(ips, ip)
			continue
		}
		if !containsString(dnsNames, san) {
			dnsNames = append(dnsNames, san)
		}
	}

	if ip := net.ParseIP(hostname); ip != nil {
		ips = append(ips, ip)
		return dnsNames, ips
	}

	// More than one dot means there is a subdomain to wildcard.
	// "example.com" has one dot and is left exact.
	if strings.Count(hostname, ".") > 1 {
		parts := strings.SplitN(hostname, ".", 2)
		dnsNames = append(dnsNames, "*."+parts[1])
	}
	return dnsNames, ips
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// applyAIA copies the configured OCSP and CA-issuer URLs onto a leaf.
// AIAURLs is "ocsp|issuer". A single OCSP URL may also be set on its own.
func applyAIA(template *x509.Certificate, cfg *CertConfig) {
	if cfg.AIAURLs != "" {
		parts := strings.Split(cfg.AIAURLs, "|")
		if len(parts) == 2 {
			ocspURL := strings.TrimSpace(parts[0])
			caIssuerURL := strings.TrimSpace(parts[1])
			if ocspURL != "" {
				template.OCSPServer = []string{ocspURL}
			}
			if caIssuerURL != "" {
				template.IssuingCertificateURL = []string{caIssuerURL}
			}
		}
		return
	}
	if cfg.OCSPServer != "" {
		template.OCSPServer = []string{cfg.OCSPServer}
	}
}
