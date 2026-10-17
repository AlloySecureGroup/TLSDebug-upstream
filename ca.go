package main

/*
The proxy's certificate authority.

Clients reject a leaf we just minted unless the CA that signed it is in
their trust store. This file creates that CA, reloads it on later starts,
and installs it into the OS trust store when the fingerprint there does
not already match.

Identity is the SHA-256 of the certificate's DER encoding, not the subject
name. Two different keys can share the name "TLS Proxy Root CA". Installing
or uninstalling by name alone can trust the wrong certificate or delete a
different one that happens to use the same words. The install path compares
fingerprints and skips the installer when the exact CA is already trusted.

The private key is written mode 0600. Anyone who can read proxy-ca.key can
sign certificates that clients of this proxy will accept. The certificate
file is public; it is the trust anchor the client needs.

Keep the .crt and the .key together. Loading one without the other, or
replacing only one of them, produces a pair that cannot sign leaves the
client will chain to the installed CA.
*/

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var (
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
)

// initCA loads the on-disk pair when both files exist, and generates a new
// pair otherwise. A pair is never half-replaced: if either file is missing,
// both are created again.
func initCA(config *ProxyConfig) error {
	certPath := filepath.Join(config.CertDir, caCertFile)
	keyPath := filepath.Join(config.CertDir, caKeyFile)

	if fileExists(certPath) && fileExists(keyPath) {
		if err := loadCA(certPath, keyPath); err != nil {
			return err
		}
		if !config.SkipInstall {
			if err := installCertificate(certPath); err != nil {
				log.Printf("WARNING: Failed to verify or install existing CA: %v", err)
				printManualInstallInstructions(certPath)
			}
		}
		return nil
	}

	return generateCA(certPath, keyPath, config.SkipInstall)
}

// generateCA creates a new RSA-2048 self-signed CA, writes it, optionally
// installs it, and loads it into caCert and caKey. The certificate is
// self-signed: the template is both the subject and the issuer.
func generateCA(certPath, keyPath string, skipInstall bool) error {
	log.Println("Generating new CA certificate...")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{certConfig.Organization},
			CommonName:   certConfig.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(certConfig.ValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	if len(certConfig.CRLDistPoints) > 0 {
		template.CRLDistributionPoints = certConfig.CRLDistPoints
		log.Printf("CA CRL Distribution Points: %v", certConfig.CRLDistPoints)
	}

	if certConfig.AIAURLs != "" {
		parts := strings.Split(certConfig.AIAURLs, "|")
		if len(parts) == 2 {
			ocspURL := strings.TrimSpace(parts[0])
			caIssuerURL := strings.TrimSpace(parts[1])
			if ocspURL != "" {
				template.OCSPServer = []string{ocspURL}
				log.Printf("CA OCSP Server: %s", ocspURL)
			}
			if caIssuerURL != "" {
				template.IssuingCertificateURL = []string{caIssuerURL}
				log.Printf("CA Issuer URL: %s", caIssuerURL)
			}
		}
	} else if certConfig.OCSPServer != "" {
		template.OCSPServer = []string{certConfig.OCSPServer}
		log.Printf("CA OCSP Server: %s", certConfig.OCSPServer)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}

	if err := writePEMFile(certPath, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}, 0644); err != nil {
		return err
	}
	// 0600, then Chmod again inside writePEMFile, because the process
	// umask can loosen the mode Open/WriteFile requested.
	if err := writePEMFile(keyPath, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}, 0600); err != nil {
		return err
	}

	log.Printf("CA certificate generated: %s", certPath)
	log.Printf("CA Organization: %s", certConfig.Organization)
	log.Printf("CA Common Name: %s", certConfig.CommonName)
	log.Printf("CA Validity: %d years", certConfig.ValidityYears)

	if skipInstall {
		log.Println("Skipping automatic certificate installation (--skip-install flag)")
		printManualInstallInstructions(certPath)
	} else {
		if err := installCertificate(certPath); err != nil {
			log.Printf("WARNING: Failed to install certificate automatically: %v", err)
			log.Printf("Please install manually: %s", certPath)
			printManualInstallInstructions(certPath)
		} else {
			log.Printf("CA certificate installed successfully")
			log.Printf("You may need to restart your browser for changes to take effect")
		}
	}

	return loadCA(certPath, keyPath)
}

func writePEMFile(path string, block *pem.Block, mode os.FileMode) error {
	var buf bytes.Buffer
	if err := pem.Encode(&buf, block); err != nil {
		return err
	}
	if err := os.WriteFile(path, buf.Bytes(), mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// loadCA parses the on-disk pair into caCert and caKey. The key must be
// PKCS#1 RSA ("BEGIN RSA PRIVATE KEY"), which is the form generateCA writes.
func loadCA(certPath, keyPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	caCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}

	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode key PEM")
	}

	caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	log.Println("Loaded existing CA certificate")
	return nil
}

// cleanupCerts removes the CA from the OS trust store and deletes the pair
// in -certdir. The trust-store step matches on the common name, which is
// broader than the fingerprint check used at install time.
func cleanupCerts(config *ProxyConfig) {
	certPath := filepath.Join(config.CertDir, caCertFile)
	keyPath := filepath.Join(config.CertDir, caKeyFile)

	log.Println("Removing certificate from system trust store...")
	if err := uninstallCertificate(); err != nil {
		log.Printf("WARNING: Failed to uninstall certificate: %v", err)
		log.Println("You may need to remove it manually")
	} else {
		log.Println("Certificate uninstalled from system")
	}

	removed := false
	if fileExists(certPath) {
		os.Remove(certPath)
		log.Printf("Removed: %s", certPath)
		removed = true
	}
	if fileExists(keyPath) {
		os.Remove(keyPath)
		log.Printf("Removed: %s", keyPath)
		removed = true
	}
	if !removed {
		log.Println("No certificate files found to remove")
	}
}

// installCertificate installs certPath when the trust store does not
// already contain that exact fingerprint, then checks the fingerprint
// again so a silent installer failure is not reported as success.
func installCertificate(certPath string) error {
	absPath, err := filepath.Abs(certPath)
	if err != nil {
		return err
	}

	installed, err := certificateInstalled(absPath)
	if err != nil {
		return fmt.Errorf("failed to check certificate trust: %w", err)
	}
	if installed {
		log.Printf("Matching CA certificate is already installed")
		return nil
	}

	switch runtime.GOOS {
	case "windows":
		err = installCertWindows(absPath)
	case "darwin":
		err = installCertMacOS(absPath)
	case "linux":
		err = installCertLinux(absPath)
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
	if err != nil {
		return err
	}

	installed, err = certificateInstalled(absPath)
	if err != nil {
		return fmt.Errorf("failed to verify certificate trust: %w", err)
	}
	if !installed {
		return fmt.Errorf("certificate installation completed but the exact CA fingerprint was not found")
	}
	return nil
}

func certificateInstalled(certPath string) (bool, error) {
	expected, err := certificateFingerprintFile(certPath)
	if err != nil {
		return false, err
	}

	switch runtime.GOOS {
	case "windows":
		return certificateInstalledWindows(expected)
	case "darwin":
		return certificateInstalledMacOS(expected)
	case "linux":
		return certificateInstalledLinux(expected)
	default:
		return false, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

func certificateFingerprintFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("failed to decode certificate PEM: %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	return certificateFingerprint(cert), nil
}

// certificateFingerprint is the lowercase hex SHA-256 of the DER encoding.
// PEM text and subject strings are not part of the hash, so reformatting
// the file does not change the fingerprint.
func certificateFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", sum)
}

// pemContainsFingerprint walks every CERTIFICATE block in data. Trust-store
// dumps often contain the whole store, so the first certificate is not
// necessarily ours.
func pemContainsFingerprint(data []byte, expected string) bool {
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			return false
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil && certificateFingerprint(cert) == expected {
			return true
		}
	}
	return false
}

func certificateInstalledWindows(expected string) (bool, error) {
	powerShell, err := exec.LookPath("powershell.exe")
	if err != nil {
		return false, fmt.Errorf("powershell.exe not found: %w", err)
	}
	script := fmt.Sprintf(
		`$sha=[Security.Cryptography.SHA256]::Create(); $match=Get-ChildItem Cert:\CurrentUser\Root | Where-Object { ([BitConverter]::ToString($sha.ComputeHash($_.RawData))).Replace('-','').ToLowerInvariant() -eq '%s' }; if ($match) { exit 0 } else { exit 1 }`,
		expected,
	)
	err = exec.Command(powerShell, "-NoProfile", "-NonInteractive", "-Command", script).Run()
	if err == nil {
		return true, nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
		return false, nil
	}
	return false, err
}

func certificateInstalledMacOS(expected string) (bool, error) {
	output, err := exec.Command(
		"security", "find-certificate", "-a", "-p", "/Library/Keychains/System.keychain",
	).Output()
	if err != nil {
		return false, err
	}
	return pemContainsFingerprint(output, expected), nil
}

func certificateInstalledLinux(expected string) (bool, error) {
	const trustedCertPath = "/usr/local/share/ca-certificates/tlsproxy.crt"
	if !fileExists(trustedCertPath) {
		return false, nil
	}
	actual, err := certificateFingerprintFile(trustedCertPath)
	if err != nil {
		return false, nil
	}
	return actual == expected, nil
}

func installCertWindows(certPath string) error {
	_, err := exec.LookPath("certutil")
	if err != nil {
		return fmt.Errorf("certutil not found in PATH - manual installation required")
	}

	log.Printf("Installing certificate to Windows trust store...")
	log.Printf("Running: certutil -addstore -user Root \"%s\"", certPath)

	cmd := exec.Command("certutil", "-addstore", "-user", "Root", certPath)
	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		log.Printf("certutil output: %s", string(output))
	}
	if err != nil {
		return fmt.Errorf("certutil failed: %v - %s", err, string(output))
	}
	return nil
}

func installCertMacOS(certPath string) error {
	cmd := exec.Command("sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot",
		"-k", "/Library/Keychains/System.keychain", certPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}
	return nil
}

func installCertLinux(certPath string) error {
	destPath := "/usr/local/share/ca-certificates/tlsproxy.crt"

	input, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}

	cmd := exec.Command("sudo", "tee", destPath)
	cmd.Stdin = bytes.NewReader(input)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to copy certificate: %v", err)
	}

	cmd = exec.Command("sudo", "update-ca-certificates")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}
	return nil
}

func uninstallCertificate() error {
	switch runtime.GOOS {
	case "windows":
		return uninstallCertWindows()
	case "darwin":
		return uninstallCertMacOS()
	case "linux":
		return uninstallCertLinux()
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

func uninstallCertWindows() error {
	cmd := exec.Command("certutil", "-delstore", "-user", "Root", "TLS Proxy Root CA")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}
	return nil
}

func uninstallCertMacOS() error {
	cmd := exec.Command("sudo", "security", "delete-certificate", "-c", "TLS Proxy Root CA",
		"/Library/Keychains/System.keychain")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}
	return nil
}

func uninstallCertLinux() error {
	destPath := "/usr/local/share/ca-certificates/tlsproxy.crt"

	cmd := exec.Command("sudo", "rm", "-f", destPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove certificate: %v", err)
	}

	cmd = exec.Command("sudo", "update-ca-certificates")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}
	return nil
}

// exportCACert writes the loaded CA certificate as PEM. path "-" writes to
// stdout so a shell can redirect it. The key is never exported here.
func exportCACert(path string) error {
	if caCert == nil {
		return fmt.Errorf("CA certificate not loaded")
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	if path == "-" {
		_, err := os.Stdout.Write(pemBytes)
		return err
	}
	if err := os.WriteFile(path, pemBytes, 0644); err != nil {
		return err
	}
	log.Printf("CA certificate exported to %s", path)
	return nil
}

// printCACertExportImportInfo prints the PEM and ready-to-run import
// commands. This is the path that works when the operator can see the log
// but cannot read the proxy's filesystem (a container, a remote host).
func printCACertExportImportInfo(monitorPort int) {
	if caCert == nil {
		return
	}
	pemText := strings.TrimRight(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})), "\r\n")
	downloadURL := fmt.Sprintf("http://localhost:%d/ca-cert", monitorPort)
	installURL := fmt.Sprintf("http://localhost:%d/install-ca", monitorPort)

	log.Println("")
	log.Println("================================================================")
	log.Println(" CA CERTIFICATE - export & import on a Windows workstation")
	log.Println("================================================================")
	if certConfig != nil {
		log.Printf(" Subject: CN=%s, O=%s", certConfig.CommonName, certConfig.Organization)
	}
	log.Println(" NOTE: if this host's certificate storage isn't persisted")
	log.Println(" (e.g. an ephemeral container), a restart generates a NEW CA")
	log.Println(" and you'll need to export/import it again.")
	log.Println("")
	log.Printf(" Remote clients: send them to %s for a self-service", installURL)
	log.Println(" download + OS-specific install instructions (Windows, macOS,")
	log.Println(" Linux, Android, iOS) - substitute this host's real address")
	log.Println(" if they're connecting over the network instead of localhost.")
	log.Println("")
	log.Printf(" Export while the proxy is running: %s", downloadURL)
	log.Println(" (substitute this host's real address if connecting remotely)")
	log.Println("")
	log.Println("---- Easiest: download + import in one PowerShell command ----")
	log.Printf(`Invoke-WebRequest %s -OutFile "$env:TEMP\tlsproxy-ca.crt"; Import-Certificate -FilePath "$env:TEMP\tlsproxy-ca.crt" -CertStoreLocation Cert:\CurrentUser\Root`, downloadURL)
	log.Println("")
	log.Println("---- Or paste the certificate PEM directly (no network needed) ----")
	log.Println(pemText)
	log.Println("")
	log.Println("$pem = @'")
	log.Println(pemText)
	log.Println("'@")
	log.Println(`$path = Join-Path $env:TEMP 'tlsproxy-ca.crt'`)
	log.Println("Set-Content -Path $path -Value $pem -Encoding ascii")
	log.Println(`Import-Certificate -FilePath $path -CertStoreLocation Cert:\CurrentUser\Root`)
	log.Println("")
	log.Println("---- Or certutil (Command Prompt, after saving the PEM above) ----")
	log.Println("  certutil -addstore -user Root tlsproxy-ca.crt")
	log.Println("  (drop -user and run elevated to install machine-wide instead)")
	log.Println("================================================================")
	log.Println("")
}

func printManualInstallInstructions(certPath string) {
	absPath, _ := filepath.Abs(certPath)

	switch runtime.GOOS {
	case "windows":
		log.Println("")
		log.Println("=== Manual Windows Installation ===")
		log.Println("Option 1 - Command Line (User Store):")
		log.Printf("  certutil -addstore -user Root \"%s\"", absPath)
		log.Println("")
		log.Println("Option 2 - Command Line (System Store, requires Admin):")
		log.Printf("  certutil -addstore Root \"%s\"", absPath)
		log.Println("")
		log.Println("Option 3 - GUI:")
		log.Printf("  1. Double-click: %s", absPath)
		log.Println("  2. Click 'Install Certificate'")
		log.Println("  3. Store Location: 'Current User'")
		log.Println("  4. Place in: 'Trusted Root Certification Authorities'")
		log.Println("  5. Click 'Next' and 'Finish'")
		log.Println("")
	case "darwin":
		log.Println("")
		log.Println("=== Manual macOS Installation ===")
		log.Printf("  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain \"%s\"", absPath)
		log.Println("")
		log.Println("OR double-click the certificate and set to 'Always Trust'")
		log.Println("")
	case "linux":
		log.Println("")
		log.Println("=== Manual Linux Installation ===")
		log.Printf("  sudo cp \"%s\" /usr/local/share/ca-certificates/tlsproxy.crt", absPath)
		log.Println("  sudo update-ca-certificates")
		log.Println("")
	}
}
