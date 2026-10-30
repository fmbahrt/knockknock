// Package devcert generates a development certificate authority and server
// certificates for running the rendezvous server without a real certificate.
// Clients trust the CA by loading its PEM, so verification still happens.
package devcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	caLifetime   = 365 * 24 * time.Hour
	certLifetime = 30 * 24 * time.Hour
	// A stored CA this close to expiry is replaced.
	renewBefore = 7 * 24 * time.Hour
)

// Generate returns a server certificate valid for hosts (DNS names or IP
// addresses) and the PEM of a new, throwaway CA that signed it.
func Generate(hosts []string) (tls.Certificate, []byte, error) {
	ca, caKey, err := newCA()
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	cert, err := issue(ca, caKey, hosts)
	return cert, pemCert(ca.Raw), err
}

// LoadOrCreate returns a fresh server certificate for hosts, signed by the CA
// stored at caPath (certificate PEM) and caPath+".key" (private key). The CA
// is created if missing or near expiry, and reused otherwise, so clients that
// copied caPath keep trusting the server across restarts. created reports
// whether a new CA was written.
func LoadOrCreate(caPath string, hosts []string) (cert tls.Certificate, created bool, err error) {
	ca, caKey, err := load(caPath)
	if err != nil {
		if ca, caKey, err = newCA(); err != nil {
			return tls.Certificate{}, false, err
		}
		if err := store(caPath, ca, caKey); err != nil {
			return tls.Certificate{}, false, err
		}
		created = true
	}
	cert, err = issue(ca, caKey, hosts)
	return cert, created, err
}

func load(caPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(caPath + ".key")
	if err != nil {
		return nil, nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || keyBlock == nil {
		return nil, nil, errors.New("devcert: malformed PEM")
	}
	ca, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if !ca.IsCA || !key.PublicKey.Equal(ca.PublicKey) {
		return nil, nil, errors.New("devcert: key does not match CA")
	}
	if time.Until(ca.NotAfter) < renewBefore {
		return nil, nil, errors.New("devcert: CA expiring")
	}
	return ca, key, nil
}

func store(caPath string, ca *x509.Certificate, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(caPath+".key", keyPEM, 0o600); err != nil {
		return fmt.Errorf("devcert: write CA key: %w", err)
	}
	if err := os.WriteFile(caPath, pemCert(ca.Raw), 0o644); err != nil {
		return fmt.Errorf("devcert: write CA: %w", err)
	}
	return nil
}

func newCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "knockknock dev CA " + now.Format("2006-01-02 15:04:05")},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caLifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	ca, err := x509.ParseCertificate(der)
	return ca, key, err
}

func issue(ca *x509.Certificate, caKey *ecdsa.PrivateKey, hosts []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "knockknock dev server"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(certLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}
