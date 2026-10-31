package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"knockknock/rendezvous/internal/devcert"
)

func writePair(t *testing.T, dir string) {
	t.Helper()
	cert, _, err := devcert.Generate([]string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCertReloader(t *testing.T) {
	dir := t.TempDir()
	r := &certReloader{
		certFile: filepath.Join(dir, "tls.crt"),
		keyFile:  filepath.Join(dir, "tls.key"),
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if _, err := r.load(); err == nil {
		t.Fatal("load succeeded without files")
	}

	writePair(t, dir)
	if changed, err := r.load(); err != nil || !changed {
		t.Fatalf("first load: changed=%v err=%v", changed, err)
	}
	first, _ := r.get(&tls.ClientHelloInfo{})
	if changed, err := r.load(); err != nil || changed {
		t.Fatalf("unchanged reload: changed=%v err=%v", changed, err)
	}

	writePair(t, dir)
	if changed, err := r.load(); err != nil || !changed {
		t.Fatalf("renewed: changed=%v err=%v", changed, err)
	}
	second, _ := r.get(&tls.ClientHelloInfo{})
	if bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Fatal("certificate not replaced")
	}

	// A broken renewal keeps serving the last good certificate.
	if err := os.WriteFile(r.keyFile, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.load(); err == nil {
		t.Fatal("load accepted a bad key")
	}
	if got, _ := r.get(&tls.ClientHelloInfo{}); got != second {
		t.Fatal("bad reload replaced the certificate")
	}
}
