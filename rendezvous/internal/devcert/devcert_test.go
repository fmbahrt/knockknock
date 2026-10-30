package devcert

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"testing"
)

func TestGeneratedCertVerifies(t *testing.T) {
	cert, caPEM, err := Generate([]string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	c, err := tls.Dial("tcp", "127.0.0.1:"+port, &tls.Config{RootCAs: roots})
	if err != nil {
		t.Fatalf("client rejected the dev certificate: %v", err)
	}
	c.Close()
}

func TestLoadOrCreateReusesTheCA(t *testing.T) {
	path := t.TempDir() + "/ca.pem"
	first, created, err := LoadOrCreate(path, []string{"127.0.0.1"})
	if err != nil || !created {
		t.Fatalf("first: created=%v err=%v", created, err)
	}
	caPEM, _ := os.ReadFile(path)

	second, created, err := LoadOrCreate(path, []string{"127.0.0.1", "localhost"})
	if err != nil || created {
		t.Fatalf("second: created=%v err=%v", created, err)
	}
	if again, _ := os.ReadFile(path); string(again) != string(caPEM) {
		t.Fatal("CA file changed on reuse")
	}
	if string(first.Certificate[0]) == string(second.Certificate[0]) {
		t.Error("server certificate should be reissued")
	}

	// The reissued certificate still verifies against the stored CA.
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	leaf, _ := x509.ParseCertificate(second.Certificate[0])
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "localhost"}); err != nil {
		t.Errorf("reissued cert does not verify: %v", err)
	}
	if info, _ := os.Stat(path + ".key"); info.Mode().Perm() != 0o600 {
		t.Errorf("key permissions %v", info.Mode().Perm())
	}

	// A corrupt key means a new CA.
	os.WriteFile(path+".key", []byte("junk"), 0o600)
	if _, created, err := LoadOrCreate(path, nil); err != nil || !created {
		t.Errorf("corrupt key: created=%v err=%v", created, err)
	}
}
