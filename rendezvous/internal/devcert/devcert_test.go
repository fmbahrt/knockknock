package devcert

import (
	"crypto/tls"
	"crypto/x509"
	"net"
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
