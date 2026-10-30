// Command rendezvous runs the knockknock rendezvous server: TLS signalling
// over TCP and BIND observation over UDP, on the same port.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"knockknock/rendezvous/internal/dashboard"
	"knockknock/rendezvous/internal/devcert"
	"knockknock/rendezvous/internal/registry"
)

func main() {
	cfg := registry.DefaultConfig()
	addr := flag.String("addr", ":7777", "address to listen on (TCP for TLS signalling, UDP for BIND)")
	certFile := flag.String("tls-cert", "", "TLS certificate chain (PEM); without it a development CA is generated")
	keyFile := flag.String("tls-key", "", "TLS private key (PEM)")
	devCA := flag.String("tls-dev-ca", "dev-ca.pem", "development CA certificate for clients to trust; its key is kept at <path>.key and reused across restarts")
	devHosts := flag.String("tls-dev-hosts", "localhost,127.0.0.1,::1", "comma-separated names and IPs the development certificate is valid for")
	flag.IntVar(&cfg.MaxLobby, "max-lobby", cfg.MaxLobby, "maximum peers per lobby, host included")
	flag.Float64Var(&cfg.Rate, "rate", cfg.Rate, "sustained new connections/joins per second per IP")
	flag.IntVar(&cfg.Burst, "burst", cfg.Burst, "burst size for -rate")
	httpAddr := flag.String("http", "127.0.0.1:8080", "address for the stats dashboard; empty disables it (it shows lobby IDs, so keep it private)")
	debug := flag.Bool("debug", false, "enable debug logging")
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	fail := func(msg string, args ...any) {
		log.Error(msg, args...)
		os.Exit(1)
	}

	cert, err := loadOrGenerate(*certFile, *keyFile, *devCA, *devHosts, log)
	if err != nil {
		fail("tls", "err", err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fail("listen tcp", "addr", *addr, "err", err)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", ln.Addr().String())
	if err != nil {
		fail("resolve address", "addr", *addr, "err", err)
	}
	udp, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fail("listen udp", "addr", udpAddr, "err", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := registry.New(udp, tlsConfig, cfg, log)
	if *httpAddr != "" {
		web := &http.Server{Addr: *httpAddr, Handler: dashboard.Handler(srv.Snapshot), ReadHeaderTimeout: 5 * time.Second}
		go func() {
			log.Info("dashboard", "url", "http://"+*httpAddr)
			if err := web.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("dashboard", "err", err)
			}
		}()
		defer web.Close()
	}

	log.Info("listening", "addr", ln.Addr())
	if err := srv.Serve(ctx, ln); err != nil {
		fail("serve", "err", err)
	}
}

func loadOrGenerate(certFile, keyFile, devCA, devHosts string, log *slog.Logger) (tls.Certificate, error) {
	if certFile != "" || keyFile != "" {
		return tls.LoadX509KeyPair(certFile, keyFile)
	}
	cert, created, err := devcert.LoadOrCreate(devCA, strings.Split(devHosts, ","))
	if err != nil {
		return tls.Certificate{}, err
	}
	if created {
		log.Warn("created a development CA; clients must trust this file (pass -tls-cert/-tls-key in production)",
			"ca", devCA, "hosts", devHosts)
	} else {
		log.Warn("using the existing development CA (pass -tls-cert/-tls-key in production)",
			"ca", devCA, "hosts", devHosts)
	}
	return cert, nil
}
