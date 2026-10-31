// Command rendezvous runs the knockknock rendezvous server: TLS signalling
// over TCP and BIND observation over UDP, on the same port.
package main

import (
	"bytes"
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
	"sync/atomic"
	"syscall"
	"time"

	"knockknock/rendezvous/internal/dashboard"
	"knockknock/rendezvous/internal/devcert"
	"knockknock/rendezvous/internal/registry"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

// certReloadInterval is how often -tls-cert/-tls-key are re-read, so a renewed
// certificate (e.g. from cert-manager) is picked up without a restart.
const certReloadInterval = time.Minute

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
	healthAddr := flag.String("health", "", "address for a /healthz endpoint (for orchestrator probes); empty disables it")
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	if *certFile != "" || *keyFile != "" {
		certs := &certReloader{certFile: *certFile, keyFile: *keyFile, log: log}
		if _, err := certs.load(); err != nil {
			fail("tls", "err", err)
		}
		go certs.run(ctx)
		tlsConfig.GetCertificate = certs.get
	} else {
		cert, err := devCertificate(*devCA, *devHosts, log)
		if err != nil {
			fail("tls", "err", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

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
	if *healthAddr != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
		health := &http.Server{Addr: *healthAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := health.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("health", "err", err)
			}
		}()
		defer health.Close()
	}

	log.Info("listening", "addr", ln.Addr(), "version", version)
	if err := srv.Serve(ctx, ln); err != nil {
		fail("serve", "err", err)
	}
}

func devCertificate(devCA, devHosts string, log *slog.Logger) (tls.Certificate, error) {
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

// certReloader serves the certificate in certFile/keyFile and re-reads both
// every certReloadInterval. A failed reload keeps the previous certificate.
type certReloader struct {
	certFile, keyFile string
	log               *slog.Logger
	cert              atomic.Pointer[tls.Certificate]
}

// load reads the key pair and reports whether it differs from the current one.
func (r *certReloader) load() (bool, error) {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return false, err
	}
	old := r.cert.Swap(&cert)
	return old == nil || !bytes.Equal(old.Certificate[0], cert.Certificate[0]), nil
}

func (r *certReloader) run(ctx context.Context) {
	t := time.NewTicker(certReloadInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			changed, err := r.load()
			if err != nil {
				r.log.Warn("tls reload failed; keeping the current certificate", "err", err)
			} else if changed {
				r.log.Info("tls certificate reloaded", "cert", r.certFile)
			}
		}
	}
}

func (r *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.cert.Load(), nil
}
