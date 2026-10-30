// Command rendezvous runs the knockknock UDP rendezvous server.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"knockknock/rendezvous/internal/dashboard"
	"knockknock/rendezvous/internal/registry"
)

func main() {
	cfg := registry.DefaultConfig()
	addr := flag.String("addr", ":7777", "UDP address to listen on")
	flag.DurationVar(&cfg.TTL, "ttl", cfg.TTL, "forget clients that have not refreshed within this duration")
	flag.IntVar(&cfg.MaxLobby, "max-lobby", cfg.MaxLobby, "maximum peers per lobby, host included")
	flag.Float64Var(&cfg.Rate, "rate", cfg.Rate, "sustained registrations/joins per second per IP")
	flag.IntVar(&cfg.Burst, "burst", cfg.Burst, "burst size for -rate")
	httpAddr := flag.String("http", "127.0.0.1:8080", "address for the stats dashboard; empty disables it (it shows lobby IDs, so keep it private)")
	debug := flag.Bool("debug", false, "enable debug logging")
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	udpAddr, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		log.Error("resolve address", "addr", *addr, "err", err)
		os.Exit(1)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Error("listen", "addr", *addr, "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := registry.New(conn, cfg, log)
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

	log.Info("listening", "addr", conn.LocalAddr())
	if err := srv.Serve(ctx); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}
