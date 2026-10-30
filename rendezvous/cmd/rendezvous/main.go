// Command rendezvous runs the knockknock UDP rendezvous server.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"knockknock/rendezvous/internal/registry"
)

func main() {
	cfg := registry.DefaultConfig()
	addr := flag.String("addr", ":7777", "UDP address to listen on")
	flag.DurationVar(&cfg.TTL, "ttl", cfg.TTL, "forget clients that have not refreshed within this duration")
	flag.IntVar(&cfg.MaxLobby, "max-lobby", cfg.MaxLobby, "maximum peers per lobby, host included")
	flag.Float64Var(&cfg.Rate, "rate", cfg.Rate, "sustained registrations/joins per second per IP")
	flag.IntVar(&cfg.Burst, "burst", cfg.Burst, "burst size for -rate")
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

	log.Info("listening", "addr", conn.LocalAddr())
	if err := registry.New(conn, cfg, log).Serve(ctx); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}
