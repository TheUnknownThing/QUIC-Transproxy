package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"quic-transproxy/internal/server"
	"quic-transproxy/internal/shared/config"
	"quic-transproxy/internal/shared/logger"
	"syscall"
)

func main() {
	configPath := flag.String("config", "", "Path to server configuration file")
	flag.Parse()

	// TODO: Parse config file
	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		panic(err)
	}

	log := logger.NewSimpleLogger()

	listener := server.NewQUICListener(cfg.ListenAddress, cfg.ListenPort, log)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-signalCh
		log.Info("Shutting down server...")
		cancel()
	}()

	if err := listener.Start(ctx); err != nil && err != context.Canceled {
		log.Error("QUIC listener error: %v", err)
	}
}
