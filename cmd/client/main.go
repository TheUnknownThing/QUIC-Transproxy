package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"quic-transproxy/internal/client"
	"quic-transproxy/internal/shared/config"
	"quic-transproxy/internal/shared/logger"
	"syscall"
)

func main() {
	configPath := flag.String("config", "", "Path to client configuration file")
	flag.Parse()

	// TODO: Parse config file
	cfg, err := config.LoadClientConfig(*configPath)
	if err != nil {
		panic(err)
	}

	log := logger.NewSimpleLogger()

	listener := client.NewListener(cfg.ListenAddress, cfg.ListenPort, log)

	quicClient := client.NewQUICClient(cfg.ProxyServerAddress, cfg.ProxyServerPort, listener, log)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-signalCh
		log.Info("Shutting down client...")
		cancel()
	}()

	go func() {
		if err := listener.Start(ctx); err != nil && err != context.Canceled {
			log.Error("Listener error: %v", err)
			cancel()
		}
	}()

	if err := quicClient.Start(ctx); err != nil && err != context.Canceled {
		log.Error("QUIC client error: %v", err)
	}
}
