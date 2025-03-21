package main

import (
	"context"
	"os"
	"os/signal"
	"quic-transproxy/internal/client"
	"quic-transproxy/internal/shared/config"
	"quic-transproxy/internal/shared/logger"
	"syscall"
)

func main() {
	/*configPath := flag.String("config", "", "Path to client configuration file")
	flag.Parse()*/

	cfg, err := config.LoadClientConfig()
	if err != nil {
		panic(err)
	}

	log := logger.NewSimpleLogger()

	proxyClient := client.NewTransparentProxyClient(
		cfg.ListenAddress,
		cfg.ListenPort,
		cfg.ProxyServerAddress,
		cfg.ProxyServerPort,
		cfg.ClientMark,
		log,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-signalCh
		log.Info("Shutting down client...")
		cancel()
	}()

	if err := proxyClient.Start(ctx); err != nil && err != context.Canceled {
		log.Error("Proxy client error: %v", err)
	}
}
