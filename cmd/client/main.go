package main

import (
	"context"
	"os"
	"os/signal"
	"quic-transproxy/internal/client"
	"quic-transproxy/internal/shared/config"
	"quic-transproxy/internal/shared/logger"
	"syscall"
	"time"
)

func main() {
	/*configPath := flag.String("config", "", "Path to client configuration file")
	flag.Parse()*/

	cfg, err := config.LoadClientConfig()
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
		for {
			if err := listener.Start(ctx); err != nil {
				if err == context.Canceled {
					return
				}

				log.Error("Listener error: %v, restarting in 5s...", err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(5 * time.Second):
					// Continue to try to restart the listener
				}
			}
		}
	}()

	for {
		if err := quicClient.Start(ctx); err != nil {
			if err == context.Canceled {
				break
			}

			log.Error("QUIC client error: %v, restarting in 5s...", err)
			select {
			case <-ctx.Done():
				break
			case <-time.After(5 * time.Second):
				continue
			}
		}
	}
}
