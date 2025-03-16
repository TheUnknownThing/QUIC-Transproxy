package main

import (
	"flag"
	"os"
	"os/signal"
	"quic-transproxy/internal/client"
	"quic-transproxy/internal/config"
	"quic-transproxy/internal/logger"
	"syscall"
)

func main() {
	configFile := flag.String("config", "", "Path to configuration file")
	listenAddr := flag.String("listen", "127.0.0.1:8000", "Local address to listen on")
	proxyAddr := flag.String("proxy", "127.0.0.1:8443", "Proxy server address")
	logLevel := flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	flag.Parse()

	log := logger.NewLogger(*logLevel)

	cfg := config.NewDefaultConfig()
	if *configFile != "" {
		// TODO: Load configuration from file
	}

	if *listenAddr != "" {
		cfg.ClientListenAddr = *listenAddr
	}
	if *proxyAddr != "" {
		cfg.ProxyServerAddr = *proxyAddr
	}
	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}

	listener := client.NewListener(cfg.ClientListenAddr, log)
	sniGenerator := client.NewSNIIdentifierGenerator(log)
	connectionIDModifier := client.NewConnectionIDModifier(log)
	quicClient := client.NewQUICClient(cfg.ProxyServerAddr, log, listener, sniGenerator, connectionIDModifier)

	err := listener.Start()
	if err != nil {
		log.Error("Failed to start listener: %v", err)
		os.Exit(1)
	}

	err = quicClient.Connect()
	if err != nil {
		log.Error("Failed to connect to proxy server: %v", err)
		os.Exit(1)
	}

	quicClient.Start()

	log.Info("Client started, listening on %s, proxy server at %s", cfg.ClientListenAddr, cfg.ProxyServerAddr)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Info("Shutting down...")

	quicClient.Close()
	listener.Close()
}
