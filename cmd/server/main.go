package main

import (
	"flag"
	"os"
	"os/signal"
	"quic-transproxy/internal/config"
	"quic-transproxy/internal/logger"
	"quic-transproxy/internal/server"
	"syscall"
)

func main() {
	configFile := flag.String("config", "", "Path to configuration file")
	listenAddr := flag.String("listen", "0.0.0.0:8443", "Address to listen on")
	logLevel := flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	flag.Parse()

	log := logger.NewLogger(*logLevel)

	cfg := config.NewDefaultConfig()
	if *configFile != "" {
		// TODO: Load configuration from file
	}

	if *listenAddr != "" {
		cfg.ServerListenAddr = *listenAddr
	}
	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}

	quicListener := server.NewQUICListener(cfg.ServerListenAddr, log)
	sniExtractor := server.NewSNIIdentifierExtractor(log)
	sniMapper := server.NewSNIMapper(log)
	connectionIDRestorer := server.NewConnectionIDRestorer(log)
	quicForwarder := server.NewQUICForwarder(log, sniMapper, sniExtractor, connectionIDRestorer)

	err := quicListener.Start()
	if err != nil {
		log.Error("Failed to start QUIC listener: %v", err)
		os.Exit(1)
	}

	log.Info("Server started, listening on %s", cfg.ServerListenAddr)

	go func() {
		for conn := range quicListener.GetConnectionChan() {
			quicForwarder.HandleConnection(conn)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Info("Shutting down...")

	quicForwarder.Close()
	quicListener.Close()
}
