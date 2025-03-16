package config

type Config struct {
	ClientListenAddr string
	ClientListenPort int
	ProxyServerAddr  string
	ProxyServerPort  int

	ServerListenAddr string
	ServerListenPort int

	LogLevel string
}

// NewDefaultConfig returns a new Config with default values.
func NewDefaultConfig() *Config {
	return &Config{
		ClientListenAddr: "127.0.0.1",
		ClientListenPort: 8000,
		ProxyServerAddr:  "127.0.0.1",
		ProxyServerPort:  8443,
		ServerListenAddr: "0.0.0.0",
		ServerListenPort: 8443,
		LogLevel:         "info",
	}
}
