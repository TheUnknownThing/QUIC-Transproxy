package config

type ClientConfig struct {
	ListenAddress      string
	ListenPort         int
	ProxyServerAddress string
	ProxyServerPort    int
	LogLevel           string
}

type ServerConfig struct {
	ListenAddress string
	ListenPort    int
	LogLevel      string
}

func LoadClientConfig() (*ClientConfig, error) {
	// PLACEHOLDER: Need to parse the config file and return the config
	return &ClientConfig{
		ListenAddress:      "127.0.0.1",
		ListenPort:         8000,
		ProxyServerAddress: "127.0.0.1",
		ProxyServerPort:    9000,
		LogLevel:           "info",
	}, nil
}

func LoadServerConfig() (*ServerConfig, error) {
	// PLACEHOLDER: Need to parse the config file and return the config
	return &ServerConfig{
		ListenAddress: "0.0.0.0",
		ListenPort:    9000,
		LogLevel:      "info",
	}, nil
}
