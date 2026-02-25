// Package config handles application configuration.
package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds all application configuration.
type Config struct {
	Proxy    ProxyConfig    `yaml:"proxy"`
	DNS      DNSConfig      `yaml:"dns"`
	Fragment FragmentConfig `yaml:"fragment"`
	Domains  DomainsConfig  `yaml:"domains"`
}

// ProxyConfig holds proxy server settings.
type ProxyConfig struct {
	Port int    `yaml:"port"`
	Mode string `yaml:"mode"` // "selective" or "all"
}

// DNSConfig holds DNS resolution settings.
type DNSConfig struct {
	Provider  string `yaml:"provider"`   // "cloudflare", "google", "custom"
	CustomURL string `yaml:"custom_url"` // Used when provider is "custom"
}

// FragmentConfig holds TLS fragmentation settings.
type FragmentConfig struct {
	Strategy  string `yaml:"strategy"`   // "first_byte", "before_sni", "middle", "chunked"
	ChunkSize int    `yaml:"chunk_size"` // Used with "chunked" strategy
}

// DomainsConfig holds domain list settings.
type DomainsConfig struct {
	Extra []string `yaml:"extra"` // Additional domains to proxy
}

// DefaultConfig returns a sensible default configuration.
func DefaultConfig() *Config {
	return &Config{
		Proxy: ProxyConfig{
			Port: 8443,
			Mode: "selective",
		},
		DNS: DNSConfig{
			Provider: "cloudflare",
		},
		Fragment: FragmentConfig{
			Strategy:  "before_sni",
			ChunkSize: 40,
		},
		Domains: DomainsConfig{
			Extra: []string{},
		},
	}
}

// Load reads configuration from the default config file, or returns defaults.
func Load() *Config {
	cfg := DefaultConfig()

	configPath := getConfigPath()
	data, err := os.ReadFile(configPath)
	if err != nil {
		// Config file doesn't exist, use defaults
		return cfg
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		// Invalid config, use defaults
		return cfg
	}

	// Ensure critical defaults
	if cfg.Proxy.Port == 0 {
		cfg.Proxy.Port = 8443
	}
	if cfg.Proxy.Mode == "" {
		cfg.Proxy.Mode = "selective"
	}
	if cfg.DNS.Provider == "" {
		cfg.DNS.Provider = "cloudflare"
	}
	if cfg.Fragment.Strategy == "" {
		cfg.Fragment.Strategy = "before_sni"
	}

	return cfg
}

// Save writes the configuration to the default config file.
func Save(cfg *Config) error {
	configPath := getConfigPath()

	// Ensure directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0644)
}

// getConfigPath returns the OS-appropriate config file path.
func getConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".alcatraz", "config.yaml")
}
