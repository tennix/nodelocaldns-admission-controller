package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	// Environment variable names
	EnvNodeLocalDNSAddress = "NODE_LOCAL_DNS_ADDRESS"
	EnvSearchDomains       = "SEARCH_DOMAINS"
	EnvDNSOptions          = "DNS_OPTIONS"
)

// Config represents the webhook configuration
type Config struct {
	// NodeLocalDNSAddress is the IP address of the node local DNS cache
	NodeLocalDNSAddress string `json:"nodeLocalDNSAddress" yaml:"nodeLocalDNSAddress"`
	// SearchDomains are the DNS search domains to inject
	SearchDomains []string `json:"searchDomains" yaml:"searchDomains"`
	// DNSOptions are the DNS options to inject
	DNSOptions []DNSOption `json:"dnsOptions" yaml:"dnsOptions"`
	// ClusterDNSAddress is the discovered cluster DNS service IP
	ClusterDNSAddress string `json:"clusterDNSAddress" yaml:"clusterDNSAddress"`
}

// DNSOption represents a DNS configuration option
type DNSOption struct {
	// Name is the option name (e.g., "ndots", "timeout")
	Name string `json:"name" yaml:"name"`
	// Value is the option value (e.g., "3", "1")
	Value string `json:"value" yaml:"value"`
}

// DNSConfig represents the DNS configuration to be injected into pods
type DNSConfig struct {
	// Nameservers is the list of DNS nameserver IP addresses
	Nameservers []string `json:"nameservers" yaml:"nameservers"`
	// Searches is the list of DNS search domains
	Searches []string `json:"searches" yaml:"searches"`
	// Options is the list of DNS resolver options
	Options []DNSOption `json:"options" yaml:"options"`
}

// DefaultConfig returns a configuration with default values
func DefaultConfig() *Config {
	return &Config{
		NodeLocalDNSAddress: "169.254.20.10",
		SearchDomains: []string{
			"default.svc.cluster.local",
			"svc.cluster.local",
			"cluster.local",
		},
		DNSOptions: []DNSOption{
			{Name: "ndots", Value: "3"},
			{Name: "attempts", Value: "2"},
			{Name: "timeout", Value: "1"},
		},
		ClusterDNSAddress: "10.96.0.10", // Default fallback
	}
}

// LoadConfig loads configuration from environment variables with the provided cluster DNS IP
func LoadConfig(clusterDNSIP string) (*Config, error) {
	// Start with default configuration
	config := DefaultConfig()

	// Load from environment variables
	if err := loadFromEnvironment(config); err != nil {
		return nil, fmt.Errorf("failed to load configuration from environment: %w", err)
	}

	// Set the discovered cluster DNS IP
	config.ClusterDNSAddress = clusterDNSIP

	// Validate final configuration
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return config, nil
}

// loadFromEnvironment loads configuration from environment variables
func loadFromEnvironment(config *Config) error {
	// Load node local DNS address (REQUIRED)
	addr := os.Getenv(EnvNodeLocalDNSAddress)
	if addr == "" {
		return fmt.Errorf("node local DNS address is required but not provided via environment variable %s", EnvNodeLocalDNSAddress)
	}

	if err := validateIPAddress(addr); err != nil {
		return fmt.Errorf("invalid node local DNS address %s: %w", addr, err)
	}
	config.NodeLocalDNSAddress = addr

	// Load search domains (optional, use defaults if not provided)
	if domains := os.Getenv(EnvSearchDomains); domains != "" {
		config.SearchDomains = strings.Split(domains, ",")
		for i, domain := range config.SearchDomains {
			config.SearchDomains[i] = strings.TrimSpace(domain)
		}
	}

	// Load DNS options (optional, use defaults if not provided)
	if options := os.Getenv(EnvDNSOptions); options != "" {
		dnsOptions, err := parseDNSOptions(options)
		if err != nil {
			return fmt.Errorf("invalid DNS options %s: %w", options, err)
		}
		config.DNSOptions = dnsOptions
	}

	return nil
}

// validateConfig validates the loaded configuration
func validateConfig(config *Config) error {
	// Validate node local DNS address
	if err := validateIPAddress(config.NodeLocalDNSAddress); err != nil {
		return fmt.Errorf("invalid node local DNS address: %w", err)
	}

	// Validate cluster DNS address
	if err := validateIPAddress(config.ClusterDNSAddress); err != nil {
		return fmt.Errorf("invalid cluster DNS address: %w", err)
	}

	// Validate search domains
	if len(config.SearchDomains) == 0 {
		return fmt.Errorf("search domains cannot be empty")
	}

	for _, domain := range config.SearchDomains {
		if strings.TrimSpace(domain) == "" {
			return fmt.Errorf("search domain cannot be empty")
		}
	}

	// Validate DNS options
	for _, option := range config.DNSOptions {
		if strings.TrimSpace(option.Name) == "" {
			return fmt.Errorf("DNS option name cannot be empty")
		}
		if strings.TrimSpace(option.Value) == "" {
			return fmt.Errorf("DNS option value cannot be empty")
		}
	}

	return nil
}

// validateIPAddress validates an IP address format
func validateIPAddress(ip string) error {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return fmt.Errorf("invalid IP address format")
	}

	for _, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 || num > 255 {
			return fmt.Errorf("invalid IP address octet: %s", part)
		}
	}

	return nil
}

// parseDNSOptions parses DNS options from string format "name1:value1,name2:value2"
func parseDNSOptions(optionsStr string) ([]DNSOption, error) {
	var options []DNSOption

	pairs := strings.Split(optionsStr, ",")
	for _, pair := range pairs {
		parts := strings.Split(strings.TrimSpace(pair), ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid DNS option format: %s (expected name:value)", pair)
		}

		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if name == "" || value == "" {
			return nil, fmt.Errorf("DNS option name and value cannot be empty: %s", pair)
		}

		options = append(options, DNSOption{
			Name:  name,
			Value: value,
		})
	}

	return options, nil
}
