package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

const (
	DefaultNamespace             = "cf-workloads"
	DefaultPollInterval          = 30 * time.Second
	DefaultPerPageSecurityGroups = 100
	DefaultTLSCertPath           = "/etc/ssl/certs/policy-agent/tls.crt"
	DefaultTLSKeyPath            = "/etc/ssl/certs/policy-agent/tls.key"
	DefaultTLSCAPath             = "/etc/ssl/certs/policy-agent/ca.crt"
)

type Config struct {
	PolicyServerURL       string
	Namespace             string
	PollInterval          time.Duration
	PerPageSecurityGroups int
	TLSCertPath           string
	TLSKeyPath            string
	TLSCAPath             string
}

func Load() *Config {
	return &Config{
		PolicyServerURL:       getEnvOrDie("POLICY_SERVER_URL"),
		Namespace:             getEnvOrDefault("NAMESPACE", DefaultNamespace),
		PollInterval:          getPollIntervalOrDefault("POLL_INTERVAL", DefaultPollInterval),
		PerPageSecurityGroups: getPerPageSecurityGroups(),
		TLSCertPath:           getEnvOrDefault("TLS_CERT_PATH", DefaultTLSCertPath),
		TLSKeyPath:            getEnvOrDefault("TLS_KEY_PATH", DefaultTLSKeyPath),
		TLSCAPath:             getEnvOrDefault("TLS_CA_PATH", DefaultTLSCAPath),
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvOrDie(key string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	panic("'" + key + "' environment variable is required but not set")
}

func getPollIntervalOrDefault(key string, defaultValue time.Duration) time.Duration {
	dur, err := time.ParseDuration(os.Getenv(key))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading poll interval from '%s': %v, falling back to %v\n", key, err, defaultValue)
		dur = defaultValue
	}

	if dur <= 0 {
		fmt.Fprintf(os.Stderr, "poll interval must be positive, falling back to %v\n", defaultValue)
		dur = defaultValue
	}

	return dur
}

func getPerPageSecurityGroups() int {
	perPageStr := os.Getenv("PER_PAGE_SECURITY_GROUPS")
	perPage, err := strconv.Atoi(perPageStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading per page security groups from env: %v, falling back to %d\n", err, DefaultPerPageSecurityGroups)
		perPage = DefaultPerPageSecurityGroups
	}

	return perPage
}
