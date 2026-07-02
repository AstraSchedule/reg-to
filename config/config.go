package config

import "os"

type Config struct {
	Port               string
	Dev                bool
	TurnstileSecretKey string
	CFAPIToken         string
	CFZoneID           string
	AstraAPIBase       string
	AstraAPISecret     string
	TLSCert            string
	TLSKey             string
	TLSCACert          string
}

func Load() *Config {
	return &Config{
		Port:               getEnv("PORT", "9002"),
		Dev:                os.Getenv("GIN_MODE") != "release",
		TurnstileSecretKey: os.Getenv("TURNSTILE_SECRET_KEY"),
		CFAPIToken:         os.Getenv("CF_API_TOKEN"),
		CFZoneID:           os.Getenv("CF_ZONE_ID"),
		AstraAPIBase:       os.Getenv("ASTRA_API_BASE"),
		AstraAPISecret:     os.Getenv("ASTRA_API_SECRET"),
		TLSCert:            os.Getenv("TLS_CERT"),
		TLSKey:             os.Getenv("TLS_KEY"),
		TLSCACert:          os.Getenv("TLS_CA_CERT"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
