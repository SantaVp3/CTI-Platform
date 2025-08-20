package config

import (
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	Environment string
	Database    DatabaseConfig
	API         APIConfig
	JWT         JWTConfig
	Log         LogConfig
	Security    SecurityConfig
	External    ExternalConfig
}

type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
}

type APIConfig struct {
	Host string
	Port string
}

type JWTConfig struct {
	Secret string
}

type LogConfig struct {
	Level string
	File  string
}

type SecurityConfig struct {
	CORSAllowedOrigins      []string
	RateLimitRequestsPerMin int
}

type ExternalConfig struct {
	VirusTotalAPIKey string
	ShodanAPIKey     string
	TAXIIServerURL   string
	TAXIIUsername    string
	TAXIIPassword    string
}

func Load() (*Config, error) {
	// Load .env file if it exists
	_ = godotenv.Load()

	config := &Config{
		Environment: getEnv("ENVIRONMENT", "development"),
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnv("DB_PORT", "3306"),
			User:     getEnv("DB_USER", "cti_user"),
			Password: getEnv("DB_PASSWORD", "cti_password"),
			Name:     getEnv("DB_NAME", "cti_platform"),
		},
		API: APIConfig{
			Host: getEnv("API_HOST", "0.0.0.0"),
			Port: getEnv("API_PORT", "8080"),
		},
		JWT: JWTConfig{
			Secret: getEnv("JWT_SECRET", "your-jwt-secret-key"),
		},
		Log: LogConfig{
			Level: getEnv("LOG_LEVEL", "info"),
			File:  getEnv("LOG_FILE", ""),
		},
		Security: SecurityConfig{
			CORSAllowedOrigins:      []string{getEnv("CORS_ALLOWED_ORIGINS", "http://localhost:3000")},
			RateLimitRequestsPerMin: getEnvAsInt("RATE_LIMIT_REQUESTS_PER_MINUTE", 100),
		},
		External: ExternalConfig{
			VirusTotalAPIKey: getEnv("VIRUSTOTAL_API_KEY", ""),
			ShodanAPIKey:     getEnv("SHODAN_API_KEY", ""),
			TAXIIServerURL:   getEnv("TAXII_SERVER_URL", ""),
			TAXIIUsername:    getEnv("TAXII_USERNAME", ""),
			TAXIIPassword:    getEnv("TAXII_PASSWORD", ""),
		},
	}

	return config, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}
