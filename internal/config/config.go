package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config represents the main configuration structure
type Config struct {
	Server      ServerConfig              `mapstructure:"server"`
	Providers   map[string]ProviderConfig `mapstructure:"providers"`
	Logging     LoggingConfig             `mapstructure:"logging"`
	Metrics     MetricsConfig             `mapstructure:"metrics"`
	Audit       AuditConfig               `mapstructure:"audit"`
	Security    SecurityConfig            `mapstructure:"security"`
	Development DevelopmentConfig         `mapstructure:"development"`
}

// ServerConfig holds server-specific configuration
type ServerConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	GRPCPort     int           `mapstructure:"grpc_port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout"`
	TLSEnabled   bool          `mapstructure:"tls_enabled"`
	TLSCertFile  string        `mapstructure:"tls_cert_file"`
	TLSKeyFile   string        `mapstructure:"tls_key_file"`
}

// ProviderConfig holds configuration for HSM providers
type ProviderConfig struct {
	Type    string                 `mapstructure:"type"`
	Enabled bool                   `mapstructure:"enabled"`
	Config  map[string]interface{} `mapstructure:"config"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"` // json, text
	Output     string `mapstructure:"output"` // stdout, file
	FilePath   string `mapstructure:"file_path"`
	MaxSize    int    `mapstructure:"max_size"` // megabytes
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAge     int    `mapstructure:"max_age"` // days
	Compress   bool   `mapstructure:"compress"`
}

// MetricsConfig holds metrics configuration
type MetricsConfig struct {
	Enabled    bool             `mapstructure:"enabled"`
	Path       string           `mapstructure:"path"`
	Port       int              `mapstructure:"port"`
	Interval   time.Duration    `mapstructure:"interval"`
	Prometheus PrometheusConfig `mapstructure:"prometheus"`
}

// PrometheusConfig holds Prometheus-specific metrics configuration
type PrometheusConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	Namespace string `mapstructure:"namespace"`
	Subsystem string `mapstructure:"subsystem"`
}

// AuditConfig holds audit logging configuration
type AuditConfig struct {
	Enabled       bool                   `mapstructure:"enabled"`
	BufferSize    int                    `mapstructure:"buffer_size"`
	FlushInterval time.Duration          `mapstructure:"flush_interval"`
	Backend       string                 `mapstructure:"backend"` // file, database, syslog
	Config        map[string]interface{} `mapstructure:"config"`
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	EnableTLS     bool            `mapstructure:"enable_tls"`
	TLSMinVersion string          `mapstructure:"tls_min_version"`
	APIKeyAuth    bool            `mapstructure:"api_key_auth"`
	JWTAuth       JWTAuthConfig   `mapstructure:"jwt_auth"`
	RateLimiting  RateLimitConfig `mapstructure:"rate_limiting"`
	CORS          CORSConfig      `mapstructure:"cors"`
}

// JWTAuthConfig holds JWT authentication configuration
type JWTAuthConfig struct {
	Enabled    bool          `mapstructure:"enabled"`
	Secret     string        `mapstructure:"secret"`
	Algorithm  string        `mapstructure:"algorithm"`
	Expiration time.Duration `mapstructure:"expiration"`
	Issuer     string        `mapstructure:"issuer"`
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Enabled           bool          `mapstructure:"enabled"`
	RequestsPerSecond float64       `mapstructure:"requests_per_second"`
	BurstSize         int           `mapstructure:"burst_size"`
	WindowSize        time.Duration `mapstructure:"window_size"`
}

// CORSConfig holds CORS configuration
type CORSConfig struct {
	Enabled          bool     `mapstructure:"enabled"`
	AllowedOrigins   []string `mapstructure:"allowed_origins"`
	AllowedMethods   []string `mapstructure:"allowed_methods"`
	AllowedHeaders   []string `mapstructure:"allowed_headers"`
	ExposedHeaders   []string `mapstructure:"exposed_headers"`
	AllowCredentials bool     `mapstructure:"allow_credentials"`
	MaxAge           int      `mapstructure:"max_age"`
}

// DevelopmentConfig holds development-specific configuration
type DevelopmentConfig struct {
	Enabled       bool `mapstructure:"enabled"`
	DebugMode     bool `mapstructure:"debug_mode"`
	MockProviders bool `mapstructure:"mock_providers"`
	PprofEnabled  bool `mapstructure:"pprof_enabled"`
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:         "0.0.0.0",
			Port:         8080,
			GRPCPort:     9090,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
			TLSEnabled:   false,
		},
		Providers: map[string]ProviderConfig{
			"mock-hsm": {
				Type:    "mock-hsm",
				Enabled: true,
				Config: map[string]interface{}{
					"persistent_storage": false,
					"simulate_errors":    false,
					"max_keys":           1000,
				},
			},
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "json",
			Output:     "stdout",
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     28,
			Compress:   true,
		},
		Metrics: MetricsConfig{
			Enabled:  true,
			Path:     "/metrics",
			Port:     9091,
			Interval: 30 * time.Second,
			Prometheus: PrometheusConfig{
				Enabled:   true,
				Namespace: "keygrid",
				Subsystem: "hsm",
			},
		},
		Audit: AuditConfig{
			Enabled:       true,
			BufferSize:    1000,
			FlushInterval: 10 * time.Second,
			Backend:       "file",
			Config: map[string]interface{}{
				"file_path": "/var/log/keygrid-hsm/audit.log",
			},
		},
		Security: SecurityConfig{
			EnableTLS:     false,
			TLSMinVersion: "1.2",
			APIKeyAuth:    false,
			JWTAuth: JWTAuthConfig{
				Enabled:    false,
				Algorithm:  "HS256",
				Expiration: 24 * time.Hour,
				Issuer:     "keygrid-hsm",
			},
			RateLimiting: RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				BurstSize:         200,
				WindowSize:        time.Minute,
			},
			CORS: CORSConfig{
				Enabled:        false,
				AllowedOrigins: []string{"*"},
				AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
				AllowedHeaders: []string{"*"},
				MaxAge:         86400,
			},
		},
		Development: DevelopmentConfig{
			Enabled:       false,
			DebugMode:     false,
			MockProviders: false,
			PprofEnabled:  false,
		},
	}
}

// LoadConfig loads configuration from file and environment variables
func LoadConfig(configPath string) (*Config, error) {
	// Set default configuration
	config := DefaultConfig()

	// Configure viper
	viper.SetConfigType("yaml")
	viper.SetConfigName("config")

	// Add config paths
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("/etc/keygrid-hsm")
	viper.AddConfigPath("$HOME/.keygrid-hsm")

	if configPath != "" {
		viper.SetConfigFile(configPath)
	}

	// Configure environment variable handling
	viper.SetEnvPrefix("KEYGRID_HSM")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()

	// Set environment variable mappings
	setEnvironmentMappings()

	// Read configuration file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found is okay, we'll use defaults and env vars
	}

	// Unmarshal configuration
	if err := viper.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// setEnvironmentMappings sets up environment variable mappings for viper
func setEnvironmentMappings() {
	// Server configuration
	viper.BindEnv("server.host", "KEYGRID_HSM_SERVER_HOST")
	viper.BindEnv("server.port", "KEYGRID_HSM_SERVER_PORT")
	viper.BindEnv("server.grpc_port", "KEYGRID_HSM_SERVER_GRPC_PORT")
	viper.BindEnv("server.tls_enabled", "KEYGRID_HSM_SERVER_TLS_ENABLED")
	viper.BindEnv("server.tls_cert_file", "KEYGRID_HSM_SERVER_TLS_CERT_FILE")
	viper.BindEnv("server.tls_key_file", "KEYGRID_HSM_SERVER_TLS_KEY_FILE")

	// Logging configuration
	viper.BindEnv("logging.level", "KEYGRID_HSM_LOG_LEVEL")
	viper.BindEnv("logging.format", "KEYGRID_HSM_LOG_FORMAT")
	viper.BindEnv("logging.output", "KEYGRID_HSM_LOG_OUTPUT")
	viper.BindEnv("logging.file_path", "KEYGRID_HSM_LOG_FILE_PATH")

	// Metrics configuration
	viper.BindEnv("metrics.enabled", "KEYGRID_HSM_METRICS_ENABLED")
	viper.BindEnv("metrics.port", "KEYGRID_HSM_METRICS_PORT")
	viper.BindEnv("metrics.prometheus.enabled", "KEYGRID_HSM_PROMETHEUS_ENABLED")

	// Audit configuration
	viper.BindEnv("audit.enabled", "KEYGRID_HSM_AUDIT_ENABLED")
	viper.BindEnv("audit.backend", "KEYGRID_HSM_AUDIT_BACKEND")

	// Security configuration
	viper.BindEnv("security.enable_tls", "KEYGRID_HSM_SECURITY_ENABLE_TLS")
	viper.BindEnv("security.api_key_auth", "KEYGRID_HSM_SECURITY_API_KEY_AUTH")
	viper.BindEnv("security.jwt_auth.enabled", "KEYGRID_HSM_SECURITY_JWT_AUTH_ENABLED")
	viper.BindEnv("security.jwt_auth.secret", "KEYGRID_HSM_SECURITY_JWT_AUTH_SECRET")

	// Development configuration
	viper.BindEnv("development.enabled", "KEYGRID_HSM_DEVELOPMENT_ENABLED")
	viper.BindEnv("development.debug_mode", "KEYGRID_HSM_DEVELOPMENT_DEBUG_MODE")
	viper.BindEnv("development.mock_providers", "KEYGRID_HSM_DEVELOPMENT_MOCK_PROVIDERS")
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate server configuration
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	if c.Server.GRPCPort <= 0 || c.Server.GRPCPort > 65535 {
		return fmt.Errorf("invalid gRPC port: %d", c.Server.GRPCPort)
	}

	if c.Server.Port == c.Server.GRPCPort {
		return fmt.Errorf("server port and gRPC port cannot be the same")
	}

	// Validate TLS configuration
	if c.Server.TLSEnabled {
		if c.Server.TLSCertFile == "" {
			return fmt.Errorf("TLS cert file is required when TLS is enabled")
		}
		if c.Server.TLSKeyFile == "" {
			return fmt.Errorf("TLS key file is required when TLS is enabled")
		}

		// Check if files exist
		if _, err := os.Stat(c.Server.TLSCertFile); os.IsNotExist(err) {
			return fmt.Errorf("TLS cert file does not exist: %s", c.Server.TLSCertFile)
		}
		if _, err := os.Stat(c.Server.TLSKeyFile); os.IsNotExist(err) {
			return fmt.Errorf("TLS key file does not exist: %s", c.Server.TLSKeyFile)
		}
	}

	// Validate logging configuration
	validLogLevels := []string{"debug", "info", "warn", "error", "fatal", "panic"}
	if !contains(validLogLevels, c.Logging.Level) {
		return fmt.Errorf("invalid log level: %s", c.Logging.Level)
	}

	validLogFormats := []string{"json", "text"}
	if !contains(validLogFormats, c.Logging.Format) {
		return fmt.Errorf("invalid log format: %s", c.Logging.Format)
	}

	validLogOutputs := []string{"stdout", "stderr", "file"}
	if !contains(validLogOutputs, c.Logging.Output) {
		return fmt.Errorf("invalid log output: %s", c.Logging.Output)
	}

	if c.Logging.Output == "file" && c.Logging.FilePath == "" {
		return fmt.Errorf("log file path is required when output is file")
	}

	// Validate metrics configuration
	if c.Metrics.Enabled && (c.Metrics.Port <= 0 || c.Metrics.Port > 65535) {
		return fmt.Errorf("invalid metrics port: %d", c.Metrics.Port)
	}

	// Validate audit configuration
	if c.Audit.Enabled {
		validAuditBackends := []string{"file", "database", "syslog"}
		if !contains(validAuditBackends, c.Audit.Backend) {
			return fmt.Errorf("invalid audit backend: %s", c.Audit.Backend)
		}
	}

	// Validate JWT configuration
	if c.Security.JWTAuth.Enabled {
		if c.Security.JWTAuth.Secret == "" {
			return fmt.Errorf("JWT secret is required when JWT auth is enabled")
		}

		validJWTAlgorithms := []string{"HS256", "HS384", "HS512", "RS256", "RS384", "RS512"}
		if !contains(validJWTAlgorithms, c.Security.JWTAuth.Algorithm) {
			return fmt.Errorf("invalid JWT algorithm: %s", c.Security.JWTAuth.Algorithm)
		}
	}

	// Validate provider configurations
	for name, provider := range c.Providers {
		if provider.Type == "" {
			return fmt.Errorf("provider %s: type is required", name)
		}

		validProviderTypes := []string{"azure-keyvault", "custom-storage", "mock-hsm"}
		if !contains(validProviderTypes, provider.Type) {
			return fmt.Errorf("provider %s: invalid type: %s", name, provider.Type)
		}
	}

	return nil
}

// GetEnabledProviders returns a list of enabled providers
func (c *Config) GetEnabledProviders() map[string]ProviderConfig {
	enabled := make(map[string]ProviderConfig)
	for name, provider := range c.Providers {
		if provider.Enabled {
			enabled[name] = provider
		}
	}
	return enabled
}

// IsDevelopmentMode returns true if development mode is enabled
func (c *Config) IsDevelopmentMode() bool {
	return c.Development.Enabled
}

// IsDebugMode returns true if debug mode is enabled
func (c *Config) IsDebugMode() bool {
	return c.Development.Enabled && c.Development.DebugMode
}

// GetLogLevel returns the log level as a string
func (c *Config) GetLogLevel() string {
	if c.IsDebugMode() {
		return "debug"
	}
	return c.Logging.Level
}

// Helper function to check if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Example configuration files
const (
	ExampleConfigYAML = `
# KeyGrid HSM Configuration
server:
  host: "0.0.0.0"
  port: 8080
  grpc_port: 9090
  read_timeout: "30s"
  write_timeout: "30s"
  idle_timeout: "120s"
  tls_enabled: false
  # tls_cert_file: "/path/to/cert.pem"
  # tls_key_file: "/path/to/key.pem"

providers:
  # Azure Key Vault Provider
  azure-keyvault:
    type: "azure-keyvault"
    enabled: false
    config:
      vault_url: "https://your-keyvault.vault.azure.net/"
      # Authentication options:
      use_system_msi: true  # Use system-assigned managed identity
      # use_cli: true       # Use Azure CLI credentials
      # client_id: ""       # Service principal client ID
      # client_secret: ""   # Service principal client secret
      # tenant_id: ""       # Azure AD tenant ID

  # Custom Storage Provider
  custom-storage:
    type: "custom-storage"
    enabled: false
    config:
      storage_type: "filesystem"  # or "database", "memory"
      encrypt_at_rest: true
      encryption_key: "your-encryption-key-here"
      key_prefix: "keygrid-hsm"
      storage_config:
        base_path: "/var/lib/keygrid-hsm/keys"

  # Mock HSM Provider (for development/testing)
  mock-hsm:
    type: "mock-hsm"
    enabled: true
    config:
      persistent_storage: false
      simulate_errors: false
      simulate_latency_ms: 0
      max_keys: 1000
      key_prefix: "mock-hsm"
      test_scenarios: []  # ["network-error", "timeout", "rate-limit", "auth-error"]

logging:
  level: "info"          # debug, info, warn, error, fatal, panic
  format: "json"         # json, text
  output: "stdout"       # stdout, stderr, file
  # file_path: "/var/log/keygrid-hsm/app.log"
  max_size: 100          # megabytes
  max_backups: 3
  max_age: 28           # days
  compress: true

metrics:
  enabled: true
  path: "/metrics"
  port: 9091
  interval: "30s"
  prometheus:
    enabled: true
    namespace: "keygrid"
    subsystem: "hsm"

audit:
  enabled: true
  buffer_size: 1000
  flush_interval: "10s"
  backend: "file"        # file, database, syslog
  config:
    file_path: "/var/log/keygrid-hsm/audit.log"

security:
  enable_tls: false
  tls_min_version: "1.2"  # 1.0, 1.1, 1.2, 1.3
  api_key_auth: false
  jwt_auth:
    enabled: false
    secret: "your-jwt-secret-here"
    algorithm: "HS256"    # HS256, HS384, HS512, RS256, RS384, RS512
    expiration: "24h"
    issuer: "keygrid-hsm"
  rate_limiting:
    enabled: true
    requests_per_second: 100
    burst_size: 200
    window_size: "1m"
  cors:
    enabled: false
    allowed_origins: ["*"]
    allowed_methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    allowed_headers: ["*"]
    exposed_headers: []
    allow_credentials: false
    max_age: 86400

development:
  enabled: false
  debug_mode: false
  mock_providers: false
  pprof_enabled: false
`

	ExampleDockerConfig = `
# Docker-specific configuration
server:
  host: "0.0.0.0"
  port: 8080
  grpc_port: 9090

providers:
  mock-hsm:
    type: "mock-hsm"
    enabled: true
    config:
      persistent_storage: true
      storage_config:
        storage_type: "filesystem"
        base_path: "/data/keys"

logging:
  level: "info"
  format: "json"
  output: "stdout"

metrics:
  enabled: true
  port: 9091

audit:
  enabled: true
  backend: "file"
  config:
    file_path: "/var/log/audit.log"

development:
  enabled: false
`

	ExampleProductionConfig = `
# Production configuration
server:
  host: "0.0.0.0"
  port: 8080
  grpc_port: 9090
  tls_enabled: true
  tls_cert_file: "/etc/ssl/certs/keygrid-hsm.crt"
  tls_key_file: "/etc/ssl/private/keygrid-hsm.key"

providers:
  azure-keyvault:
    type: "azure-keyvault"
    enabled: true
    config:
      vault_url: "${AZURE_KEYVAULT_URL}"
      use_system_msi: true

logging:
  level: "info"
  format: "json"
  output: "file"
  file_path: "/var/log/keygrid-hsm/app.log"
  max_size: 500
  max_backups: 10
  max_age: 30
  compress: true

metrics:
  enabled: true
  port: 9091
  prometheus:
    enabled: true
    namespace: "keygrid"
    subsystem: "hsm"

audit:
  enabled: true
  buffer_size: 5000
  flush_interval: "5s"
  backend: "database"
  config:
    dsn: "${DATABASE_URL}"
    table: "audit_events"

security:
  enable_tls: true
  tls_min_version: "1.2"
  jwt_auth:
    enabled: true
    secret: "${JWT_SECRET}"
    algorithm: "RS256"
    expiration: "1h"
  rate_limiting:
    enabled: true
    requests_per_second: 1000
    burst_size: 2000
    window_size: "1m"

development:
  enabled: false
`
)
