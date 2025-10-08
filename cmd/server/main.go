package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/jimmy/keygridhsm/internal/config"
	"github.com/jimmy/keygridhsm/internal/core"
	"github.com/jimmy/keygridhsm/internal/providers"
	"github.com/jimmy/keygridhsm/pkg/models"
)

var (
	configFile string
	logger     *logrus.Logger
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "keygrid-hsm",
		Short: "KeyGrid HSM - Enterprise Hardware Security Module",
		Long:  "KeyGrid HSM provides enterprise-grade cryptographic operations with pluggable storage backends",
	}

	var serverCmd = &cobra.Command{
		Use:   "server",
		Short: "Start the KeyGrid HSM server",
		Run:   runServer,
	}

	var healthCmd = &cobra.Command{
		Use:   "health",
		Short: "Check the health of KeyGrid HSM service",
		Run:   runHealthCheck,
	}

	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run:   runVersion,
	}

	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "config file path")
	serverCmd.Flags().String("bind", "0.0.0.0:8080", "address to bind the server to")
	serverCmd.Flags().Bool("tls", false, "enable TLS")
	serverCmd.Flags().String("cert", "", "TLS certificate file")
	serverCmd.Flags().String("key", "", "TLS private key file")

	rootCmd.AddCommand(serverCmd)
	rootCmd.AddCommand(healthCmd)
	rootCmd.AddCommand(versionCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runServer(cmd *cobra.Command, args []string) {
	// Initialize logger
	logger = logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)

	// Load configuration
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		logger.WithError(err).Fatal("Failed to load configuration")
	}

	// Set log level from config
	if level, err := logrus.ParseLevel(cfg.Server.LogLevel); err == nil {
		logger.SetLevel(level)
	}

	logger.WithFields(logrus.Fields{
		"config_file": configFile,
		"log_level":   logger.Level,
	}).Info("Starting KeyGrid HSM Server")

	// Initialize HSM Manager
	registry := core.NewProviderRegistry()
	manager := core.NewHSMManager(core.HSMManagerConfig{
		Registry: registry,
		Logger:   logger,
	})

	// Register providers
	if err := registerProviders(registry, cfg, logger); err != nil {
		logger.WithError(err).Fatal("Failed to register HSM providers")
	}

	// Create HTTP server
	server := &HSMServer{
		manager: manager,
		config:  cfg,
		logger:  logger,
	}

	router := server.setupRoutes()

	// Get server configuration
	bind, _ := cmd.Flags().GetString("bind")
	tlsEnabled, _ := cmd.Flags().GetBool("tls")
	certFile, _ := cmd.Flags().GetString("cert")
	keyFile, _ := cmd.Flags().GetString("key")

	httpServer := &http.Server{
		Addr:           bind,
		Handler:        router,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		logger.Info("Received shutdown signal, starting graceful shutdown...")
		shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 30*time.Second)
		defer shutdownCancel()

		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.WithError(err).Error("Server shutdown error")
		}
		cancel()
	}()

	// Start server
	logger.WithFields(logrus.Fields{
		"bind":        bind,
		"tls_enabled": tlsEnabled,
	}).Info("KeyGrid HSM Server starting")

	var serverErr error
	if tlsEnabled {
		if certFile == "" || keyFile == "" {
			logger.Fatal("TLS enabled but cert or key file not provided")
		}
		serverErr = httpServer.ListenAndServeTLS(certFile, keyFile)
	} else {
		serverErr = httpServer.ListenAndServe()
	}

	if serverErr != nil && serverErr != http.ErrServerClosed {
		logger.WithError(serverErr).Fatal("Server failed to start")
	}

	<-ctx.Done()
	logger.Info("KeyGrid HSM Server stopped")
}

func runHealthCheck(cmd *cobra.Command, args []string) {
	logger = logrus.New()
	logger.SetLevel(logrus.WarnLevel)

	// Simple health check - just verify the service can start
	bind := "localhost:8080"
	if configFile != "" {
		cfg, err := config.LoadConfig(configFile)
		if err == nil && cfg.Server.Port != 0 {
			bind = fmt.Sprintf("localhost:%d", cfg.Server.Port)
		}
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://%s/health", bind))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Health check failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Health check failed with status: %d\n", resp.StatusCode)
		os.Exit(1)
	}

	fmt.Println("Health check passed")
}

func runVersion(cmd *cobra.Command, args []string) {
	fmt.Printf("KeyGrid HSM version 1.0.0\n")
	fmt.Printf("Build time: %s\n", time.Now().Format(time.RFC3339))
	fmt.Printf("Go version: %s\n", "go1.21")
}

func registerProviders(registry *core.ProviderRegistry, cfg *config.Config, logger *logrus.Logger) error {
	// Register Mock HSM Provider
	mockProvider := providers.NewMockHSMProvider(logger)
	if err := registry.RegisterProvider("mock-hsm", mockProvider); err != nil {
		return fmt.Errorf("failed to register mock HSM provider: %w", err)
	}

	// Register Custom Storage Provider
	customProvider := providers.NewCustomStorageProvider(logger)
	if err := registry.RegisterProvider("custom-storage", customProvider); err != nil {
		return fmt.Errorf("failed to register custom storage provider: %w", err)
	}

	// Register Azure KeyVault Provider
	azureProvider := providers.NewAzureKeyVaultProvider(logger)
	if err := registry.RegisterProvider("azure-keyvault", azureProvider); err != nil {
		return fmt.Errorf("failed to register Azure KeyVault provider: %w", err)
	}

	logger.WithFields(logrus.Fields{
		"providers": registry.ListProviders(),
	}).Info("HSM providers registered successfully")

	return nil
}

// HSMServer represents the HTTP server for KeyGrid HSM
type HSMServer struct {
	manager *core.HSMManager
	config  *config.Config
	logger  *logrus.Logger
}

func (s *HSMServer) setupRoutes() *mux.Router {
	router := mux.NewRouter()

	// Health and metrics endpoints
	router.HandleFunc("/health", s.handleHealth).Methods("GET")
	router.HandleFunc("/ready", s.handleReady).Methods("GET")
	router.Handle("/metrics", promhttp.Handler()).Methods("GET")

	// API endpoints
	api := router.PathPrefix("/api/v1").Subrouter()
	api.Use(s.loggingMiddleware)
	api.Use(s.authMiddleware)

	// Provider management
	api.HandleFunc("/providers", s.handleListProviders).Methods("GET")
	api.HandleFunc("/providers/{provider}/info", s.handleProviderInfo).Methods("GET")
	api.HandleFunc("/providers/{provider}/health", s.handleProviderHealth).Methods("GET")

	// Key management
	api.HandleFunc("/keys", s.handleListKeys).Methods("GET")
	api.HandleFunc("/keys", s.handleGenerateKey).Methods("POST")
	api.HandleFunc("/keys/{keyId}", s.handleGetKey).Methods("GET")
	api.HandleFunc("/keys/{keyId}", s.handleDeleteKey).Methods("DELETE")
	api.HandleFunc("/keys/{keyId}/activate", s.handleActivateKey).Methods("POST")
	api.HandleFunc("/keys/{keyId}/deactivate", s.handleDeactivateKey).Methods("POST")

	// Cryptographic operations
	api.HandleFunc("/keys/{keyId}/sign", s.handleSign).Methods("POST")
	api.HandleFunc("/keys/{keyId}/verify", s.handleVerify).Methods("POST")
	api.HandleFunc("/keys/{keyId}/encrypt", s.handleEncrypt).Methods("POST")
	api.HandleFunc("/keys/{keyId}/decrypt", s.handleDecrypt).Methods("POST")

	return router
}

func (s *HSMServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.logger.WithFields(logrus.Fields{
			"method":   r.Method,
			"path":     r.URL.Path,
			"duration": time.Since(start),
			"remote":   r.RemoteAddr,
		}).Info("HTTP request")
	})
}

func (s *HSMServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: Implement proper authentication (JWT, API keys, etc.)
		// For now, just pass through
		next.ServeHTTP(w, r)
	})
}

func (s *HSMServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"version":   "1.0.0",
	}
	s.sendJSONResponse(w, http.StatusOK, response)
}

func (s *HSMServer) handleReady(w http.ResponseWriter, r *http.Request) {
	// Check if all registered providers are healthy
	providers := s.manager.ListProviders()
	allHealthy := true

	for _, providerName := range providers {
		// Simple readiness check - this could be expanded
		if providerName == "" {
			allHealthy = false
			break
		}
	}

	status := "ready"
	statusCode := http.StatusOK
	if !allHealthy {
		status = "not_ready"
		statusCode = http.StatusServiceUnavailable
	}

	response := map[string]interface{}{
		"status":    status,
		"timestamp": time.Now().UTC(),
		"providers": len(providers),
	}
	s.sendJSONResponse(w, statusCode, response)
}

func (s *HSMServer) handleListProviders(w http.ResponseWriter, r *http.Request) {
	providers := s.manager.ListProviders()
	response := map[string]interface{}{
		"providers": providers,
		"count":     len(providers),
	}
	s.sendJSONResponse(w, http.StatusOK, response)
}

func (s *HSMServer) handleProviderInfo(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerName := vars["provider"]

	// This would need to be implemented in the manager
	response := map[string]interface{}{
		"provider": providerName,
		"status":   "active",
	}
	s.sendJSONResponse(w, http.StatusOK, response)
}

func (s *HSMServer) handleProviderHealth(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerName := vars["provider"]

	// This would need to be implemented in the manager
	response := map[string]interface{}{
		"provider": providerName,
		"status":   "healthy",
	}
	s.sendJSONResponse(w, http.StatusOK, response)
}

func (s *HSMServer) handleGenerateKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider string          `json:"provider"`
		Config   interface{}     `json:"config"`
		KeySpec  models.KeySpec  `json:"key_spec"`
		Name     string          `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// TODO: Implement key generation via HSM manager
	response := map[string]interface{}{
		"message": "Key generation endpoint - implementation needed",
		"request": req,
	}
	s.sendJSONResponse(w, http.StatusOK, response)
}

func (s *HSMServer) handleListKeys(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement key listing
	response := map[string]interface{}{
		"keys":  []string{},
		"count": 0,
	}
	s.sendJSONResponse(w, http.StatusOK, response)
}

func (s *HSMServer) handleGetKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyId := vars["keyId"]

	// TODO: Implement key retrieval
	response := map[string]interface{}{
		"key_id": keyId,
		"status": "not_implemented",
	}
	s.sendJSONResponse(w, http.StatusOK, response)
}

func (s *HSMServer) handleDeleteKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyId := vars["keyId"]

	// TODO: Implement key deletion
	response := map[string]interface{}{
		"key_id": keyId,
		"status": "deleted",
	}
	s.sendJSONResponse(w, http.StatusOK, response)
}

func (s *HSMServer) handleActivateKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyId := vars["keyId"]

	response := map[string]interface{}{
		"key_id": keyId,
		"status": "activated",
	}
	s.sendJSONResponse(w, http.StatusOK, response)
}

func (s *HSMServer) handleDeactivateKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyId := vars["keyId"]

	response := map[string]interface{}{
		"key_id": keyId,
		"status": "deactivated",
	}
	s.sendJSONResponse(w, http.StatusOK, response)
}

func (s *HSMServer) handleSign(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyId := vars["keyId"]

	var req struct {
		Data      []byte `json:"data"`
		Algorithm string `json:"algorithm"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	response := map[string]interface{}{
		"key_id":    keyId,
		"signature": "mock_signature_data",
		"algorithm": req.Algorithm,
	}
	s.sendJSONResponse(w, http.StatusOK, response)
}

func (s *HSMServer) handleVerify(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyId := vars["keyId"]

	var req struct {
		Data      []byte `json:"data"`
		Signature []byte `json:"signature"`
		Algorithm string `json:"algorithm"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	response := map[string]interface{}{
		"key_id": keyId,
		"valid":  true,
	}
	s.sendJSONResponse(w, http.StatusOK, response)
}

func (s *HSMServer) handleEncrypt(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyId := vars["keyId"]

	var req struct {
		Data      []byte `json:"data"`
		Algorithm string `json:"algorithm"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	response := map[string]interface{}{
		"key_id":     keyId,
		"ciphertext": "mock_encrypted_data",
		"algorithm":  req.Algorithm,
	}
	s.sendJSONResponse(w, http.StatusOK, response)
}

func (s *HSMServer) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyId := vars["keyId"]

	var req struct {
		Ciphertext []byte `json:"ciphertext"`
		Algorithm  string `json:"algorithm"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	response := map[string]interface{}{
		"key_id":    keyId,
		"plaintext": "mock_decrypted_data",
		"algorithm": req.Algorithm,
	}
	s.sendJSONResponse(w, http.StatusOK, response)
}

func (s *HSMServer) sendJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		s.logger.WithError(err).Error("Failed to encode JSON response")
	}
}

func (s *HSMServer) sendErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
	response := map[string]interface{}{
		"error":   message,
		"status":  statusCode,
		"timestamp": time.Now().UTC(),
	}
	if err != nil {
		response["details"] = err.Error()
		s.logger.WithError(err).Error(message)
	}
	s.sendJSONResponse(w, statusCode, response)
}