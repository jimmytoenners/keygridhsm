package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/jimmy/keygridhsm/internal/core"
	"github.com/jimmy/keygridhsm/pkg/models"
)

// Config holds the HTTP server configuration
type Config struct {
	Host    string
	Port    string
	Logger  *logrus.Logger
	Manager *core.HSMManager
}

// HTTPServer represents the HTTP API server for KeyGrid HSM
type HTTPServer struct {
	config     Config
	router     *mux.Router
	httpServer *http.Server
}

// NewHTTPServer creates a new HTTP server instance
func NewHTTPServer(config Config) *HTTPServer {
	server := &HTTPServer{
		config: config,
		router: mux.NewRouter(),
	}

	server.setupRoutes()
	return server
}

// setupRoutes configures the HTTP routes
func (s *HTTPServer) setupRoutes() {
	// Health check endpoint
	s.router.HandleFunc("/health", s.healthCheckHandler).Methods("GET")

	// API v1 routes
	api := s.router.PathPrefix("/api/v1").Subrouter()

	// Provider routes
	api.HandleFunc("/providers", s.listProvidersHandler).Methods("GET")
	api.HandleFunc("/providers/{provider}/health", s.providerHealthHandler).Methods("GET")

	// Key management routes
	api.HandleFunc("/providers/{provider}/keys", s.listKeysHandler).Methods("GET")
	api.HandleFunc("/providers/{provider}/keys", s.generateKeyHandler).Methods("POST")
	api.HandleFunc("/providers/{provider}/keys/{keyId}", s.getKeyHandler).Methods("GET")
	api.HandleFunc("/providers/{provider}/keys/{keyId}", s.deleteKeyHandler).Methods("DELETE")
	api.HandleFunc("/providers/{provider}/keys/{keyId}/activate", s.activateKeyHandler).Methods("POST")
	api.HandleFunc("/providers/{provider}/keys/{keyId}/deactivate", s.deactivateKeyHandler).Methods("POST")

	// Cryptographic operations
	api.HandleFunc("/providers/{provider}/keys/{keyId}/sign", s.signHandler).Methods("POST")
	api.HandleFunc("/providers/{provider}/keys/{keyId}/verify", s.verifyHandler).Methods("POST")
	api.HandleFunc("/providers/{provider}/keys/{keyId}/encrypt", s.encryptHandler).Methods("POST")
	api.HandleFunc("/providers/{provider}/keys/{keyId}/decrypt", s.decryptHandler).Methods("POST")

	// Middleware
	s.router.Use(s.loggingMiddleware)
	s.router.Use(s.corsMiddleware)
}

// Start starts the HTTP server
func (s *HTTPServer) Start() error {
	addr := fmt.Sprintf("%s:%s", s.config.Host, s.config.Port)

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	s.config.Logger.Infof("Starting KeyGrid HSM HTTP server on %s", addr)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the HTTP server
func (s *HTTPServer) Shutdown(ctx context.Context) error {
	s.config.Logger.Info("Shutting down HTTP server...")
	return s.httpServer.Shutdown(ctx)
}

// HTTP Handlers

// healthCheckHandler handles health check requests
func (s *HTTPServer) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"service":   "keygrid-hsm",
		"version":   "1.0.0",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to encode response: %v", err))
		return
	}
}

// listProvidersHandler handles listing available providers
func (s *HTTPServer) listProvidersHandler(w http.ResponseWriter, r *http.Request) {
	if s.config.Manager == nil {
		s.writeError(w, http.StatusInternalServerError, "HSM manager not available")
		return
	}

	// This would need to be implemented in the core.ProviderRegistry
	providers := []string{"mock-hsm", "custom-storage"} // Placeholder

	response := map[string]interface{}{
		"providers": providers,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to encode response: %v", err))
		return
	}
}

// providerHealthHandler checks provider health
func (s *HTTPServer) providerHealthHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerName := vars["provider"]

	if s.config.Manager == nil {
		s.writeError(w, http.StatusInternalServerError, "HSM manager not available")
		return
	}

	// This would need to be implemented in the HSM manager
	// ctx := r.Context()
	// healthy, err := s.config.Manager.CheckProviderHealth(ctx, providerName)

	// Placeholder implementation
	response := map[string]interface{}{
		"provider": providerName,
		"healthy":  true,
		"status":   "ok",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to encode response: %v", err))
		return
	}
}

// generateKeyHandler handles key generation requests
func (s *HTTPServer) generateKeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerName := vars["provider"]

	var req struct {
		KeyName   string                 `json:"keyName"`
		KeyType   models.KeyType         `json:"keyType"`
		KeySize   int                    `json:"keySize"`
		Algorithm string                 `json:"algorithm"`
		Usage     []models.KeyUsage      `json:"usage"`
		Config    map[string]interface{} `json:"config"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	keySpec := models.KeySpec{
		KeyType:   req.KeyType,
		KeySize:   req.KeySize,
		Algorithm: req.Algorithm,
		Usage:     req.Usage,
	}

	ctx := r.Context()
	keyHandle, err := s.config.Manager.GenerateKey(ctx, providerName, req.Config, keySpec, req.KeyName)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to generate key: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(keyHandle); err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to encode key handle: %v", err))
		return
	}
}

// listKeysHandler handles key listing requests
func (s *HTTPServer) listKeysHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerName := vars["provider"]

	// Extract config from query parameters or request body
	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":           1000,
		"key_prefix":         "api",
	}

	ctx := r.Context()
	keys, err := s.config.Manager.ListKeys(ctx, providerName, config)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to list keys: %v", err))
		return
	}

	response := map[string]interface{}{
		"keys":     keys,
		"count":    len(keys),
		"provider": providerName,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to encode response: %v", err))
		return
	}
}

// getKeyHandler handles key retrieval requests
func (s *HTTPServer) getKeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerName := vars["provider"]
	keyID := vars["keyId"]

	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":           1000,
		"key_prefix":         "api",
	}

	ctx := r.Context()
	keyHandle, err := s.config.Manager.GetKey(ctx, providerName, config, keyID)
	if err != nil {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("Key not found: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(keyHandle); err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to encode key handle: %v", err))
		return
	}
}

// signHandler handles signing requests
func (s *HTTPServer) signHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerName := vars["provider"]
	keyID := vars["keyId"]

	var req struct {
		Data      []byte                 `json:"data"`
		Algorithm string                 `json:"algorithm"`
		Config    map[string]interface{} `json:"config"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	signingRequest := models.SigningRequest{
		KeyHandle: keyID,
		Data:      req.Data,
		Algorithm: req.Algorithm,
	}

	ctx := r.Context()
	response, err := s.config.Manager.Sign(ctx, providerName, req.Config, signingRequest)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to sign: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to encode response: %v", err))
		return
	}
}

// verifyHandler handles signature verification requests
func (s *HTTPServer) verifyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerName := vars["provider"]
	keyID := vars["keyId"]

	var req struct {
		Data      []byte                 `json:"data"`
		Signature []byte                 `json:"signature"`
		Algorithm string                 `json:"algorithm"`
		Config    map[string]interface{} `json:"config"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	ctx := r.Context()
	valid, err := s.config.Manager.Verify(ctx, providerName, req.Config, keyID, req.Data, req.Signature, req.Algorithm)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to verify: %v", err))
		return
	}

	response := map[string]interface{}{
		"valid":     valid,
		"keyId":     keyID,
		"algorithm": req.Algorithm,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to encode response: %v", err))
		return
	}
}

// encryptHandler handles encryption requests
func (s *HTTPServer) encryptHandler(w http.ResponseWriter, r *http.Request) {
	// Implementation similar to signHandler
	s.writeError(w, http.StatusNotImplemented, "Encryption endpoint not yet implemented")
}

// decryptHandler handles decryption requests
func (s *HTTPServer) decryptHandler(w http.ResponseWriter, r *http.Request) {
	// Implementation similar to signHandler
	s.writeError(w, http.StatusNotImplemented, "Decryption endpoint not yet implemented")
}

// activateKeyHandler handles key activation requests
func (s *HTTPServer) activateKeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerName := vars["provider"]
	keyID := vars["keyId"]

	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":           1000,
		"key_prefix":         "api",
	}

	ctx := r.Context()
	err := s.config.Manager.ActivateKey(ctx, providerName, config, keyID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to activate key: %v", err))
		return
	}

	response := map[string]interface{}{
		"keyId":   keyID,
		"status":  "activated",
		"message": "Key successfully activated",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to encode response: %v", err))
		return
	}
}

// deactivateKeyHandler handles key deactivation requests
func (s *HTTPServer) deactivateKeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerName := vars["provider"]
	keyID := vars["keyId"]

	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":           1000,
		"key_prefix":         "api",
	}

	ctx := r.Context()
	err := s.config.Manager.DeactivateKey(ctx, providerName, config, keyID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to deactivate key: %v", err))
		return
	}

	response := map[string]interface{}{
		"keyId":   keyID,
		"status":  "deactivated",
		"message": "Key successfully deactivated",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to encode response: %v", err))
		return
	}
}

// deleteKeyHandler handles key deletion requests
func (s *HTTPServer) deleteKeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerName := vars["provider"]
	keyID := vars["keyId"]

	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":           1000,
		"key_prefix":         "api",
	}

	ctx := r.Context()
	err := s.config.Manager.DeleteKey(ctx, providerName, config, keyID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to delete key: %v", err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Middleware

// loggingMiddleware logs HTTP requests
func (s *HTTPServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a response writer wrapper to capture status code
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		s.config.Logger.WithFields(logrus.Fields{
			"method":      r.Method,
			"path":        r.URL.Path,
			"status":      rw.statusCode,
			"duration":    duration,
			"remote_addr": r.RemoteAddr,
		}).Info("HTTP request")
	})
}

// corsMiddleware adds CORS headers
func (s *HTTPServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Helper functions

// writeError writes an error response
func (s *HTTPServer) writeError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	errorResponse := map[string]interface{}{
		"error":     true,
		"message":   message,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(errorResponse)
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
