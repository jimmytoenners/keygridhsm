package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

// EventType represents the type of audit event
type EventType string

const (
	// Key lifecycle events
	EventKeyGenerate   EventType = "key_generate"
	EventKeyImport     EventType = "key_import"
	EventKeyExport     EventType = "key_export"
	EventKeyDelete     EventType = "key_delete"
	EventKeyActivate   EventType = "key_activate"
	EventKeyDeactivate EventType = "key_deactivate"
	EventKeyRotate     EventType = "key_rotate"

	// Cryptographic operations
	EventKeySign    EventType = "key_sign"
	EventKeyVerify  EventType = "key_verify"
	EventKeyEncrypt EventType = "key_encrypt"
	EventKeyDecrypt EventType = "key_decrypt"
	EventKeyWrap    EventType = "key_wrap"
	EventKeyUnwrap  EventType = "key_unwrap"

	// Authentication and authorization
	EventAuthLogin    EventType = "auth_login"
	EventAuthLogout   EventType = "auth_logout"
	EventAuthFailure  EventType = "auth_failure"
	EventAuthSuccess  EventType = "auth_success"
	EventAccessDenied EventType = "access_denied"

	// Administrative actions
	EventProviderRegister   EventType = "provider_register"
	EventProviderUnregister EventType = "provider_unregister"
	EventConfigChange       EventType = "config_change"
	EventSystemStartup      EventType = "system_startup"
	EventSystemShutdown     EventType = "system_shutdown"

	// Security events
	EventSecurityViolation  EventType = "security_violation"
	EventRateLimitExceeded  EventType = "rate_limit_exceeded"
	EventSuspiciousActivity EventType = "suspicious_activity"
)

// AuditEvent represents a single audit event
type AuditEvent struct {
	// Event metadata
	EventID   string    `json:"event_id"`
	Timestamp time.Time `json:"timestamp"`
	EventType EventType `json:"event_type"`
	Severity  string    `json:"severity"`

	// Context information
	UserID    string `json:"user_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	ClientIP  string `json:"client_ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`

	// HSM-specific information
	Provider  string `json:"provider,omitempty"`
	KeyID     string `json:"key_id,omitempty"`
	KeyType   string `json:"key_type,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`

	// Event details
	Action   string                 `json:"action"`
	Resource string                 `json:"resource,omitempty"`
	Result   string                 `json:"result"`
	Message  string                 `json:"message"`
	Error    string                 `json:"error,omitempty"`
	Details  map[string]interface{} `json:"details,omitempty"`

	// Compliance fields
	DataClassification string `json:"data_classification,omitempty"`
	RetentionPeriod    string `json:"retention_period,omitempty"`

	// Performance metrics
	Duration     *time.Duration `json:"duration,omitempty"`
	ResponseSize *int64         `json:"response_size,omitempty"`
	RequestSize  *int64         `json:"request_size,omitempty"`
}

// AuditLogger interface for audit logging implementations
type AuditLogger interface {
	LogEvent(ctx context.Context, event *AuditEvent) error
	Close() error
}

// FileAuditLogger implements audit logging to files
type FileAuditLogger struct {
	file   io.WriteCloser
	logger *logrus.Logger
}

// NewFileAuditLogger creates a new file-based audit logger
func NewFileAuditLogger(filename string) (*FileAuditLogger, error) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file: %w", err)
	}

	logger := logrus.New()
	logger.SetOutput(file)
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat:   time.RFC3339Nano,
		DisableHTMLEscape: true,
	})
	logger.SetLevel(logrus.InfoLevel)

	return &FileAuditLogger{
		file:   file,
		logger: logger,
	}, nil
}

// LogEvent logs an audit event to file
func (f *FileAuditLogger) LogEvent(ctx context.Context, event *AuditEvent) error {
	// Convert event to structured log entry
	entry := f.logger.WithFields(logrus.Fields{
		"audit_event_id":   event.EventID,
		"audit_event_type": event.EventType,
		"audit_severity":   event.Severity,
		"audit_user_id":    event.UserID,
		"audit_session_id": event.SessionID,
		"audit_request_id": event.RequestID,
		"audit_client_ip":  event.ClientIP,
		"audit_provider":   event.Provider,
		"audit_key_id":     event.KeyID,
		"audit_key_type":   event.KeyType,
		"audit_algorithm":  event.Algorithm,
		"audit_action":     event.Action,
		"audit_resource":   event.Resource,
		"audit_result":     event.Result,
		"audit_error":      event.Error,
		"audit_details":    event.Details,
	})

	if event.Duration != nil {
		entry = entry.WithField("audit_duration_ms", event.Duration.Milliseconds())
	}

	entry.Info(event.Message)
	return nil
}

// Close closes the audit log file
func (f *FileAuditLogger) Close() error {
	return f.file.Close()
}

// StdoutAuditLogger implements audit logging to stdout
type StdoutAuditLogger struct {
	logger *logrus.Logger
}

// NewStdoutAuditLogger creates a new stdout-based audit logger
func NewStdoutAuditLogger() *StdoutAuditLogger {
	logger := logrus.New()
	logger.SetOutput(os.Stdout)
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat:   time.RFC3339Nano,
		DisableHTMLEscape: true,
	})
	logger.SetLevel(logrus.InfoLevel)

	return &StdoutAuditLogger{
		logger: logger,
	}
}

// LogEvent logs an audit event to stdout
func (s *StdoutAuditLogger) LogEvent(ctx context.Context, event *AuditEvent) error {
	// Convert event to JSON and log
	jsonData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	s.logger.WithField("audit", string(jsonData)).Info("Audit Event")
	return nil
}

// Close is a no-op for stdout logger
func (s *StdoutAuditLogger) Close() error {
	return nil
}

// MultiAuditLogger logs to multiple audit loggers simultaneously
type MultiAuditLogger struct {
	loggers []AuditLogger
}

// NewMultiAuditLogger creates a new multi-destination audit logger
func NewMultiAuditLogger(loggers ...AuditLogger) *MultiAuditLogger {
	return &MultiAuditLogger{
		loggers: loggers,
	}
}

// LogEvent logs an audit event to all configured loggers
func (m *MultiAuditLogger) LogEvent(ctx context.Context, event *AuditEvent) error {
	for _, logger := range m.loggers {
		if err := logger.LogEvent(ctx, event); err != nil {
			// Log error but continue with other loggers
			fmt.Fprintf(os.Stderr, "Audit logging error: %v\n", err)
		}
	}
	return nil
}

// Close closes all audit loggers
func (m *MultiAuditLogger) Close() error {
	var lastErr error
	for _, logger := range m.loggers {
		if err := logger.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// AuditManager manages audit logging for the HSM system
type AuditManager struct {
	logger  AuditLogger
	enabled bool
}

// NewAuditManager creates a new audit manager
func NewAuditManager(logger AuditLogger, enabled bool) *AuditManager {
	return &AuditManager{
		logger:  logger,
		enabled: enabled,
	}
}

// LogKeyOperation logs a key-related operation
func (a *AuditManager) LogKeyOperation(ctx context.Context, eventType EventType, provider, keyID, keyType, algorithm, action, result, message string, duration *time.Duration, details map[string]interface{}) error {
	if !a.enabled {
		return nil
	}

	event := &AuditEvent{
		EventID:            generateEventID(),
		Timestamp:          time.Now().UTC(),
		EventType:          eventType,
		Severity:           "INFO",
		Provider:           provider,
		KeyID:              keyID,
		KeyType:            keyType,
		Algorithm:          algorithm,
		Action:             action,
		Resource:           fmt.Sprintf("key:%s", keyID),
		Result:             result,
		Message:            message,
		Details:            details,
		Duration:           duration,
		DataClassification: "SENSITIVE",
		RetentionPeriod:    "7_YEARS", // Typical compliance requirement
	}

	// Extract context information if available
	if userID := ctx.Value("user_id"); userID != nil {
		event.UserID = fmt.Sprintf("%v", userID)
	}
	if sessionID := ctx.Value("session_id"); sessionID != nil {
		event.SessionID = fmt.Sprintf("%v", sessionID)
	}
	if requestID := ctx.Value("request_id"); requestID != nil {
		event.RequestID = fmt.Sprintf("%v", requestID)
	}
	if clientIP := ctx.Value("client_ip"); clientIP != nil {
		event.ClientIP = fmt.Sprintf("%v", clientIP)
	}

	return a.logger.LogEvent(ctx, event)
}

// LogAuthenticationEvent logs an authentication-related event
func (a *AuditManager) LogAuthenticationEvent(ctx context.Context, eventType EventType, userID, method, result, message string, clientIP string, details map[string]interface{}) error {
	if !a.enabled {
		return nil
	}

	severity := "INFO"
	if result == "failure" || result == "denied" {
		severity = "WARNING"
	}

	event := &AuditEvent{
		EventID:            generateEventID(),
		Timestamp:          time.Now().UTC(),
		EventType:          eventType,
		Severity:           severity,
		UserID:             userID,
		ClientIP:           clientIP,
		Action:             string(eventType),
		Result:             result,
		Message:            message,
		Details:            details,
		DataClassification: "CONFIDENTIAL",
		RetentionPeriod:    "3_YEARS",
	}

	if method != "" {
		if event.Details == nil {
			event.Details = make(map[string]interface{})
		}
		event.Details["auth_method"] = method
	}

	return a.logger.LogEvent(ctx, event)
}

// LogSecurityEvent logs a security-related event
func (a *AuditManager) LogSecurityEvent(ctx context.Context, eventType EventType, severity, action, resource, message string, details map[string]interface{}) error {
	if !a.enabled {
		return nil
	}

	event := &AuditEvent{
		EventID:            generateEventID(),
		Timestamp:          time.Now().UTC(),
		EventType:          eventType,
		Severity:           severity,
		Action:             action,
		Resource:           resource,
		Result:             "detected",
		Message:            message,
		Details:            details,
		DataClassification: "RESTRICTED",
		RetentionPeriod:    "10_YEARS",
	}

	// Extract context information if available
	if userID := ctx.Value("user_id"); userID != nil {
		event.UserID = fmt.Sprintf("%v", userID)
	}
	if clientIP := ctx.Value("client_ip"); clientIP != nil {
		event.ClientIP = fmt.Sprintf("%v", clientIP)
	}

	return a.logger.LogEvent(ctx, event)
}

// LogSystemEvent logs a system-level event
func (a *AuditManager) LogSystemEvent(ctx context.Context, eventType EventType, action, message string, details map[string]interface{}) error {
	if !a.enabled {
		return nil
	}

	event := &AuditEvent{
		EventID:            generateEventID(),
		Timestamp:          time.Now().UTC(),
		EventType:          eventType,
		Severity:           "INFO",
		Action:             action,
		Result:             "completed",
		Message:            message,
		Details:            details,
		DataClassification: "INTERNAL",
		RetentionPeriod:    "1_YEAR",
	}

	return a.logger.LogEvent(ctx, event)
}

// Close closes the audit logger
func (a *AuditManager) Close() error {
	if a.logger != nil {
		return a.logger.Close()
	}
	return nil
}

// generateEventID generates a unique event ID
func generateEventID() string {
	// Use timestamp + random component for uniqueness
	return fmt.Sprintf("audit_%d_%d", time.Now().UnixNano(), time.Now().Nanosecond()%10000)
}

// AuditContext provides audit context information
type AuditContext struct {
	UserID    string
	SessionID string
	RequestID string
	ClientIP  string
	UserAgent string
}

// NewAuditContext creates a new audit context
func NewAuditContext(userID, sessionID, requestID, clientIP, userAgent string) *AuditContext {
	return &AuditContext{
		UserID:    userID,
		SessionID: sessionID,
		RequestID: requestID,
		ClientIP:  clientIP,
		UserAgent: userAgent,
	}
}

// WithAuditContext adds audit context to a Go context
func WithAuditContext(ctx context.Context, auditCtx *AuditContext) context.Context {
	ctx = context.WithValue(ctx, "user_id", auditCtx.UserID)
	ctx = context.WithValue(ctx, "session_id", auditCtx.SessionID)
	ctx = context.WithValue(ctx, "request_id", auditCtx.RequestID)
	ctx = context.WithValue(ctx, "client_ip", auditCtx.ClientIP)
	ctx = context.WithValue(ctx, "user_agent", auditCtx.UserAgent)
	return ctx
}
