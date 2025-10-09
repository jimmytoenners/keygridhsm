// Package audit provides audit logging functionality for security
// and compliance requirements in the KeyGrid HSM system.
package audit

import (
	"context"

	"github.com/jimmy/keygridhsm/pkg/models"
)

// Auditor defines the interface for audit logging
type Auditor interface {
	// LogEvent logs an audit event
	LogEvent(ctx context.Context, event models.AuditEvent) error

	// LogEvents logs multiple audit events in batch
	LogEvents(ctx context.Context, events []models.AuditEvent) error

	// Close closes the auditor and flushes any pending events
	Close() error
}

// NoOpAuditor is a no-operation auditor for testing or when auditing is disabled
type NoOpAuditor struct{}

func (a *NoOpAuditor) LogEvent(ctx context.Context, event models.AuditEvent) error {
	return nil
}

func (a *NoOpAuditor) LogEvents(ctx context.Context, events []models.AuditEvent) error {
	return nil
}

func (a *NoOpAuditor) Close() error {
	return nil
}
