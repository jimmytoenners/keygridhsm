package metrics

import (
	"time"
)

// Collector defines the interface for metrics collection
type Collector interface {
	// RecordOperation records an HSM operation with its outcome
	RecordOperation(operation, provider string, duration time.Duration, success bool, err error)

	// RecordHealthCheck records a health check result
	RecordHealthCheck(provider string, healthy bool, duration time.Duration)

	// Close closes the metrics collector
	Close() error
}

// NoOpCollector is a no-operation metrics collector for testing or when metrics are disabled
type NoOpCollector struct{}

func (c *NoOpCollector) RecordOperation(operation, provider string, duration time.Duration, success bool, err error) {
	// No-op
}

func (c *NoOpCollector) RecordHealthCheck(provider string, healthy bool, duration time.Duration) {
	// No-op
}

func (c *NoOpCollector) Close() error {
	return nil
}
