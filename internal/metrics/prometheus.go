package metrics

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	MetricsNamespace = "keygrid_hsm"
)

// PrometheusCollector implements metrics collection using Prometheus
type PrometheusCollector struct {
	// Counter metrics
	operationsTotal        *prometheus.CounterVec
	errorsTotal            *prometheus.CounterVec
	authenticationAttempts *prometheus.CounterVec
	auditEventsTotal       *prometheus.CounterVec

	// Histogram metrics
	operationDuration *prometheus.HistogramVec
	requestSize       *prometheus.HistogramVec
	responseSize      *prometheus.HistogramVec

	// Gauge metrics
	activeConnections   prometheus.Gauge
	registeredProviders prometheus.Gauge
	activeKeys          *prometheus.GaugeVec
	healthStatus        *prometheus.GaugeVec

	// Summary metrics
	keyOperationLatency *prometheus.SummaryVec
}

// NewPrometheusCollector creates a new Prometheus metrics collector
func NewPrometheusCollector() *PrometheusCollector {
	return &PrometheusCollector{
		operationsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: MetricsNamespace,
				Name:      "operations_total",
				Help:      "Total number of HSM operations",
			},
			[]string{"provider", "operation", "status"},
		),

		errorsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: MetricsNamespace,
				Name:      "errors_total",
				Help:      "Total number of errors by type",
			},
			[]string{"provider", "operation", "error_type"},
		),

		authenticationAttempts: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: MetricsNamespace,
				Name:      "authentication_attempts_total",
				Help:      "Total number of authentication attempts",
			},
			[]string{"method", "status"},
		),

		auditEventsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: MetricsNamespace,
				Name:      "audit_events_total",
				Help:      "Total number of audit events",
			},
			[]string{"event_type", "provider"},
		),

		operationDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: MetricsNamespace,
				Name:      "operation_duration_seconds",
				Help:      "Duration of HSM operations",
				Buckets:   prometheus.ExponentialBuckets(0.001, 2, 12), // 1ms to ~4s
			},
			[]string{"provider", "operation"},
		),

		requestSize: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: MetricsNamespace,
				Name:      "request_size_bytes",
				Help:      "Size of incoming requests",
				Buckets:   prometheus.ExponentialBuckets(64, 2, 10), // 64B to ~64KB
			},
			[]string{"endpoint"},
		),

		responseSize: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: MetricsNamespace,
				Name:      "response_size_bytes",
				Help:      "Size of outgoing responses",
				Buckets:   prometheus.ExponentialBuckets(64, 2, 10), // 64B to ~64KB
			},
			[]string{"endpoint"},
		),

		activeConnections: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: MetricsNamespace,
				Name:      "active_connections",
				Help:      "Number of active connections",
			},
		),

		registeredProviders: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: MetricsNamespace,
				Name:      "registered_providers",
				Help:      "Number of registered HSM providers",
			},
		),

		activeKeys: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: MetricsNamespace,
				Name:      "active_keys",
				Help:      "Number of active keys by provider",
			},
			[]string{"provider", "key_type"},
		),

		healthStatus: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: MetricsNamespace,
				Name:      "health_status",
				Help:      "Health status of providers (1=healthy, 0=unhealthy)",
			},
			[]string{"provider", "component"},
		),

		keyOperationLatency: promauto.NewSummaryVec(
			prometheus.SummaryOpts{
				Namespace:  MetricsNamespace,
				Name:       "key_operation_latency_seconds",
				Help:       "Key operation latency summary",
				Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.95: 0.005, 0.99: 0.001},
				MaxAge:     time.Minute * 5,
				AgeBuckets: 3,
			},
			[]string{"provider", "operation"},
		),
	}
}

// RecordOperation records an HSM operation with timing and status
func (p *PrometheusCollector) RecordOperation(provider, operation, status string, duration time.Duration) {
	p.operationsTotal.WithLabelValues(provider, operation, status).Inc()
	p.operationDuration.WithLabelValues(provider, operation).Observe(duration.Seconds())
	p.keyOperationLatency.WithLabelValues(provider, operation).Observe(duration.Seconds())
}

// RecordError records an error event
func (p *PrometheusCollector) RecordError(provider, operation, errorType string) {
	p.errorsTotal.WithLabelValues(provider, operation, errorType).Inc()
}

// RecordAuthentication records an authentication attempt
func (p *PrometheusCollector) RecordAuthentication(method, status string) {
	p.authenticationAttempts.WithLabelValues(method, status).Inc()
}

// RecordAuditEvent records an audit event
func (p *PrometheusCollector) RecordAuditEvent(eventType, provider string) {
	p.auditEventsTotal.WithLabelValues(eventType, provider).Inc()
}

// RecordRequestSize records the size of an incoming request
func (p *PrometheusCollector) RecordRequestSize(endpoint string, size float64) {
	p.requestSize.WithLabelValues(endpoint).Observe(size)
}

// RecordResponseSize records the size of an outgoing response
func (p *PrometheusCollector) RecordResponseSize(endpoint string, size float64) {
	p.responseSize.WithLabelValues(endpoint).Observe(size)
}

// SetActiveConnections sets the current number of active connections
func (p *PrometheusCollector) SetActiveConnections(count float64) {
	p.activeConnections.Set(count)
}

// SetRegisteredProviders sets the number of registered providers
func (p *PrometheusCollector) SetRegisteredProviders(count float64) {
	p.registeredProviders.Set(count)
}

// SetActiveKeys sets the number of active keys for a provider
func (p *PrometheusCollector) SetActiveKeys(provider, keyType string, count float64) {
	p.activeKeys.WithLabelValues(provider, keyType).Set(count)
}

// SetHealthStatus sets the health status for a provider component
func (p *PrometheusCollector) SetHealthStatus(provider, component string, healthy bool) {
	status := 0.0
	if healthy {
		status = 1.0
	}
	p.healthStatus.WithLabelValues(provider, component).Set(status)
}

// Timer provides a convenient way to time operations
type Timer struct {
	collector *PrometheusCollector
	provider  string
	operation string
	startTime time.Time
}

// NewTimer creates a new timer for measuring operation duration
func (p *PrometheusCollector) NewTimer(provider, operation string) *Timer {
	return &Timer{
		collector: p,
		provider:  provider,
		operation: operation,
		startTime: time.Now(),
	}
}

// Finish completes the timing measurement and records the operation
func (t *Timer) Finish(status string) {
	duration := time.Since(t.startTime)
	t.collector.RecordOperation(t.provider, t.operation, status, duration)
}

// FinishWithError completes the timing measurement and records an error
func (t *Timer) FinishWithError(errorType string) {
	duration := time.Since(t.startTime)
	t.collector.RecordOperation(t.provider, t.operation, "error", duration)
	t.collector.RecordError(t.provider, t.operation, errorType)
}

// Middleware provides HTTP middleware for recording request metrics
func (p *PrometheusCollector) Middleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Record request size
			if r.ContentLength > 0 {
				p.RecordRequestSize(r.URL.Path, float64(r.ContentLength))
			}

			// Call next handler
			next.ServeHTTP(w, r)

			// Record response size (if available)
			// This would require a response writer wrapper to capture size

			// Record request duration
			duration := time.Since(start)
			status := "success" // This would need to be determined from response
			p.RecordOperation("http", "request", status, duration)
		})
	}
}

// HealthCollector periodically collects health status metrics
type HealthCollector struct {
	collector *PrometheusCollector
}

// NewHealthCollector creates a new health status collector
func (p *PrometheusCollector) NewHealthCollector() *HealthCollector {
	return &HealthCollector{
		collector: p,
	}
}

// CollectHealth collects health status for all registered providers
func (h *HealthCollector) CollectHealth(ctx context.Context, providers []string) {
	// This would be called periodically to update health status
	for _, provider := range providers {
		// Example health check - in reality this would call the actual health check
		healthy := true // Replace with actual health check
		h.collector.SetHealthStatus(provider, "service", healthy)
		h.collector.SetHealthStatus(provider, "storage", healthy)
		h.collector.SetHealthStatus(provider, "network", healthy)
	}
}
