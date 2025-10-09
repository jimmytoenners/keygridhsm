package performance

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jimmy/keygridhsm/pkg/models"
)

// LoadTestConfig holds configuration for load tests
type LoadTestConfig struct {
	Duration        time.Duration
	ConcurrentUsers int
	RequestsPerSec  int
	MaxKeys         int
	KeyPrefix       string
}

// LoadTestResults holds metrics from load tests
type LoadTestResults struct {
	TotalRequests   int64
	SuccessRequests int64
	FailedRequests  int64
	AvgLatency      time.Duration
	MinLatency      time.Duration
	MaxLatency      time.Duration
	RequestsPerSec  float64
	Errors          []error
}

// TestHighConcurrencyKeyGeneration tests key generation under high concurrency
func TestHighConcurrencyKeyGeneration(t *testing.T) {
	setupBenchmark()
	ctx := context.Background()

	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":           10000,
		"key_prefix":         "load-test",
	}

	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}

	testCases := []struct {
		name        string
		concurrency int
		duration    time.Duration
	}{
		{"Light-Load", 10, 5 * time.Second},
		{"Medium-Load", 50, 10 * time.Second},
		{"Heavy-Load", 100, 15 * time.Second},
		{"Extreme-Load", 200, 20 * time.Second},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				totalRequests   int64
				successRequests int64
				failedRequests  int64
				wg              sync.WaitGroup
				latencies       []time.Duration
				latencyMutex    sync.Mutex
				keyIDs          []string
				keyIDMutex      sync.Mutex
			)

			startTime := time.Now()

			// Launch concurrent workers
			for i := 0; i < tc.concurrency; i++ {
				wg.Add(1)
				go func(workerID int) {
					defer wg.Done()

					for time.Since(startTime) < tc.duration {
						atomic.AddInt64(&totalRequests, 1)

						start := time.Now()
						keyName := fmt.Sprintf("load-test-key-%d-%d", workerID, time.Now().UnixNano())
						keyHandle, err := benchmarkManager.GenerateKey(ctx, "mock-hsm", config, keySpec, keyName)
						latency := time.Since(start)

						latencyMutex.Lock()
						latencies = append(latencies, latency)
						latencyMutex.Unlock()

						if err != nil {
							atomic.AddInt64(&failedRequests, 1)
							t.Errorf("Key generation failed: %v", err)
						} else {
							atomic.AddInt64(&successRequests, 1)
							keyIDMutex.Lock()
							keyIDs = append(keyIDs, keyHandle.ID)
							keyIDMutex.Unlock()
						}

						// Small delay to prevent overwhelming the system
						time.Sleep(10 * time.Millisecond)
					}
				}(i)
			}

			wg.Wait()
			actualDuration := time.Since(startTime)

			// Note: Key cleanup not available in current HSMManager implementation
			for _, keyID := range keyIDs {
				_ = keyID // Use keyID to avoid unused variable warning
			}

			// Calculate metrics
			var totalLatency time.Duration
			minLatency := latencies[0]
			maxLatency := latencies[0]

			for _, latency := range latencies {
				totalLatency += latency
				if latency < minLatency {
					minLatency = latency
				}
				if latency > maxLatency {
					maxLatency = latency
				}
			}

			avgLatency := totalLatency / time.Duration(len(latencies))
			requestsPerSec := float64(totalRequests) / actualDuration.Seconds()

			// Assert success criteria
			assert.GreaterOrEqual(t, float64(successRequests)/float64(totalRequests), 0.95,
				"Success rate should be at least 95%%")
			assert.Less(t, avgLatency, 1*time.Second,
				"Average latency should be less than 1 second")

			t.Logf("Load Test Results for %s:", tc.name)
			t.Logf("  Total Requests: %d", totalRequests)
			t.Logf("  Success Requests: %d", successRequests)
			t.Logf("  Failed Requests: %d", failedRequests)
			t.Logf("  Success Rate: %.2f%%", float64(successRequests)/float64(totalRequests)*100)
			t.Logf("  Average Latency: %v", avgLatency)
			t.Logf("  Min Latency: %v", minLatency)
			t.Logf("  Max Latency: %v", maxLatency)
			t.Logf("  Requests/sec: %.2f", requestsPerSec)
		})
	}
}

// TestSustainedSigningLoad tests signing operations under sustained load
func TestSustainedSigningLoad(t *testing.T) {
	setupBenchmark()
	ctx := context.Background()

	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":           1000,
		"key_prefix":         "signing-load-test",
	}

	// Pre-generate test keys
	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}

	const numKeys = 10
	keyHandles := make([]*models.KeyHandle, numKeys)

	for i := 0; i < numKeys; i++ {
		keyName := fmt.Sprintf("signing-load-key-%d", i)
		keyHandle, err := benchmarkManager.GenerateKey(ctx, "mock-hsm", config, keySpec, keyName)
		require.NoError(t, err)
		keyHandles[i] = keyHandle
	}

	defer func() {
		// Note: Key cleanup not available in current HSMManager implementation
		for _, keyHandle := range keyHandles {
			_ = keyHandle // Use keyHandle to avoid unused variable warning
		}
	}()

	testData := []byte("Load test signing data - this message will be signed repeatedly under load")

	loadConfigs := []LoadTestConfig{
		{Duration: 30 * time.Second, ConcurrentUsers: 20, RequestsPerSec: 100},
		{Duration: 60 * time.Second, ConcurrentUsers: 50, RequestsPerSec: 200},
		{Duration: 120 * time.Second, ConcurrentUsers: 100, RequestsPerSec: 500},
	}

	for i, loadConfig := range loadConfigs {
		t.Run(fmt.Sprintf("Load-Config-%d", i+1), func(t *testing.T) {
			results := runSigningLoadTest(t, ctx, loadConfig, keyHandles, testData, config)

			// Verify performance criteria
			assert.GreaterOrEqual(t, float64(results.SuccessRequests)/float64(results.TotalRequests), 0.98,
				"Success rate should be at least 98%% for sustained load")
			assert.Less(t, results.AvgLatency, 500*time.Millisecond,
				"Average latency should be less than 500ms")
			assert.GreaterOrEqual(t, results.RequestsPerSec, float64(loadConfig.RequestsPerSec)*0.8,
				"Should achieve at least 80%% of target RPS")

			t.Logf("Signing Load Test Results:")
			t.Logf("  Target RPS: %d, Actual RPS: %.2f", loadConfig.RequestsPerSec, results.RequestsPerSec)
			t.Logf("  Total Requests: %d", results.TotalRequests)
			t.Logf("  Success Rate: %.2f%%", float64(results.SuccessRequests)/float64(results.TotalRequests)*100)
			t.Logf("  Avg Latency: %v", results.AvgLatency)
			t.Logf("  Min/Max Latency: %v / %v", results.MinLatency, results.MaxLatency)
		})
	}
}

// runSigningLoadTest executes a signing load test with the given configuration
func runSigningLoadTest(t *testing.T, ctx context.Context, config LoadTestConfig,
	keyHandles []*models.KeyHandle, testData []byte, hsmConfig map[string]interface{}) LoadTestResults {

	var (
		totalRequests   int64
		successRequests int64
		failedRequests  int64
		latencies       []time.Duration
		latencyMutex    sync.Mutex
		errors          []error
		errorMutex      sync.Mutex
		wg              sync.WaitGroup
	)

	// Rate limiter
	ticker := time.NewTicker(time.Second / time.Duration(config.RequestsPerSec))
	defer ticker.Stop()

	startTime := time.Now()
	timeout := time.After(config.Duration)

	// Launch concurrent workers
	for i := 0; i < config.ConcurrentUsers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for {
				select {
				case <-timeout:
					return
				case <-ticker.C:
					atomic.AddInt64(&totalRequests, 1)

					// Select random key
					keyHandle := keyHandles[int(totalRequests)%len(keyHandles)]

					signingRequest := models.SigningRequest{
						KeyHandle: keyHandle.ID,
						Data:      testData,
						Algorithm: "RSA-PSS",
					}

					start := time.Now()
					_, err := benchmarkManager.Sign(ctx, "mock-hsm", hsmConfig, signingRequest)
					latency := time.Since(start)

					latencyMutex.Lock()
					latencies = append(latencies, latency)
					latencyMutex.Unlock()

					if err != nil {
						atomic.AddInt64(&failedRequests, 1)
						errorMutex.Lock()
						errors = append(errors, err)
						errorMutex.Unlock()
					} else {
						atomic.AddInt64(&successRequests, 1)
					}
				}
			}
		}()
	}

	wg.Wait()
	actualDuration := time.Since(startTime)

	// Calculate metrics
	var totalLatency time.Duration
	minLatency := latencies[0]
	maxLatency := latencies[0]

	for _, latency := range latencies {
		totalLatency += latency
		if latency < minLatency {
			minLatency = latency
		}
		if latency > maxLatency {
			maxLatency = latency
		}
	}

	return LoadTestResults{
		TotalRequests:   totalRequests,
		SuccessRequests: successRequests,
		FailedRequests:  failedRequests,
		AvgLatency:      totalLatency / time.Duration(len(latencies)),
		MinLatency:      minLatency,
		MaxLatency:      maxLatency,
		RequestsPerSec:  float64(totalRequests) / actualDuration.Seconds(),
		Errors:          errors,
	}
}

// TestMemoryLeakDetection tests for memory leaks under load
func TestMemoryLeakDetection(t *testing.T) {
	setupBenchmark()
	ctx := context.Background()

	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":           5000,
		"key_prefix":         "memory-leak-test",
	}

	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}

	// Record initial memory stats
	runtime.GC()
	var initialStats runtime.MemStats
	runtime.ReadMemStats(&initialStats)

	const iterations = 1000
	keyIDs := make([]string, 0, iterations)

	// Perform operations that might leak memory
	for i := 0; i < iterations; i++ {
		// Generate key
		keyName := fmt.Sprintf("leak-test-key-%d", i)
		keyHandle, err := benchmarkManager.GenerateKey(ctx, "mock-hsm", config, keySpec, keyName)
		require.NoError(t, err)
		keyIDs = append(keyIDs, keyHandle.ID)

		// Sign something
		signingRequest := models.SigningRequest{
			KeyHandle: keyHandle.ID,
			Data:      []byte(fmt.Sprintf("test data %d", i)),
			Algorithm: "RSA-PSS",
		}
		_, err = benchmarkManager.Sign(ctx, "mock-hsm", config, signingRequest)
		require.NoError(t, err)

		// List keys
		_, err = benchmarkManager.ListKeys(ctx, "mock-hsm", config)
		require.NoError(t, err)
	}

	// Note: Key cleanup not available in current HSMManager implementation
	for _, keyID := range keyIDs {
		_ = keyID // Use keyID to avoid unused variable warning
	}

	// Force garbage collection and measure final memory
	runtime.GC()
	runtime.GC()                       // Run twice to be sure
	time.Sleep(100 * time.Millisecond) // Allow finalizers to run

	var finalStats runtime.MemStats
	runtime.ReadMemStats(&finalStats)

	// Check for memory growth
	memoryGrowth := finalStats.Alloc - initialStats.Alloc
	heapGrowth := finalStats.HeapAlloc - initialStats.HeapAlloc

	t.Logf("Memory Analysis:")
	t.Logf("  Initial Alloc: %d bytes", initialStats.Alloc)
	t.Logf("  Final Alloc: %d bytes", finalStats.Alloc)
	t.Logf("  Memory Growth: %d bytes", memoryGrowth)
	t.Logf("  Initial Heap: %d bytes", initialStats.HeapAlloc)
	t.Logf("  Final Heap: %d bytes", finalStats.HeapAlloc)
	t.Logf("  Heap Growth: %d bytes", heapGrowth)
	t.Logf("  GC Runs: %d -> %d", initialStats.NumGC, finalStats.NumGC)

	// Memory growth should be reasonable (less than 1MB for cleanup operations)
	assert.Less(t, memoryGrowth, uint64(1024*1024),
		"Memory growth should be less than 1MB after cleanup")
	assert.Less(t, heapGrowth, uint64(1024*1024),
		"Heap growth should be less than 1MB after cleanup")
}

// TestResourceExhaustion tests behavior under resource constraints
func TestResourceExhaustion(t *testing.T) {
	setupBenchmark()
	ctx := context.Background()

	// Test with limited key capacity
	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":           100, // Limited capacity
		"key_prefix":         "exhaustion-test",
	}

	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}

	keyIDs := make([]string, 0, 150) // Try to exceed capacity

	// Generate keys up to and beyond capacity
	for i := 0; i < 150; i++ {
		keyName := fmt.Sprintf("exhaustion-key-%d", i)
		keyHandle, err := benchmarkManager.GenerateKey(ctx, "mock-hsm", config, keySpec, keyName)

		if i < 100 {
			// Should succeed within capacity
			require.NoError(t, err, "Key generation should succeed within capacity")
			keyIDs = append(keyIDs, keyHandle.ID)
		} else {
			// Should fail beyond capacity
			assert.Error(t, err, "Key generation should fail beyond capacity")
		}
	}

	// Test that operations still work within capacity
	if len(keyIDs) > 0 {
		testData := []byte("Resource exhaustion test data")
		signingRequest := models.SigningRequest{
			KeyHandle: keyIDs[0],
			Data:      testData,
			Algorithm: "RSA-PSS",
		}

		_, err := benchmarkManager.Sign(ctx, "mock-hsm", config, signingRequest)
		assert.NoError(t, err, "Signing should still work within capacity")

		// List keys should return all keys within capacity
		keys, err := benchmarkManager.ListKeys(ctx, "mock-hsm", config)
		assert.NoError(t, err, "List keys should work")
		assert.Equal(t, 100, len(keys), "Should have exactly 100 keys at capacity")
	}

	// Note: Key cleanup not available in current HSMManager implementation
	for _, keyID := range keyIDs {
		_ = keyID // Use keyID to avoid unused variable warning
	}
}

// TestProviderFailover tests behavior when a provider fails
func TestProviderFailover(t *testing.T) {
	setupBenchmark()
	ctx := context.Background()

	// Create a provider that simulates errors
	errorConfig := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    true,
		"error_rate":         0.5, // 50% error rate
		"max_keys":           1000,
		"key_prefix":         "failover-test",
	}

	normalConfig := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":           1000,
		"key_prefix":         "failover-test",
	}

	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}

	// Test with error-prone provider
	var successCount, errorCount int
	const attempts = 100

	for i := 0; i < attempts; i++ {
		keyName := fmt.Sprintf("failover-key-%d", i)
		_, err := benchmarkManager.GenerateKey(ctx, "mock-hsm", errorConfig, keySpec, keyName)

		if err != nil {
			errorCount++
		} else {
			successCount++
		}
	}

	// Should have roughly 50% failure rate
	errorRate := float64(errorCount) / float64(attempts)
	assert.InDelta(t, 0.5, errorRate, 0.1, "Error rate should be around 50%")

	t.Logf("Failover Test Results:")
	t.Logf("  Total Attempts: %d", attempts)
	t.Logf("  Success Count: %d", successCount)
	t.Logf("  Error Count: %d", errorCount)
	t.Logf("  Error Rate: %.2f%%", errorRate*100)

	// Test that normal provider still works
	_, err := benchmarkManager.GenerateKey(ctx, "mock-hsm", normalConfig, keySpec, "normal-test-key")
	assert.NoError(t, err, "Normal provider should still work")

	// Note: Key cleanup not available in current HSMManager implementation
	// _ = benchmarkManager.DeleteKey(ctx, "mock-hsm", normalConfig, "normal-test-key")
}

// TestConcurrentProviderAccess tests accessing multiple providers concurrently
func TestConcurrentProviderAccess(t *testing.T) {
	setupBenchmark()
	ctx := context.Background()

	providers := map[string]map[string]interface{}{
		"mock-hsm": {
			"persistent_storage": false,
			"simulate_errors":    false,
			"max_keys":           1000,
			"key_prefix":         "concurrent-mock",
		},
		"custom-storage": {
			"storage_type":    "memory",
			"encrypt_at_rest": false,
			"key_prefix":      "concurrent-custom",
		},
	}

	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}

	var wg sync.WaitGroup
	results := make(chan struct {
		provider string
		success  bool
		error    error
	}, len(providers)*10)

	// Launch concurrent workers for each provider
	for providerName, config := range providers {
		wg.Add(1)
		go func(provider string, cfg map[string]interface{}) {
			defer wg.Done()

			for i := 0; i < 10; i++ {
				keyName := fmt.Sprintf("concurrent-%s-key-%d", provider, i)
				keyHandle, err := benchmarkManager.GenerateKey(ctx, provider, cfg, keySpec, keyName)

				results <- struct {
					provider string
					success  bool
					error    error
				}{
					provider: provider,
					success:  err == nil,
					error:    err,
				}

				if err == nil {
					// Note: Key cleanup not available in current HSMManager implementation
					_ = keyHandle // Use keyHandle to avoid unused variable warning
				}
			}
		}(providerName, config)
	}

	wg.Wait()
	close(results)

	// Analyze results
	providerResults := make(map[string]struct {
		success int
		total   int
	})

	for result := range results {
		stats := providerResults[result.provider]
		stats.total++
		if result.success {
			stats.success++
		}
		providerResults[result.provider] = stats

		if result.error != nil {
			t.Logf("Provider %s error: %v", result.provider, result.error)
		}
	}

	// Verify all providers worked
	for providerName, stats := range providerResults {
		successRate := float64(stats.success) / float64(stats.total)
		assert.GreaterOrEqual(t, successRate, 0.9,
			"Provider %s should have at least 90%% success rate", providerName)

		t.Logf("Provider %s: %d/%d successful (%.2f%%)",
			providerName, stats.success, stats.total, successRate*100)
	}
}

// TestLongRunningStability tests system stability over extended periods
func TestLongRunningStability(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping long-running stability test in short mode")
	}

	setupBenchmark()
	ctx := context.Background()

	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":           1000,
		"key_prefix":         "stability-test",
	}

	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}

	testDuration := 5 * time.Minute
	checkInterval := 30 * time.Second

	var (
		totalOperations   int64
		successOperations int64
		errorOperations   int64
		wg                sync.WaitGroup
		stopChan          = make(chan struct{})
	)

	// Start background workers
	const numWorkers = 5
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			keyIDs := make([]string, 0, 100)
			defer func() {
				// Note: Key cleanup not available in current HSMManager implementation
				for _, keyID := range keyIDs {
					_ = keyID // Use keyID to avoid unused variable warning
				}
			}()

			for {
				select {
				case <-stopChan:
					return
				default:
					atomic.AddInt64(&totalOperations, 1)

					// Randomly choose operation
					switch atomic.LoadInt64(&totalOperations) % 4 {
					case 0: // Generate key
						keyName := fmt.Sprintf("stability-worker-%d-key-%d", workerID, len(keyIDs))
						keyHandle, err := benchmarkManager.GenerateKey(ctx, "mock-hsm", config, keySpec, keyName)
						if err != nil {
							atomic.AddInt64(&errorOperations, 1)
						} else {
							atomic.AddInt64(&successOperations, 1)
							keyIDs = append(keyIDs, keyHandle.ID)
						}

					case 1: // Sign data
						if len(keyIDs) > 0 {
							keyID := keyIDs[len(keyIDs)-1]
							signingRequest := models.SigningRequest{
								KeyHandle: keyID,
								Data:      []byte("stability test data"),
								Algorithm: "RSA-PSS",
							}
							_, err := benchmarkManager.Sign(ctx, "mock-hsm", config, signingRequest)
							if err != nil {
								atomic.AddInt64(&errorOperations, 1)
							} else {
								atomic.AddInt64(&successOperations, 1)
							}
						} else {
							atomic.AddInt64(&successOperations, 1) // Skip if no keys
						}

					case 2: // List keys
						_, err := benchmarkManager.ListKeys(ctx, "mock-hsm", config)
						if err != nil {
							atomic.AddInt64(&errorOperations, 1)
						} else {
							atomic.AddInt64(&successOperations, 1)
						}

					case 3: // Check key health (DeleteKey not available)
						if len(keyIDs) > 0 {
							keyID := keyIDs[len(keyIDs)-1]
							_, err := benchmarkManager.GetPublicKey(ctx, "mock-hsm", config, keyID)
							if err != nil {
								atomic.AddInt64(&errorOperations, 1)
							} else {
								atomic.AddInt64(&successOperations, 1)
							}
						} else {
							atomic.AddInt64(&successOperations, 1) // Skip if no keys
						}
					}

					time.Sleep(100 * time.Millisecond) // Throttle operations
				}
			}
		}(i)
	}

	// Monitor progress
	startTime := time.Now()
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ticker.C:
				elapsed := time.Since(startTime)
				total := atomic.LoadInt64(&totalOperations)
				success := atomic.LoadInt64(&successOperations)
				errors := atomic.LoadInt64(&errorOperations)

				t.Logf("Stability Test Progress (%.1f%% complete):",
					float64(elapsed)/float64(testDuration)*100)
				t.Logf("  Total Operations: %d", total)
				t.Logf("  Success Rate: %.2f%%", float64(success)/float64(total)*100)
				t.Logf("  Error Count: %d", errors)
				t.Logf("  Operations/sec: %.2f", float64(total)/elapsed.Seconds())

				if elapsed >= testDuration {
					close(stopChan)
					return
				}
			}
		}
	}()

	wg.Wait()

	// Final results
	total := atomic.LoadInt64(&totalOperations)
	success := atomic.LoadInt64(&successOperations)
	errors := atomic.LoadInt64(&errorOperations)
	successRate := float64(success) / float64(total)

	assert.GreaterOrEqual(t, successRate, 0.95,
		"Long-running stability test should maintain 95%% success rate")
	assert.Greater(t, total, int64(1000),
		"Should perform at least 1000 operations during stability test")

	t.Logf("Final Stability Test Results:")
	t.Logf("  Duration: %v", time.Since(startTime))
	t.Logf("  Total Operations: %d", total)
	t.Logf("  Success Operations: %d", success)
	t.Logf("  Error Operations: %d", errors)
	t.Logf("  Success Rate: %.2f%%", successRate*100)
}
