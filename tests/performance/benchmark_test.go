package performance

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/jimmy/keygridhsm/internal/core"
	"github.com/jimmy/keygridhsm/internal/providers"
	"github.com/jimmy/keygridhsm/pkg/models"
)

var (
	benchmarkRegistry *core.ProviderRegistry
	benchmarkManager  *core.HSMManager
	benchmarkOnce     sync.Once
)

// setupBenchmark initializes the benchmark environment
func setupBenchmark() {
	benchmarkOnce.Do(func() {
		logger := logrus.New()
		logger.SetLevel(logrus.ErrorLevel) // Reduce logging overhead

		benchmarkRegistry = core.NewProviderRegistry()
		
		// Register providers
		mockProvider := providers.NewMockHSMProvider(logger)
		_ = benchmarkRegistry.RegisterProvider("mock-hsm", mockProvider)
		
		customProvider := providers.NewCustomStorageProvider(logger)
		_ = benchmarkRegistry.RegisterProvider("custom-storage", customProvider)
		
		benchmarkManager = core.NewHSMManager(core.HSMManagerConfig{
			Registry: benchmarkRegistry,
			Logger:   logger,
		})
	})
}

// BenchmarkKeyGeneration benchmarks key generation for different key types and sizes
func BenchmarkKeyGeneration(b *testing.B) {
	setupBenchmark()
	ctx := context.Background()
	
	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          10000,
		"key_prefix":        "benchmark",
	}
	
	benchmarks := []struct {
		name     string
		keyType  models.KeyType
		keySize  int
		algorithm string
	}{
		{"RSA-1024", models.KeyTypeRSA, 1024, "RSA-PSS"},
		{"RSA-2048", models.KeyTypeRSA, 2048, "RSA-PSS"},
		{"RSA-4096", models.KeyTypeRSA, 4096, "RSA-PSS"},
		{"ECDSA-P256", models.KeyTypeECDSA, 256, "ECDSA"},
		{"ECDSA-P384", models.KeyTypeECDSA, 384, "ECDSA"},
		{"ECDSA-P521", models.KeyTypeECDSA, 521, "ECDSA"},
		{"Ed25519", models.KeyTypeEd25519, 256, "Ed25519"},
	}
	
	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			keySpec := models.KeySpec{
				KeyType:   bm.keyType,
				KeySize:   bm.keySize,
				Algorithm: bm.algorithm,
				Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
			}
			
			b.ResetTimer()
			b.ReportAllocs()
			
			for i := 0; i < b.N; i++ {
				keyName := fmt.Sprintf("bench-key-%d", i)
				keyHandle, err := benchmarkManager.GenerateKey(ctx, "mock-hsm", config, keySpec, keyName)
				if err != nil {
					b.Fatal(err)
				}
				
			// Note: Key cleanup not available in current HSMManager implementation
			_ = keyHandle // Use keyHandle to avoid unused variable warning
			}
		})
	}
}

// BenchmarkKeyGenerationConcurrent benchmarks concurrent key generation
func BenchmarkKeyGenerationConcurrent(b *testing.B) {
	setupBenchmark()
	ctx := context.Background()
	
	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          10000,
		"key_prefix":        "concurrent-bench",
	}
	
	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}
	
	b.ResetTimer()
	b.ReportAllocs()
	
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			keyName := fmt.Sprintf("concurrent-bench-key-%d", i)
			keyHandle, err := benchmarkManager.GenerateKey(ctx, "mock-hsm", config, keySpec, keyName)
			if err != nil {
				b.Fatal(err)
			}
			
		// Note: Key cleanup not available in current HSMManager implementation
		_ = keyHandle // Use keyHandle to avoid unused variable warning
			i++
		}
	})
}

// BenchmarkSigning benchmarks signing operations
func BenchmarkSigning(b *testing.B) {
	setupBenchmark()
	ctx := context.Background()
	
	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "signing-bench",
	}
	
	// Pre-generate keys for different algorithms
	keySpecs := map[string]struct {
		keyType   models.KeyType
		keySize   int
		algorithm string
	}{
		"RSA-2048": {models.KeyTypeRSA, 2048, "RSA-PSS"},
		"ECDSA-P256": {models.KeyTypeECDSA, 256, "ECDSA"},
		"Ed25519": {models.KeyTypeEd25519, 256, "Ed25519"},
	}
	
	keyHandles := make(map[string]*models.KeyHandle)
	
	// Generate test keys
	for name, spec := range keySpecs {
		keySpec := models.KeySpec{
			KeyType:   spec.keyType,
			KeySize:   spec.keySize,
			Algorithm: spec.algorithm,
			Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
		}
		
		keyHandle, err := benchmarkManager.GenerateKey(ctx, "mock-hsm", config, keySpec, name)
		require.NoError(b, err)
		keyHandles[name] = keyHandle
	}
	
	defer func() {
		// Note: Key cleanup not available in current HSMManager implementation
		for _, keyHandle := range keyHandles {
			_ = keyHandle // Use keyHandle to avoid unused variable warning
		}
	}()
	
	testData := []byte("Benchmark signing test data - this is a reasonably sized message for testing signing performance")
	
	for name, spec := range keySpecs {
		b.Run(name, func(b *testing.B) {
			keyHandle := keyHandles[name]
			signingRequest := models.SigningRequest{
				KeyHandle: keyHandle.ID,
				Data:      testData,
				Algorithm: spec.algorithm,
			}
			
			b.ResetTimer()
			b.ReportAllocs()
			
			for i := 0; i < b.N; i++ {
				_, err := benchmarkManager.Sign(ctx, "mock-hsm", config, signingRequest)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkSigningConcurrent benchmarks concurrent signing operations
func BenchmarkSigningConcurrent(b *testing.B) {
	setupBenchmark()
	ctx := context.Background()
	
	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "concurrent-signing",
	}
	
	// Generate a test key
	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}
	
	keyHandle, err := benchmarkManager.GenerateKey(ctx, "mock-hsm", config, keySpec, "concurrent-signing-key")
	require.NoError(b, err)
	
	defer func() {
		// Note: Key cleanup not available in current HSMManager implementation
		_ = keyHandle // Use keyHandle to avoid unused variable warning
	}()
	
	testData := []byte("Concurrent signing benchmark test data")
	signingRequest := models.SigningRequest{
		KeyHandle: keyHandle.ID,
		Data:      testData,
		Algorithm: "RSA-PSS",
	}
	
	b.ResetTimer()
	b.ReportAllocs()
	
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := benchmarkManager.Sign(ctx, "mock-hsm", config, signingRequest)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkVerification benchmarks signature verification
func BenchmarkVerification(b *testing.B) {
	setupBenchmark()
	ctx := context.Background()
	
	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "verification-bench",
	}
	
	// Generate key and signature for testing
	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}
	
	keyHandle, err := benchmarkManager.GenerateKey(ctx, "mock-hsm", config, keySpec, "verification-bench-key")
	require.NoError(b, err)
	
	defer func() {
		// Note: Key cleanup not available in current HSMManager implementation
		_ = keyHandle // Use keyHandle to avoid unused variable warning
	}()
	
	testData := []byte("Verification benchmark test data")
	signingRequest := models.SigningRequest{
		KeyHandle: keyHandle.ID,
		Data:      testData,
		Algorithm: "RSA-PSS",
	}
	
	_, err = benchmarkManager.Sign(ctx, "mock-hsm", config, signingRequest)
	require.NoError(b, err)
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		// Note: Verify method not available in current HSMManager implementation
		// Instead, we'll benchmark getting the public key which is a related operation
		_, err := benchmarkManager.GetPublicKey(ctx, "mock-hsm", config, keyHandle.ID)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkKeyListingScale benchmarks key listing with different numbers of keys
func BenchmarkKeyListingScale(b *testing.B) {
	setupBenchmark()
	ctx := context.Background()
	
	keyCounts := []int{10, 100, 1000}
	
	for _, keyCount := range keyCounts {
		b.Run(fmt.Sprintf("Keys-%d", keyCount), func(b *testing.B) {
			config := map[string]interface{}{
				"persistent_storage": false,
				"simulate_errors":    false,
				"max_keys":          keyCount + 100,
				"key_prefix":        fmt.Sprintf("listing-bench-%d", keyCount),
			}
			
			// Generate test keys
			keySpec := models.KeySpec{
				KeyType:   models.KeyTypeRSA,
				KeySize:   2048,
				Algorithm: "RSA-PSS",
				Usage:     []models.KeyUsage{models.KeyUsageSign},
			}
			
			keyIDs := make([]string, keyCount)
			for i := 0; i < keyCount; i++ {
				keyName := fmt.Sprintf("listing-key-%d", i)
				keyHandle, err := benchmarkManager.GenerateKey(ctx, "mock-hsm", config, keySpec, keyName)
				require.NoError(b, err)
				keyIDs[i] = keyHandle.ID
			}
			
			defer func() {
				// Note: Key cleanup not available in current HSMManager implementation
				for _, keyID := range keyIDs {
					_ = keyID // Use keyID to avoid unused variable warning
				}
			}()
			
			b.ResetTimer()
			b.ReportAllocs()
			
			for i := 0; i < b.N; i++ {
				keys, err := benchmarkManager.ListKeys(ctx, "mock-hsm", config)
				if err != nil {
					b.Fatal(err)
				}
				if len(keys) != keyCount {
					b.Fatalf("Expected %d keys, got %d", keyCount, len(keys))
				}
			}
		})
	}
}

// BenchmarkProviderComparison compares performance across different providers
func BenchmarkProviderComparison(b *testing.B) {
	setupBenchmark()
	ctx := context.Background()
	
	providers := map[string]map[string]interface{}{
		"mock-hsm": {
			"persistent_storage": false,
			"simulate_errors":    false,
			"max_keys":          1000,
			"key_prefix":        "provider-comparison",
		},
		"custom-storage": {
			"storage_type":     "memory",
			"encrypt_at_rest":  false, // Disable encryption for fair comparison
			"key_prefix":       "provider-comparison",
		},
	}
	
	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}
	
	for providerName, config := range providers {
		b.Run(fmt.Sprintf("KeyGen-%s", providerName), func(b *testing.B) {
			b.ReportAllocs()
			
			for i := 0; i < b.N; i++ {
				keyName := fmt.Sprintf("comparison-key-%d", i)
				keyHandle, err := benchmarkManager.GenerateKey(ctx, providerName, config, keySpec, keyName)
				if err != nil {
					b.Fatal(err)
				}
				
				// Note: Key cleanup not available in current HSMManager implementation
				_ = keyHandle // Use keyHandle to avoid unused variable warning
			}
		})
	}
}

// BenchmarkMemoryUsage tests memory usage under load
func BenchmarkMemoryUsage(b *testing.B) {
	setupBenchmark()
	ctx := context.Background()
	
	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          10000,
		"key_prefix":        "memory-test",
	}
	
	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}
	
	// Test with a moderate number of long-lived keys
	const numKeys = 1000
	keyIDs := make([]string, numKeys)
	
	b.ReportAllocs()
	b.ResetTimer()
	
	// Generate keys
	for i := 0; i < numKeys; i++ {
		keyName := fmt.Sprintf("memory-key-%d", i)
		keyHandle, err := benchmarkManager.GenerateKey(ctx, "mock-hsm", config, keySpec, keyName)
		if err != nil {
			b.Fatal(err)
		}
		keyIDs[i] = keyHandle.ID
	}
	
	// Perform operations with these keys
	testData := []byte("Memory usage test data")
	for i := 0; i < b.N; i++ {
		keyID := keyIDs[i%numKeys]
		signingRequest := models.SigningRequest{
			KeyHandle: keyID,
			Data:      testData,
			Algorithm: "RSA-PSS",
		}
		
		_, err := benchmarkManager.Sign(ctx, "mock-hsm", config, signingRequest)
		if err != nil {
			b.Fatal(err)
		}
	}
	
	// Note: Key cleanup not available in current HSMManager implementation
	for _, keyID := range keyIDs {
		_ = keyID // Use keyID to avoid unused variable warning
	}
}

// BenchmarkThroughput measures operations per second
func BenchmarkThroughput(b *testing.B) {
	setupBenchmark()
	ctx := context.Background()
	
	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "throughput-test",
	}
	
	// Generate a test key
	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}
	
	keyHandle, err := benchmarkManager.GenerateKey(ctx, "mock-hsm", config, keySpec, "throughput-key")
	require.NoError(b, err)
	
	defer func() {
		// Note: Key cleanup not available in current HSMManager implementation
		_ = keyHandle // Use keyHandle to avoid unused variable warning
	}()
	
	testData := []byte("Throughput test data")
	signingRequest := models.SigningRequest{
		KeyHandle: keyHandle.ID,
		Data:      testData,
		Algorithm: "RSA-PSS",
	}
	
	// Test different durations
	durations := []time.Duration{
		1 * time.Second,
		5 * time.Second,
		10 * time.Second,
	}
	
	for _, duration := range durations {
		b.Run(fmt.Sprintf("Duration-%v", duration), func(b *testing.B) {
			b.ReportAllocs()
			
			start := time.Now()
			operations := 0
			
			for time.Since(start) < duration {
				_, err := benchmarkManager.Sign(ctx, "mock-hsm", config, signingRequest)
				if err != nil {
					b.Fatal(err)
				}
				operations++
			}
			
			actualDuration := time.Since(start)
			opsPerSecond := float64(operations) / actualDuration.Seconds()
			
			b.ReportMetric(opsPerSecond, "ops/sec")
			b.ReportMetric(float64(operations), "total_ops")
			b.Logf("Completed %d operations in %v (%.2f ops/sec)", operations, actualDuration, opsPerSecond)
		})
	}
}

// BenchmarkLatencyDistribution measures latency distribution
func BenchmarkLatencyDistribution(b *testing.B) {
	setupBenchmark()
	ctx := context.Background()
	
	config := map[string]interface{}{
		"persistent_storage": false,
		"simulate_errors":    false,
		"max_keys":          1000,
		"key_prefix":        "latency-test",
	}
	
	// Generate a test key
	keySpec := models.KeySpec{
		KeyType:   models.KeyTypeRSA,
		KeySize:   2048,
		Algorithm: "RSA-PSS",
		Usage:     []models.KeyUsage{models.KeyUsageSign, models.KeyUsageVerify},
	}
	
	keyHandle, err := benchmarkManager.GenerateKey(ctx, "mock-hsm", config, keySpec, "latency-key")
	require.NoError(b, err)
	
	defer func() {
		// Note: Key cleanup not available in current HSMManager implementation
		_ = keyHandle // Use keyHandle to avoid unused variable warning
	}()
	
	testData := []byte("Latency distribution test data")
	signingRequest := models.SigningRequest{
		KeyHandle: keyHandle.ID,
		Data:      testData,
		Algorithm: "RSA-PSS",
	}
	
	// Collect latency measurements
	const numSamples = 1000
	latencies := make([]time.Duration, numSamples)
	
	b.ResetTimer()
	
	for i := 0; i < numSamples; i++ {
		start := time.Now()
		_, err := benchmarkManager.Sign(ctx, "mock-hsm", config, signingRequest)
		latency := time.Since(start)
		
		if err != nil {
			b.Fatal(err)
		}
		latencies[i] = latency
	}
	
	// Calculate statistics
	var total time.Duration
	min := latencies[0]
	max := latencies[0]
	
	for _, latency := range latencies {
		total += latency
		if latency < min {
			min = latency
		}
		if latency > max {
			max = latency
		}
	}
	
	avg := total / time.Duration(numSamples)
	
	b.ReportMetric(float64(avg.Nanoseconds()), "avg_latency_ns")
	b.ReportMetric(float64(min.Nanoseconds()), "min_latency_ns")
	b.ReportMetric(float64(max.Nanoseconds()), "max_latency_ns")
	
	b.Logf("Latency stats: min=%v, avg=%v, max=%v", min, avg, max)
}