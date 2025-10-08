# KeyGrid HSM Testing Suite

This directory contains a comprehensive testing suite for the KeyGrid HSM system, covering all aspects from unit tests to end-to-end integration testing.

## Test Structure

```
tests/
├── unit/                    # Unit tests for individual components
│   ├── provider_registry_test.go    # Provider registry functionality
│   └── ...
├── integration/             # Integration tests for complete workflows
│   ├── hsm_integration_test.go      # End-to-end HSM workflows
│   └── ...
├── performance/             # Performance and load testing
│   ├── benchmark_test.go            # Benchmark tests for operations
│   ├── loadtest_test.go            # Load testing and stress tests
│   └── ...
├── security/                # Security and vulnerability testing
│   ├── security_test.go            # Security-focused tests
│   └── ...
├── e2e/                     # End-to-end system tests
│   ├── e2e_test.go                 # Complete system validation
│   └── ...
└── README.md               # This file
```

## Test Categories

### 1. Unit Tests (`tests/unit/`)

Unit tests focus on testing individual components in isolation:

- **Provider Registry Tests**: Test provider registration, lifecycle, and isolation
- **Core Manager Tests**: Test HSM manager functionality
- **Provider Tests**: Test individual HSM providers
- **Model Tests**: Test data models and validation

**Key Features:**
- Fast execution (< 1 minute)
- No external dependencies
- High code coverage
- Focused on specific functionality

### 2. Integration Tests (`tests/integration/`)

Integration tests validate complete workflows across multiple components:

- **HSM Workflows**: End-to-end key lifecycle management
- **Multi-Provider Testing**: Cross-provider functionality
- **Key Type Testing**: All supported cryptographic key types
- **Concurrent Operations**: Multi-threaded testing
- **Error Handling**: Comprehensive error condition testing

**Key Features:**
- Complete workflow validation
- Multiple key types (RSA, ECDSA, Ed25519)
- Concurrent operation testing
- Provider isolation validation
- Comprehensive error scenarios

### 3. Performance Tests (`tests/performance/`)

Performance tests measure system performance and scalability:

- **Benchmark Tests**: Operation performance measurement
- **Load Tests**: High-concurrency and sustained load testing
- **Memory Tests**: Memory usage and leak detection
- **Latency Tests**: Response time distribution analysis
- **Throughput Tests**: Operations per second measurement

**Key Features:**
- Detailed performance metrics
- Memory leak detection
- Concurrent load testing
- Latency distribution analysis
- Provider performance comparison

### 4. Security Tests (`tests/security/`)

Security tests focus on cryptographic security and system hardening:

- **Key Isolation**: Multi-tenant key isolation
- **Input Validation**: Security through input validation
- **Signature Validation**: Cryptographic integrity
- **Timing Attack Resistance**: Side-channel attack prevention
- **Secure Deletion**: Secure key disposal
- **Provider Isolation**: Security boundaries between providers

**Key Features:**
- Cryptographic security validation
- Multi-tenant isolation testing
- Input validation and sanitization
- Timing attack resistance
- Secure key lifecycle management

### 5. End-to-End Tests (`tests/e2e/`)

End-to-end tests validate the complete system in realistic scenarios:

- **Complete Lifecycles**: Full key management workflows
- **Multi-Provider Scenarios**: Complex cross-provider operations
- **Error Recovery**: System resilience and recovery
- **Capacity Management**: System limits and cleanup
- **Data Integrity**: Consistency across operations
- **System Integration**: Component interaction validation

**Key Features:**
- Realistic usage scenarios
- System resilience testing
- Complete integration validation
- Performance under realistic loads
- Error recovery mechanisms

## Running Tests

### Prerequisites

Ensure you have Go 1.21+ installed and all dependencies are available:

```bash
cd /Users/jimmy/dev/cf/keygridhsm
go mod download
```

### Quick Test Execution

Run all tests:
```bash
make test
```

Run tests with coverage:
```bash
make test-coverage
```

### Individual Test Categories

#### Unit Tests
```bash
# Run all unit tests
go test -v ./tests/unit/...

# Run specific unit test
go test -v ./tests/unit -run TestProviderRegistry
```

#### Integration Tests
```bash
# Run all integration tests
go test -v ./tests/integration/...

# Run with timeout (recommended for integration tests)
go test -timeout 10m -v ./tests/integration/...
```

#### Performance Tests
```bash
# Run all performance tests
go test -v ./tests/performance/...

# Run benchmarks
go test -bench=. -benchmem ./tests/performance/...

# Run with custom duration
go test -timeout 30m -v ./tests/performance/...
```

#### Security Tests
```bash
# Run all security tests
go test -v ./tests/security/...

# Run with race detection
go test -race -v ./tests/security/...
```

#### End-to-End Tests
```bash
# Enable E2E tests (they're skipped by default)
export RUN_E2E_TESTS=true

# Run all E2E tests
go test -timeout 20m -v ./tests/e2e/...

# Run specific E2E test
go test -timeout 20m -v ./tests/e2e -run TestCompleteKeyLifecycle
```

### Test Configuration

#### Environment Variables

- `RUN_E2E_TESTS=true`: Enable end-to-end tests (disabled by default)
- `BENCHMARK_DURATION=30s`: Set custom benchmark duration
- `LOAD_TEST_USERS=100`: Set concurrent users for load tests
- `MAX_TEST_KEYS=1000`: Set maximum keys for capacity tests

#### Test Flags

- `-short`: Skip long-running tests
- `-race`: Enable race condition detection
- `-timeout 30m`: Set test timeout
- `-v`: Verbose output
- `-bench=.`: Run benchmarks
- `-benchmem`: Include memory allocation stats
- `-cover`: Generate coverage report

## Test Data and Cleanup

### Test Data Management

All tests are designed to be self-contained and clean up after themselves:

- Test keys are automatically deleted after each test
- No persistent state between test runs
- Isolated test configurations prevent cross-contamination

### Cleanup Procedures

Tests include comprehensive cleanup in `defer` statements:

```go
defer func() {
    // Clean up all created resources
    for _, keyHandle := range createdKeys {
        _ = manager.DeleteKey(ctx, provider, config, keyHandle.ID)
    }
}()
```

## Performance Baselines

### Expected Performance Metrics

Based on typical hardware, the following are baseline expectations:

#### Key Generation
- **RSA-2048**: >10 keys/second
- **ECDSA-P256**: >50 keys/second
- **Ed25519**: >100 keys/second

#### Signing Operations
- **RSA-PSS**: >100 operations/second
- **ECDSA**: >500 operations/second
- **Ed25519**: >1000 operations/second

#### Memory Usage
- **Base Memory**: <50MB for basic operations
- **Memory Growth**: <1MB per 1000 keys
- **No Memory Leaks**: Memory usage should stabilize

### Performance Test Interpretation

Performance tests provide detailed metrics:

```
BenchmarkKeyGeneration/RSA-2048-8    100    15.2ms/op    2048 B/op    12 allocs/op
BenchmarkSigning/RSA-PSS-8          1000     1.2ms/op     512 B/op     8 allocs/op
```

Key metrics:
- **Operations/second**: Higher is better
- **Memory/operation**: Lower is better
- **Allocations/operation**: Lower is better

## Security Test Interpretation

Security tests validate critical security properties:

### Key Isolation
- Verifies multi-tenant key separation
- Ensures cross-tenant access prevention
- Validates provider-level isolation

### Cryptographic Integrity
- Signature validation accuracy
- Tamper detection capability
- Algorithm security compliance

### Attack Resistance
- Timing attack resistance
- Input validation effectiveness
- Secure deletion verification

## Troubleshooting

### Common Issues

#### Test Timeouts
If tests timeout, increase the timeout:
```bash
go test -timeout 30m -v ./tests/...
```

#### Memory Issues
For memory-intensive tests, increase available memory:
```bash
export GOMAXPROCS=8
export GOMEMLIMIT=4GiB
```

#### Concurrent Test Failures
Reduce concurrency for debugging:
```bash
go test -p 1 -v ./tests/...
```

#### Provider Connection Issues
Check provider configurations and dependencies:
```bash
# Verify mock providers work
go test -v ./tests/unit -run TestProviderRegistry

# Check individual providers
go test -v ./internal/providers/...
```

### Debug Mode

Enable debug mode for detailed logging:
```bash
export HSM_DEBUG=true
export HSM_LOG_LEVEL=debug
go test -v ./tests/...
```

### Test Isolation

Run tests in isolation to debug issues:
```bash
# Run single test
go test -v ./tests/integration -run TestKeyGeneration

# Run with clean cache
go clean -testcache
go test -v ./tests/...
```

## Continuous Integration

### GitHub Actions Integration

The test suite is designed for CI/CD integration:

```yaml
- name: Run Unit Tests
  run: go test -v ./tests/unit/...

- name: Run Integration Tests  
  run: go test -timeout 10m -v ./tests/integration/...

- name: Run Performance Tests
  run: go test -timeout 15m -bench=. ./tests/performance/...

- name: Run Security Tests
  run: go test -race -v ./tests/security/...

- name: Run E2E Tests
  env:
    RUN_E2E_TESTS: true
  run: go test -timeout 20m -v ./tests/e2e/...
```

### Coverage Requirements

Minimum coverage expectations:
- **Unit Tests**: >90% line coverage
- **Integration Tests**: >80% workflow coverage
- **Overall**: >85% combined coverage

### Quality Gates

Tests serve as quality gates for:
- **Functionality**: All workflows work correctly
- **Performance**: No performance regressions
- **Security**: All security requirements met
- **Reliability**: System handles errors gracefully

## Contributing

### Adding New Tests

When adding functionality, include corresponding tests:

1. **Unit Tests**: For new components or functions
2. **Integration Tests**: For new workflows or features
3. **Performance Tests**: For performance-critical features
4. **Security Tests**: For security-related features

### Test Standards

Follow these standards for test quality:

- **Descriptive Names**: Test names should clearly describe what's being tested
- **Independent Tests**: Each test should be independent and isolated
- **Comprehensive Cleanup**: Always clean up resources in defer statements
- **Clear Assertions**: Use descriptive assertion messages
- **Edge Cases**: Test boundary conditions and error cases
- **Documentation**: Document complex test scenarios

### Test Review Checklist

Before submitting tests:

- [ ] Tests are independent and can run in any order
- [ ] All resources are properly cleaned up
- [ ] Test names are descriptive and clear
- [ ] Edge cases and error conditions are tested
- [ ] Performance implications are considered
- [ ] Security implications are validated
- [ ] Tests run successfully in CI environment

## Resources

### Documentation
- [Go Testing Package](https://pkg.go.dev/testing)
- [Testify Testing Toolkit](https://github.com/stretchr/testify)
- [Go Benchmarking](https://dave.cheney.net/2013/06/30/how-to-write-benchmarks-in-go)

### Tools
- `go test`: Core testing tool
- `go test -bench`: Benchmarking
- `go test -race`: Race detection  
- `go test -cover`: Coverage analysis
- `golangci-lint`: Code quality

This testing suite ensures the KeyGrid HSM system meets all functional, performance, security, and reliability requirements for production deployment.