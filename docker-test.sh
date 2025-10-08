#!/bin/bash

# Docker Test Script for KeyGrid HSM
# This script builds and runs tests in a Docker container

set -e

echo "🔧 Building KeyGrid HSM Test Container..."

# Build the test container
docker build -f Dockerfile.test -t keygrid-hsm-test:latest .

echo "✅ Container built successfully!"

echo "🧪 Running Unit Tests in Docker..."

# Run unit tests
docker run --rm keygrid-hsm-test:latest sh -c "
    echo '=== Unit Tests ===' &&
    go test -v ./tests/unit/... &&
    echo '=== Core Library Build Test ===' &&
    go build -v ./internal/core/... &&
    go build -v ./internal/providers/... &&
    go build -v ./internal/config/... &&
    go build -v ./internal/metrics/... &&
    go build -v ./internal/audit/... &&
    echo '=== Test HSM Program Build ===' &&
    go build -v ./cmd/test-hsm/... &&
    echo '=== Performance Tests (Quick) ===' &&
    go test -short -v ./tests/performance/... &&
    echo '=== All tests completed successfully! ==='
"

echo "🎉 Docker tests completed successfully!"

echo ""
echo "📊 Test Summary:"
echo "  ✅ Unit Tests: PASSED"
echo "  ✅ Core Library Build: PASSED"
echo "  ✅ Test HSM Program Build: PASSED"  
echo "  ✅ Performance Tests (Quick): PASSED"
echo ""
echo "🚀 KeyGrid HSM is ready for production deployment!"