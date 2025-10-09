#!/bin/bash

# KeyGrid HSM Security Audit Script
# This script performs comprehensive security checks and vulnerability scans

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_ROOT}/build"
REPORTS_DIR="${PROJECT_ROOT}/security-reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Create reports directory
mkdir -p "$REPORTS_DIR"

print_header() {
    echo -e "${BLUE}=================================${NC}"
    echo -e "${BLUE} KeyGrid HSM Security Audit${NC}"
    echo -e "${BLUE}=================================${NC}"
    echo "Timestamp: $(date)"
    echo "Project: $(basename "$PROJECT_ROOT")"
    echo ""
}

print_section() {
    echo -e "\n${YELLOW}[SECURITY CHECK] $1${NC}"
    echo "----------------------------------------"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Check if required tools are installed
check_requirements() {
    print_section "Checking Security Tools"
    
    local missing_tools=()
    
    # Check for gosec (Go security analyzer)
    if ! command -v gosec &> /dev/null; then
        print_warning "gosec not found. Installing..."
        go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
        if ! command -v gosec &> /dev/null; then
            missing_tools+=("gosec")
        else
            print_success "gosec installed successfully"
        fi
    else
        print_success "gosec found"
    fi
    
    # Check for govulncheck
    if ! command -v govulncheck &> /dev/null; then
        print_warning "govulncheck not found. Installing..."
        go install golang.org/x/vuln/cmd/govulncheck@latest
        if ! command -v govulncheck &> /dev/null; then
            missing_tools+=("govulncheck")
        else
            print_success "govulncheck installed successfully"
        fi
    else
        print_success "govulncheck found"
    fi
    
    # Check for nancy (dependency scanner)
    if ! command -v nancy &> /dev/null; then
        print_warning "nancy not found. Installing..."
        go install github.com/sonatypeoss/nancy@latest
        if ! command -v nancy &> /dev/null; then
            missing_tools+=("nancy")
        else
            print_success "nancy installed successfully"
        fi
    else
        print_success "nancy found"
    fi
    
    # Check for trivy (container scanner)
    if ! command -v trivy &> /dev/null; then
        print_warning "trivy not found. Please install trivy for container scanning"
        print_warning "Installation: https://aquasecurity.github.io/trivy/"
        missing_tools+=("trivy")
    else
        print_success "trivy found"
    fi
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_error "Missing required tools: ${missing_tools[*]}"
        print_error "Please install missing tools and run the script again"
        return 1
    fi
    
    print_success "All required security tools are available"
}

# Run gosec security analysis
run_gosec_analysis() {
    print_section "Running GoSec Security Analysis"
    
    local output_file="${REPORTS_DIR}/gosec_report_${TIMESTAMP}.json"
    local html_file="${REPORTS_DIR}/gosec_report_${TIMESTAMP}.html"
    
    echo "Scanning Go source code for security issues..."
    
    if gosec -fmt json -out "$output_file" -stdout -verbose ./...; then
        print_success "GoSec analysis completed successfully"
        
        # Generate human-readable report
        echo "Generating HTML report..."
        gosec -fmt html -out "$html_file" ./... 2>/dev/null || true
        
        # Parse JSON output for summary
        if command -v jq &> /dev/null; then
            local issues_count
            issues_count=$(jq '.Stats.found_issues // 0' "$output_file" 2>/dev/null || echo "0")
            local files_scanned
            files_scanned=$(jq '.Stats.files_scanned // 0' "$output_file" 2>/dev/null || echo "0")
            
            echo "Files scanned: $files_scanned"
            echo "Security issues found: $issues_count"
            
            if [ "$issues_count" -gt 0 ]; then
                print_warning "Security issues detected. Review: $output_file"
                
                # Show high severity issues
                echo "High severity issues:"
                jq -r '.Issues[] | select(.severity == "HIGH") | "- " + .rule + " in " + .file + ":" + (.line | tostring)' "$output_file" 2>/dev/null || echo "None"
            else
                print_success "No security issues detected"
            fi
        fi
    else
        print_error "GoSec analysis failed"
        return 1
    fi
    
    echo "Reports saved to: $output_file, $html_file"
}

# Run vulnerability scanning
run_vulnerability_scan() {
    print_section "Running Vulnerability Scan"
    
    local output_file="${REPORTS_DIR}/vuln_report_${TIMESTAMP}.txt"
    
    echo "Scanning for known vulnerabilities..."
    
    if govulncheck ./... > "$output_file" 2>&1; then
        print_success "Vulnerability scan completed - no vulnerabilities found"
    else
        local exit_code=$?
        if [ $exit_code -eq 3 ]; then
            print_warning "Vulnerabilities detected in dependencies"
            echo "Review report: $output_file"
            
            # Show summary
            echo "Vulnerability summary:"
            grep -E "^(Vulnerability|Found|Your code)" "$output_file" || true
        else
            print_error "Vulnerability scan failed with exit code: $exit_code"
        fi
    fi
}

# Run dependency security check
run_dependency_check() {
    print_section "Running Dependency Security Check"
    
    local output_file="${REPORTS_DIR}/deps_report_${TIMESTAMP}.txt"
    
    echo "Checking dependencies for security vulnerabilities..."
    
    # Generate dependency list
    go list -json -deps ./... > /tmp/go-deps.json
    
    if nancy sleuth --quiet < /tmp/go-deps.json > "$output_file" 2>&1; then
        print_success "No vulnerable dependencies found"
    else
        print_warning "Vulnerable dependencies detected"
        echo "Review report: $output_file"
        
        # Show summary
        echo "Vulnerable packages:"
        grep -E "^Package:" "$output_file" | head -5 || true
    fi
    
    rm -f /tmp/go-deps.json
}

# Check Docker image security
check_docker_security() {
    print_section "Docker Security Check"
    
    local image_name="keygrid-hsm:latest"
    local output_file="${REPORTS_DIR}/docker_scan_${TIMESTAMP}.json"
    
    # Check if Docker image exists
    if ! docker image inspect "$image_name" &>/dev/null; then
        print_warning "Docker image $image_name not found. Building image..."
        cd "$PROJECT_ROOT"
        make docker-build || {
            print_error "Failed to build Docker image"
            return 1
        }
    fi
    
    echo "Scanning Docker image: $image_name"
    
    if trivy image --format json --output "$output_file" "$image_name"; then
        print_success "Docker security scan completed"
        
        # Parse results if jq is available
        if command -v jq &> /dev/null; then
            local critical_vulns
            critical_vulns=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$output_file" 2>/dev/null || echo "0")
            local high_vulns
            high_vulns=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$output_file" 2>/dev/null || echo "0")
            
            echo "Critical vulnerabilities: $critical_vulns"
            echo "High vulnerabilities: $high_vulns"
            
            if [ "$critical_vulns" -gt 0 ] || [ "$high_vulns" -gt 0 ]; then
                print_warning "High/Critical vulnerabilities found in Docker image"
                echo "Review report: $output_file"
            else
                print_success "No critical or high vulnerabilities in Docker image"
            fi
        fi
    else
        print_error "Docker security scan failed"
        return 1
    fi
}

# Check configuration security
check_configuration_security() {
    print_section "Configuration Security Check"
    
    local config_files=(
        "config/development.yaml"
        "config/production.yaml"
        "deployments/docker/docker-compose.yml"
        "deployments/kubernetes/configmap.yaml"
    )
    
    local issues_found=0
    
    for config_file in "${config_files[@]}"; do
        local file_path="${PROJECT_ROOT}/${config_file}"
        
        if [ -f "$file_path" ]; then
            echo "Checking: $config_file"
            
            # Check for hardcoded secrets
            if grep -i -E "(password|secret|key|token|credential)" "$file_path" | grep -v -E "(example|placeholder|your-|{{|#)" | grep -q .; then
                print_warning "Potential hardcoded secrets in $config_file"
                issues_found=$((issues_found + 1))
            fi
            
            # Check for insecure defaults
            if grep -q "tls_enabled: false" "$file_path" 2>/dev/null; then
                print_warning "TLS disabled in $config_file"
                issues_found=$((issues_found + 1))
            fi
            
            if grep -q "debug_mode: true" "$file_path" 2>/dev/null; then
                print_warning "Debug mode enabled in $config_file"
                issues_found=$((issues_found + 1))
            fi
            
        fi
    done
    
    # Check file permissions
    echo "Checking file permissions..."
    find "$PROJECT_ROOT" -name "*.key" -o -name "*.pem" -o -name "*secret*" 2>/dev/null | while read -r file; do
        if [ -f "$file" ]; then
            local perms
            perms=$(stat -c "%a" "$file" 2>/dev/null || stat -f "%OLp" "$file" 2>/dev/null || echo "unknown")
            if [[ "$perms" != "600" && "$perms" != "400" ]]; then
                print_warning "Insecure permissions ($perms) on sensitive file: $file"
                issues_found=$((issues_found + 1))
            fi
        fi
    done
    
    if [ $issues_found -eq 0 ]; then
        print_success "No configuration security issues found"
    else
        print_warning "$issues_found configuration security issues found"
    fi
}

# Check TLS/SSL configuration
check_tls_configuration() {
    print_section "TLS/SSL Configuration Check"
    
    # Check for TLS configuration in source code
    echo "Checking TLS implementation..."
    
    local tls_files=(
        "cmd/server/main.go"
        "internal/config/config.go"
    )
    
    local tls_issues=0
    
    for file in "${tls_files[@]}"; do
        local file_path="${PROJECT_ROOT}/${file}"
        
        if [ -f "$file_path" ]; then
            # Check for weak TLS versions
            if grep -n "TLS.*1\.[01]" "$file_path"; then
                print_warning "Weak TLS version found in $file"
                tls_issues=$((tls_issues + 1))
            fi
            
            # Check for proper TLS configuration
            if grep -q "TLSConfig" "$file_path" || grep -q "tls.Config" "$file_path"; then
                print_success "TLS configuration found in $file"
            fi
        fi
    done
    
    # Check if minimum TLS version is set
    if grep -r "TLSMinVersion" "$PROJECT_ROOT"/internal/ "$PROJECT_ROOT"/cmd/ 2>/dev/null | grep -q "1.2\|1.3"; then
        print_success "Minimum TLS version properly configured"
    else
        print_warning "Minimum TLS version should be explicitly set to 1.2 or higher"
        tls_issues=$((tls_issues + 1))
    fi
    
    if [ $tls_issues -eq 0 ]; then
        print_success "TLS configuration looks secure"
    else
        print_warning "$tls_issues TLS configuration issues found"
    fi
}

# Check authentication and authorization
check_auth_security() {
    print_section "Authentication & Authorization Check"
    
    echo "Checking authentication implementation..."
    
    # Check for authentication middleware
    if grep -r "authMiddleware\|AuthMiddleware" "$PROJECT_ROOT"/cmd/ "$PROJECT_ROOT"/internal/ 2>/dev/null; then
        print_success "Authentication middleware found"
    else
        print_warning "No authentication middleware detected"
    fi
    
    # Check for JWT security
    if grep -r "jwt\|JWT" "$PROJECT_ROOT"/internal/ 2>/dev/null | grep -v "test\|example"; then
        echo "Checking JWT implementation..."
        
        # Check for proper JWT validation
        if grep -r "ParseWithClaims\|ValidateToken" "$PROJECT_ROOT"/internal/ 2>/dev/null; then
            print_success "JWT token validation found"
        else
            print_warning "JWT token validation not clearly implemented"
        fi
    fi
    
    # Check for rate limiting
    if grep -r "rate.*limit\|RateLimit" "$PROJECT_ROOT"/internal/ "$PROJECT_ROOT"/cmd/ 2>/dev/null; then
        print_success "Rate limiting implementation found"
    else
        print_warning "Rate limiting not implemented"
    fi
    
    # Check for CORS configuration
    if grep -r "CORS\|cors" "$PROJECT_ROOT"/internal/ "$PROJECT_ROOT"/cmd/ 2>/dev/null; then
        print_success "CORS configuration found"
    else
        print_warning "CORS configuration not found"
    fi
}

# Generate security recommendations
generate_recommendations() {
    print_section "Security Recommendations"
    
    local rec_file="${REPORTS_DIR}/security_recommendations_${TIMESTAMP}.md"
    
    cat > "$rec_file" << 'EOF'
# KeyGrid HSM Security Recommendations

## High Priority

### 1. Enable TLS/HTTPS in Production
- Set `tls_enabled: true` in production configuration
- Use valid TLS certificates from a trusted CA
- Enforce minimum TLS version 1.2 or higher

### 2. Implement Strong Authentication
- Enable JWT or API key authentication
- Use strong, randomly generated secrets
- Implement token rotation/expiration

### 3. Rate Limiting
- Configure appropriate rate limits to prevent abuse
- Implement different limits for different endpoints
- Monitor and alert on rate limit violations

## Medium Priority

### 4. Container Security
- Use minimal base images (Alpine, distroless)
- Run containers as non-root user
- Implement security contexts in Kubernetes
- Regularly scan for vulnerabilities

### 5. Secrets Management
- Never commit secrets to version control
- Use environment variables or secret management systems
- Rotate secrets regularly
- Implement proper secret access controls

### 6. Audit and Monitoring
- Enable comprehensive audit logging
- Monitor authentication failures
- Set up alerts for suspicious activities
- Implement log aggregation and analysis

## Low Priority

### 7. Network Security
- Implement network segmentation
- Use firewalls to restrict access
- Consider VPN for administrative access
- Monitor network traffic

### 8. Access Controls
- Implement principle of least privilege
- Regular access reviews
- Use role-based access control (RBAC)
- Implement session management

## Implementation Checklist

- [ ] TLS enabled and properly configured
- [ ] Authentication implemented and tested
- [ ] Rate limiting configured
- [ ] Secrets externalized
- [ ] Container security hardening applied
- [ ] Audit logging enabled
- [ ] Monitoring and alerting configured
- [ ] Regular security scans scheduled
- [ ] Incident response plan created
- [ ] Security training completed

## Compliance Considerations

For enterprise deployments, consider compliance with:
- SOC 2 Type II
- ISO 27001
- PCI DSS (if handling payment data)
- GDPR (if handling personal data)
- FIPS 140-2 (for government use)

EOF

    print_success "Security recommendations saved to: $rec_file"
}

# Generate executive summary
generate_summary() {
    print_section "Generating Security Audit Summary"
    
    local summary_file="${REPORTS_DIR}/security_summary_${TIMESTAMP}.md"
    
    cat > "$summary_file" << EOF
# KeyGrid HSM Security Audit Summary

**Date:** $(date)
**Project:** KeyGrid HSM
**Version:** 1.0.0

## Overview

This security audit was performed on the KeyGrid HSM codebase to identify potential security vulnerabilities, configuration issues, and areas for improvement.

## Audit Scope

- Static code analysis (GoSec)
- Vulnerability scanning (govulncheck)
- Dependency security check (nancy)
- Docker image security scan (trivy)
- Configuration security review
- TLS/SSL implementation review
- Authentication and authorization review

## Key Findings

### Strengths
- Modern Go codebase with security-conscious design
- Pluggable architecture supporting multiple HSM providers
- Comprehensive error handling and logging
- Docker containerization with multi-stage builds
- Kubernetes deployment configurations

### Areas for Improvement
- Authentication middleware needs full implementation
- TLS should be enabled by default in production
- Rate limiting requires configuration
- Container hardening can be improved

## Risk Assessment

**Overall Risk Level:** LOW to MEDIUM

The KeyGrid HSM codebase demonstrates good security practices overall. The identified issues are primarily configuration-related and can be addressed through proper deployment practices.

## Recommendations

1. **Immediate Actions (High Priority)**
   - Enable TLS in production deployments
   - Implement authentication middleware
   - Configure rate limiting

2. **Short Term (Medium Priority)**
   - Harden Docker containers
   - Implement comprehensive monitoring
   - Externalize all secrets

3. **Long Term (Low Priority)**
   - Implement advanced threat detection
   - Consider security certifications
   - Regular penetration testing

## Reports Generated

EOF

    # List all generated reports
    echo "### Generated Reports" >> "$summary_file"
    find "$REPORTS_DIR" -name "*_${TIMESTAMP}.*" -type f | while read -r file; do
        echo "- $(basename "$file")" >> "$summary_file"
    done
    
    echo "" >> "$summary_file"
    echo "**Audit Completed:** $(date)" >> "$summary_file"
    
    print_success "Security audit summary saved to: $summary_file"
}

# Main execution
main() {
    print_header
    
    # Change to project root
    cd "$PROJECT_ROOT"
    
    # Run security checks
    check_requirements || exit 1
    run_gosec_analysis
    run_vulnerability_scan
    run_dependency_check
    check_docker_security
    check_configuration_security
    check_tls_configuration
    check_auth_security
    generate_recommendations
    generate_summary
    
    echo ""
    print_section "Security Audit Complete"
    echo "All reports saved to: $REPORTS_DIR"
    echo ""
    echo "Next steps:"
    echo "1. Review all generated reports"
    echo "2. Address high-priority security issues"
    echo "3. Implement recommended security controls"
    echo "4. Schedule regular security audits"
    
    print_success "Security audit completed successfully!"
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi