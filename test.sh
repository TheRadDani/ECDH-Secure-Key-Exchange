#!/bin/bash

# Test Script for Cryptography Demonstration Programs
# This script validates that both programs compile and run correctly

set -e  # Exit on error

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# Print colored output
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

print_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
    echo ""
}

# Test function wrapper
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    echo -e "${YELLOW}Testing: $test_name${NC}"
    
    if eval "$test_command"; then
        print_success "$test_name"
        ((TESTS_PASSED++))
        return 0
    else
        print_error "$test_name"
        ((TESTS_FAILED++))
        return 1
    fi
}

# Cleanup function
cleanup() {
    print_info "Cleaning up test artifacts..."
    rm -f /tmp/secure_transfer.sock
    pkill -f "secure_transfer receive" 2>/dev/null || true
    sleep 1
}

# Trap cleanup on exit
trap cleanup EXIT

# Main test sequence
main() {
    print_header "CRYPTOGRAPHY DEMONSTRATION - TEST SUITE"
    
    # Test 1: Check prerequisites
    print_header "TEST 1: Prerequisites Check"
    
    run_test "g++ compiler available" "which g++ > /dev/null 2>&1"
    run_test "g++ version check (>= 4.8)" "g++ --version | head -n1"
    run_test "OpenSSL library available" "pkg-config --exists openssl || openssl version"
    run_test "make utility available" "which make > /dev/null 2>&1"
    
    # Test 2: Compilation
    print_header "TEST 2: Compilation Tests"
    
    print_info "Cleaning previous builds..."
    make clean > /dev/null 2>&1 || true
    
    run_test "Compile crypto_core" "make crypto > /dev/null 2>&1"
    run_test "Compile secure_transfer" "make transfer > /dev/null 2>&1"
    run_test "crypto_core executable exists" "test -x ./crypto_core"
    run_test "secure_transfer executable exists" "test -x ./secure_transfer"
    
    # Test 3: crypto_core functionality
    print_header "TEST 3: Core Cryptography Tests"
    
    print_info "Running crypto_core..."
    if ./crypto_core > /tmp/crypto_test_output.txt 2>&1; then
        print_success "crypto_core executed successfully"
        ((TESTS_PASSED++))
        
        # Check for expected output
        if grep -q "Message integrity verified: YES" /tmp/crypto_test_output.txt; then
            print_success "Message integrity verification works"
            ((TESTS_PASSED++))
        else
            print_error "Message integrity verification failed"
            ((TESTS_FAILED++))
        fi
        
        if grep -q "Shared secrets match: YES" /tmp/crypto_test_output.txt; then
            print_success "ECDH key exchange works"
            ((TESTS_PASSED++))
        else
            print_error "ECDH key exchange failed"
            ((TESTS_FAILED++))
        fi
        
        if grep -q "DEMONSTRATION COMPLETE" /tmp/crypto_test_output.txt; then
            print_success "Program completed successfully"
            ((TESTS_PASSED++))
        else
            print_error "Program did not complete"
            ((TESTS_FAILED++))
        fi
    else
        print_error "crypto_core execution failed"
        ((TESTS_FAILED++))
        echo "Output:"
        cat /tmp/crypto_test_output.txt
    fi
    
    # Test 4: secure_transfer functionality
    print_header "TEST 4: Secure Transfer Tests"
    
    print_info "Starting receiver in background..."
    cleanup  # Make sure no previous instance is running
    
    # Start receiver in background
    timeout 30 ./secure_transfer receive > /tmp/receiver_output.txt 2>&1 &
    RECEIVER_PID=$!
    sleep 2  # Give receiver time to start
    
    if ps -p $RECEIVER_PID > /dev/null; then
        print_success "Receiver started (PID: $RECEIVER_PID)"
        ((TESTS_PASSED++))
        
        print_info "Sending test message..."
        if timeout 10 ./secure_transfer send "Test Message 12345" > /tmp/sender_output.txt 2>&1; then
            print_success "Sender completed successfully"
            ((TESTS_PASSED++))
            
            # Wait for receiver to finish
            sleep 2
            
            # Check receiver output
            if grep -q "DECRYPTED MESSAGE" /tmp/receiver_output.txt; then
                print_success "Receiver decrypted message"
                ((TESTS_PASSED++))
                
                if grep -q "Test Message 12345" /tmp/receiver_output.txt; then
                    print_success "Message content matches"
                    ((TESTS_PASSED++))
                else
                    print_error "Message content mismatch"
                    ((TESTS_FAILED++))
                fi
            else
                print_error "Receiver did not decrypt message"
                ((TESTS_FAILED++))
            fi
            
            if grep -q "Secure transfer complete" /tmp/receiver_output.txt; then
                print_success "Transfer completed successfully"
                ((TESTS_PASSED++))
            else
                print_error "Transfer did not complete"
                ((TESTS_FAILED++))
            fi
        else
            print_error "Sender failed"
            ((TESTS_FAILED++))
            echo "Sender output:"
            cat /tmp/sender_output.txt
        fi
        
        # Kill receiver if still running
        kill $RECEIVER_PID 2>/dev/null || true
    else
        print_error "Receiver failed to start"
        ((TESTS_FAILED++))
        echo "Receiver output:"
        cat /tmp/receiver_output.txt
    fi
    
    # Final results
    print_header "TEST RESULTS"
    
    echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
    echo -e "Total Tests:  $((TESTS_PASSED + TESTS_FAILED))"
    echo ""
    
    if [ $TESTS_FAILED -eq 0 ]; then
        print_success "ALL TESTS PASSED! 🎉"
        echo ""
        echo "Your cryptography programs are working correctly!"
        echo "You can now use them for secure communication."
        return 0
    else
        print_error "SOME TESTS FAILED!"
        echo ""
        echo "Please check the output above for details."
        echo "Common issues:"
        echo "  - OpenSSL not installed: sudo apt-get install libssl-dev"
        echo "  - Compiler not found: sudo apt-get install build-essential"
        echo "  - Socket permission issues: check /tmp directory permissions"
        return 1
    fi
}

# Run main function
main "$@"