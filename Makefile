# Makefile for Cryptography Demonstration Programs
# 
# Usage:
#   make          - Build all programs
#   make crypto   - Build only crypto_core
#   make transfer - Build only secure_transfer
#   make clean    - Remove built programs and temporary files
#   make test     - Build and run basic tests

# Compiler settings
CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -O3 -pthread
LDFLAGS = -lssl -lcrypto

# Color output (optional, for nice terminal output)
BLUE = \033[0;34m
GREEN = \033[0;32m
NC = \033[0m # No Color

# Targets
.PHONY: all crypto transfer clean test help

all: crypto_core secure_transfer
	@echo "$(GREEN)✓ All programs built successfully!$(NC)"
	@echo ""
	@echo "Run programs with:"
	@echo "  ./crypto_core                              - Core crypto demonstration"
	@echo "  ./secure_transfer receive                  - Start receiver (terminal 1)"
	@echo "  ./secure_transfer send \"your message\"      - Send message (terminal 2)"

crypto: crypto_core
	@echo "$(GREEN)✓ crypto_core built successfully!$(NC)"

transfer: secure_transfer
	@echo "$(GREEN)✓ secure_transfer built successfully!$(NC)"

crypto_core: crypto_core.cpp
	@echo "$(BLUE)Building crypto_core...$(NC)"
	$(CXX) $(CXXFLAGS) -o crypto_core crypto_core.cpp $(LDFLAGS)

secure_transfer: secure_transfer.cpp
	@echo "$(BLUE)Building secure_transfer...$(NC)"
	$(CXX) $(CXXFLAGS) -o secure_transfer secure_transfer.cpp $(LDFLAGS)

test: all
	@echo "$(BLUE)Running crypto_core test...$(NC)"
	@./crypto_core
	@echo ""
	@echo "$(GREEN)✓ Test completed!$(NC)"

clean:
	@echo "$(BLUE)Cleaning up...$(NC)"
	rm -f crypto_core secure_transfer
	rm -f /tmp/secure_transfer.sock
	@echo "$(GREEN)✓ Cleanup complete!$(NC)"

help:
	@echo "Cryptography Demonstration - Makefile Help"
	@echo ""
	@echo "Available targets:"
	@echo "  make          - Build all programs"
	@echo "  make crypto   - Build only crypto_core"
	@echo "  make transfer - Build only secure_transfer"
	@echo "  make test     - Build and run crypto_core test"
	@echo "  make clean    - Remove built programs and temporary files"
	@echo "  make help     - Show this help message"
	@echo ""
	@echo "Prerequisites:"
	@echo "  - g++ compiler (C++11 support)"
	@echo "  - OpenSSL development libraries (libssl-dev)"
	@echo ""
	@echo "Install on Ubuntu/Debian:"
	@echo "  sudo apt-get install build-essential libssl-dev"