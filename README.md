# High-Performance Cryptography Demonstration in C++

## Overview

This project demonstrates secure cryptographic practices using **AES-256-GCM** for symmetric encryption and **ECC (Elliptic Curve Cryptography)** for key exchange. It consists of two programs:

1. **crypto_core.cpp** - Core encryption concepts demonstration
2. **secure_transfer.cpp** - Network-based secure data transfer simulation

## Cryptographic Concepts Explained

### AES-256-GCM (Advanced Encryption Standard)
- **Type**: Symmetric encryption (same key for encryption/decryption)
- **Key Size**: 256 bits (extremely secure)
- **Mode**: GCM (Galois/Counter Mode)
  - Provides **encryption** AND **authentication**
  - Detects if data has been tampered with
  - Prevents replay attacks using unique IVs
- **Components**:
  - **Key**: Secret 256-bit key (must be kept secure)
  - **IV** (Initialization Vector): Random 96-bit value (unique per encryption)
  - **Tag**: 128-bit authentication code (proves data integrity)

**Why AES?**
- Industry standard, used by governments worldwide
- Fast in both hardware and software
- No known practical attacks on AES-256

### ECC P-256 (Elliptic Curve Cryptography)
- **Type**: Asymmetric encryption (public/private key pairs)
- **Curve**: P-256 (also known as secp256r1 or prime256v1)
  - NIST standard curve
  - 256-bit security level ≈ 3072-bit RSA
- **Advantages over RSA**:
  - Much smaller keys (256 bits vs 3072 bits)
  - Faster computation
  - Less bandwidth required

### ECDH (Elliptic Curve Diffie-Hellman)
- **Purpose**: Secure key exchange over insecure channel
- **How it works**:
  1. Alice generates key pair (privateA, publicA)
  2. Bob generates key pair (privateB, publicB)
  3. They exchange public keys (safe to send openly!)
  4. Alice computes: sharedSecret = ECDH(privateA, publicB)
  5. Bob computes: sharedSecret = ECDH(privateB, publicA)
  6. **Both get the SAME secret without ever transmitting it!**
- **Magic**: Even if an attacker intercepts both public keys, they cannot derive the shared secret

## Prerequisites

### Required Software
- **Linux** (Ubuntu 20.04+, Debian 10+, or similar)
- **g++** compiler with C++11 support
- **OpenSSL development libraries** (version 1.1.0 or higher)

### Installing Dependencies

#### Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install build-essential libssl-dev
```

#### Fedora/CentOS/RHEL:
```bash
sudo dnf install gcc-c++ openssl-devel
# Or for older systems:
sudo yum install gcc-c++ openssl-devel
```

#### Arch Linux:
```bash
sudo pacman -S base-devel openssl
```

### Verify Installation
```bash
# Check g++ version (should be 4.8.1 or higher)
g++ --version

# Check OpenSSL version (should be 1.1.0 or higher)
openssl version

# Verify OpenSSL development files
pkg-config --modversion openssl
```

## Compilation Instructions

### Method 1: Using the Provided Makefile (Recommended)

Create a `Makefile`:
```makefile
# Compiler settings
CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -O3 -pthread
LDFLAGS = -lssl -lcrypto

# Targets
all: crypto_core secure_transfer

crypto_core: crypto_core.cpp
	$(CXX) $(CXXFLAGS) -o crypto_core crypto_core.cpp $(LDFLAGS)

secure_transfer: secure_transfer.cpp
	$(CXX) $(CXXFLAGS) -o secure_transfer secure_transfer.cpp $(LDFLAGS)

clean:
	rm -f crypto_core secure_transfer
	rm -f /tmp/secure_transfer.sock

.PHONY: all clean
```

Then compile:
```bash
make
```

### Method 2: Manual Compilation

Compile each program individually:

```bash
# Compile crypto_core
g++ -std=c++11 -Wall -Wextra -O3 \
    -o crypto_core crypto_core.cpp \
    -lssl -lcrypto

# Compile secure_transfer
g++ -std=c++11 -Wall -Wextra -O3 -pthread \
    -o secure_transfer secure_transfer.cpp \
    -lssl -lcrypto
```

### Compilation Flags Explained
- `-std=c++11`: Use C++11 standard (required for modern features)
- `-Wall -Wextra`: Enable all warnings (good practice)
- `-O3`: Optimize for maximum performance
- `-pthread`: Enable POSIX threads support (for secure_transfer)
- `-lssl -lcrypto`: Link against OpenSSL libraries

## Running the Programs

### Program 1: crypto_core

This program demonstrates the core encryption concepts in a single process.

```bash
./crypto_core
```

**What it does:**
1. Generates a random AES-256 key
2. Encrypts a message using AES-256-GCM
3. Generates ECC key pairs for Alice and Bob
4. Exchanges public keys
5. Derives shared secret using ECDH
6. Decrypts the message
7. Verifies message integrity

**Expected Output:**
```
======================================
  CRYPTOGRAPHY DEMONSTRATION
  AES-256-GCM + ECC (P-256)
======================================

[STEP 1] Alice generates AES key for data encryption

=== AES KEY GENERATION ===
Generated 256-bit AES key
AES Key: 3f9a8b7c2d1e0f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8

...

[✓] Message integrity verified: YES ✓
```

### Program 2: secure_transfer

This program simulates secure network communication between two parties.

**You need TWO terminal windows:**

#### Terminal 1 (Receiver):
```bash
./secure_transfer receive
```

#### Terminal 2 (Sender):
```bash
./secure_transfer send "Your secret message here"
```

**Example:**
```bash
# Terminal 1
./secure_transfer receive

# Terminal 2
./secure_transfer send "Attack at dawn! 🔐"
```

**What happens:**
1. Receiver starts listening on Unix socket
2. Sender connects to receiver
3. They exchange ECC public keys
4. Both derive the same AES session key via ECDH
5. Sender encrypts message with AES-256-GCM
6. Sender transmits encrypted data
7. Receiver decrypts and verifies message

## Understanding the Output

### Key Components in Output

1. **AES Key** - 256-bit (32 bytes) hex string
   ```
   AES Key: 3f9a8b7c2d1e0f4a5b6c7d8e9f0a1b2c...
   ```

2. **IV (Initialization Vector)** - 96-bit (12 bytes) random value
   ```
   IV: a1b2c3d4e5f6a7b8c9d0e1f2
   ```

3. **Authentication Tag** - 128-bit (16 bytes) integrity proof
   ```
   Tag: 4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d
   ```

4. **Shared Secret** - Derived via ECDH (32 bytes)
   ```
   Shared Secret: 7f8e9d0a1b2c3d4e5f6a7b8c9d0e1f2a...
   ```

### Status Indicators
- `[*]` - Operation in progress
- `[✓]` - Success
- `[✗]` - Failure

## 🔬 Technical Deep Dive

### Memory Safety
- Uses RAII (Resource Acquisition Is Initialization) for automatic cleanup
- Smart wrappers prevent OpenSSL memory leaks
- Automatic cleanup of sockets and file descriptors

### Security Features
1. **Authenticated Encryption**: GCM mode prevents tampering
2. **Random IVs**: Each encryption uses unique IV
3. **Forward Secrecy**: New ECDH keys for each session (in secure_transfer)
4. **Length-Prefixed Protocol**: Prevents injection attacks

### Performance Optimizations
1. **-O3 Optimization**: Compiler optimizations for speed
2. **Buffer Reuse**: Minimize allocations
3. **Efficient Crypto**: Hardware-accelerated AES when available

## Testing and Validation

### Test 1: Basic Encryption
```bash
./crypto_core
# Verify "Message integrity verified: YES ✓" appears
```

### Test 2: Network Transfer
```bash
# Terminal 1
./secure_transfer receive

# Terminal 2
./secure_transfer send "Test message 123"

# Verify both show "Secure transfer complete!"
```

### Test 3: Tampering Detection
Modify the encrypted data to see authentication failure:
- The program will detect tampering via GCM authentication tag

## Security Best Practices

### What This Code Does Right
1. **Uses industry-standard algorithms** (AES-256, P-256)
2. **Authenticated encryption** (GCM mode)
3. **Cryptographically secure randomness** (RAND_bytes)
4. **Forward secrecy** via ECDH
5. **No hardcoded keys or secrets**

### Production Considerations

For production use, you should also implement:

1. **Key Derivation Function (KDF)**
   ```cpp
   // Use HKDF to derive AES key from ECDH secret
   // Don't use raw ECDH output directly
   ```

2. **Certificate Validation**
   - Use X.509 certificates for identity verification
   - Implement proper PKI (Public Key Infrastructure)

3. **Perfect Forward Secrecy**
   - Generate new ECDH keys for each session
   - Don't reuse long-term keys for encryption

4. **Additional Authentication**
   - Add HMAC for extra layer
   - Consider using AAD (Additional Authenticated Data) in GCM

5. **Key Storage**
   - Use hardware security modules (HSM) for keys
   - Implement secure key rotation policies

6. **Network Security**
   - Use TLS 1.3 for production network communication
   - Implement proper timeout and retry logic
   - Add rate limiting to prevent DoS

7. **Error Handling**
   - Don't leak information in error messages
   - Log securely without exposing sensitive data

## Common Issues and Solutions

### Issue: "Failed to create cipher context"
**Solution**: Ensure OpenSSL is properly installed
```bash
sudo apt-get install --reinstall libssl-dev
```

### Issue: "Failed to connect to receiver"
**Solution**: Make sure receiver is started first and socket path is accessible
```bash
# Check if socket exists
ls -la /tmp/secure_transfer.sock

# Clean up old socket
rm /tmp/secure_transfer.sock
```

### Issue: Compilation errors about OpenSSL
**Solution**: Specify OpenSSL path explicitly
```bash
g++ -std=c++11 -I/usr/include/openssl \
    -o crypto_core crypto_core.cpp \
    -L/usr/lib/x86_64-linux-gnu -lssl -lcrypto
```

### Issue: "Authentication failed"
**Solution**: This is expected if data is modified! The GCM tag detects tampering.

## Learning Resources

### Books
- "Cryptography Engineering" by Ferguson, Schneier, and Kohno
- "Applied Cryptography" by Bruce Schneier
- "Serious Cryptography" by Jean-Philippe Aumasson

### Online Resources
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [NIST Guidelines](https://csrc.nist.gov/publications/fips)
- [Cryptography Stack Exchange](https://crypto.stackexchange.com/)

### Standards
- [FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) - AES Standard
- [FIPS 186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) - Digital Signature Standard (includes ECC)
- [RFC 8446](https://tools.ietf.org/html/rfc8446) - TLS 1.3

## Code Structure

### crypto_core.cpp
```
├── CryptoUtils class      - Utility functions (hex printing, error handling)
├── AESCrypto class        - AES-256-GCM encryption/decryption
├── ECCCrypto class        - ECC key generation and ECDH
└── main()                 - Demonstration flow
```

### secure_transfer.cpp
```
├── Utils namespace        - Socket I/O and utilities
├── AESCrypto class        - AES-256-GCM encryption/decryption
├── ECCCrypto class        - ECC key generation and ECDH
├── SecureReceiver class   - Server-side logic
├── SecureSender class     - Client-side logic
└── main()                 - Mode selection and execution
```

## License and Disclaimer

This code is for **educational purposes only**. While it uses production-grade cryptography libraries and follows best practices, additional security measures are needed for production deployment.

**Important**: 
- Never roll your own crypto for production systems
- Use established libraries like OpenSSL, libsodium, or BoringSSL
- Get security audits for production cryptographic code
- Stay updated with latest security advisories

## Contributing

Found a bug or have a suggestion? This is educational code, but improvements are always welcome!

## Support

If you encounter issues:
1. Check the "Common Issues" section above
2. Verify OpenSSL installation: `openssl version`
3. Ensure g++ supports C++11: `g++ --version`
4. Check system logs for detailed errors

---