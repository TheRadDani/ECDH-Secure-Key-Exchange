/**
 * CRYPTO CORE - Demonstrating AES Encryption and ECC Key Exchange
 * 
 * This program demonstrates:
 * 1. Symmetric encryption using AES-256-GCM (Advanced Encryption Standard)
 * 2. Asymmetric encryption using ECC (Elliptic Curve Cryptography)
 * 3. Secure key exchange using ECDH (Elliptic Curve Diffie-Hellman)
 * 
 * CONCEPTS EXPLAINED:
 * - AES: Fast symmetric encryption where same key encrypts and decrypts
 * - ECC: Public-key cryptography using elliptic curves (smaller keys, same security)
 * - GCM: Galois/Counter Mode provides both encryption and authentication
 * - ECDH: Key agreement protocol allowing two parties to establish shared secret
 */

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <iostream>
#include <vector>
#include <cstring>
#include <iomanip>
#include <memory>

// RAII wrapper for OpenSSL contexts to prevent memory leaks
class EVPCipherContext {
    EVP_CIPHER_CTX* ctx;
public:
    EVPCipherContext() : ctx(EVP_CIPHER_CTX_new()) {
        if (!ctx) throw std::runtime_error("Failed to create cipher context");
    }
    ~EVPCipherContext() { EVP_CIPHER_CTX_free(ctx); }
    operator EVP_CIPHER_CTX*() { return ctx; }
};

class EVPPKeyContext {
    EVP_PKEY_CTX* ctx;
public:
    EVPPKeyContext(EVP_PKEY_CTX* c) : ctx(c) {}
    ~EVPPKeyContext() { if (ctx) EVP_PKEY_CTX_free(ctx); }
    operator EVP_PKEY_CTX*() { return ctx; }
};

/**
 * CRYPTOGRAPHIC UTILITIES
 */
class CryptoUtils {
public:
    // Print bytes in hexadecimal format for debugging
    static void printHex(const std::string& label, const unsigned char* data, size_t len) {
        std::cout << label << ": ";
        for (size_t i = 0; i < len; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << static_cast<int>(data[i]);
        }
        std::cout << std::dec << std::endl;
    }

    // Handle OpenSSL errors
    static void handleErrors(const std::string& msg) {
        std::cerr << "Error: " << msg << std::endl;
        ERR_print_errors_fp(stderr);
        throw std::runtime_error(msg);
    }
};

/**
 * AES-256-GCM ENCRYPTION CLASS
 * 
 * AES (Advanced Encryption Standard):
 * - Symmetric cipher (same key for encryption/decryption)
 * - 256-bit key size (very secure)
 * - GCM mode provides authenticated encryption (detects tampering)
 * - Uses IV (Initialization Vector) for randomization
 */
class AESCrypto {
private:
    static constexpr size_t KEY_SIZE = 32;    // 256 bits
    static constexpr size_t IV_SIZE = 12;     // 96 bits (recommended for GCM)
    static constexpr size_t TAG_SIZE = 16;    // 128-bit authentication tag

public:
    /**
     * Generate a random AES key
     * This is the secret key that will be shared securely using ECC
     */
    static std::vector<unsigned char> generateKey() {
        std::vector<unsigned char> key(KEY_SIZE);
        
        // Use cryptographically secure random number generator
        if (RAND_bytes(key.data(), KEY_SIZE) != 1) {
            CryptoUtils::handleErrors("Failed to generate AES key");
        }
        
        std::cout << "\n=== AES KEY GENERATION ===" << std::endl;
        std::cout << "Generated 256-bit AES key" << std::endl;
        CryptoUtils::printHex("AES Key", key.data(), KEY_SIZE);
        
        return key;
    }

    /**
     * Encrypt data using AES-256-GCM
     * 
     * Process:
     * 1. Generate random IV (must be unique for each encryption)
     * 2. Initialize cipher with key and IV
     * 3. Encrypt plaintext
     * 4. Generate authentication tag (proves data hasn't been tampered)
     * 
     * Returns: IV + Ciphertext + Tag (all needed for decryption)
     */
    static std::vector<unsigned char> encrypt(
        const std::vector<unsigned char>& plaintext,
        const std::vector<unsigned char>& key
    ) {
        // Generate random IV
        std::vector<unsigned char> iv(IV_SIZE);
        if (RAND_bytes(iv.data(), IV_SIZE) != 1) {
            CryptoUtils::handleErrors("Failed to generate IV");
        }

        // Create cipher context
        EVPCipherContext ctx;
        
        // Initialize encryption operation with AES-256-GCM
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            CryptoUtils::handleErrors("Failed to initialize encryption");
        }

        // Set IV length (GCM mode allows custom IV lengths)
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, nullptr) != 1) {
            CryptoUtils::handleErrors("Failed to set IV length");
        }

        // Initialize key and IV
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
            CryptoUtils::handleErrors("Failed to set key and IV");
        }

        // Allocate buffer for ciphertext (can be slightly larger than plaintext)
        std::vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_CTX_block_size(ctx));
        int len = 0;
        int ciphertext_len = 0;

        // Perform encryption
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
            CryptoUtils::handleErrors("Encryption failed");
        }
        ciphertext_len = len;

        // Finalize encryption (GCM mode may have pending data)
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            CryptoUtils::handleErrors("Encryption finalization failed");
        }
        ciphertext_len += len;
        ciphertext.resize(ciphertext_len);

        // Get authentication tag (proves data integrity)
        std::vector<unsigned char> tag(TAG_SIZE);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data()) != 1) {
            CryptoUtils::handleErrors("Failed to get authentication tag");
        }

        std::cout << "\n=== AES ENCRYPTION ===" << std::endl;
        std::cout << "Plaintext size: " << plaintext.size() << " bytes" << std::endl;
        std::cout << "Ciphertext size: " << ciphertext_len << " bytes" << std::endl;
        CryptoUtils::printHex("IV", iv.data(), IV_SIZE);
        CryptoUtils::printHex("Tag", tag.data(), TAG_SIZE);

        // Combine IV + Ciphertext + Tag for transmission
        std::vector<unsigned char> result;
        result.insert(result.end(), iv.begin(), iv.end());
        result.insert(result.end(), ciphertext.begin(), ciphertext.end());
        result.insert(result.end(), tag.begin(), tag.end());

        return result;
    }

    /**
     * Decrypt data using AES-256-GCM
     * 
     * Process:
     * 1. Extract IV, ciphertext, and tag from input
     * 2. Initialize decipher with key and IV
     * 3. Set expected authentication tag
     * 4. Decrypt ciphertext
     * 5. Verify authentication tag (automatically checked in finalize)
     */
    static std::vector<unsigned char> decrypt(
        const std::vector<unsigned char>& encrypted_data,
        const std::vector<unsigned char>& key
    ) {
        if (encrypted_data.size() < IV_SIZE + TAG_SIZE) {
            CryptoUtils::handleErrors("Encrypted data too small");
        }

        // Extract components
        std::vector<unsigned char> iv(encrypted_data.begin(), encrypted_data.begin() + IV_SIZE);
        std::vector<unsigned char> tag(encrypted_data.end() - TAG_SIZE, encrypted_data.end());
        std::vector<unsigned char> ciphertext(
            encrypted_data.begin() + IV_SIZE,
            encrypted_data.end() - TAG_SIZE
        );

        // Create cipher context
        EVPCipherContext ctx;

        // Initialize decryption operation
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            CryptoUtils::handleErrors("Failed to initialize decryption");
        }

        // Set IV length
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, nullptr) != 1) {
            CryptoUtils::handleErrors("Failed to set IV length");
        }

        // Initialize key and IV
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
            CryptoUtils::handleErrors("Failed to set key and IV");
        }

        // Allocate buffer for plaintext
        std::vector<unsigned char> plaintext(ciphertext.size());
        int len = 0;
        int plaintext_len = 0;

        // Perform decryption
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
            CryptoUtils::handleErrors("Decryption failed");
        }
        plaintext_len = len;

        // Set expected authentication tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag.data()) != 1) {
            CryptoUtils::handleErrors("Failed to set authentication tag");
        }

        // Finalize decryption (verifies authentication tag)
        int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
        if (ret <= 0) {
            CryptoUtils::handleErrors("Decryption failed: authentication tag mismatch (data tampered!)");
        }
        plaintext_len += len;
        plaintext.resize(plaintext_len);

        std::cout << "\n=== AES DECRYPTION ===" << std::endl;
        std::cout << "Decryption successful!" << std::endl;
        std::cout << "Authentication verified (data is authentic)" << std::endl;

        return plaintext;
    }
};

/**
 * ELLIPTIC CURVE CRYPTOGRAPHY (ECC) CLASS
 * 
 * ECC Advantages:
 * - Smaller keys than RSA for equivalent security (256-bit ECC ≈ 3072-bit RSA)
 * - Faster computation
 * - Less bandwidth for key exchange
 * 
 * We use P-256 curve (also known as secp256r1 or prime256v1)
 * - NIST standard curve
 * - Widely supported
 * - Good balance of security and performance
 */
class ECCCrypto {
private:
    EVP_PKEY* privateKey;
    EVP_PKEY* publicKey;

public:
    ECCCrypto() : privateKey(nullptr), publicKey(nullptr) {}

    ~ECCCrypto() {
        if (privateKey) EVP_PKEY_free(privateKey);
        if (publicKey) EVP_PKEY_free(publicKey);
    }

    /**
     * Generate ECC key pair
     * 
     * Public key: Can be shared openly (sent to other party)
     * Private key: Must be kept secret (never transmitted)
     */
    void generateKeyPair() {
        std::cout << "\n=== ECC KEY PAIR GENERATION ===" << std::endl;

        // Create parameter context for P-256 curve
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        if (!pctx) CryptoUtils::handleErrors("Failed to create parameter context");
        EVPPKeyContext pctx_guard(pctx);

        // Initialize key generation
        if (EVP_PKEY_paramgen_init(pctx) != 1) {
            CryptoUtils::handleErrors("Failed to initialize paramgen");
        }

        // Set curve to P-256 (prime256v1)
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) != 1) {
            CryptoUtils::handleErrors("Failed to set curve");
        }

        // Generate parameters
        EVP_PKEY* params = nullptr;
        if (EVP_PKEY_paramgen(pctx, &params) != 1) {
            CryptoUtils::handleErrors("Failed to generate parameters");
        }

        // Create key generation context
        EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new(params, nullptr);
        EVP_PKEY_free(params);
        if (!kctx) CryptoUtils::handleErrors("Failed to create key context");
        EVPPKeyContext kctx_guard(kctx);

        // Initialize key generation
        if (EVP_PKEY_keygen_init(kctx) != 1) {
            CryptoUtils::handleErrors("Failed to initialize keygen");
        }

        // Generate key pair
        if (EVP_PKEY_keygen(kctx, &privateKey) != 1) {
            CryptoUtils::handleErrors("Failed to generate key pair");
        }

        // Extract public key
        publicKey = EVP_PKEY_new();
        if (!publicKey) CryptoUtils::handleErrors("Failed to create public key");

        // Copy public key from private key
        EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(privateKey);
        if (!ec_key) CryptoUtils::handleErrors("Failed to get EC_KEY");
        
        EC_KEY* pub_ec_key = EC_KEY_new();
        EC_KEY_set_group(pub_ec_key, EC_KEY_get0_group(ec_key));
        EC_KEY_set_public_key(pub_ec_key, EC_KEY_get0_public_key(ec_key));
        EVP_PKEY_set1_EC_KEY(publicKey, pub_ec_key);
        
        EC_KEY_free(ec_key);
        EC_KEY_free(pub_ec_key);

        std::cout << "Generated P-256 ECC key pair" << std::endl;
        std::cout << "Public key can be safely shared" << std::endl;
        std::cout << "Private key must remain secret" << std::endl;
    }

    /**
     * Export public key to PEM format
     * PEM: Privacy-Enhanced Mail format (base64-encoded, human-readable)
     * This is what you'd send to the other party
     */
    std::string exportPublicKey() {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) CryptoUtils::handleErrors("Failed to create BIO");

        if (PEM_write_bio_PUBKEY(bio, publicKey) != 1) {
            BIO_free(bio);
            CryptoUtils::handleErrors("Failed to write public key");
        }

        char* pem_data = nullptr;
        long pem_size = BIO_get_mem_data(bio, &pem_data);
        std::string result(pem_data, pem_size);
        BIO_free(bio);

        return result;
    }

    /**
     * Import public key from PEM format
     * Used to load the other party's public key
     */
    static EVP_PKEY* importPublicKey(const std::string& pem) {
        BIO* bio = BIO_new_mem_buf(pem.data(), pem.size());
        if (!bio) CryptoUtils::handleErrors("Failed to create BIO");

        EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!key) CryptoUtils::handleErrors("Failed to read public key");
        return key;
    }

    /**
     * Perform ECDH (Elliptic Curve Diffie-Hellman) key derivation
     * 
     * ECDH allows two parties to establish a shared secret:
     * 1. Alice generates her key pair (privA, pubA)
     * 2. Bob generates his key pair (privB, pubB)
     * 3. Alice and Bob exchange public keys
     * 4. Alice computes: sharedSecret = ECDH(privA, pubB)
     * 5. Bob computes: sharedSecret = ECDH(privB, pubA)
     * 6. Both get the SAME shared secret without transmitting it!
     * 
     * We use this shared secret to derive an AES key
     */
    std::vector<unsigned char> deriveSharedSecret(EVP_PKEY* peer_public_key) {
        std::cout << "\n=== ECDH KEY DERIVATION ===" << std::endl;

        // Create derivation context
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privateKey, nullptr);
        if (!ctx) CryptoUtils::handleErrors("Failed to create derivation context");
        EVPPKeyContext ctx_guard(ctx);

        // Initialize key derivation
        if (EVP_PKEY_derive_init(ctx) != 1) {
            CryptoUtils::handleErrors("Failed to initialize key derivation");
        }

        // Set peer's public key
        if (EVP_PKEY_derive_set_peer(ctx, peer_public_key) != 1) {
            CryptoUtils::handleErrors("Failed to set peer public key");
        }

        // Determine buffer length needed
        size_t secret_len = 0;
        if (EVP_PKEY_derive(ctx, nullptr, &secret_len) != 1) {
            CryptoUtils::handleErrors("Failed to determine secret length");
        }

        // Derive shared secret
        std::vector<unsigned char> shared_secret(secret_len);
        if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) != 1) {
            CryptoUtils::handleErrors("Failed to derive shared secret");
        }

        std::cout << "Derived shared secret via ECDH" << std::endl;
        std::cout << "Both parties now have same secret without transmitting it!" << std::endl;
        CryptoUtils::printHex("Shared Secret", shared_secret.data(), secret_len);

        return shared_secret;
    }

    EVP_PKEY* getPublicKey() { return publicKey; }
};

/**
 * MAIN DEMONSTRATION
 */
int main() {
    try {
        std::cout << "======================================" << std::endl;
        std::cout << "  CRYPTOGRAPHY DEMONSTRATION" << std::endl;
        std::cout << "  AES-256-GCM + ECC (P-256)" << std::endl;
        std::cout << "======================================" << std::endl;

        // ===== SCENARIO: Alice wants to send encrypted data to Bob =====

        // Step 1: Alice generates an AES key for encrypting her data
        std::cout << "\n[STEP 1] Alice generates AES key for data encryption" << std::endl;
        auto aes_key = AESCrypto::generateKey();

        // Step 2: Alice encrypts her sensitive data
        std::cout << "\n[STEP 2] Alice encrypts her message with AES" << std::endl;
        std::string plaintext = "This is a TOP SECRET message that needs encryption!";
        std::vector<unsigned char> plaintext_vec(plaintext.begin(), plaintext.end());
        
        std::cout << "Original message: \"" << plaintext << "\"" << std::endl;
        auto encrypted_data = AESCrypto::encrypt(plaintext_vec, aes_key);

        // Step 3: Generate ECC key pairs for both parties
        std::cout << "\n[STEP 3] Alice and Bob generate their ECC key pairs" << std::endl;
        ECCCrypto alice_ecc;
        alice_ecc.generateKeyPair();
        
        ECCCrypto bob_ecc;
        bob_ecc.generateKeyPair();

        // Step 4: Exchange public keys (this happens over insecure channel - that's OK!)
        std::cout << "\n[STEP 4] Alice and Bob exchange public keys (safe to send openly)" << std::endl;
        std::string alice_pub = alice_ecc.exportPublicKey();
        std::string bob_pub = bob_ecc.exportPublicKey();
        
        std::cout << "Alice's public key (first 100 chars):\n" 
                  << alice_pub.substr(0, 100) << "..." << std::endl;
        std::cout << "Bob's public key (first 100 chars):\n" 
                  << bob_pub.substr(0, 100) << "..." << std::endl;

        // Step 5: Both parties derive the same shared secret using ECDH
        std::cout << "\n[STEP 5] Deriving shared secrets using ECDH" << std::endl;
        std::cout << "Alice computes: shared_secret = ECDH(alice_private, bob_public)" << std::endl;
        EVP_PKEY* bob_public_key = ECCCrypto::importPublicKey(bob_pub);
        auto alice_shared_secret = alice_ecc.deriveSharedSecret(bob_public_key);
        
        std::cout << "\nBob computes: shared_secret = ECDH(bob_private, alice_public)" << std::endl;
        EVP_PKEY* alice_public_key = ECCCrypto::importPublicKey(alice_pub);
        auto bob_shared_secret = bob_ecc.deriveSharedSecret(alice_public_key);

        // Verify both got the same secret
        bool secrets_match = (alice_shared_secret == bob_shared_secret);
        std::cout << "\nShared secrets match: " << (secrets_match ? "YES ✓" : "NO ✗") << std::endl;

        if (!secrets_match) {
            throw std::runtime_error("ECDH key exchange failed!");
        }

        // Step 6: In practice, derive AES key from shared secret using KDF
        // For demonstration, we'll use the shared secret directly as AES key
        // In production, use HKDF or PBKDF2 to derive proper AES key
        std::vector<unsigned char> derived_aes_key(alice_shared_secret.begin(), 
                                                    alice_shared_secret.begin() + 32);

        // Step 7: Alice sends encrypted data to Bob (over any channel)
        std::cout << "\n[STEP 6] Alice sends encrypted data to Bob" << std::endl;
        std::cout << "Transmitted: Encrypted data (" << encrypted_data.size() << " bytes)" << std::endl;

        // Step 8: Bob decrypts the data using the shared AES key
        std::cout << "\n[STEP 7] Bob decrypts the data" << std::endl;
        auto decrypted_data = AESCrypto::decrypt(encrypted_data, aes_key);
        std::string decrypted_message(decrypted_data.begin(), decrypted_data.end());
        
        std::cout << "Decrypted message: \"" << decrypted_message << "\"" << std::endl;

        // Verify integrity
        bool integrity_ok = (decrypted_message == plaintext);
        std::cout << "\nMessage integrity verified: " << (integrity_ok ? "YES ✓" : "NO ✗") << std::endl;

        // Cleanup
        EVP_PKEY_free(bob_public_key);
        EVP_PKEY_free(alice_public_key);

        std::cout << "\n======================================" << std::endl;
        std::cout << "  DEMONSTRATION COMPLETE!" << std::endl;
        std::cout << "======================================" << std::endl;
        std::cout << "\nKey Concepts Demonstrated:" << std::endl;
        std::cout << "✓ AES-256-GCM: Symmetric encryption with authentication" << std::endl;
        std::cout << "✓ ECC P-256: Efficient public-key cryptography" << std::endl;
        std::cout << "✓ ECDH: Secure key agreement over insecure channel" << std::endl;
        std::cout << "✓ Key Exchange: How to safely share encryption keys" << std::endl;
        std::cout << "✓ Authentication: Detecting data tampering" << std::endl;

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "\nFATAL ERROR: " << e.what() << std::endl;
        return 1;
    }
}