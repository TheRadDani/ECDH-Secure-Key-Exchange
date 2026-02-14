/**
 * SECURE DATA TRANSFER - Network Simulation
 * 
 * This program demonstrates secure data transfer between two parties:
 * - Sender: Encrypts data and sends it
 * - Receiver: Receives and decrypts data
 * 
 * NETWORK SIMULATION:
 * - Uses Unix domain sockets for local IPC (Inter-Process Communication)
 * - In production, replace with TCP/IP sockets for actual network transfer
 * - Demonstrates complete handshake and secure transfer protocol
 * 
 * PROTOCOL:
 * 1. Key Exchange Phase: Exchange ECC public keys
 * 2. Session Establishment: Derive shared AES key via ECDH
 * 3. Data Transfer: Send encrypted data with authentication
 * 4. Verification: Receiver decrypts and verifies integrity
 */

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <iostream>
#include <vector>
#include <cstring>
#include <thread>
#include <chrono>
#include <iomanip>

// Socket path for local communication
const char* SOCKET_PATH = "/tmp/secure_transfer.sock";

// RAII wrappers for OpenSSL
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
 * UTILITY FUNCTIONS
 */
namespace Utils {
    void printHex(const std::string& label, const unsigned char* data, size_t len, size_t max_display = 32) {
        std::cout << label << " (" << len << " bytes): ";
        size_t display_len = std::min(len, max_display);
        for (size_t i = 0; i < display_len; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                      << static_cast<int>(data[i]);
        }
        if (len > max_display) std::cout << "...";
        std::cout << std::dec << std::endl;
    }

    void handleErrors(const std::string& msg) {
        std::cerr << "Error: " << msg << std::endl;
        ERR_print_errors_fp(stderr);
        throw std::runtime_error(msg);
    }

    // Send length-prefixed data over socket
    bool sendData(int socket, const std::vector<unsigned char>& data) {
        // Send length first (4 bytes)
        uint32_t len = data.size();
        if (send(socket, &len, sizeof(len), 0) != sizeof(len)) {
            return false;
        }
        
        // Send actual data
        size_t sent = 0;
        while (sent < data.size()) {
            ssize_t n = send(socket, data.data() + sent, data.size() - sent, 0);
            if (n <= 0) return false;
            sent += n;
        }
        return true;
    }

    // Receive length-prefixed data from socket
    std::vector<unsigned char> receiveData(int socket) {
        // Receive length first
        uint32_t len;
        if (recv(socket, &len, sizeof(len), MSG_WAITALL) != sizeof(len)) {
            throw std::runtime_error("Failed to receive data length");
        }

        if (len > 10 * 1024 * 1024) { // 10MB sanity check
            throw std::runtime_error("Data size too large");
        }

        // Receive actual data
        std::vector<unsigned char> data(len);
        size_t received = 0;
        while (received < len) {
            ssize_t n = recv(socket, data.data() + received, len - received, 0);
            if (n <= 0) throw std::runtime_error("Failed to receive data");
            received += n;
        }
        return data;
    }

    // Send string data
    bool sendString(int socket, const std::string& str) {
        std::vector<unsigned char> data(str.begin(), str.end());
        return sendData(socket, data);
    }

    // Receive string data
    std::string receiveString(int socket) {
        auto data = receiveData(socket);
        return std::string(data.begin(), data.end());
    }
}

/**
 * AES-256-GCM ENCRYPTION
 */
class AESCrypto {
private:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t IV_SIZE = 12;
    static constexpr size_t TAG_SIZE = 16;

public:
    static std::vector<unsigned char> generateKey() {
        std::vector<unsigned char> key(KEY_SIZE);
        if (RAND_bytes(key.data(), KEY_SIZE) != 1) {
            Utils::handleErrors("Failed to generate AES key");
        }
        return key;
    }

    static std::vector<unsigned char> encrypt(
        const std::vector<unsigned char>& plaintext,
        const std::vector<unsigned char>& key
    ) {
        std::vector<unsigned char> iv(IV_SIZE);
        if (RAND_bytes(iv.data(), IV_SIZE) != 1) {
            Utils::handleErrors("Failed to generate IV");
        }

        EVPCipherContext ctx;
        
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            Utils::handleErrors("Failed to initialize encryption");
        }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, nullptr) != 1) {
            Utils::handleErrors("Failed to set IV length");
        }

        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
            Utils::handleErrors("Failed to set key and IV");
        }

        std::vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_CTX_block_size(ctx));
        int len = 0;
        int ciphertext_len = 0;

        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
            Utils::handleErrors("Encryption failed");
        }
        ciphertext_len = len;

        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            Utils::handleErrors("Encryption finalization failed");
        }
        ciphertext_len += len;
        ciphertext.resize(ciphertext_len);

        std::vector<unsigned char> tag(TAG_SIZE);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data()) != 1) {
            Utils::handleErrors("Failed to get authentication tag");
        }

        // Combine IV + Ciphertext + Tag
        std::vector<unsigned char> result;
        result.insert(result.end(), iv.begin(), iv.end());
        result.insert(result.end(), ciphertext.begin(), ciphertext.end());
        result.insert(result.end(), tag.begin(), tag.end());

        return result;
    }

    static std::vector<unsigned char> decrypt(
        const std::vector<unsigned char>& encrypted_data,
        const std::vector<unsigned char>& key
    ) {
        if (encrypted_data.size() < IV_SIZE + TAG_SIZE) {
            Utils::handleErrors("Encrypted data too small");
        }

        std::vector<unsigned char> iv(encrypted_data.begin(), encrypted_data.begin() + IV_SIZE);
        std::vector<unsigned char> tag(encrypted_data.end() - TAG_SIZE, encrypted_data.end());
        std::vector<unsigned char> ciphertext(
            encrypted_data.begin() + IV_SIZE,
            encrypted_data.end() - TAG_SIZE
        );

        EVPCipherContext ctx;

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            Utils::handleErrors("Failed to initialize decryption");
        }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, nullptr) != 1) {
            Utils::handleErrors("Failed to set IV length");
        }

        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
            Utils::handleErrors("Failed to set key and IV");
        }

        std::vector<unsigned char> plaintext(ciphertext.size());
        int len = 0;
        int plaintext_len = 0;

        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
            Utils::handleErrors("Decryption failed");
        }
        plaintext_len = len;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag.data()) != 1) {
            Utils::handleErrors("Failed to set authentication tag");
        }

        int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
        if (ret <= 0) {
            Utils::handleErrors("Authentication failed: data has been tampered!");
        }
        plaintext_len += len;
        plaintext.resize(plaintext_len);

        return plaintext;
    }
};

/**
 * ELLIPTIC CURVE CRYPTOGRAPHY
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

    void generateKeyPair() {
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        if (!pctx) Utils::handleErrors("Failed to create parameter context");
        EVPPKeyContext pctx_guard(pctx);

        if (EVP_PKEY_paramgen_init(pctx) != 1) {
            Utils::handleErrors("Failed to initialize paramgen");
        }

        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) != 1) {
            Utils::handleErrors("Failed to set curve");
        }

        EVP_PKEY* params = nullptr;
        if (EVP_PKEY_paramgen(pctx, &params) != 1) {
            Utils::handleErrors("Failed to generate parameters");
        }

        EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new(params, nullptr);
        EVP_PKEY_free(params);
        if (!kctx) Utils::handleErrors("Failed to create key context");
        EVPPKeyContext kctx_guard(kctx);

        if (EVP_PKEY_keygen_init(kctx) != 1) {
            Utils::handleErrors("Failed to initialize keygen");
        }

        if (EVP_PKEY_keygen(kctx, &privateKey) != 1) {
            Utils::handleErrors("Failed to generate key pair");
        }

        publicKey = EVP_PKEY_new();
        if (!publicKey) Utils::handleErrors("Failed to create public key");

        EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(privateKey);
        if (!ec_key) Utils::handleErrors("Failed to get EC_KEY");
        
        EC_KEY* pub_ec_key = EC_KEY_new();
        EC_KEY_set_group(pub_ec_key, EC_KEY_get0_group(ec_key));
        EC_KEY_set_public_key(pub_ec_key, EC_KEY_get0_public_key(ec_key));
        EVP_PKEY_set1_EC_KEY(publicKey, pub_ec_key);
        
        EC_KEY_free(ec_key);
        EC_KEY_free(pub_ec_key);
    }

    std::string exportPublicKey() {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) Utils::handleErrors("Failed to create BIO");

        if (PEM_write_bio_PUBKEY(bio, publicKey) != 1) {
            BIO_free(bio);
            Utils::handleErrors("Failed to write public key");
        }

        char* pem_data = nullptr;
        long pem_size = BIO_get_mem_data(bio, &pem_data);
        std::string result(pem_data, pem_size);
        BIO_free(bio);

        return result;
    }

    static EVP_PKEY* importPublicKey(const std::string& pem) {
        BIO* bio = BIO_new_mem_buf(pem.data(), pem.size());
        if (!bio) Utils::handleErrors("Failed to create BIO");

        EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!key) Utils::handleErrors("Failed to read public key");
        return key;
    }

    std::vector<unsigned char> deriveSharedSecret(EVP_PKEY* peer_public_key) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privateKey, nullptr);
        if (!ctx) Utils::handleErrors("Failed to create derivation context");
        EVPPKeyContext ctx_guard(ctx);

        if (EVP_PKEY_derive_init(ctx) != 1) {
            Utils::handleErrors("Failed to initialize key derivation");
        }

        if (EVP_PKEY_derive_set_peer(ctx, peer_public_key) != 1) {
            Utils::handleErrors("Failed to set peer public key");
        }

        size_t secret_len = 0;
        if (EVP_PKEY_derive(ctx, nullptr, &secret_len) != 1) {
            Utils::handleErrors("Failed to determine secret length");
        }

        std::vector<unsigned char> shared_secret(secret_len);
        if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) != 1) {
            Utils::handleErrors("Failed to derive shared secret");
        }

        return shared_secret;
    }

    EVP_PKEY* getPublicKey() { return publicKey; }
};

/**
 * RECEIVER - Listens for incoming connections and decrypts data
 */
class SecureReceiver {
private:
    int server_socket;
    ECCCrypto ecc;

public:
    SecureReceiver() : server_socket(-1) {}

    ~SecureReceiver() {
        if (server_socket >= 0) {
            close(server_socket);
            unlink(SOCKET_PATH);
        }
    }

    void start() {
        std::cout << "\n╔══════════════════════════════════════╗" << std::endl;
        std::cout << "║        SECURE RECEIVER STARTED       ║" << std::endl;
        std::cout << "╚══════════════════════════════════════╝" << std::endl;

        // Create socket
        server_socket = socket(AF_UNIX, SOCK_STREAM, 0);
        if (server_socket < 0) {
            throw std::runtime_error("Failed to create socket");
        }

        // Remove old socket file if exists
        unlink(SOCKET_PATH);

        // Bind socket
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

        if (bind(server_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            throw std::runtime_error("Failed to bind socket");
        }

        // Listen for connections
        if (listen(server_socket, 1) < 0) {
            throw std::runtime_error("Failed to listen on socket");
        }

        std::cout << "\n[*] Listening for connections on " << SOCKET_PATH << std::endl;
        std::cout << "[*] Waiting for sender..." << std::endl;

        // Accept connection
        int client_socket = accept(server_socket, nullptr, nullptr);
        if (client_socket < 0) {
            throw std::runtime_error("Failed to accept connection");
        }

        std::cout << "[✓] Connection established!" << std::endl;

        try {
            handleClient(client_socket);
        } catch (...) {
            close(client_socket);
            throw;
        }

        close(client_socket);
    }

private:
    void handleClient(int socket) {
        // ===== PHASE 1: KEY EXCHANGE =====
        std::cout << "\n┌─────────────────────────────────────┐" << std::endl;
        std::cout << "│  PHASE 1: ECC PUBLIC KEY EXCHANGE  │" << std::endl;
        std::cout << "└─────────────────────────────────────┘" << std::endl;

        // Generate our ECC key pair
        std::cout << "[*] Generating ECC key pair..." << std::endl;
        ecc.generateKeyPair();
        std::string our_public_key = ecc.exportPublicKey();
        std::cout << "[✓] ECC key pair generated" << std::endl;

        // Send our public key to sender
        std::cout << "[*] Sending our public key to sender..." << std::endl;
        if (!Utils::sendString(socket, our_public_key)) {
            throw std::runtime_error("Failed to send public key");
        }
        std::cout << "[✓] Public key sent (" << our_public_key.size() << " bytes)" << std::endl;

        // Receive sender's public key
        std::cout << "[*] Receiving sender's public key..." << std::endl;
        std::string peer_public_key_pem = Utils::receiveString(socket);
        std::cout << "[✓] Received sender's public key (" << peer_public_key_pem.size() << " bytes)" << std::endl;

        // ===== PHASE 2: DERIVE SHARED SECRET =====
        std::cout << "\n┌─────────────────────────────────────┐" << std::endl;
        std::cout << "│  PHASE 2: ECDH KEY DERIVATION       │" << std::endl;
        std::cout << "└─────────────────────────────────────┘" << std::endl;

        std::cout << "[*] Deriving shared secret via ECDH..." << std::endl;
        EVP_PKEY* peer_public_key = ECCCrypto::importPublicKey(peer_public_key_pem);
        auto shared_secret = ecc.deriveSharedSecret(peer_public_key);
        EVP_PKEY_free(peer_public_key);

        // Use first 32 bytes as AES key
        std::vector<unsigned char> aes_key(shared_secret.begin(), shared_secret.begin() + 32);
        std::cout << "[✓] Shared secret derived" << std::endl;
        Utils::printHex("   Session AES Key", aes_key.data(), aes_key.size());

        // ===== PHASE 3: RECEIVE ENCRYPTED DATA =====
        std::cout << "\n┌─────────────────────────────────────┐" << std::endl;
        std::cout << "│  PHASE 3: RECEIVE & DECRYPT DATA   │" << std::endl;
        std::cout << "└─────────────────────────────────────┘" << std::endl;

        std::cout << "[*] Waiting for encrypted data..." << std::endl;
        auto encrypted_data = Utils::receiveData(socket);
        std::cout << "[✓] Received encrypted payload (" << encrypted_data.size() << " bytes)" << std::endl;
        Utils::printHex("   Encrypted Data", encrypted_data.data(), encrypted_data.size());

        // ===== PHASE 4: DECRYPT AND VERIFY =====
        std::cout << "\n[*] Decrypting data..." << std::endl;
        auto decrypted_data = AESCrypto::decrypt(encrypted_data, aes_key);
        std::string message(decrypted_data.begin(), decrypted_data.end());

        std::cout << "[✓] Decryption successful!" << std::endl;
        std::cout << "[✓] Authentication verified (data is authentic)" << std::endl;
        
        std::cout << "\n╔══════════════════════════════════════╗" << std::endl;
        std::cout << "║       DECRYPTED MESSAGE:             ║" << std::endl;
        std::cout << "╚══════════════════════════════════════╝" << std::endl;
        std::cout << "\n\"" << message << "\"" << std::endl;
        std::cout << "\n[✓] Secure transfer complete!" << std::endl;
    }
};

/**
 * SENDER - Connects to receiver and sends encrypted data
 */
class SecureSender {
private:
    ECCCrypto ecc;

public:
    void send(const std::string& message) {
        std::cout << "\n╔══════════════════════════════════════╗" << std::endl;
        std::cout << "║         SECURE SENDER STARTED        ║" << std::endl;
        std::cout << "╚══════════════════════════════════════╝" << std::endl;

        std::cout << "\n[*] Message to send: \"" << message << "\"" << std::endl;

        // Create socket
        int sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) {
            throw std::runtime_error("Failed to create socket");
        }

        // Connect to receiver
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

        std::cout << "[*] Connecting to receiver..." << std::endl;
        
        // Retry connection a few times (receiver might not be ready immediately)
        int retries = 5;
        while (retries-- > 0) {
            if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                break;
            }
            if (retries == 0) {
                close(sock);
                throw std::runtime_error("Failed to connect to receiver");
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        std::cout << "[✓] Connected to receiver!" << std::endl;

        try {
            performSecureTransfer(sock, message);
        } catch (...) {
            close(sock);
            throw;
        }

        close(sock);
    }

private:
    void performSecureTransfer(int socket, const std::string& message) {
        // ===== PHASE 1: KEY EXCHANGE =====
        std::cout << "\n┌─────────────────────────────────────┐" << std::endl;
        std::cout << "│  PHASE 1: ECC PUBLIC KEY EXCHANGE  │" << std::endl;
        std::cout << "└─────────────────────────────────────┘" << std::endl;

        // Generate our ECC key pair
        std::cout << "[*] Generating ECC key pair..." << std::endl;
        ecc.generateKeyPair();
        std::string our_public_key = ecc.exportPublicKey();
        std::cout << "[✓] ECC key pair generated" << std::endl;

        // Receive receiver's public key first
        std::cout << "[*] Receiving receiver's public key..." << std::endl;
        std::string peer_public_key_pem = Utils::receiveString(socket);
        std::cout << "[✓] Received receiver's public key (" << peer_public_key_pem.size() << " bytes)" << std::endl;

        // Send our public key
        std::cout << "[*] Sending our public key to receiver..." << std::endl;
        if (!Utils::sendString(socket, our_public_key)) {
            throw std::runtime_error("Failed to send public key");
        }
        std::cout << "[✓] Public key sent (" << our_public_key.size() << " bytes)" << std::endl;

        // ===== PHASE 2: DERIVE SHARED SECRET =====
        std::cout << "\n┌─────────────────────────────────────┐" << std::endl;
        std::cout << "│  PHASE 2: ECDH KEY DERIVATION       │" << std::endl;
        std::cout << "└─────────────────────────────────────┘" << std::endl;

        std::cout << "[*] Deriving shared secret via ECDH..." << std::endl;
        EVP_PKEY* peer_public_key = ECCCrypto::importPublicKey(peer_public_key_pem);
        auto shared_secret = ecc.deriveSharedSecret(peer_public_key);
        EVP_PKEY_free(peer_public_key);

        // Use first 32 bytes as AES key
        std::vector<unsigned char> aes_key(shared_secret.begin(), shared_secret.begin() + 32);
        std::cout << "[✓] Shared secret derived" << std::endl;
        Utils::printHex("   Session AES Key", aes_key.data(), aes_key.size());

        // ===== PHASE 3: ENCRYPT DATA =====
        std::cout << "\n┌─────────────────────────────────────┐" << std::endl;
        std::cout << "│  PHASE 3: ENCRYPT & SEND DATA       │" << std::endl;
        std::cout << "└─────────────────────────────────────┘" << std::endl;

        std::cout << "[*] Encrypting message with AES-256-GCM..." << std::endl;
        std::vector<unsigned char> plaintext(message.begin(), message.end());
        auto encrypted_data = AESCrypto::encrypt(plaintext, aes_key);
        std::cout << "[✓] Message encrypted (" << encrypted_data.size() << " bytes)" << std::endl;
        Utils::printHex("   Encrypted Data", encrypted_data.data(), encrypted_data.size());

        // ===== PHASE 4: SEND ENCRYPTED DATA =====
        std::cout << "\n[*] Sending encrypted data to receiver..." << std::endl;
        if (!Utils::sendData(socket, encrypted_data)) {
            throw std::runtime_error("Failed to send encrypted data");
        }
        std::cout << "[✓] Encrypted data sent successfully!" << std::endl;
        std::cout << "\n[✓] Secure transfer complete!" << std::endl;
    }
};

/**
 * MAIN PROGRAM
 */
int main(int argc, char* argv[]) {
    try {
        std::cout << "╔════════════════════════════════════════════════╗" << std::endl;
        std::cout << "║   SECURE DATA TRANSFER DEMONSTRATION           ║" << std::endl;
        std::cout << "║   ECC (P-256) + AES-256-GCM                    ║" << std::endl;
        std::cout << "╚════════════════════════════════════════════════╝" << std::endl;

        if (argc < 2) {
            std::cout << "\nUsage:" << std::endl;
            std::cout << "  Receiver: " << argv[0] << " receive" << std::endl;
            std::cout << "  Sender:   " << argv[0] << " send \"your message here\"" << std::endl;
            std::cout << "\nExample:" << std::endl;
            std::cout << "  Terminal 1: " << argv[0] << " receive" << std::endl;
            std::cout << "  Terminal 2: " << argv[0] << " send \"Hello, World!\"" << std::endl;
            return 1;
        }

        std::string mode = argv[1];

        if (mode == "receive") {
            // Run as receiver
            SecureReceiver receiver;
            receiver.start();

        } else if (mode == "send") {
            // Run as sender
            if (argc < 3) {
                std::cerr << "Error: Please provide a message to send" << std::endl;
                std::cerr << "Usage: " << argv[0] << " send \"your message\"" << std::endl;
                return 1;
            }

            std::string message = argv[2];
            SecureSender sender;
            sender.send(message);

        } else {
            std::cerr << "Error: Unknown mode '" << mode << "'" << std::endl;
            std::cerr << "Valid modes: receive, send" << std::endl;
            return 1;
        }

        std::cout << "\n╔════════════════════════════════════════════════╗" << std::endl;
        std::cout << "║             PROGRAM COMPLETED                  ║" << std::endl;
        std::cout << "╚════════════════════════════════════════════════╝" << std::endl;

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "\n╔════════════════════════════════════════════════╗" << std::endl;
        std::cerr << "║                 FATAL ERROR                    ║" << std::endl;
        std::cerr << "╚════════════════════════════════════════════════╝" << std::endl;
        std::cerr << "\nError: " << e.what() << std::endl;
        return 1;
    }
}