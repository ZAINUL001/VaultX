#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace vaultx::crypto {

constexpr size_t kKeySize = 32;     // AES-256
constexpr size_t kSaltSize = 16;    // PBKDF2 salt
constexpr size_t kNonceSize = 12;   // GCM standard 96-bit nonce
constexpr size_t kNoncePrefixSize = 4;
constexpr size_t kTagSize = 16;     // GCM authentication tag

using Nonce = std::array<uint8_t, kNonceSize>;

/// 256-bit key that wipes itself from memory when destroyed.
struct SecureKey {
    std::array<uint8_t, kKeySize> bytes{};
    SecureKey() = default;
    SecureKey(const SecureKey&) = default;
    SecureKey& operator=(const SecureKey&) = default;
    ~SecureKey();
};

/// Thin, thread-safe wrapper over OpenSSL (EVP). No custom cryptography.
/// Every call creates its own cipher context, so workers can call these
/// functions concurrently with a shared read-only key.
class CryptoManager {
public:
    /// Fills `out` with `n` cryptographically secure random bytes.
    static void randomBytes(uint8_t* out, size_t n);

    /// Password -> 256-bit key using PBKDF2-HMAC-SHA256.
    static SecureKey deriveKey(const std::string& password, const uint8_t* salt,
                               size_t saltLen, uint32_t iterations);

    /// 12-byte nonce = 4-byte per-file random prefix || 8-byte big-endian chunk index.
    /// Unique for every chunk of a file, independent of thread scheduling.
    static Nonce makeNonce(const uint8_t* prefix, uint64_t chunkIndex);

    /// AES-256-GCM encrypt. Writes `len` ciphertext bytes to `out` (may equal `in`
    /// size, no expansion) and the 16-byte tag to `tagOut`.
    static void encryptChunk(const SecureKey& key, const Nonce& nonce,
                             const uint8_t* aad, size_t aadLen,
                             const uint8_t* in, size_t len,
                             uint8_t* out, uint8_t* tagOut);

    /// AES-256-GCM decrypt + verify. Returns false if authentication fails
    /// (wrong key, modified data, modified AAD). Output must not be trusted then.
    static bool decryptChunk(const SecureKey& key, const Nonce& nonce,
                             const uint8_t* aad, size_t aadLen,
                             const uint8_t* in, size_t len,
                             const uint8_t* tag, uint8_t* out);
};

}  // namespace vaultx::crypto
