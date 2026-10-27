#include "vaultx/crypto/crypto_manager.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <limits>
#include <memory>
#include <stdexcept>

#include "vaultx/core/errors.hpp"

namespace vaultx::crypto {

namespace {

struct CtxDeleter {
    void operator()(EVP_CIPHER_CTX* c) const { EVP_CIPHER_CTX_free(c); }
};
using CtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CtxDeleter>;

CtxPtr newCtx() {
    CtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) throw VaultError("OpenSSL: failed to allocate cipher context");
    return ctx;
}

int toInt(size_t n) {
    if (n > static_cast<size_t>(std::numeric_limits<int>::max())) {
        throw VaultError("Buffer too large for a single OpenSSL call");
    }
    return static_cast<int>(n);
}

}  // namespace

SecureKey::~SecureKey() { OPENSSL_cleanse(bytes.data(), bytes.size()); }

void CryptoManager::randomBytes(uint8_t* out, size_t n) {
    if (RAND_bytes(out, toInt(n)) != 1) {
        throw VaultError("OpenSSL: secure random generator failed");
    }
}

SecureKey CryptoManager::deriveKey(const std::string& password, const uint8_t* salt,
                                   size_t saltLen, uint32_t iterations) {
    if (iterations == 0) throw VaultError("KDF iteration count must be > 0");
    SecureKey key;
    const int ok = PKCS5_PBKDF2_HMAC(password.data(), toInt(password.size()), salt,
                                     toInt(saltLen), static_cast<int>(iterations),
                                     EVP_sha256(), static_cast<int>(kKeySize),
                                     key.bytes.data());
    if (ok != 1) throw VaultError("OpenSSL: PBKDF2 key derivation failed");
    return key;
}

Nonce CryptoManager::makeNonce(const uint8_t* prefix, uint64_t chunkIndex) {
    Nonce n{};
    for (size_t i = 0; i < kNoncePrefixSize; ++i) n[i] = prefix[i];
    for (int i = 0; i < 8; ++i) {
        n[kNoncePrefixSize + static_cast<size_t>(i)] =
            static_cast<uint8_t>(chunkIndex >> (8 * (7 - i)));
    }
    return n;
}

void CryptoManager::encryptChunk(const SecureKey& key, const Nonce& nonce,
                                 const uint8_t* aad, size_t aadLen,
                                 const uint8_t* in, size_t len,
                                 uint8_t* out, uint8_t* tagOut) {
    CtxPtr ctx = newCtx();
    int outLen = 0;

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kNonceSize), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.bytes.data(), nonce.data()) != 1) {
        throw VaultError("OpenSSL: AES-256-GCM encrypt init failed");
    }
    if (aadLen > 0 && EVP_EncryptUpdate(ctx.get(), nullptr, &outLen, aad, toInt(aadLen)) != 1) {
        throw VaultError("OpenSSL: failed to process associated data");
    }
    if (len > 0 && EVP_EncryptUpdate(ctx.get(), out, &outLen, in, toInt(len)) != 1) {
        throw VaultError("OpenSSL: AES-256-GCM encrypt failed");
    }
    uint8_t finalBlock[16];
    if (EVP_EncryptFinal_ex(ctx.get(), finalBlock, &outLen) != 1) {
        throw VaultError("OpenSSL: AES-256-GCM finalize failed");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(kTagSize), tagOut) != 1) {
        throw VaultError("OpenSSL: failed to read authentication tag");
    }
}

bool CryptoManager::decryptChunk(const SecureKey& key, const Nonce& nonce,
                                 const uint8_t* aad, size_t aadLen,
                                 const uint8_t* in, size_t len,
                                 const uint8_t* tag, uint8_t* out) {
    CtxPtr ctx = newCtx();
    int outLen = 0;

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kNonceSize), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.bytes.data(), nonce.data()) != 1) {
        throw VaultError("OpenSSL: AES-256-GCM decrypt init failed");
    }
    if (aadLen > 0 && EVP_DecryptUpdate(ctx.get(), nullptr, &outLen, aad, toInt(aadLen)) != 1) {
        return false;
    }
    if (len > 0 && EVP_DecryptUpdate(ctx.get(), out, &outLen, in, toInt(len)) != 1) {
        return false;
    }
    // The tag must be set before the final call; OpenSSL takes a non-const pointer.
    uint8_t tagCopy[kTagSize];
    for (size_t i = 0; i < kTagSize; ++i) tagCopy[i] = tag[i];
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(kTagSize), tagCopy) != 1) {
        throw VaultError("OpenSSL: failed to set authentication tag");
    }
    uint8_t finalBlock[16];
    return EVP_DecryptFinal_ex(ctx.get(), finalBlock, &outLen) == 1;
}

}  // namespace vaultx::crypto
