#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

#include "vaultx/core/file_format.hpp"
#include "vaultx/crypto/crypto_manager.hpp"
#include "vaultx/io/file_manager.hpp"

namespace vaultx::core {

using io::ByteBuffer;

constexpr uint32_t kDefaultChunkSize = 1u << 20;      // 1 MiB
constexpr uint32_t kDefaultIterations = 600'000;      // PBKDF2-HMAC-SHA256
constexpr unsigned kMaxThreads = 256;

/// Called from the calling thread while workers run: (chunksDone, chunksTotal).
using ProgressFn = std::function<void(size_t done, size_t total)>;

struct VaultOptions {
    unsigned threads = 1;
    uint32_t chunkSize = kDefaultChunkSize;
    uint32_t iterations = kDefaultIterations;
    ProgressFn progress;  // optional
};

/// Wall-clock timings (seconds) of one operation, measured with steady_clock.
struct Timings {
    double keyDerivation = 0;  // PBKDF2 (serial)
    double chunkProcessing = 0;  // parallel part: all chunks through the thread pool
    double total = 0;            // read + KDF + chunks + write
    uint64_t plainBytes = 0;
    uint64_t chunks = 0;
};

class Vault {
public:
    /// New header with fresh random salt + nonce prefix.
    static FileHeader makeHeader(uint64_t plainSize, uint32_t chunkSize, uint32_t iterations);

    /// THE parallel core: encrypts `plain` chunk-by-chunk with a thread pool, writing
    /// header + encrypted chunks into `out` (must hold header.totalFileSize() bytes).
    /// Deterministic for a given key/header, regardless of thread count.
    static void encryptInto(const ByteBuffer& plain, const crypto::SecureKey& key,
                            const FileHeader& header, unsigned threads, uint8_t* out,
                            const ProgressFn& progress = nullptr);

    /// Convenience wrapper: allocates the output buffer and calls encryptInto().
    static ByteBuffer encryptBuffer(const ByteBuffer& plain, const crypto::SecureKey& key,
                                    const FileHeader& header, unsigned threads,
                                    const ProgressFn& progress = nullptr);

    /// Parses + validates, derives the key from the password, decrypts chunks in
    /// parallel. Throws FormatError (malformed) or AuthError (wrong password/modified).
    static ByteBuffer decryptBuffer(const ByteBuffer& encrypted, const std::string& password,
                                    unsigned threads, const ProgressFn& progress = nullptr,
                                    Timings* timings = nullptr);

    static Timings encryptFile(const std::string& inPath, const std::string& outPath,
                               const std::string& password, const VaultOptions& opts);
    static Timings decryptFile(const std::string& inPath, const std::string& outPath,
                               const std::string& password, const VaultOptions& opts);
};

}  // namespace vaultx::core
