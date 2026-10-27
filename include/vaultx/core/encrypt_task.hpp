#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

#include "vaultx/core/file_format.hpp"
#include "vaultx/crypto/crypto_manager.hpp"

namespace vaultx::core {

/// Everything a worker needs to know about one chunk. Chunks never overlap,
/// so concurrent tasks touch disjoint memory and need no locking.
struct ChunkJob {
    const crypto::SecureKey* key;                           // shared, read-only
    const std::array<uint8_t, FileHeader::kSize>* header;   // shared, read-only (used as AAD)
    const uint8_t* noncePrefix;                             // 4 bytes
    uint64_t index;                                         // chunk number
    bool isFinal;                                           // last chunk of the file?
    const uint8_t* in;
    size_t len;
    uint8_t* out;                                           // ciphertext (len) + tag (16) when encrypting
    std::atomic<size_t>* progress;                          // optional completed-chunk counter
};

/// One unit of parallel work: encrypt a single chunk with AES-256-GCM.
class EncryptTask {
public:
    explicit EncryptTask(ChunkJob job) : job_(job) {}
    void operator()() const;

private:
    ChunkJob job_;
};

/// Mirror image: verify and decrypt one chunk. Sets `*failed` on auth failure.
class DecryptTask {
public:
    DecryptTask(ChunkJob job, std::atomic<bool>* failed) : job_(job), failed_(failed) {}
    void operator()() const;

private:
    ChunkJob job_;
    std::atomic<bool>* failed_;
};

}  // namespace vaultx::core
