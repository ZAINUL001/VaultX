#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "vaultx/crypto/crypto_manager.hpp"

namespace vaultx::core {

/// .vx file layout (all integers little-endian):
///
///   offset size  field
///   0      6     magic "VAULTX"
///   6      1     format version (1)
///   7      1     reserved (0)
///   8      4     PBKDF2 iteration count
///   12     16    PBKDF2 salt (random per file)
///   28     4     nonce prefix (random per file)
///   32     4     chunk size in bytes (plaintext)
///   36     8     original (plaintext) size
///   44     8     chunk count
///   52 ... chunk records, back to back: [ciphertext (== plaintext len)][16-byte GCM tag]
///
/// The whole 52-byte header is fed to GCM as associated data for every chunk,
/// together with the chunk index and a "final chunk" flag. Changing the header,
/// reordering chunks, or truncating the file therefore breaks authentication.
struct FileHeader {
    static constexpr size_t kSize = 52;
    static constexpr uint8_t kVersion = 1;
    static constexpr uint32_t kMinChunkSize = 1024;               // 1 KiB
    static constexpr uint32_t kMaxChunkSize = 64u * 1024 * 1024;  // 64 MiB
    static constexpr uint32_t kMaxIterations = 50'000'000;        // sanity cap on untrusted input

    uint32_t iterations = 0;
    std::array<uint8_t, crypto::kSaltSize> salt{};
    std::array<uint8_t, crypto::kNoncePrefixSize> noncePrefix{};
    uint32_t chunkSize = 0;
    uint64_t originalSize = 0;
    uint64_t chunkCount = 0;

    std::array<uint8_t, kSize> serialize() const;

    /// Parses and validates. Throws FormatError for anything malformed.
    static FileHeader parse(const uint8_t* data, size_t len);

    /// Total size of the encrypted file implied by this header.
    uint64_t totalFileSize() const { return kSize + originalSize + chunkCount * crypto::kTagSize; }
};

}  // namespace vaultx::core
