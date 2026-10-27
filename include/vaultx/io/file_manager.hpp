#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vaultx::io {

/// A contiguous byte buffer representing file (or chunk) data.
using ByteBuffer = std::vector<uint8_t>;

/// Reads/writes whole files and does chunk arithmetic for the thread pool.
class FileManager {
public:
    /// Reads the entire file into memory. Throws std::runtime_error on failure.
    static ByteBuffer readFile(const std::string& path);

    /// Writes `data` to `path`, overwriting any existing file.
    static void writeFile(const std::string& path, const ByteBuffer& data);

    static uint64_t fileSize(const std::string& path);
    static bool exists(const std::string& path);

    /// Number of chunks needed for `totalSize` bytes. A zero-byte file
    /// still counts as ONE (empty) chunk so it carries an authentication tag.
    static uint64_t chunkCount(uint64_t totalSize, uint64_t chunkSize);

    /// Splits `data` into copies of at most `chunkSize` bytes each.
    /// (The encryption pipeline itself works zero-copy on offsets instead.)
    static std::vector<ByteBuffer> splitIntoChunks(const ByteBuffer& data, size_t chunkSize);

    /// Returns true if both files exist and have identical bytes.
    static bool filesIdentical(const std::string& a, const std::string& b);
};

}  // namespace vaultx::io
