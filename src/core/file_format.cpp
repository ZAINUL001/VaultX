#include "vaultx/core/file_format.hpp"

#include <cstring>

#include "vaultx/core/errors.hpp"
#include "vaultx/io/file_manager.hpp"

namespace vaultx::core {

namespace {

constexpr uint8_t kMagic[6] = {'V', 'A', 'U', 'L', 'T', 'X'};

void putU32(uint8_t* p, uint32_t v) {
    for (int i = 0; i < 4; ++i) p[i] = static_cast<uint8_t>(v >> (8 * i));
}
void putU64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = static_cast<uint8_t>(v >> (8 * i));
}
uint32_t getU32(const uint8_t* p) {
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v |= static_cast<uint32_t>(p[i]) << (8 * i);
    return v;
}
uint64_t getU64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (8 * i);
    return v;
}

}  // namespace

std::array<uint8_t, FileHeader::kSize> FileHeader::serialize() const {
    std::array<uint8_t, kSize> out{};
    std::memcpy(out.data(), kMagic, 6);
    out[6] = kVersion;
    out[7] = 0;
    putU32(out.data() + 8, iterations);
    std::memcpy(out.data() + 12, salt.data(), salt.size());
    std::memcpy(out.data() + 28, noncePrefix.data(), noncePrefix.size());
    putU32(out.data() + 32, chunkSize);
    putU64(out.data() + 36, originalSize);
    putU64(out.data() + 44, chunkCount);
    return out;
}

FileHeader FileHeader::parse(const uint8_t* data, size_t len) {
    if (len < kSize) throw FormatError("File is too small to be a VaultX file");
    if (std::memcmp(data, kMagic, 6) != 0) throw FormatError("Not a VaultX file (bad magic number)");
    if (data[6] != kVersion) throw FormatError("Unsupported VaultX file version");

    FileHeader h;
    h.iterations = getU32(data + 8);
    std::memcpy(h.salt.data(), data + 12, h.salt.size());
    std::memcpy(h.noncePrefix.data(), data + 28, h.noncePrefix.size());
    h.chunkSize = getU32(data + 32);
    h.originalSize = getU64(data + 36);
    h.chunkCount = getU64(data + 44);

    if (h.iterations == 0 || h.iterations > kMaxIterations)
        throw FormatError("Corrupt header (invalid KDF iteration count)");
    if (h.chunkSize < kMinChunkSize || h.chunkSize > kMaxChunkSize)
        throw FormatError("Corrupt header (invalid chunk size)");
    if (h.originalSize > (uint64_t{1} << 56))
        throw FormatError("Corrupt header (implausible file size)");
    if (h.chunkCount != io::FileManager::chunkCount(h.originalSize, h.chunkSize))
        throw FormatError("Corrupt header (chunk count does not match file size)");
    return h;
}

}  // namespace vaultx::core
