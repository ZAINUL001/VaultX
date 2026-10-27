#include "vaultx/io/file_manager.hpp"

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <stdexcept>

namespace vaultx::io {

namespace fs = std::filesystem;

ByteBuffer FileManager::readFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) throw std::runtime_error("Failed to open file for reading: " + path);

    const std::streamsize size = in.tellg();
    if (size < 0) throw std::runtime_error("Failed to determine size of file: " + path);
    in.seekg(0, std::ios::beg);

    ByteBuffer buffer(static_cast<size_t>(size));
    if (size > 0 && !in.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Failed to read file contents: " + path);
    }
    return buffer;
}

void FileManager::writeFile(const std::string& path, const ByteBuffer& data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("Failed to open file for writing: " + path);

    if (!data.empty()) {
        out.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));
    }
    out.flush();
    if (!out) throw std::runtime_error("Failed to write file contents: " + path);
}

uint64_t FileManager::fileSize(const std::string& path) {
    std::error_code ec;
    const auto size = fs::file_size(path, ec);
    if (ec) throw std::runtime_error("Failed to stat file: " + path + " (" + ec.message() + ")");
    return static_cast<uint64_t>(size);
}

bool FileManager::exists(const std::string& path) {
    std::error_code ec;
    return fs::is_regular_file(path, ec) && !ec;
}

uint64_t FileManager::chunkCount(uint64_t totalSize, uint64_t chunkSize) {
    if (chunkSize == 0) throw std::invalid_argument("chunkSize must be greater than zero");
    if (totalSize == 0) return 1;
    return (totalSize + chunkSize - 1) / chunkSize;
}

std::vector<ByteBuffer> FileManager::splitIntoChunks(const ByteBuffer& data, size_t chunkSize) {
    if (chunkSize == 0) throw std::invalid_argument("chunkSize must be greater than zero");

    std::vector<ByteBuffer> chunks;
    if (data.empty()) return chunks;

    chunks.reserve((data.size() + chunkSize - 1) / chunkSize);
    for (size_t offset = 0; offset < data.size(); offset += chunkSize) {
        const size_t len = std::min(chunkSize, data.size() - offset);
        chunks.emplace_back(data.begin() + static_cast<std::ptrdiff_t>(offset),
                            data.begin() + static_cast<std::ptrdiff_t>(offset + len));
    }
    return chunks;
}

bool FileManager::filesIdentical(const std::string& a, const std::string& b) {
    if (!exists(a) || !exists(b)) return false;
    if (fileSize(a) != fileSize(b)) return false;

    std::ifstream fa(a, std::ios::binary), fb(b, std::ios::binary);
    if (!fa || !fb) return false;

    constexpr size_t kBuf = 1 << 20;
    std::vector<char> ba(kBuf), bb(kBuf);
    while (fa && fb) {
        fa.read(ba.data(), kBuf);
        fb.read(bb.data(), kBuf);
        const auto na = fa.gcount();
        if (na != fb.gcount()) return false;
        if (!std::equal(ba.begin(), ba.begin() + na, bb.begin())) return false;
        if (na == 0) break;
    }
    return true;
}

}  // namespace vaultx::io
