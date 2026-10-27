#include "vaultx/core/encrypt_task.hpp"

#include <cstring>

namespace vaultx::core {

namespace {

constexpr size_t kAadSize = FileHeader::kSize + 8 + 1;

/// AAD = header || chunk index (LE) || final flag.
std::array<uint8_t, kAadSize> buildAad(const ChunkJob& j) {
    std::array<uint8_t, kAadSize> aad{};
    std::memcpy(aad.data(), j.header->data(), FileHeader::kSize);
    for (int i = 0; i < 8; ++i) {
        aad[FileHeader::kSize + static_cast<size_t>(i)] = static_cast<uint8_t>(j.index >> (8 * i));
    }
    aad[kAadSize - 1] = j.isFinal ? 1 : 0;
    return aad;
}

}  // namespace

void EncryptTask::operator()() const {
    const auto aad = buildAad(job_);
    const auto nonce = crypto::CryptoManager::makeNonce(job_.noncePrefix, job_.index);
    crypto::CryptoManager::encryptChunk(*job_.key, nonce, aad.data(), aad.size(),
                                        job_.in, job_.len, job_.out, job_.out + job_.len);
    if (job_.progress) job_.progress->fetch_add(1, std::memory_order_relaxed);
}

void DecryptTask::operator()() const {
    if (failed_->load(std::memory_order_relaxed)) return;  // another chunk already failed: stop early
    const auto aad = buildAad(job_);
    const auto nonce = crypto::CryptoManager::makeNonce(job_.noncePrefix, job_.index);
    // For decryption, `in` points at ciphertext followed by the tag.
    const bool ok = crypto::CryptoManager::decryptChunk(*job_.key, nonce, aad.data(), aad.size(),
                                                        job_.in, job_.len, job_.in + job_.len, job_.out);
    if (!ok) failed_->store(true, std::memory_order_relaxed);
    if (job_.progress) job_.progress->fetch_add(1, std::memory_order_relaxed);
}

}  // namespace vaultx::core
