#include "vaultx/core/vault.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <future>
#include <vector>

#include "vaultx/core/encrypt_task.hpp"
#include "vaultx/core/errors.hpp"
#include "vaultx/threading/thread_pool.hpp"

namespace vaultx::core {

namespace {

using Clock = std::chrono::steady_clock;
using crypto::kTagSize;

double secondsSince(Clock::time_point t0) {
    return std::chrono::duration<double>(Clock::now() - t0).count();
}

void checkThreads(unsigned threads) {
    if (threads == 0 || threads > kMaxThreads) {
        throw VaultError("Thread count must be between 1 and " + std::to_string(kMaxThreads));
    }
}

void checkChunkSize(uint32_t chunkSize) {
    if (chunkSize < FileHeader::kMinChunkSize || chunkSize > FileHeader::kMaxChunkSize) {
        throw VaultError("Chunk size must be between 1 KiB and 64 MiB");
    }
}

/// Waits for every future (in order), reporting progress from the calling thread.
void waitAll(std::vector<std::future<void>>& futures, const std::atomic<size_t>& done,
             const ProgressFn& progress) {
    const size_t total = futures.size();
    std::exception_ptr firstError;
    for (auto& f : futures) {
        while (f.wait_for(std::chrono::milliseconds(50)) != std::future_status::ready) {
            if (progress) progress(done.load(std::memory_order_relaxed), total);
        }
        try {
            f.get();
        } catch (...) {
            if (!firstError) firstError = std::current_exception();
        }
    }
    if (progress) progress(total, total);
    if (firstError) std::rethrow_exception(firstError);
}

}  // namespace

FileHeader Vault::makeHeader(uint64_t plainSize, uint32_t chunkSize, uint32_t iterations) {
    checkChunkSize(chunkSize);
    FileHeader h;
    h.iterations = iterations;
    h.chunkSize = chunkSize;
    h.originalSize = plainSize;
    h.chunkCount = io::FileManager::chunkCount(plainSize, chunkSize);
    crypto::CryptoManager::randomBytes(h.salt.data(), h.salt.size());
    crypto::CryptoManager::randomBytes(h.noncePrefix.data(), h.noncePrefix.size());
    return h;
}

void Vault::encryptInto(const ByteBuffer& plain, const crypto::SecureKey& key,
                        const FileHeader& header, unsigned threads, uint8_t* out,
                        const ProgressFn& progress) {
    checkThreads(threads);
    if (plain.size() != header.originalSize) throw VaultError("Header does not match input size");
    const uint64_t nChunks = header.chunkCount;
    const size_t chunkSize = header.chunkSize;

    // Output layout is fully known up front, so every worker writes to its own
    // slice: chunk i lives at kSize + i * (chunkSize + tag). No locks on data.
    const auto headerBytes = header.serialize();
    std::memcpy(out, headerBytes.data(), headerBytes.size());

    std::atomic<size_t> done{0};
    std::vector<std::future<void>> futures;
    futures.reserve(static_cast<size_t>(nChunks));

    {
        threading::ThreadPool pool(threads);
        for (uint64_t i = 0; i < nChunks; ++i) {
            const size_t inOff = static_cast<size_t>(i * chunkSize);
            const size_t len = std::min<size_t>(chunkSize, plain.size() - inOff);
            const size_t outOff = FileHeader::kSize + static_cast<size_t>(i * (chunkSize + kTagSize));

            ChunkJob job{&key, &headerBytes, header.noncePrefix.data(), i, i + 1 == nChunks,
                         plain.data() + inOff, len, out + outOff, &done};
            futures.push_back(pool.submit(EncryptTask(job)));
        }
        waitAll(futures, done, progress);
    }  // pool destructor joins the workers
}

ByteBuffer Vault::encryptBuffer(const ByteBuffer& plain, const crypto::SecureKey& key,
                                const FileHeader& header, unsigned threads,
                                const ProgressFn& progress) {
    ByteBuffer out(static_cast<size_t>(header.totalFileSize()));
    encryptInto(plain, key, header, threads, out.data(), progress);
    return out;
}

ByteBuffer Vault::decryptBuffer(const ByteBuffer& enc, const std::string& password,
                                unsigned threads, const ProgressFn& progress, Timings* timings) {
    checkThreads(threads);
    const FileHeader header = FileHeader::parse(enc.data(), enc.size());
    if (enc.size() != header.totalFileSize()) {
        throw FormatError("File is truncated or has extra data (size does not match header)");
    }

    const auto tKdf = Clock::now();
    const crypto::SecureKey key = crypto::CryptoManager::deriveKey(
        password, header.salt.data(), header.salt.size(), header.iterations);
    const double kdfSec = secondsSince(tKdf);

    const auto headerBytes = header.serialize();
    const uint64_t nChunks = header.chunkCount;
    const size_t chunkSize = header.chunkSize;
    ByteBuffer plain(static_cast<size_t>(header.originalSize));

    std::atomic<size_t> done{0};
    std::atomic<bool> failed{false};
    std::vector<std::future<void>> futures;
    futures.reserve(static_cast<size_t>(nChunks));

    const auto tChunks = Clock::now();
    {
        threading::ThreadPool pool(threads);
        for (uint64_t i = 0; i < nChunks; ++i) {
            const size_t plainOff = static_cast<size_t>(i * chunkSize);
            const size_t len = std::min<size_t>(chunkSize, plain.size() - plainOff);
            const size_t encOff = FileHeader::kSize + static_cast<size_t>(i * (chunkSize + kTagSize));

            ChunkJob job{&key, &headerBytes, header.noncePrefix.data(), i, i + 1 == nChunks,
                         enc.data() + encOff, len, plain.data() + plainOff, &done};
            futures.push_back(pool.submit(DecryptTask(job, &failed)));
        }
        waitAll(futures, done, progress);
    }
    if (timings) {
        timings->keyDerivation = kdfSec;
        timings->chunkProcessing = secondsSince(tChunks);
        timings->plainBytes = header.originalSize;
        timings->chunks = nChunks;
    }
    if (failed.load()) {
        throw AuthError("Authentication failed: wrong password, or the file has been modified/corrupted");
    }
    return plain;
}

Timings Vault::encryptFile(const std::string& inPath, const std::string& outPath,
                           const std::string& password, const VaultOptions& opts) {
    checkThreads(opts.threads);
    checkChunkSize(opts.chunkSize);
    const auto t0 = Clock::now();
    Timings t;

    const ByteBuffer plain = io::FileManager::readFile(inPath);
    FileHeader header = makeHeader(plain.size(), opts.chunkSize, opts.iterations);

    const auto tKdf = Clock::now();
    const crypto::SecureKey key = crypto::CryptoManager::deriveKey(
        password, header.salt.data(), header.salt.size(), header.iterations);
    t.keyDerivation = secondsSince(tKdf);

    const auto tChunks = Clock::now();
    const ByteBuffer enc = encryptBuffer(plain, key, header, opts.threads, opts.progress);
    t.chunkProcessing = secondsSince(tChunks);

    io::FileManager::writeFile(outPath, enc);
    t.total = secondsSince(t0);
    t.plainBytes = plain.size();
    t.chunks = header.chunkCount;
    return t;
}

Timings Vault::decryptFile(const std::string& inPath, const std::string& outPath,
                           const std::string& password, const VaultOptions& opts) {
    const auto t0 = Clock::now();
    Timings t;
    const ByteBuffer enc = io::FileManager::readFile(inPath);
    const ByteBuffer plain = decryptBuffer(enc, password, opts.threads, opts.progress, &t);
    io::FileManager::writeFile(outPath, plain);  // only reached if authentication succeeded
    t.total = secondsSince(t0);
    return t;
}

}  // namespace vaultx::core
