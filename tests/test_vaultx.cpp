// Self-contained test runner (no external test framework needed).
// Build + run:  cmake --build build && ctest --test-dir build --output-on-failure
//          or:  ./build/bin/vaultx_tests

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <functional>
#include <iostream>
#include <numeric>
#include <random>
#include <set>
#include <string>
#include <vector>

#include "vaultx/core/errors.hpp"
#include "vaultx/core/vault.hpp"
#include "vaultx/io/file_manager.hpp"
#include "vaultx/threading/thread_pool.hpp"

using namespace vaultx;
using core::ByteBuffer;
using core::FileHeader;
using core::Vault;

namespace {

constexpr uint32_t kFastIters = 1000;  // keep tests quick; production default is 600,000
constexpr uint32_t kChunk = 64 * 1024;

int g_failed = 0;
int g_passed = 0;

#define CHECK(cond)                                                                  \
    do {                                                                             \
        if (!(cond)) {                                                               \
            std::cout << "    FAILED: " #cond "  (line " << __LINE__ << ")\n";       \
            throw std::runtime_error("check failed");                                \
        }                                                                            \
    } while (0)

template <class E, class F>
bool throwsType(F&& f) {
    try { f(); } catch (const E&) { return true; } catch (...) { return false; }
    return false;
}

ByteBuffer randomData(size_t n, unsigned seed = 1) {
    std::mt19937 rng(seed);
    ByteBuffer b(n);
    for (auto& x : b) x = static_cast<uint8_t>(rng());
    return b;
}

ByteBuffer encrypt(const ByteBuffer& plain, const std::string& pw, unsigned threads, uint32_t chunk = kChunk) {
    FileHeader h = Vault::makeHeader(plain.size(), chunk, kFastIters);
    auto key = crypto::CryptoManager::deriveKey(pw, h.salt.data(), h.salt.size(), h.iterations);
    return Vault::encryptBuffer(plain, key, h, threads);
}

std::filesystem::path tmpPath(const std::string& name) {
    return std::filesystem::temp_directory_path() / ("vaultx_test_" + name);
}

void run(const std::string& name, const std::function<void()>& fn) {
    std::cout << "[ RUN  ] " << name << "\n";
    try {
        fn();
        ++g_passed;
        std::cout << "[  OK  ] " << name << "\n";
    } catch (const std::exception& e) {
        ++g_failed;
        std::cout << "[ FAIL ] " << name << " : " << e.what() << "\n";
    }
}

// ---------------------------------------------------------------- tests

void testRoundTrip() {
    const ByteBuffer plain = randomData(1'000'000);
    const ByteBuffer enc = encrypt(plain, "correct horse", 4);
    CHECK(enc != plain);
    CHECK(Vault::decryptBuffer(enc, "correct horse", 4) == plain);
}

void testFileRoundTrip() {
    const auto in = tmpPath("in.bin").string(), vx = tmpPath("out.vx").string(), back = tmpPath("back.bin").string();
    io::FileManager::writeFile(in, randomData(300'001, 7));
    core::VaultOptions o;
    o.threads = 3; o.chunkSize = kChunk; o.iterations = kFastIters;
    Vault::encryptFile(in, vx, "pw", o);
    Vault::decryptFile(vx, back, "pw", o);
    CHECK(io::FileManager::filesIdentical(in, back));
    std::filesystem::remove(in); std::filesystem::remove(vx); std::filesystem::remove(back);
}

void testWrongPassword() {
    const ByteBuffer enc = encrypt(randomData(200'000), "right", 2);
    CHECK(throwsType<AuthError>([&] { Vault::decryptBuffer(enc, "wrong", 2); }));
}

void testWrongPasswordWritesNoFile() {
    const auto in = tmpPath("in2.bin").string(), vx = tmpPath("out2.vx").string(), back = tmpPath("back2.bin").string();
    io::FileManager::writeFile(in, randomData(100'000));
    core::VaultOptions o; o.threads = 2; o.chunkSize = kChunk; o.iterations = kFastIters;
    Vault::encryptFile(in, vx, "right", o);
    std::filesystem::remove(back);
    CHECK(throwsType<AuthError>([&] { Vault::decryptFile(vx, back, "wrong", o); }));
    CHECK(!std::filesystem::exists(back));  // nothing unauthenticated is ever written
    std::filesystem::remove(in); std::filesystem::remove(vx);
}

void testTamperedCiphertext() {
    ByteBuffer enc = encrypt(randomData(500'000), "pw", 4);
    enc[FileHeader::kSize + 3 * (kChunk + 16) + 100] ^= 0x01;  // one bit in chunk 3
    CHECK(throwsType<AuthError>([&] { Vault::decryptBuffer(enc, "pw", 4); }));
}

void testTamperedTag() {
    ByteBuffer enc = encrypt(randomData(500'000), "pw", 2);
    enc[FileHeader::kSize + kChunk + 5] ^= 0x80;  // inside the first chunk's tag
    CHECK(throwsType<AuthError>([&] { Vault::decryptBuffer(enc, "pw", 2); }));
}

void testTamperedHeader() {
    ByteBuffer enc = encrypt(randomData(200'000), "pw", 2);
    enc[28] ^= 0x01;  // nonce prefix: changes AAD and nonce
    CHECK(throwsType<AuthError>([&] { Vault::decryptBuffer(enc, "pw", 2); }));
    ByteBuffer enc2 = encrypt(randomData(200'000), "pw", 2);
    enc2[12] ^= 0x01;  // salt: derives a different key
    CHECK(throwsType<AuthError>([&] { Vault::decryptBuffer(enc2, "pw", 2); }));
}

void testTruncatedAndExtended() {
    const ByteBuffer enc = encrypt(randomData(300'000), "pw", 2);
    ByteBuffer cut(enc.begin(), enc.end() - 1);
    CHECK(throwsType<FormatError>([&] { Vault::decryptBuffer(cut, "pw", 2); }));
    ByteBuffer longer = enc; longer.push_back(0);
    CHECK(throwsType<FormatError>([&] { Vault::decryptBuffer(longer, "pw", 2); }));
    // Dropping a whole chunk record and fixing nothing else must also fail.
    ByteBuffer dropped(enc.begin(), enc.end() - (kChunk + 16));
    CHECK(throwsType<FormatError>([&] { Vault::decryptBuffer(dropped, "pw", 2); }));
}

void testReorderedChunks() {
    ByteBuffer enc = encrypt(randomData(4 * kChunk), "pw", 2);
    const size_t rec = kChunk + 16;
    std::swap_ranges(enc.begin() + FileHeader::kSize, enc.begin() + FileHeader::kSize + rec,
                     enc.begin() + FileHeader::kSize + rec);
    CHECK(throwsType<AuthError>([&] { Vault::decryptBuffer(enc, "pw", 2); }));
}

void testNotAVaultFile() {
    ByteBuffer junk = randomData(5000);
    CHECK(throwsType<FormatError>([&] { Vault::decryptBuffer(junk, "pw", 1); }));
    ByteBuffer tiny(10, 0);
    CHECK(throwsType<FormatError>([&] { Vault::decryptBuffer(tiny, "pw", 1); }));
}

void testMultiThreadMatchesSingleThread() {
    // Same key + header => ciphertext must be byte-identical for every thread count.
    const ByteBuffer plain = randomData(2'000'003, 3);
    FileHeader h = Vault::makeHeader(plain.size(), kChunk, kFastIters);
    auto key = crypto::CryptoManager::deriveKey("pw", h.salt.data(), h.salt.size(), h.iterations);
    const ByteBuffer ref = Vault::encryptBuffer(plain, key, h, 1);
    for (unsigned t : {2u, 3u, 4u, 8u, 16u}) {
        CHECK(Vault::encryptBuffer(plain, key, h, t) == ref);
    }
}

void testThreadCounts() {
    const ByteBuffer plain = randomData(700'000, 5);
    for (unsigned t : {1u, 2u, 4u, 8u}) {
        const ByteBuffer enc = encrypt(plain, "pw", t);
        CHECK(Vault::decryptBuffer(enc, "pw", t) == plain);
        CHECK(Vault::decryptBuffer(enc, "pw", 1) == plain);  // decrypt with a different count
    }
    CHECK(throwsType<VaultError>([&] { encrypt(plain, "pw", 0); }));
}

void testEmptyAndSmallFiles() {
    for (size_t n : {size_t{0}, size_t{1}, size_t{15}, size_t{16}, size_t{17}, size_t{kChunk - 1},
                     size_t{kChunk}, size_t{kChunk + 1}, size_t{3 * kChunk}}) {
        const ByteBuffer plain = randomData(n, static_cast<unsigned>(n + 1));
        for (unsigned t : {1u, 4u}) {
            const ByteBuffer enc = encrypt(plain, "pw", t);
            CHECK(Vault::decryptBuffer(enc, "pw", t) == plain);
        }
    }
    // An empty file still produces an authenticated file; changing it is detected.
    ByteBuffer enc = encrypt(ByteBuffer{}, "pw", 2);
    CHECK(enc.size() == FileHeader::kSize + 16);
    enc.back() ^= 1;
    CHECK(throwsType<AuthError>([&] { Vault::decryptBuffer(enc, "pw", 2); }));
}

void testUniqueNonces() {
    const uint8_t prefix[4] = {9, 8, 7, 6};
    std::set<crypto::Nonce> seen;
    for (uint64_t i = 0; i < 100000; ++i) seen.insert(crypto::CryptoManager::makeNonce(prefix, i));
    CHECK(seen.size() == 100000);
}

void testFreshSaltEachTime() {
    const ByteBuffer plain = randomData(10'000);
    const ByteBuffer a = encrypt(plain, "pw", 1), b = encrypt(plain, "pw", 1);
    CHECK(a != b);  // same file + password still gives different output (random salt/nonce prefix)
    CHECK(!std::equal(a.begin() + 12, a.begin() + 28, b.begin() + 12));  // salts differ
}

void testThreadPool() {
    threading::ThreadPool pool(4);
    std::atomic<long> sum{0};
    std::vector<std::future<void>> fs;
    for (int i = 1; i <= 1000; ++i) fs.push_back(pool.submit([&sum, i] { sum += i; }));
    for (auto& f : fs) f.get();
    CHECK(sum.load() == 500500);

    auto bad = pool.submit([] { throw std::runtime_error("boom"); });
    CHECK(throwsType<std::runtime_error>([&] { bad.get(); }));
    CHECK(throwsType<std::invalid_argument>([] { threading::ThreadPool p(0); }));
}

void testFileManager() {
    CHECK(io::FileManager::chunkCount(0, 100) == 1);
    CHECK(io::FileManager::chunkCount(100, 100) == 1);
    CHECK(io::FileManager::chunkCount(101, 100) == 2);
    CHECK(throwsType<std::runtime_error>([] { io::FileManager::readFile("/definitely/not/here.bin"); }));
    const ByteBuffer d = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    const auto chunks = io::FileManager::splitIntoChunks(d, 4);
    CHECK(chunks.size() == 3 && chunks[2].size() == 1);
}

}  // namespace

int main() {
    run("encrypt -> decrypt returns original", testRoundTrip);
    run("file-level encrypt -> decrypt matches original", testFileRoundTrip);
    run("wrong password fails authentication", testWrongPassword);
    run("wrong password writes no output file", testWrongPasswordWritesNoFile);
    run("modified ciphertext fails authentication", testTamperedCiphertext);
    run("modified authentication tag fails", testTamperedTag);
    run("modified header fails", testTamperedHeader);
    run("truncated / extended file is rejected", testTruncatedAndExtended);
    run("reordered chunks are detected", testReorderedChunks);
    run("non-VaultX input is rejected", testNotAVaultFile);
    run("multithreaded output identical to single-thread", testMultiThreadMatchesSingleThread);
    run("thread counts 1,2,4,8 all work", testThreadCounts);
    run("empty and small files work", testEmptyAndSmallFiles);
    run("every chunk gets a unique nonce", testUniqueNonces);
    run("fresh salt/nonce prefix per encryption", testFreshSaltEachTime);
    run("thread pool runs tasks and propagates errors", testThreadPool);
    run("file manager basics", testFileManager);

    std::cout << "\n" << g_passed << " passed, " << g_failed << " failed\n";
    return g_failed == 0 ? 0 : 1;
}
