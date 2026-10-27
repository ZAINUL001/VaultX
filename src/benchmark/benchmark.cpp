#include "vaultx/benchmark/benchmark.hpp"

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <thread>

#include "vaultx/core/vault.hpp"
#include "vaultx/crypto/crypto_manager.hpp"

namespace vaultx::benchmark {

namespace {
using Clock = std::chrono::steady_clock;

double median(std::vector<double> v) {
    std::sort(v.begin(), v.end());
    const size_t n = v.size();
    return n % 2 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2.0;
}
}  // namespace

BenchmarkResult Benchmark::run(const io::ByteBuffer& data, const std::vector<unsigned>& threadCounts,
                               unsigned runs, uint32_t chunkSize) {
    if (threadCounts.empty()) throw std::invalid_argument("No thread counts given");
    if (runs == 0) runs = 1;

    BenchmarkResult result;
    result.bytes = data.size();
    result.runs = runs;
    result.hardwareThreads = std::thread::hardware_concurrency();

    // One header + key for the whole benchmark => identical inputs for every run.
    // (Low iteration count: key derivation is not part of what we measure.)
    const core::FileHeader header = core::Vault::makeHeader(data.size(), chunkSize, 1000);
    result.chunks = header.chunkCount;
    const crypto::SecureKey key = crypto::CryptoManager::deriveKey(
        "benchmark", header.salt.data(), header.salt.size(), header.iterations);

    // Output buffers are allocated ONCE, outside the timed region, so the numbers
    // reflect encryption work and not memory allocation / zero-filling.
    io::ByteBuffer out(static_cast<size_t>(header.totalFileSize()));
    io::ByteBuffer reference;
    bool identical = true;

    // Warm-up round (not timed) for EVERY setting: touches the output pages, warms
    // caches and lets the CPU reach its working clock speed before anything is measured.
    for (unsigned threads : threadCounts) {
        core::Vault::encryptInto(data, key, header, threads, out.data());
        if (reference.empty()) reference = out;
        identical = identical && (out == reference);
    }

    // Timed rounds are INTERLEAVED (1,2,4,8, 1,2,4,8, ...) instead of finishing all
    // runs of one setting before the next. This stops slow drift (CPU clock changes,
    // thermal throttling, background load) from favouring or penalising one setting.
    std::vector<std::vector<double>> times(threadCounts.size());
    for (unsigned r = 0; r < runs; ++r) {
        for (size_t i = 0; i < threadCounts.size(); ++i) {
            const auto t0 = Clock::now();
            core::Vault::encryptInto(data, key, header, threadCounts[i], out.data());
            times[i].push_back(std::chrono::duration<double>(Clock::now() - t0).count());
        }
    }
    identical = identical && (out == reference);

    for (size_t i = 0; i < threadCounts.size(); ++i) {
        BenchmarkRow row;
        row.threads = threadCounts[i];
        row.seconds = median(times[i]);
        row.mbPerSec = (static_cast<double>(data.size()) / (1024.0 * 1024.0)) / row.seconds;
        result.rows.push_back(row);
    }

    // Speedup is relative to the 1-thread row (or the first row if 1 wasn't requested).
    double base = result.rows.front().seconds;
    for (const auto& r : result.rows) if (r.threads == 1) base = r.seconds;
    for (auto& r : result.rows) r.speedup = base / r.seconds;

    result.outputsIdentical = identical;
    return result;
}

void Benchmark::print(const BenchmarkResult& r, std::ostream& os) {
    os << "\n[VaultX] Benchmark results\n";
    os << "  Data: " << std::fixed << std::setprecision(2)
       << static_cast<double>(r.bytes) / (1024.0 * 1024.0) << " MB, " << r.chunks
       << " chunks | Runs per setting: " << r.runs << " (median) | CPU threads available: "
       << r.hardwareThreads << "\n\n";
    os << "  " << std::left << std::setw(9) << "Threads" << std::setw(12) << "Time"
       << std::setw(16) << "Throughput" << "Speedup\n";
    os << "  " << std::string(46, '-') << "\n";
    for (const auto& row : r.rows) {
        std::ostringstream t, tp, sp;
        t << std::fixed << std::setprecision(3) << row.seconds << " s";
        tp << std::fixed << std::setprecision(1) << row.mbPerSec << " MB/s";
        sp << std::fixed << std::setprecision(2) << row.speedup << "x";
        os << "  " << std::left << std::setw(9) << row.threads << std::setw(12) << t.str()
           << std::setw(16) << tp.str() << sp.str() << "\n";
    }
    os << "\n  Output identical for every thread count: "
       << (r.outputsIdentical ? "YES (parallel result verified)" : "NO - BUG!") << "\n";
    os << "  Timed: parallel chunk encryption only (excludes file I/O and key derivation). 1 MB = 2^20 bytes.\n";
    if (r.hardwareThreads > 0) {
        os << "  Note: speedup cannot exceed the number of CPU cores/threads (" << r.hardwareThreads << " here).\n";
        for (const auto& row : r.rows) {
            if (row.speedup > r.hardwareThreads * 1.15) {
                os << "  WARNING: " << row.threads << "-thread speedup (" << std::fixed << std::setprecision(2)
                   << row.speedup << "x) exceeds the CPU threads available - this is measurement noise.\n"
                   << "           Use a larger file (500+ MB) and/or more --runs for a trustworthy result.\n";
                break;
            }
        }
    }
}

}  // namespace vaultx::benchmark
