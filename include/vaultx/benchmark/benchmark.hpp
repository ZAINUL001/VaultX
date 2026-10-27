#pragma once

#include <cstdint>
#include <ostream>
#include <vector>

#include "vaultx/io/file_manager.hpp"

namespace vaultx::benchmark {

struct BenchmarkRow {
    unsigned threads = 0;
    double seconds = 0;     // median over runs
    double mbPerSec = 0;    // plain bytes / 2^20 / seconds
    double speedup = 0;     // time(1 thread) / time(this row)
};

struct BenchmarkResult {
    std::vector<BenchmarkRow> rows;
    uint64_t bytes = 0;
    uint64_t chunks = 0;
    unsigned runs = 0;
    unsigned hardwareThreads = 0;
    bool outputsIdentical = false;  // ciphertext byte-identical for every thread count
};

/// Encrypts the SAME in-memory data with different thread counts and measures
/// real wall-clock time. Nothing here is hard-coded: every figure is computed
/// from steady_clock measurements taken during this run.
///
/// What is timed: the parallel chunk-encryption phase only (thread pool start-up
/// through all chunks finished). File I/O and the one-off PBKDF2 key derivation
/// are excluded so the table isolates the effect of multithreading.
class Benchmark {
public:
    static BenchmarkResult run(const io::ByteBuffer& data, const std::vector<unsigned>& threadCounts,
                               unsigned runs, uint32_t chunkSize);

    static void print(const BenchmarkResult& r, std::ostream& os);
};

}  // namespace vaultx::benchmark
