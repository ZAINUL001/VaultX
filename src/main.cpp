// VaultX - Secure Multithreaded File Vault (college prototype)
//
// Usage:
//   vaultx                                   interactive menu
//   vaultx encrypt   <in> <out> [--threads N] [--password PW] [--chunk-kb K]
//   vaultx decrypt   <in> <out> [--threads N] [--password PW]
//   vaultx benchmark <in> [--runs N] [--threads-list 1,2,4,8] [--chunk-kb K]
//   vaultx generate  <out> <size_mb>         make a random test file
//   vaultx compare   <fileA> <fileB>         byte-for-byte comparison

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#include "vaultx/benchmark/benchmark.hpp"
#include "vaultx/core/errors.hpp"
#include "vaultx/core/vault.hpp"
#include "vaultx/core/version.hpp"
#include "vaultx/io/file_manager.hpp"

using namespace vaultx;
using io::FileManager;

namespace {

constexpr double kMB = 1024.0 * 1024.0;  // 1 MB = 2^20 bytes throughout VaultX

// ------------------------------------------------------------ small helpers

void printBanner() {
    std::cout << "========================================\n"
              << "              VAULTX\n"
              << "     Secure Multithreaded File Vault\n"
              << "========================================\n";
}

std::string fmtMB(double bytes) {
    std::ostringstream o;
    o << std::fixed << std::setprecision(2) << bytes / kMB << " MB";
    return o.str();
}

std::string fmtSec(double s) {
    std::ostringstream o;
    o << std::fixed << std::setprecision(2) << s << " s";
    return o.str();
}

unsigned defaultThreads() {
    const unsigned hw = std::thread::hardware_concurrency();
    return hw == 0 ? 4 : hw;
}

/// Strips surrounding quotes/whitespace (Windows drag-and-drop adds quotes).
std::string cleanPath(std::string s) {
    auto notSpace = [](unsigned char c) { return !std::isspace(c); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), notSpace));
    s.erase(std::find_if(s.rbegin(), s.rend(), notSpace).base(), s.end());
    if (s.size() >= 2 && ((s.front() == '"' && s.back() == '"') || (s.front() == '\'' && s.back() == '\''))) {
        s = s.substr(1, s.size() - 2);
    }
    return s;
}

bool sameFile(const std::string& a, const std::string& b) {
    std::error_code ec;
    return std::filesystem::exists(a, ec) && std::filesystem::exists(b, ec) &&
           std::filesystem::equivalent(a, b, ec);
}

/// Turns terminal echo on/off. Returns false if the terminal doesn't support it.
bool setEcho(bool enable) {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (h == INVALID_HANDLE_VALUE || !GetConsoleMode(h, &mode)) return false;
    mode = enable ? (mode | ENABLE_ECHO_INPUT) : (mode & ~static_cast<DWORD>(ENABLE_ECHO_INPUT));
    return SetConsoleMode(h, mode) != 0;
#else
    termios t{};
    if (tcgetattr(STDIN_FILENO, &t) != 0) return false;
    if (enable) t.c_lflag |= ECHO; else t.c_lflag &= ~static_cast<tcflag_t>(ECHO);
    return tcsetattr(STDIN_FILENO, TCSANOW, &t) == 0;
#endif
}

std::string promptLine(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string line;
    if (!std::getline(std::cin, line)) throw VaultError("Input closed");
    if (!line.empty() && line.back() == '\r') line.pop_back();
    return line;
}

std::string readPassword(const std::string& prompt) {
    std::cout << prompt << std::flush;
    const bool hidden = setEcho(false);
    std::string pw;
    std::getline(std::cin, pw);
    if (hidden) {
        setEcho(true);
        std::cout << "\n";
    } else {
        std::cout << "   (note: this terminal cannot hide typing)\n";
    }
    if (!pw.empty() && pw.back() == '\r') pw.pop_back();
    return pw;
}

/// Password priority: --password flag, then VAULTX_PASSWORD env var, then prompt.
std::string getPassword(const std::map<std::string, std::string>& opts, bool confirm) {
    if (auto it = opts.find("password"); it != opts.end()) {
        if (it->second.empty()) throw VaultError("Password must not be empty");
        return it->second;
    }
    if (const char* env = std::getenv("VAULTX_PASSWORD"); env && *env) return env;

    const std::string pw = readPassword("Password: ");
    if (pw.empty()) throw VaultError("Password must not be empty");
    if (confirm && readPassword("Confirm password: ") != pw) throw VaultError("Passwords do not match");
    return pw;
}

unsigned long parseUInt(const std::string& text, const std::string& what, unsigned long lo, unsigned long hi) {
    try {
        size_t pos = 0;
        if (!text.empty() && text[0] == '-') throw std::invalid_argument("neg");
        const unsigned long v = std::stoul(text, &pos);
        if (pos != text.size() || v < lo || v > hi) throw std::out_of_range("range");
        return v;
    } catch (...) {
        throw VaultError("Invalid " + what + " '" + text + "' (expected a whole number from " +
                         std::to_string(lo) + " to " + std::to_string(hi) + ")");
    }
}

// ------------------------------------------------------------ arg parsing

struct Args {
    std::vector<std::string> positional;
    std::map<std::string, std::string> options;
};

Args parseArgs(const std::vector<std::string>& argv, const std::vector<std::string>& allowed) {
    Args a;
    for (size_t i = 0; i < argv.size(); ++i) {
        const std::string& s = argv[i];
        if (s.rfind("--", 0) != 0) { a.positional.push_back(s); continue; }

        std::string key = s.substr(2), value;
        if (const auto eq = key.find('='); eq != std::string::npos) {
            value = key.substr(eq + 1);
            key = key.substr(0, eq);
        } else if (i + 1 < argv.size()) {
            value = argv[++i];
        } else {
            throw VaultError("Option --" + key + " needs a value");
        }
        if (std::find(allowed.begin(), allowed.end(), key) == allowed.end()) {
            throw VaultError("Unknown option --" + key);
        }
        a.options[key] = value;
    }
    return a;
}

unsigned threadsFrom(const Args& a) {
    if (auto it = a.options.find("threads"); it != a.options.end())
        return static_cast<unsigned>(parseUInt(it->second, "thread count", 1, core::kMaxThreads));
    return defaultThreads();
}

uint32_t chunkFrom(const Args& a) {
    if (auto it = a.options.find("chunk-kb"); it != a.options.end())
        return static_cast<uint32_t>(parseUInt(it->second, "chunk size (KB)", 1, 65536)) * 1024u;
    return core::kDefaultChunkSize;
}

// ------------------------------------------------------------ commands

/// Prints a line each time a new 20% step is reached. Works in any terminal
/// (no carriage-return tricks). Very fast jobs simply print one 100% line.
core::ProgressFn makeProgressPrinter() {
    auto lastStep = std::make_shared<int>(0);
    return [lastStep](size_t done, size_t total) {
        const int step = total == 0 ? 5 : static_cast<int>(done * 5 / total);
        if (step > *lastStep) {
            *lastStep = step;
            std::cout << "[VaultX]   " << std::setw(3) << step * 20 << "%  (" << done << "/" << total
                      << " chunks)\n" << std::flush;
        }
    };
}

int doEncrypt(const std::string& in, const std::string& out, unsigned threads, uint32_t chunkSize,
              const std::string& password, uint32_t iterations = core::kDefaultIterations) {
    if (!FileManager::exists(in)) throw VaultError("Input file not found: " + in);
    if (sameFile(in, out)) throw VaultError("Input and output must be different files");

    const uint64_t size = FileManager::fileSize(in);
    std::cout << "[VaultX] Encrypting: " << in << "\n"
              << "[VaultX] File size: " << fmtMB(static_cast<double>(size)) << "\n"
              << "[VaultX] Threads: " << threads << "\n"
              << "[VaultX] Chunks: " << FileManager::chunkCount(size, chunkSize) << " x "
              << chunkSize / 1024 << " KB\n"
              << "[VaultX] Deriving key (PBKDF2-HMAC-SHA256, " << iterations << " iterations)...\n"
              << "[VaultX] Processing chunks...\n" << std::flush;

    core::VaultOptions opts;
    opts.threads = threads;
    opts.chunkSize = chunkSize;
    opts.iterations = iterations;
    opts.progress = makeProgressPrinter();
    const core::Timings t = core::Vault::encryptFile(in, out, password, opts);

    const double mbps = (static_cast<double>(t.plainBytes) / kMB) / std::max(t.chunkProcessing, 1e-9);
    std::cout << "[VaultX] Encryption completed.\n\n"
              << "Key derivation:   " << fmtSec(t.keyDerivation) << "\n"
              << "Chunk encryption: " << fmtSec(t.chunkProcessing) << "  (" << threads << " thread"
              << (threads == 1 ? "" : "s") << ")\n"
              << "Total time:       " << fmtSec(t.total) << "  (includes reading and writing the file)\n"
              << "Throughput:       " << std::fixed << std::setprecision(2) << mbps
              << " MB/s  (chunk encryption)\n"
              << "Output:           " << out << "  (" << fmtMB(static_cast<double>(FileManager::fileSize(out))) << ")\n";
    return 0;
}

int doDecrypt(const std::string& in, const std::string& out, unsigned threads, const std::string& password) {
    if (!FileManager::exists(in)) throw VaultError("Input file not found: " + in);
    if (sameFile(in, out)) throw VaultError("Input and output must be different files");

    std::cout << "[VaultX] Decrypting: " << in << "\n"
              << "[VaultX] File size: " << fmtMB(static_cast<double>(FileManager::fileSize(in))) << "\n"
              << "[VaultX] Threads: " << threads << "\n"
              << "[VaultX] Verifying and decrypting chunks...\n" << std::flush;

    core::VaultOptions opts;
    opts.threads = threads;
    opts.progress = makeProgressPrinter();
    const core::Timings t = core::Vault::decryptFile(in, out, password, opts);

    const double mbps = (static_cast<double>(t.plainBytes) / kMB) / std::max(t.chunkProcessing, 1e-9);
    std::cout << "[VaultX] Decryption completed. Authentication OK.\n\n"
              << "Key derivation:   " << fmtSec(t.keyDerivation) << "\n"
              << "Chunk decryption: " << fmtSec(t.chunkProcessing) << "\n"
              << "Total time:       " << fmtSec(t.total) << "\n"
              << "Throughput:       " << std::fixed << std::setprecision(2) << mbps << " MB/s\n"
              << "Output:           " << out << "\n";
    return 0;
}

int doBenchmark(const std::string& in, const std::vector<unsigned>& threadCounts, unsigned runs,
                uint32_t chunkSize) {
    if (!FileManager::exists(in)) throw VaultError("Input file not found: " + in);
    const uint64_t size = FileManager::fileSize(in);

    std::cout << "[VaultX] Benchmarking: " << in << " (" << fmtMB(static_cast<double>(size)) << ")\n"
              << "[VaultX] Thread counts: ";
    for (size_t i = 0; i < threadCounts.size(); ++i) std::cout << (i ? ", " : "") << threadCounts[i];
    std::cout << " | " << runs << " timed run(s) each (interleaved) after a warm-up round\n";
    if (size < 8 * 1024 * 1024) {
        std::cout << "[VaultX] Warning: small file - timings will be noisy. Use 50+ MB "
                     "(try: vaultx generate data/test_files/test_100mb.bin 100)\n";
    }
    std::cout << "[VaultX] Running (this takes a moment)...\n" << std::flush;

    const io::ByteBuffer data = FileManager::readFile(in);
    const auto result = benchmark::Benchmark::run(data, threadCounts, runs, chunkSize);
    benchmark::Benchmark::print(result, std::cout);
    return result.outputsIdentical ? 0 : 3;
}

int doGenerate(const std::string& out, unsigned long sizeMB) {
    std::ofstream f(out, std::ios::binary | std::ios::trunc);
    if (!f) throw VaultError("Cannot create file: " + out);

    std::mt19937_64 rng{std::random_device{}()};
    std::vector<uint64_t> block((1u << 20) / sizeof(uint64_t));
    for (unsigned long i = 0; i < sizeMB; ++i) {
        for (auto& w : block) w = rng();
        f.write(reinterpret_cast<const char*>(block.data()), static_cast<std::streamsize>(block.size() * sizeof(uint64_t)));
    }
    f.flush();
    if (!f) throw VaultError("Failed while writing: " + out);
    std::cout << "[VaultX] Generated " << sizeMB << " MB of random test data: " << out << "\n";
    return 0;
}

int doCompare(const std::string& a, const std::string& b) {
    if (!FileManager::exists(a)) throw VaultError("File not found: " + a);
    if (!FileManager::exists(b)) throw VaultError("File not found: " + b);
    const bool same = FileManager::filesIdentical(a, b);
    std::cout << (same ? "[VaultX] MATCH: files are identical byte-for-byte.\n"
                       : "[VaultX] DIFFERENT: files do not match.\n");
    return same ? 0 : 1;
}

std::vector<unsigned> parseThreadList(const std::string& text) {
    std::vector<unsigned> v;
    std::stringstream ss(text);
    std::string item;
    while (std::getline(ss, item, ',')) {
        v.push_back(static_cast<unsigned>(parseUInt(item, "thread count", 1, core::kMaxThreads)));
    }
    if (v.empty()) throw VaultError("Empty --threads-list");
    return v;
}

void printUsage() {
    std::cout << "VaultX " << version() << " - secure multithreaded file vault\n\n"
              << "Usage:\n"
              << "  vaultx                                  interactive menu\n"
              << "  vaultx encrypt   <in> <out> [--threads N] [--chunk-kb K] [--password PW]\n"
              << "  vaultx decrypt   <in> <out> [--threads N] [--password PW]\n"
              << "  vaultx benchmark <in> [--runs N] [--threads-list 1,2,4,8] [--chunk-kb K]\n"
              << "  vaultx generate  <out> <size_mb>        create a random test file\n"
              << "  vaultx compare   <fileA> <fileB>        check two files are identical\n\n"
              << "Password: --password PW (visible in shell history!), or the VAULTX_PASSWORD\n"
              << "environment variable, or you will be prompted. Default threads: " << defaultThreads()
              << " (this machine).\n";
}

// ------------------------------------------------------------ interactive menu

unsigned askThreads() {
    const std::string t = promptLine("Threads [" + std::to_string(defaultThreads()) + "]: ");
    return t.empty() ? defaultThreads()
                     : static_cast<unsigned>(parseUInt(t, "thread count", 1, core::kMaxThreads));
}

void runMenu() {
    for (;;) {
        std::cout << "\n";
        printBanner();
        std::cout << "\n1. Encrypt File\n2. Decrypt File\n3. Benchmark\n4. Exit\n\n";
        const std::string choice = cleanPath(promptLine("Choose an option: "));
        try {
            if (choice == "1") {
                const std::string in = cleanPath(promptLine("File to encrypt: "));
                std::string out = cleanPath(promptLine("Output file [" + in + ".vx]: "));
                if (out.empty()) out = in + ".vx";
                const unsigned threads = askThreads();
                const std::string pw = getPassword({}, true);
                std::cout << "\n";
                doEncrypt(in, out, threads, core::kDefaultChunkSize, pw);
            } else if (choice == "2") {
                const std::string in = cleanPath(promptLine("File to decrypt (.vx): "));
                const std::string out = cleanPath(promptLine("Output file: "));
                const unsigned threads = askThreads();
                const std::string pw = getPassword({}, false);
                std::cout << "\n";
                doDecrypt(in, out, threads, pw);
            } else if (choice == "3") {
                const std::string in = cleanPath(promptLine("File to benchmark: "));
                std::cout << "\n";
                doBenchmark(in, {1, 2, 4, 8}, 5, core::kDefaultChunkSize);
            } else if (choice == "4" || choice == "q" || choice == "Q") {
                std::cout << "Goodbye.\n";
                return;
            } else {
                std::cout << "Please enter 1, 2, 3 or 4.\n";
            }
        } catch (const VaultError& e) {
            std::cout << "[VaultX] ERROR: " << e.what() << "\n";
        } catch (const std::exception& e) {
            std::cout << "[VaultX] ERROR: " << e.what() << "\n";
        }
    }
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 1) {
            runMenu();
            return 0;
        }
        const std::string cmd = argv[1];
        const std::vector<std::string> rest(argv + 2, argv + argc);

        if (cmd == "encrypt") {
            const Args a = parseArgs(rest, {"threads", "password", "chunk-kb", "iterations"});
            if (a.positional.size() != 2) throw VaultError("Usage: vaultx encrypt <in> <out> [--threads N]");
            uint32_t iters = core::kDefaultIterations;
            if (auto it = a.options.find("iterations"); it != a.options.end())
                iters = static_cast<uint32_t>(parseUInt(it->second, "iterations", 1000, core::FileHeader::kMaxIterations));
            const std::string pw = getPassword(a.options, true);
            return doEncrypt(a.positional[0], a.positional[1], threadsFrom(a), chunkFrom(a), pw, iters);
        }
        if (cmd == "decrypt") {
            const Args a = parseArgs(rest, {"threads", "password"});
            if (a.positional.size() != 2) throw VaultError("Usage: vaultx decrypt <in> <out> [--threads N]");
            const std::string pw = getPassword(a.options, false);
            return doDecrypt(a.positional[0], a.positional[1], threadsFrom(a), pw);
        }
        if (cmd == "benchmark") {
            const Args a = parseArgs(rest, {"runs", "threads-list", "chunk-kb"});
            if (a.positional.size() != 1) throw VaultError("Usage: vaultx benchmark <in> [--runs N]");
            const unsigned runs = a.options.count("runs")
                                      ? static_cast<unsigned>(parseUInt(a.options.at("runs"), "runs", 1, 100)) : 5;
            const auto list = a.options.count("threads-list") ? parseThreadList(a.options.at("threads-list"))
                                                              : std::vector<unsigned>{1, 2, 4, 8};
            return doBenchmark(a.positional[0], list, runs, chunkFrom(a));
        }
        if (cmd == "generate") {
            const Args a = parseArgs(rest, {});
            if (a.positional.size() != 2) throw VaultError("Usage: vaultx generate <out> <size_mb>");
            return doGenerate(a.positional[0], parseUInt(a.positional[1], "size (MB)", 1, 8192));
        }
        if (cmd == "compare") {
            const Args a = parseArgs(rest, {});
            if (a.positional.size() != 2) throw VaultError("Usage: vaultx compare <fileA> <fileB>");
            return doCompare(a.positional[0], a.positional[1]);
        }
        if (cmd == "help" || cmd == "--help" || cmd == "-h") {
            printUsage();
            return 0;
        }
        std::cerr << "Unknown command '" << cmd << "'\n\n";
        printUsage();
        return 1;
    } catch (const AuthError& e) {
        std::cerr << "[VaultX] ERROR: " << e.what() << "\n";
        return 2;
    } catch (const FormatError& e) {
        std::cerr << "[VaultX] ERROR: " << e.what() << "\n";
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "[VaultX] ERROR: " << e.what() << "\n";
        return 1;
    }
}
