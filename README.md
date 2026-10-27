# VaultX

**Secure Multithreaded File Vault** - a C++20 command-line tool that encrypts and decrypts files with
AES-256-GCM (OpenSSL) and uses a custom thread pool to process file chunks in parallel.

> **This is a college-project prototype.** It has not been security-audited. Do not use it to protect
> data you cannot afford to lose.

## Problem statement
Encrypting a large file on one thread leaves most of a modern CPU idle. Many simple tools also encrypt
*without authentication*, so a corrupted or tampered file can silently "decrypt" into garbage.

## Objective
1. Encrypt/decrypt files securely using a trusted, authenticated algorithm (no home-made crypto).
2. Split files into independent chunks and process them on N worker threads.
3. Measure the real effect of multithreading with a benchmark (time, throughput, speedup).
4. Detect wrong passwords and modified files.

## Technologies
C++20, OpenSSL (EVP API: AES-256-GCM, PBKDF2-HMAC-SHA256, secure RNG), CMake, standard `<thread>`,
`<mutex>`, `<condition_variable>`, `<future>`.

## Architecture
```
main.cpp (CLI / menu)
   |
   v
Vault ----------------- reads file (FileManager), derives key (CryptoManager),
   |                    builds header, runs the parallel stage, writes output
   v
ThreadPool  <--- task queue (mutex + condition_variable)
   |-- Worker 1 --> EncryptTask (chunk i)
   |-- Worker 2 --> EncryptTask (chunk j)
   |-- Worker N --> ...
   v
Encrypted chunks written into their own slice of the output buffer --> .vx file
```

| Module | Class / file | Responsibility |
|---|---|---|
| `io` | `FileManager` | read/write files, file size, chunk arithmetic, file comparison |
| `crypto` | `CryptoManager` | AES-256-GCM encrypt/decrypt, PBKDF2 key derivation, random bytes, nonce construction |
| `threading` | `ThreadPool` | worker threads, task queue, synchronisation, futures |
| `core` | `EncryptTask`, `DecryptTask` | one chunk = one task |
| `core` | `Vault`, `FileHeader` | file format, orchestration of the whole pipeline |
| `benchmark` | `Benchmark` | runs the same encryption at several thread counts, measures and tabulates |

## How multithreading is used
1. The file is read into memory and divided into chunks (default 1 MiB).
2. Each chunk becomes an `EncryptTask` pushed onto the pool's queue.
3. Worker threads take tasks from the queue and encrypt them with AES-256-GCM.
4. **No locks on the data:** the output layout is known in advance (chunk *i* starts at
   `header + i * (chunk + 16)`), so each worker writes only to its own slice. The only shared mutable
   structure is the task queue, which is mutex-protected. The key is shared read-only, and every
   OpenSSL call uses its own cipher context.
5. The main thread waits on the futures (and prints progress), then writes the file.

Decryption is parallelised the same way, since each chunk has its own authentication tag.

## Security design
* **AES-256-GCM** (authenticated encryption) from OpenSSL. No custom cryptography.
* **Password -> key:** PBKDF2-HMAC-SHA256, 600,000 iterations, random 16-byte salt per file.
  Passwords are never written to the file.
* **Nonces:** each chunk uses a 12-byte nonce = 4-byte random per-file prefix + 8-byte chunk index.
  No two chunks of a file share a nonce, regardless of which thread processes them. A fresh salt per
  file also gives a fresh key per file.
* **Chunk binding:** the 52-byte header, the chunk index and a "final chunk" flag are authenticated
  as associated data. Reordering chunks, truncating or extending the file, or editing the header is
  detected.
* **Empty files** are stored as one empty authenticated chunk.
* **No output on failure:** if any chunk fails authentication, nothing is written to disk.
* GCM cannot tell a wrong password from a tampered file; both give the same error.

### `.vx` file format (little-endian)
| Offset | Size | Field |
|---|---|---|
| 0 | 6 | magic `VAULTX` |
| 6 | 1 | version (1) |
| 7 | 1 | reserved |
| 8 | 4 | PBKDF2 iterations |
| 12 | 16 | salt |
| 28 | 4 | nonce prefix |
| 32 | 4 | chunk size |
| 36 | 8 | original size |
| 44 | 8 | chunk count |
| 52 | ... | chunks: ciphertext + 16-byte tag, repeated |

## Build
Requirements: C++20 compiler (GCC 10+), CMake 3.16+, OpenSSL development files.

**Linux:** `sudo apt install build-essential cmake libssl-dev`

**Windows (MSYS2 - recommended):** install MSYS2, open the **"MSYS2 MINGW64"** terminal, then
```
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-openssl
```
Use a compiler and OpenSSL built for the *same* toolchain (a Visual Studio-built OpenSSL will not link
with MinGW g++). Run VaultX from the MSYS2 MINGW64 terminal so the OpenSSL DLLs are found.

```
cmake -S . -B build -G "MinGW Makefiles"     # Linux: cmake -S . -B build
cmake --build build -j
```

## Run
```
./build/bin/vaultx                                   # interactive menu
./build/bin/vaultx encrypt input.txt output.vx --threads 4
./build/bin/vaultx decrypt output.vx restored.txt
./build/bin/vaultx benchmark input.txt
./build/bin/vaultx generate data/test_files/big.bin 500    # make a 500 MB random test file
./build/bin/vaultx compare input.txt restored.txt          # byte-for-byte check
```
Options: `--threads N` (1-256, default = this machine's thread count), `--chunk-kb K`,
`--password PW` (insecure: visible in shell history; otherwise the `VAULTX_PASSWORD` environment
variable or an interactive prompt is used), benchmark: `--runs N`, `--threads-list 1,2,4,8`.
Exit codes: 0 success, 1 usage/IO error, 2 wrong password / modified / not a VaultX file.

### One-command demo
```
bash benchmarks/demo.sh 500
```
Generates a test file, encrypts with 1/2/4/8 threads, runs the benchmark, decrypts, verifies the
restored file matches, then shows a wrong-password and a tampered-file failure.

## Tests
```
cmake --build build && ctest --test-dir build --output-on-failure
```
17 tests: round trip, wrong password, modified data/tag/header, truncated/extended files, reordered
chunks, non-VaultX input, multi-thread output identical to single-thread, thread counts 1/2/4/8,
empty and tiny files, unique nonces, thread pool behaviour. The suite was also run clean under
ThreadSanitizer and AddressSanitizer/UBSan on Linux.

## Benchmark methodology
* Same data, same key and same header for every thread count.
* **Timed:** the parallel chunk-encryption phase only (`steady_clock`, from creating the pool until all
  chunks are done). **Not timed:** file I/O, PBKDF2 key derivation, buffer allocation.
* One untimed warm-up round, then N timed rounds *interleaved* across thread counts
  (1,2,4,8,1,2,4,8...) so CPU frequency drift does not favour one setting. Median is reported.
* `Throughput = size / 2^20 / time` (MB/s). `Speedup = time(1 thread) / time(N threads)`.
* The ciphertext from every thread count is compared byte-for-byte to prove parallel output is correct.
* All values come from the actual run; nothing is hard-coded. Report your CPU model and core count
  together with results, because speedup is bounded by the number of cores.
* **Use a large file (500 MB+).** Modern CPUs have hardware AES (AES-NI) and encrypt at several GB/s per
  core, so a small file finishes in a few milliseconds and the timings are mostly noise. The tool warns
  when a result is larger than the available hardware could deliver.

## Limitations
* Prototype; no security audit.
* The whole file is held in memory (input + output, and 3x during benchmark), so very large files are
  limited by RAM.
* Speedup is limited by core count, memory bandwidth, and the serial parts (disk I/O, key derivation).
  With AES-NI, real-world encryption of a file on disk is usually limited by the disk, not the CPU.
* The password prompt cannot hide typing in every terminal (e.g. MSYS2's mintty).
* File name, permissions and timestamps are not preserved.
* Tested on Linux (GCC 13, OpenSSL 3.0) on a 1-core machine, so multi-core speedup must be confirmed
  on your own hardware.

## Future improvements
Streaming / memory-mapped I/O for constant memory use; overlap disk I/O with encryption; Argon2 or
scrypt key derivation; key-file support; directory encryption and compression; per-chunk progress bar;
automatic thread-count selection; work-stealing pool and chunk-size tuning.
