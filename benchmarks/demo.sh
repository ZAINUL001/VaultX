#!/usr/bin/env bash
# VaultX demo: the full workflow for a presentation.
# Run from the project root, inside the MSYS2 MINGW64 terminal (Windows) or any Linux/macOS shell:
#     bash benchmarks/demo.sh          # 300 MB test file
#     bash benchmarks/demo.sh 800      # bigger file = clearer speedup (needs ~3x that much RAM)
set -e

SIZE_MB="${1:-300}"
BIN="${BIN:-./build/bin/vaultx}"
[ -x "$BIN" ] || [ -x "$BIN.exe" ] || { echo "Build first:  cmake -S . -B build && cmake --build build -j"; exit 1; }

DIR="data/test_files"; mkdir -p "$DIR"
SRC="$DIR/demo_input.bin"
export VAULTX_PASSWORD="demo-password-123"   # demo only; normally you are prompted

step() { echo; echo "================ STEP $1: $2 ================"; }

step 1 "Generate a ${SIZE_MB} MB test file"
"$BIN" generate "$SRC" "$SIZE_MB"

for T in 1 2 4 8; do
  step "2-5" "Encrypt with $T thread(s)"
  "$BIN" encrypt "$SRC" "$DIR/demo_t$T.vx" --threads "$T"
done

step 6 "Benchmark (real timings, 1/2/4/8 threads)"
"$BIN" benchmark "$SRC"

step 7 "Decrypt the encrypted file"
"$BIN" decrypt "$DIR/demo_t4.vx" "$DIR/demo_restored.bin" --threads 4

step 8 "Verify the restored file matches the original"
"$BIN" compare "$SRC" "$DIR/demo_restored.bin"

step 9 "Security checks: wrong password, then a tampered file"
set +e
"$BIN" decrypt "$DIR/demo_t4.vx" "$DIR/should_not_exist.bin" --password "wrong-password"
echo "(exit code $? - decryption refused, no output file written)"
cp "$DIR/demo_t4.vx" "$DIR/demo_tampered.vx"
printf '\xff' | dd of="$DIR/demo_tampered.vx" bs=1 seek=1000000 conv=notrunc 2>/dev/null
"$BIN" decrypt "$DIR/demo_tampered.vx" "$DIR/should_not_exist.bin" --threads 4
echo "(exit code $? - one modified byte was detected)"

echo; echo "Cleaning up large demo files..."
rm -f "$DIR"/demo_*.bin "$DIR"/demo_*.vx
echo "Done."
