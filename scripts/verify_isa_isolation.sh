#!/usr/bin/env bash
# Verifies, by disassembling the built object files, that architecture-
# specific AES instructions only ever appear in the one translation unit
# CMakeLists.txt scopes them to (see the set_source_files_properties(...
# COMPILE_OPTIONS "-maes"/"-march=...+crypto"/"-march=...zkne") calls there).
#
# This is what actually makes runtime dispatch (cpu_detect.cpp) sound: if an
# AES-NI/Crypto-Extensions/Zkne opcode leaked into any other object file, the
# compiler could in principle place it on a code path reachable *before*
# cpu::has_hw_aes() has confirmed the host supports it, and a binary built on
# a capable machine could then SIGILL on one that isn't — silently breaking
# the "same binary, both machines" guarantee Challenge.tex 2.2 requires.
# Nothing in the build enforces that by itself; this script is the check.
#
# Usage: scripts/verify_isa_isolation.sh [build-dir]   (default: build)
set -euo pipefail

build_dir="${1:-build}"
obj_dir="$build_dir/CMakeFiles/aeslib.dir/src"

if [[ ! -d "$obj_dir" ]]; then
    echo "error: $obj_dir not found — configure and build aeslib first (see README.md)" >&2
    exit 2
fi

if command -v objdump >/dev/null 2>&1; then
    disas() { objdump -d "$1" 2>/dev/null; }
elif command -v llvm-objdump >/dev/null 2>&1; then
    disas() { llvm-objdump -d "$1" 2>/dev/null; }
elif command -v xcrun >/dev/null 2>&1 && xcrun --find llvm-objdump >/dev/null 2>&1; then
    disas() { xcrun llvm-objdump -d "$1" 2>/dev/null; }
else
    echo "error: no objdump/llvm-objdump found on PATH" >&2
    exit 2
fi

# guarded_file:opcode_regex — one pair per ISA extension scoped in CMakeLists.txt.
checks=(
    "aes_core_ni.cpp.o:\b(aesenc|aesenclast|aesdec|aesdeclast|aesimc|aeskeygenassist)\b"
    "aes_core_arm.cpp.o:\b(aese|aesd|aesmc|aesimc)(\.16b)?\b"
    "aes_core_riscv.cpp.o:\b(aes(32|64)(es|esm|ds|dsm|im)i?|aes64ks1i|aes64ks2)\b"
)

status=0
for check in "${checks[@]}"; do
    guarded_file="${check%%:*}"
    pattern="${check#*:}"

    for obj in "$obj_dir"/*.cpp.o; do
        name="$(basename "$obj")"
        matches="$(disas "$obj" | grep -iE "$pattern" || true)"
        [[ -z "$matches" ]] && continue

        if [[ "$name" == "$guarded_file" ]]; then
            count="$(echo "$matches" | wc -l | tr -d ' ')"
            echo "ok: $name contains $count matching instruction(s), as expected"
        else
            echo "FAIL: $name contains instructions matching '$pattern', expected only in $guarded_file:"
            echo "$matches" | sed 's/^/    /'
            status=1
        fi
    done
done

if [[ $status -eq 0 ]]; then
    echo "PASS: architecture-specific AES instructions are isolated to their guarded translation units."
else
    echo "FAIL: architecture-specific AES instructions leaked outside their guarded translation unit." >&2
fi
exit $status
