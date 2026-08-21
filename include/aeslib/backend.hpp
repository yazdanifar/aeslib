#pragma once

namespace aeslib {

// Which AES block-cipher implementation is being used. Exposed so tests and
// diagnostics can observe the dispatch decision; ordinary callers of
// Aes256Ctr never need to look at this.
enum class Backend {
    Software,  // Portable, no CPU-specific instructions.
    Hardware,  // AES-NI on amd64, AArch64 Crypto Extensions on arm64, RV64
               // Zkne on riscv64.
};

// Returns the backend Aes256Ctr will actually use on this machine, decided
// once at first use via a runtime CPU-capability check (see cpu_detect.cpp)
// — never baked in at compile time, so the same binary picks the right path
// on any host of a supported architecture.
Backend active_backend();

} // namespace aeslib
