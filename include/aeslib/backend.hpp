#pragma once

namespace aeslib {

// Which AES block-cipher implementation is being used. Exposed so tests and
// diagnostics can observe the dispatch decision; ordinary callers of
// Aes256Ctr never need to look at this.
enum class Backend {
    Software,  // Portable, no CPU-specific instructions.
    Hardware,  // AES-NI intrinsics (amd64 only).
};

// Returns the backend Aes256Ctr will actually use on this machine, decided
// once at first use via a runtime CPUID check (see cpu_detect.cpp) — never
// baked in at compile time, so the same binary picks the right path on any
// amd64 host.
Backend active_backend();

} // namespace aeslib
