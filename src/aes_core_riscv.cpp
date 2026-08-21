#include <array>
#include <cstring>
#include <stdexcept>

#include "internal.hpp"

// AES forward cipher using the RV64 Zkne scalar crypto extension
// (aes64es/aes64esm/aes64ks1i/aes64ks2). Only ever reached when
// cpu::has_hw_aes() returned true (see aes_core_hw.cpp's dispatch), so it's
// safe to assume the instructions exist here.
//
// This translation unit is compiled with an -march string enabling zkne (see
// CMakeLists.txt) even though the rest of the binary is not, so the crypto
// instructions this file emits don't leak into code paths that must run on
// non-crypto-capable RISC-V hardware — the same isolation rationale as
// aes_core_ni.cpp's -maes scoping on x86 and aes_core_arm.cpp's
// -march=...+crypto scoping on ARM.
//
// Unlike ARM's AESE/AESMC, RV64's scalar AES instructions DO include
// dedicated key-schedule-assist instructions (aes64ks1i/aes64ks2), the same
// role x86's _mm_aeskeygenassist_si128 plays — so, like aes_core_ni.cpp, this
// file computes its own hand-rolled schedule rather than sharing the
// portable aes_key_schedule.hpp template ARM uses for lack of any such
// instruction.
//
// The 128-bit AES state/round-key is represented as a pair of 64-bit
// registers (lo = bytes 0..7, hi = bytes 8..15), the layout the ISA's AES
// instructions are defined over (RISC-V is little-endian, so a raw 8-byte
// load from the block reproduces this layout with no byte-swapping, the same
// as x86-64/AArch64's 128-bit vector loads). This file's instruction
// sequences (round loop, AES-128/256 key schedules) follow OpenSSL's
// rv64i_zkne_encrypt/rv64i_zkne_set_encrypt_key reference implementation
// (crypto/aes/asm/aes-riscv64-zkn.pl), the canonical worked example of this
// extension.
//
// The instructions themselves are emitted via inline asm (the raw mnemonics
// aes64es/aes64esm/aes64ks1i/aes64ks2), not <riscv_crypto.h>'s C intrinsics:
// that header is a comparatively recent GCC/Clang addition (present in a
// current Homebrew GCC 16, absent from Ubuntu 24.04's g++-riscv64-linux-gnu
// package, GCC 13.3 — confirmed against this project's own qemu-riscv64 CI
// leg) and there's no reason to require it just to reach four instructions
// binutils has recognized as plain mnemonics since before GCC added the
// intrinsics. The `-march=rv64gc_zkne` flag scoped to this file
// (CMakeLists.txt) is what actually authorizes the assembler to accept
// them; the same flag would be needed either way.

#if defined(__riscv) && __riscv_xlen == 64
#define AESLIB_HAVE_RISCV_CRYPTO_INTRINSICS 1
#else
#define AESLIB_HAVE_RISCV_CRYPTO_INTRINSICS 0
#endif

namespace aeslib::detail {

#if AESLIB_HAVE_RISCV_CRYPTO_INTRINSICS

namespace {

// Thin inline-asm wrappers around the four Zkne instructions this backend
// needs (see the file-level comment for why these aren't <riscv_crypto.h>
// intrinsics). `rnum` must be a genuine assembler immediate (0x0..0xA per
// the ISA), which is why every call site below passes a literal, never a
// runtime variable.
inline std::uint64_t riscv_aes64esm(std::uint64_t rs1, std::uint64_t rs2) {
    std::uint64_t rd;
    asm("aes64esm %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2));
    return rd;
}

inline std::uint64_t riscv_aes64es(std::uint64_t rs1, std::uint64_t rs2) {
    std::uint64_t rd;
    asm("aes64es %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2));
    return rd;
}

inline std::uint64_t riscv_aes64ks2(std::uint64_t rs1, std::uint64_t rs2) {
    std::uint64_t rd;
    asm("aes64ks2 %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2));
    return rd;
}

inline std::uint64_t riscv_aes64ks1i(std::uint64_t rs1, int rnum) {
    std::uint64_t rd;
    asm("aes64ks1i %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(rnum));
    return rd;
}

struct State {
    std::uint64_t lo; // block bytes 0..7
    std::uint64_t hi; // block bytes 8..15
};

State load_state(const Block& block) {
    State s{};
    std::memcpy(&s.lo, block.data(), 8);
    std::memcpy(&s.hi, block.data() + 8, 8);
    return s;
}

Block store_state(const State& s) {
    Block out{};
    std::memcpy(out.data(), &s.lo, 8);
    std::memcpy(out.data() + 8, &s.hi, 8);
    return out;
}

State xor_state(const State& a, const State& b) { return State{a.lo ^ b.lo, a.hi ^ b.hi}; }

// One AES-256/128 non-final round: SubBytes+ShiftRows+MixColumns on both
// halves (aes64esm), reversed operand order between the two halves per the
// ISA's state layout — mirrors OpenSSL's `aes64esm Q2,Q0,Q1` / `aes64esm
// Q3,Q1,Q0` pair.
State round_middle(const State& s) {
    return State{riscv_aes64esm(s.lo, s.hi), riscv_aes64esm(s.hi, s.lo)};
}

// The final round: same as round_middle but SubBytes+ShiftRows only (no
// MixColumns), matching every other backend's final-round treatment.
State round_final(const State& s) {
    return State{riscv_aes64es(s.lo, s.hi), riscv_aes64es(s.hi, s.lo)};
}

// Same rationale as the other backends' wipe_schedule(): the round-key
// schedule is a direct, reversible function of the raw key, so it's zeroed
// with a volatile byte-level loop before going out of scope.
template <std::size_t N>
void wipe_schedule(std::array<State, N>& schedule) noexcept {
    auto* bytes = reinterpret_cast<volatile unsigned char*>(schedule.data());
    for (std::size_t i = 0; i < sizeof(State) * N; ++i) bytes[i] = 0;
}

// AES-256 key schedule (FIPS-197 Nk=8, Nr=14, 15 round keys), built from
// aes64ks1i/aes64ks2 following OpenSSL's ke256enc: the rnum=0xA step (fixed,
// not a loop variable) reproduces FIPS-197's "extra SubWord, no RotWord"
// step required for Nk>6 at schedule index i%Nk==4 — aes64ks1i's rnum
// argument must be a compile-time immediate, so the loop is unrolled.
std::array<State, 15> expand_key256_riscv(const SecretKey& key) {
    const auto& kb = key_bytes(key);
    std::uint64_t t0, t1, t2, t3;
    std::memcpy(&t0, kb.data(), 8);
    std::memcpy(&t1, kb.data() + 8, 8);
    std::memcpy(&t2, kb.data() + 16, 8);
    std::memcpy(&t3, kb.data() + 24, 8);

    std::array<State, 15> rk{};
    rk[0] = State{t0, t1};
    rk[1] = State{t2, t3};

#define AESLIB_KS256_STEP(rnum, idx)                       \
    do {                                                   \
        std::uint64_t t4 = riscv_aes64ks1i(t3, rnum);    \
        t0 = riscv_aes64ks2(t4, t0);                     \
        t1 = riscv_aes64ks2(t0, t1);                     \
        rk[idx] = State{t0, t1};                           \
        if ((rnum) != 6) {                                 \
            t4 = riscv_aes64ks1i(t1, 0xA);                \
            t2 = riscv_aes64ks2(t4, t2);                 \
            t3 = riscv_aes64ks2(t2, t3);                 \
            rk[(idx) + 1] = State{t2, t3};                 \
        }                                                  \
    } while (false)

    AESLIB_KS256_STEP(0, 2);
    AESLIB_KS256_STEP(1, 4);
    AESLIB_KS256_STEP(2, 6);
    AESLIB_KS256_STEP(3, 8);
    AESLIB_KS256_STEP(4, 10);
    AESLIB_KS256_STEP(5, 12);
    AESLIB_KS256_STEP(6, 14);

#undef AESLIB_KS256_STEP

    return rk;
}

// AES-128 key schedule (FIPS-197 Nk=4, Nr=10, 11 round keys), following
// OpenSSL's ke128enc.
std::array<State, 11> expand_key128_riscv(const SecretKey& key) {
    const auto& kb = key_bytes(key);
    std::uint64_t t0, t1;
    std::memcpy(&t0, kb.data(), 8);
    std::memcpy(&t1, kb.data() + 8, 8);

    std::array<State, 11> rk{};
    rk[0] = State{t0, t1};

#define AESLIB_KS128_STEP(rnum, idx)                        \
    do {                                                    \
        std::uint64_t t2 = riscv_aes64ks1i(t1, rnum);     \
        t0 = riscv_aes64ks2(t2, t0);                      \
        t1 = riscv_aes64ks2(t0, t1);                      \
        rk[idx] = State{t0, t1};                            \
    } while (false)

    AESLIB_KS128_STEP(0, 1);
    AESLIB_KS128_STEP(1, 2);
    AESLIB_KS128_STEP(2, 3);
    AESLIB_KS128_STEP(3, 4);
    AESLIB_KS128_STEP(4, 5);
    AESLIB_KS128_STEP(5, 6);
    AESLIB_KS128_STEP(6, 7);
    AESLIB_KS128_STEP(7, 8);
    AESLIB_KS128_STEP(8, 9);
    AESLIB_KS128_STEP(9, 10);

#undef AESLIB_KS128_STEP

    return rk;
}

template <std::size_t N>
Block encrypt_with_schedule(std::array<State, N>& rk, const Block& block) {
    constexpr std::size_t kNr = N - 1;
    State state = xor_state(load_state(block), rk[0]);
    for (std::size_t round = 1; round < kNr; ++round) {
        state = xor_state(round_middle(state), rk[round]);
    }
    state = xor_state(round_final(state), rk[kNr]);
    wipe_schedule(rk);
    return store_state(state);
}

} // namespace

Block aes256_encrypt_block_riscv(const SecretKey& key, const Block& block) {
    auto rk = expand_key256_riscv(key);
    return encrypt_with_schedule(rk, block);
}

Block aes128_encrypt_block_riscv(const SecretKey& key, const Block& block) {
    auto rk = expand_key128_riscv(key);
    return encrypt_with_schedule(rk, block);
}

#else

Block aes256_encrypt_block_riscv(const SecretKey&, const Block&) {
    throw std::logic_error("aes256_encrypt_block_riscv called on a non-RV64 build");
}

Block aes128_encrypt_block_riscv(const SecretKey&, const Block&) {
    throw std::logic_error("aes128_encrypt_block_riscv called on a non-RV64 build");
}

#endif

} // namespace aeslib::detail
