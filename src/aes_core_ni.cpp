#include <array>
#include <stdexcept>

#include "internal.hpp"

// AES forward cipher using amd64 AES-NI intrinsics. Only ever reached when
// cpu::has_hw_aes() returned true (see aes_core_hw.cpp's dispatch), so it's
// safe to assume the instructions exist here.
//
// This translation unit is compiled with -maes (see CMakeLists.txt) even
// though the rest of the binary is not, so the AES-NI instructions this file
// emits don't leak into code paths that must run on non-AES-NI hardware.

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#define AESLIB_HAVE_X86_INTRINSICS 1
#include <immintrin.h>
#else
#define AESLIB_HAVE_X86_INTRINSICS 0
#endif

namespace aeslib::detail {

#if AESLIB_HAVE_X86_INTRINSICS

// __m128i carries a vector_size/alignment attribute that GCC drops when it's
// used as std::array's template argument, and then warns about the attribute
// it itself ignored ([-Wignored-attributes]) — a known GCC quirk with no
// effect on the actual alignment/codegen here, so silenced for this file
// rather than worked around with a wrapper type.
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wignored-attributes"
#endif

namespace {

constexpr int kNumRoundKeys = 15; // AES-256: 14 rounds + 1 initial whitening key

// One step of the standard AES-256 AES-NI key-expansion routine (see Intel's
// "AES-NI Sample Library" white paper). Produces the next even-indexed
// round key from the running temp1/temp2 state.
void key_expansion_step_even(__m128i* temp1, __m128i temp2) {
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    __m128i temp4 = _mm_slli_si128(*temp1, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    *temp1 = _mm_xor_si128(*temp1, temp2);
}

// Produces the next odd-indexed round key (the "SubWord without RotWord"
// half of the Nk=8 key schedule).
void key_expansion_step_odd(const __m128i& temp1, __m128i* temp3) {
    __m128i temp4 = _mm_aeskeygenassist_si128(temp1, 0x0);
    __m128i temp2 = _mm_shuffle_epi32(temp4, 0xaa);
    temp4 = _mm_slli_si128(*temp3, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    *temp3 = _mm_xor_si128(*temp3, temp2);
}

std::array<__m128i, kNumRoundKeys> expand_key_ni(const SecretKey& key) {
    std::array<__m128i, kNumRoundKeys> schedule{};
    const auto* raw_key_bytes = reinterpret_cast<const unsigned char*>(key_bytes(key).data());

    __m128i temp1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(raw_key_bytes));
    __m128i temp3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(raw_key_bytes + 16));
    schedule[0] = temp1;
    schedule[1] = temp3;

    // Unrolled rather than looped: _mm_aeskeygenassist_si128's round-constant
    // argument must be a compile-time immediate, so it can't be read out of
    // an array with a runtime index.
    __m128i temp2;

#define AESLIB_EVEN_STEP(rcon)                              \
    temp2 = _mm_aeskeygenassist_si128(temp3, rcon);          \
    key_expansion_step_even(&temp1, temp2)
#define AESLIB_ODD_STEP() key_expansion_step_odd(temp1, &temp3)

    AESLIB_EVEN_STEP(0x01); schedule[2] = temp1;
    AESLIB_ODD_STEP();      schedule[3] = temp3;
    AESLIB_EVEN_STEP(0x02); schedule[4] = temp1;
    AESLIB_ODD_STEP();      schedule[5] = temp3;
    AESLIB_EVEN_STEP(0x04); schedule[6] = temp1;
    AESLIB_ODD_STEP();      schedule[7] = temp3;
    AESLIB_EVEN_STEP(0x08); schedule[8] = temp1;
    AESLIB_ODD_STEP();      schedule[9] = temp3;
    AESLIB_EVEN_STEP(0x10); schedule[10] = temp1;
    AESLIB_ODD_STEP();      schedule[11] = temp3;
    AESLIB_EVEN_STEP(0x20); schedule[12] = temp1;
    AESLIB_ODD_STEP();      schedule[13] = temp3;
    AESLIB_EVEN_STEP(0x40); schedule[14] = temp1;

#undef AESLIB_EVEN_STEP
#undef AESLIB_ODD_STEP

    return schedule;
}

// Same rationale as aes_core_soft.cpp's wipe_schedule(): the round-key
// schedule is a direct, reversible function of the raw key and is
// recomputed on every block, so it's zeroed the same volatile-write way
// SecretKey::wipe() zeroes the key itself. __m128i isn't a type `volatile`
// can portably apply to element-wise, so this drops to a volatile byte view
// over the array instead.
void wipe_schedule(std::array<__m128i, kNumRoundKeys>& schedule) noexcept {
    auto* bytes = reinterpret_cast<volatile unsigned char*>(schedule.data());
    for (std::size_t i = 0; i < sizeof(__m128i) * kNumRoundKeys; ++i) bytes[i] = 0;
}

} // namespace

Block aes256_encrypt_block_ni(const SecretKey& key, const Block& block) {
    auto schedule = expand_key_ni(key);

    __m128i state = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block.data()));
    state = _mm_xor_si128(state, schedule[0]);
    for (int round = 1; round < kNumRoundKeys - 1; ++round) {
        state = _mm_aesenc_si128(state, schedule[static_cast<std::size_t>(round)]);
    }
    state = _mm_aesenclast_si128(state, schedule[kNumRoundKeys - 1]);
    wipe_schedule(schedule);

    Block out{};
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out.data()), state);
    return out;
}

namespace {

constexpr int kNumRoundKeys128 = 11; // AES-128: 10 rounds + 1 initial whitening key

// Standard single-word AES-128 AES-NI key-expansion step (Intel's "AES-NI
// Sample Library" white paper's KEY_128_ASSIST macro): one
// _mm_aeskeygenassist_si128 call per round constant, no odd/even split
// needed since AES-128's schedule advances one word (not two) per step.
__m128i key_128_assist(__m128i temp1, __m128i temp2) {
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    __m128i temp3 = _mm_slli_si128(temp1, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp1 = _mm_xor_si128(temp1, temp2);
    return temp1;
}

std::array<__m128i, kNumRoundKeys128> expand_key128_ni(const SecretKey& key) {
    std::array<__m128i, kNumRoundKeys128> schedule{};
    const auto* raw_key_bytes = reinterpret_cast<const unsigned char*>(key_bytes(key).data());

    __m128i temp1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(raw_key_bytes));
    schedule[0] = temp1;

    // Unrolled rather than looped: _mm_aeskeygenassist_si128's round-constant
    // argument must be a compile-time immediate, so it can't be read out of
    // an array with a runtime index.
    __m128i temp2;
#define AESLIB_KEY128_STEP(rcon, idx)                        \
    temp2 = _mm_aeskeygenassist_si128(temp1, rcon);           \
    temp1 = key_128_assist(temp1, temp2);                     \
    schedule[idx] = temp1

    AESLIB_KEY128_STEP(0x01, 1);
    AESLIB_KEY128_STEP(0x02, 2);
    AESLIB_KEY128_STEP(0x04, 3);
    AESLIB_KEY128_STEP(0x08, 4);
    AESLIB_KEY128_STEP(0x10, 5);
    AESLIB_KEY128_STEP(0x20, 6);
    AESLIB_KEY128_STEP(0x40, 7);
    AESLIB_KEY128_STEP(0x80, 8);
    AESLIB_KEY128_STEP(0x1B, 9);
    AESLIB_KEY128_STEP(0x36, 10);

#undef AESLIB_KEY128_STEP

    return schedule;
}

// Same rationale as the AES-256 wipe_schedule() above.
void wipe_schedule(std::array<__m128i, kNumRoundKeys128>& schedule) noexcept {
    auto* bytes = reinterpret_cast<volatile unsigned char*>(schedule.data());
    for (std::size_t i = 0; i < sizeof(__m128i) * kNumRoundKeys128; ++i) bytes[i] = 0;
}

} // namespace

Block aes128_encrypt_block_ni(const SecretKey& key, const Block& block) {
    auto schedule = expand_key128_ni(key);

    __m128i state = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block.data()));
    state = _mm_xor_si128(state, schedule[0]);
    for (int round = 1; round < kNumRoundKeys128 - 1; ++round) {
        state = _mm_aesenc_si128(state, schedule[static_cast<std::size_t>(round)]);
    }
    state = _mm_aesenclast_si128(state, schedule[kNumRoundKeys128 - 1]);
    wipe_schedule(schedule);

    Block out{};
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out.data()), state);
    return out;
}

#else

Block aes256_encrypt_block_ni(const SecretKey&, const Block&) {
    throw std::logic_error("aes256_encrypt_block_ni called on a non-x86 build");
}

Block aes128_encrypt_block_ni(const SecretKey&, const Block&) {
    throw std::logic_error("aes128_encrypt_block_ni called on a non-x86 build");
}

#endif

} // namespace aeslib::detail
