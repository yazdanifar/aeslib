#include <array>
#include <stdexcept>

#include "aes_key_schedule.hpp"
#include "internal.hpp"

// AES forward cipher using AArch64 Crypto Extensions intrinsics. Only ever
// reached when cpu::has_hw_aes() returned true (see aes_core_hw.cpp's
// dispatch), so it's safe to assume the instructions exist here.
//
// This translation unit is compiled with -march=armv8-a+crypto (see
// CMakeLists.txt) even though the rest of the binary is not, so the crypto
// instructions this file emits don't leak into code paths that must run on
// non-crypto-capable ARM hardware — the same isolation rationale as
// aes_core_ni.cpp's -maes scoping on x86.
//
// Unlike x86's AES-NI, the ARMv8 Crypto Extensions have no dedicated
// key-expansion instruction — AESE/AESMC only accelerate the round
// *transform*. Real-world implementations (mbedTLS's aesce.c, Botan's
// aes_armv8.cpp) compute the round-key schedule in portable code, so this
// file reuses the exact same FIPS-197 schedule the software backend uses
// (aes_key_schedule.hpp) rather than hand-rolling a third copy of it.

#if defined(__aarch64__) || defined(_M_ARM64)
#define AESLIB_HAVE_ARM_CRYPTO_INTRINSICS 1
#include <arm_neon.h>
#else
#define AESLIB_HAVE_ARM_CRYPTO_INTRINSICS 0
#endif

namespace aeslib::detail {

#if AESLIB_HAVE_ARM_CRYPTO_INTRINSICS

namespace {

// Packs a 4*(Nr+1)-word FIPS-197 schedule into one 128-bit NEON vector per
// round key.
template <int Nr>
std::array<uint8x16_t, static_cast<std::size_t>(Nr) + 1> pack_round_keys(const std::array<Word, kScheduleNb*(Nr + 1)>& schedule) {
    std::array<uint8x16_t, static_cast<std::size_t>(Nr) + 1> round_keys{};
    for (int round = 0; round <= Nr; ++round) {
        std::array<std::uint8_t, 16> rk_bytes{};
        for (int w = 0; w < kScheduleNb; ++w) {
            const Word& word = schedule[static_cast<std::size_t>(round * kScheduleNb + w)];
            for (int b = 0; b < 4; ++b) rk_bytes[static_cast<std::size_t>(w * 4 + b)] = word[static_cast<std::size_t>(b)];
        }
        round_keys[static_cast<std::size_t>(round)] = vld1q_u8(rk_bytes.data());
    }
    return round_keys;
}

// Same rationale as aes_key_schedule.hpp's wipe_schedule(): the packed NEON
// round-key copy is just as sensitive as the Word-array schedule it was
// built from, so it gets the same volatile-write treatment before going out
// of scope. uint8x16_t isn't a type `volatile` can portably apply to
// element-wise, so this drops to a volatile byte view over the array.
template <int Nr>
void wipe_round_keys(std::array<uint8x16_t, static_cast<std::size_t>(Nr) + 1>& round_keys) noexcept {
    auto* bytes = reinterpret_cast<volatile unsigned char*>(round_keys.data());
    for (std::size_t i = 0; i < sizeof(uint8x16_t) * round_keys.size(); ++i) bytes[i] = 0;
}

// Standard ARMv8 Crypto Extensions AES round loop (used identically by
// mbedTLS/Botan/OpenSSL's AArch64 backends): vaeseq_u8(x, k) computes
// ShiftRows(SubBytes(x ^ k)) — AddRoundKey fused into the next round's
// SubBytes/ShiftRows step. This reproduces standard FIPS-197 encryption
// because SubBytes and ShiftRows commute (ShiftRows only permutes byte
// *positions*; SubBytes acts identically on every byte regardless of
// position), so folding round r's trailing AddRoundKey into round r+1's
// leading SubBytes/ShiftRows is equivalent to doing them in the textbook
// order. The final round omits MixColumns and uses a plain XOR for its
// AddRoundKey, matching every other backend in this codebase.
template <int Nk, int Nr>
Block aes_encrypt_block_arm(const SecretKey& key, const Block& block) {
    auto schedule = expand_key<Nk, Nr>(key);
    auto round_keys = pack_round_keys<Nr>(schedule);
    wipe_schedule<Nr>(schedule);

    uint8x16_t state = vld1q_u8(reinterpret_cast<const std::uint8_t*>(block.data()));
    for (int round = 0; round < Nr - 1; ++round) {
        state = vaeseq_u8(state, round_keys[static_cast<std::size_t>(round)]);
        state = vaesmcq_u8(state);
    }
    state = vaeseq_u8(state, round_keys[static_cast<std::size_t>(Nr - 1)]);
    state = veorq_u8(state, round_keys[static_cast<std::size_t>(Nr)]);
    wipe_round_keys<Nr>(round_keys);

    Block out{};
    vst1q_u8(reinterpret_cast<std::uint8_t*>(out.data()), state);
    return out;
}

} // namespace

Block aes256_encrypt_block_arm(const SecretKey& key, const Block& block) { return aes_encrypt_block_arm<8, 14>(key, block); }

Block aes128_encrypt_block_arm(const SecretKey& key, const Block& block) { return aes_encrypt_block_arm<4, 10>(key, block); }

#else

Block aes256_encrypt_block_arm(const SecretKey&, const Block&) {
    throw std::logic_error("aes256_encrypt_block_arm called on a non-ARM64 build");
}

Block aes128_encrypt_block_arm(const SecretKey&, const Block&) {
    throw std::logic_error("aes128_encrypt_block_arm called on a non-ARM64 build");
}

#endif

} // namespace aeslib::detail
