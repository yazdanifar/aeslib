#pragma once

// FIPS-197 §5.2 AES round-key schedule (key expansion), shared by any backend
// whose instruction set has no dedicated key-expansion instruction of its
// own. The software backend (aes_core_soft.cpp) always needs this; the ARM
// AArch64 Crypto Extensions backend (aes_core_arm.cpp) also needs it, since
// unlike x86's `_mm_aeskeygenassist_si128`, ARM's AESE/AESMC instructions
// only accelerate the round *transform*, not the key schedule — real-world
// implementations (mbedTLS, Botan) do the schedule itself in portable code,
// which is exactly this header. Kept template/header-only so it can be
// instantiated from multiple translation units without a shared .cpp.

#include <array>
#include <cstddef>
#include <cstdint>

#include "aeslib/key.hpp"
#include "internal.hpp" // ct_sbox()

namespace aeslib::detail {

inline constexpr int kScheduleNb = 4; // words per state block

using Word = std::array<std::uint8_t, 4>;

// Round constants (FIPS-197 5.2), indices 0..10. The AES-256 schedule (Nk=8)
// only ever reads indices 1..7; AES-128 (Nk=4) reads indices 1..10.
inline constexpr std::array<std::uint8_t, 11> kScheduleRcon = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
};

inline Word schedule_sub_word(Word w) {
    for (auto& b : w) b = ct_sbox(b);
    return w;
}

inline Word schedule_rot_word(Word w) { return Word{w[1], w[2], w[3], w[0]}; }

inline Word schedule_xor_word(Word a, Word b) {
    return Word{static_cast<std::uint8_t>(a[0] ^ b[0]), static_cast<std::uint8_t>(a[1] ^ b[1]),
                static_cast<std::uint8_t>(a[2] ^ b[2]), static_cast<std::uint8_t>(a[3] ^ b[3])};
}

// Expands an Nk*32-bit key into the 4*(Nr+1)-word round-key schedule
// (FIPS-197 5.2). The "extra SubWord step for Nk>6" branch (i % Nk == 4) is
// written generically and is naturally dead for Nk=4 (i%4 never equals 4),
// so AES-128's simpler schedule falls out automatically with no separate
// code path.
template <int Nk, int Nr>
std::array<Word, kScheduleNb*(Nr + 1)> expand_key(const SecretKey& key) {
    constexpr int kScheduleWords = kScheduleNb * (Nr + 1);
    std::array<Word, kScheduleWords> schedule{};
    const auto& kb = key_bytes(key);

    for (int i = 0; i < Nk; ++i) {
        schedule[static_cast<std::size_t>(i)] = Word{static_cast<std::uint8_t>(kb[4 * i]),
                                                       static_cast<std::uint8_t>(kb[4 * i + 1]),
                                                       static_cast<std::uint8_t>(kb[4 * i + 2]),
                                                       static_cast<std::uint8_t>(kb[4 * i + 3])};
    }

    for (int i = Nk; i < kScheduleWords; ++i) {
        Word temp = schedule[static_cast<std::size_t>(i - 1)];
        if (i % Nk == 0) {
            temp = schedule_xor_word(schedule_sub_word(schedule_rot_word(temp)),
                                      Word{kScheduleRcon[static_cast<std::size_t>(i / Nk)], 0, 0, 0});
        } else if (Nk > 6 && i % Nk == 4) {
            // Extra SubWord step required for Nk=8 (FIPS-197 5.2, Nk > 6 case).
            temp = schedule_sub_word(temp);
        }
        schedule[static_cast<std::size_t>(i)] = schedule_xor_word(schedule[static_cast<std::size_t>(i - Nk)], temp);
    }
    return schedule;
}

// The round-key schedule is a direct, reversible function of the raw key —
// just as sensitive as the key itself, and recomputed on every block (CTR/GCM
// call this once per 16 bytes of keystream), so it's wiped the same way
// SecretKey::wipe() wipes the key: a volatile byte-level loop so the
// compiler can't drop it as a dead store right before the array goes out of
// scope.
template <int Nr>
void wipe_schedule(std::array<Word, kScheduleNb*(Nr + 1)>& schedule) noexcept {
    auto* bytes = reinterpret_cast<volatile std::uint8_t*>(schedule.data());
    for (std::size_t i = 0; i < sizeof(Word) * schedule.size(); ++i) bytes[i] = 0;
}

} // namespace aeslib::detail
