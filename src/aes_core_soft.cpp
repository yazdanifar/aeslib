#include <array>
#include <cstdint>

#include "internal.hpp"

// Portable, from-scratch AES-256 forward cipher (FIPS-197), used when the
// CPU has no AES-NI. CTR mode only ever needs AES *encryption* — decryption
// (InvSubBytes/InvMixColumns/etc.) is never used, since CTR produces its
// keystream by encrypting counter blocks regardless of whether the caller is
// encrypting or decrypting the message itself.

namespace aeslib::detail {

namespace {

// clang-format off
constexpr std::array<std::uint8_t, 256> kSBox = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};
// clang-format on

// Round constants for the Nk=8 key schedule (indices 1..7 are used).
constexpr std::array<std::uint8_t, 8> kRcon = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
};

constexpr int kNb = 4;   // words per state block
constexpr int kNk = 8;   // words per AES-256 key
constexpr int kNr = 14;  // AES-256 rounds
constexpr int kScheduleWords = kNb * (kNr + 1);

using Word = std::array<std::uint8_t, 4>;

std::uint8_t xtime(std::uint8_t b) {
    return static_cast<std::uint8_t>((b << 1) ^ ((b & 0x80) ? 0x1b : 0x00));
}

std::uint8_t gmul(std::uint8_t a, std::uint8_t b) {
    std::uint8_t product = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) product ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return product;
}

Word sub_word(Word w) {
    for (auto& b : w) b = kSBox[b];
    return w;
}

Word rot_word(Word w) { return Word{w[1], w[2], w[3], w[0]}; }

Word xor_word(Word a, Word b) {
    return Word{static_cast<std::uint8_t>(a[0] ^ b[0]), static_cast<std::uint8_t>(a[1] ^ b[1]),
                static_cast<std::uint8_t>(a[2] ^ b[2]), static_cast<std::uint8_t>(a[3] ^ b[3])};
}

// Expands a 256-bit key into the 60-word round-key schedule (FIPS-197 5.2,
// specialized for Nk=8).
std::array<Word, kScheduleWords> expand_key(const SecretKey& key) {
    std::array<Word, kScheduleWords> schedule{};
    const auto& kb = key.bytes();

    for (int i = 0; i < kNk; ++i) {
        schedule[i] = Word{static_cast<std::uint8_t>(kb[4 * i]),
                            static_cast<std::uint8_t>(kb[4 * i + 1]),
                            static_cast<std::uint8_t>(kb[4 * i + 2]),
                            static_cast<std::uint8_t>(kb[4 * i + 3])};
    }

    for (int i = kNk; i < kScheduleWords; ++i) {
        Word temp = schedule[i - 1];
        if (i % kNk == 0) {
            temp = xor_word(sub_word(rot_word(temp)), Word{kRcon[i / kNk], 0, 0, 0});
        } else if (i % kNk == 4) {
            // Extra SubWord step required for Nk=8 (FIPS-197 5.2, Nk > 6 case).
            temp = sub_word(temp);
        }
        schedule[i] = xor_word(schedule[i - kNk], temp);
    }
    return schedule;
}

void add_round_key(std::array<std::uint8_t, 16>& state, const std::array<Word, kScheduleWords>& schedule,
                    int round) {
    for (int c = 0; c < kNb; ++c) {
        const Word& w = schedule[round * kNb + c];
        for (int r = 0; r < 4; ++r) {
            state[c * 4 + r] ^= w[r];
        }
    }
}

void sub_bytes(std::array<std::uint8_t, 16>& state) {
    for (auto& b : state) b = kSBox[b];
}

void shift_rows(std::array<std::uint8_t, 16>& state) {
    // State is column-major: state[col*4 + row].
    std::array<std::uint8_t, 16> s = state;
    for (int row = 1; row < 4; ++row) {
        for (int col = 0; col < 4; ++col) {
            state[col * 4 + row] = s[((col + row) % 4) * 4 + row];
        }
    }
}

void mix_columns(std::array<std::uint8_t, 16>& state) {
    for (int c = 0; c < 4; ++c) {
        std::uint8_t a0 = state[c * 4 + 0], a1 = state[c * 4 + 1], a2 = state[c * 4 + 2], a3 = state[c * 4 + 3];
        state[c * 4 + 0] = static_cast<std::uint8_t>(gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3);
        state[c * 4 + 1] = static_cast<std::uint8_t>(a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3);
        state[c * 4 + 2] = static_cast<std::uint8_t>(a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3));
        state[c * 4 + 3] = static_cast<std::uint8_t>(gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2));
    }
}

} // namespace

Block aes256_encrypt_block_soft(const SecretKey& key, const Block& block) {
    const auto schedule = expand_key(key);

    std::array<std::uint8_t, 16> state{};
    for (int i = 0; i < 16; ++i) state[i] = static_cast<std::uint8_t>(block[i]);

    add_round_key(state, schedule, 0);
    for (int round = 1; round < kNr; ++round) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, schedule, round);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, schedule, kNr);

    Block out{};
    for (int i = 0; i < 16; ++i) out[i] = static_cast<std::byte>(state[i]);
    return out;
}

} // namespace aeslib::detail
