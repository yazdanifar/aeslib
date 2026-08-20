#include <array>
#include <cstdint>

#include "internal.hpp"

// Portable, from-scratch AES forward cipher (FIPS-197), used when the CPU
// has no AES-NI. CTR/GCM only ever need AES *encryption* — decryption
// (InvSubBytes/InvMixColumns/etc.) is never used, since both modes produce
// their keystream by encrypting counter blocks regardless of whether the
// caller is encrypting or decrypting the message itself.
//
// Parameterized by (Nk, Nr) so the same code serves both AES-256 (Nk=8,
// Nr=14) and AES-128 (Nk=4, Nr=10) — see aes_encrypt_block_soft below.

namespace aeslib::detail {

namespace {

// Round constants (FIPS-197 5.2), indices 0..10. The AES-256 schedule (Nk=8)
// only ever reads indices 1..7; AES-128 (Nk=4) reads indices 1..10.
constexpr std::array<std::uint8_t, 11> kRcon = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
};

constexpr int kNb = 4; // words per state block

using Word = std::array<std::uint8_t, 4>;

std::uint8_t xtime(std::uint8_t b) {
    return static_cast<std::uint8_t>((b << 1) ^ ((b & 0x80) ? 0x1b : 0x00));
}

// GF(2^8) multiply, deliberately branch-/table-free so it's safe to call with
// secret operands (used by the S-box below, which inverts key- and
// state-dependent bytes). MixColumns' multipliers are public constants (2, 3)
// so it didn't strictly need this, but there's no reason for two versions.
std::uint8_t gmul(std::uint8_t a, std::uint8_t b) {
    std::uint8_t product = 0;
    for (int i = 0; i < 8; ++i) {
        const auto mask = static_cast<std::uint8_t>(-static_cast<std::uint8_t>(b & 1));
        product ^= static_cast<std::uint8_t>(a & mask);
        a = xtime(a);
        b = static_cast<std::uint8_t>(b >> 1);
    }
    return product;
}

// Multiplicative inverse in GF(2^8): x^-1 == x^254 for x != 0, and by the AES
// S-box's own convention 0 maps to 0 (which x^254 already gives, since 0
// stays 0 under squaring/multiplication). 254 = 0b11111110 is a fixed
// exponent, so this left-to-right square-and-multiply chain performs exactly
// the same 8 squarings/7 multiplies for every input — the sequence of
// operations never branches on the secret byte's value, only gmul's internal
// bit-masking (also branch-free) touches the value itself.
std::uint8_t gf256_inv(std::uint8_t x) {
    std::uint8_t result = 1;
    for (int bit = 7; bit >= 0; --bit) {
        result = gmul(result, result);
        if ((254 >> bit) & 1) result = gmul(result, x);
    }
    return result;
}

std::uint8_t rotl8(std::uint8_t v, int shift) {
    return static_cast<std::uint8_t>(static_cast<std::uint8_t>(v << shift) | static_cast<std::uint8_t>(v >> (8 - shift)));
}

} // namespace

// Constant-time AES S-box: GF(2^8) inversion (above) followed by the fixed
// FIPS-197 5.1.1 affine bit transform, both of which touch the secret byte
// only through branch-free arithmetic/bit-rotation — no lookup table indexed
// by secret data, so no cache-timing side channel from this substitution
// step. Declared in internal.hpp and exhaustively checked against the
// canonical 256-entry S-box table in tests/test_aes_core.cpp.
std::uint8_t ct_sbox(std::uint8_t x) {
    const std::uint8_t inv = gf256_inv(x);
    return static_cast<std::uint8_t>(inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63);
}

namespace {

Word sub_word(Word w) {
    for (auto& b : w) b = ct_sbox(b);
    return w;
}

Word rot_word(Word w) { return Word{w[1], w[2], w[3], w[0]}; }

Word xor_word(Word a, Word b) {
    return Word{static_cast<std::uint8_t>(a[0] ^ b[0]), static_cast<std::uint8_t>(a[1] ^ b[1]),
                static_cast<std::uint8_t>(a[2] ^ b[2]), static_cast<std::uint8_t>(a[3] ^ b[3])};
}

// Expands an Nk*32-bit key into the 4*(Nr+1)-word round-key schedule
// (FIPS-197 5.2). The "extra SubWord step for Nk>6" branch (i % Nk == 4) is
// written generically and is naturally dead for Nk=4 (i%4 never equals 4),
// so AES-128's simpler schedule falls out automatically with no separate
// code path.
template <int Nk, int Nr>
std::array<Word, kNb*(Nr + 1)> expand_key(const SecretKey& key) {
    constexpr int kScheduleWords = kNb * (Nr + 1);
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
            temp = xor_word(sub_word(rot_word(temp)), Word{kRcon[static_cast<std::size_t>(i / Nk)], 0, 0, 0});
        } else if (Nk > 6 && i % Nk == 4) {
            // Extra SubWord step required for Nk=8 (FIPS-197 5.2, Nk > 6 case).
            temp = sub_word(temp);
        }
        schedule[static_cast<std::size_t>(i)] = xor_word(schedule[static_cast<std::size_t>(i - Nk)], temp);
    }
    return schedule;
}

template <int Nr>
void add_round_key(std::array<std::uint8_t, 16>& state, const std::array<Word, kNb*(Nr + 1)>& schedule, int round) {
    for (int c = 0; c < kNb; ++c) {
        const Word& w = schedule[static_cast<std::size_t>(round * kNb + c)];
        for (int r = 0; r < 4; ++r) {
            state[static_cast<std::size_t>(c * 4 + r)] ^= w[static_cast<std::size_t>(r)];
        }
    }
}

void sub_bytes(std::array<std::uint8_t, 16>& state) {
    for (auto& b : state) b = ct_sbox(b);
}

void shift_rows(std::array<std::uint8_t, 16>& state) {
    // State is column-major: state[col*4 + row].
    std::array<std::uint8_t, 16> s = state;
    for (int row = 1; row < 4; ++row) {
        for (int col = 0; col < 4; ++col) {
            state[static_cast<std::size_t>(col * 4 + row)] = s[static_cast<std::size_t>(((col + row) % 4) * 4 + row)];
        }
    }
}

// The round-key schedule is a direct, reversible function of the raw key —
// just as sensitive as the key itself, and recomputed on every block (CTR/GCM
// call this once per 16 bytes of keystream), so it's wiped the same way
// SecretKey::wipe() wipes the key: a volatile byte-level loop so the
// compiler can't drop it as a dead store right before the array goes out of
// scope.
template <int Nr>
void wipe_schedule(std::array<Word, kNb*(Nr + 1)>& schedule) noexcept {
    auto* bytes = reinterpret_cast<volatile std::uint8_t*>(schedule.data());
    for (std::size_t i = 0; i < sizeof(Word) * schedule.size(); ++i) bytes[i] = 0;
}

void mix_columns(std::array<std::uint8_t, 16>& state) {
    for (int c = 0; c < 4; ++c) {
        std::uint8_t a0 = state[static_cast<std::size_t>(c * 4 + 0)], a1 = state[static_cast<std::size_t>(c * 4 + 1)],
                      a2 = state[static_cast<std::size_t>(c * 4 + 2)], a3 = state[static_cast<std::size_t>(c * 4 + 3)];
        state[static_cast<std::size_t>(c * 4 + 0)] = static_cast<std::uint8_t>(gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3);
        state[static_cast<std::size_t>(c * 4 + 1)] = static_cast<std::uint8_t>(a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3);
        state[static_cast<std::size_t>(c * 4 + 2)] = static_cast<std::uint8_t>(a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3));
        state[static_cast<std::size_t>(c * 4 + 3)] = static_cast<std::uint8_t>(gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2));
    }
}

template <int Nk, int Nr>
Block aes_encrypt_block_soft(const SecretKey& key, const Block& block) {
    auto schedule = expand_key<Nk, Nr>(key);

    std::array<std::uint8_t, 16> state{};
    for (int i = 0; i < 16; ++i) state[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(block[static_cast<std::size_t>(i)]);

    add_round_key<Nr>(state, schedule, 0);
    for (int round = 1; round < Nr; ++round) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key<Nr>(state, schedule, round);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key<Nr>(state, schedule, Nr);
    wipe_schedule<Nr>(schedule);

    Block out{};
    for (int i = 0; i < 16; ++i) out[static_cast<std::size_t>(i)] = static_cast<std::byte>(state[static_cast<std::size_t>(i)]);
    return out;
}

} // namespace

Block aes256_encrypt_block_soft(const SecretKey& key, const Block& block) { return aes_encrypt_block_soft<8, 14>(key, block); }

Block aes128_encrypt_block_soft(const SecretKey& key, const Block& block) { return aes_encrypt_block_soft<4, 10>(key, block); }

} // namespace aeslib::detail
