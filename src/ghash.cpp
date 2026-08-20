#include <algorithm>
#include <cstdint>

#include "internal.hpp"

// GHASH (NIST SP 800-38D §6.3-6.4), implemented from spec as an
// independently KAT-testable primitive (see tests/test_gcm.cpp), matching
// this project's existing "primitives get their own KATs" convention (SHA-256/
// HMAC/PBKDF2 in src/sha256.cpp). No PCLMULQDQ acceleration — kept portable,
// branch-free C++ throughout, same "correct everywhere" category as the rest
// of the non-AES-NI code.

namespace aeslib::detail {

namespace {

std::uint64_t load_be64(const std::byte* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | static_cast<std::uint8_t>(p[i]);
    return v;
}

void store_be64(std::byte* p, std::uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        p[i] = static_cast<std::byte>(v & 0xff);
        v >>= 8;
    }
}

} // namespace

// GF(2^128) multiplication with the GCM reduction polynomial R = 0xE1 ||
// 0^120 (NIST SP 800-38D Algorithm 1: the standard bit-serial
// shift-and-conditionally-XOR algorithm, one bit of y at a time). Written
// branch-free (constant-time w.r.t. both operands, since both x and y are
// secret-derived here — the GHASH subkey H and the running accumulator) via
// a bitmask rather than an `if`, same discipline as gmul/gf256_inv in
// aes_core_soft.cpp.
Block gf128_mul(const Block& x, const Block& y) {
    std::uint64_t v_hi = load_be64(x.data());
    std::uint64_t v_lo = load_be64(x.data() + 8);
    const std::uint64_t y_hi = load_be64(y.data());
    const std::uint64_t y_lo = load_be64(y.data() + 8);

    constexpr std::uint64_t kRHi = 0xE100000000000000ULL; // R's low 64 bits are all zero.

    std::uint64_t z_hi = 0;
    std::uint64_t z_lo = 0;

    for (int i = 0; i < 128; ++i) {
        const std::uint64_t ybit = (i < 64) ? ((y_hi >> (63 - i)) & 1) : ((y_lo >> (63 - (i - 64))) & 1);
        const auto zmask = static_cast<std::uint64_t>(0) - ybit;
        z_hi ^= zmask & v_hi;
        z_lo ^= zmask & v_lo;

        const std::uint64_t lsb = v_lo & 1;
        const std::uint64_t new_lo = (v_lo >> 1) | ((v_hi & 1) << 63);
        const std::uint64_t new_hi = v_hi >> 1;
        const auto rmask = static_cast<std::uint64_t>(0) - lsb;
        v_hi = new_hi ^ (rmask & kRHi);
        v_lo = new_lo; // R's low 64 bits are 0, nothing to XOR in.
    }

    Block out{};
    store_be64(out.data(), z_hi);
    store_be64(out.data() + 8, z_lo);
    return out;
}

namespace {

// XORs `count` zero-padded 16-byte blocks of `data` into `y`, multiplying by
// `h` after each fold (NIST SP 800-38D §6.4's GHASH recursion).
void fold_into(Block& y, const Block& h, const std::byte* data, std::size_t len) {
    std::size_t offset = 0;
    while (offset < len) {
        Block block{};
        const std::size_t chunk = std::min<std::size_t>(kBlockSizeBytes, len - offset);
        for (std::size_t i = 0; i < chunk; ++i) block[i] = data[offset + i];
        for (std::size_t i = 0; i < kBlockSizeBytes; ++i) y[i] = static_cast<std::byte>(y[i] ^ block[i]);
        y = gf128_mul(y, h);
        offset += chunk;
    }
}

} // namespace

Block ghash(const Block& h, const std::vector<std::byte>& aad, const std::vector<std::byte>& ciphertext) {
    Block y{};
    fold_into(y, h, aad.data(), aad.size());
    fold_into(y, h, ciphertext.data(), ciphertext.size());

    // Final "length block": big-endian 64-bit bit-lengths of AAD and
    // ciphertext, folded in the same way as any other block.
    Block len_block{};
    store_be64(len_block.data(), static_cast<std::uint64_t>(aad.size()) * 8);
    store_be64(len_block.data() + 8, static_cast<std::uint64_t>(ciphertext.size()) * 8);
    for (std::size_t i = 0; i < kBlockSizeBytes; ++i) y[i] = static_cast<std::byte>(y[i] ^ len_block[i]);
    y = gf128_mul(y, h);

    return y;
}

} // namespace aeslib::detail
