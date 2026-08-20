#include <algorithm>
#include <cstring>
#include <vector>

#include "internal.hpp"

namespace aeslib::detail {

// SHA-256 per FIPS 180-4: constants and operations.
namespace {

constexpr std::uint32_t kSha256K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

std::uint32_t ror32(std::uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

std::uint32_t ch(std::uint32_t x, std::uint32_t y, std::uint32_t z) { return (x & y) ^ (~x & z); }

std::uint32_t maj(std::uint32_t x, std::uint32_t y, std::uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }

std::uint32_t sigma0(std::uint32_t x) { return ror32(x, 2) ^ ror32(x, 13) ^ ror32(x, 22); }

std::uint32_t sigma1(std::uint32_t x) { return ror32(x, 6) ^ ror32(x, 11) ^ ror32(x, 25); }

std::uint32_t gamma0(std::uint32_t x) { return ror32(x, 7) ^ ror32(x, 18) ^ (x >> 3); }

std::uint32_t gamma1(std::uint32_t x) { return ror32(x, 17) ^ ror32(x, 19) ^ (x >> 10); }


// Convert uint32 to 4 bytes (big-endian).
void u32_to_be(std::uint8_t* p, std::uint32_t x) {
    p[0] = static_cast<std::uint8_t>(x >> 24);
    p[1] = static_cast<std::uint8_t>(x >> 16);
    p[2] = static_cast<std::uint8_t>(x >> 8);
    p[3] = static_cast<std::uint8_t>(x);
}

// Convert uint64 to 8 bytes (big-endian).
void u64_to_be(std::uint8_t* p, std::uint64_t x) {
    p[0] = static_cast<std::uint8_t>(x >> 56);
    p[1] = static_cast<std::uint8_t>(x >> 48);
    p[2] = static_cast<std::uint8_t>(x >> 40);
    p[3] = static_cast<std::uint8_t>(x >> 32);
    p[4] = static_cast<std::uint8_t>(x >> 24);
    p[5] = static_cast<std::uint8_t>(x >> 16);
    p[6] = static_cast<std::uint8_t>(x >> 8);
    p[7] = static_cast<std::uint8_t>(x);
}

// Convert 4 bytes (big-endian) to uint32.
std::uint32_t be_to_u32(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

} // namespace

std::array<std::byte, 32> sha256(const std::byte* data, std::size_t len) {
    // SHA-256 per FIPS 180-4: initialize hash values (§5.3.3).
    std::uint32_t h0 = 0x6a09e667;
    std::uint32_t h1 = 0xbb67ae85;
    std::uint32_t h2 = 0x3c6ef372;
    std::uint32_t h3 = 0xa54ff53a;
    std::uint32_t h4 = 0x510e527f;
    std::uint32_t h5 = 0x9b05688c;
    std::uint32_t h6 = 0x1f83d9ab;
    std::uint32_t h7 = 0x5be0cd19;

    const auto* bytes = reinterpret_cast<const std::uint8_t*>(data);

    // Pre-processing per §5.1.1.
    std::uint64_t ml = static_cast<std::uint64_t>(len) * 8;

    // Pad message: append '1' bit, then '0' bits, then 128-bit length.
    // Simplest approach: buffer full blocks as we go, keeping a partial block.
    std::uint8_t block[64];
    std::uint64_t block_len = 0;

    auto process_block = [&](const std::uint8_t* b) {
        // Schedule per §5.2.2.
        std::uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = be_to_u32(&b[i * 4]);
        }
        for (int i = 16; i < 64; ++i) {
            w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
        }

        // Compression per §6.2.2.
        std::uint32_t a = h0, b_var = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
        for (int i = 0; i < 64; ++i) {
            std::uint32_t t1 = h + sigma1(e) + ch(e, f, g) + kSha256K[i] + w[i];
            std::uint32_t t2 = sigma0(a) + maj(a, b_var, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b_var;
            b_var = a;
            a = t1 + t2;
        }

        h0 += a;
        h1 += b_var;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    };

    // Process full message in 64-byte blocks.
    for (std::size_t i = 0; i < len; ++i) {
        block[block_len++] = bytes[i];
        if (block_len == 64) {
            process_block(block);
            block_len = 0;
        }
    }

    // Finalize: append '1' bit (0x80), then zeros, then length.
    block[block_len++] = 0x80;
    if (block_len > 56) {
        // Need a full block for padding.
        std::memset(&block[block_len], 0, 64 - block_len);
        process_block(block);
        block_len = 0;
    }
    std::memset(&block[block_len], 0, 56 - block_len);
    u64_to_be(&block[56], ml);
    process_block(block);

    // Produce output per §5.3.5.
    std::array<std::byte, 32> digest;
    auto* out = reinterpret_cast<std::uint8_t*>(digest.data());
    u32_to_be(&out[0], h0);
    u32_to_be(&out[4], h1);
    u32_to_be(&out[8], h2);
    u32_to_be(&out[12], h3);
    u32_to_be(&out[16], h4);
    u32_to_be(&out[20], h5);
    u32_to_be(&out[24], h6);
    u32_to_be(&out[28], h7);
    return digest;
}

std::array<std::byte, 32> hmac_sha256(const std::byte* key, std::size_t key_len, const std::byte* data,
                                       std::size_t len) {
    // HMAC per RFC 2104 / FIPS 198-1. SHA-256 block size is 64 bytes.
    constexpr std::size_t block_size = 64;
    constexpr std::uint8_t ipad_byte = 0x36;
    constexpr std::uint8_t opad_byte = 0x5c;

    // If key is longer than block size, hash it first.
    std::array<std::byte, 32> actual_key_bytes;
    if (key_len > block_size) {
        actual_key_bytes = sha256(key, key_len);
        key = actual_key_bytes.data();
        key_len = actual_key_bytes.size();
    }

    // Build ipad and opad, padding key with zeros to block_size.
    std::uint8_t ipad[block_size];
    std::uint8_t opad[block_size];
    std::memset(ipad, ipad_byte, block_size);
    std::memset(opad, opad_byte, block_size);
    for (std::size_t i = 0; i < key_len; ++i) {
        ipad[i] ^= static_cast<std::uint8_t>(key[i]);
        opad[i] ^= static_cast<std::uint8_t>(key[i]);
    }

    // Inner hash: SHA-256(ipad || data). PBKDF2's inner loop calls this
    // ~iterations times with data that's always exactly 32 bytes (the
    // previous HMAC output), so this stays on the stack for that common
    // case (avoiding a heap allocation per call in a ~1.2M-call loop at the
    // default 600,000 iterations) and only spills to the heap for inputs
    // larger than that fixed bound — unlike a single large fixed buffer,
    // this doesn't silently truncate oversized input.
    constexpr std::size_t kInlineCap = 256;
    std::array<std::byte, block_size + kInlineCap> inline_buf;
    std::vector<std::byte> heap_buf;
    std::byte* inner_data;
    if (len <= kInlineCap) {
        inner_data = inline_buf.data();
    } else {
        heap_buf.resize(block_size + len);
        inner_data = heap_buf.data();
    }
    std::memcpy(inner_data, ipad, block_size);
    if (len > 0) {
        std::memcpy(inner_data + block_size, data, len);
    }
    std::array<std::byte, 32> inner = sha256(inner_data, block_size + len);

    // Outer hash: SHA-256(opad || inner_hash).
    std::array<std::byte, block_size + 32> outer_buf;
    std::memcpy(outer_buf.data(), opad, block_size);
    std::memcpy(&outer_buf[block_size], inner.data(), 32);
    return sha256(outer_buf.data(), block_size + 32);
}

std::array<std::byte, 64> pbkdf2_hmac_sha256(std::string_view passphrase, const std::byte* salt,
                                              std::size_t salt_len, std::uint32_t iterations) {
    // PBKDF2 per RFC 8018 §5.2, with dkLen = 64 and PRF = HMAC-SHA256.
    // hLen (HMAC-SHA256 output) = 32 bytes.
    // dkLen = 64, so l = ceil(64 / 32) = 2 blocks.
    constexpr std::size_t hlen = 32;
    constexpr std::size_t dklen = 64;

    std::array<std::byte, dklen> result{};

    const auto* pass = reinterpret_cast<const std::byte*>(passphrase.data());
    std::size_t pass_len = passphrase.size();

    for (std::uint32_t block_idx = 1; block_idx <= 2; ++block_idx) {
        // U_1 = PRF(password, salt || block_count)
        std::vector<std::byte> u_input_buf(salt_len + 4);
        std::memcpy(u_input_buf.data(), salt, salt_len);
        u_input_buf[salt_len] = static_cast<std::byte>(block_idx >> 24);
        u_input_buf[salt_len + 1] = static_cast<std::byte>(block_idx >> 16);
        u_input_buf[salt_len + 2] = static_cast<std::byte>(block_idx >> 8);
        u_input_buf[salt_len + 3] = static_cast<std::byte>(block_idx);
        std::array<std::byte, 32> u = hmac_sha256(pass, pass_len, u_input_buf.data(), salt_len + 4);

        // T_block = U_1 XOR U_2 XOR ... XOR U_iterations
        std::array<std::byte, 32> t_block = u;
        for (std::uint32_t i = 2; i <= iterations; ++i) {
            u = hmac_sha256(pass, pass_len, u.data(), u.size());
            for (std::size_t j = 0; j < 32; ++j) {
                t_block[j] ^= u[j];
            }
        }

        // Copy to result (dkLen = 64, hlen = 32, so two 32-byte blocks).
        std::size_t offset = (block_idx - 1) * hlen;
        std::memcpy(&result[offset], t_block.data(), hlen);
    }

    return result;
}

bool constant_time_equal(const std::byte* a, const std::byte* b, std::size_t len) noexcept {
    // Compare all bytes regardless of value, preventing early-exit timing leaks.
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < len; ++i) {
        diff |= static_cast<std::uint8_t>(a[i]) ^ static_cast<std::uint8_t>(b[i]);
    }
    return diff == 0;
}

void secure_wipe(std::byte* data, std::size_t len) noexcept {
    // Volatile writes prevent dead-store elimination.
    auto* vdata = reinterpret_cast<volatile std::byte*>(data);
    for (std::size_t i = 0; i < len; ++i) vdata[i] = std::byte{0};
}

} // namespace aeslib::detail
