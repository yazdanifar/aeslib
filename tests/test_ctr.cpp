// Round-trip and keystream-consistency tests for Aes256Ctr. NIST SP 800-38A's
// published CTR vectors use a free-running 128-bit counter block, whereas
// this library uses a 96-bit random nonce || 32-bit counter (see
// make_counter_block in aes256_ctr.cpp) — so those vectors don't apply
// directly here. Correctness is instead anchored at the block-cipher layer
// (test_aes_core.cpp's FIPS-197 KAT) plus the self-consistency checks below.

#include <cstdint>
#include <vector>

#include "aeslib/aes256_ctr.hpp"
#include "aeslib/exceptions.hpp"
#include "src/internal.hpp"
#include "test_support.hpp"

namespace {

using aeslib::Aes256Ctr;
using aeslib::LimitError;
using aeslib::SecretKey;

std::vector<std::byte> make_bytes(std::size_t size) {
    std::vector<std::byte> data(size);
    for (std::size_t i = 0; i < size; ++i) {
        data[i] = static_cast<std::byte>(i % 256);
    }
    return data;
}

} // namespace

AESLIB_TEST(ctr, round_trip_various_sizes) {
    const SecretKey key = SecretKey::generate();
    for (std::size_t size : {0u, 1u, 15u, 16u, 17u, 4096u, 100000u}) {
        const std::vector<std::byte> plaintext = make_bytes(size);
        const auto container = Aes256Ctr::encrypt(key, plaintext);
        const auto decrypted = Aes256Ctr::decrypt(key, container);
        CHECK_EQ(decrypted, plaintext);
    }
}

AESLIB_TEST(ctr, ciphertext_differs_from_plaintext_for_nonempty_input) {
    const SecretKey key = SecretKey::generate();
    const std::vector<std::byte> plaintext = make_bytes(64);
    const auto container = Aes256Ctr::encrypt(key, plaintext);
    CHECK(container.ciphertext != plaintext);
}

AESLIB_TEST(ctr, repeated_encryption_uses_fresh_nonces) {
    const SecretKey key = SecretKey::generate();
    const std::vector<std::byte> plaintext = make_bytes(64);
    const auto first = Aes256Ctr::encrypt(key, plaintext);
    const auto second = Aes256Ctr::encrypt(key, plaintext);
    // Same plaintext, same key: ciphertexts must differ because the nonce is
    // randomly regenerated per call — a repeated nonce under the same key
    // would be a keystream-reuse vulnerability.
    CHECK(first.nonce != second.nonce);
    CHECK(first.ciphertext != second.ciphertext);
}

AESLIB_TEST(ctr, block_count_guard_rejects_input_beyond_counter_range) {
    // The CTR construction's block counter is 32 bits, so a single call can
    // address at most 2^32 blocks (64 GiB) before it would wrap and reuse
    // keystream. validate_block_count() takes a size, not a real buffer, so
    // this exercises the boundary without allocating 64 GiB.
    constexpr std::uint64_t kMaxBlocks = std::uint64_t{1} << 32;
    constexpr std::uint64_t kMaxBytes = kMaxBlocks * 16;

    // Exactly at the limit: must NOT throw.
    aeslib::detail::validate_block_count(static_cast<std::size_t>(kMaxBytes));
    // One byte beyond, forcing one extra block past the counter's range.
    CHECK_THROWS(aeslib::detail::validate_block_count(static_cast<std::size_t>(kMaxBytes) + 1), LimitError);
}

AESLIB_TEST(ctr, decrypting_with_wrong_key_does_not_recover_plaintext) {
    const SecretKey key = SecretKey::generate();
    const SecretKey wrong_key = SecretKey::generate();
    const std::vector<std::byte> plaintext = make_bytes(64);
    const auto container = Aes256Ctr::encrypt(key, plaintext);
    const auto decrypted = Aes256Ctr::decrypt(wrong_key, container);
    CHECK(decrypted != plaintext);
}
