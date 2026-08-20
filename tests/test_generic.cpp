// Bonus: generic support for other types via templates. Round-trips
// Aes256Ctr/AesGcm through several byte-viewable types beyond the baseline
// std::vector<std::byte>, plus the FormatError paths when a decrypted byte
// count doesn't fit the requested type.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "aeslib/aes256_ctr.hpp"
#include "aeslib/aes_gcm.hpp"
#include "aeslib/byte_view.hpp"
#include "aeslib/exceptions.hpp"
#include "test_support.hpp"

namespace {

using aeslib::Aes256Ctr;
using aeslib::AesGcm;
using aeslib::FormatError;
using aeslib::SecretKey;

// A plain aggregate: trivially copyable, not a container, so it's viewed as
// one opaque sizeof(T)-byte blob.
struct SensorReading {
    std::uint32_t id;
    float value;
    std::array<std::byte, 4> flags;

    bool operator==(const SensorReading& other) const {
        return id == other.id && value == other.value && flags == other.flags;
    }
};

// Disqualified types, checked at compile time below: neither is trivially
// copyable end-to-end, so is_byte_viewable must reject both.
struct HasVectorMember {
    std::vector<int> data; // not trivially copyable itself
};

} // namespace

static_assert(!aeslib::detail::is_byte_viewable_v<HasVectorMember>,
              "a struct holding a std::vector member must not be byte-viewable");
static_assert(!aeslib::detail::is_byte_viewable_v<std::vector<std::string>>,
              "std::string elements aren't trivially copyable, so this container must not be byte-viewable");
static_assert(aeslib::detail::is_byte_viewable_v<std::vector<std::byte>>,
              "the baseline type must remain byte-viewable");
static_assert(aeslib::detail::is_byte_viewable_v<SensorReading>,
              "a plain trivially copyable aggregate must be byte-viewable");

AESLIB_TEST(generic, ctr_round_trip_vector_uint8) {
    const SecretKey key = SecretKey::generate();
    const std::vector<std::uint8_t> plaintext{1, 2, 3, 4, 5, 250, 251, 252};
    const auto container = Aes256Ctr::encrypt(key, plaintext);
    const auto decrypted = Aes256Ctr::decrypt_as<std::vector<std::uint8_t>>(key, container);
    CHECK(decrypted == plaintext);
}

AESLIB_TEST(generic, ctr_round_trip_array_byte) {
    const SecretKey key = SecretKey::generate();
    std::array<std::byte, 16> plaintext{};
    for (std::size_t i = 0; i < plaintext.size(); ++i) {
        plaintext[i] = static_cast<std::byte>(i);
    }
    const auto container = Aes256Ctr::encrypt(key, plaintext);
    const auto decrypted = Aes256Ctr::decrypt_as<std::array<std::byte, 16>>(key, container);
    CHECK(decrypted == plaintext);
}

AESLIB_TEST(generic, ctr_round_trip_array_uint8) {
    const SecretKey key = SecretKey::generate();
    std::array<std::uint8_t, 8> plaintext{{9, 8, 7, 6, 5, 4, 3, 2}};
    const auto container = Aes256Ctr::encrypt(key, plaintext);
    const auto decrypted = Aes256Ctr::decrypt_as<std::array<std::uint8_t, 8>>(key, container);
    CHECK(decrypted == plaintext);
}

AESLIB_TEST(generic, ctr_round_trip_string) {
    const SecretKey key = SecretKey::generate();
    const std::string plaintext = "the quick brown fox jumps over the lazy dog";
    const auto container = Aes256Ctr::encrypt(key, plaintext);
    const auto decrypted = Aes256Ctr::decrypt_as<std::string>(key, container);
    CHECK_EQ(decrypted, plaintext);
}

AESLIB_TEST(generic, ctr_round_trip_vector_int32) {
    const SecretKey key = SecretKey::generate();
    const std::vector<std::int32_t> plaintext{-1, 0, 1, 42, -1000000, 2147483647};
    const auto container = Aes256Ctr::encrypt(key, plaintext);
    const auto decrypted = Aes256Ctr::decrypt_as<std::vector<std::int32_t>>(key, container);
    CHECK(decrypted == plaintext);
}

AESLIB_TEST(generic, ctr_round_trip_pod_struct) {
    const SecretKey key = SecretKey::generate();
    const SensorReading reading{
        42, 3.14f, {std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}}};
    const auto container = Aes256Ctr::encrypt(key, reading);
    const auto decrypted = Aes256Ctr::decrypt_as<SensorReading>(key, container);
    CHECK(decrypted == reading);
}

AESLIB_TEST(generic, ctr_decrypt_as_fixed_array_wrong_length_throws_format_error) {
    const SecretKey key = SecretKey::generate();
    const std::vector<std::byte> plaintext(5, std::byte{0}); // 5 bytes, not 4
    const auto container = Aes256Ctr::encrypt(key, plaintext);
    CHECK_THROWS((Aes256Ctr::decrypt_as<std::array<std::byte, 4>>(key, container)), FormatError);
}

AESLIB_TEST(generic, ctr_decrypt_as_vector_int32_non_multiple_length_throws_format_error) {
    const SecretKey key = SecretKey::generate();
    const std::vector<std::byte> plaintext(3, std::byte{0}); // 3 bytes, not a multiple of 4
    const auto container = Aes256Ctr::encrypt(key, plaintext);
    CHECK_THROWS((Aes256Ctr::decrypt_as<std::vector<std::int32_t>>(key, container)), FormatError);
}

AESLIB_TEST(generic, ctr_decrypt_as_struct_wrong_length_throws_format_error) {
    const SecretKey key = SecretKey::generate();
    const std::vector<std::byte> plaintext(sizeof(SensorReading) - 1, std::byte{0});
    const auto container = Aes256Ctr::encrypt(key, plaintext);
    CHECK_THROWS((Aes256Ctr::decrypt_as<SensorReading>(key, container)), FormatError);
}

AESLIB_TEST(generic, gcm_round_trip_vector_uint8_with_aad) {
    const SecretKey key = SecretKey::generate();
    const std::vector<std::uint8_t> plaintext{10, 20, 30, 40};
    const std::vector<std::byte> aad{std::byte{0xAA}, std::byte{0xBB}};
    const auto container = AesGcm::encrypt(key, plaintext, aad);
    const auto decrypted = AesGcm::decrypt_as<std::vector<std::uint8_t>>(key, container, aad);
    CHECK(decrypted == plaintext);
}

AESLIB_TEST(generic, gcm_round_trip_pod_struct) {
    const SecretKey key = SecretKey::generate();
    const SensorReading reading{
        7, -2.5f, {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}}};
    const auto container = AesGcm::encrypt(key, reading);
    const auto decrypted = AesGcm::decrypt_as<SensorReading>(key, container);
    CHECK(decrypted == reading);
}

AESLIB_TEST(generic, ctr_generic_encrypt_matches_vector_byte_baseline) {
    // Sanity check: encrypting via the template path (a byte-identical
    // container type) must produce ciphertext decryptable through the
    // untouched std::vector<std::byte> baseline path, proving the template
    // overload doesn't diverge from encrypt(vector<byte>).
    const SecretKey key = SecretKey::generate();
    const std::array<std::byte, 6> plaintext{std::byte{1}, std::byte{2}, std::byte{3},
                                              std::byte{4}, std::byte{5}, std::byte{6}};
    const auto container = Aes256Ctr::encrypt(key, plaintext);
    const std::vector<std::byte> decrypted = Aes256Ctr::decrypt(key, container);
    CHECK_EQ(decrypted.size(), plaintext.size());
    CHECK(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()) == 0);
}
