#include <filesystem>
#include <vector>

#include "aeslib/container.hpp"
#include "aeslib/exceptions.hpp"
#include "test_support.hpp"

namespace {

using aeslib::Container;
using aeslib::FormatError;

Container make_container() {
    Container c;
    for (std::size_t i = 0; i < c.nonce.size(); ++i) c.nonce[i] = static_cast<std::byte>(i);
    c.ciphertext = {std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}, std::byte{5}};
    return c;
}

} // namespace

AESLIB_TEST(container, serialize_deserialize_round_trip) {
    const Container original = make_container();
    const auto bytes = aeslib::serialize(original);
    const Container restored = aeslib::deserialize(bytes);
    CHECK(restored.nonce == original.nonce);
    CHECK_EQ(restored.ciphertext, original.ciphertext);
}

AESLIB_TEST(container, empty_ciphertext_round_trips) {
    Container original = make_container();
    original.ciphertext.clear();
    const auto bytes = aeslib::serialize(original);
    const Container restored = aeslib::deserialize(bytes);
    CHECK(restored.ciphertext.empty());
}

AESLIB_TEST(container, rejects_bad_magic) {
    auto bytes = aeslib::serialize(make_container());
    bytes[0] = std::byte{'X'};
    CHECK_THROWS(aeslib::deserialize(bytes), FormatError);
}

AESLIB_TEST(container, rejects_unsupported_version) {
    auto bytes = aeslib::serialize(make_container());
    bytes[4] = static_cast<std::byte>(aeslib::kContainerVersion + 1);
    CHECK_THROWS(aeslib::deserialize(bytes), FormatError);
}

AESLIB_TEST(container, rejects_truncated_header) {
    std::vector<std::byte> bytes(3, std::byte{0});
    CHECK_THROWS(aeslib::deserialize(bytes), FormatError);
}

AESLIB_TEST(container, rejects_ciphertext_length_mismatch) {
    auto bytes = aeslib::serialize(make_container());
    bytes.pop_back(); // truncate ciphertext by one byte without updating ct_len
    CHECK_THROWS(aeslib::deserialize(bytes), FormatError);
}

AESLIB_TEST(container, file_round_trip) {
    const Container original = make_container();
    const auto path = std::filesystem::temp_directory_path() / "aeslib_test_container.aesc";
    aeslib::save_container(original, path);
    const Container restored = aeslib::load_container(path);
    std::filesystem::remove(path);
    CHECK(restored.nonce == original.nonce);
    CHECK_EQ(restored.ciphertext, original.ciphertext);
}

AESLIB_TEST(container, load_missing_file_throws_io_error) {
    const auto path = std::filesystem::temp_directory_path() / "aeslib_test_does_not_exist.aesc";
    CHECK_THROWS(aeslib::load_container(path), aeslib::IoError);
}
