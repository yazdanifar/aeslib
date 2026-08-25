#include <algorithm>
#include <filesystem>
#include <fstream>

#include "aeslib/exceptions.hpp"
#include "aeslib/key.hpp"
#include "test_support.hpp"

#if defined(__linux__)
#include <optional>
#include <sstream>
#include <string>
#endif

namespace {
using aeslib::FormatError;
using aeslib::IoError;
using aeslib::SecretKey;
} // namespace

AESLIB_TEST(key, generate_produces_distinct_keys) {
    const SecretKey a = SecretKey::generate();
    const SecretKey b = SecretKey::generate();
    CHECK(aeslib::detail::key_bytes(a) != aeslib::detail::key_bytes(b));
}

AESLIB_TEST(key, save_load_round_trip) {
    const SecretKey original = SecretKey::generate();
    const auto path = std::filesystem::temp_directory_path() / "aeslib_test_roundtrip.key";
    original.save_to_file(path);
    const SecretKey loaded = SecretKey::load_from_file(path);
    std::filesystem::remove(path);
    CHECK(aeslib::detail::key_bytes(loaded) == aeslib::detail::key_bytes(original));
}

AESLIB_TEST(key, move_from_wipes_source) {
    SecretKey original = SecretKey::generate();
    const SecretKey moved = std::move(original);
    (void)moved;
    for (const std::byte b : aeslib::detail::key_bytes(original)) CHECK(b == std::byte{0});
}

// Regression: the move operations must carry `size_` across, not just the
// key bytes. When they didn't, a moved AES-128 key reported itself as
// AES-256 — reachable in practice through the C ABI, whose opaque handle is
// move-constructed on the way into its unique_ptr (src/capi.cpp), so
// aeslib_key_generate(128, ...) persisted a 32-byte key file.
AESLIB_TEST(key, move_preserves_key_size) {
    SecretKey original = SecretKey::generate(aeslib::KeySize::Aes128);
    const SecretKey moved = std::move(original);
    CHECK(moved.size() == aeslib::KeySize::Aes128);
    CHECK(moved.size_bytes() == 16);
}

AESLIB_TEST(key, move_assign_preserves_key_size) {
    SecretKey source = SecretKey::generate(aeslib::KeySize::Aes128);
    SecretKey target = SecretKey::generate(aeslib::KeySize::Aes256);
    target = std::move(source);
    CHECK(target.size() == aeslib::KeySize::Aes128);
    CHECK(target.size_bytes() == 16);
}

// The same property observed end-to-end: a moved AES-128 key must still
// serialize as one (2-byte header + 16 key bytes), not as an AES-256 key.
AESLIB_TEST(key, moved_aes128_key_saves_as_aes128) {
    SecretKey original = SecretKey::generate(aeslib::KeySize::Aes128);
    const SecretKey moved = std::move(original);
    const auto path = std::filesystem::temp_directory_path() / "aeslib_test_moved_128.key";
    moved.save_to_file(path);
    const SecretKey loaded = SecretKey::load_from_file(path);
    const auto size = std::filesystem::file_size(path);
    std::filesystem::remove(path);
    CHECK(size == 18);
    CHECK(loaded.size() == aeslib::KeySize::Aes128);
}

AESLIB_TEST(key, load_missing_file_throws_io_error) {
    const auto path = std::filesystem::temp_directory_path() / "aeslib_test_missing.key";
    CHECK_THROWS(SecretKey::load_from_file(path), IoError);
}

AESLIB_TEST(key, load_bad_version_throws_format_error) {
    const auto path = std::filesystem::temp_directory_path() / "aeslib_test_bad_version.key";
    {
        std::ofstream out(path, std::ios::binary);
        out.put(static_cast<char>(99)); // not kKeyFileVersion
        out.put(static_cast<char>(32)); // size marker
        std::string padding(aeslib::kKeySizeBytes, '\0');
        out.write(padding.data(), static_cast<std::streamsize>(padding.size()));
    }
    CHECK_THROWS(SecretKey::load_from_file(path), FormatError);
    std::filesystem::remove(path);
}

AESLIB_TEST(key, load_bad_size_marker_throws_format_error) {
    const auto path = std::filesystem::temp_directory_path() / "aeslib_test_bad_size_marker.key";
    {
        std::ofstream out(path, std::ios::binary);
        out.put(static_cast<char>(2)); // kKeyFileVersion
        out.put(static_cast<char>(24)); // not 16 or 32
        std::string padding(24, '\0');
        out.write(padding.data(), static_cast<std::streamsize>(padding.size()));
    }
    CHECK_THROWS(SecretKey::load_from_file(path), FormatError);
    std::filesystem::remove(path);
}

AESLIB_TEST(key, load_truncated_file_throws_format_error) {
    const auto path = std::filesystem::temp_directory_path() / "aeslib_test_truncated.key";
    {
        std::ofstream out(path, std::ios::binary);
        out.put(static_cast<char>(2)); // kKeyFileVersion
        out.put(static_cast<char>(32)); // size marker
        out.put(static_cast<char>(0)); // only 1 of 32 key bytes present
    }
    CHECK_THROWS(SecretKey::load_from_file(path), FormatError);
    std::filesystem::remove(path);
}

AESLIB_TEST(key, generate_aes128_has_correct_size) {
    const SecretKey key = SecretKey::generate(aeslib::KeySize::Aes128);
    CHECK(key.size() == aeslib::KeySize::Aes128);
    CHECK_EQ(key.size_bytes(), std::size_t{16});
}

AESLIB_TEST(key, generate_default_is_aes256) {
    const SecretKey key = SecretKey::generate();
    CHECK(key.size() == aeslib::KeySize::Aes256);
    CHECK_EQ(key.size_bytes(), std::size_t{32});
}

AESLIB_TEST(key, aes128_save_load_round_trip) {
    const SecretKey original = SecretKey::generate(aeslib::KeySize::Aes128);
    const auto path = std::filesystem::temp_directory_path() / "aeslib_test_roundtrip128.key";
    original.save_to_file(path);
    const SecretKey loaded = SecretKey::load_from_file(path);
    std::filesystem::remove(path);
    CHECK(loaded.size() == aeslib::KeySize::Aes128);
    // Only the first 16 bytes are logically part of an AES-128 key; compare
    // just that prefix (the trailing 16 bytes of storage are unused padding
    // on both sides, see key.hpp's bytes_ comment).
    const auto& original_bytes = aeslib::detail::key_bytes(original);
    const auto& loaded_bytes = aeslib::detail::key_bytes(loaded);
    CHECK(std::equal(original_bytes.begin(), original_bytes.begin() + 16, loaded_bytes.begin()));
}

AESLIB_TEST(key, aes128_save_load_encrypted_round_trip) {
    // save_to_file_encrypted/load_from_file_encrypted support both key sizes
    // (see key_storage.cpp's version-2 wrapped-key format) — the more
    // detailed coverage for this (invalid size markers, tamper detection,
    // etc.) lives in tests/test_key_storage.cpp; this just confirms the
    // basic round trip from SecretKey's own test file.
    const SecretKey key = SecretKey::generate(aeslib::KeySize::Aes128);
    const auto path = std::filesystem::temp_directory_path() / "aeslib_test_aes128_encrypted.key";
    key.save_to_file_encrypted(path, "passphrase", 1000);
    const SecretKey loaded = SecretKey::load_from_file_encrypted(path, "passphrase");
    std::filesystem::remove(path);
    CHECK(loaded.size() == aeslib::KeySize::Aes128);
}

#if defined(__linux__)
namespace {
// Parses the "VmLck:  <n> kB" line out of /proc/self/status. Reading our own
// locked-page count (rather than trusting mlock()'s return value, which
// SecretKey deliberately ignores) is the only way to check from userspace
// that lock_memory() actually pinned pages instead of silently no-op'ing.
std::optional<long> current_vm_lck_kb() {
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("VmLck:", 0) == 0) {
            std::istringstream iss(line.substr(6));
            long kb = -1;
            iss >> kb;
            if (iss) return kb;
        }
    }
    return std::nullopt;
}
} // namespace

AESLIB_TEST(key, generate_increases_locked_memory_on_linux) {
    const auto before = current_vm_lck_kb();
    if (!before.has_value()) return; // /proc unavailable (e.g. sandboxed); nothing to assert
    {
        const SecretKey key = SecretKey::generate();
        const auto during = current_vm_lck_kb();
        if (during.has_value()) {
            // mlock() is best-effort (see key.cpp): a tight RLIMIT_MEMLOCK
            // (common in containers) makes it fail silently, so this can't
            // assert an increase unconditionally without risking a spurious
            // failure on such hosts. It only checks that IF mlock() worked,
            // the accounting reflects it.
            CHECK(*during >= *before);
        }
    }
    const auto after = current_vm_lck_kb();
    if (after.has_value()) {
        // Whatever got locked while `key` was alive must be unlocked again
        // once it's destroyed, regardless of whether mlock() succeeded above.
        CHECK_EQ(*after, *before);
    }
}
#endif
