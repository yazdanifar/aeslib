#pragma once

// Bonus: generic support for other types via templates.
//
// Lets Aes256Ctr/AesGcm's encrypt()/decrypt_as() work with more than
// std::vector<std::byte> by treating a caller's type as raw bytes — either
// element-wise (a container of trivially copyable elements: std::vector<T>,
// std::array<T,N>, std::string, ...) or as one opaque blob (a single
// trivially copyable object, e.g. a plain struct).
//
// C++17 (this project's target, see CMakeLists.txt) has no std::span or
// concepts, so "is this type safe to view as bytes" is expressed as SFINAE
// traits over std::is_trivially_copyable rather than a C++20 concept.
//
// std::is_trivially_copyable is necessary but not sufficient for "safe to
// persist": it only guarantees the *language* allows copying the object
// representation byte-for-byte (cppreference's TriviallyCopyable named
// requirement). A struct holding a raw pointer or a std::variant<...> that
// happens to be trivially copyable would still pass this check, but
// serializing its bytes to disk and reading them back in another process is
// meaningless. C++17 has no reflection to inspect member types, so this is a
// caller responsibility this trait cannot catch — documented in DESIGN.md,
// not silently swept under the rug.

#include <cstddef>
#include <cstring>
#include <type_traits>
#include <vector>

#include "aeslib/exceptions.hpp"

namespace aeslib::detail {

// Detects T::data()/T::size()/T::value_type — the shape shared by
// std::vector, std::array, std::basic_string, and similar contiguous
// containers.
template <typename T, typename = void>
struct has_contiguous_storage : std::false_type {};

template <typename T>
struct has_contiguous_storage<
    T, std::void_t<decltype(std::declval<T&>().data()), decltype(std::declval<T&>().size()),
                   typename T::value_type>> : std::true_type {};

// Detects T::resize(size_t) — distinguishes std::vector/std::string
// (resizable, decrypt_as() can size the result to fit) from std::array
// (fixed capacity, decrypt_as() must instead require an exact length match).
template <typename T, typename = void>
struct is_resizable : std::false_type {};

template <typename T>
struct is_resizable<T, std::void_t<decltype(std::declval<T&>().resize(std::size_t{}))>>
    : std::true_type {};

// A type is byte-viewable as a *container*: contiguous storage of a
// trivially copyable element type. The container itself need not be
// trivially copyable (std::string manages a heap buffer and isn't), only
// its elements need to be, since this path copies element-wise via
// data()/size() rather than reinterpreting the container object itself.
template <typename T, typename = void>
struct is_byte_container : std::false_type {};

template <typename T>
struct is_byte_container<
    T, std::enable_if_t<has_contiguous_storage<T>::value &&
                         std::is_trivially_copyable_v<typename T::value_type>>> : std::true_type {
};

// A type is byte-viewable as a single *object*: trivially copyable as a
// whole, and not itself a byte-container (a container is always handled
// element-wise above, never as one undifferentiated blob).
template <typename T>
struct is_byte_object
    : std::bool_constant<std::is_trivially_copyable_v<T> && !is_byte_container<T>::value> {};

template <typename T>
struct is_byte_viewable
    : std::bool_constant<is_byte_container<T>::value || is_byte_object<T>::value> {};

template <typename T>
inline constexpr bool is_byte_viewable_v = is_byte_viewable<T>::value;

// --- T -> bytes ---

template <typename T, std::enable_if_t<is_byte_container<T>::value, int> = 0>
std::vector<std::byte> to_byte_vector(const T& value) {
    const auto* p = reinterpret_cast<const std::byte*>(value.data());
    return std::vector<std::byte>(p, p + value.size() * sizeof(typename T::value_type));
}

template <typename T, std::enable_if_t<is_byte_object<T>::value, int> = 0>
std::vector<std::byte> to_byte_vector(const T& value) {
    const auto* p = reinterpret_cast<const std::byte*>(std::addressof(value));
    return std::vector<std::byte>(p, p + sizeof(T));
}

// --- bytes -> T ---

// Resizable byte-container (std::vector<X>, std::string): sized to fit the
// decrypted byte count, which must be a whole multiple of the element size.
template <typename T,
          std::enable_if_t<is_byte_container<T>::value && is_resizable<T>::value, int> = 0>
T from_byte_vector(const std::vector<std::byte>& bytes) {
    using Elem = typename T::value_type;
    if (bytes.size() % sizeof(Elem) != 0) {
        throw FormatError("decrypted byte length is not a whole multiple of the target element size");
    }
    T out;
    out.resize(bytes.size() / sizeof(Elem));
    std::memcpy(out.data(), bytes.data(), bytes.size());
    return out;
}

// Fixed-capacity byte-container (std::array<X, N>): capacity can't change,
// so the decrypted byte count must match it exactly.
template <typename T,
          std::enable_if_t<is_byte_container<T>::value && !is_resizable<T>::value, int> = 0>
T from_byte_vector(const std::vector<std::byte>& bytes) {
    T out{};
    if (bytes.size() != out.size() * sizeof(typename T::value_type)) {
        throw FormatError("decrypted byte length does not match the fixed-size container's capacity");
    }
    std::memcpy(out.data(), bytes.data(), bytes.size());
    return out;
}

// Byte-object (a single trivially copyable value, e.g. a plain struct): the
// decrypted byte count must match sizeof(T) exactly.
template <typename T, std::enable_if_t<is_byte_object<T>::value, int> = 0>
T from_byte_vector(const std::vector<std::byte>& bytes) {
    if (bytes.size() != sizeof(T)) {
        throw FormatError("decrypted byte length does not match sizeof(T)");
    }
    T out;
    std::memcpy(std::addressof(out), bytes.data(), sizeof(T));
    return out;
}

} // namespace aeslib::detail
