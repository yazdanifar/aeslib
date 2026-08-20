"""ctypes binding for aeslib's C ABI (include/aeslib/capi.h).

Minimal example of calling the library from a language other than C++, per
the challenge's "Foreign-language interface" bonus. See demo.py for usage
and DESIGN.md's "Foreign-language interface" section for the design
rationale (opaque handles, status codes instead of exceptions crossing the
boundary, buffer ownership).
"""

import ctypes
import os
import platform
from ctypes import POINTER, c_char_p, c_int, c_size_t, c_uint8, c_void_p

NONCE_BYTES = 12
TAG_BYTES = 16

_STATUS_NAMES = {
    0: "AESLIB_OK",
    1: "AESLIB_ERR_INVALID_ARGUMENT",
    2: "AESLIB_ERR_IO",
    3: "AESLIB_ERR_FORMAT",
    4: "AESLIB_ERR_LIMIT",
    5: "AESLIB_ERR_AUTHENTICATION",
    6: "AESLIB_ERR_UNKNOWN",
}

BACKEND_SOFTWARE = 0
BACKEND_HARDWARE = 1


class AeslibError(RuntimeError):
    """Raised when an aeslib_* call returns a status other than AESLIB_OK.

    `status` is the raw integer aeslib_status value; `status_name` is its
    symbolic name (see include/aeslib/capi.h).
    """

    def __init__(self, status: int, message: str):
        self.status = status
        self.status_name = _STATUS_NAMES.get(status, f"UNKNOWN({status})")
        super().__init__(f"{self.status_name}: {message}")


def _default_library_names():
    system = platform.system()
    if system == "Windows":
        return ["aeslib_c.dll"]
    if system == "Darwin":
        return ["libaeslib_c.dylib"]
    return ["libaeslib_c.so"]


def _find_library_path() -> str:
    """Locates the aeslib_c shared library.

    Prefers the AESLIB_C_LIBRARY_PATH env var (set by the CTest
    aeslib.capi_python test, via CMake's $<TARGET_FILE:aeslib_c>), falling
    back to a couple of common build-directory locations for manual runs
    from the repository root.
    """
    env_path = os.environ.get("AESLIB_C_LIBRARY_PATH")
    if env_path:
        return env_path

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    candidate_dirs = [
        os.path.join(repo_root, "build"),
        os.path.join(repo_root, "build", "Release"),
        os.path.join(repo_root, "build-san"),
    ]
    for directory in candidate_dirs:
        for name in _default_library_names():
            candidate = os.path.join(directory, name)
            if os.path.exists(candidate):
                return candidate

    raise FileNotFoundError(
        "could not locate the aeslib_c shared library; set AESLIB_C_LIBRARY_PATH "
        "to its full path (e.g. build/libaeslib_c.dylib after building with "
        "-DAESLIB_BUILD_C_API=ON)"
    )


_lib = ctypes.CDLL(_find_library_path())

# Every exported function gets explicit argtypes/restype: ctypes performs no
# automatic type checking otherwise, and a mismatched signature here is a
# silent memory-corruption bug rather than a Python exception.
_lib.aeslib_last_error_message.argtypes = []
_lib.aeslib_last_error_message.restype = c_char_p

_lib.aeslib_active_backend.argtypes = []
_lib.aeslib_active_backend.restype = c_int

_lib.aeslib_key_generate.argtypes = [c_int, POINTER(c_void_p)]
_lib.aeslib_key_generate.restype = c_int

_lib.aeslib_key_free.argtypes = [c_void_p]
_lib.aeslib_key_free.restype = None

_lib.aeslib_key_save_to_file.argtypes = [c_void_p, c_char_p]
_lib.aeslib_key_save_to_file.restype = c_int

_lib.aeslib_key_load_from_file.argtypes = [c_char_p, POINTER(c_void_p)]
_lib.aeslib_key_load_from_file.restype = c_int

_lib.aeslib_ctr_encrypt.argtypes = [
    c_void_p, POINTER(c_uint8), c_size_t, POINTER(c_uint8),
    POINTER(POINTER(c_uint8)), POINTER(c_size_t),
]
_lib.aeslib_ctr_encrypt.restype = c_int

_lib.aeslib_ctr_decrypt.argtypes = [
    c_void_p, POINTER(c_uint8), POINTER(c_uint8), c_size_t,
    POINTER(POINTER(c_uint8)), POINTER(c_size_t),
]
_lib.aeslib_ctr_decrypt.restype = c_int

_lib.aeslib_gcm_encrypt.argtypes = [
    c_void_p, POINTER(c_uint8), c_size_t, POINTER(c_uint8), c_size_t,
    POINTER(c_uint8), POINTER(c_uint8), POINTER(POINTER(c_uint8)), POINTER(c_size_t),
]
_lib.aeslib_gcm_encrypt.restype = c_int

_lib.aeslib_gcm_decrypt.argtypes = [
    c_void_p, POINTER(c_uint8), POINTER(c_uint8), POINTER(c_uint8), c_size_t,
    POINTER(c_uint8), c_size_t, POINTER(POINTER(c_uint8)), POINTER(c_size_t),
]
_lib.aeslib_gcm_decrypt.restype = c_int

_lib.aeslib_buffer_free.argtypes = [POINTER(c_uint8)]
_lib.aeslib_buffer_free.restype = None


def _check(status: int) -> None:
    if status != 0:
        raise AeslibError(status, _lib.aeslib_last_error_message().decode("utf-8", "replace"))


def _to_uint8_array(data: bytes):
    buf = (c_uint8 * len(data))(*data)
    return ctypes.cast(buf, POINTER(c_uint8)) if len(data) else None


def _take_buffer(ptr, length: int) -> bytes:
    if length == 0:
        _lib.aeslib_buffer_free(ptr)
        return b""
    data = bytes(ctypes.cast(ptr, POINTER(c_uint8 * length)).contents)
    _lib.aeslib_buffer_free(ptr)
    return data


def active_backend() -> int:
    """Returns BACKEND_HARDWARE or BACKEND_SOFTWARE (see aeslib::active_backend())."""
    return _lib.aeslib_active_backend()


class SecretKey:
    """Wraps an aeslib_key_t handle; frees it via aeslib_key_free() on __del__.

    Not a full replacement for the C++ SecretKey's hardening (mlock/wipe) —
    this binding's job is demonstrating the C ABI, not re-implementing
    bonus 3.6 in Python.
    """

    def __init__(self, handle: ctypes.c_void_p):
        self._handle = handle

    @classmethod
    def generate(cls, key_size_bits: int = 256) -> "SecretKey":
        handle = c_void_p()
        _check(_lib.aeslib_key_generate(key_size_bits, ctypes.byref(handle)))
        return cls(handle)

    @classmethod
    def load_from_file(cls, path: str) -> "SecretKey":
        handle = c_void_p()
        _check(_lib.aeslib_key_load_from_file(path.encode("utf-8"), ctypes.byref(handle)))
        return cls(handle)

    def save_to_file(self, path: str) -> None:
        _check(_lib.aeslib_key_save_to_file(self._handle, path.encode("utf-8")))

    def close(self) -> None:
        if self._handle:
            _lib.aeslib_key_free(self._handle)
            self._handle = c_void_p()

    def __del__(self):
        self.close()


def ctr_encrypt(key: SecretKey, plaintext: bytes):
    """Returns (nonce: bytes, ciphertext: bytes)."""
    nonce = (c_uint8 * NONCE_BYTES)()
    out_ptr = POINTER(c_uint8)()
    out_len = c_size_t()
    _check(
        _lib.aeslib_ctr_encrypt(
            key._handle, _to_uint8_array(plaintext), len(plaintext), nonce,
            ctypes.byref(out_ptr), ctypes.byref(out_len),
        )
    )
    return bytes(nonce), _take_buffer(out_ptr, out_len.value)


def ctr_decrypt(key: SecretKey, nonce: bytes, ciphertext: bytes) -> bytes:
    nonce_buf = (c_uint8 * NONCE_BYTES)(*nonce)
    out_ptr = POINTER(c_uint8)()
    out_len = c_size_t()
    _check(
        _lib.aeslib_ctr_decrypt(
            key._handle, nonce_buf, _to_uint8_array(ciphertext), len(ciphertext),
            ctypes.byref(out_ptr), ctypes.byref(out_len),
        )
    )
    return _take_buffer(out_ptr, out_len.value)


def gcm_encrypt(key: SecretKey, plaintext: bytes, aad: bytes = b""):
    """Returns (nonce: bytes, tag: bytes, ciphertext: bytes)."""
    nonce = (c_uint8 * NONCE_BYTES)()
    tag = (c_uint8 * TAG_BYTES)()
    out_ptr = POINTER(c_uint8)()
    out_len = c_size_t()
    _check(
        _lib.aeslib_gcm_encrypt(
            key._handle, _to_uint8_array(plaintext), len(plaintext), _to_uint8_array(aad),
            len(aad), nonce, tag, ctypes.byref(out_ptr), ctypes.byref(out_len),
        )
    )
    return bytes(nonce), bytes(tag), _take_buffer(out_ptr, out_len.value)


def gcm_decrypt(key: SecretKey, nonce: bytes, tag: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    nonce_buf = (c_uint8 * NONCE_BYTES)(*nonce)
    tag_buf = (c_uint8 * TAG_BYTES)(*tag)
    out_ptr = POINTER(c_uint8)()
    out_len = c_size_t()
    _check(
        _lib.aeslib_gcm_decrypt(
            key._handle, nonce_buf, tag_buf, _to_uint8_array(ciphertext), len(ciphertext),
            _to_uint8_array(aad), len(aad), ctypes.byref(out_ptr), ctypes.byref(out_len),
        )
    )
    return _take_buffer(out_ptr, out_len.value)
