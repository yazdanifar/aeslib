#!/usr/bin/env python3
"""Minimal cross-language demo for aeslib's C ABI (bonus 3.8).

Mirrors main.cpp's harness shape but calls exclusively through the C ABI
(aeslib_ffi.py, a ctypes binding around include/aeslib/capi.h) rather than
linking the C++ library directly — proving the FFI surface actually works
end to end, not just compiles. Registered as the `aeslib.capi_python` CTest
test (see CMakeLists.txt) so this runs on every `ctest` invocation, not just
when someone remembers to run it by hand.

Exit code 0 on success, 1 on any failure (round-trip mismatch, unexpected
error, or a deliberately-tampered GCM tag *not* being rejected).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from aeslib_ffi import (  # noqa: E402
    AeslibError,
    BACKEND_HARDWARE,
    SecretKey,
    active_backend,
    ctr_decrypt,
    ctr_encrypt,
    gcm_decrypt,
    gcm_encrypt,
)

SAMPLE_PLAINTEXT = (
    b"The quick brown fox jumps over the lazy dog. "
    b"aeslib C ABI cross-language round-trip test payload.\n"
)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    backend_name = "Hardware" if active_backend() == BACKEND_HARDWARE else "Software"
    print(f"[python/ctypes] Backend in use: {backend_name}")

    # AES-256-CTR round trip.
    key = SecretKey.generate(256)
    nonce, ciphertext = ctr_encrypt(key, SAMPLE_PLAINTEXT)
    decrypted = ctr_decrypt(key, nonce, ciphertext)
    check(decrypted == SAMPLE_PLAINTEXT, "CTR round trip did not reproduce the original plaintext")
    check(ciphertext != SAMPLE_PLAINTEXT, "CTR ciphertext must not equal the plaintext")
    print(f"[python/ctypes] AES-256-CTR round trip OK ({len(SAMPLE_PLAINTEXT)} bytes)")

    # AES-256-GCM round trip, with AAD, plus a tamper-detection check.
    aad = b"aeslib-capi-demo-aad"
    gcm_nonce, tag, gcm_ciphertext = gcm_encrypt(key, SAMPLE_PLAINTEXT, aad)
    gcm_decrypted = gcm_decrypt(key, gcm_nonce, tag, gcm_ciphertext, aad)
    check(gcm_decrypted == SAMPLE_PLAINTEXT, "GCM round trip did not reproduce the original plaintext")
    print(f"[python/ctypes] AES-256-GCM round trip OK ({len(SAMPLE_PLAINTEXT)} bytes, with AAD)")

    tampered_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
    try:
        gcm_decrypt(key, gcm_nonce, tampered_tag, gcm_ciphertext, aad)
        raise AssertionError("tampered GCM tag was accepted instead of rejected")
    except AeslibError as e:
        check(e.status_name == "AESLIB_ERR_AUTHENTICATION",
              f"expected AESLIB_ERR_AUTHENTICATION for a tampered tag, got {e.status_name}")
        print("[python/ctypes] Tampered GCM tag correctly rejected (AESLIB_ERR_AUTHENTICATION)")

    print("[python/ctypes] SUCCESS")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001 — top-level harness: report and fail, not crash
        print(f"[python/ctypes] FAILURE: {e}", file=sys.stderr)
        sys.exit(1)
