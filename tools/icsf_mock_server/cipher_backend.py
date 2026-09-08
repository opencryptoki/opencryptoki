# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
cipher_backend.py — AES / DES / 3DES ECB/CBC/CBC-PAD via ctypes → libcrypto.

Uses OpenSSL's EVP API through ctypes so no third-party Python packages are
needed.  libcrypto.so is always present on any Linux system that has OpenSSL
installed (which is required by the LDAP stack openCryptoki itself depends on).

Public API
----------
aes_encrypt(key, plaintext, mode, iv=None) -> bytes
aes_decrypt(key, ciphertext, mode, iv=None) -> bytes

mode is one of the strings: 'ECB', 'CBC', 'CBC-PAD'

For ECB and CBC the caller is responsible for block-aligning the data.
For CBC-PAD this module applies/strips PKCS#7 padding automatically.
"""

import ctypes
import ctypes.util
import os

# ---------------------------------------------------------------------------
# Load libcrypto
# ---------------------------------------------------------------------------

def _load_libcrypto():
    # Try the generic name first, then version-suffixed names.
    for name in ('crypto', 'ssl'):
        path = ctypes.util.find_library(name)
        if path:
            try:
                return ctypes.CDLL(path)
            except OSError:
                pass
    # Fallback: try common absolute paths
    for path in ('/lib/x86_64-linux-gnu/libcrypto.so.3',
                 '/lib/x86_64-linux-gnu/libcrypto.so.1.1',
                 '/usr/lib/x86_64-linux-gnu/libcrypto.so.3',
                 '/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1',
                 '/lib/s390x-linux-gnu/libcrypto.so.3',
                 '/lib/s390x-linux-gnu/libcrypto.so.1.1',
                 '/usr/lib/libcrypto.so.3',
                 '/usr/lib/libcrypto.so.1.1',
                 'libcrypto.so.3',
                 'libcrypto.so.1.1',
                 'libcrypto.so'):
        try:
            return ctypes.CDLL(path)
        except OSError:
            pass
    raise ImportError(
        'Cannot find libcrypto.so — install OpenSSL (libssl-dev / openssl-libs)')


_libcrypto = _load_libcrypto()

# ---------------------------------------------------------------------------
# OpenSSL 3.x provider loading
#
# Single-DES (EVP_des_ecb / EVP_des_cbc) is a "legacy" algorithm in OpenSSL
# 3.x.  Without the legacy provider loaded, EVP_des_*() returns a non-NULL
# descriptor but EVP_EncryptInit_ex / EVP_DecryptInit_ex fail at runtime
# because there is no implementation available.
#
# We attempt to load both the "legacy" and "default" providers.  On OpenSSL
# 1.x these symbols do not exist; getattr returns None and we skip silently.
# On OpenSSL 3.x, loading "legacy" enables DES/3DES/RC4/RC2/CAST/IDEA/SEED;
# "default" must also be loaded explicitly once any provider is loaded
# manually (otherwise AES etc. stop working).
# ---------------------------------------------------------------------------

def _load_ossl_providers():
    load_fn = getattr(_libcrypto, 'OSSL_PROVIDER_load', None)
    if load_fn is None:
        return   # OpenSSL 1.x — providers not supported, nothing to do

    load_fn.restype  = ctypes.c_void_p
    load_fn.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

    # "default" must come first so it stays the default dispatch target.
    for name in (b'default', b'legacy'):
        handle = load_fn(None, name)
        if not handle:
            import logging as _logging
            _logging.getLogger(__name__).warning(
                'cipher_backend: OSSL_PROVIDER_load(%r) returned NULL — '
                'install the openssl-legacy package (or libssl-dev on '
                'Debian/Ubuntu) so single-DES operations work', name.decode())

    # OpenSSL 3.x (especially 3.5) enforces a default security level that
    # blocks SHA-1 for signing.  For a mock/test server that must emulate
    # ICSF's full algorithm support (including legacy SHA-1), reset the
    # global property query string to empty so no algorithms are excluded.
    # Equivalent to setting CipherString=DEFAULT:@SECLEVEL=0 in openssl.cnf,
    # but scoped to this process only.
    set_props_fn = getattr(_libcrypto, 'EVP_set_default_properties', None)
    if set_props_fn is not None:
        set_props_fn.restype  = ctypes.c_int
        set_props_fn.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        set_props_fn(None, b'')


_load_ossl_providers()

# ---------------------------------------------------------------------------
# Minimal EVP wrappers
# ---------------------------------------------------------------------------

_libcrypto.EVP_CIPHER_CTX_new.restype  = ctypes.c_void_p
_libcrypto.EVP_CIPHER_CTX_new.argtypes = []

_libcrypto.EVP_CIPHER_CTX_free.restype  = None
_libcrypto.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]

_libcrypto.EVP_EncryptInit_ex.restype  = ctypes.c_int
_libcrypto.EVP_EncryptInit_ex.argtypes = [
    ctypes.c_void_p,   # ctx
    ctypes.c_void_p,   # type (EVP_CIPHER *)
    ctypes.c_void_p,   # impl (ENGINE *, usually NULL)
    ctypes.c_void_p,   # key  (raw bytes — c_char_p would truncate at \x00)
    ctypes.c_void_p,   # iv   (raw bytes)
]

_libcrypto.EVP_EncryptUpdate.restype  = ctypes.c_int
_libcrypto.EVP_EncryptUpdate.argtypes = [
    ctypes.c_void_p,   # ctx
    ctypes.c_char_p,   # out
    ctypes.POINTER(ctypes.c_int),  # outl
    ctypes.c_char_p,   # in
    ctypes.c_int,      # inl
]

_libcrypto.EVP_EncryptFinal_ex.restype  = ctypes.c_int
_libcrypto.EVP_EncryptFinal_ex.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_int),
]

_libcrypto.EVP_DecryptInit_ex.restype  = ctypes.c_int
_libcrypto.EVP_DecryptInit_ex.argtypes = [
    ctypes.c_void_p,   # ctx
    ctypes.c_void_p,   # type (EVP_CIPHER *)
    ctypes.c_void_p,   # impl (ENGINE *, usually NULL)
    ctypes.c_void_p,   # key  (raw bytes — c_char_p would truncate at \x00)
    ctypes.c_void_p,   # iv   (raw bytes)
]

_libcrypto.EVP_DecryptUpdate.restype  = ctypes.c_int
_libcrypto.EVP_DecryptUpdate.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_int),
    ctypes.c_char_p,
    ctypes.c_int,
]

_libcrypto.EVP_DecryptFinal_ex.restype  = ctypes.c_int
_libcrypto.EVP_DecryptFinal_ex.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_int),
]

_libcrypto.EVP_CIPHER_CTX_set_padding.restype  = ctypes.c_int
_libcrypto.EVP_CIPHER_CTX_set_padding.argtypes = [ctypes.c_void_p, ctypes.c_int]

# EVP_aes_*() / EVP_des_*() cipher selectors
for _sym in ('EVP_aes_128_ecb', 'EVP_aes_192_ecb', 'EVP_aes_256_ecb',
             'EVP_aes_128_cbc', 'EVP_aes_192_cbc', 'EVP_aes_256_cbc',
             'EVP_des_ede3_ecb', 'EVP_des_ede3_cbc',
             'EVP_des_ecb', 'EVP_des_cbc'):
    fn = getattr(_libcrypto, _sym, None)
    if fn is not None:
        fn.restype  = ctypes.c_void_p
        fn.argtypes = []

AES_BLOCK = 16
DES_BLOCK  = 8

# ---------------------------------------------------------------------------
# Cipher selector
# ---------------------------------------------------------------------------

def _evp_cipher(algo, key_len, mode_str):
    """Return the EVP_CIPHER* for the given algorithm, key length, and mode."""
    if algo == 'AES':
        bits = key_len * 8
        if mode_str == 'ECB':
            fn_name = {128: 'EVP_aes_128_ecb',
                       192: 'EVP_aes_192_ecb',
                       256: 'EVP_aes_256_ecb'}[bits]
        else:  # CBC / CBC-PAD
            fn_name = {128: 'EVP_aes_128_cbc',
                       192: 'EVP_aes_192_cbc',
                       256: 'EVP_aes_256_cbc'}[bits]
    elif algo == 'DES3' or (algo == 'DES' and key_len != 8):
        # 24-byte DES3 key, or a DES2 key that _evp_crypt already expanded to
        # 24 bytes (key[:8]+key[8:16]+key[:8]) before calling here.
        fn_name = 'EVP_des_ede3_ecb' if mode_str == 'ECB' else 'EVP_des_ede3_cbc'
    else:  # single DES (8-byte key)
        fn_name = 'EVP_des_ecb' if mode_str == 'ECB' else 'EVP_des_cbc'

    fn = getattr(_libcrypto, fn_name, None)
    if fn is None:
        raise ValueError('libcrypto does not export %s' % fn_name)
    result = fn()
    if not result:
        raise ValueError('%s() returned NULL' % fn_name)
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def aes_encrypt(key: bytes, plaintext: bytes, mode: str,
                iv: bytes = None, algo: str = None,
                pad: bool = None) -> bytes:
    """
    Encrypt plaintext with AES (or DES/3DES) using the given mode.

    mode    : 'ECB', 'CBC', or 'CBC-PAD'
    iv      : 16-byte IV for CBC/CBC-PAD; ignored for ECB
    key     : raw key bytes (16/24/32 for AES; 8 for DES; 16/24 for 3DES)
    algo    : 'AES', 'DES', or 'DES3'; inferred from key length if omitted
    pad     : override PKCS#7 padding behaviour; defaults to True for
              CBC-PAD, False for ECB/CBC.  Pass False for INITIAL/CONTINUE
              calls of a multipart CBC-PAD sequence.

    ECB/CBC: caller must supply block-aligned data; no padding is added.
    CBC-PAD: PKCS#7 padding is applied automatically (last chunk only).
    """
    if pad is None:
        pad = (mode == 'CBC-PAD')
    return _evp_crypt(key, plaintext, mode, iv, encrypt=True, algo=algo,
                      use_padding=pad)


def aes_decrypt(key: bytes, ciphertext: bytes, mode: str,
                iv: bytes = None, algo: str = None,
                pad: bool = None) -> bytes:
    """
    Decrypt ciphertext with AES (or DES/3DES) using the given mode.

    ECB/CBC: no unpadding (output length == input length).
    CBC-PAD: PKCS#7 padding is stripped automatically (last chunk only).
    algo    : 'AES', 'DES', or 'DES3'; inferred from key length if omitted
    pad     : override unpadding; defaults to True for CBC-PAD.  Pass False
              for INITIAL/CONTINUE calls of a multipart CBC-PAD sequence.
    """
    if pad is None:
        pad = (mode == 'CBC-PAD')
    return _evp_crypt(key, ciphertext, mode, iv, encrypt=False, algo=algo,
                      use_padding=pad)


# ---------------------------------------------------------------------------
# Internal implementation
# ---------------------------------------------------------------------------

def _algo_for_key(key):
    """Infer algorithm from key length."""
    n = len(key)
    if n in (16, 24, 32):
        return 'AES'
    if n == 8:
        return 'DES'
    # DES3 with 16 or 24 bytes is handled by EVP_des_ede3_*
    return 'DES3'


def _evp_crypt(key: bytes, data: bytes, mode: str, iv: bytes,
               encrypt: bool, algo: str = None,
               use_padding: bool = False) -> bytes:
    if algo is None:
        algo = _algo_for_key(key)

    # DES2 uses a 16-byte key (EDE2: K1=K3).  EVP_des_ede3_* always expects
    # exactly 24 bytes regardless of the variant; passing 16 bytes causes
    # OpenSSL to read 8 undefined bytes for K3, producing different results
    # in EVP_EncryptInit_ex vs EVP_DecryptInit_ex.  Expand explicitly so K3
    # equals K1, which is the correct DES2 definition.
    if algo != 'AES' and len(key) == 16:
        key = key + key[:8]

    block = AES_BLOCK if algo == 'AES' else DES_BLOCK

    # For ECB/CBC OpenSSL still needs an IV buffer; pass zeros if none supplied.
    if iv is None or mode == 'ECB':
        iv_buf = b'\x00' * block
    else:
        iv_buf = (iv + b'\x00' * block)[:block]

    evp_type = _evp_cipher(algo, len(key), mode)
    ctx = _libcrypto.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError('EVP_CIPHER_CTX_new failed')

    try:
        # Allocate output buffer large enough for data + one extra block (padding)
        out_buf = ctypes.create_string_buffer(len(data) + block)
        outl    = ctypes.c_int(0)
        final_buf = ctypes.create_string_buffer(block)
        finall    = ctypes.c_int(0)

        # Wrap key, IV, and data in ctypes buffers so raw byte pointers are
        # passed to OpenSSL without null-termination truncation.  A plain Python
        # bytes object passed as c_char_p is silently truncated at the first
        # \x00 byte, which breaks DES/AES keys, IVs, and ciphertext that contain
        # null bytes.
        key_buf  = ctypes.create_string_buffer(key, len(key))
        iv_c     = ctypes.create_string_buffer(iv_buf, len(iv_buf))
        data_buf = ctypes.create_string_buffer(data, len(data))

        if encrypt:
            rc = _libcrypto.EVP_EncryptInit_ex(ctx, evp_type, None, key_buf, iv_c)
            if not rc:
                raise RuntimeError('EVP_EncryptInit_ex failed')
            _libcrypto.EVP_CIPHER_CTX_set_padding(ctx, 1 if use_padding else 0)
            rc = _libcrypto.EVP_EncryptUpdate(ctx, out_buf, ctypes.byref(outl),
                                              data_buf, len(data))
            if not rc:
                raise RuntimeError('EVP_EncryptUpdate failed')
            rc = _libcrypto.EVP_EncryptFinal_ex(ctx, final_buf, ctypes.byref(finall))
            if not rc:
                raise RuntimeError('EVP_EncryptFinal_ex failed (data not block-aligned?)')
        else:
            rc = _libcrypto.EVP_DecryptInit_ex(ctx, evp_type, None, key_buf, iv_c)
            if not rc:
                raise RuntimeError('EVP_DecryptInit_ex failed')
            _libcrypto.EVP_CIPHER_CTX_set_padding(ctx, 1 if use_padding else 0)
            rc = _libcrypto.EVP_DecryptUpdate(ctx, out_buf, ctypes.byref(outl),
                                              data_buf, len(data))
            if not rc:
                raise RuntimeError('EVP_DecryptUpdate failed')
            rc = _libcrypto.EVP_DecryptFinal_ex(ctx, final_buf, ctypes.byref(finall))
            if not rc:
                raise RuntimeError('EVP_DecryptFinal_ex failed (bad padding or data?)')

        return out_buf.raw[:outl.value] + final_buf.raw[:finall.value]
    finally:
        _libcrypto.EVP_CIPHER_CTX_free(ctx)
