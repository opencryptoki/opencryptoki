# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
rsa_backend.py — Real RSA operations via ctypes → libcrypto.

Supports both OpenSSL 1.1 and OpenSSL 3.x:

  • OpenSSL 1.1: uses the RSA_* low-level API (RSA_new, RSA_set0_key, etc.)
  • OpenSSL 3.x: uses EVP_PKEY_fromdata / OSSL_PARAM (low-level RSA API removed)

Detection is automatic: if RSA_new is not exported we assume OpenSSL 3.x.

All key material is represented as raw big-endian bytes matching the
PKCS#11 CKA_* attributes stored in the token.

Public API
----------
rsa_generate(bits) -> dict
rsa_public_encrypt(attr_dict, plaintext, padding) -> bytes
rsa_private_decrypt(attr_dict, ciphertext, padding) -> bytes
rsa_private_sign(attr_dict, data, mech_rule) -> bytes
rsa_public_verify(attr_dict, data, signature, mech_rule) -> bool
"""

import ctypes
import ctypes.util

from cipher_backend import _libcrypto   # reuse already-loaded libcrypto handle

# ---------------------------------------------------------------------------
# CKA_* constants (kept local to avoid circular imports)
# ---------------------------------------------------------------------------
_CKA_MODULUS           = 0x00000120
_CKA_PUBLIC_EXPONENT   = 0x00000122
_CKA_PRIVATE_EXPONENT  = 0x00000123
_CKA_PRIME_1           = 0x00000124
_CKA_PRIME_2           = 0x00000125
_CKA_EXPONENT_1        = 0x00000126
_CKA_EXPONENT_2        = 0x00000127
_CKA_COEFFICIENT       = 0x00000128

# RSA padding constants (match OpenSSL)
_RSA_PKCS1_PADDING  = 1
_RSA_NO_PADDING     = 3


# ---------------------------------------------------------------------------
# Bind helpers
# ---------------------------------------------------------------------------

import logging as _logging
_log = _logging.getLogger(__name__)


def _bind(name, restype, argtypes):
    fn = getattr(_libcrypto, name, None)
    if fn is None:
        _log.debug('rsa_backend: symbol not found in libcrypto: %s', name)
        return None
    fn.restype  = restype
    fn.argtypes = argtypes
    return fn


# ---------------------------------------------------------------------------
# Detect OpenSSL version (1.1 vs 3.x)
# ---------------------------------------------------------------------------

# Prefer the positive indicator: EVP_PKEY_fromdata was introduced in OpenSSL 3.0.
# Fall back to "RSA_new absent" for distros that strip the compat symbols.
_OPENSSL3 = (getattr(_libcrypto, 'EVP_PKEY_fromdata', None) is not None)
_log.info('rsa_backend: _OPENSSL3=%s (EVP_PKEY_fromdata %s, RSA_new %s)',
          _OPENSSL3,
          'present' if _OPENSSL3 else 'absent',
          'absent' if getattr(_libcrypto, 'RSA_new', None) is None else 'present')

# ---------------------------------------------------------------------------
# EVP_MD helpers (shared by both paths)
#
# OpenSSL 3 introduced EVP_MD_fetch() which returns a provider-aware EVP_MD*
# that is compatible with keys built via EVP_PKEY_fromdata().  The older
# EVP_sha1() / EVP_get_digestbyname() functions return "legacy" method objects
# that OpenSSL 3 rejects with "invalid digest" when used with provider keys.
#
# Strategy:
#   OpenSSL 3  → EVP_MD_fetch(NULL, name, NULL)  [must be freed by caller]
#   OpenSSL 1.1 → EVP_get_digestbyname(name)     [static, no free needed]
#
# _get_md() returns (md_ptr, needs_free).  Callers must call _free_md(md, nf).
#
# OpenSSL 3.5 restricts SHA-1 (and MD5) in signing contexts regardless of
# provider, property string, or EVP_set_default_properties() — the "invalid
# digest" error fires inside EVP_DigestSignInit regardless of how the EVP_MD*
# was obtained.  The restriction applies only to the *combined* hash+sign path;
# the raw digest functions (EVP_DigestInit/Update/Final) and the raw RSA sign
# primitive (EVP_PKEY_sign) are not restricted.
#
# _compute_digest() hashes data with a plain EVP_MD_CTX (no signing involved),
# which works for all algorithms including SHA-1.
# _evp_sign/_evp_verify use this for hash algorithms that OpenSSL 3 blocks in
# the sign context: they compute the digest, prepend the RFC 3447 DigestInfo
# DER prefix, then call the unrestricted raw RSA PKCS#1 sign/verify primitive.
# ---------------------------------------------------------------------------

_EVP_MD_CTX_new       = _bind('EVP_MD_CTX_new',       ctypes.c_void_p, [])
_EVP_MD_CTX_free      = _bind('EVP_MD_CTX_free',      None,            [ctypes.c_void_p])
_EVP_PKEY_free        = _bind('EVP_PKEY_free',         None,            [ctypes.c_void_p])

# OpenSSL 3: fetch a provider-aware digest by name
_EVP_MD_fetch         = _bind('EVP_MD_fetch',         ctypes.c_void_p,
                               [ctypes.c_void_p,   # OSSL_LIB_CTX* (NULL = default)
                                ctypes.c_char_p,   # algorithm name
                                ctypes.c_char_p])  # properties (NULL = any)
_EVP_MD_free          = _bind('EVP_MD_free',          None,
                               [ctypes.c_void_p])

# OpenSSL 1.1 fallback: static digest pointer, no free needed
_EVP_get_digestbyname = _bind('EVP_get_digestbyname', ctypes.c_void_p,
                               [ctypes.c_char_p])

# Raw digest functions — no sign context, no policy restriction on any algorithm
_EVP_DigestInit_ex    = _bind('EVP_DigestInit_ex',    ctypes.c_int,
                               [ctypes.c_void_p,    # EVP_MD_CTX*
                                ctypes.c_void_p,    # const EVP_MD*
                                ctypes.c_void_p])   # ENGINE* (NULL)
_EVP_DigestUpdate     = _bind('EVP_DigestUpdate',     ctypes.c_int,
                               [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t])
_EVP_DigestFinal_ex   = _bind('EVP_DigestFinal_ex',   ctypes.c_int,
                               [ctypes.c_void_p,     # EVP_MD_CTX*
                                ctypes.c_char_p,     # unsigned char *md (output)
                                ctypes.POINTER(ctypes.c_uint)])  # unsigned int *s

# ICSF rule-array hash name → OpenSSL fetch name
_MD_OSSL_NAME = {
    'MD5':      b'MD5',
    'SHA-1':    b'SHA1',
    'SHA-224':  b'SHA224',
    'SHA-256':  b'SHA256',
    'SHA-384':  b'SHA384',
    'SHA-512':  b'SHA512',
    'SHA3-224': b'SHA3-224',
    'SHA3-256': b'SHA3-256',
    'SHA3-384': b'SHA3-384',
    'SHA3-512': b'SHA3-512',
}

# RFC 3447 §9.2 DigestInfo DER prefixes for RSA PKCS#1 v1.5.
# Each entry is the bytes that precede the raw hash output in the DigestInfo
# structure: SEQUENCE { SEQUENCE { OID, NULL }, OCTET STRING(hash) }.
# Used by _evp_sign/_evp_verify when OpenSSL 3 blocks EVP_DigestSignInit for
# a given algorithm (currently SHA-1 and MD5 in OpenSSL 3.5+).
_DIGESTINFO_PREFIX = {
    'MD5':     bytes.fromhex('3020300c06082a864886f70d020505000410'),
    'SHA-1':   bytes.fromhex('3021300906052b0e03021a05000414'),
    'SHA-224': bytes.fromhex('302d300d06096086480165030402040500041c'),
    'SHA-256': bytes.fromhex('3031300d060960864801650304020105000420'),
    'SHA-384': bytes.fromhex('3041300d060960864801650304020205000430'),
    'SHA-512': bytes.fromhex('3051300d060960864801650304020305000440'),
}

# Hash output lengths (bytes) matching the entries above
_MD_DIGEST_LEN = {
    'MD5': 16, 'SHA-1': 20, 'SHA-224': 28, 'SHA-256': 32,
    'SHA-384': 48, 'SHA-512': 64,
    'SHA3-224': 28, 'SHA3-256': 32, 'SHA3-384': 48, 'SHA3-512': 64,
}

# On OpenSSL 3.5+ these hash algorithms are blocked inside EVP_DigestSignInit
# even though EVP_MD_fetch succeeds.  We detect them and fall back to the
# manual digest+DigestInfo+raw-sign path that is not restricted.
_OSSL3_SIGN_BLOCKED = frozenset({'MD5', 'SHA-1'})


def _get_md(hash_name: str):
    """Return (ctypes.c_void_p, needs_free) for *hash_name* (ICSF rule-array spelling).

    Always returns md as a ctypes.c_void_p so it is passed correctly to
    EVP_DigestInit_ex / EVP_DigestSignInit as a genuine pointer argument —
    a raw Python int is silently mishandled by some ctypes versions.

    On OpenSSL 3 uses EVP_MD_fetch() → caller must call _free_md() after use.
    On OpenSSL 1.1 uses EVP_get_digestbyname() → static pointer, no free.
    Raises ValueError for unknown names, RuntimeError if OpenSSL returns NULL.
    """
    ossl_name = _MD_OSSL_NAME.get(hash_name)
    if ossl_name is None:
        raise ValueError('Unknown hash algorithm: %r' % hash_name)

    if _OPENSSL3 and _EVP_MD_fetch is not None:
        md_int = _EVP_MD_fetch(None, ossl_name, None)
        if not md_int:
            raise RuntimeError('EVP_MD_fetch(%r) failed: %s'
                               % (hash_name, _ossl_err_str()))
        return ctypes.c_void_p(md_int), True   # caller must free

    if _EVP_get_digestbyname is not None:
        md_int = _EVP_get_digestbyname(ossl_name)
        if md_int:
            return ctypes.c_void_p(md_int), False   # static, no free

    raise RuntimeError('Cannot resolve EVP_MD* for %r' % hash_name)


def _free_md(md, needs_free: bool):
    """Free an EVP_MD* returned by _get_md() if needed."""
    if needs_free and md and _EVP_MD_free is not None:
        _EVP_MD_free(md)


def _compute_digest(data: bytes, hash_name: str) -> bytes:
    """Compute a raw message digest using EVP_DigestInit/Update/Final.

    This path is NOT subject to OpenSSL's signing policy restrictions — it
    only hashes the data, it does not involve any sign context.  Used to
    work around the OpenSSL 3.5 SHA-1/MD5 block in EVP_DigestSignInit.
    """
    md, md_needs_free = _get_md(hash_name)
    ctx = _EVP_MD_CTX_new()
    if not ctx:
        _free_md(md, md_needs_free)
        raise RuntimeError('EVP_MD_CTX_new failed')
    try:
        if _EVP_DigestInit_ex(ctx, md, None) != 1:
            raise RuntimeError('EVP_DigestInit_ex(%s) failed: %s'
                               % (hash_name, _ossl_err_str()))
        if _EVP_DigestUpdate(ctx, data, len(data)) != 1:
            raise RuntimeError('EVP_DigestUpdate failed: %s' % _ossl_err_str())
        dlen = _MD_DIGEST_LEN.get(hash_name, 64)
        out_buf = ctypes.create_string_buffer(dlen)
        out_len = ctypes.c_uint(0)
        if _EVP_DigestFinal_ex(ctx, out_buf, ctypes.byref(out_len)) != 1:
            raise RuntimeError('EVP_DigestFinal_ex failed: %s' % _ossl_err_str())
        return out_buf.raw[:out_len.value]
    finally:
        _EVP_MD_CTX_free(ctx)
        _free_md(md, md_needs_free)


# EVP_DigestSign/Verify — second arg is EVP_PKEY_CTX** (pointer-to-pointer).
# We use POINTER(c_void_p) so we can pass ctypes.byref(pctx_var) and retrieve
# the pctx after init in order to set RSA padding.
_EVP_DigestSignInit   = _bind('EVP_DigestSignInit',    ctypes.c_int,
                               [ctypes.c_void_p,
                                ctypes.POINTER(ctypes.c_void_p),   # EVP_PKEY_CTX**
                                ctypes.c_void_p,                    # const EVP_MD*
                                ctypes.c_void_p,                    # ENGINE*
                                ctypes.c_void_p])                   # EVP_PKEY*
_EVP_DigestSignUpdate = _bind('EVP_DigestSignUpdate',  ctypes.c_int,
                               [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t])
_EVP_DigestSignFinal  = _bind('EVP_DigestSignFinal',   ctypes.c_int,
                               [ctypes.c_void_p, ctypes.c_char_p,
                                ctypes.POINTER(ctypes.c_size_t)])
_EVP_DigestVerifyInit   = _bind('EVP_DigestVerifyInit',   ctypes.c_int,
                                 [ctypes.c_void_p,
                                  ctypes.POINTER(ctypes.c_void_p), # EVP_PKEY_CTX**
                                  ctypes.c_void_p,                  # const EVP_MD*
                                  ctypes.c_void_p,                  # ENGINE*
                                  ctypes.c_void_p])                 # EVP_PKEY*
_EVP_DigestVerifyUpdate = _bind('EVP_DigestVerifyUpdate', ctypes.c_int,
                                 [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t])
_EVP_DigestVerifyFinal  = _bind('EVP_DigestVerifyFinal',  ctypes.c_int,
                                 [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t])

# EVP_PKEY_CTX_set_rsa_padding is a C macro (expands to EVP_PKEY_CTX_ctrl).
# EVP_PKEY_CTX_set_signature_md is a real exported symbol on OpenSSL 3.
#   EVP_PKEY_CTRL_RSA_PADDING    = EVP_PKEY_ALG_CTRL(0x1000) + 1 = 0x1001
#   EVP_PKEY_CTX_ctrl(ctx, id=-1, op=-1, cmd, p1, p2)
_EVP_PKEY_CTX_ctrl           = _bind('EVP_PKEY_CTX_ctrl', ctypes.c_int,
                                      [ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                                       ctypes.c_int, ctypes.c_int, ctypes.c_void_p])
_EVP_PKEY_CTX_set_signature_md = _bind('EVP_PKEY_CTX_set_signature_md',
                                        ctypes.c_int,
                                        [ctypes.c_void_p, ctypes.c_void_p])
_EVP_PKEY_CTRL_RSA_PADDING   = 0x1001   # EVP_PKEY_ALG_CTRL(0x1000) + 1


def _set_rsa_padding(pctx, pad: int):
    """Set RSA padding on an EVP_PKEY_CTX.

    EVP_PKEY_CTX_set_rsa_padding is a C macro — not an exported symbol.
    We call the underlying EVP_PKEY_CTX_ctrl() directly instead.
    """
    if _EVP_PKEY_CTX_ctrl is None:
        _log.warning('rsa_backend: EVP_PKEY_CTX_ctrl not found; '
                     'cannot set RSA padding (assuming default PKCS1)')
        return
    rc = _EVP_PKEY_CTX_ctrl(pctx, -1, -1, _EVP_PKEY_CTRL_RSA_PADDING, pad, None)
    if rc <= 0:
        raise RuntimeError('EVP_PKEY_CTX_ctrl(set_rsa_padding=%d) failed: %s'
                           % (pad, _ossl_err_str()))

# Startup check — log any None bindings so we can see what's missing
for _sym_name, _sym_val in [
    ('EVP_MD_CTX_new',         _EVP_MD_CTX_new),
    ('EVP_MD_CTX_free',        _EVP_MD_CTX_free),
    ('EVP_PKEY_free',          _EVP_PKEY_free),
    ('EVP_MD_fetch',           _EVP_MD_fetch),
    ('EVP_MD_free',            _EVP_MD_free),
    ('EVP_get_digestbyname',   _EVP_get_digestbyname),
    ('EVP_DigestSignInit',     _EVP_DigestSignInit),
    ('EVP_DigestSignUpdate',   _EVP_DigestSignUpdate),
    ('EVP_DigestSignFinal',    _EVP_DigestSignFinal),
    ('EVP_DigestVerifyInit',   _EVP_DigestVerifyInit),
    ('EVP_DigestVerifyUpdate', _EVP_DigestVerifyUpdate),
    ('EVP_DigestVerifyFinal',  _EVP_DigestVerifyFinal),
    ('EVP_PKEY_CTX_ctrl',      _EVP_PKEY_CTX_ctrl),
]:
    if _sym_val is None:
        _log.warning('rsa_backend: symbol not found: %s', _sym_name)
    else:
        _log.debug('rsa_backend: OK %s', _sym_name)
del _sym_name, _sym_val

# ---------------------------------------------------------------------------
# BIGNUM helpers (used by OpenSSL 1.1 path and rsa_generate on both)
# ---------------------------------------------------------------------------

_BN_new      = _bind('BN_new',      ctypes.c_void_p, [])
_BN_free     = _bind('BN_free',     None,            [ctypes.c_void_p])
_BN_bin2bn   = _bind('BN_bin2bn',   ctypes.c_void_p,
                      [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p])
_BN_bn2bin   = _bind('BN_bn2bin',   ctypes.c_int,
                      [ctypes.c_void_p, ctypes.c_char_p])
_BN_num_bits = _bind('BN_num_bits', ctypes.c_int,    [ctypes.c_void_p])
_BN_set_word = _bind('BN_set_word', ctypes.c_int,    [ctypes.c_void_p, ctypes.c_ulong])


def _bytes_to_bn(b: bytes) -> ctypes.c_void_p:
    bn = _BN_bin2bn(b, len(b), None)
    if not bn:
        raise RuntimeError('BN_bin2bn failed')
    return bn


def _bn_to_bytes(bn) -> bytes:
    nbits  = _BN_num_bits(bn)
    nbytes = (nbits + 7) // 8
    if nbytes == 0:
        return b'\x00'
    buf = ctypes.create_string_buffer(nbytes)
    _BN_bn2bin(bn, buf)
    return buf.raw


# ===========================================================================
# OpenSSL 1.1 low-level RSA path
# ===========================================================================

if not _OPENSSL3:
    _RSA_new             = _bind('RSA_new',             ctypes.c_void_p, [])
    _RSA_free            = _bind('RSA_free',            None,            [ctypes.c_void_p])
    _RSA_generate_key_ex = _bind('RSA_generate_key_ex', ctypes.c_int,
                                  [ctypes.c_void_p, ctypes.c_int,
                                   ctypes.c_void_p, ctypes.c_void_p])
    _RSA_size            = _bind('RSA_size',            ctypes.c_int,    [ctypes.c_void_p])
    _RSA_public_encrypt  = _bind('RSA_public_encrypt',  ctypes.c_int,
                                  [ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p,
                                   ctypes.c_void_p, ctypes.c_int])
    _RSA_private_decrypt = _bind('RSA_private_decrypt', ctypes.c_int,
                                  [ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p,
                                   ctypes.c_void_p, ctypes.c_int])
    _RSA_private_encrypt = _bind('RSA_private_encrypt', ctypes.c_int,
                                  [ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p,
                                   ctypes.c_void_p, ctypes.c_int])
    _RSA_public_decrypt  = _bind('RSA_public_decrypt',  ctypes.c_int,
                                  [ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p,
                                   ctypes.c_void_p, ctypes.c_int])
    _RSA_get0_key        = _bind('RSA_get0_key',        None,
                                  [ctypes.c_void_p,
                                   ctypes.POINTER(ctypes.c_void_p),
                                   ctypes.POINTER(ctypes.c_void_p),
                                   ctypes.POINTER(ctypes.c_void_p)])
    _RSA_get0_factors    = _bind('RSA_get0_factors',    None,
                                  [ctypes.c_void_p,
                                   ctypes.POINTER(ctypes.c_void_p),
                                   ctypes.POINTER(ctypes.c_void_p)])
    _RSA_get0_crt_params = _bind('RSA_get0_crt_params', None,
                                  [ctypes.c_void_p,
                                   ctypes.POINTER(ctypes.c_void_p),
                                   ctypes.POINTER(ctypes.c_void_p),
                                   ctypes.POINTER(ctypes.c_void_p)])
    _RSA_set0_key        = _bind('RSA_set0_key',        ctypes.c_int,
                                  [ctypes.c_void_p,
                                   ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p])
    _RSA_set0_factors    = _bind('RSA_set0_factors',    ctypes.c_int,
                                  [ctypes.c_void_p,
                                   ctypes.c_void_p, ctypes.c_void_p])
    _RSA_set0_crt_params = _bind('RSA_set0_crt_params', ctypes.c_int,
                                  [ctypes.c_void_p,
                                   ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p])
    _EVP_PKEY_new        = _bind('EVP_PKEY_new',        ctypes.c_void_p, [])
    _EVP_PKEY_assign_RSA = _bind('EVP_PKEY_assign_RSA', ctypes.c_int,
                                  [ctypes.c_void_p, ctypes.c_void_p])

# ===========================================================================
# OpenSSL 3.x EVP_PKEY_fromdata path
# ===========================================================================

# Bind ERR functions unconditionally — used for diagnostics on both versions
_ERR_get_error           = _bind('ERR_get_error',           ctypes.c_ulong, [])
_ERR_peek_last_error     = _bind('ERR_peek_last_error',     ctypes.c_ulong, [])
_ERR_error_string_n      = _bind('ERR_error_string_n',      None,
                                  [ctypes.c_ulong, ctypes.c_char_p, ctypes.c_size_t])
_ERR_print_errors_fp_fn  = None   # not used


def _ossl_err_str():
    """Return all pending OpenSSL error strings, draining the queue."""
    msgs = []
    if _ERR_get_error is None:
        return ''
    buf = ctypes.create_string_buffer(512)
    while True:
        code = _ERR_get_error()
        if not code:
            break
        if _ERR_error_string_n:
            _ERR_error_string_n(code, buf, 512)
            msgs.append(buf.value.decode('ascii', errors='replace'))
        else:
            msgs.append('0x%x' % code)
    return '; '.join(msgs) if msgs else ''


def _ossl_peek_err():
    """Peek at the last error without consuming it."""
    if _ERR_peek_last_error is None:
        return ''
    code = _ERR_peek_last_error()
    if not code:
        return ''
    if _ERR_error_string_n:
        buf = ctypes.create_string_buffer(512)
        _ERR_error_string_n(code, buf, 512)
        return buf.value.decode('ascii', errors='replace')
    return '0x%x' % code


if _OPENSSL3:
    # OSSL_PARAM helpers
    # struct OSSL_PARAM { const char *key; unsigned int data_type;
    #                     void *data; size_t data_size; size_t return_size; }
    # OSSL_PARAM_END data_type = 0
    _OSSL_PARAM_END_DATA_TYPE = 0

    class _OSSLParam(ctypes.Structure):
        _fields_ = [
            ('key',         ctypes.c_char_p),
            ('data_type',   ctypes.c_uint),
            ('data',        ctypes.c_void_p),
            ('data_size',   ctypes.c_size_t),
            ('return_size', ctypes.c_size_t),
        ]

    # OSSL_PARAM data type constants from openssl/params.h
    _OSSL_PARAM_INTEGER          = 1
    _OSSL_PARAM_UNSIGNED_INTEGER = 2   # also used for BN (big-endian bytes)
    _OSSL_PARAM_UTF8_STRING      = 4
    _OSSL_PARAM_OCTET_STRING     = 5
    # Alias: OpenSSL passes BN values as UNSIGNED_INTEGER with big-endian bytes
    _OSSL_PARAM_BN = _OSSL_PARAM_UNSIGNED_INTEGER

    # EVP_PKEY_CTX — log any missing symbols immediately at import time
    def _brequire(name, restype, argtypes):
        """Bind and raise if the symbol is absent (required for OpenSSL 3 path)."""
        fn = _bind(name, restype, argtypes)
        if fn is None:
            raise ImportError('Required OpenSSL 3 symbol missing: %s '
                              '(libcrypto may be too old or missing)' % name)
        return fn

    # EVP_PKEY_CTX_new_id creates a legacy-method context on OpenSSL 3 — keys
    # built from it cannot interoperate with provider-fetched objects such as
    # EVP_MD_fetch().  Use EVP_PKEY_CTX_new_from_name() instead, which creates
    # a proper provider-based context so EVP_DigestSign* accepts fetched MDs.
    _EVP_PKEY_CTX_new_from_name = _bind('EVP_PKEY_CTX_new_from_name',
                                         ctypes.c_void_p,
                                         [ctypes.c_void_p,    # OSSL_LIB_CTX* (NULL)
                                          ctypes.c_char_p,    # name e.g. b"RSA"
                                          ctypes.c_char_p])   # propquery (NULL)
    _log.info('rsa_backend: EVP_PKEY_CTX_new_from_name: %s',
              'present' if _EVP_PKEY_CTX_new_from_name else 'ABSENT (will use new_id fallback)')
    _EVP_PKEY_CTX_new_id    = _bind('EVP_PKEY_CTX_new_id',  ctypes.c_void_p,
                                     [ctypes.c_int, ctypes.c_void_p])
    _EVP_PKEY_CTX_free      = _brequire('EVP_PKEY_CTX_free',    None,
                                          [ctypes.c_void_p])
    _EVP_PKEY_fromdata_init = _brequire('EVP_PKEY_fromdata_init', ctypes.c_int,
                                          [ctypes.c_void_p])
    _EVP_PKEY_fromdata      = _brequire('EVP_PKEY_fromdata',    ctypes.c_int,
                                          [ctypes.c_void_p,
                                           ctypes.POINTER(ctypes.c_void_p),
                                           ctypes.c_int, ctypes.c_void_p])
    _EVP_PKEY_keygen_init   = _brequire('EVP_PKEY_keygen_init', ctypes.c_int,
                                          [ctypes.c_void_p])
    _EVP_PKEY_CTX_set_rsa_keygen_bits = _bind('EVP_PKEY_CTX_set_rsa_keygen_bits',
                                               ctypes.c_int,
                                               [ctypes.c_void_p, ctypes.c_int])
    _EVP_PKEY_keygen        = _brequire('EVP_PKEY_keygen',      ctypes.c_int,
                                          [ctypes.c_void_p,
                                           ctypes.POINTER(ctypes.c_void_p)])
    _EVP_PKEY_get_bn_param  = _bind('EVP_PKEY_get_bn_param',   ctypes.c_int,
                                     [ctypes.c_void_p, ctypes.c_char_p,
                                      ctypes.POINTER(ctypes.c_void_p)])

    # EVP key type IDs
    _EVP_PKEY_RSA = 6
    # Selection flags for EVP_PKEY_fromdata (OSSL_KEYMGMT_SELECT_* from core_dispatch.h)
    _EVP_PKEY_PRIVATE_KEY    = 0x01
    _EVP_PKEY_PUBLIC_KEY     = 0x02
    _EVP_PKEY_KEYPAIR        = 0x03   # PRIVATE_KEY | PUBLIC_KEY

    # OSSL_PKEY_PARAM_* name constants for RSA
    _P_N    = b'n'
    _P_E    = b'e'
    _P_D    = b'd'
    _P_P    = b'rsa-factor1'
    _P_Q    = b'rsa-factor2'
    _P_DP   = b'rsa-exponent1'
    _P_DQ   = b'rsa-exponent2'
    _P_QINV = b'rsa-coefficient1'

    # EVP_PKEY_encrypt / decrypt / sign / verify raw
    _EVP_PKEY_CTX_new        = _bind('EVP_PKEY_CTX_new',        ctypes.c_void_p,
                                      [ctypes.c_void_p, ctypes.c_void_p])
    _EVP_PKEY_encrypt_init   = _bind('EVP_PKEY_encrypt_init',   ctypes.c_int,
                                      [ctypes.c_void_p])
    _EVP_PKEY_encrypt        = _bind('EVP_PKEY_encrypt',        ctypes.c_int,
                                      [ctypes.c_void_p, ctypes.c_char_p,
                                       ctypes.POINTER(ctypes.c_size_t),
                                       ctypes.c_char_p, ctypes.c_size_t])
    _EVP_PKEY_decrypt_init   = _bind('EVP_PKEY_decrypt_init',   ctypes.c_int,
                                      [ctypes.c_void_p])
    _EVP_PKEY_decrypt        = _bind('EVP_PKEY_decrypt',        ctypes.c_int,
                                      [ctypes.c_void_p, ctypes.c_char_p,
                                       ctypes.POINTER(ctypes.c_size_t),
                                       ctypes.c_char_p, ctypes.c_size_t])
    _EVP_PKEY_sign_init      = _bind('EVP_PKEY_sign_init',      ctypes.c_int,
                                      [ctypes.c_void_p])
    _EVP_PKEY_sign           = _bind('EVP_PKEY_sign',           ctypes.c_int,
                                      [ctypes.c_void_p, ctypes.c_char_p,
                                       ctypes.POINTER(ctypes.c_size_t),
                                       ctypes.c_char_p, ctypes.c_size_t])
    _EVP_PKEY_verify_init    = _bind('EVP_PKEY_verify_init',    ctypes.c_int,
                                      [ctypes.c_void_p])
    _EVP_PKEY_verify         = _bind('EVP_PKEY_verify',         ctypes.c_int,
                                      [ctypes.c_void_p, ctypes.c_char_p,
                                       ctypes.c_size_t, ctypes.c_char_p,
                                       ctypes.c_size_t])

# ---------------------------------------------------------------------------
# Internal: build EVP_PKEY from CKA_* attribute dict
# ---------------------------------------------------------------------------

def _attr_bytes(attr_dict, cka):
    """Get a CKA attribute as bytes, normalising int and stripping zero placeholders."""
    v = attr_dict.get(cka)
    if v is None or v == b'\x00':
        return None
    if isinstance(v, int):
        n = v
        length = (n.bit_length() + 7) // 8
        v = n.to_bytes(length, 'big')
    return v or None


def _build_pkey(attr_dict: dict, private: bool) -> ctypes.c_void_p:
    """
    Build an EVP_PKEY* from a CKA_* attribute dict.
    Works on both OpenSSL 1.1 (via RSA_*) and OpenSSL 3 (via EVP_PKEY_fromdata).
    Caller must free with _EVP_PKEY_free().
    """
    n_bytes  = _attr_bytes(attr_dict, _CKA_MODULUS)
    e_bytes  = _attr_bytes(attr_dict, _CKA_PUBLIC_EXPONENT)
    d_bytes  = _attr_bytes(attr_dict, _CKA_PRIVATE_EXPONENT) if private else None
    p_bytes  = _attr_bytes(attr_dict, _CKA_PRIME_1)          if private else None
    q_bytes  = _attr_bytes(attr_dict, _CKA_PRIME_2)          if private else None
    dp_bytes = _attr_bytes(attr_dict, _CKA_EXPONENT_1)       if private else None
    dq_bytes = _attr_bytes(attr_dict, _CKA_EXPONENT_2)       if private else None
    qi_bytes = _attr_bytes(attr_dict, _CKA_COEFFICIENT)      if private else None

    if not n_bytes or not e_bytes:
        raise ValueError('RSA key missing modulus or public exponent')

    if _OPENSSL3:
        return _build_pkey_ossl3(n_bytes, e_bytes, d_bytes,
                                  p_bytes, q_bytes, dp_bytes, dq_bytes, qi_bytes,
                                  private)
    else:
        return _build_pkey_ossl1(n_bytes, e_bytes, d_bytes,
                                  p_bytes, q_bytes, dp_bytes, dq_bytes, qi_bytes)


def _build_pkey_ossl3(n, e, d, p, q, dp, dq, qi, private):
    """OpenSSL 3: EVP_PKEY_fromdata with OSSL_PARAM array."""
    # Keep all ctypes buffers alive until after EVP_PKEY_fromdata returns.
    bufs = []

    def _add_bn_param(params, name, value):
        if value is None:
            return
        buf = ctypes.create_string_buffer(value, len(value))
        bufs.append(buf)
        param = _OSSLParam()
        param.key       = name
        param.data_type = _OSSL_PARAM_BN
        param.data      = ctypes.cast(buf, ctypes.c_void_p)
        param.data_size = len(value)
        param.return_size = ctypes.c_size_t(-1).value  # OSSL_PARAM_UNMODIFIED
        params.append(param)

    def _make_param_array(extra_private_params):
        params = []
        _add_bn_param(params, _P_N, n)
        _add_bn_param(params, _P_E, e)
        for name, value in extra_private_params:
            _add_bn_param(params, name, value)
        term = _OSSLParam()
        term.key = None; term.data_type = _OSSL_PARAM_END_DATA_TYPE
        term.data = None; term.data_size = 0; term.return_size = 0
        params.append(term)
        ParamArray = _OSSLParam * len(params)
        return ParamArray(*params)

    def _try_fromdata(param_arr, selection):
        # Prefer EVP_PKEY_CTX_new_from_name: creates a provider-based context
        # so the resulting EVP_PKEY works with EVP_MD_fetch'd digests.
        # Fall back to EVP_PKEY_CTX_new_id only if the newer function is absent.
        if _EVP_PKEY_CTX_new_from_name is not None:
            pctx = _EVP_PKEY_CTX_new_from_name(None, b'RSA', None)
            if not pctx:
                raise RuntimeError('EVP_PKEY_CTX_new_from_name(RSA) failed: %s'
                                   % _ossl_err_str())
        else:
            pctx = _EVP_PKEY_CTX_new_id(_EVP_PKEY_RSA, None)
            if not pctx:
                raise RuntimeError('EVP_PKEY_CTX_new_id(RSA) failed: %s'
                                   % _ossl_err_str())
        pkey = ctypes.c_void_p(None)
        try:
            if _EVP_PKEY_fromdata_init(pctx) != 1:
                raise RuntimeError('EVP_PKEY_fromdata_init failed: %s'
                                   % _ossl_err_str())
            rc = _EVP_PKEY_fromdata(pctx, ctypes.byref(pkey), selection,
                                    ctypes.cast(param_arr, ctypes.c_void_p))
            # Read error queue immediately — before _EVP_PKEY_CTX_free clears it
            err = _ossl_peek_err() or _ossl_err_str()
            return rc, pkey, err
        finally:
            _EVP_PKEY_CTX_free(pctx)

    if not private:
        param_arr = _make_param_array([])
        rc, pkey, err = _try_fromdata(param_arr, _EVP_PKEY_PUBLIC_KEY)
        if rc != 1:
            raise RuntimeError('EVP_PKEY_fromdata (public) failed: %s' % err)
        return pkey

    # Private key: try full CRT set first, then fall back to n+e+d only.
    have_crt = all(v is not None for v in (d, p, q, dp, dq, qi))
    have_d   = d is not None

    if not have_d:
        raise ValueError('RSA private key missing private exponent (d)')

    _log.debug('_build_pkey_ossl3: n=%d e=%d d=%d p=%s q=%s have_crt=%s',
               len(n), len(e), len(d),
               len(p) if p else None, len(q) if q else None, have_crt)

    if have_crt:
        param_arr = _make_param_array([
            (_P_D, d), (_P_P, p), (_P_Q, q),
            (_P_DP, dp), (_P_DQ, dq), (_P_QINV, qi),
        ])
        rc, pkey, err = _try_fromdata(param_arr, _EVP_PKEY_KEYPAIR)
        if rc == 1:
            return pkey
        _log.warning('EVP_PKEY_fromdata with full CRT failed (rc=%d): %s; '
                     'retrying with n+e+d only', rc, err)

    # Minimal private key: only n, e, d
    param_arr = _make_param_array([(_P_D, d)])
    rc, pkey, err = _try_fromdata(param_arr, _EVP_PKEY_KEYPAIR)
    if rc != 1:
        raise RuntimeError('EVP_PKEY_fromdata (n+e+d) failed: %s' % err)
    return pkey


def _build_pkey_ossl1(n, e, d, p, q, dp, dq, qi):
    """OpenSSL 1.1: RSA_new + RSA_set0_* + EVP_PKEY_assign_RSA."""
    rsa = _RSA_new()
    if not rsa:
        raise RuntimeError('RSA_new failed')
    try:
        bn_n = _bytes_to_bn(n)
        bn_e = _bytes_to_bn(e)
        bn_d = _bytes_to_bn(d) if d else None
        if _RSA_set0_key(rsa, bn_n, bn_e, bn_d) != 1:
            raise RuntimeError('RSA_set0_key failed')
        bn_n = bn_e = bn_d = None  # ownership transferred

        if p and q:
            bn_p = _bytes_to_bn(p)
            bn_q = _bytes_to_bn(q)
            if _RSA_set0_factors(rsa, bn_p, bn_q) != 1:
                raise RuntimeError('RSA_set0_factors failed')
            bn_p = bn_q = None

        if dp and dq and qi:
            bn_dp = _bytes_to_bn(dp)
            bn_dq = _bytes_to_bn(dq)
            bn_qi = _bytes_to_bn(qi)
            if _RSA_set0_crt_params(rsa, bn_dp, bn_dq, bn_qi) != 1:
                raise RuntimeError('RSA_set0_crt_params failed')
            bn_dp = bn_dq = bn_qi = None

        pkey = _EVP_PKEY_new()
        if not pkey:
            raise RuntimeError('EVP_PKEY_new failed')
        if _EVP_PKEY_assign_RSA(pkey, rsa) != 1:
            _EVP_PKEY_free(pkey)
            raise RuntimeError('EVP_PKEY_assign_RSA failed')
        rsa = None  # ownership transferred to pkey
        return pkey
    finally:
        if rsa:
            _RSA_free(rsa)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def rsa_generate(bits: int = 2048) -> dict:
    """Generate a real RSA key pair. Returns dict mapping CKA_* ints → bytes."""
    if _OPENSSL3:
        return _rsa_generate_ossl3(bits)
    else:
        return _rsa_generate_ossl1(bits)


def _rsa_generate_ossl3(bits):
    if _EVP_PKEY_CTX_new_from_name is not None:
        pctx = _EVP_PKEY_CTX_new_from_name(None, b'RSA', None)
    else:
        pctx = _EVP_PKEY_CTX_new_id(_EVP_PKEY_RSA, None)
    if not pctx:
        raise RuntimeError('EVP_PKEY_CTX_new_from_name/new_id(RSA) failed')
    try:
        if _EVP_PKEY_keygen_init(pctx) != 1:
            raise RuntimeError('EVP_PKEY_keygen_init failed')
        if _EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, bits) <= 0:
            raise RuntimeError('EVP_PKEY_CTX_set_rsa_keygen_bits failed')
        pkey = ctypes.c_void_p(None)
        if _EVP_PKEY_keygen(pctx, ctypes.byref(pkey)) != 1:
            raise RuntimeError('EVP_PKEY_keygen failed')
    finally:
        _EVP_PKEY_CTX_free(pctx)

    try:
        def _get_bn(name):
            bn = ctypes.c_void_p(None)
            if _EVP_PKEY_get_bn_param(pkey, name, ctypes.byref(bn)) != 1:
                return None
            result = _bn_to_bytes(bn)
            _BN_free(bn)
            return result

        return {
            _CKA_MODULUS:          _get_bn(b'n'),
            _CKA_PUBLIC_EXPONENT:  _get_bn(b'e'),
            _CKA_PRIVATE_EXPONENT: _get_bn(b'd'),
            _CKA_PRIME_1:          _get_bn(b'rsa-factor1'),
            _CKA_PRIME_2:          _get_bn(b'rsa-factor2'),
            _CKA_EXPONENT_1:       _get_bn(b'rsa-exponent1'),
            _CKA_EXPONENT_2:       _get_bn(b'rsa-exponent2'),
            _CKA_COEFFICIENT:      _get_bn(b'rsa-coefficient1'),
        }
    finally:
        _EVP_PKEY_free(pkey)


def _rsa_generate_ossl1(bits):
    e_bn = _BN_new()
    _BN_set_word(e_bn, 65537)
    rsa = _RSA_new()
    if not rsa:
        _BN_free(e_bn)
        raise RuntimeError('RSA_new failed')
    try:
        if _RSA_generate_key_ex(rsa, bits, e_bn, None) != 1:
            raise RuntimeError('RSA_generate_key_ex failed')

        n_ptr = ctypes.c_void_p(); e_ptr = ctypes.c_void_p(); d_ptr = ctypes.c_void_p()
        _RSA_get0_key(rsa, ctypes.byref(n_ptr), ctypes.byref(e_ptr), ctypes.byref(d_ptr))
        p_ptr = ctypes.c_void_p(); q_ptr = ctypes.c_void_p()
        _RSA_get0_factors(rsa, ctypes.byref(p_ptr), ctypes.byref(q_ptr))
        dp_ptr = ctypes.c_void_p(); dq_ptr = ctypes.c_void_p(); qi_ptr = ctypes.c_void_p()
        _RSA_get0_crt_params(rsa, ctypes.byref(dp_ptr), ctypes.byref(dq_ptr), ctypes.byref(qi_ptr))

        return {
            _CKA_MODULUS:          _bn_to_bytes(n_ptr),
            _CKA_PUBLIC_EXPONENT:  _bn_to_bytes(e_ptr),
            _CKA_PRIVATE_EXPONENT: _bn_to_bytes(d_ptr),
            _CKA_PRIME_1:          _bn_to_bytes(p_ptr),
            _CKA_PRIME_2:          _bn_to_bytes(q_ptr),
            _CKA_EXPONENT_1:       _bn_to_bytes(dp_ptr),
            _CKA_EXPONENT_2:       _bn_to_bytes(dq_ptr),
            _CKA_COEFFICIENT:      _bn_to_bytes(qi_ptr),
        }
    finally:
        _RSA_free(rsa)
        _BN_free(e_bn)


def _rsa_raw_encrypt(attr_dict: dict, plaintext: bytes) -> bytes:
    """Perform the raw RSA public operation used by RSA-ZERO."""
    n = int.from_bytes(_attr_bytes(attr_dict, _CKA_MODULUS), 'big')
    e = int.from_bytes(_attr_bytes(attr_dict, _CKA_PUBLIC_EXPONENT), 'big')
    mod_len = (n.bit_length() + 7) // 8
    if len(plaintext) > mod_len:
        raise ValueError('RSA-ZERO input is too long')
    encoded = plaintext.rjust(mod_len, b'\x00')
    return pow(int.from_bytes(encoded, 'big'), e, n).to_bytes(mod_len, 'big')


def rsa_public_encrypt(attr_dict: dict, plaintext: bytes, padding: str) -> bytes:
    if padding != 'PKCS1':
        return _rsa_raw_encrypt(attr_dict, plaintext)

    pkey = _build_pkey(attr_dict, private=False)
    try:
        return _pkey_encrypt(pkey, plaintext, _RSA_PKCS1_PADDING)
    finally:
        _EVP_PKEY_free(pkey)


def rsa_private_decrypt(attr_dict: dict, ciphertext: bytes, padding: str) -> bytes:
    if padding != 'PKCS1':
        n = int.from_bytes(_attr_bytes(attr_dict, _CKA_MODULUS), 'big')
        d = int.from_bytes(_attr_bytes(attr_dict, _CKA_PRIVATE_EXPONENT), 'big')
        mod_len = (n.bit_length() + 7) // 8
        if len(ciphertext) != mod_len:
            raise ValueError('RSA-ZERO input must equal modulus length')
        return pow(int.from_bytes(ciphertext, 'big'), d, n).to_bytes(mod_len, 'big')

    pkey = _build_pkey(attr_dict, private=True)
    try:
        return _pkey_decrypt(pkey, ciphertext, _RSA_PKCS1_PADDING)
    finally:
        _EVP_PKEY_free(pkey)



def _rsa_raw_sign(attr_dict: dict, data: bytes, pkcs1: bool) -> bytes:
    """Perform the raw RSA private operation for ICSF RSA-PKCS/RSA-ZERO."""
    n = int.from_bytes(_attr_bytes(attr_dict, _CKA_MODULUS), 'big')
    d = int.from_bytes(_attr_bytes(attr_dict, _CKA_PRIVATE_EXPONENT), 'big')
    mod_len = (n.bit_length() + 7) // 8

    if pkcs1:
        if len(data) > mod_len - 11:
            raise ValueError('RSA-PKCS input is too long')
        encoded = b'\x00\x01' + b'\xff' * (mod_len - len(data) - 3)
        encoded += b'\x00' + data
    else:
        if len(data) > mod_len:
            raise ValueError('RSA-ZERO input is too long')
        encoded = data.rjust(mod_len, b'\x00')

    return pow(int.from_bytes(encoded, 'big'), d, n).to_bytes(mod_len, 'big')


def _rsa_raw_verify(attr_dict: dict, data: bytes, signature: bytes,
                    pkcs1: bool) -> bool:
    """Verify a raw RSA signature using the public exponent."""
    n = int.from_bytes(_attr_bytes(attr_dict, _CKA_MODULUS), 'big')
    e = int.from_bytes(_attr_bytes(attr_dict, _CKA_PUBLIC_EXPONENT), 'big')
    mod_len = (n.bit_length() + 7) // 8
    if len(signature) != mod_len:
        return False

    recovered = pow(int.from_bytes(signature, 'big'), e, n).to_bytes(mod_len, 'big')
    if pkcs1:
        if len(data) > mod_len - 11:
            return False
        expected = b'\x00\x01' + b'\xff' * (mod_len - len(data) - 3)
        expected += b'\x00' + data
    else:
        if len(data) > mod_len:
            return False
        expected = data.rjust(mod_len, b'\x00')
    return recovered == expected


def rsa_private_sign(attr_dict: dict, data: bytes, mech_rule: str) -> bytes:
    """RSA sign using the ICSF rule-array spelling."""
    rule = mech_rule.strip()
    if rule in ('RSA-PKCS', 'RSA-ZERO'):
        return _rsa_raw_sign(attr_dict, data, rule == 'RSA-PKCS')

    pkey = _build_pkey(attr_dict, private=True)
    try:
        return _evp_sign(pkey, data, rule.split()[0])
    finally:
        _EVP_PKEY_free(pkey)


def rsa_public_verify(attr_dict: dict, data: bytes,
                      signature: bytes, mech_rule: str) -> bool:
    """RSA verify. Returns True if valid."""
    rule = mech_rule.strip()
    if rule in ('RSA-PKCS', 'RSA-ZERO'):
        return _rsa_raw_verify(attr_dict, data, signature, rule == 'RSA-PKCS')

    pkey = _build_pkey(attr_dict, private=False)
    try:
        return _evp_verify(pkey, data, signature, rule.split()[0])
    finally:
        _EVP_PKEY_free(pkey)


# ---------------------------------------------------------------------------
# Low-level EVP_PKEY encrypt/decrypt/sign/verify helpers
# ---------------------------------------------------------------------------

def _pkey_encrypt(pkey, plaintext: bytes, pad: int) -> bytes:
    if _OPENSSL3:
        pctx = _EVP_PKEY_CTX_new(pkey, None)
        if not pctx:
            raise RuntimeError('EVP_PKEY_CTX_new failed')
        try:
            if _EVP_PKEY_encrypt_init(pctx) != 1:
                raise RuntimeError('EVP_PKEY_encrypt_init failed')
            _set_rsa_padding(pctx, pad)
            out_len = ctypes.c_size_t(0)
            if _EVP_PKEY_encrypt(pctx, None, ctypes.byref(out_len),
                                  plaintext, len(plaintext)) != 1:
                raise RuntimeError('EVP_PKEY_encrypt (size query) failed')
            out_buf = ctypes.create_string_buffer(out_len.value)
            if _EVP_PKEY_encrypt(pctx, out_buf, ctypes.byref(out_len),
                                  plaintext, len(plaintext)) != 1:
                raise RuntimeError('EVP_PKEY_encrypt failed')
            return out_buf.raw[:out_len.value]
        finally:
            _EVP_PKEY_CTX_free(pctx)
    else:
        # OpenSSL 1.1: extract RSA* from pkey for direct call
        rsa = ctypes.cast(
            _libcrypto.EVP_PKEY_get0_RSA(pkey), ctypes.c_void_p)
        mod_len = _RSA_size(rsa)
        out_buf = ctypes.create_string_buffer(mod_len)
        rc = _RSA_public_encrypt(len(plaintext), plaintext, out_buf, rsa, pad)
        if rc < 0:
            raise RuntimeError('RSA_public_encrypt failed (rc=%d)' % rc)
        return out_buf.raw[:rc]


def _pkey_decrypt(pkey, ciphertext: bytes, pad: int) -> bytes:
    if _OPENSSL3:
        pctx = _EVP_PKEY_CTX_new(pkey, None)
        if not pctx:
            raise RuntimeError('EVP_PKEY_CTX_new failed')
        try:
            if _EVP_PKEY_decrypt_init(pctx) != 1:
                raise RuntimeError('EVP_PKEY_decrypt_init failed')
            _set_rsa_padding(pctx, pad)
            out_len = ctypes.c_size_t(0)
            if _EVP_PKEY_decrypt(pctx, None, ctypes.byref(out_len),
                                  ciphertext, len(ciphertext)) != 1:
                raise RuntimeError('EVP_PKEY_decrypt (size query) failed')
            out_buf = ctypes.create_string_buffer(out_len.value)
            if _EVP_PKEY_decrypt(pctx, out_buf, ctypes.byref(out_len),
                                  ciphertext, len(ciphertext)) != 1:
                raise RuntimeError('EVP_PKEY_decrypt failed')
            return out_buf.raw[:out_len.value]
        finally:
            _EVP_PKEY_CTX_free(pctx)
    else:
        rsa = ctypes.cast(
            _libcrypto.EVP_PKEY_get0_RSA(pkey), ctypes.c_void_p)
        mod_len = _RSA_size(rsa)
        out_buf = ctypes.create_string_buffer(mod_len)
        rc = _RSA_private_decrypt(len(ciphertext), ciphertext, out_buf, rsa, pad)
        if rc < 0:
            raise RuntimeError('RSA_private_decrypt failed (rc=%d)' % rc)
        return out_buf.raw[:rc]


def _pkey_sign_raw(pkey, data: bytes, pad: int) -> bytes:
    """Raw RSA sign (no hash): PKCS#1 type-1 block or no-padding modexp."""
    if _OPENSSL3:
        pctx = _EVP_PKEY_CTX_new(pkey, None)
        if not pctx:
            raise RuntimeError('EVP_PKEY_CTX_new failed')
        try:
            if _EVP_PKEY_sign_init(pctx) != 1:
                raise RuntimeError('EVP_PKEY_sign_init failed')
            _set_rsa_padding(pctx, pad)
            # Set digest to NID_undef (0) for raw sign via EVP_PKEY_CTX_set_signature_md
            _set_sig_md = _bind('EVP_PKEY_CTX_set_signature_md', ctypes.c_int,
                                 [ctypes.c_void_p, ctypes.c_void_p])
            if _set_sig_md and _set_sig_md(pctx, None) <= 0:
                pass  # some builds don't need/want this for raw
            out_len = ctypes.c_size_t(0)
            if _EVP_PKEY_sign(pctx, None, ctypes.byref(out_len),
                               data, len(data)) != 1:
                raise RuntimeError('EVP_PKEY_sign (size query) failed')
            out_buf = ctypes.create_string_buffer(out_len.value)
            if _EVP_PKEY_sign(pctx, out_buf, ctypes.byref(out_len),
                               data, len(data)) != 1:
                raise RuntimeError('EVP_PKEY_sign failed')
            return out_buf.raw[:out_len.value]
        finally:
            _EVP_PKEY_CTX_free(pctx)
    else:
        rsa = ctypes.cast(
            _libcrypto.EVP_PKEY_get0_RSA(pkey), ctypes.c_void_p)
        mod_len = _RSA_size(rsa)
        if pad == _RSA_NO_PADDING:
            data = data.rjust(mod_len, b'\x00')
        out_buf = ctypes.create_string_buffer(mod_len)
        rc = _RSA_private_encrypt(len(data), data, out_buf, rsa, pad)
        if rc < 0:
            raise RuntimeError('RSA_private_encrypt failed (rc=%d)' % rc)
        return out_buf.raw[:rc]


def _pkey_verify_raw(pkey, data: bytes, signature: bytes, pad: int) -> bool:
    """Raw RSA verify (no hash)."""
    if _OPENSSL3:
        pctx = _EVP_PKEY_CTX_new(pkey, None)
        if not pctx:
            raise RuntimeError('EVP_PKEY_CTX_new failed')
        try:
            if _EVP_PKEY_verify_init(pctx) != 1:
                raise RuntimeError('EVP_PKEY_verify_init failed')
            _set_rsa_padding(pctx, pad)
            rc = _EVP_PKEY_verify(pctx, signature, len(signature), data, len(data))
            return rc == 1
        finally:
            _EVP_PKEY_CTX_free(pctx)
    else:
        rsa = ctypes.cast(
            _libcrypto.EVP_PKEY_get0_RSA(pkey), ctypes.c_void_p)
        mod_len = _RSA_size(rsa)
        out_buf = ctypes.create_string_buffer(mod_len)
        rc = _RSA_public_decrypt(len(signature), signature, out_buf, rsa, pad)
        if rc < 0:
            return False
        return out_buf.raw[:rc] == data


def _evp_sign(pkey, data: bytes, hash_name: str) -> bytes:
    """Hash-then-sign using RSA PKCS#1 v1.5.

    For hash algorithms that OpenSSL 3.5 blocks inside EVP_DigestSignInit
    (currently SHA-1 and MD5), we use the manual path:
      1. Hash data with EVP_DigestInit/Update/Final (no policy restriction)
      2. Prepend the RFC 3447 DigestInfo DER prefix
      3. Sign the DigestInfo with raw RSA PKCS#1 (_pkey_sign_raw)

    For all other algorithms EVP_DigestSignInit works and we use the standard
    EVP_DigestSign* flow.
    """
    # Normalise pkey: accept both a plain int and a ctypes.c_void_p wrapper.
    pkey_val = pkey.value if isinstance(pkey, ctypes.c_void_p) else int(pkey)
    pkey_ptr = ctypes.c_void_p(pkey_val)

    if _OPENSSL3 and hash_name in _OSSL3_SIGN_BLOCKED:
        # Manual path: hash then raw-sign with DigestInfo wrapper
        digest = _compute_digest(data, hash_name)
        prefix = _DIGESTINFO_PREFIX.get(hash_name)
        if prefix is None:
            raise ValueError('No DigestInfo prefix for %r' % hash_name)
        di = prefix + digest
        return _pkey_sign_raw(pkey_ptr, di, _RSA_PKCS1_PADDING)

    md, md_needs_free = _get_md(hash_name)
    ctx = _EVP_MD_CTX_new()
    if not ctx:
        _free_md(md, md_needs_free)
        raise RuntimeError('EVP_MD_CTX_new failed')
    try:
        pctx = ctypes.c_void_p(None)
        if _EVP_DigestSignInit(ctx, ctypes.byref(pctx),
                               md, None, pkey_ptr) != 1:
            raise RuntimeError('EVP_DigestSignInit failed: %s' % _ossl_err_str())
        if pctx:
            _set_rsa_padding(pctx, _RSA_PKCS1_PADDING)
        if _EVP_DigestSignUpdate(ctx, data, len(data)) != 1:
            raise RuntimeError('EVP_DigestSignUpdate failed: %s' % _ossl_err_str())
        sig_len = ctypes.c_size_t(0)
        if _EVP_DigestSignFinal(ctx, None, ctypes.byref(sig_len)) != 1:
            raise RuntimeError('EVP_DigestSignFinal (size query) failed: %s'
                               % _ossl_err_str())
        sig_buf = ctypes.create_string_buffer(sig_len.value)
        if _EVP_DigestSignFinal(ctx, sig_buf, ctypes.byref(sig_len)) != 1:
            raise RuntimeError('EVP_DigestSignFinal failed: %s' % _ossl_err_str())
        return sig_buf.raw[:sig_len.value]
    finally:
        _EVP_MD_CTX_free(ctx)
        _free_md(md, md_needs_free)


def _evp_verify(pkey, data: bytes, signature: bytes, hash_name: str) -> bool:
    """Hash-then-verify using RSA PKCS#1 v1.5.

    Mirrors _evp_sign: uses the manual digest+DigestInfo+raw-verify path for
    hash algorithms that OpenSSL 3.5 blocks in EVP_DigestVerifyInit.
    """
    pkey_val = pkey.value if isinstance(pkey, ctypes.c_void_p) else int(pkey)
    pkey_ptr = ctypes.c_void_p(pkey_val)

    if _OPENSSL3 and hash_name in _OSSL3_SIGN_BLOCKED:
        digest = _compute_digest(data, hash_name)
        prefix = _DIGESTINFO_PREFIX.get(hash_name)
        if prefix is None:
            raise ValueError('No DigestInfo prefix for %r' % hash_name)
        di = prefix + digest
        return _pkey_verify_raw(pkey_ptr, di, signature, _RSA_PKCS1_PADDING)

    md, md_needs_free = _get_md(hash_name)
    ctx = _EVP_MD_CTX_new()
    if not ctx:
        _free_md(md, md_needs_free)
        raise RuntimeError('EVP_MD_CTX_new failed')
    try:
        pctx = ctypes.c_void_p(None)
        if _EVP_DigestVerifyInit(ctx, ctypes.byref(pctx),
                                 md, None, pkey_ptr) != 1:
            raise RuntimeError('EVP_DigestVerifyInit failed: %s' % _ossl_err_str())
        if pctx:
            _set_rsa_padding(pctx, _RSA_PKCS1_PADDING)
        if _EVP_DigestVerifyUpdate(ctx, data, len(data)) != 1:
            raise RuntimeError('EVP_DigestVerifyUpdate failed: %s' % _ossl_err_str())
        return _EVP_DigestVerifyFinal(ctx, signature, len(signature)) == 1
    finally:
        _EVP_MD_CTX_free(ctx)
        _free_md(md, md_needs_free)
