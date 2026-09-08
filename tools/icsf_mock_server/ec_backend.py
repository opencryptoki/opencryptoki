# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
ec_backend.py — Real EC (ECDSA) operations via ctypes → libcrypto.

Supports OpenSSL 1.1 and OpenSSL 3.x.

All EC key material is represented using the PKCS#11 CKA_* attributes:
  CKA_EC_PARAMS  — DER-encoded ECParameters (curve OID)
  CKA_EC_POINT   — DER-encoded OCTET STRING wrapping the uncompressed point,
                   i.e.  04 <len> 04 <X> <Y>  (PKCS#11 §2.3.3 / ANSI X9.62)
  CKA_VALUE      — private scalar (big-endian bytes), private key only

Public API
----------
ec_generate(ec_params_der) -> dict   {CKA_EC_PARAMS, CKA_EC_POINT, CKA_VALUE}
ec_sign(attr_dict, data, mech_rule)  -> bytes  (DER-encoded ECDSA signature)
ec_verify(attr_dict, data, signature, mech_rule) -> bool
"""

import ctypes
import logging

from cipher_backend import _libcrypto
from pkcs11_const import CKA_EC_PARAMS, CKA_EC_POINT, CKA_VALUE

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Detect OpenSSL version (same heuristic as rsa_backend)
# ---------------------------------------------------------------------------
_OPENSSL3 = (getattr(_libcrypto, 'EVP_PKEY_fromdata', None) is not None)


def _bind(name, restype, argtypes):
    fn = getattr(_libcrypto, name, None)
    if fn is None:
        _log.debug('ec_backend: symbol not found: %s', name)
        return None
    fn.restype  = restype
    fn.argtypes = argtypes
    return fn


# ---------------------------------------------------------------------------
# Error helpers (shared)
# ---------------------------------------------------------------------------

_ERR_get_error           = _bind('ERR_get_error',           ctypes.c_ulong, [])
_ERR_peek_last_error     = _bind('ERR_peek_last_error',     ctypes.c_ulong, [])
_ERR_error_string_n      = _bind('ERR_error_string_n',      None,
                                  [ctypes.c_ulong, ctypes.c_char_p, ctypes.c_size_t])


def _ossl_err():
    """Drain the OpenSSL error queue and return all error strings."""
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
    """Peek at the last error WITHOUT consuming it (queue stays intact)."""
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


# ---------------------------------------------------------------------------
# EVP_PKEY lifetime helpers (always available)
# ---------------------------------------------------------------------------

_EVP_PKEY_free = _bind('EVP_PKEY_free', None, [ctypes.c_void_p])

# ---------------------------------------------------------------------------
# EVP_PKEY_derive — ECDH shared-secret computation (available on both 1.1 / 3)
# ---------------------------------------------------------------------------

_EVP_PKEY_derive_init  = _bind('EVP_PKEY_derive_init', ctypes.c_int,
                                [ctypes.c_void_p])
_EVP_PKEY_derive_set_peer = _bind('EVP_PKEY_derive_set_peer', ctypes.c_int,
                                   [ctypes.c_void_p, ctypes.c_void_p])
_EVP_PKEY_derive       = _bind('EVP_PKEY_derive', ctypes.c_int,
                                [ctypes.c_void_p,
                                 ctypes.c_char_p,
                                 ctypes.POINTER(ctypes.c_size_t)])

# ---------------------------------------------------------------------------
# BIO helpers (needed by d2i / i2d paths for older OpenSSL)
# ---------------------------------------------------------------------------

_BIO_new_mem_buf = _bind('BIO_new_mem_buf', ctypes.c_void_p,
                          [ctypes.c_char_p, ctypes.c_int])
_BIO_free_all    = _bind('BIO_free_all',    None, [ctypes.c_void_p])

# ---------------------------------------------------------------------------
# Low-level EC helpers — available on both OpenSSL 1.1 and OpenSSL 3.
# (EC_GROUP/EC_POINT/BN APIs were not removed in OpenSSL 3, only deprecated.)
# Used by _ec_derive_pub (both versions) and by the OpenSSL 1.1 key-build path.
# ---------------------------------------------------------------------------

# OBJ_txt2nid: curve name → NID
_OBJ_txt2nid = _bind('OBJ_txt2nid', ctypes.c_int, [ctypes.c_char_p])

# EC_GROUP
_EC_GROUP_new_by_curve_name = _bind('EC_GROUP_new_by_curve_name',
                                    ctypes.c_void_p, [ctypes.c_int])
_EC_GROUP_free              = _bind('EC_GROUP_free', None, [ctypes.c_void_p])
_EC_GROUP_get_degree        = _bind('EC_GROUP_get_degree', ctypes.c_int,
                                    [ctypes.c_void_p])

# EC_POINT
_EC_POINT_new    = _bind('EC_POINT_new',  ctypes.c_void_p, [ctypes.c_void_p])
_EC_POINT_free   = _bind('EC_POINT_free', None,            [ctypes.c_void_p])
_EC_POINT_mul    = _bind('EC_POINT_mul',  ctypes.c_int,
                          [ctypes.c_void_p,   # group
                           ctypes.c_void_p,   # r
                           ctypes.c_void_p,   # n (scalar*G), or NULL
                           ctypes.c_void_p,   # q (point), or NULL
                           ctypes.c_void_p,   # m (scalar*q), or NULL
                           ctypes.c_void_p])  # BN_CTX*, or NULL
_EC_POINT_oct2point = _bind('EC_POINT_oct2point', ctypes.c_int,
                             [ctypes.c_void_p, ctypes.c_void_p,
                              ctypes.c_char_p, ctypes.c_size_t,
                              ctypes.c_void_p])
_EC_POINT_point2oct = _bind('EC_POINT_point2oct', ctypes.c_size_t,
                             [ctypes.c_void_p, ctypes.c_void_p,
                              ctypes.c_int,
                              ctypes.c_char_p, ctypes.c_size_t,
                              ctypes.c_void_p])
_EC_POINT_get_affine_coordinates = _bind('EC_POINT_get_affine_coordinates',
                                          ctypes.c_int,
                                          [ctypes.c_void_p,   # group
                                           ctypes.c_void_p,   # point
                                           ctypes.c_void_p,   # x BN
                                           ctypes.c_void_p,   # y BN
                                           ctypes.c_void_p])  # ctx

# BIGNUM
_BN_new      = _bind('BN_new',      ctypes.c_void_p, [])
_BN_free     = _bind('BN_free',     None,            [ctypes.c_void_p])
_BN_bin2bn   = _bind('BN_bin2bn',   ctypes.c_void_p,
                      [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p])
_BN_bn2bin   = _bind('BN_bn2bin',   ctypes.c_int,
                      [ctypes.c_void_p, ctypes.c_char_p])
_BN_bn2binpad = _bind('BN_bn2binpad', ctypes.c_int,
                       [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int])
_BN_num_bits = _bind('BN_num_bits', ctypes.c_int,    [ctypes.c_void_p])

_POINT_CONVERSION_UNCOMPRESSED = 4

# ---------------------------------------------------------------------------
# OpenSSL 1.1 only: EC_KEY API (removed/deprecated in OpenSSL 3)
# ---------------------------------------------------------------------------

if not _OPENSSL3:
    _EC_KEY_new_by_curve_name = _bind('EC_KEY_new_by_curve_name',
                                      ctypes.c_void_p, [ctypes.c_int])
    _EC_KEY_free              = _bind('EC_KEY_free', None, [ctypes.c_void_p])
    _EC_KEY_generate_key      = _bind('EC_KEY_generate_key', ctypes.c_int,
                                      [ctypes.c_void_p])
    _EC_KEY_get0_group        = _bind('EC_KEY_get0_group', ctypes.c_void_p,
                                      [ctypes.c_void_p])
    _EC_KEY_get0_public_key   = _bind('EC_KEY_get0_public_key', ctypes.c_void_p,
                                      [ctypes.c_void_p])
    _EC_KEY_get0_private_key  = _bind('EC_KEY_get0_private_key', ctypes.c_void_p,
                                      [ctypes.c_void_p])
    _EC_KEY_set_public_key    = _bind('EC_KEY_set_public_key', ctypes.c_int,
                                      [ctypes.c_void_p, ctypes.c_void_p])
    _EC_KEY_set_private_key   = _bind('EC_KEY_set_private_key', ctypes.c_int,
                                      [ctypes.c_void_p, ctypes.c_void_p])
    _EVP_PKEY_new             = _bind('EVP_PKEY_new', ctypes.c_void_p, [])
    _EVP_PKEY_assign_EC_KEY   = _bind('EVP_PKEY_assign_EC_KEY', ctypes.c_int,
                                      [ctypes.c_void_p, ctypes.c_void_p])
    _d2i_ECParameters         = _bind('d2i_ECParameters', ctypes.c_void_p,
                                      [ctypes.POINTER(ctypes.c_void_p),
                                       ctypes.POINTER(ctypes.c_char_p),
                                       ctypes.c_long])

# ---------------------------------------------------------------------------
# OpenSSL 3: EVP_PKEY_fromdata / EVP_PKEY_CTX_new_from_name
# ---------------------------------------------------------------------------

if _OPENSSL3:
    _EVP_PKEY_CTX_new_from_name = _bind('EVP_PKEY_CTX_new_from_name',
                                         ctypes.c_void_p,
                                         [ctypes.c_void_p, ctypes.c_char_p,
                                          ctypes.c_char_p])
    _EVP_PKEY_CTX_free      = _bind('EVP_PKEY_CTX_free', None,
                                     [ctypes.c_void_p])
    _EVP_PKEY_fromdata_init = _bind('EVP_PKEY_fromdata_init', ctypes.c_int,
                                     [ctypes.c_void_p])
    _EVP_PKEY_fromdata      = _bind('EVP_PKEY_fromdata',  ctypes.c_int,
                                     [ctypes.c_void_p,
                                      ctypes.POINTER(ctypes.c_void_p),
                                      ctypes.c_int, ctypes.c_void_p])
    _EVP_PKEY_keygen_init   = _bind('EVP_PKEY_keygen_init', ctypes.c_int,
                                     [ctypes.c_void_p])
    _EVP_PKEY_keygen        = _bind('EVP_PKEY_keygen',  ctypes.c_int,
                                     [ctypes.c_void_p,
                                      ctypes.POINTER(ctypes.c_void_p)])
    _EVP_PKEY_get_octet_string_param = _bind('EVP_PKEY_get_octet_string_param',
                                              ctypes.c_int,
                                              [ctypes.c_void_p, ctypes.c_char_p,
                                               ctypes.c_char_p,
                                               ctypes.c_size_t,
                                               ctypes.POINTER(ctypes.c_size_t)])
    _EVP_PKEY_CTX_set_group_name = _bind('EVP_PKEY_CTX_set_group_name',
                                          ctypes.c_int,
                                          [ctypes.c_void_p, ctypes.c_char_p])
    _EVP_PKEY_get_bn_param       = _bind('EVP_PKEY_get_bn_param', ctypes.c_int,
                                          [ctypes.c_void_p, ctypes.c_char_p,
                                           ctypes.POINTER(ctypes.c_void_p)])
    # OSSL_PARAM helpers (same structure as rsa_backend)
    class _OSSLParam(ctypes.Structure):
        _fields_ = [
            ('key',         ctypes.c_char_p),
            ('data_type',   ctypes.c_uint),
            ('data',        ctypes.c_void_p),
            ('data_size',   ctypes.c_size_t),
            ('return_size', ctypes.c_size_t),
        ]
    _OSSL_PARAM_UNSIGNED_INTEGER = 2   # BN: big-endian bytes (used for priv scalar)
    _OSSL_PARAM_OCTET_STRING     = 5   # used for pub point
    # OSSL_KEYMGMT_SELECT_* flags (openssl/core_dispatch.h).
    # The 'group' OSSL_PARAM carries a domain parameter — bit 0x04 must be
    # included whenever a group/curve name is passed to EVP_PKEY_fromdata.
    _OSSL_KEYMGMT_SELECT_PRIVATE_KEY       = 0x01
    _OSSL_KEYMGMT_SELECT_PUBLIC_KEY        = 0x02
    _OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS = 0x04
    _EVP_PKEY_PRIVATE_KEY = (_OSSL_KEYMGMT_SELECT_PRIVATE_KEY |
                             _OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)   # 0x05
    _EVP_PKEY_PUBLIC_KEY  = (_OSSL_KEYMGMT_SELECT_PUBLIC_KEY  |
                             _OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)   # 0x06
    _EVP_PKEY_KEYPAIR     = (_OSSL_KEYMGMT_SELECT_PRIVATE_KEY |
                             _OSSL_KEYMGMT_SELECT_PUBLIC_KEY  |
                             _OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)   # 0x07

# ---------------------------------------------------------------------------
# EVP_PKEY_sign / _verify — raw sign of pre-hashed data (no digest step).
# This is the correct API for CKM_ECDSA where the caller passes an already-
# hashed value.  EVP_DigestSignInit with md=NULL is not valid for EC keys.
# ---------------------------------------------------------------------------

_EVP_PKEY_CTX_new    = _bind('EVP_PKEY_CTX_new',    ctypes.c_void_p,
                               [ctypes.c_void_p, ctypes.c_void_p])
_EVP_PKEY_CTX_free_s = _bind('EVP_PKEY_CTX_free',   None, [ctypes.c_void_p])
_EVP_PKEY_sign_init  = _bind('EVP_PKEY_sign_init',   ctypes.c_int,
                               [ctypes.c_void_p])
_EVP_PKEY_sign       = _bind('EVP_PKEY_sign',        ctypes.c_int,
                               [ctypes.c_void_p, ctypes.c_char_p,
                                ctypes.POINTER(ctypes.c_size_t),
                                ctypes.c_char_p, ctypes.c_size_t])
_EVP_PKEY_verify_init = _bind('EVP_PKEY_verify_init', ctypes.c_int,
                                [ctypes.c_void_p])
_EVP_PKEY_verify     = _bind('EVP_PKEY_verify',       ctypes.c_int,
                               [ctypes.c_void_p, ctypes.c_char_p,
                                ctypes.c_size_t, ctypes.c_char_p,
                                ctypes.c_size_t])

# ---------------------------------------------------------------------------
# OID → curve name map for OpenSSL 3
# ---------------------------------------------------------------------------

# Well-known EC curve OIDs (DER-encoded, matching OCK_* macros in ec_curves.h)
# mapped to the OpenSSL curve name accepted by EVP_PKEY_CTX_set_group_name /
# EVP_PKEY_CTX_new_from_name and (on OpenSSL 1.1) OBJ_txt2nid / EC_GROUP.
_OID_TO_CURVE = {
    # NIST prime curves
    bytes.fromhex('06082a8648ce3d030101'): b'prime192v1',   # P-192
    bytes.fromhex('06052b81040021'):       b'secp224r1',    # P-224
    bytes.fromhex('06082a8648ce3d030107'): b'prime256v1',   # P-256
    bytes.fromhex('06052b81040022'):       b'secp384r1',    # P-384
    bytes.fromhex('06052b81040023'):       b'secp521r1',    # P-521
    # Koblitz
    bytes.fromhex('06052b8104000a'):       b'secp256k1',
    # Brainpool
    bytes.fromhex('06092b2403030208010101'): b'brainpoolP160r1',
    bytes.fromhex('06092b2403030208010102'): b'brainpoolP160t1',
    bytes.fromhex('06092b2403030208010103'): b'brainpoolP192r1',
    bytes.fromhex('06092b2403030208010104'): b'brainpoolP192t1',
    bytes.fromhex('06092b2403030208010105'): b'brainpoolP224r1',
    bytes.fromhex('06092b2403030208010106'): b'brainpoolP224t1',
    bytes.fromhex('06092b2403030208010107'): b'brainpoolP256r1',
    bytes.fromhex('06092b2403030208010108'): b'brainpoolP256t1',
    bytes.fromhex('06092b2403030208010109'): b'brainpoolP320r1',
    bytes.fromhex('06092b240303020801010a'): b'brainpoolP320t1',
    bytes.fromhex('06092b240303020801010b'): b'brainpoolP384r1',
    bytes.fromhex('06092b240303020801010c'): b'brainpoolP384t1',
    bytes.fromhex('06092b240303020801010d'): b'brainpoolP512r1',
    bytes.fromhex('06092b240303020801010e'): b'brainpoolP512t1',
}

# Reverse map for key generation
_CURVE_OID = {v: k for k, v in _OID_TO_CURVE.items()}

# Curve name → field size in bytes (ceil(bit_length / 8))
_CURVE_FIELD_BYTES = {
    b'prime192v1':      24,
    b'secp224r1':       28,
    b'prime256v1':      32,
    b'secp384r1':       48,
    b'secp521r1':       66,   # ceil(521/8)
    b'secp256k1':       32,
    b'brainpoolP160r1': 20,
    b'brainpoolP160t1': 20,
    b'brainpoolP192r1': 24,
    b'brainpoolP192t1': 24,
    b'brainpoolP224r1': 28,
    b'brainpoolP224t1': 28,
    b'brainpoolP256r1': 32,
    b'brainpoolP256t1': 32,
    b'brainpoolP320r1': 40,
    b'brainpoolP320t1': 40,
    b'brainpoolP384r1': 48,
    b'brainpoolP384t1': 48,
    b'brainpoolP512r1': 64,
    b'brainpoolP512t1': 64,
}


def _field_size(ec_params_der: bytes) -> int:
    """Return the field size in bytes for the curve identified by ec_params_der."""
    curve_name = _OID_TO_CURVE.get(ec_params_der)
    return _CURVE_FIELD_BYTES.get(curve_name, 66) if curve_name else 66


def ec_max_sig_len(ec_params_der: bytes) -> int:
    """Return the fixed raw R||S signature length for the given curve OID.

    ICSF returns ECDSA signatures as raw  R || S  with each component
    zero-padded to exactly n bytes (the field size).  The length is therefore
    always  2 * n  — no variable-length DER encoding.
    """
    return 2 * _field_size(ec_params_der)


def _der_sig_to_raw(der_sig: bytes, n: int) -> bytes:
    """Convert a DER-encoded ECDSA signature to fixed-size raw  R || S.

    Each of R and S is stripped of any leading 0x00 padding byte and then
    zero-padded on the left to exactly n bytes.
    """
    # SEQUENCE { INTEGER r, INTEGER s }
    if not der_sig or der_sig[0] != 0x30:
        raise ValueError('DER sig does not start with SEQUENCE tag')
    pos = 1
    # Skip SEQUENCE length (may be 1 or 2 bytes)
    if der_sig[pos] & 0x80:
        pos += 1 + (der_sig[pos] & 0x7f)
    else:
        pos += 1

    def _read_int():
        nonlocal pos
        if der_sig[pos] != 0x02:
            raise ValueError('Expected INTEGER tag 0x02, got 0x%02x' % der_sig[pos])
        pos += 1
        length = der_sig[pos]; pos += 1
        val = der_sig[pos:pos + length]; pos += length
        # Strip leading 0x00 padding
        val = val.lstrip(b'\x00') or b'\x00'
        return val

    r = _read_int()
    s = _read_int()
    return r.rjust(n, b'\x00') + s.rjust(n, b'\x00')


def _raw_sig_to_der(raw_sig: bytes, n: int) -> bytes:
    """Convert a fixed-size raw  R || S  signature to DER ECDSA encoding."""
    if len(raw_sig) != 2 * n:
        raise ValueError('Raw sig length %d != 2*%d' % (len(raw_sig), n))
    r = raw_sig[:n].lstrip(b'\x00') or b'\x00'
    s = raw_sig[n:].lstrip(b'\x00') or b'\x00'

    def _encode_int(v):
        if v[0] & 0x80:          # prepend 0x00 so it stays positive
            v = b'\x00' + v
        return bytes([0x02, len(v)]) + v

    r_enc = _encode_int(r)
    s_enc = _encode_int(s)
    content = r_enc + s_enc
    # SEQUENCE length: use 2-byte form if needed
    if len(content) > 127:
        seq_len = bytes([0x81, len(content)])
    else:
        seq_len = bytes([len(content)])
    return b'\x30' + seq_len + content


def ec_curve_supported(ec_params_der: bytes) -> bool:
    """Return True if OpenSSL can actually use the curve identified by ec_params_der.

    Performs a live probe: looks up the curve name in _OID_TO_CURVE, then
    asks OpenSSL to create the EC_GROUP (which fails immediately if the curve
    is not compiled in or disabled by the active provider).  No key material
    is generated or stored.
    """
    curve_name = _OID_TO_CURVE.get(ec_params_der)
    if curve_name is None:
        return False   # not even in our known-curve table
    nid = _OBJ_txt2nid(curve_name)
    if nid <= 0:
        return False
    group = _EC_GROUP_new_by_curve_name(nid)
    if not group:
        _ossl_err()   # drain error queue
        return False
    _EC_GROUP_free(group)
    return True


# ---------------------------------------------------------------------------
# CKA_EC_POINT DER-OCTET-STRING wrap / unwrap helpers
#
# PKCS#11 §2.3.3: CKA_EC_POINT is a DER-encoded OCTET STRING whose content
# is the X9.62 uncompressed point  04 || X || Y.  OpenSSL's EVP_PKEY API
# (both 1.x and 3.x) wants the raw  04 || X || Y  bytes, not the outer DER
# OCTET STRING wrapper.
# ---------------------------------------------------------------------------

def _wrap_ec_point(raw_point: bytes) -> bytes:
    """Wrap raw  04 || X || Y  in a DER OCTET STRING for CKA_EC_POINT storage."""
    n = len(raw_point)
    if n < 0x80:
        length = bytes([n])
    elif n <= 0xFF:
        length = bytes([0x81, n])
    else:
        length = bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    return b'\x04' + length + raw_point


def _unwrap_ec_point(ec_point: bytes) -> bytes:
    """Strip the outer DER OCTET STRING tag/length from CKA_EC_POINT.

    Accepts both the DER-wrapped form (tag 0x04) and the raw form
    (tag 0x04 used as the uncompressed-point indicator) by checking the
    second byte: if it looks like a valid DER length *and* the remaining
    content starts with a recognised point-format byte (02/03/04/06/07),
    treat it as DER-wrapped; otherwise return as-is.

    For points whose inner content does not start with a recognised format
    byte (bare X||Y or X||Y with a leading null), use the curve-aware
    decode_ec_public_value() instead.
    """
    if not ec_point:
        return ec_point
    if ec_point[0] != 0x04 or len(ec_point) < 2:
        return ec_point
    # Try to parse a DER length at offset 1
    b1 = ec_point[1]
    if b1 < 0x80:
        hdr = 2; inner_len = b1
    elif b1 == 0x81 and len(ec_point) >= 3:
        hdr = 3; inner_len = ec_point[2]
    elif b1 == 0x82 and len(ec_point) >= 4:
        hdr = 4; inner_len = (ec_point[2] << 8) | ec_point[3]
    else:
        return ec_point  # unrecognised form — pass through
    if hdr + inner_len == len(ec_point) and inner_len >= 1 \
            and ec_point[hdr] in (0x02, 0x03, 0x04, 0x06, 0x07):
        # Outer tag 0x04 (OCTET STRING), length matches, inner starts with
        # a recognised point-format byte → DER-wrapped, unwrap it.
        return ec_point[hdr:hdr + inner_len]
    # Not DER-wrapped (or inner content has no recognised format byte) —
    # return as-is; caller should use decode_ec_public_value() if the curve
    # is known.
    return ec_point


def decode_ec_public_value(raw: bytes, ec_params_der: bytes) -> bytes:
    """Decode a peer EC public value into a raw point OpenSSL can accept.

    Mirrors ec_point_from_public_data() in usr/lib/common/mech_ec.c.

    The publicValue in a DVK/ECDH request may be encoded in several ways
    (ICSF manual: "with or without DER encoding"):

      - Raw point with format byte   : 04||X||Y, 02/03||X, 06/07||X||Y
      - BER OCTET STRING wrapping    : any of the above, DER-encoded
      - No format byte (trimmed)     : X||Y with leading zeros possibly
                                       removed; padded back to 2*p bytes

    Algorithm (matches the C reference exactly):
      1. If the first byte is a valid point-format byte AND the total length
         matches the expected size for that format → raw point, return as-is.
      2. Otherwise try BER OCTET STRING decode; if it succeeds AND the inner
         length + format byte match → return the inner bytes.
      3. Fallback: treat data (inner if BER-decoded, raw otherwise) as a
         trimmed X||Y without format byte.  Zero-pad on the left to 2*p and
         prepend 0x04 (uncompressed).

    Parameters
    ----------
    raw          : bytes — publicValue as received off the wire
    ec_params_der: bytes — DER OID of the curve (CKA_EC_PARAMS of base key)

    Returns
    -------
    bytes — raw point accepted by OpenSSL: 04||X||Y, 02/03||X, or 06/07||X||Y
    """
    p = _field_size(ec_params_der)   # field size in bytes for this curve

    # --- Step 1: check for raw point with a valid format byte ---
    form = raw[0] & ~0x01 if raw else 0
    if form == 0x02:  # POINT_CONVERSION_COMPRESSED (02 or 03)
        if len(raw) == p + 1:
            return raw
    elif form in (0x04, 0x06):  # POINT_CONVERSION_UNCOMPRESSED / HYBRID (04/06/07)
        if len(raw) == 2 * p + 1:
            return raw

    # --- Step 2: try BER OCTET STRING decode ---
    value = None
    if raw and raw[0] == 0x04 and len(raw) >= 2:
        b1 = raw[1]
        if b1 < 0x80:
            hdr = 2; inner_len = b1
        elif b1 == 0x81 and len(raw) >= 3:
            hdr = 3; inner_len = raw[2]
        elif b1 == 0x82 and len(raw) >= 4:
            hdr = 4; inner_len = (raw[2] << 8) | raw[3]
        else:
            hdr = 0; inner_len = -1

        if inner_len >= 0 and hdr + inner_len == len(raw):
            inner = raw[hdr:hdr + inner_len]
            # Check inner for a valid format byte + correct length
            iform = inner[0] & ~0x01 if inner else 0
            if iform == 0x02 and len(inner) == p + 1:
                return inner
            if iform in (0x04, 0x06) and len(inner) == 2 * p + 1:
                return inner
            # Inner content has no valid format byte — use for fallback
            if p < len(inner) <= 2 * p:
                value = inner

    # --- Step 3: fallback — bare X||Y, zero-pad left to 2*p, prepend 04 ---
    # Use BER-decoded inner if available, otherwise the raw data itself.
    src = value if value is not None else raw
    src_len = len(src)
    if src_len <= p or src_len > 2 * p:
        # Too short (can't contain both X and Y) or too large — pass through
        return raw
    pad = 2 * p - src_len
    return b'\x04' + b'\x00' * pad + src


class CurveNotSupportedError(Exception):
    """Raised when a curve OID is not known or not supported by this OpenSSL build."""


def _curve_name_from_params(ec_params: bytes) -> bytes:
    """Return OpenSSL curve name bytes for *ec_params* DER, or raise CurveNotSupportedError."""
    name = _OID_TO_CURVE.get(ec_params)
    if name is not None:
        return name
    raise CurveNotSupportedError('Unknown EC curve OID: %s' % ec_params.hex())


# ---------------------------------------------------------------------------
# Build EVP_PKEY from PKCS#11 attribute dict
# ---------------------------------------------------------------------------

def _build_ec_pkey(attr_dict: dict, private: bool) -> ctypes.c_void_p:
    """Build EVP_PKEY* from CKA_EC_PARAMS / CKA_EC_POINT / CKA_VALUE.

    CKA_EC_POINT is optional for private keys (PKCS#11 does not mandate it on
    private key objects).  When absent the public point is derived from the
    private scalar inside the OpenSSL-version-specific builder.
    CKA_EC_POINT is stored in DER-OCTET-STRING form; unwrap it to raw before
    passing to OpenSSL.
    """
    ec_params = attr_dict.get(CKA_EC_PARAMS)
    ec_point  = _unwrap_ec_point(attr_dict.get(CKA_EC_POINT))  # raw 04||X||Y
    ec_value  = attr_dict.get(CKA_VALUE)      # private scalar

    if not ec_params:
        raise ValueError('EC key missing CKA_EC_PARAMS')
    if not private and not ec_point:
        raise ValueError('EC public key missing CKA_EC_POINT')
    if private and not ec_value:
        raise ValueError('EC private key missing CKA_VALUE (private scalar)')

    if _OPENSSL3:
        return _build_ec_pkey_ossl3(ec_params, ec_point, ec_value, private)
    else:
        return _build_ec_pkey_ossl1(ec_params, ec_point, ec_value, private)


def _build_ec_pkey_ossl3(ec_params, ec_point, ec_value, private):
    """OpenSSL 3: build EVP_PKEY via EVP_PKEY_fromdata with OSSL_PARAM array.

    When ec_point is absent (private key with no CKA_EC_POINT), derive the
    public point via _ec_derive_pub() which uses EC_GROUP_new_by_curve_name +
    EC_POINT_mul — the same approach as ec_point_from_priv_key() in mech_ec.c.
    """
    curve_name = _curve_name_from_params(ec_params)

    # If public point is missing, derive it via low-level OpenSSL EC math.
    if private and not ec_point:
        ec_point = _ec_derive_pub(curve_name, ec_value)

    # Build the OSSL_PARAM array using the module-level _OSSLParam struct.
    # All ctypes buffers must stay alive until EVP_PKEY_fromdata returns.
    bufs = []
    _OSSL_PARAM_UTF8_STRING = 4
    _OSSL_PARAM_UNMODIFIED  = ctypes.c_size_t(-1).value

    def _make_param(key, dtype, data_bytes):
        buf = ctypes.create_string_buffer(data_bytes, len(data_bytes))
        bufs.append(buf)
        p = _OSSLParam()
        p.key         = key
        p.data_type   = dtype
        p.data        = ctypes.cast(buf, ctypes.c_void_p)
        p.data_size   = len(data_bytes)
        p.return_size = _OSSL_PARAM_UNMODIFIED
        return p

    _log.debug('_build_ec_pkey_ossl3: curve=%r private=%s ec_point=%s ec_value=%s',
               curve_name,
               private,
               ec_point.hex() if ec_point else None,
               ('%d bytes' % len(ec_value)) if ec_value else None)

    params = [_make_param(b'group', _OSSL_PARAM_UTF8_STRING, curve_name)]
    if ec_point:
        params.append(_make_param(b'pub',  _OSSL_PARAM_OCTET_STRING,     ec_point))
    if private:
        params.append(_make_param(b'priv', _OSSL_PARAM_UNSIGNED_INTEGER, ec_value))

    # Terminator
    term = _OSSLParam()
    term.key = None; term.data_type = 0; term.data = None
    term.data_size = 0; term.return_size = 0
    params.append(term)

    ParamArray = _OSSLParam * len(params)
    param_arr  = ParamArray(*params)

    pctx = _EVP_PKEY_CTX_new_from_name(None, b'EC', None)
    if not pctx:
        raise CurveNotSupportedError(
            'EVP_PKEY_CTX_new_from_name(EC) failed: %s' % _ossl_err())
    try:
        if _EVP_PKEY_fromdata_init(pctx) != 1:
            raise CurveNotSupportedError(
                'EVP_PKEY_fromdata_init failed: %s' % _ossl_err())
        selection = _EVP_PKEY_KEYPAIR if private else _EVP_PKEY_PUBLIC_KEY
        pkey = ctypes.c_void_p(None)
        rc = _EVP_PKEY_fromdata(pctx, ctypes.byref(pkey), selection,
                                ctypes.cast(param_arr, ctypes.c_void_p))
        # Capture the error string BEFORE the finally block calls CTX_free,
        # which clears the OpenSSL error queue on some builds.
        err = _ossl_peek_err() or _ossl_err()
        if rc != 1:
            raise CurveNotSupportedError(
                'EVP_PKEY_fromdata(EC) failed: %s' % err)
        return pkey
    finally:
        _EVP_PKEY_CTX_free(pctx)


def _ec_derive_pub(curve_name: bytes, ec_value: bytes) -> bytes:
    """Derive the uncompressed public point pub = d*G via OpenSSL low-level API.

    Mirrors ec_point_from_priv_key() in usr/lib/common/mech_ec.c:
      EC_GROUP_new_by_curve_name(nid) → EC_POINT_mul(group, pub, bn_d, NULL, NULL, NULL)
      → EC_POINT_get_affine_coordinates → BN_bn2binpad

    Works on both OpenSSL 1.1 and OpenSSL 3 (these APIs were not removed in 3.x).
    Returns bytes: 0x04 || X || Y  (uncompressed point, big-endian).
    """
    nid = _OBJ_txt2nid(curve_name)
    if nid <= 0:
        raise ValueError('OBJ_txt2nid(%r) failed — unknown curve name' % curve_name)

    group = _EC_GROUP_new_by_curve_name(nid)
    if not group:
        raise CurveNotSupportedError(
            'EC_GROUP_new_by_curve_name(%d/%r) failed: %s' % (nid, curve_name, _ossl_err()))
    try:
        p_len = (_EC_GROUP_get_degree(group) + 7) // 8
        if p_len <= 0:
            raise RuntimeError('EC_GROUP_get_degree returned 0')

        bn_d = _BN_bin2bn(ec_value, len(ec_value), None)
        if not bn_d:
            raise RuntimeError('BN_bin2bn failed: %s' % _ossl_err())
        try:
            pub = _EC_POINT_new(group)
            if not pub:
                raise RuntimeError('EC_POINT_new failed: %s' % _ossl_err())
            try:
                if _EC_POINT_mul(group, pub, bn_d, None, None, None) != 1:
                    raise RuntimeError('EC_POINT_mul failed: %s' % _ossl_err())

                bn_x = _BN_new()
                bn_y = _BN_new()
                if not bn_x or not bn_y:
                    raise RuntimeError('BN_new failed')
                try:
                    if _EC_POINT_get_affine_coordinates(
                            group, pub, bn_x, bn_y, None) != 1:
                        raise RuntimeError('EC_POINT_get_affine_coordinates failed: %s'
                                           % _ossl_err())
                    buf = ctypes.create_string_buffer(1 + 2 * p_len)
                    buf[0:1] = bytes([_POINT_CONVERSION_UNCOMPRESSED])
                    _BN_bn2binpad(bn_x, ctypes.cast(ctypes.addressof(buf) + 1,
                                                    ctypes.c_char_p), p_len)
                    _BN_bn2binpad(bn_y, ctypes.cast(ctypes.addressof(buf) + 1 + p_len,
                                                    ctypes.c_char_p), p_len)
                    return bytes(buf)
                finally:
                    if bn_x:
                        _BN_free(bn_x)
                    if bn_y:
                        _BN_free(bn_y)
            finally:
                _EC_POINT_free(pub)
        finally:
            _BN_free(bn_d)
    finally:
        _EC_GROUP_free(group)


def _build_ec_pkey_ossl1(ec_params, ec_point, ec_value, private):
    """OpenSSL 1.1: build EC_KEY + EVP_PKEY.

    When ec_point is None (private key with no CKA_EC_POINT) the public point
    is computed via EC_POINT_mul(group, pub, scalar, NULL, NULL, NULL) — i.e.
    pub = scalar * G.
    """
    # Parse the DER ECParameters to get an EC_KEY with the correct group
    params_ptr = ctypes.cast(ctypes.c_char_p(ec_params),
                             ctypes.POINTER(ctypes.c_char))
    ec_key = _d2i_ECParameters(None,
                               ctypes.byref(params_ptr),
                               len(ec_params))
    if not ec_key:
        raise RuntimeError('d2i_ECParameters failed: %s' % _ossl_err())

    try:
        group = _EC_KEY_get0_group(ec_key)

        # Resolve the public point bytes: supplied directly, or derive from scalar.
        pub_bytes = ec_point
        if not pub_bytes and private:
            curve_name = _curve_name_from_params(ec_params)
            pub_bytes = _ec_derive_pub(curve_name, ec_value)

        # Parse and set the public point on the EC_KEY
        point = _EC_POINT_new(group)
        if not point:
            raise RuntimeError('EC_POINT_new failed')
        try:
            if _EC_POINT_oct2point(group, point, pub_bytes,
                                   len(pub_bytes), None) != 1:
                raise RuntimeError('EC_POINT_oct2point failed: %s' % _ossl_err())
            if _EC_KEY_set_public_key(ec_key, point) != 1:
                raise RuntimeError('EC_KEY_set_public_key failed: %s' % _ossl_err())
        finally:
            _EC_POINT_free(point)

        if private:
            bn_d = _BN_bin2bn(ec_value, len(ec_value), None)
            if not bn_d:
                raise RuntimeError('BN_bin2bn(ec_value) failed')
            try:
                if _EC_KEY_set_private_key(ec_key, bn_d) != 1:
                    raise RuntimeError('EC_KEY_set_private_key failed: %s'
                                       % _ossl_err())
            finally:
                _BN_free(bn_d)

        pkey = _EVP_PKEY_new()
        if not pkey:
            raise RuntimeError('EVP_PKEY_new failed')
        if _EVP_PKEY_assign_EC_KEY(pkey, ec_key) != 1:
            _EVP_PKEY_free(pkey)
            raise RuntimeError('EVP_PKEY_assign_EC_KEY failed: %s' % _ossl_err())
        ec_key = None  # ownership transferred
        return pkey
    finally:
        if ec_key:
            _EC_KEY_free(ec_key)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def ec_generate(ec_params_der: bytes) -> dict:
    """Generate a real EC key pair.  Returns dict with CKA_* keys."""
    if _OPENSSL3:
        return _ec_generate_ossl3(ec_params_der)
    else:
        return _ec_generate_ossl1(ec_params_der)


def _ossl3_get_pub(pkey) -> bytes:
    """Extract uncompressed EC public point from an EVP_PKEY* (OpenSSL 3)."""
    buf = ctypes.create_string_buffer(256)
    rlen = ctypes.c_size_t(len(buf))
    if _EVP_PKEY_get_octet_string_param(pkey, b'pub', buf,
                                        len(buf), ctypes.byref(rlen)) != 1:
        raise RuntimeError('get pub point failed: %s' % _ossl_err())
    return bytes(buf.raw[:rlen.value])


def _ossl3_get_priv(pkey) -> bytes:
    """Extract EC private scalar from an EVP_PKEY* (OpenSSL 3).

    Tries octet-string first (most builds); falls back to BN param for builds
    that expose the private scalar as OSSL_PARAM_UNSIGNED_INTEGER instead.
    """
    buf = ctypes.create_string_buffer(256)
    rlen = ctypes.c_size_t(len(buf))
    # Clear any pending errors so we can detect a genuine failure below.
    _ossl_err()
    if _EVP_PKEY_get_octet_string_param(pkey, b'priv', buf,
                                        len(buf), ctypes.byref(rlen)) == 1:
        return bytes(buf.raw[:rlen.value])

    # Octet-string getter failed (e.g. "param of incompatible type" on some
    # OpenSSL 3 builds that store the private scalar as an unsigned integer).
    # Fall back to EVP_PKEY_get_bn_param and encode the BN to big-endian bytes.
    _ossl_err()   # drain the failed-getter error
    bn = ctypes.c_void_p(None)
    if _EVP_PKEY_get_bn_param(pkey, b'priv', ctypes.byref(bn)) != 1:
        raise RuntimeError('get priv scalar (BN fallback) failed: %s' % _ossl_err())
    try:
        nbits  = _BN_num_bits(bn)
        nbytes = (nbits + 7) // 8
        priv_buf = ctypes.create_string_buffer(nbytes)
        _BN_bn2bin(bn, priv_buf)
        return bytes(priv_buf.raw[:nbytes])
    finally:
        _BN_free(bn)



def _ec_generate_ossl3(ec_params_der):
    curve_name = _curve_name_from_params(ec_params_der)
    pctx = _EVP_PKEY_CTX_new_from_name(None, b'EC', None)
    if not pctx:
        raise CurveNotSupportedError(
            'EVP_PKEY_CTX_new_from_name(EC) failed: %s' % _ossl_err())
    try:
        if _EVP_PKEY_keygen_init(pctx) != 1:
            raise CurveNotSupportedError(
                'EVP_PKEY_keygen_init failed: %s' % _ossl_err())
        if _EVP_PKEY_CTX_set_group_name(pctx, curve_name) <= 0:
            raise CurveNotSupportedError(
                'EVP_PKEY_CTX_set_group_name(%r) failed: %s'
                % (curve_name, _ossl_err()))
        pkey = ctypes.c_void_p(None)
        if _EVP_PKEY_keygen(pctx, ctypes.byref(pkey)) != 1:
            raise CurveNotSupportedError(
                'EVP_PKEY_keygen failed: %s' % _ossl_err())
    finally:
        _EVP_PKEY_CTX_free(pctx)

    try:
        ec_point = _ossl3_get_pub(pkey)
        ec_value = _ossl3_get_priv(pkey)
        return {
            CKA_EC_PARAMS: ec_params_der,
            CKA_EC_POINT:  _wrap_ec_point(ec_point),
            CKA_VALUE:     ec_value,
        }
    finally:
        _EVP_PKEY_free(pkey)


def _ec_generate_ossl1(ec_params_der):
    params_ptr = ctypes.cast(ctypes.c_char_p(ec_params_der),
                             ctypes.POINTER(ctypes.c_char))
    ec_key = _d2i_ECParameters(None, ctypes.byref(params_ptr), len(ec_params_der))
    if not ec_key:
        raise CurveNotSupportedError('d2i_ECParameters failed: %s' % _ossl_err())
    try:
        if _EC_KEY_generate_key(ec_key) != 1:
            raise CurveNotSupportedError(
                'EC_KEY_generate_key failed: %s' % _ossl_err())

        group = _EC_KEY_get0_group(ec_key)
        pub_point = _EC_KEY_get0_public_key(ec_key)

        # Encode uncompressed public point
        pt_len = _EC_POINT_point2oct(group, pub_point,
                                     _POINT_CONVERSION_UNCOMPRESSED,
                                     None, 0, None)
        pt_buf = ctypes.create_string_buffer(pt_len)
        _EC_POINT_point2oct(group, pub_point,
                            _POINT_CONVERSION_UNCOMPRESSED,
                            pt_buf, pt_len, None)
        ec_point = pt_buf.raw[:pt_len]

        # Encode private scalar
        bn_d = _EC_KEY_get0_private_key(ec_key)
        nbits  = _BN_num_bits(bn_d)
        nbytes = (nbits + 7) // 8
        priv_buf = ctypes.create_string_buffer(nbytes)
        _BN_bn2bin(bn_d, priv_buf)
        ec_value = priv_buf.raw[:nbytes]

        return {
            CKA_EC_PARAMS: ec_params_der,
            CKA_EC_POINT:  _wrap_ec_point(ec_point),
            CKA_VALUE:     ec_value,
        }
    finally:
        _EC_KEY_free(ec_key)


def ec_sign(attr_dict: dict, data: bytes, mech_rule: str) -> bytes:
    """ECDSA sign.  Returns raw R||S (each component zero-padded to field size).

    ICSF returns signatures as raw  R || S  with fixed length  2 * n  where
    n is the curve field size in bytes.  OpenSSL produces DER-encoded output
    which we convert with _der_sig_to_raw().

    *data* is the pre-computed hash (ICSF pre-hashes before calling PKS for
    CKM_ECDSA).  We use EVP_PKEY_sign which signs the hash directly without
    an additional digest step.
    """
    n = _field_size(attr_dict.get(CKA_EC_PARAMS, b''))
    pkey = _build_ec_pkey(attr_dict, private=True)
    try:
        pctx = _EVP_PKEY_CTX_new(pkey, None)
        if not pctx:
            raise RuntimeError('EVP_PKEY_CTX_new failed')
        try:
            if _EVP_PKEY_sign_init(pctx) != 1:
                raise RuntimeError('EVP_PKEY_sign_init failed: %s' % _ossl_err())
            sig_len = ctypes.c_size_t(0)
            if _EVP_PKEY_sign(pctx, None, ctypes.byref(sig_len),
                              data, len(data)) != 1:
                raise RuntimeError('EVP_PKEY_sign (size) failed: %s' % _ossl_err())
            sig_buf = ctypes.create_string_buffer(sig_len.value)
            if _EVP_PKEY_sign(pctx, sig_buf, ctypes.byref(sig_len),
                              data, len(data)) != 1:
                raise RuntimeError('EVP_PKEY_sign failed: %s' % _ossl_err())
            der_sig = sig_buf.raw[:sig_len.value]
            return _der_sig_to_raw(der_sig, n)
        finally:
            _EVP_PKEY_CTX_free_s(pctx)
    finally:
        _EVP_PKEY_free(pkey)


def ec_verify(attr_dict: dict, data: bytes, signature: bytes,
              mech_rule: str) -> bool:
    """ECDSA verify.  Returns True if valid.

    *signature* is raw  R || S  (as returned/expected by ICSF).  Convert to
    DER before passing to OpenSSL's EVP_PKEY_verify.
    *data* is the pre-computed hash.
    """
    n = _field_size(attr_dict.get(CKA_EC_PARAMS, b''))
    der_sig = _raw_sig_to_der(signature, n)
    pkey = _build_ec_pkey(attr_dict, private=False)
    try:
        pctx = _EVP_PKEY_CTX_new(pkey, None)
        if not pctx:
            raise RuntimeError('EVP_PKEY_CTX_new failed')
        try:
            if _EVP_PKEY_verify_init(pctx) != 1:
                raise RuntimeError('EVP_PKEY_verify_init failed: %s' % _ossl_err())
            rc = _EVP_PKEY_verify(pctx, der_sig, len(der_sig),
                                  data, len(data))
            return rc == 1
        finally:
            _EVP_PKEY_CTX_free_s(pctx)
    finally:
        _EVP_PKEY_free(pkey)


def ec_ecdh_derive(priv_attr_dict: dict, peer_pub_point_raw: bytes) -> bytes:
    """Compute the raw ECDH shared secret  Z = d * Q_peer.

    Parameters
    ----------
    priv_attr_dict    : PKCS#11 attribute dict for the local EC private key
                        (must contain CKA_EC_PARAMS and CKA_VALUE).
    peer_pub_point_raw: peer's uncompressed public point bytes (04 || X || Y).
                        This is the *raw* point, NOT the DER-OCTET-STRING-wrapped
                        form stored in CKA_EC_POINT.

    Returns
    -------
    bytes — the shared secret Z (big-endian, field-size bytes).

    The caller is responsible for any KDF step; this function returns the
    raw ECDH output exactly as ICSF does for CKM_ECDH1_DERIVE with
    CKD_NULL (kdf==0).
    """
    if _EVP_PKEY_derive_init is None or _EVP_PKEY_derive_set_peer is None \
            or _EVP_PKEY_derive is None:
        raise RuntimeError('OpenSSL EVP_PKEY_derive not available')

    # Build the local private key EVP_PKEY
    priv_pkey = _build_ec_pkey(priv_attr_dict, private=True)
    try:
        # Build the peer's public key EVP_PKEY from the raw point.
        # We need the curve params from the private key.
        ec_params = priv_attr_dict.get(CKA_EC_PARAMS, b'')
        peer_pub_wrapped = _wrap_ec_point(peer_pub_point_raw)
        peer_attr = {CKA_EC_PARAMS: ec_params, CKA_EC_POINT: peer_pub_wrapped}
        peer_pkey = _build_ec_pkey(peer_attr, private=False)
        try:
            pctx = _EVP_PKEY_CTX_new(priv_pkey, None)
            if not pctx:
                raise RuntimeError('EVP_PKEY_CTX_new failed: %s' % _ossl_err())
            try:
                if _EVP_PKEY_derive_init(pctx) != 1:
                    raise RuntimeError('EVP_PKEY_derive_init failed: %s'
                                       % _ossl_err())
                if _EVP_PKEY_derive_set_peer(pctx, peer_pkey) != 1:
                    raise RuntimeError('EVP_PKEY_derive_set_peer failed: %s'
                                       % _ossl_err())
                # Query the output length
                secret_len = ctypes.c_size_t(0)
                if _EVP_PKEY_derive(pctx, None, ctypes.byref(secret_len)) != 1:
                    raise RuntimeError('EVP_PKEY_derive (size) failed: %s'
                                       % _ossl_err())
                buf = ctypes.create_string_buffer(secret_len.value)
                if _EVP_PKEY_derive(pctx, buf,
                                    ctypes.byref(secret_len)) != 1:
                    raise RuntimeError('EVP_PKEY_derive failed: %s'
                                       % _ossl_err())
                return bytes(buf.raw[:secret_len.value])
            finally:
                _EVP_PKEY_CTX_free_s(pctx)
        finally:
            _EVP_PKEY_free(peer_pkey)
    finally:
        _EVP_PKEY_free(priv_pkey)
