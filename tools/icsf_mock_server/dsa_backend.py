# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
dsa_backend.py — Real DSA operations via ctypes → libcrypto.

Supports both OpenSSL 1.1 and OpenSSL 3.x:
  • OpenSSL 1.1: uses DSA_* low-level API (DSA_new, DSA_set0_pqg, etc.)
  • OpenSSL 3.x: uses EVP_PKEY_fromdata / EVP_PKEY_keygen

DSA key attributes (PKCS#11):
  CKA_PRIME       — p (prime modulus, 512–3072 bits)
  CKA_SUBPRIME    — q (prime divisor of p-1, 160/224/256 bits)
  CKA_BASE        — g (generator)
  CKA_VALUE       — public key y (public), private key x (private)

Public API
----------
dsa_generate(prime_bytes, subprime_bytes, base_bytes)
    -> dict {CKA_PRIME, CKA_SUBPRIME, CKA_BASE, 'pub_value', 'priv_value'}
dsa_sign(priv_attr_dict, data) -> bytes   raw R||S (each padded to |q| bytes)
dsa_verify(pub_attr_dict, data, signature) -> bool
dsa_max_sig_len(subprime_bytes) -> int    = 2 * len(q)
"""

import ctypes
import logging

from cipher_backend import _libcrypto
from pkcs11_const import CKA_PRIME, CKA_SUBPRIME, CKA_BASE, CKA_VALUE

_log = logging.getLogger(__name__)

# Detect OpenSSL version
_OPENSSL3 = (getattr(_libcrypto, 'EVP_PKEY_fromdata', None) is not None)


def _bind(name, restype, argtypes):
    fn = getattr(_libcrypto, name, None)
    if fn is None:
        _log.debug('dsa_backend: symbol not found in libcrypto: %s', name)
        return None
    fn.restype = restype
    fn.argtypes = argtypes
    return fn


# ---------------------------------------------------------------------------
# Common BIGNUM helpers
# ---------------------------------------------------------------------------

_BN_new        = _bind('BN_new',        ctypes.c_void_p, [])
_BN_free       = _bind('BN_free',       None,            [ctypes.c_void_p])
_BN_clear_free = _bind('BN_clear_free', None,            [ctypes.c_void_p])
_BN_bin2bn     = _bind('BN_bin2bn',     ctypes.c_void_p,
                        [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p])
_BN_bn2bin     = _bind('BN_bn2bin',     ctypes.c_int,
                        [ctypes.c_void_p, ctypes.c_char_p])
_BN_bn2binpad  = _bind('BN_bn2binpad',  ctypes.c_int,
                        [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int])
_BN_num_bits   = _bind('BN_num_bits',   ctypes.c_int,    [ctypes.c_void_p])

_EVP_PKEY_free = _bind('EVP_PKEY_free', None,            [ctypes.c_void_p])

# ---------------------------------------------------------------------------
# Error helpers
# ---------------------------------------------------------------------------

_ERR_get_error       = _bind('ERR_get_error',       ctypes.c_ulong, [])
_ERR_error_string_n  = _bind('ERR_error_string_n',  None,
                              [ctypes.c_ulong, ctypes.c_char_p, ctypes.c_size_t])


def _ossl_err():
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


def _bytes_to_bn(b: bytes):
    if not b:
        return None
    bn = _BN_bin2bn(b, len(b), None)
    if not bn:
        raise RuntimeError('BN_bin2bn failed')
    return bn


def _bn_to_bytes(bn, pad_len: int = 0) -> bytes:
    if not bn:
        return b''
    nbytes = (_BN_num_bits(bn) + 7) // 8
    target = max(nbytes, pad_len)
    buf = ctypes.create_string_buffer(target)
    if _BN_bn2binpad:
        written = _BN_bn2binpad(bn, buf, target)
        if written >= 0:
            return bytes(buf[:written])
    written = _BN_bn2bin(bn, buf)
    return bytes(buf[:written]).rjust(target, b'\x00')


# ---------------------------------------------------------------------------
# OpenSSL 1.1 path: DSA_* low-level API
# ---------------------------------------------------------------------------

if not _OPENSSL3:
    _DSA_new          = _bind('DSA_new',          ctypes.c_void_p, [])
    _DSA_free         = _bind('DSA_free',         None,            [ctypes.c_void_p])
    _DSA_set0_pqg     = _bind('DSA_set0_pqg',     ctypes.c_int,
                               [ctypes.c_void_p,
                                ctypes.c_void_p,   # p
                                ctypes.c_void_p,   # q
                                ctypes.c_void_p])  # g
    _DSA_set0_key     = _bind('DSA_set0_key',     ctypes.c_int,
                               [ctypes.c_void_p,
                                ctypes.c_void_p,   # pub_key
                                ctypes.c_void_p])  # priv_key (or NULL)
    _DSA_get0_key     = _bind('DSA_get0_key',     None,
                               [ctypes.c_void_p,
                                ctypes.POINTER(ctypes.c_void_p),
                                ctypes.POINTER(ctypes.c_void_p)])
    _DSA_generate_key = _bind('DSA_generate_key', ctypes.c_int,
                               [ctypes.c_void_p])
    _DSA_size         = _bind('DSA_size',         ctypes.c_int,
                               [ctypes.c_void_p])
    _EVP_PKEY_new          = _bind('EVP_PKEY_new',          ctypes.c_void_p, [])
    _EVP_PKEY_assign_DSA   = _bind('EVP_PKEY_assign_DSA',   ctypes.c_int,
                                    [ctypes.c_void_p, ctypes.c_void_p])
    _EVP_PKEY_CTX_new      = _bind('EVP_PKEY_CTX_new',      ctypes.c_void_p,
                                    [ctypes.c_void_p, ctypes.c_void_p])
    _EVP_PKEY_CTX_free     = _bind('EVP_PKEY_CTX_free',     None,
                                    [ctypes.c_void_p])
    _EVP_PKEY_sign_init    = _bind('EVP_PKEY_sign_init',    ctypes.c_int,
                                    [ctypes.c_void_p])
    _EVP_PKEY_sign         = _bind('EVP_PKEY_sign',         ctypes.c_int,
                                    [ctypes.c_void_p, ctypes.c_char_p,
                                     ctypes.POINTER(ctypes.c_size_t),
                                     ctypes.c_char_p, ctypes.c_size_t])
    _EVP_PKEY_verify_init  = _bind('EVP_PKEY_verify_init',  ctypes.c_int,
                                    [ctypes.c_void_p])
    _EVP_PKEY_verify       = _bind('EVP_PKEY_verify',       ctypes.c_int,
                                    [ctypes.c_void_p, ctypes.c_char_p,
                                     ctypes.c_size_t, ctypes.c_char_p,
                                     ctypes.c_size_t])

# ---------------------------------------------------------------------------
# OpenSSL 3.x path: EVP_PKEY_fromdata
# ---------------------------------------------------------------------------

if _OPENSSL3:
    class _OSSLParam(ctypes.Structure):
        _fields_ = [
            ('key',         ctypes.c_char_p),
            ('data_type',   ctypes.c_uint),
            ('data',        ctypes.c_void_p),
            ('data_size',   ctypes.c_size_t),
            ('return_size', ctypes.c_size_t),
        ]

    _OSSL_PARAM_UNSIGNED_INTEGER = 2
    _OSSL_KEYMGMT_SELECT_PRIVATE_KEY       = 0x01
    _OSSL_KEYMGMT_SELECT_PUBLIC_KEY        = 0x02
    _OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS = 0x04
    _EVP_PKEY_KEYPAIR = (_OSSL_KEYMGMT_SELECT_PRIVATE_KEY |
                         _OSSL_KEYMGMT_SELECT_PUBLIC_KEY  |
                         _OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)  # 0x07
    _EVP_PKEY_PUBKEY  = (_OSSL_KEYMGMT_SELECT_PUBLIC_KEY  |
                         _OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)  # 0x06

    _EVP_PKEY_CTX_new_from_name = _bind('EVP_PKEY_CTX_new_from_name',
                                         ctypes.c_void_p,
                                         [ctypes.c_void_p, ctypes.c_char_p,
                                          ctypes.c_char_p])
    _EVP_PKEY_CTX_free      = _bind('EVP_PKEY_CTX_free',      None,
                                     [ctypes.c_void_p])
    _EVP_PKEY_CTX_new       = _bind('EVP_PKEY_CTX_new',       ctypes.c_void_p,
                                     [ctypes.c_void_p, ctypes.c_void_p])
    _EVP_PKEY_fromdata_init = _bind('EVP_PKEY_fromdata_init', ctypes.c_int,
                                     [ctypes.c_void_p])
    _EVP_PKEY_fromdata      = _bind('EVP_PKEY_fromdata',      ctypes.c_int,
                                     [ctypes.c_void_p,
                                      ctypes.POINTER(ctypes.c_void_p),
                                      ctypes.c_int, ctypes.c_void_p])
    _EVP_PKEY_keygen_init   = _bind('EVP_PKEY_keygen_init',   ctypes.c_int,
                                     [ctypes.c_void_p])
    _EVP_PKEY_keygen        = _bind('EVP_PKEY_keygen',        ctypes.c_int,
                                     [ctypes.c_void_p,
                                      ctypes.POINTER(ctypes.c_void_p)])
    _EVP_PKEY_get_bn_param  = _bind('EVP_PKEY_get_bn_param',  ctypes.c_int,
                                     [ctypes.c_void_p, ctypes.c_char_p,
                                      ctypes.POINTER(ctypes.c_void_p)])
    _EVP_PKEY_sign_init     = _bind('EVP_PKEY_sign_init',     ctypes.c_int,
                                     [ctypes.c_void_p])
    _EVP_PKEY_sign          = _bind('EVP_PKEY_sign',          ctypes.c_int,
                                     [ctypes.c_void_p, ctypes.c_char_p,
                                      ctypes.POINTER(ctypes.c_size_t),
                                      ctypes.c_char_p, ctypes.c_size_t])
    _EVP_PKEY_verify_init   = _bind('EVP_PKEY_verify_init',   ctypes.c_int,
                                     [ctypes.c_void_p])
    _EVP_PKEY_verify        = _bind('EVP_PKEY_verify',        ctypes.c_int,
                                     [ctypes.c_void_p, ctypes.c_char_p,
                                      ctypes.c_size_t, ctypes.c_char_p,
                                      ctypes.c_size_t])


# ---------------------------------------------------------------------------
# DER signature helpers (DER SEQUENCE{INTEGER r, INTEGER s} ↔ raw R||S)
# ---------------------------------------------------------------------------

def _der_sig_to_raw(der_sig: bytes, n: int) -> bytes:
    """Convert DER-encoded DSA signature to fixed-size raw R||S (n bytes each)."""
    if not der_sig or der_sig[0] != 0x30:
        raise ValueError('DSA DER sig does not start with SEQUENCE tag')
    pos = 1
    if der_sig[pos] & 0x80:
        pos += 1 + (der_sig[pos] & 0x7f)
    else:
        pos += 1

    def _read_int():
        nonlocal pos
        if der_sig[pos] != 0x02:
            raise ValueError('Expected INTEGER tag 0x02')
        pos += 1
        length = der_sig[pos]; pos += 1
        val = der_sig[pos:pos + length]; pos += length
        val = val.lstrip(b'\x00') or b'\x00'
        return val

    r = _read_int()
    s = _read_int()
    return r.rjust(n, b'\x00') + s.rjust(n, b'\x00')


def _raw_sig_to_der(raw_sig: bytes, n: int) -> bytes:
    """Convert fixed-size raw R||S to DER-encoded DSA signature."""
    if len(raw_sig) != 2 * n:
        raise ValueError('Raw DSA sig length %d != 2*%d' % (len(raw_sig), n))
    r = raw_sig[:n].lstrip(b'\x00') or b'\x00'
    s = raw_sig[n:].lstrip(b'\x00') or b'\x00'

    def _encode_int(v):
        if v[0] & 0x80:
            v = b'\x00' + v
        return bytes([0x02, len(v)]) + v

    r_enc = _encode_int(r)
    s_enc = _encode_int(s)
    content = r_enc + s_enc
    if len(content) > 127:
        seq_len = bytes([0x81, len(content)])
    else:
        seq_len = bytes([len(content)])
    return b'\x30' + seq_len + content


def dsa_max_sig_len(subprime_bytes: bytes) -> int:
    """Return fixed raw R||S length for the given subprime q."""
    return 2 * len(subprime_bytes)


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def dsa_generate(prime_bytes: bytes, subprime_bytes: bytes,
                 base_bytes: bytes) -> dict:
    """
    Generate a DSA key pair given domain parameters (p, q, g).
    Returns dict with CKA_PRIME, CKA_SUBPRIME, CKA_BASE, 'pub_value', 'priv_value'.
    """
    if _OPENSSL3:
        return _dsa_generate_ossl3(prime_bytes, subprime_bytes, base_bytes)
    else:
        return _dsa_generate_ossl1(prime_bytes, subprime_bytes, base_bytes)


def _dsa_generate_ossl1(prime_bytes: bytes, subprime_bytes: bytes,
                         base_bytes: bytes) -> dict:
    dsa = _DSA_new()
    if not dsa:
        raise RuntimeError('DSA_new failed')
    try:
        bn_p = _bytes_to_bn(prime_bytes)
        bn_q = _bytes_to_bn(subprime_bytes)
        bn_g = _bytes_to_bn(base_bytes)
        # DSA_set0_pqg takes ownership on success
        if _DSA_set0_pqg(dsa, bn_p, bn_q, bn_g) != 1:
            _BN_free(bn_p)
            _BN_free(bn_q)
            _BN_free(bn_g)
            raise RuntimeError('DSA_set0_pqg failed: %s' % _ossl_err())

        if _DSA_generate_key(dsa) != 1:
            raise RuntimeError('DSA_generate_key failed: %s' % _ossl_err())

        pub_ptr  = ctypes.c_void_p()
        priv_ptr = ctypes.c_void_p()
        _DSA_get0_key(dsa, ctypes.byref(pub_ptr), ctypes.byref(priv_ptr))

        # Pad public value to prime length; private value to subprime length
        prime_len    = len(prime_bytes)
        subprime_len = len(subprime_bytes)
        pub_bytes  = _bn_to_bytes(pub_ptr.value,  prime_len)
        priv_bytes = _bn_to_bytes(priv_ptr.value, subprime_len)

        return {
            CKA_PRIME:    prime_bytes,
            CKA_SUBPRIME: subprime_bytes,
            CKA_BASE:     base_bytes,
            'pub_value':  pub_bytes,
            'priv_value': priv_bytes,
        }
    finally:
        _DSA_free(dsa)


def _make_ossl_param(key: bytes, data_bytes: bytes, buffers: list) -> '_OSSLParam':
    buf = ctypes.create_string_buffer(data_bytes, len(data_bytes))
    buffers.append(buf)
    param = _OSSLParam()
    param.key = key
    param.data_type = _OSSL_PARAM_UNSIGNED_INTEGER
    param.data = ctypes.cast(buf, ctypes.c_void_p)
    param.data_size = len(data_bytes)
    param.return_size = 0
    return param


def _ossl3_param_array(entries, buffers):
    """Build a NULL-terminated OSSL_PARAM array from (key, data_bytes) pairs."""
    params = [_make_ossl_param(k, v, buffers) for k, v in entries]
    term = _OSSLParam()
    term.key = None; term.data_type = 0; term.data = None
    term.data_size = 0; term.return_size = 0
    params.append(term)
    ArrayType = _OSSLParam * len(params)
    return ArrayType(*params)


def _dsa_generate_ossl3(prime_bytes: bytes, subprime_bytes: bytes,
                         base_bytes: bytes) -> dict:
    # Build domain-parameter EVP_PKEY first, then generate a key pair from it
    bufs = []
    param_arr = _ossl3_param_array([
        (b'p', prime_bytes),
        (b'q', subprime_bytes),
        (b'g', base_bytes),
    ], bufs)

    pctx = _EVP_PKEY_CTX_new_from_name(None, b'DSA', None)
    if not pctx:
        raise RuntimeError('EVP_PKEY_CTX_new_from_name(DSA) failed: %s' % _ossl_err())

    pkey_params = ctypes.c_void_p(None)
    kctx = None
    pkey = ctypes.c_void_p(None)
    try:
        if _EVP_PKEY_fromdata_init(pctx) != 1:
            raise RuntimeError('EVP_PKEY_fromdata_init failed: %s' % _ossl_err())
        if _EVP_PKEY_fromdata(pctx, ctypes.byref(pkey_params),
                              _OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                              ctypes.cast(param_arr, ctypes.c_void_p)) != 1:
            raise RuntimeError('EVP_PKEY_fromdata (DSA params) failed: %s' % _ossl_err())

        kctx = _EVP_PKEY_CTX_new(pkey_params, None)
        if not kctx:
            raise RuntimeError('EVP_PKEY_CTX_new failed: %s' % _ossl_err())

        if _EVP_PKEY_keygen_init(kctx) != 1:
            raise RuntimeError('EVP_PKEY_keygen_init failed: %s' % _ossl_err())

        if _EVP_PKEY_keygen(kctx, ctypes.byref(pkey)) != 1:
            raise RuntimeError('EVP_PKEY_keygen (DSA) failed: %s' % _ossl_err())

        def _get_bn(name):
            bn = ctypes.c_void_p(None)
            if _EVP_PKEY_get_bn_param(pkey, name, ctypes.byref(bn)) != 1:
                return None
            result = _bn_to_bytes(bn)
            _BN_free(bn)
            return result

        prime_len    = len(prime_bytes)
        subprime_len = len(subprime_bytes)
        pub_raw  = _get_bn(b'pub')
        priv_raw = _get_bn(b'priv')
        if pub_raw is None or priv_raw is None:
            raise RuntimeError('Failed to retrieve DSA key components: %s' % _ossl_err())

        # Pad to expected sizes
        pub_bytes  = pub_raw.rjust(prime_len,    b'\x00')
        priv_bytes = priv_raw.rjust(subprime_len, b'\x00')

        return {
            CKA_PRIME:    prime_bytes,
            CKA_SUBPRIME: subprime_bytes,
            CKA_BASE:     base_bytes,
            'pub_value':  pub_bytes,
            'priv_value': priv_bytes,
        }
    finally:
        if pkey.value:
            _EVP_PKEY_free(pkey)
        if kctx:
            _EVP_PKEY_CTX_free(kctx)
        if pkey_params.value:
            _EVP_PKEY_free(pkey_params)
        if pctx:
            _EVP_PKEY_CTX_free(pctx)


# ---------------------------------------------------------------------------
# Build EVP_PKEY from PKCS#11 CKA_* attribute dict
# ---------------------------------------------------------------------------

def _attr_bytes(attr_dict, cka):
    v = attr_dict.get(cka)
    if v is None or v == b'':
        return None
    if isinstance(v, int):
        n = v
        length = (n.bit_length() + 7) // 8
        return n.to_bytes(length, 'big')
    return v or None


def _build_dsa_pkey(attr_dict: dict, private: bool) -> ctypes.c_void_p:
    """Build EVP_PKEY* from CKA_PRIME / CKA_SUBPRIME / CKA_BASE / CKA_VALUE."""
    p_bytes = _attr_bytes(attr_dict, CKA_PRIME)
    q_bytes = _attr_bytes(attr_dict, CKA_SUBPRIME)
    g_bytes = _attr_bytes(attr_dict, CKA_BASE)
    v_bytes = _attr_bytes(attr_dict, CKA_VALUE)

    if not p_bytes or not q_bytes or not g_bytes:
        raise ValueError('DSA key missing CKA_PRIME/CKA_SUBPRIME/CKA_BASE')
    if not v_bytes:
        raise ValueError('DSA key missing CKA_VALUE')

    if _OPENSSL3:
        return _build_dsa_pkey_ossl3(p_bytes, q_bytes, g_bytes, v_bytes, private)
    else:
        return _build_dsa_pkey_ossl1(p_bytes, q_bytes, g_bytes, v_bytes, private)


def _build_dsa_pkey_ossl1(p_bytes, q_bytes, g_bytes, v_bytes, private):
    dsa = _DSA_new()
    if not dsa:
        raise RuntimeError('DSA_new failed')
    try:
        bn_p = _bytes_to_bn(p_bytes)
        bn_q = _bytes_to_bn(q_bytes)
        bn_g = _bytes_to_bn(g_bytes)
        if _DSA_set0_pqg(dsa, bn_p, bn_q, bn_g) != 1:
            _BN_free(bn_p); _BN_free(bn_q); _BN_free(bn_g)
            raise RuntimeError('DSA_set0_pqg failed: %s' % _ossl_err())

        bn_v = _bytes_to_bn(v_bytes)
        if private:
            # DSA_set0_key(pub=NULL, priv=bn_v) — we also need pub, derive it
            # via y = g^x mod p
            p_int = int.from_bytes(p_bytes, 'big')
            g_int = int.from_bytes(g_bytes, 'big')
            x_int = int.from_bytes(v_bytes, 'big')
            y_int = pow(g_int, x_int, p_int)
            y_bytes = y_int.to_bytes(len(p_bytes), 'big')
            bn_y = _bytes_to_bn(y_bytes)
            if _DSA_set0_key(dsa, bn_y, bn_v) != 1:
                _BN_free(bn_y); _BN_free(bn_v)
                raise RuntimeError('DSA_set0_key (priv) failed: %s' % _ossl_err())
        else:
            if _DSA_set0_key(dsa, bn_v, None) != 1:
                _BN_free(bn_v)
                raise RuntimeError('DSA_set0_key (pub) failed: %s' % _ossl_err())

        pkey = _EVP_PKEY_new()
        if not pkey:
            raise RuntimeError('EVP_PKEY_new failed')
        if _EVP_PKEY_assign_DSA(pkey, dsa) != 1:
            _EVP_PKEY_free(pkey)
            raise RuntimeError('EVP_PKEY_assign_DSA failed: %s' % _ossl_err())
        dsa = None  # ownership transferred
        return pkey
    finally:
        if dsa:
            _DSA_free(dsa)


def _build_dsa_pkey_ossl3(p_bytes, q_bytes, g_bytes, v_bytes, private):
    bufs = []
    entries = [
        (b'p', p_bytes),
        (b'q', q_bytes),
        (b'g', g_bytes),
    ]
    if private:
        entries.append((b'priv', v_bytes))
        # Compute pub = g^x mod p so OpenSSL has it for the keypair
        p_int = int.from_bytes(p_bytes, 'big')
        g_int = int.from_bytes(g_bytes, 'big')
        x_int = int.from_bytes(v_bytes, 'big')
        y_int = pow(g_int, x_int, p_int)
        y_bytes = y_int.to_bytes(len(p_bytes), 'big')
        entries.append((b'pub', y_bytes))
    else:
        entries.append((b'pub', v_bytes))

    param_arr = _ossl3_param_array(entries, bufs)
    pctx = _EVP_PKEY_CTX_new_from_name(None, b'DSA', None)
    if not pctx:
        raise RuntimeError('EVP_PKEY_CTX_new_from_name(DSA) failed: %s' % _ossl_err())

    pkey = ctypes.c_void_p(None)
    try:
        if _EVP_PKEY_fromdata_init(pctx) != 1:
            raise RuntimeError('EVP_PKEY_fromdata_init failed: %s' % _ossl_err())
        selection = _EVP_PKEY_KEYPAIR if private else _EVP_PKEY_PUBKEY
        if _EVP_PKEY_fromdata(pctx, ctypes.byref(pkey), selection,
                              ctypes.cast(param_arr, ctypes.c_void_p)) != 1:
            raise RuntimeError('EVP_PKEY_fromdata (DSA %s) failed: %s'
                               % ('priv' if private else 'pub', _ossl_err()))
        return pkey
    finally:
        _EVP_PKEY_CTX_free(pctx)


# ---------------------------------------------------------------------------
# Public API: sign / verify
# ---------------------------------------------------------------------------

def dsa_sign(attr_dict: dict, data: bytes) -> bytes:
    """
    DSA sign over pre-hashed *data* (must be exactly |q| bytes for CKM_DSA).
    Returns raw R||S, each component zero-padded to len(q) bytes.
    """
    q_bytes = _attr_bytes(attr_dict, CKA_SUBPRIME)
    n = len(q_bytes) if q_bytes else 20  # default 160-bit DSA
    pkey = _build_dsa_pkey(attr_dict, private=True)
    try:
        pctx = _EVP_PKEY_CTX_new(pkey, None)
        if not pctx:
            raise RuntimeError('EVP_PKEY_CTX_new failed: %s' % _ossl_err())
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
            _EVP_PKEY_CTX_free(pctx)
    finally:
        _EVP_PKEY_free(pkey)


def dsa_verify(attr_dict: dict, data: bytes, signature: bytes) -> bool:
    """
    DSA verify.  *signature* is raw R||S (as returned by dsa_sign / ICSF).
    *data* is the pre-computed hash.  Returns True if valid.
    """
    q_bytes = _attr_bytes(attr_dict, CKA_SUBPRIME)
    n = len(q_bytes) if q_bytes else 20
    der_sig = _raw_sig_to_der(signature, n)
    pkey = _build_dsa_pkey(attr_dict, private=False)
    try:
        pctx = _EVP_PKEY_CTX_new(pkey, None)
        if not pctx:
            raise RuntimeError('EVP_PKEY_CTX_new failed: %s' % _ossl_err())
        try:
            if _EVP_PKEY_verify_init(pctx) != 1:
                raise RuntimeError('EVP_PKEY_verify_init failed: %s' % _ossl_err())
            rc = _EVP_PKEY_verify(pctx, der_sig, len(der_sig),
                                  data, len(data))
            return rc == 1
        finally:
            _EVP_PKEY_CTX_free(pctx)
    finally:
        _EVP_PKEY_free(pkey)
