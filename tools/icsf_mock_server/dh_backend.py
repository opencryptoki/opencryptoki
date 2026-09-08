# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
dh_backend.py — Real Diffie-Hellman operations via ctypes → libcrypto.

Supports both OpenSSL 1.1 and OpenSSL 3.x:
  • OpenSSL 1.1: uses DH_* low-level API (DH_new, DH_set0_pqg, DH_generate_key, DH_compute_key)
  • OpenSSL 3.x: uses EVP_PKEY_fromdata / EVP_PKEY_keygen / EVP_PKEY_derive

Public API
----------
dh_generate(prime_bytes, base_bytes) -> dict {CKA_PRIME, CKA_BASE, 'pub_value', 'priv_value'}
dh_derive(priv_attr_dict, peer_pub_bytes) -> bytes
"""

import ctypes
import logging
from cipher_backend import _libcrypto
from pkcs11_const import CKA_PRIME, CKA_BASE, CKA_VALUE

_log = logging.getLogger(__name__)

# Detect OpenSSL version
_OPENSSL3 = (getattr(_libcrypto, 'EVP_PKEY_fromdata', None) is not None)


def _bind(name, restype, argtypes):
    fn = getattr(_libcrypto, name, None)
    if fn is None:
        _log.debug('dh_backend: symbol not found in libcrypto: %s', name)
        return None
    fn.restype = restype
    fn.argtypes = argtypes
    return fn


# Common OpenSSL / BIGNUM functions
_BN_new        = _bind('BN_new',        ctypes.c_void_p, [])
_BN_free       = _bind('BN_free',       None,            [ctypes.c_void_p])
_BN_clear_free = _bind('BN_clear_free', None,            [ctypes.c_void_p])
_BN_bin2bn     = _bind('BN_bin2bn',     ctypes.c_void_p, [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p])
_BN_bn2bin     = _bind('BN_bn2bin',     ctypes.c_int,    [ctypes.c_void_p, ctypes.c_char_p])
_BN_bn2binpad  = _bind('BN_bn2binpad',  ctypes.c_int,    [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int])
_BN_num_bits   = _bind('BN_num_bits',   ctypes.c_int,    [ctypes.c_void_p])

_EVP_PKEY_free        = _bind('EVP_PKEY_free',        None,            [ctypes.c_void_p])
_EVP_PKEY_CTX_new     = _bind('EVP_PKEY_CTX_new',     ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_void_p])
_EVP_PKEY_CTX_free    = _bind('EVP_PKEY_CTX_free',    None,            [ctypes.c_void_p])

_EVP_PKEY_derive_init     = _bind('EVP_PKEY_derive_init',     ctypes.c_int, [ctypes.c_void_p])
_EVP_PKEY_derive_set_peer = _bind('EVP_PKEY_derive_set_peer', ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p])
_EVP_PKEY_derive          = _bind('EVP_PKEY_derive',          ctypes.c_int, [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t)])

if not _OPENSSL3:
    # OpenSSL 1.1 DH functions
    _DH_new          = _bind('DH_new',          ctypes.c_void_p, [])
    _DH_free         = _bind('DH_free',         None,            [ctypes.c_void_p])
    _DH_set0_pqg     = _bind('DH_set0_pqg',     ctypes.c_int,    [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p])
    _DH_set0_key     = _bind('DH_set0_key',     ctypes.c_int,    [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p])
    _DH_get0_key     = _bind('DH_get0_key',     None,            [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p)])
    _DH_generate_key = _bind('DH_generate_key', ctypes.c_int,    [ctypes.c_void_p])
    _DH_compute_key  = _bind('DH_compute_key',  ctypes.c_int,    [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p])
    _DH_size         = _bind('DH_size',         ctypes.c_int,    [ctypes.c_void_p])
else:
    # OpenSSL 3.x functions & structures
    class _OSSLParam(ctypes.Structure):
        _fields_ = [
            ('key',         ctypes.c_char_p),
            ('data_type',   ctypes.c_uint),
            ('data',        ctypes.c_void_p),
            ('data_size',   ctypes.c_size_t),
            ('return_size', ctypes.c_size_t),
        ]

    _OSSL_PARAM_UNSIGNED_INTEGER = 2   # BN: big-endian bytes

    _OSSL_KEYMGMT_SELECT_PRIVATE_KEY       = 0x01
    _OSSL_KEYMGMT_SELECT_PUBLIC_KEY        = 0x02
    _OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS = 0x04

    _EVP_PKEY_DOMPARAMS = _OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS                         # 0x04
    _EVP_PKEY_KEYPAIR   = (_OSSL_KEYMGMT_SELECT_PRIVATE_KEY |
                           _OSSL_KEYMGMT_SELECT_PUBLIC_KEY |
                           _OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)                       # 0x07
    _EVP_PKEY_PUBKEY    = (_OSSL_KEYMGMT_SELECT_PUBLIC_KEY |
                           _OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)                       # 0x06

    _EVP_PKEY_fromdata_init     = _bind('EVP_PKEY_fromdata_init',     ctypes.c_int, [ctypes.c_void_p])
    _EVP_PKEY_fromdata          = _bind('EVP_PKEY_fromdata',          ctypes.c_int, [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_int, ctypes.c_void_p])
    _EVP_PKEY_keygen_init       = _bind('EVP_PKEY_keygen_init',       ctypes.c_int, [ctypes.c_void_p])
    _EVP_PKEY_keygen            = _bind('EVP_PKEY_keygen',            ctypes.c_int, [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)])
    _EVP_PKEY_get_bn_param      = _bind('EVP_PKEY_get_bn_param',      ctypes.c_int, [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)])
    _EVP_PKEY_CTX_new_from_name = _bind('EVP_PKEY_CTX_new_from_name', ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p])


def _bytes_to_bn(b: bytes):
    if not b:
        return None
    return _BN_bin2bn(b, len(b), None)


def _bn_to_bytes(bn_ptr, pad_to_len: int = 0) -> bytes:
    if not bn_ptr:
        return b''
    nbytes = (_BN_num_bits(bn_ptr) + 7) // 8
    target_len = max(nbytes, pad_to_len)
    buf = ctypes.create_string_buffer(target_len)
    if _BN_bn2binpad:
        written = _BN_bn2binpad(bn_ptr, buf, target_len)
        if written < 0:
            written = _BN_bn2bin(bn_ptr, buf)
            return bytes(buf[:written]).rjust(target_len, b'\x00')
        return bytes(buf[:written])
    else:
        written = _BN_bn2bin(bn_ptr, buf)
        return bytes(buf[:written]).rjust(target_len, b'\x00')


def _make_ossl_param(key: bytes, data_bytes: bytes, buffers: list) -> _OSSLParam:
    buf = ctypes.create_string_buffer(data_bytes)
    buffers.append(buf)
    param = _OSSLParam()
    param.key = key
    param.data_type = _OSSL_PARAM_UNSIGNED_INTEGER
    param.data = ctypes.cast(buf, ctypes.c_void_p)
    param.data_size = len(data_bytes)
    param.return_size = 0
    return param


def dh_generate(prime_bytes: bytes, base_bytes: bytes) -> dict:
    """
    Generate DH key pair given prime (p) and base (g).
    Returns dict with CKA_PRIME, CKA_BASE, 'pub_value', 'priv_value'.
    """
    if _OPENSSL3:
        return _dh_generate_ossl3(prime_bytes, base_bytes)
    else:
        return _dh_generate_ossl1(prime_bytes, base_bytes)


def _dh_generate_ossl1(prime_bytes: bytes, base_bytes: bytes) -> dict:
    dh = _DH_new()
    if not dh:
        raise RuntimeError('DH_new failed')
    try:
        bn_p = _bytes_to_bn(prime_bytes)
        bn_g = _bytes_to_bn(base_bytes)
        if not bn_p or not bn_g:
            raise RuntimeError('Failed to create BIGNUM for DH params')
        # DH_set0_pqg takes ownership of BIGNUMs on success
        if _DH_set0_pqg(dh, bn_p, None, bn_g) != 1:
            _BN_free(bn_p)
            _BN_free(bn_g)
            raise RuntimeError('DH_set0_pqg failed')

        if _DH_generate_key(dh) != 1:
            raise RuntimeError('DH_generate_key failed')

        pub_key_ptr = ctypes.c_void_p()
        priv_key_ptr = ctypes.c_void_p()
        _DH_get0_key(dh, ctypes.byref(pub_key_ptr), ctypes.byref(priv_key_ptr))

        prime_len = len(prime_bytes)
        pub_bytes = _bn_to_bytes(pub_key_ptr.value, prime_len)
        priv_bytes = _bn_to_bytes(priv_key_ptr.value, prime_len)

        return {
            CKA_PRIME: prime_bytes,
            CKA_BASE: base_bytes,
            'pub_value': pub_bytes,
            'priv_value': priv_bytes,
        }
    finally:
        _DH_free(dh)


def _dh_generate_ossl3(prime_bytes: bytes, base_bytes: bytes) -> dict:
    buffers = []
    params = [
        _make_ossl_param(b'p', prime_bytes, buffers),
        _make_ossl_param(b'g', base_bytes, buffers),
    ]
    term = _OSSLParam()
    term.key = None
    term.data_type = 0
    term.data = None
    term.data_size = 0
    term.return_size = 0
    params.append(term)

    ParamArray = _OSSLParam * len(params)
    param_arr = ParamArray(*params)

    pctx = _EVP_PKEY_CTX_new_from_name(None, b'DH', None)
    if not pctx:
        raise RuntimeError('EVP_PKEY_CTX_new_from_name(DH) failed')

    pkey_params = ctypes.c_void_p(None)
    kctx = None
    pkey = ctypes.c_void_p(None)
    try:
        if _EVP_PKEY_fromdata_init(pctx) != 1:
            raise RuntimeError('EVP_PKEY_fromdata_init failed')

        if _EVP_PKEY_fromdata(pctx, ctypes.byref(pkey_params), _EVP_PKEY_DOMPARAMS,
                              ctypes.cast(param_arr, ctypes.c_void_p)) != 1:
            raise RuntimeError('EVP_PKEY_fromdata failed')

        kctx = _EVP_PKEY_CTX_new(pkey_params, None)
        if not kctx:
            raise RuntimeError('EVP_PKEY_CTX_new failed')

        if _EVP_PKEY_keygen_init(kctx) != 1:
            raise RuntimeError('EVP_PKEY_keygen_init failed')

        if _EVP_PKEY_keygen(kctx, ctypes.byref(pkey)) != 1:
            raise RuntimeError('EVP_PKEY_keygen failed')

        pub_bn = ctypes.c_void_p(None)
        priv_bn = ctypes.c_void_p(None)
        if _EVP_PKEY_get_bn_param(pkey, b'pub', ctypes.byref(pub_bn)) != 1:
            raise RuntimeError('EVP_PKEY_get_bn_param pub failed')
        if _EVP_PKEY_get_bn_param(pkey, b'priv', ctypes.byref(priv_bn)) != 1:
            _BN_free(pub_bn)
            raise RuntimeError('EVP_PKEY_get_bn_param priv failed')

        prime_len = len(prime_bytes)
        pub_bytes = _bn_to_bytes(pub_bn, prime_len)
        priv_bytes = _bn_to_bytes(priv_bn, prime_len)
        _BN_free(pub_bn)
        _BN_clear_free(priv_bn)

        return {
            CKA_PRIME: prime_bytes,
            CKA_BASE: base_bytes,
            'pub_value': pub_bytes,
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


def dh_derive(priv_attr_dict: dict, peer_pub_bytes: bytes) -> bytes:
    """
    Compute Diffie-Hellman shared secret Z = peer_pub ^ priv mod p.
    """
    prime_bytes = priv_attr_dict.get(CKA_PRIME, b'')
    base_bytes = priv_attr_dict.get(CKA_BASE, b'')
    priv_bytes = priv_attr_dict.get(CKA_VALUE, b'')

    if not prime_bytes or not priv_bytes:
        raise ValueError('Missing CKA_PRIME or CKA_VALUE in DH private key')

    if _OPENSSL3:
        return _dh_derive_ossl3(prime_bytes, base_bytes, priv_bytes, peer_pub_bytes)
    else:
        return _dh_derive_ossl1(prime_bytes, base_bytes, priv_bytes, peer_pub_bytes)


def _dh_derive_ossl1(prime_bytes: bytes, base_bytes: bytes, priv_bytes: bytes, peer_pub_bytes: bytes) -> bytes:
    dh = _DH_new()
    if not dh:
        raise RuntimeError('DH_new failed')
    bn_peer_pub = None
    try:
        bn_p = _bytes_to_bn(prime_bytes)
        bn_g = _bytes_to_bn(base_bytes) if base_bytes else _bytes_to_bn(b'\x02')
        bn_priv = _bytes_to_bn(priv_bytes)

        if _DH_set0_pqg(dh, bn_p, None, bn_g) != 1:
            _BN_free(bn_p)
            _BN_free(bn_g)
            raise RuntimeError('DH_set0_pqg failed')

        if _DH_set0_key(dh, None, bn_priv) != 1:
            _BN_free(bn_priv)
            raise RuntimeError('DH_set0_key failed')

        bn_peer_pub = _bytes_to_bn(peer_pub_bytes)
        dh_size = _DH_size(dh)
        out_buf = ctypes.create_string_buffer(dh_size)
        res = _DH_compute_key(out_buf, bn_peer_pub, dh)
        if res < 0:
            raise RuntimeError('DH_compute_key failed')

        # DH secret padded to prime size
        return bytes(out_buf[:res]).rjust(len(prime_bytes), b'\x00')
    finally:
        if bn_peer_pub:
            _BN_free(bn_peer_pub)
        _DH_free(dh)


def _dh_derive_ossl3(prime_bytes: bytes, base_bytes: bytes, priv_bytes: bytes, peer_pub_bytes: bytes) -> bytes:
    # Build private key EVP_PKEY
    bufs_priv = []
    params_priv_list = [
        _make_ossl_param(b'p', prime_bytes, bufs_priv),
        _make_ossl_param(b'g', base_bytes if base_bytes else b'\x02', bufs_priv),
        _make_ossl_param(b'priv', priv_bytes, bufs_priv),
    ]
    term = _OSSLParam()
    term.key = None
    term.data_type = 0
    term.data = None
    term.data_size = 0
    term.return_size = 0
    params_priv_list.append(term)
    ParamArrayPriv = _OSSLParam * len(params_priv_list)
    param_arr_priv = ParamArrayPriv(*params_priv_list)

    # Build peer public key EVP_PKEY
    bufs_pub = []
    params_pub_list = [
        _make_ossl_param(b'p', prime_bytes, bufs_pub),
        _make_ossl_param(b'g', base_bytes if base_bytes else b'\x02', bufs_pub),
        _make_ossl_param(b'pub', peer_pub_bytes, bufs_pub),
    ]
    term_pub = _OSSLParam()
    term_pub.key = None
    term_pub.data_type = 0
    term_pub.data = None
    term_pub.data_size = 0
    term_pub.return_size = 0
    params_pub_list.append(term_pub)
    ParamArrayPub = _OSSLParam * len(params_pub_list)
    param_arr_pub = ParamArrayPub(*params_pub_list)

    pctx_priv = _EVP_PKEY_CTX_new_from_name(None, b'DH', None)
    pctx_pub  = _EVP_PKEY_CTX_new_from_name(None, b'DH', None)
    if not pctx_priv or not pctx_pub:
        raise RuntimeError('EVP_PKEY_CTX_new_from_name(DH) failed')

    pkey_priv = ctypes.c_void_p(None)
    pkey_pub  = ctypes.c_void_p(None)
    dctx      = None

    try:
        if _EVP_PKEY_fromdata_init(pctx_priv) != 1 or \
           _EVP_PKEY_fromdata(pctx_priv, ctypes.byref(pkey_priv), _EVP_PKEY_KEYPAIR,
                              ctypes.cast(param_arr_priv, ctypes.c_void_p)) != 1:
            raise RuntimeError('Failed to build DH private EVP_PKEY')

        if _EVP_PKEY_fromdata_init(pctx_pub) != 1 or \
           _EVP_PKEY_fromdata(pctx_pub, ctypes.byref(pkey_pub), _EVP_PKEY_PUBKEY,
                              ctypes.cast(param_arr_pub, ctypes.c_void_p)) != 1:
            raise RuntimeError('Failed to build DH peer public EVP_PKEY')

        dctx = _EVP_PKEY_CTX_new(pkey_priv, None)
        if not dctx or _EVP_PKEY_derive_init(dctx) != 1 or \
           _EVP_PKEY_derive_set_peer(dctx, pkey_pub) != 1:
            raise RuntimeError('Failed to init EVP_PKEY derivation')

        out_len = ctypes.c_size_t(0)
        if _EVP_PKEY_derive(dctx, None, ctypes.byref(out_len)) != 1:
            raise RuntimeError('Failed to query derive output length')

        out_buf = ctypes.create_string_buffer(out_len.value)
        if _EVP_PKEY_derive(dctx, out_buf, ctypes.byref(out_len)) != 1:
            raise RuntimeError('EVP_PKEY_derive failed')

        return bytes(out_buf[:out_len.value]).rjust(len(prime_bytes), b'\x00')
    finally:
        if dctx:
            _EVP_PKEY_CTX_free(dctx)
        if pkey_pub.value:
            _EVP_PKEY_free(pkey_pub)
        if pkey_priv.value:
            _EVP_PKEY_free(pkey_priv)
        if pctx_pub:
            _EVP_PKEY_CTX_free(pctx_pub)
        if pctx_priv:
            _EVP_PKEY_CTX_free(pctx_priv)
