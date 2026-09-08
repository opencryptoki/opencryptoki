# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
handlers/gkp.py — CSFPGKP: Generate Key Pair (service tag 4).

Request (from icsf_generate_key_pair() in icsf.c):

    GKPInput ::= SEQUENCE {
        publicKeyAttrList   Attributes,
        privateKeyAttrList  Attributes
    }

    Each attribute list is written by icsf_ber_put_attribute_list() as a
    SEQUENCE-OF-SEQUENCE directly (no extra wrapper).

Response:
    GKPOutput ::= privateKeyHandle  OCTET STRING (44 bytes)

    The *public* key handle is returned in the common header handle field.
    The *private* key handle is the first (and only) field in the service data.

The mock generates a key pair using os.urandom for the key material
(not a real RSA/EC key, but sufficient to satisfy attribute size probes
and round-trip test the mock sign/verify handlers).  All PKCS#11-defined
attributes for the key class are stored with appropriate defaults.
"""

import logging

from ber_codec import (
    encode_response,
    make_object_handle, parse_handle,
    decode_attribute_list, encode_sequence, HANDLE_LEN,
    _decode_tlv
)
from token_store import OBJ_TYPE_TOKEN
from pkcs11_const import (
    CKA_KEY_TYPE, CKA_TOKEN,
    CKA_MODULUS, CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT,
    CKA_PRIVATE_EXPONENT, CKA_PRIME_1, CKA_PRIME_2,
    CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_COEFFICIENT,
    CKA_PRIME, CKA_SUBPRIME, CKA_BASE,
    CKO_PUBLIC_KEY, CKO_PRIVATE_KEY,
    CKK_RSA, CKK_DSA, CKK_DH, CKK_EC,
    CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_DSA_KEY_PAIR_GEN,
    CKM_DH_PKCS_KEY_PAIR_GEN, CKM_EC_KEY_PAIR_GEN,
    CKA_EC_PARAMS, CKA_EC_POINT, CKA_VALUE,
)
import secrets
from obj_attrs import (
    make_rsa_keypair_attrs,
    make_ec_keypair_attrs,
    make_dh_keypair_attrs,
    make_dsa_keypair_attrs,
)
from rsa_backend import rsa_generate
from ec_backend import ec_generate, CurveNotSupportedError
from dh_backend import dh_generate
from dsa_backend import dsa_generate

logger = logging.getLogger(__name__)

ICSF_TAG_CSFPGKP = 4

RC_SUCCESS           = 0
RC_ERROR             = 8
RSN_TOKEN_NOT_FOUND  = 3024
RSN_INVALID_ATTR     = 3003


def handle_gkp(store, request):
    """
    Process a CSFPGKP request.

    Parameters
    ----------
    store   : TokenStore
    request : ICSFRequest

    Returns
    -------
    bytes — raw BER responseValue
    """
    token_name, _, _ = parse_handle(request.handle)
    if not token_name:
        logger.error('GKP: empty token name in handle')
        return encode_response(
            request.handle, RC_ERROR, 3001, ICSF_TAG_CSFPGKP, b'')

    if not store.token_exists(token_name):
        logger.error('GKP: token %r not found', token_name)
        return encode_response(
            request.handle, RC_ERROR, RSN_TOKEN_NOT_FOUND, ICSF_TAG_CSFPGKP, b'')

    # service_data = GKPInput contents (two consecutive attribute list SEQUENCEs)
    pub_attrs  = []
    priv_attrs = []
    try:
        pos = 0
        # First SEQUENCE = public key attrs
        tag, pub_seq_val, pos = _decode_tlv(request.service_data, pos)
        pub_attrs = decode_attribute_list(encode_sequence(pub_seq_val))
        # Second SEQUENCE = private key attrs
        tag, priv_seq_val, pos = _decode_tlv(request.service_data, pos)
        priv_attrs = decode_attribute_list(encode_sequence(priv_seq_val))
    except Exception as exc:
        logger.warning('GKP: could not decode attribute lists: %s', exc)

    pub_dict  = {t: v for t, v in pub_attrs}
    priv_dict = {t: v for t, v in priv_attrs}

    # Determine key type from public key attrs (canonical source)
    key_type = pub_dict.get(CKA_KEY_TYPE)
    if isinstance(key_type, bytes):
        key_type = int.from_bytes(key_type, 'big')

    # Token persistence
    is_pub_token  = _is_token_obj(pub_dict)
    is_priv_token = _is_token_obj(priv_dict)
    pub_obj_type  = OBJ_TYPE_TOKEN if is_pub_token  else 'S'
    priv_obj_type = OBJ_TYPE_TOKEN if is_priv_token else 'S'

    if key_type == CKK_EC:
        try:
            pub_final, priv_final = _build_ec_attrs(pub_attrs, priv_attrs, pub_dict)
        except CurveNotSupportedError as exc:
            logger.warning('GKP: curve not supported: %s', exc)
            # rc=8 / reason=874 → CKR_CURVE_NOT_SUPPORTED in icsf_to_ock_err.
            return encode_response(
                request.handle, RC_ERROR, 874, ICSF_TAG_CSFPGKP, b'')
    elif key_type == CKK_DSA:
        pub_final, priv_final = _build_dsa_attrs(pub_attrs, priv_attrs, pub_dict)
    elif key_type == CKK_DH:
        pub_final, priv_final = _build_dh_attrs(pub_attrs, priv_attrs, pub_dict)
    else:
        # Default to RSA for unknown key types
        pub_final, priv_final = _build_rsa_attrs(pub_attrs, priv_attrs, pub_dict)

    pub_obj = store.create_object(token_name, pub_obj_type, pub_final)
    if pub_obj is None:
        logger.error('GKP: failed to create public key in token %r', token_name)
        return encode_response(
            request.handle, RC_ERROR, RSN_TOKEN_NOT_FOUND, ICSF_TAG_CSFPGKP, b'')

    priv_obj = store.create_object(token_name, priv_obj_type, priv_final)
    if priv_obj is None:
        logger.error('GKP: failed to create private key in token %r', token_name)
        return encode_response(
            request.handle, RC_ERROR, RSN_TOKEN_NOT_FOUND, ICSF_TAG_CSFPGKP, b'')

    pub_handle  = make_object_handle(token_name, pub_obj.sequence,  pub_obj_type)
    priv_handle = make_object_handle(token_name, priv_obj.sequence, priv_obj_type)

    logger.info('GKP: token=%r pub_seq=%d priv_seq=%d key_type=0x%x pub_attrs=%d priv_attrs=%d',
                token_name, pub_obj.sequence, priv_obj.sequence,
                key_type if key_type else 0,
                len(pub_final), len(priv_final))

    # GKPOutput: the private key handle as a raw OCTET STRING.
    # icsf_generate_key_pair() reads the service context TLV value directly with
    # ber_scanf(result, "m", &bv_priv_handle) — "m" reads the raw bytes of the
    # *current* TLV value (the context tag).  The svc_data therefore IS the
    # 44-byte handle verbatim; no inner OCTET STRING wrapper is added.
    svc_data = priv_handle
    return encode_response(pub_handle, RC_SUCCESS, 0, ICSF_TAG_CSFPGKP, svc_data)


# ---------------------------------------------------------------------------
# RSA key pair builders
# ---------------------------------------------------------------------------

def _build_rsa_attrs(pub_attrs, priv_attrs, pub_dict):
    """Generate a real RSA key pair and build complete attribute lists."""
    mod_bits = pub_dict.get(CKA_MODULUS_BITS, 2048)
    if isinstance(mod_bits, bytes):
        mod_bits = int.from_bytes(mod_bits, 'big')

    key = rsa_generate(mod_bits)

    # Inject all CRT components into the private-key caller attrs so that
    # make_rsa_keypair_attrs / complete_key_attrs stores them on the object.
    priv_extra = [
        (CKA_PRIVATE_EXPONENT, key[CKA_PRIVATE_EXPONENT]),
        (CKA_PRIME_1,          key[CKA_PRIME_1]),
        (CKA_PRIME_2,          key[CKA_PRIME_2]),
        (CKA_EXPONENT_1,       key[CKA_EXPONENT_1]),
        (CKA_EXPONENT_2,       key[CKA_EXPONENT_2]),
        (CKA_COEFFICIENT,      key[CKA_COEFFICIENT]),
    ]

    return make_rsa_keypair_attrs(
        pub_caller_attrs=pub_attrs,
        priv_caller_attrs=list(priv_attrs) + priv_extra,
        modulus=key[CKA_MODULUS],
        public_exponent=key[CKA_PUBLIC_EXPONENT],
        key_gen_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN,
    )


# ---------------------------------------------------------------------------
# EC key pair builders
# ---------------------------------------------------------------------------

# NIST P-256 OID: 1.2.840.10045.3.1.7 (DER encoded)
_P256_PARAMS = bytes.fromhex('06082a8648ce3d030107')


def _build_ec_attrs(pub_attrs, priv_attrs, pub_dict):
    """Generate a real EC key pair and build complete attribute lists."""
    ec_params = pub_dict.get(CKA_EC_PARAMS) or _P256_PARAMS
    key = ec_generate(ec_params)

    # Inject the private scalar into the private-key caller attrs so that
    # make_ec_keypair_attrs / complete_key_attrs stores it on the object.
    priv_extra = [(CKA_VALUE, key[CKA_VALUE])]

    return make_ec_keypair_attrs(
        pub_caller_attrs=pub_attrs,
        priv_caller_attrs=list(priv_attrs) + priv_extra,
        ec_params=key[CKA_EC_PARAMS],
        ec_point=key[CKA_EC_POINT],
        key_gen_mechanism=CKM_EC_KEY_PAIR_GEN,
    )


# ---------------------------------------------------------------------------
# DSA key pair builders
# ---------------------------------------------------------------------------

# Default 1024-bit DSA domain parameters matching the values in dsa_func.c
# (DSA_PUBL_PRIME / DSA_PUBL_SUBPRIME / DSA_PUBL_BASE).  Used as fallback when
# the caller did not supply domain parameters.
_DSA_DEFAULT_PRIME = bytes([
    0xba, 0xa2, 0x5b, 0xd9, 0x77, 0xb3, 0xf0, 0x2d, 0xa1, 0x65,
    0xf1, 0x83, 0xa7, 0xc9, 0xf0, 0x8a, 0x51, 0x3f, 0x74, 0xe8,
    0xeb, 0x1f, 0xd7, 0x0a, 0xd5, 0x41, 0xfa, 0x52, 0x3c, 0x1f,
    0x79, 0x15, 0x55, 0x18, 0x45, 0x41, 0x29, 0x27, 0x12, 0x4a,
    0xb4, 0x32, 0xa6, 0xd2, 0xec, 0xe2, 0x82, 0x73, 0xf4, 0x30,
    0x66, 0x1a, 0x31, 0x06, 0x37, 0xd2, 0xb0, 0xe4, 0x26, 0x39,
    0x2a, 0x0e, 0x48, 0xf6, 0x77, 0x94, 0x47, 0xea, 0x7d, 0x99,
    0x22, 0xce, 0x65, 0x61, 0x82, 0xd5, 0xe3, 0xfc, 0x15, 0x3f,
    0xff, 0xff, 0xc8, 0xb9, 0x4f, 0x37, 0xbf, 0x7a, 0xa6, 0x6a,
    0xbe, 0xff, 0xa9, 0xdf, 0xfd, 0xed, 0x4a, 0xb6, 0x83, 0xd6,
    0x0f, 0xea, 0xf6, 0x90, 0x4f, 0x12, 0x8e, 0x09, 0x6e, 0x3c,
    0x0a, 0x6d, 0x2e, 0xfb, 0xb3, 0x79, 0x90, 0x8e, 0x39, 0xc0,
    0x86, 0x0e, 0x5d, 0xf0, 0x56, 0xcd, 0x26, 0x45,
])
_DSA_DEFAULT_SUBPRIME = bytes([
    0x9f, 0x3d, 0x47, 0x13, 0xa3, 0xff, 0x93, 0xbb, 0x4a, 0xa6,
    0xb0, 0xf1, 0x7e, 0x54, 0x1e, 0xba, 0xf0, 0x66, 0x03, 0x61,
])
_DSA_DEFAULT_BASE = bytes([
    0x1a, 0x5b, 0xfe, 0x12, 0xba, 0x85, 0x8e, 0x9b, 0x08, 0x86,
    0xd1, 0x43, 0x9b, 0x4a, 0xaf, 0x44, 0x31, 0xdf, 0xa1, 0x57,
    0xd8, 0xe0, 0xec, 0x34, 0x07, 0x4b, 0x78, 0x8e, 0x3c, 0x62,
    0x47, 0x4c, 0x2f, 0x5d, 0xd3, 0x31, 0x2c, 0xe9, 0xdd, 0x59,
    0xc5, 0xe7, 0x2e, 0x06, 0x40, 0x6c, 0x72, 0x9c, 0x95, 0xc6,
    0xa4, 0x2a, 0x1c, 0x1c, 0x45, 0xb9, 0xf3, 0xdc, 0x83, 0xb6,
    0xc6, 0xdd, 0x94, 0x45, 0x4f, 0x74, 0xc6, 0x55, 0x36, 0x54,
    0xba, 0x20, 0xad, 0x9a, 0xb6, 0xe3, 0x20, 0xf2, 0xdd, 0xd3,
    0x66, 0x19, 0xeb, 0x53, 0xf5, 0x88, 0x35, 0xe1, 0xea, 0xe8,
    0xd4, 0x57, 0xe1, 0x3d, 0xea, 0xd5, 0x00, 0xc2, 0xa4, 0xf5,
    0xff, 0xfb, 0x0b, 0xfb, 0xa2, 0xb9, 0xf1, 0x49, 0x46, 0x9d,
    0x11, 0xa5, 0xb1, 0x94, 0x52, 0x47, 0x6e, 0x2e, 0x79, 0x4b,
    0xc5, 0x18, 0xe9, 0xbc, 0xff, 0xae, 0x34, 0x7f,
])


def _build_dsa_attrs(pub_attrs, priv_attrs, pub_dict):
    """Generate a DSA key pair from domain parameters (p, q, g) and build attribute lists."""
    prime_bytes    = pub_dict.get(CKA_PRIME,    b'')
    subprime_bytes = pub_dict.get(CKA_SUBPRIME, b'')
    base_bytes     = pub_dict.get(CKA_BASE,     b'')

    # Validate / normalise attribute byte values
    if isinstance(prime_bytes,    int):
        prime_bytes    = prime_bytes.to_bytes((prime_bytes.bit_length()    + 7) // 8, 'big')
    if isinstance(subprime_bytes, int):
        subprime_bytes = subprime_bytes.to_bytes((subprime_bytes.bit_length() + 7) // 8, 'big')
    if isinstance(base_bytes,     int):
        base_bytes     = base_bytes.to_bytes((base_bytes.bit_length()     + 7) // 8, 'big')

    if not prime_bytes:
        prime_bytes    = _DSA_DEFAULT_PRIME
        subprime_bytes = _DSA_DEFAULT_SUBPRIME
        base_bytes     = _DSA_DEFAULT_BASE
    elif not subprime_bytes:
        # Minimal fallback: 160-bit subprime relative to the supplied prime
        subprime_bytes = _DSA_DEFAULT_SUBPRIME
    if not base_bytes:
        base_bytes = _DSA_DEFAULT_BASE

    try:
        key = dsa_generate(prime_bytes, subprime_bytes, base_bytes)
        pub_value  = key['pub_value']
        priv_value = key['priv_value']
    except Exception as exc:
        # Pure-Python fallback: x random in [2, q-2], y = g^x mod p
        logger.warning('GKP: OpenSSL dsa_generate failed (%s), falling back to python pow', exc)
        p_int = int.from_bytes(prime_bytes, 'big')
        q_int = int.from_bytes(subprime_bytes, 'big')
        g_int = int.from_bytes(base_bytes, 'big')
        x_int = secrets.randbelow(q_int - 3) + 2
        y_int = pow(g_int, x_int, p_int)
        priv_value = x_int.to_bytes(len(subprime_bytes), 'big')
        pub_value  = y_int.to_bytes(len(prime_bytes), 'big')

    return make_dsa_keypair_attrs(
        pub_caller_attrs=pub_attrs,
        priv_caller_attrs=priv_attrs,
        prime=prime_bytes,
        subprime=subprime_bytes,
        base=base_bytes,
        pub_value=pub_value,
        priv_value=priv_value,
        key_gen_mechanism=CKM_DSA_KEY_PAIR_GEN,
    )


# ---------------------------------------------------------------------------
# DH key pair builders
# ---------------------------------------------------------------------------

def _build_dh_attrs(pub_attrs, priv_attrs, pub_dict):
    """Generate a DH key pair from domain parameters (p, g) and build attribute lists."""
    prime_bytes = pub_dict.get(CKA_PRIME, b'')
    base_bytes  = pub_dict.get(CKA_BASE, b'')

    if not prime_bytes:
        # Fallback default 1024-bit MODP prime if unspecified
        prime_int = int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE653E0"
            "FF2F0B20DF253F3F", 16
        )
        prime_len = (prime_int.bit_length() + 7) // 8
        prime_bytes = prime_int.to_bytes(prime_len, 'big')

    if not base_bytes:
        base_bytes = b'\x02'

    try:
        key = dh_generate(prime_bytes, base_bytes)
        pub_value = key['pub_value']
        priv_value = key['priv_value']
    except Exception as exc:
        logger.warning('GKP: OpenSSL dh_generate failed (%s), falling back to python pow: ', exc)
        prime_int = int.from_bytes(prime_bytes, 'big')
        prime_len = len(prime_bytes)
        base_int = int.from_bytes(base_bytes, 'big')
        x_int = secrets.randbelow(prime_int - 3) + 2
        y_int = pow(base_int, x_int, prime_int)
        priv_value = x_int.to_bytes(prime_len, 'big')
        pub_value  = y_int.to_bytes(prime_len, 'big')

    return make_dh_keypair_attrs(
        pub_caller_attrs=pub_attrs,
        priv_caller_attrs=priv_attrs,
        prime=prime_bytes,
        base=base_bytes,
        pub_value=pub_value,
        priv_value=priv_value,
        key_gen_mechanism=CKM_DH_PKCS_KEY_PAIR_GEN,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_token_obj(attr_dict):
    v = attr_dict.get(CKA_TOKEN, b'\x00')
    return bool(v[0] if isinstance(v, bytes) else v)
