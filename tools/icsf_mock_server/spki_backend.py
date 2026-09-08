# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
spki_backend.py — Pure-Python SubjectPublicKeyInfo (SPKI) DER builders.

Builds the DER-encoded SubjectPublicKeyInfo structure (RFC 5480 / RFC 3279)
that is stored as CKA_PUBLIC_KEY_INFO on both public and private key objects.

SubjectPublicKeyInfo ::= SEQUENCE {
    algorithm         AlgorithmIdentifier,
    subjectPublicKey  BIT STRING
}

AlgorithmIdentifier ::= SEQUENCE {
    algorithm   OBJECT IDENTIFIER,
    parameters  ANY OPTIONAL
}

Supported key types
-------------------
  RSA   — rsaEncryption OID (1.2.840.113549.1.1.1), parameters NULL, key is
           DER BIT STRING wrapping SEQUENCE { INTEGER n, INTEGER e }  (RFC 3279)
  EC    — id-ecPublicKey OID (1.2.840.10045.2.1), parameters = ECParameters
           (the DER OID already stored in CKA_EC_PARAMS), key is BIT STRING
           wrapping the uncompressed point 04||X||Y  (RFC 5480)
  DSA   — id-dsa OID (1.2.840.10040.4.1), parameters = Dss-Parms SEQUENCE
           { INTEGER p, INTEGER q, INTEGER g }, key is BIT STRING wrapping
           a single INTEGER y  (RFC 3279)
  DH    — dhPublicNumber OID (1.2.840.10046.2.7), parameters = DomainParameters
           SEQUENCE { INTEGER p, ..., INTEGER g }, key is BIT STRING wrapping
           INTEGER pub_value  (RFC 3279 §2.3.3 / PKCS#3)

Public API
----------
  spki_from_rsa(n_bytes, e_bytes)  -> bytes   DER SPKI
  spki_from_ec(ec_params_der, ec_point_bytes) -> bytes   DER SPKI
  spki_from_dsa(p, q, g, pub_value) -> bytes   DER SPKI
  spki_from_dh(p, g, pub_value)    -> bytes   DER SPKI
  spki_from_attrs(attr_dict)       -> bytes or None
"""

import logging

from pkcs11_const import (
    CKA_CLASS, CKA_KEY_TYPE,
    CKA_MODULUS, CKA_PUBLIC_EXPONENT,
    CKA_EC_PARAMS, CKA_EC_POINT,
    CKA_PRIME, CKA_SUBPRIME, CKA_BASE, CKA_VALUE,
    CKO_PUBLIC_KEY, CKO_PRIVATE_KEY,
    CKK_RSA, CKK_EC, CKK_DSA, CKK_DH,
)

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# DER primitives
# ---------------------------------------------------------------------------

def _der_len(n: int) -> bytes:
    """DER length encoding."""
    if n < 0x80:
        return bytes([n])
    if n <= 0xFF:
        return bytes([0x81, n])
    if n <= 0xFFFF:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    raise ValueError('DER length too large: %d' % n)


def _der_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(value)) + value


def _der_sequence(*items) -> bytes:
    body = b''.join(items)
    return _der_tlv(0x30, body)


def _der_oid(encoded: bytes) -> bytes:
    """Wrap pre-encoded OID content bytes in the OID tag (0x06)."""
    return _der_tlv(0x06, encoded)


def _der_null() -> bytes:
    return bytes([0x05, 0x00])


def _der_integer(value: bytes) -> bytes:
    """DER INTEGER from big-endian byte string.

    Strips leading zero bytes, but adds a leading 0x00 byte if the high bit
    of the first remaining byte is set (to keep the value positive).
    """
    if not value:
        return _der_tlv(0x02, b'\x00')
    # Strip leading zeros
    stripped = value.lstrip(b'\x00') or b'\x00'
    # Add sign byte if high bit is set
    if stripped[0] & 0x80:
        stripped = b'\x00' + stripped
    return _der_tlv(0x02, stripped)


def _der_bit_string(payload: bytes) -> bytes:
    """DER BIT STRING with 0 unused bits."""
    return _der_tlv(0x03, b'\x00' + payload)


def _unwrap_ec_point(ec_point: bytes) -> bytes:
    """Strip PKCS#11 DER OCTET STRING wrapper from CKA_EC_POINT if present."""
    if not ec_point:
        return ec_point
    if ec_point[0] != 0x04 or len(ec_point) < 2:
        return ec_point
    b1 = ec_point[1]
    if b1 < 0x80:
        hdr = 2; inner_len = b1
    elif b1 == 0x81 and len(ec_point) >= 3:
        hdr = 3; inner_len = ec_point[2]
    elif b1 == 0x82 and len(ec_point) >= 4:
        hdr = 4; inner_len = (ec_point[2] << 8) | ec_point[3]
    else:
        return ec_point
    if hdr + inner_len == len(ec_point) and inner_len >= 1 \
            and ec_point[hdr] in (0x02, 0x03, 0x04, 0x06, 0x07):
        return ec_point[hdr:hdr + inner_len]
    return ec_point


# ---------------------------------------------------------------------------
# Well-known OID content bytes (without the 0x06 tag — that is added by
# _der_oid()).  Values are standard, taken from relevant RFCs.
# ---------------------------------------------------------------------------

# rsaEncryption  1.2.840.113549.1.1.1
_OID_RSA_ENCRYPTION = bytes.fromhex('2a 86 48 86 f7 0d 01 01 01'.replace(' ', ''))

# id-ecPublicKey  1.2.840.10045.2.1
_OID_EC_PUBLIC_KEY = bytes.fromhex('2a 86 48 ce 3d 02 01'.replace(' ', ''))

# id-dsa  1.2.840.10040.4.1
_OID_DSA = bytes.fromhex('2a 86 48 ce 38 04 01'.replace(' ', ''))

# dhKeyAgreement  1.2.840.113549.1.3.1  (PKCS#3 DH — used by OpenSSL EVP_PKEY_DH)
# Note: dhPublicNumber (1.2.840.10046.2.7) is the X9.42 DH OID used by EVP_PKEY_DHX.
# openCryptoki uses PKCS#3 DH (CKM_DH_PKCS_KEY_PAIR_GEN) and p11sak exports via
# EVP_PKEY_DH, so d2i_PUBKEY expects the dhKeyAgreement OID here.
_OID_DH_KEY_AGREEMENT = bytes.fromhex('2a8648 86f70d 010301'.replace(' ', ''))


# ---------------------------------------------------------------------------
# Public builder functions
# ---------------------------------------------------------------------------

def spki_from_rsa(n_bytes: bytes, e_bytes: bytes) -> bytes:
    """Build SubjectPublicKeyInfo for RSA (RFC 3279 §2.3.1).

    AlgorithmIdentifier: rsaEncryption, parameters NULL.
    SubjectPublicKey: BIT STRING wrapping SEQUENCE { INTEGER n, INTEGER e }.
    """
    algorithm = _der_sequence(
        _der_oid(_OID_RSA_ENCRYPTION),
        _der_null(),
    )
    pub_key_inner = _der_sequence(
        _der_integer(n_bytes),
        _der_integer(e_bytes),
    )
    subject_public_key = _der_bit_string(pub_key_inner)
    return _der_sequence(algorithm, subject_public_key)


def spki_from_ec(ec_params_der: bytes, ec_point_bytes: bytes) -> bytes:
    """Build SubjectPublicKeyInfo for EC (RFC 5480 §2).

    AlgorithmIdentifier: id-ecPublicKey, parameters = ECParameters OID.
    SubjectPublicKey: BIT STRING wrapping the uncompressed point 04||X||Y.

    ec_params_der  : DER-encoded ECParameters (the raw OID bytes as stored in
                     CKA_EC_PARAMS, e.g. 06 08 2a 86 48 ce 3d 03 01 07 for P-256)
    ec_point_bytes : raw point bytes (04||X||Y), already unwrapped from any
                     PKCS#11 OCTET STRING wrapper.
    """
    algorithm = _der_sequence(
        _der_oid(_OID_EC_PUBLIC_KEY),
        ec_params_der,          # already DER-encoded (tag 0x06 + OID body)
    )
    subject_public_key = _der_bit_string(ec_point_bytes)
    return _der_sequence(algorithm, subject_public_key)


def spki_from_dsa(p: bytes, q: bytes, g: bytes, pub_value: bytes) -> bytes:
    """Build SubjectPublicKeyInfo for DSA (RFC 3279 §2.3.2).

    AlgorithmIdentifier: id-dsa, parameters = Dss-Parms SEQUENCE{p, q, g}.
    SubjectPublicKey: BIT STRING wrapping INTEGER y.
    """
    dss_params = _der_sequence(
        _der_integer(p),
        _der_integer(q),
        _der_integer(g),
    )
    algorithm = _der_sequence(
        _der_oid(_OID_DSA),
        dss_params,
    )
    subject_public_key = _der_bit_string(_der_integer(pub_value))
    return _der_sequence(algorithm, subject_public_key)


def spki_from_dh(p: bytes, g: bytes, pub_value: bytes) -> bytes:
    """Build SubjectPublicKeyInfo for PKCS#3 DH (RFC 3279 §2.3.3).

    AlgorithmIdentifier: dhKeyAgreement OID (1.2.840.113549.1.3.1), parameters =
    DHParameter SEQUENCE { INTEGER p, INTEGER g }.
    SubjectPublicKey: BIT STRING wrapping INTEGER pub_value.

    This is the OID used by OpenSSL for EVP_PKEY_DH (PKCS#3 DH), which is what
    openCryptoki generates with CKM_DH_PKCS_KEY_PAIR_GEN and what p11sak/OpenSSL
    expect when calling d2i_PUBKEY on a DH SPKI.  The X9.42 DH OID
    (dhPublicNumber, 1.2.840.10046.2.7, EVP_PKEY_DHX) is a different type.
    """
    dh_params = _der_sequence(
        _der_integer(p),
        _der_integer(g),
    )
    algorithm = _der_sequence(
        _der_oid(_OID_DH_KEY_AGREEMENT),
        dh_params,
    )
    subject_public_key = _der_bit_string(_der_integer(pub_value))
    return _der_sequence(algorithm, subject_public_key)


def spki_from_attrs(attr_dict: dict):
    """Derive the SPKI bytes from a PKCS#11 attribute dict.

    Works for both public key objects (CKO_PUBLIC_KEY) and private key objects
    (CKO_PRIVATE_KEY) provided the necessary public key material is present.

    Returns bytes on success, or None if the key type is unknown or required
    attributes are missing.
    """
    def _get(key):
        v = attr_dict.get(key)
        if v is None or v == b'' or v == b'\x00':
            return None
        if isinstance(v, int):
            n = v
            length = (n.bit_length() + 7) // 8 or 1
            return n.to_bytes(length, 'big')
        return v if v else None

    key_type = _get(CKA_KEY_TYPE)
    if key_type is None:
        return None
    if isinstance(key_type, bytes):
        key_type = int.from_bytes(key_type, 'big')

    try:
        if key_type == CKK_RSA:
            n = _get(CKA_MODULUS)
            e = _get(CKA_PUBLIC_EXPONENT)
            if n and e:
                return spki_from_rsa(n, e)

        elif key_type == CKK_EC:
            params = _get(CKA_EC_PARAMS)
            raw_point = _unwrap_ec_point(_get(CKA_EC_POINT))
            if params and raw_point:
                return spki_from_ec(params, raw_point)

        elif key_type == CKK_DSA:
            p = _get(CKA_PRIME)
            q = _get(CKA_SUBPRIME)
            g = _get(CKA_BASE)
            y = _get(CKA_VALUE)
            obj_class = attr_dict.get(CKA_CLASS)
            if isinstance(obj_class, bytes):
                obj_class = int.from_bytes(obj_class, 'big')
            # CKA_VALUE on DSA public key is y; on DSA private key it is x —
            # we cannot build a valid SPKI from a private-key-only attribute set
            # unless pub_value was injected.  Skip if class is private and y looks
            # like a subprime-sized value (x), since y should be prime-sized.
            if obj_class == CKO_PRIVATE_KEY:
                # For private keys, pub_value must have been explicitly injected
                # into the attr_dict under a well-known key.  Check that y is
                # prime-sized (len == len(p)), otherwise it is x and we cannot
                # build the SPKI.
                if p and y and len(y) < len(p):
                    _log.debug('spki_from_attrs: DSA private key, no public value injected, skipping')
                    return None
            if p and q and g and y:
                return spki_from_dsa(p, q, g, y)

        elif key_type == CKK_DH:
            p = _get(CKA_PRIME)
            g = _get(CKA_BASE)
            v = _get(CKA_VALUE)
            obj_class = attr_dict.get(CKA_CLASS)
            if isinstance(obj_class, bytes):
                obj_class = int.from_bytes(obj_class, 'big')
            # Same logic as DSA: CKA_VALUE on a DH public key is the public value,
            # on a private key it is the private exponent — skip for private keys.
            if obj_class == CKO_PUBLIC_KEY and p and g and v:
                return spki_from_dh(p, g, v)
            if obj_class == CKO_PRIVATE_KEY:
                _log.debug('spki_from_attrs: DH private key, no public value available, skipping')
                return None

    except Exception as exc:
        _log.warning('spki_from_attrs: failed to build SPKI: %s', exc)

    return None
