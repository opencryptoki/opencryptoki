# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
obj_attrs.py — PKCS#11-compliant attribute completion for key and certificate objects.

When the ICSF server creates an object (via TRC, GSK, or GKP) it stores ALL
attributes defined by PKCS#11 for that object class, not just the ones the
caller supplied.  This module implements that attribute-filling logic.

PKCS#11 v2.40 attribute groups
───────────────────────────────
  Common object attributes  (Table 13)
      CKA_CLASS, CKA_TOKEN, CKA_PRIVATE, CKA_MODIFIABLE, CKA_LABEL,
      CKA_COPYABLE, CKA_DESTROYABLE

  Common key attributes  (Table 18)
      CKA_KEY_TYPE, CKA_ID, CKA_START_DATE, CKA_END_DATE,
      CKA_DERIVE, CKA_LOCAL, CKA_KEY_GEN_MECHANISM,
      CKA_ALLOWED_MECHANISMS

  Common secret-key attributes  (Table 24)
      + CKA_SENSITIVE, CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, CKA_VERIFY,
        CKA_WRAP, CKA_UNWRAP, CKA_EXTRACTABLE,
        CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE,
        CKA_WRAP_WITH_TRUSTED, CKA_UNWRAP_TEMPLATE, CKA_DERIVE_TEMPLATE,
        CKA_TRUSTED, CKA_VALUE, CKA_VALUE_LEN

  Common public-key attributes  (Table 19)
      + CKA_SUBJECT, CKA_ENCRYPT, CKA_VERIFY, CKA_VERIFY_RECOVER,
        CKA_WRAP, CKA_TRUSTED, CKA_WRAP_TEMPLATE, CKA_PUBLIC_KEY_INFO

  Common private-key attributes  (Table 20)
      + CKA_SUBJECT, CKA_SENSITIVE, CKA_DECRYPT, CKA_SIGN, CKA_SIGN_RECOVER,
        CKA_UNWRAP, CKA_EXTRACTABLE, CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE,
        CKA_WRAP_WITH_TRUSTED, CKA_UNWRAP_TEMPLATE, CKA_ALWAYS_AUTHENTICATE,
        CKA_PUBLIC_KEY_INFO

  X.509 certificate attributes  (Table 23)
      CKA_CERTIFICATE_TYPE, CKA_TRUSTED, CKA_CERTIFICATE_CATEGORY,
      CKA_CHECK_VALUE, CKA_START_DATE, CKA_END_DATE,
      CKA_SUBJECT, CKA_ID, CKA_ISSUER, CKA_SERIAL_NUMBER, CKA_VALUE,
      CKA_URL, CKA_HASH_OF_SUBJECT_PUBLIC_KEY, CKA_HASH_OF_ISSUER_PUBLIC_KEY,
      CKA_NAME_HASH_ALGORITHM

Public API
──────────
  complete_key_attrs(attrs, key_gen_mechanism)
      Fill in all PKCS#11-defined defaults for a key object.

  complete_cert_attrs(attrs)
      Fill in all PKCS#11-defined defaults for a certificate object.

  make_x509_cert_attrs(der_value, caller_attrs)
      Build a complete X.509 certificate attribute list.
"""

import logging

from pkcs11_const import (
    # Object
    CKA_CLASS, CKA_TOKEN, CKA_PRIVATE, CKA_MODIFIABLE, CKA_LABEL,
    CKA_COPYABLE, CKA_DESTROYABLE,
    # Key common
    CKA_KEY_TYPE, CKA_ID, CKA_START_DATE, CKA_END_DATE,
    CKA_DERIVE, CKA_LOCAL, CKA_KEY_GEN_MECHANISM, CKA_ALLOWED_MECHANISMS,
    # Crypto
    CKA_SENSITIVE, CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, CKA_VERIFY,
    CKA_VERIFY_RECOVER, CKA_SIGN_RECOVER, CKA_WRAP, CKA_UNWRAP,
    CKA_EXTRACTABLE, CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE,
    CKA_WRAP_WITH_TRUSTED, CKA_UNWRAP_TEMPLATE, CKA_DERIVE_TEMPLATE,
    CKA_WRAP_TEMPLATE, CKA_TRUSTED, CKA_ALWAYS_AUTHENTICATE,
    CKA_VALUE, CKA_VALUE_BITS, CKA_VALUE_LEN,
    # RSA
    CKA_MODULUS, CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT,
    # EC
    CKA_EC_PARAMS, CKA_EC_POINT,
    # DH / DSA domain parameters & key values
    CKA_PRIME, CKA_SUBPRIME, CKA_BASE, CKA_PRIME_BITS, CKA_SUBPRIME_BITS,
    # Subject / issuer
    CKA_SUBJECT, CKA_ISSUER, CKA_SERIAL_NUMBER,
    CKA_CERTIFICATE_TYPE, CKA_CERTIFICATE_CATEGORY,
    CKA_CHECK_VALUE, CKA_URL,
    CKA_HASH_OF_SUBJECT_PUBLIC_KEY, CKA_HASH_OF_ISSUER_PUBLIC_KEY,
    CKA_NAME_HASH_ALGORITHM,
    # CKA_PUBLIC_KEY_INFO (PKCS#11 v2.40 §4.8 / §4.9)
    CKA_PUBLIC_KEY_INFO,
    # Classes
    CKO_SECRET_KEY, CKO_PUBLIC_KEY, CKO_PRIVATE_KEY, CKO_CERTIFICATE,
    # Certificate types
    CKC_X_509,
    # Key types
    CKK_DES, CKK_DES2, CKK_DES3, CKK_AES, CKK_GENERIC_SECRET,
    CKK_RSA, CKK_DSA, CKK_DH, CKK_EC,
    # Mechanisms
    CKM_UNAVAILABLE_INFORMATION, CKM_SHA256,
    CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_DSA_KEY_PAIR_GEN,
    CKM_DH_PKCS_KEY_PAIR_GEN, CKM_EC_KEY_PAIR_GEN,
    CKM_DES_KEY_GEN, CKM_DES2_KEY_GEN, CKM_DES3_KEY_GEN,
    CKM_AES_KEY_GEN, CKM_GENERIC_SECRET_KEY_GEN,
    # Booleans
    bool_attr,
)
from spki_backend import spki_from_attrs, spki_from_dsa, spki_from_dh

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default key sizes in bytes for fixed-size key types
# ---------------------------------------------------------------------------
_FIXED_KEY_LEN = {
    CKK_DES:  8,
    CKK_DES2: 16,
    CKK_DES3: 24,
}

# Default generating mechanism per key type (used when key_gen_mechanism is
# not explicitly supplied to complete_key_attrs)
_DEFAULT_GEN_MECH = {
    CKK_RSA: CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKK_DSA: CKM_DSA_KEY_PAIR_GEN,
    CKK_DH:  CKM_DH_PKCS_KEY_PAIR_GEN,
    CKK_EC:  CKM_EC_KEY_PAIR_GEN,
    CKK_DES: CKM_DES_KEY_GEN,
    CKK_DES2: CKM_DES2_KEY_GEN,
    CKK_DES3: CKM_DES3_KEY_GEN,
    CKK_AES:  CKM_AES_KEY_GEN,
    CKK_GENERIC_SECRET: CKM_GENERIC_SECRET_KEY_GEN,
}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def complete_key_attrs(attrs, key_gen_mechanism=None):
    """
    Return a list of (attr_type, attr_value) with ALL PKCS#11-defined
    attributes for the key class, filling in defaults for anything missing
    from *attrs*.

    Parameters
    ----------
    attrs : list of (int, bytes|int)
        Caller-supplied attributes (from C_CreateObject template, GSK input,
        GKP input, etc.).  May be empty.
    key_gen_mechanism : int or None
        The CKM_* mechanism that generated this key.  Use
        CKM_UNAVAILABLE_INFORMATION for C_CreateObject paths.
        None means the function will infer from key type.

    Returns
    -------
    list of (int, bytes|int)
        Complete attribute set.  Caller-supplied values take priority over
        defaults; only missing attributes are added.
    """
    # Work with a dict for easy lookup; preserve first-seen order via dict.
    attr_dict = {}
    for t, v in attrs:
        attr_dict[t] = v

    # Resolve object class
    obj_class = _get_int(attr_dict, CKA_CLASS)

    if obj_class == CKO_CERTIFICATE:
        return complete_cert_attrs(attrs)

    if obj_class not in (CKO_SECRET_KEY, CKO_PUBLIC_KEY, CKO_PRIVATE_KEY):
        # Not a recognised object class — return attrs unchanged.
        return list(attrs)

    # ----------------------------------------------------------------
    # Common object attributes (PKCS#11 Table 13)
    # ----------------------------------------------------------------
    _default(attr_dict, CKA_TOKEN,       bool_attr(False))
    _default(attr_dict, CKA_PRIVATE,     bool_attr(False))
    _default(attr_dict, CKA_MODIFIABLE,  bool_attr(True))
    _default(attr_dict, CKA_LABEL,       b'')
    _default(attr_dict, CKA_COPYABLE,    bool_attr(True))
    _default(attr_dict, CKA_DESTROYABLE, bool_attr(True))

    # ----------------------------------------------------------------
    # Common key attributes (PKCS#11 Table 18)
    # ----------------------------------------------------------------
    _default(attr_dict, CKA_ID,                 b'')
    _default(attr_dict, CKA_START_DATE,         b'')
    _default(attr_dict, CKA_END_DATE,           b'')
    _default(attr_dict, CKA_DERIVE,             bool_attr(False))
    # CKA_LOCAL: True when generated on-token, False when imported
    if CKA_LOCAL not in attr_dict:
        is_local = (key_gen_mechanism is not None and
                    key_gen_mechanism != CKM_UNAVAILABLE_INFORMATION)
        attr_dict[CKA_LOCAL] = bool_attr(is_local)

    # CKA_KEY_GEN_MECHANISM — omit if unknown; real ICSF does not return
    # CK_UNAVAILABLE_INFORMATION (0xFFFFFFFF) on the wire.
    if CKA_KEY_GEN_MECHANISM not in attr_dict:
        key_type = _get_int(attr_dict, CKA_KEY_TYPE)
        if key_gen_mechanism is not None and \
                key_gen_mechanism != CKM_UNAVAILABLE_INFORMATION:
            attr_dict[CKA_KEY_GEN_MECHANISM] = key_gen_mechanism
        elif key_type is not None and key_type in _DEFAULT_GEN_MECH:
            attr_dict[CKA_KEY_GEN_MECHANISM] = _DEFAULT_GEN_MECH[key_type]
        # else: leave absent — real ICSF omits it rather than sending 0xFFFFFFFF

    # CKA_ALLOWED_MECHANISMS — empty sequence means "all mechanisms allowed"
    _default(attr_dict, CKA_ALLOWED_MECHANISMS, b'')

    # ----------------------------------------------------------------
    # Class-specific defaults
    # ----------------------------------------------------------------
    if obj_class == CKO_SECRET_KEY:
        _complete_secret_key(attr_dict)
    elif obj_class == CKO_PUBLIC_KEY:
        _complete_public_key(attr_dict)
    elif obj_class == CKO_PRIVATE_KEY:
        _complete_private_key(attr_dict)

    # Return in a stable order: caller-supplied first (preserving original
    # ordering), followed by defaults appended in definition order.
    # Filter out any attribute whose value is CK_UNAVAILABLE_INFORMATION —
    # real ICSF omits such attributes rather than encoding an invalid integer.
    return [(t, v) for t, v in attr_dict.items()
            if not (isinstance(v, int) and v == CKM_UNAVAILABLE_INFORMATION)]


# ---------------------------------------------------------------------------
# Secret key completion
# ---------------------------------------------------------------------------

def _complete_secret_key(d):
    """Fill in all common secret-key attribute defaults (PKCS#11 Table 24).

    CKA_SIGN / CKA_VERIFY defaults depend on the key type:
      - CKK_GENERIC_SECRET: True  (used for HMAC; real ICSF returns True)
      - All other secret key types (AES, DES, 3DES, ...): False
    """
    sensitive   = _get_bool(d, CKA_SENSITIVE,   False)
    extractable = _get_bool(d, CKA_EXTRACTABLE,  True)

    key_type = _get_int(d, CKA_KEY_TYPE)
    sign_verify_default = (key_type == CKK_GENERIC_SECRET)

    _default(d, CKA_SENSITIVE,         bool_attr(False))
    _default(d, CKA_ENCRYPT,           bool_attr(True))
    _default(d, CKA_DECRYPT,           bool_attr(True))
    _default(d, CKA_SIGN,              bool_attr(sign_verify_default))
    _default(d, CKA_VERIFY,            bool_attr(sign_verify_default))
    _default(d, CKA_WRAP,              bool_attr(True))
    _default(d, CKA_UNWRAP,            bool_attr(True))
    _default(d, CKA_EXTRACTABLE,       bool_attr(True))
    _default(d, CKA_ALWAYS_SENSITIVE,  bool_attr(sensitive))
    _default(d, CKA_NEVER_EXTRACTABLE, bool_attr(not extractable))
    _default(d, CKA_WRAP_WITH_TRUSTED, bool_attr(False))
    _default(d, CKA_TRUSTED,           bool_attr(False))
    # Template attributes — empty (no forced unwrap/derive template)
    _default(d, CKA_UNWRAP_TEMPLATE,   b'')
    _default(d, CKA_DERIVE_TEMPLATE,   b'')

    # Derive CKA_VALUE_LEN from CKA_VALUE if both not present
    if CKA_VALUE_LEN not in d:
        if CKA_VALUE in d:
            val = d[CKA_VALUE]
            vlen = len(val) if isinstance(val, (bytes, bytearray)) else 0
            if vlen > 0:
                d[CKA_VALUE_LEN] = vlen
        elif key_type is not None and key_type in _FIXED_KEY_LEN:
            d[CKA_VALUE_LEN] = _FIXED_KEY_LEN[key_type]


# ---------------------------------------------------------------------------
# Public key completion
# ---------------------------------------------------------------------------

def _complete_public_key(d):
    """Fill in all common public-key attribute defaults (PKCS#11 Table 19)."""
    _default(d, CKA_SUBJECT,         b'')
    _default(d, CKA_ENCRYPT,         bool_attr(False))
    _default(d, CKA_VERIFY,          bool_attr(True))
    _default(d, CKA_VERIFY_RECOVER,  bool_attr(False))
    _default(d, CKA_WRAP,            bool_attr(False))
    _default(d, CKA_TRUSTED,         bool_attr(False))
    _default(d, CKA_WRAP_TEMPLATE,   b'')

    # Key-type-specific attributes
    key_type = _get_int(d, CKA_KEY_TYPE)
    if key_type == CKK_RSA:
        _complete_rsa_public_key(d)
    elif key_type == CKK_DSA:
        _complete_dsa_public_key(d)
    elif key_type == CKK_DH:
        _complete_dh_public_key(d)
    elif key_type == CKK_EC:
        _complete_ec_public_key(d)

    # CKA_PUBLIC_KEY_INFO: DER SubjectPublicKeyInfo (PKCS#11 v2.40 §4.9).
    # Derive from the key material already in d if not supplied by the caller.
    if CKA_PUBLIC_KEY_INFO not in d:
        spki = spki_from_attrs(d)
        if spki:
            d[CKA_PUBLIC_KEY_INFO] = spki


def _complete_rsa_public_key(d):
    """Derive CKA_MODULUS_BITS from CKA_MODULUS if absent."""
    if CKA_MODULUS_BITS not in d and CKA_MODULUS in d:
        mod = d[CKA_MODULUS]
        mbits = len(mod) * 8 if isinstance(mod, (bytes, bytearray)) else 0
        if mbits > 0:
            d[CKA_MODULUS_BITS] = mbits


def _complete_dsa_public_key(d):
    """DSA public key: CKA_PRIME, CKA_SUBPRIME, CKA_BASE, CKA_VALUE."""
    _default(d, CKA_PRIME,    b'')
    _default(d, CKA_SUBPRIME, b'')
    _default(d, CKA_BASE,     b'')
    _default(d, CKA_VALUE,    b'')


def _complete_dh_public_key(d):
    """DH public key: CKA_PRIME and CKA_BASE must be present."""
    _default(d, CKA_PRIME, b'')
    _default(d, CKA_BASE,  b'')
    _default(d, CKA_VALUE, b'')


def _complete_ec_public_key(d):
    """EC public key: CKA_EC_PARAMS and CKA_EC_POINT must be present."""
    # These are mandatory and have no default; just ensure they exist
    # if absent (keeps the store consistent; actual value is caller's job)
    _default(d, CKA_EC_PARAMS, b'')
    _default(d, CKA_EC_POINT,  b'')


# ---------------------------------------------------------------------------
# Private key completion
# ---------------------------------------------------------------------------

def _complete_private_key(d):
    """Fill in all common private-key attribute defaults (PKCS#11 Table 20)."""
    sensitive   = _get_bool(d, CKA_SENSITIVE,   True)
    extractable = _get_bool(d, CKA_EXTRACTABLE, False)

    _default(d, CKA_SUBJECT,           b'')
    _default(d, CKA_SENSITIVE,         bool_attr(True))
    _default(d, CKA_DECRYPT,           bool_attr(False))
    _default(d, CKA_SIGN,              bool_attr(False))
    _default(d, CKA_SIGN_RECOVER,      bool_attr(False))
    _default(d, CKA_UNWRAP,            bool_attr(False))
    _default(d, CKA_EXTRACTABLE,       bool_attr(False))
    _default(d, CKA_ALWAYS_SENSITIVE,  bool_attr(sensitive))
    _default(d, CKA_NEVER_EXTRACTABLE, bool_attr(not extractable))
    _default(d, CKA_WRAP_WITH_TRUSTED, bool_attr(False))
    _default(d, CKA_ALWAYS_AUTHENTICATE, bool_attr(False))
    _default(d, CKA_UNWRAP_TEMPLATE,   b'')
    _default(d, CKA_DERIVE_TEMPLATE,   b'')

    # Key-type-specific attributes
    key_type = _get_int(d, CKA_KEY_TYPE)
    if key_type == CKK_RSA:
        _complete_rsa_private_key(d)
    elif key_type == CKK_DSA:
        _complete_dsa_private_key(d)
    elif key_type == CKK_DH:
        _complete_dh_private_key(d)
    elif key_type == CKK_EC:
        _complete_ec_private_key(d)

    # CKA_PUBLIC_KEY_INFO: DER SubjectPublicKeyInfo (PKCS#11 v2.40 §4.8).
    # Derive from the public key material already in d if not supplied by caller.
    # For RSA and EC the public material is present on private key objects; for
    # DSA/DH a pub_value must have been injected by the key-pair builder first.
    if CKA_PUBLIC_KEY_INFO not in d:
        spki = spki_from_attrs(d)
        if spki:
            d[CKA_PUBLIC_KEY_INFO] = spki


def _complete_rsa_private_key(d):
    """RSA private key completion.

    CKA_MODULUS_BITS is intentionally NOT set on private key objects — real
    ICSF does not return it for private keys and p11sak expects it only on
    public key objects (the test counts exactly 3 occurrences across 3 public +
    3 private RSA key objects).
    """
    pass


def _complete_dsa_private_key(d):
    """DSA private key: CKA_PRIME, CKA_SUBPRIME, CKA_BASE, CKA_VALUE."""
    _default(d, CKA_PRIME,    b'')
    _default(d, CKA_SUBPRIME, b'')
    _default(d, CKA_BASE,     b'')
    _default(d, CKA_VALUE,    b'')


def _complete_dh_private_key(d):
    """DH private key: CKA_PRIME, CKA_BASE, CKA_VALUE, CKA_VALUE_BITS.

    CKA_VALUE_BITS holds the bit length of the private value and is stored
    only on the private key object (not on the public key).  Real ICSF sets
    it from the bit length of CKA_VALUE; p11sak sets it as a keygen template
    attribute and expects to read it back on the private key.
    """
    _default(d, CKA_PRIME, b'')
    _default(d, CKA_BASE,  b'')
    _default(d, CKA_VALUE, b'')
    # Derive CKA_VALUE_BITS from CKA_VALUE if not already present
    if CKA_VALUE_BITS not in d and CKA_VALUE in d:
        val = d[CKA_VALUE]
        vbits = len(val) * 8 if isinstance(val, (bytes, bytearray)) else 0
        if vbits > 0:
            d[CKA_VALUE_BITS] = vbits


def _complete_ec_private_key(d):
    """EC private key: CKA_EC_PARAMS must be present."""
    _default(d, CKA_EC_PARAMS, b'')


# ---------------------------------------------------------------------------
# Convenience: build a complete attribute list from scratch for key-gen ops
# ---------------------------------------------------------------------------

def make_secret_key_attrs(key_type, key_value, caller_attrs=None,
                          key_gen_mechanism=None):
    """
    Build a complete attribute list for a freshly generated secret key.

    Parameters
    ----------
    key_type        : int   — CKK_* constant
    key_value       : bytes — raw key material
    caller_attrs    : list of (int, bytes|int) or None — caller-supplied attrs
    key_gen_mechanism : int or None — CKM_* for the generating mechanism

    Returns
    -------
    list of (int, bytes|int)
    """
    base = list(caller_attrs) if caller_attrs else []
    # Ensure mandatory fields are set before completing
    base_dict = {t: v for t, v in base}
    if CKA_CLASS not in base_dict:
        base = [(CKA_CLASS, CKO_SECRET_KEY)] + base
    if CKA_KEY_TYPE not in base_dict:
        base = base + [(CKA_KEY_TYPE, key_type)]
    if CKA_VALUE not in base_dict:
        base = base + [(CKA_VALUE, key_value)]
    if key_gen_mechanism is None:
        key_gen_mechanism = _DEFAULT_GEN_MECH.get(key_type,
                                                   CKM_UNAVAILABLE_INFORMATION)
    return complete_key_attrs(base, key_gen_mechanism=key_gen_mechanism)


def make_rsa_keypair_attrs(pub_caller_attrs, priv_caller_attrs,
                           modulus, public_exponent,
                           key_gen_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN):
    """
    Build complete attribute lists for an RSA key pair.

    Returns (pub_attrs, priv_attrs).
    """
    # --- Public key ---
    pub_base = list(pub_caller_attrs)
    pub_dict = {t: v for t, v in pub_base}
    if CKA_CLASS not in pub_dict:
        pub_base = [(CKA_CLASS, CKO_PUBLIC_KEY)] + pub_base
    if CKA_KEY_TYPE not in pub_dict:
        pub_base = pub_base + [(CKA_KEY_TYPE, CKK_RSA)]
    if CKA_MODULUS not in pub_dict:
        pub_base = pub_base + [(CKA_MODULUS, modulus)]
    if CKA_PUBLIC_EXPONENT not in pub_dict:
        pub_base = pub_base + [(CKA_PUBLIC_EXPONENT, public_exponent)]
    # RSA public keys can encrypt and verify by default
    pub_dict2 = {t: v for t, v in pub_base}
    if CKA_ENCRYPT not in pub_dict2:
        pub_base = pub_base + [(CKA_ENCRYPT, bool_attr(True))]
    if CKA_VERIFY not in pub_dict2:
        pub_base = pub_base + [(CKA_VERIFY, bool_attr(True))]

    pub_attrs = complete_key_attrs(pub_base, key_gen_mechanism=key_gen_mechanism)

    # --- Private key ---
    priv_base = list(priv_caller_attrs)
    priv_dict = {t: v for t, v in priv_base}
    if CKA_CLASS not in priv_dict:
        priv_base = [(CKA_CLASS, CKO_PRIVATE_KEY)] + priv_base
    if CKA_KEY_TYPE not in priv_dict:
        priv_base = priv_base + [(CKA_KEY_TYPE, CKK_RSA)]
    if CKA_MODULUS not in priv_dict:
        priv_base = priv_base + [(CKA_MODULUS, modulus)]
    if CKA_PUBLIC_EXPONENT not in priv_dict:
        priv_base = priv_base + [(CKA_PUBLIC_EXPONENT, public_exponent)]
    # RSA private keys can decrypt and sign by default
    priv_dict2 = {t: v for t, v in priv_base}
    if CKA_DECRYPT not in priv_dict2:
        priv_base = priv_base + [(CKA_DECRYPT, bool_attr(True))]
    if CKA_SIGN not in priv_dict2:
        priv_base = priv_base + [(CKA_SIGN, bool_attr(True))]

    priv_attrs = complete_key_attrs(priv_base, key_gen_mechanism=key_gen_mechanism)

    return pub_attrs, priv_attrs


def make_ec_keypair_attrs(pub_caller_attrs, priv_caller_attrs,
                          ec_params, ec_point,
                          key_gen_mechanism=CKM_EC_KEY_PAIR_GEN):
    """
    Build complete attribute lists for an EC key pair.

    Returns (pub_attrs, priv_attrs).
    """
    # --- Public key ---
    pub_base = list(pub_caller_attrs)
    pub_dict = {t: v for t, v in pub_base}
    if CKA_CLASS not in pub_dict:
        pub_base = [(CKA_CLASS, CKO_PUBLIC_KEY)] + pub_base
    if CKA_KEY_TYPE not in pub_dict:
        pub_base = pub_base + [(CKA_KEY_TYPE, CKK_EC)]
    if CKA_EC_PARAMS not in pub_dict:
        pub_base = pub_base + [(CKA_EC_PARAMS, ec_params)]
    if CKA_EC_POINT not in pub_dict:
        pub_base = pub_base + [(CKA_EC_POINT, ec_point)]
    pub_dict2 = {t: v for t, v in pub_base}
    if CKA_VERIFY not in pub_dict2:
        pub_base = pub_base + [(CKA_VERIFY, bool_attr(True))]

    pub_attrs = complete_key_attrs(pub_base, key_gen_mechanism=key_gen_mechanism)

    # --- Private key ---
    priv_base = list(priv_caller_attrs)
    priv_dict = {t: v for t, v in priv_base}
    if CKA_CLASS not in priv_dict:
        priv_base = [(CKA_CLASS, CKO_PRIVATE_KEY)] + priv_base
    if CKA_KEY_TYPE not in priv_dict:
        priv_base = priv_base + [(CKA_KEY_TYPE, CKK_EC)]
    if CKA_EC_PARAMS not in priv_dict:
        priv_base = priv_base + [(CKA_EC_PARAMS, ec_params)]
    if CKA_EC_POINT not in priv_dict:
        priv_base = priv_base + [(CKA_EC_POINT, ec_point)]
    priv_dict2 = {t: v for t, v in priv_base}
    if CKA_SIGN not in priv_dict2:
        priv_base = priv_base + [(CKA_SIGN, bool_attr(True))]
    if CKA_DERIVE not in priv_dict2:
        priv_base = priv_base + [(CKA_DERIVE, bool_attr(True))]

    priv_attrs = complete_key_attrs(priv_base, key_gen_mechanism=key_gen_mechanism)

    return pub_attrs, priv_attrs


def make_dh_keypair_attrs(pub_caller_attrs, priv_caller_attrs,
                          prime, base, pub_value, priv_value,
                          key_gen_mechanism=CKM_DH_PKCS_KEY_PAIR_GEN):
    """
    Build complete attribute lists for a DH key pair.

    Returns (pub_attrs, priv_attrs).
    """
    # Pre-compute the SPKI once from the known public value so both the public
    # key object and the private key object receive CKA_PUBLIC_KEY_INFO.  DH
    # private key objects hold only the private exponent in CKA_VALUE, so
    # spki_from_attrs() cannot derive it automatically from the private key.
    dh_spki = None
    if prime and base and pub_value:
        try:
            dh_spki = spki_from_dh(prime, base, pub_value)
        except Exception as exc:
            logger.warning('make_dh_keypair_attrs: failed to build SPKI: %s', exc)

    # --- Public key ---
    pub_base = list(pub_caller_attrs)
    pub_dict = {t: v for t, v in pub_base}
    if CKA_CLASS not in pub_dict:
        pub_base = [(CKA_CLASS, CKO_PUBLIC_KEY)] + pub_base
    if CKA_KEY_TYPE not in pub_dict:
        pub_base = pub_base + [(CKA_KEY_TYPE, CKK_DH)]
    if CKA_PRIME not in pub_dict and prime:
        pub_base = pub_base + [(CKA_PRIME, prime)]
    if CKA_BASE not in pub_dict and base:
        pub_base = pub_base + [(CKA_BASE, base)]
    if CKA_VALUE not in pub_dict and pub_value:
        pub_base = pub_base + [(CKA_VALUE, pub_value)]
    # Inject pre-computed SPKI so complete_key_attrs does not need to re-derive
    pub_dict2 = {t: v for t, v in pub_base}
    if CKA_PUBLIC_KEY_INFO not in pub_dict2 and dh_spki:
        pub_base = pub_base + [(CKA_PUBLIC_KEY_INFO, dh_spki)]

    pub_attrs = complete_key_attrs(pub_base, key_gen_mechanism=key_gen_mechanism)

    # --- Private key ---
    priv_base = list(priv_caller_attrs)
    priv_dict = {t: v for t, v in priv_base}
    if CKA_CLASS not in priv_dict:
        priv_base = [(CKA_CLASS, CKO_PRIVATE_KEY)] + priv_base
    if CKA_KEY_TYPE not in priv_dict:
        priv_base = priv_base + [(CKA_KEY_TYPE, CKK_DH)]
    if CKA_PRIME not in priv_dict and prime:
        priv_base = priv_base + [(CKA_PRIME, prime)]
    if CKA_BASE not in priv_dict and base:
        priv_base = priv_base + [(CKA_BASE, base)]
    if CKA_VALUE not in priv_dict and priv_value:
        priv_base = priv_base + [(CKA_VALUE, priv_value)]
    priv_dict2 = {t: v for t, v in priv_base}
    if CKA_DERIVE not in priv_dict2:
        priv_base = priv_base + [(CKA_DERIVE, bool_attr(True))]
    # Inject pre-computed SPKI: private key CKA_VALUE is the private exponent,
    # not the public value, so spki_from_attrs cannot derive it automatically.
    priv_dict3 = {t: v for t, v in priv_base}
    if CKA_PUBLIC_KEY_INFO not in priv_dict3 and dh_spki:
        priv_base = priv_base + [(CKA_PUBLIC_KEY_INFO, dh_spki)]

    priv_attrs = complete_key_attrs(priv_base, key_gen_mechanism=key_gen_mechanism)

    return pub_attrs, priv_attrs


def make_dsa_keypair_attrs(pub_caller_attrs, priv_caller_attrs,
                           prime, subprime, base, pub_value, priv_value,
                           key_gen_mechanism=CKM_DSA_KEY_PAIR_GEN):
    """
    Build complete attribute lists for a DSA key pair.

    Returns (pub_attrs, priv_attrs).
    """
    # Pre-compute the SPKI once from the known public value so both the public
    # key object and the private key object receive CKA_PUBLIC_KEY_INFO.  DSA
    # private key objects hold only the private scalar x in CKA_VALUE (which
    # is subprime-sized), so spki_from_attrs() cannot derive it automatically.
    dsa_spki = None
    if prime and subprime and base and pub_value:
        try:
            dsa_spki = spki_from_dsa(prime, subprime, base, pub_value)
        except Exception as exc:
            logger.warning('make_dsa_keypair_attrs: failed to build SPKI: %s', exc)

    # --- Public key ---
    pub_base = list(pub_caller_attrs)
    pub_dict = {t: v for t, v in pub_base}
    if CKA_CLASS not in pub_dict:
        pub_base = [(CKA_CLASS, CKO_PUBLIC_KEY)] + pub_base
    if CKA_KEY_TYPE not in pub_dict:
        pub_base = pub_base + [(CKA_KEY_TYPE, CKK_DSA)]
    if CKA_PRIME not in pub_dict and prime:
        pub_base = pub_base + [(CKA_PRIME, prime)]
    if CKA_SUBPRIME not in pub_dict and subprime:
        pub_base = pub_base + [(CKA_SUBPRIME, subprime)]
    if CKA_BASE not in pub_dict and base:
        pub_base = pub_base + [(CKA_BASE, base)]
    if CKA_VALUE not in pub_dict and pub_value:
        pub_base = pub_base + [(CKA_VALUE, pub_value)]
    pub_dict2 = {t: v for t, v in pub_base}
    if CKA_VERIFY not in pub_dict2:
        pub_base = pub_base + [(CKA_VERIFY, bool_attr(True))]
    # Inject pre-computed SPKI so complete_key_attrs does not need to re-derive
    if CKA_PUBLIC_KEY_INFO not in pub_dict2 and dsa_spki:
        pub_base = pub_base + [(CKA_PUBLIC_KEY_INFO, dsa_spki)]

    pub_attrs = complete_key_attrs(pub_base, key_gen_mechanism=key_gen_mechanism)

    # --- Private key ---
    priv_base = list(priv_caller_attrs)
    priv_dict = {t: v for t, v in priv_base}
    if CKA_CLASS not in priv_dict:
        priv_base = [(CKA_CLASS, CKO_PRIVATE_KEY)] + priv_base
    if CKA_KEY_TYPE not in priv_dict:
        priv_base = priv_base + [(CKA_KEY_TYPE, CKK_DSA)]
    if CKA_PRIME not in priv_dict and prime:
        priv_base = priv_base + [(CKA_PRIME, prime)]
    if CKA_SUBPRIME not in priv_dict and subprime:
        priv_base = priv_base + [(CKA_SUBPRIME, subprime)]
    if CKA_BASE not in priv_dict and base:
        priv_base = priv_base + [(CKA_BASE, base)]
    if CKA_VALUE not in priv_dict and priv_value:
        priv_base = priv_base + [(CKA_VALUE, priv_value)]
    priv_dict2 = {t: v for t, v in priv_base}
    if CKA_SIGN not in priv_dict2:
        priv_base = priv_base + [(CKA_SIGN, bool_attr(True))]
    # Inject pre-computed SPKI: private key CKA_VALUE is the private scalar x,
    # not the public key y, so spki_from_attrs cannot derive it automatically.
    priv_dict3 = {t: v for t, v in priv_base}
    if CKA_PUBLIC_KEY_INFO not in priv_dict3 and dsa_spki:
        priv_base = priv_base + [(CKA_PUBLIC_KEY_INFO, dsa_spki)]

    priv_attrs = complete_key_attrs(priv_base, key_gen_mechanism=key_gen_mechanism)

    return pub_attrs, priv_attrs


# ---------------------------------------------------------------------------
# Certificate completion
# ---------------------------------------------------------------------------

def complete_cert_attrs(attrs):
    """
    Return a list of (attr_type, attr_value) with ALL PKCS#11-defined
    attributes for an X.509 certificate object (PKCS#11 Table 23), filling
    in defaults for anything missing from *attrs*.

    Caller-supplied values always take priority.
    """
    attr_dict = {}
    for t, v in attrs:
        attr_dict[t] = v

    # ----------------------------------------------------------------
    # Common object attributes (PKCS#11 Table 13)
    # ----------------------------------------------------------------
    _default(attr_dict, CKA_CLASS,       CKO_CERTIFICATE)
    _default(attr_dict, CKA_TOKEN,       bool_attr(False))
    _default(attr_dict, CKA_PRIVATE,     bool_attr(False))
    _default(attr_dict, CKA_MODIFIABLE,  bool_attr(True))
    _default(attr_dict, CKA_LABEL,       b'')
    _default(attr_dict, CKA_COPYABLE,    bool_attr(True))
    _default(attr_dict, CKA_DESTROYABLE, bool_attr(True))

    # ----------------------------------------------------------------
    # X.509 certificate attributes (PKCS#11 Table 23)
    # ----------------------------------------------------------------
    _default(attr_dict, CKA_CERTIFICATE_TYPE,    CKC_X_509)
    _default(attr_dict, CKA_TRUSTED,             bool_attr(False))
    # CKA_CERTIFICATE_CATEGORY: 0 = unspecified, 1 = token user, 2 = authority, 3 = other
    _default(attr_dict, CKA_CERTIFICATE_CATEGORY, 0)
    _default(attr_dict, CKA_CHECK_VALUE,          b'')
    _default(attr_dict, CKA_START_DATE,           b'')
    _default(attr_dict, CKA_END_DATE,             b'')
    _default(attr_dict, CKA_SUBJECT,              b'')
    _default(attr_dict, CKA_ID,                   b'')
    _default(attr_dict, CKA_ISSUER,               b'')
    _default(attr_dict, CKA_SERIAL_NUMBER,        b'')
    _default(attr_dict, CKA_VALUE,                b'')
    _default(attr_dict, CKA_URL,                  b'')
    _default(attr_dict, CKA_HASH_OF_SUBJECT_PUBLIC_KEY, b'')
    _default(attr_dict, CKA_HASH_OF_ISSUER_PUBLIC_KEY,  b'')
    # CKA_NAME_HASH_ALGORITHM defaults to SHA-1 per PKCS#11 spec
    _default(attr_dict, CKA_NAME_HASH_ALGORITHM,  CKM_SHA256)

    return [(t, v) for t, v in attr_dict.items()
            if not (isinstance(v, int) and v == CKM_UNAVAILABLE_INFORMATION)]


def make_x509_cert_attrs(der_value, caller_attrs=None):
    """
    Build a complete X.509 certificate attribute list.

    Parameters
    ----------
    der_value    : bytes — DER-encoded certificate (CKA_VALUE).
    caller_attrs : list of (int, bytes|int) or None — caller-supplied attrs.

    Returns
    -------
    list of (int, bytes|int)
    """
    base = list(caller_attrs) if caller_attrs else []
    base_dict = {t: v for t, v in base}
    if CKA_CLASS not in base_dict:
        base = [(CKA_CLASS, CKO_CERTIFICATE)] + base
    if CKA_VALUE not in base_dict:
        base = base + [(CKA_VALUE, der_value)]
    return complete_cert_attrs(base)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _default(d, attr_type, default_value):
    """Set attr_type in d only if it is not already present."""
    if attr_type not in d:
        d[attr_type] = default_value


def _get_int(d, attr_type):
    """Return integer value of attr_type, or None if absent."""
    v = d.get(attr_type)
    if v is None:
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, (bytes, bytearray)) and v:
        return int.from_bytes(v, 'big')
    return None


def _get_bool(d, attr_type, default=False):
    """Return boolean value of attr_type, or *default* if absent."""
    v = d.get(attr_type)
    if v is None:
        return default
    if isinstance(v, (bytes, bytearray)):
        return bool(v[0]) if v else default
    return bool(v)
