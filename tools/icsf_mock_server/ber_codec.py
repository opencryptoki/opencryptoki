# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
ber_codec.py — BER encode/decode for ICSF extended-operation payloads.

All ICSF services share a common request/response envelope described by the
ASN.1 in icsf.c.  This module re-implements *only* the subset needed to parse
what the openCryptoki ICSF token sends and to build matching responses.

Wire layout (DER/BER, same as OpenLDAP uses):

    requestValue ::= SEQUENCE {
        version         INTEGER,          -- always 1
        exitData        OCTET STRING,     -- ignored / ""
        handle          OCTET STRING,     -- 44 bytes
        ruleArraySeq    SEQUENCE {
            ruleArrayCount  INTEGER,
            ruleArray       OCTET STRING  -- N * 8-byte space-padded keywords
        },
        requestData     [tag] ...         -- context-constructed, tag = service
    }

    responseValue ::= SEQUENCE {
        version         INTEGER,
        ICSFRc          INTEGER,
        ICSFRsnCode     INTEGER,
        exitData        OCTET STRING,
        handle          OCTET STRING,     -- 44 bytes (updated by server)
        responseData    [tag] ...         -- context-constructed, tag = service
    }

Attribute list (used by TRC/TRL/GAV/SAV/GKP/GSK) follows this grammar:
    Attributes ::= SEQUENCE OF SEQUENCE {
        attrName    INTEGER,
        attrValue   CHOICE {
            charValue   [0] OCTET STRING,
            intValue    [1] INTEGER
        }
    }
"""

# ---------------------------------------------------------------------------
# BER tag constants (matching OpenLDAP lber.h values used by icsf.c)
# ---------------------------------------------------------------------------

LBER_BOOLEAN       = 0x01   # universal, primitive, BOOLEAN
LBER_INTEGER       = 0x02   # universal, primitive, INTEGER
LBER_OCTET_STRING  = 0x04   # universal, primitive, OCTET STRING
LBER_NULL          = 0x05
LBER_SEQUENCE      = 0x30   # universal, constructed, SEQUENCE

# Context class tags used by icsf.c
# context primitive  [n] = 0x80 | n
# context constructed[n] = 0xa0 | n
CTX_PRIM  = 0x80
CTX_CONS  = 0xa0

from pkcs11_const import NUMERIC_ATTR_TYPES as _NUMERIC_ATTR_TYPES

HANDLE_LEN      = 44
TOKEN_NAME_LEN  = 32
SEQ_LEN         = 8
RULE_ITEM_LEN   = 8


# ---------------------------------------------------------------------------
# Low-level BER primitives
# ---------------------------------------------------------------------------

def _encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    elif n <= 0xFF:
        return bytes([0x81, n])
    elif n <= 0xFFFF:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    elif n <= 0xFFFFFF:
        return bytes([0x83, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])
    else:
        return bytes([0x84,
                      (n >> 24) & 0xFF, (n >> 16) & 0xFF,
                      (n >> 8)  & 0xFF,  n         & 0xFF])


def _decode_length(data: bytes, pos: int):
    """Return (length, new_pos)."""
    b = data[pos]
    pos += 1
    if b < 0x80:
        return b, pos
    num_bytes = b & 0x7F
    length = 0
    for _ in range(num_bytes):
        length = (length << 8) | data[pos]
        pos += 1
    return length, pos


def _decode_tlv(data: bytes, pos: int):
    """Return (tag, value_bytes, new_pos)."""
    tag = data[pos]
    pos += 1
    # multi-byte tag (rare in ICSF but handle it)
    if (tag & 0x1F) == 0x1F:
        while data[pos] & 0x80:
            tag = (tag << 8) | data[pos]
            pos += 1
        tag = (tag << 8) | data[pos]
        pos += 1
    length, pos = _decode_length(data, pos)
    value = data[pos:pos + length]
    return tag, value, pos + length


def encode_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(value)) + value


def encode_integer(n: int) -> bytes:
    """Encode a non-negative integer as BER INTEGER."""
    if n == 0:
        return encode_tlv(LBER_INTEGER, b'\x00')
    out = []
    while n:
        out.append(n & 0xFF)
        n >>= 8
    out.reverse()
    # Prepend 0x00 if high bit set (keep it positive)
    if out[0] & 0x80:
        out.insert(0, 0x00)
    return encode_tlv(LBER_INTEGER, bytes(out))


def encode_boolean(val: bool) -> bytes:
    """Encode a BER BOOLEAN value."""
    return encode_tlv(LBER_BOOLEAN, b'\xff' if val else b'\x00')


def decode_boolean(data: bytes) -> bool:
    """Decode BER BOOLEAN bytes (the value portion only, no tag/length)."""
    if not data:
        return False
    return any(b != 0 for b in data)


def decode_integer(data: bytes) -> int:
    """Decode BER INTEGER bytes (the value portion only, no tag/length)."""
    if not data:
        return 0
    n = 0
    for b in data:
        n = (n << 8) | b
    return n


def encode_octet_string(b: bytes) -> bytes:
    return encode_tlv(LBER_OCTET_STRING, b)


def encode_sequence(contents: bytes) -> bytes:
    return encode_tlv(LBER_SEQUENCE, contents)


def encode_ctx_prim(tag_num: int, value: bytes) -> bytes:
    return encode_tlv(CTX_PRIM | tag_num, value)


def encode_ctx_cons(tag_num: int, contents: bytes) -> bytes:
    return encode_tlv(CTX_CONS | tag_num, contents)


# ---------------------------------------------------------------------------
# Handle helpers — must match object_record_to_handle() / token_name_to_handle()
# in icsf.c exactly.
# ---------------------------------------------------------------------------

def make_token_handle(token_name: str) -> bytes:
    """Build a 44-byte token handle from a token name."""
    name_bytes = token_name.encode('ascii', errors='replace')
    name_padded = name_bytes[:TOKEN_NAME_LEN].ljust(TOKEN_NAME_LEN, b' ')
    return name_padded + b' ' * (HANDLE_LEN - TOKEN_NAME_LEN)


def make_object_handle(token_name: str, sequence: int, obj_type: str) -> bytes:
    """Build a 44-byte object handle."""
    name_bytes = token_name.encode('ascii', errors='replace')
    name_padded = name_bytes[:TOKEN_NAME_LEN].ljust(TOKEN_NAME_LEN, b' ')
    hex_seq = ('%0*X' % (SEQ_LEN, sequence)).encode('ascii')
    rest = obj_type.encode('ascii') + b' ' * (HANDLE_LEN - TOKEN_NAME_LEN - SEQ_LEN - 1)
    return name_padded + hex_seq + rest


def parse_handle(handle: bytes):
    """
    Return (token_name, sequence, obj_type).
    For a token handle sequence==0 and obj_type==' '.
    """
    if len(handle) < HANDLE_LEN:
        handle = handle.ljust(HANDLE_LEN, b' ')
    token_name = handle[:TOKEN_NAME_LEN].rstrip(b' ').decode('ascii', errors='replace')
    hex_seq = handle[TOKEN_NAME_LEN:TOKEN_NAME_LEN + SEQ_LEN]
    obj_type_byte = handle[TOKEN_NAME_LEN + SEQ_LEN:TOKEN_NAME_LEN + SEQ_LEN + 1]
    try:
        sequence = int(hex_seq, 16)
    except ValueError:
        sequence = 0
    obj_type = obj_type_byte.decode('ascii', errors='replace')
    return token_name, sequence, obj_type


def parse_rule_array(data: bytes):
    """Return a list of stripped 8-byte rule-array keywords."""
    keywords = []
    for i in range(0, len(data), RULE_ITEM_LEN):
        kw = data[i:i + RULE_ITEM_LEN].rstrip(b' ').decode('ascii', errors='replace')
        if kw:
            keywords.append(kw)
    return keywords


# ---------------------------------------------------------------------------
# ICSF request envelope parser
# ---------------------------------------------------------------------------

class ICSFRequest:
    """Parsed ICSF extended-operation request."""

    def __init__(self):
        self.version      = 0
        self.exit_data    = b''
        self.handle       = b''
        self.rule_array   = []   # list of stripped keyword strings
        self.service_tag  = 0    # bare tag number (1..18)
        self.service_data = b''  # raw bytes of the context TLV value


def decode_request(raw: bytes) -> ICSFRequest:
    """
    Parse the BER value of an ICSF extended-op request.
    Raises ValueError on malformed input.
    """
    req = ICSFRequest()

    # Outer SEQUENCE
    tag, seq_val, _ = _decode_tlv(raw, 0)
    if tag != LBER_SEQUENCE:
        raise ValueError('Expected SEQUENCE, got 0x%02x' % tag)

    pos = 0

    # version INTEGER
    tag, val, pos = _decode_tlv(seq_val, pos)
    if tag != LBER_INTEGER:
        raise ValueError('Expected INTEGER for version')
    req.version = decode_integer(val)

    # exitData OCTET STRING
    tag, val, pos = _decode_tlv(seq_val, pos)
    if tag != LBER_OCTET_STRING:
        raise ValueError('Expected OCTET STRING for exitData')
    req.exit_data = val

    # handle OCTET STRING (44 bytes)
    tag, val, pos = _decode_tlv(seq_val, pos)
    if tag != LBER_OCTET_STRING:
        raise ValueError('Expected OCTET STRING for handle')
    req.handle = val

    # ruleArraySeq SEQUENCE { ruleArrayCount INTEGER, ruleArray OCTET STRING }
    tag, ra_seq, pos = _decode_tlv(seq_val, pos)
    if tag != LBER_SEQUENCE:
        raise ValueError('Expected SEQUENCE for ruleArraySeq')
    ra_pos = 0
    tag2, val2, ra_pos = _decode_tlv(ra_seq, ra_pos)
    if tag2 != LBER_INTEGER:
        raise ValueError('Expected INTEGER for ruleArrayCount')
    # ra_count = decode_integer(val2)  # not strictly needed
    tag2, ra_bytes, ra_pos = _decode_tlv(ra_seq, ra_pos)
    if tag2 != LBER_OCTET_STRING:
        raise ValueError('Expected OCTET STRING for ruleArray')
    req.rule_array = parse_rule_array(ra_bytes)

    # requestData [tag] context-constructed
    if pos < len(seq_val):
        svc_tag_raw = seq_val[pos]
        # The tag byte in lber: context | constructed | tag_number
        # icsf.c does:  tag |= LBER_CLASS_CONTEXT | LBER_CONSTRUCTED
        # That gives:   0xa0 | tag_number
        req.service_tag  = svc_tag_raw & 0x1F  # low 5 bits = tag number
        _, svc_val, _ = _decode_tlv(seq_val, pos)
        req.service_data = svc_val

    return req


# ---------------------------------------------------------------------------
# ICSF response envelope builder
# ---------------------------------------------------------------------------

def encode_response(handle: bytes, rc: int, reason: int,
                    service_tag: int, service_data: bytes) -> bytes:
    """
    Build the BER-encoded responseValue for an ICSF extended operation.

    handle       — 44-byte handle to echo back (updated by some services)
    rc           — ICSF return code (0=OK, 4=partial, 8=error, 12=fatal)
    reason       — ICSF reason code
    service_tag  — bare tag number matching the request
    service_data — BER payload for the service-specific response field
                   (the *contents* of the context TLV; may be b'')
    """
    version_bytes = encode_integer(1)
    rc_bytes      = encode_integer(rc)
    reason_bytes  = encode_integer(reason)
    exit_data     = encode_octet_string(b'')
    handle_bytes  = encode_octet_string(handle.ljust(HANDLE_LEN, b' ')[:HANDLE_LEN])

    # Context-constructed TLV for service response
    svc_tlv = encode_tlv(CTX_CONS | service_tag, service_data)

    inner = (version_bytes + rc_bytes + reason_bytes +
             exit_data + handle_bytes + svc_tlv)
    return encode_sequence(inner)


# ---------------------------------------------------------------------------
# Attribute list encode/decode (shared by TRC/GAV/SAV/GKP/GSK)
# ---------------------------------------------------------------------------


def encode_attribute_list(attrs: list) -> bytes:
    """
    Encode a list of (attr_type, attr_value) tuples into the wire format
    expected by icsf_ber_decode_get_attribute_list() in icsf.c.

    The C decoder uses ber_scanf(buf, "{{") to enter [service-TLV] then
    [GAVOutput SEQUENCE], and then loops calling ber_scanf(buf, "{it...}") to
    open each individual attribute item SEQUENCE.  Therefore the items must be
    placed DIRECTLY inside GAVOutput with NO intermediate wrapper SEQUENCE:

        GAVOutput ::= SEQUENCE {
            SEQUENCE { INTEGER attrName, [0] OCTET STRING | [1] INTEGER value }
            SEQUENCE { ... }
            ...
            INTEGER attrListLen
        }

    This function returns just the flat concatenation of item SEQUENCEs
    (no outer SEQUENCE wrapper).  The caller (gav.py) wraps the whole
    thing in encode_sequence() to form GAVOutput.
    """
    items = b''
    for attr_type, attr_value in attrs:
        type_bytes = encode_integer(attr_type)
        if attr_type in _NUMERIC_ATTR_TYPES or isinstance(attr_value, int):
            # intValue [1] INTEGER
            value_bytes = encode_tlv(CTX_PRIM | 1, _int_to_bytes(attr_value))
        else:
            # charValue [0] OCTET STRING
            if isinstance(attr_value, str):
                attr_value = attr_value.encode('ascii')
            value_bytes = encode_ctx_prim(0, attr_value)
        items += encode_sequence(type_bytes + value_bytes)
    return items   # flat — NO outer SEQUENCE wrapper


def decode_attribute_list(data: bytes) -> list:
    """
    Decode an attribute list (BER) as produced by icsf_ber_put_attribute_list().
    Returns list of (attr_type: int, attr_value: bytes|int).
    """
    attrs = []
    # Outer SEQUENCE
    tag, seq_val, _ = _decode_tlv(data, 0)
    if tag != LBER_SEQUENCE:
        raise ValueError('decode_attribute_list: expected SEQUENCE, got 0x%02x' % tag)

    pos = 0
    while pos < len(seq_val):
        tag, item_val, pos = _decode_tlv(seq_val, pos)
        if tag != LBER_SEQUENCE:
            break
        ipos = 0
        tag2, tval, ipos = _decode_tlv(item_val, ipos)
        attr_type = decode_integer(tval)
        tag2, vval, ipos = _decode_tlv(item_val, ipos)
        tag_num = tag2 & 0x1F
        if tag_num == 0:
            # charValue [0] OCTET STRING
            attrs.append((attr_type, vval))
        else:
            # intValue [1] INTEGER
            attrs.append((attr_type, decode_integer(vval)))
    return attrs


def _int_to_bytes(n: int) -> bytes:
    if n == 0:
        return b'\x00'
    out = []
    while n:
        out.append(n & 0xFF)
        n >>= 8
    out.reverse()
    if out[0] & 0x80:
        out.insert(0, 0x00)
    return bytes(out)


# ---------------------------------------------------------------------------
# PKCS#8 PrivateKeyInfo encode/decode for RSA and EC private keys
#
# RSA wire format (RFC 5958 / PKCS#8):
#
#   PrivateKeyInfo ::= SEQUENCE {
#     version     INTEGER (0),
#     algorithm   SEQUENCE { OID rsaEncryption (1.2.840.113549.1.1.1), NULL },
#     privateKey  OCTET STRING {
#       RSAPrivateKey ::= SEQUENCE {
#         version           INTEGER (0),
#         modulus           INTEGER,
#         publicExponent    INTEGER,
#         privateExponent   INTEGER,
#         prime1            INTEGER,
#         prime2            INTEGER,
#         exponent1         INTEGER,
#         exponent2         INTEGER,
#         coefficient       INTEGER
#       }
#     }
#   }
#
# EC wire format (RFC 5915 / PKCS#8):
#
#   PrivateKeyInfo ::= SEQUENCE {
#     version     INTEGER (0),
#     algorithm   SEQUENCE { OID id-ecPublicKey (1.2.840.10045.2.1),
#                            OID <curve OID> },
#     privateKey  OCTET STRING {
#       ECPrivateKey ::= SEQUENCE {
#         version     INTEGER (1),
#         privateKey  OCTET STRING (private scalar d),
#         [1] EXPLICIT BIT STRING 04||X||Y  (optional public point)
#       }
#     }
#   }
#
# The mock only generates modulus + publicExponent (no real private exponent or
# CRT components), so zeros are stored/used for the private fields when absent.
# On decode we recover whatever integers were packed so the object is restored
# with exactly the attributes that were encoded.
# ---------------------------------------------------------------------------

# rsaEncryption OID DER encoding: 1.2.840.113549.1.1.1
_OID_RSA = bytes.fromhex('06092a864886f70d010101')
_NULL    = b'\x05\x00'

# id-ecPublicKey OID DER encoding: 1.2.840.10045.2.1
_OID_EC  = bytes.fromhex('06072a8648ce3d0201')

# PKCS#11 attribute types used for RSA — kept local to avoid circular imports.
_CKA_MODULUS           = 0x00000120
_CKA_PUBLIC_EXPONENT   = 0x00000122
_CKA_PRIVATE_EXPONENT  = 0x00000123
_CKA_PRIME_1           = 0x00000124
_CKA_PRIME_2           = 0x00000125
_CKA_EXPONENT_1        = 0x00000126
_CKA_EXPONENT_2        = 0x00000127
_CKA_COEFFICIENT       = 0x00000128


def _encode_ber_integer(b: bytes) -> bytes:
    """Encode raw big-endian bytes as a BER INTEGER (prepend 0x00 if high bit set)."""
    if not b or b == b'\x00':
        return encode_tlv(LBER_INTEGER, b'\x00')
    # Strip leading zero bytes, but keep at least one
    b = b.lstrip(b'\x00') or b'\x00'
    if b[0] & 0x80:
        b = b'\x00' + b
    return encode_tlv(LBER_INTEGER, b)


def _decode_ber_integer_value(data: bytes, pos: int):
    """
    Read one BER INTEGER TLV at pos.
    Returns (value_bytes_unsigned, new_pos).
    value_bytes_unsigned has leading 0x00 stripped.
    """
    tag, val, pos = _decode_tlv(data, pos)
    if tag != LBER_INTEGER:
        raise ValueError('Expected INTEGER tag 0x02, got 0x%02x' % tag)
    # Strip the sign byte (0x00 prepended for positive numbers)
    v = val.lstrip(b'\x00') or b'\x00'
    return v, pos


def rsa_attrs_to_pkcs8(attr_dict: dict) -> bytes:
    """
    Encode an RSA private key stored in a PKCS#11 attribute dict as a
    PKCS#8 PrivateKeyInfo DER blob.

    attr_dict maps CKA_* integer types to bytes values.
    Missing private-key fields default to a single zero byte.
    """
    def _get(cka):
        v = attr_dict.get(cka, b'\x00')
        if isinstance(v, int):
            return _int_to_bytes(v)
        return v if v else b'\x00'

    rsa_priv = encode_sequence(
        _encode_ber_integer(b'\x00') +              # version = 0
        _encode_ber_integer(_get(_CKA_MODULUS)) +
        _encode_ber_integer(_get(_CKA_PUBLIC_EXPONENT)) +
        _encode_ber_integer(_get(_CKA_PRIVATE_EXPONENT)) +
        _encode_ber_integer(_get(_CKA_PRIME_1)) +
        _encode_ber_integer(_get(_CKA_PRIME_2)) +
        _encode_ber_integer(_get(_CKA_EXPONENT_1)) +
        _encode_ber_integer(_get(_CKA_EXPONENT_2)) +
        _encode_ber_integer(_get(_CKA_COEFFICIENT))
    )

    alg_id = encode_sequence(_OID_RSA + _NULL)

    pkcs8 = encode_sequence(
        _encode_ber_integer(b'\x00') +   # version = 0
        alg_id +
        encode_tlv(LBER_OCTET_STRING, rsa_priv)
    )
    return pkcs8


def pkcs8_to_rsa_attrs(pkcs8: bytes) -> dict:
    """
    Decode a PKCS#8 PrivateKeyInfo DER blob and return a dict mapping
    CKA_* types to bytes values for the RSA components.

    Returns keys: CKA_MODULUS, CKA_PUBLIC_EXPONENT, CKA_PRIVATE_EXPONENT,
                  CKA_PRIME_1, CKA_PRIME_2, CKA_EXPONENT_1, CKA_EXPONENT_2,
                  CKA_COEFFICIENT  (omitted if zero / absent).
    """
    # Outer PrivateKeyInfo SEQUENCE
    tag, outer, _ = _decode_tlv(pkcs8, 0)
    if tag != LBER_SEQUENCE:
        raise ValueError('PKCS#8: expected outer SEQUENCE, got 0x%02x' % tag)

    pos = 0
    # version INTEGER
    _, pos = _decode_ber_integer_value(outer, pos)
    # AlgorithmIdentifier SEQUENCE — skip it
    tag, _, pos = _decode_tlv(outer, pos)
    # privateKey OCTET STRING
    tag, priv_key_bytes, pos = _decode_tlv(outer, pos)
    if tag != LBER_OCTET_STRING:
        raise ValueError('PKCS#8: expected OCTET STRING for privateKey')

    # RSAPrivateKey SEQUENCE inside the OCTET STRING
    tag, rsa_seq, _ = _decode_tlv(priv_key_bytes, 0)
    if tag != LBER_SEQUENCE:
        raise ValueError('PKCS#8: expected RSAPrivateKey SEQUENCE')

    rpos = 0
    # version
    _, rpos = _decode_ber_integer_value(rsa_seq, rpos)

    result = {}
    fields = [
        _CKA_MODULUS, _CKA_PUBLIC_EXPONENT, _CKA_PRIVATE_EXPONENT,
        _CKA_PRIME_1, _CKA_PRIME_2,
        _CKA_EXPONENT_1, _CKA_EXPONENT_2, _CKA_COEFFICIENT,
    ]
    for cka in fields:
        v, rpos = _decode_ber_integer_value(rsa_seq, rpos)
        # Only store non-zero values (zero means "absent / mock placeholder")
        if v and v != b'\x00':
            result[cka] = v

    return result


# ---------------------------------------------------------------------------
# PKCS#11 attribute types used for EC — kept local to avoid circular imports.
# ---------------------------------------------------------------------------
_CKA_EC_PARAMS = 0x00000180
_CKA_EC_POINT  = 0x00000181
# CKA_VALUE (0x11) is already the private scalar for EC keys.
_CKA_VALUE     = 0x00000011


def ec_attrs_to_pkcs8(attr_dict: dict) -> bytes:
    """
    Encode an EC private key stored in a PKCS#11 attribute dict as a
    PKCS#8 PrivateKeyInfo DER blob (RFC 5958 / RFC 5915).

    attr_dict maps CKA_* integer types to bytes values.
    Required: CKA_EC_PARAMS (curve OID DER), CKA_VALUE (private scalar).
    Optional: CKA_EC_POINT (DER-OCTET-STRING-wrapped 04||X||Y public point).

    The ECPrivateKey (RFC 5915) inner structure:
        SEQUENCE {
            version    INTEGER (1),
            privateKey OCTET STRING (scalar d),
            [1] EXPLICIT BIT STRING (04||X||Y)  -- included if CKA_EC_POINT present
        }
    The AlgorithmIdentifier uses id-ecPublicKey (1.2.840.10045.2.1) with the
    curve OID as the parameter (the raw CKA_EC_PARAMS bytes, which are already
    a DER-encoded OID).
    """
    ec_params = attr_dict.get(_CKA_EC_PARAMS, b'')
    ec_value  = attr_dict.get(_CKA_VALUE, b'')
    ec_point  = attr_dict.get(_CKA_EC_POINT, b'')

    # ECPrivateKey inner SEQUENCE (RFC 5915)
    inner = (
        _encode_ber_integer(b'\x01') +           # version = 1
        encode_tlv(LBER_OCTET_STRING, ec_value)  # privateKey OCTET STRING
    )

    # [1] EXPLICIT BIT STRING containing the uncompressed public point.
    # CKA_EC_POINT is stored as a DER OCTET STRING wrapping 04||X||Y; unwrap it.
    if ec_point:
        raw_point = _unwrap_pkcs11_ec_point(ec_point)
        if raw_point:
            # BIT STRING: one leading byte 0x00 (zero unused bits) + point bytes
            bit_string_val = b'\x00' + raw_point
            # [1] EXPLICIT — context constructed tag 0xa1
            inner += encode_tlv(0xa1, encode_tlv(0x03, bit_string_val))

    ec_priv_key_inner = encode_sequence(inner)

    # AlgorithmIdentifier: { id-ecPublicKey, curve-OID }
    alg_id = encode_sequence(_OID_EC + ec_params)

    pkcs8 = encode_sequence(
        _encode_ber_integer(b'\x00') +                    # version = 0
        alg_id +
        encode_tlv(LBER_OCTET_STRING, ec_priv_key_inner)  # privateKey
    )
    return pkcs8


def pkcs8_to_ec_attrs(pkcs8: bytes) -> dict:
    """
    Decode a PKCS#8 PrivateKeyInfo DER blob for an EC private key and return
    a dict mapping CKA_* types to bytes values.

    Returns keys: CKA_EC_PARAMS, CKA_VALUE (private scalar).
    Also returns CKA_EC_POINT (DER-OCTET-STRING-wrapped 04||X||Y) if the
    optional public-key field was included in the ECPrivateKey structure.
    """
    # Outer PrivateKeyInfo SEQUENCE
    tag, outer, _ = _decode_tlv(pkcs8, 0)
    if tag != LBER_SEQUENCE:
        raise ValueError('PKCS#8/EC: expected outer SEQUENCE, got 0x%02x' % tag)

    pos = 0
    # version INTEGER — must be 0
    _, pos = _decode_ber_integer_value(outer, pos)

    # AlgorithmIdentifier SEQUENCE: { id-ecPublicKey OID, curve-OID }
    tag, alg_seq, pos = _decode_tlv(outer, pos)
    if tag != LBER_SEQUENCE:
        raise ValueError('PKCS#8/EC: expected AlgorithmIdentifier SEQUENCE')
    apos = 0
    # id-ecPublicKey OID — skip it
    tag, _, apos = _decode_tlv(alg_seq, apos)
    # Curve OID — this is CKA_EC_PARAMS
    tag, ec_params, apos = _decode_tlv(alg_seq, apos)
    # Re-encode with its tag so we get the full DER OID TLV
    ec_params_der = encode_tlv(tag, ec_params)

    # privateKey OCTET STRING (contains ECPrivateKey DER)
    tag, priv_key_bytes, pos = _decode_tlv(outer, pos)
    if tag != LBER_OCTET_STRING:
        raise ValueError('PKCS#8/EC: expected OCTET STRING for privateKey')

    # ECPrivateKey SEQUENCE (RFC 5915)
    tag, ec_seq, _ = _decode_tlv(priv_key_bytes, 0)
    if tag != LBER_SEQUENCE:
        raise ValueError('PKCS#8/EC: expected ECPrivateKey SEQUENCE')

    epos = 0
    # version INTEGER (1)
    _, epos = _decode_ber_integer_value(ec_seq, epos)
    # privateKey OCTET STRING (scalar d)
    tag, ec_value, epos = _decode_tlv(ec_seq, epos)
    if tag != LBER_OCTET_STRING:
        raise ValueError('PKCS#8/EC: expected OCTET STRING for private scalar')

    result = {
        _CKA_EC_PARAMS: ec_params_der,
        _CKA_VALUE:     ec_value,
    }

    # [1] EXPLICIT public point (optional)
    if epos < len(ec_seq):
        tag, ctx_val, epos = _decode_tlv(ec_seq, epos)
        if (tag & 0xe0) == 0xa0 and (tag & 0x1f) == 1:
            # [1] EXPLICIT — content is a BIT STRING
            bpos = 0
            tag2, bs_val, bpos = _decode_tlv(ctx_val, bpos)
            if tag2 == 0x03 and bs_val:
                # Strip the leading "unused bits" byte (always 0x00)
                raw_point = bs_val[1:] if bs_val[0:1] == b'\x00' else bs_val
                # Wrap as PKCS#11 DER OCTET STRING for CKA_EC_POINT storage
                result[_CKA_EC_POINT] = _wrap_pkcs11_ec_point(raw_point)

    return result


def pkcs8_get_alg_oid(pkcs8: bytes) -> bytes:
    """
    Return the AlgorithmIdentifier OID bytes from a PKCS#8 blob (the value
    portion only, without the tag/length).  Used to dispatch RSA vs EC.

    Returns b'' on any parse error.
    """
    try:
        tag, outer, _ = _decode_tlv(pkcs8, 0)
        if tag != LBER_SEQUENCE:
            return b''
        pos = 0
        # version
        _, pos = _decode_ber_integer_value(outer, pos)
        # AlgorithmIdentifier SEQUENCE
        tag, alg_seq, pos = _decode_tlv(outer, pos)
        if tag != LBER_SEQUENCE:
            return b''
        # First element is the algorithm OID — return just the value bytes
        tag2, oid_val, _ = _decode_tlv(alg_seq, 0)
        if tag2 != 0x06:   # OID tag
            return b''
        return oid_val
    except Exception:
        return b''


# ---------------------------------------------------------------------------
# CKA_EC_POINT DER-OCTET-STRING wrap/unwrap helpers
# (kept local so ber_codec has no dependency on ec_backend)
# ---------------------------------------------------------------------------

def _unwrap_pkcs11_ec_point(ec_point: bytes) -> bytes:
    """
    Strip the outer DER OCTET STRING tag+length from a CKA_EC_POINT value,
    returning the raw 04||X||Y bytes.  If the value is already raw, return
    it unchanged.
    """
    if not ec_point or ec_point[0] != 0x04 or len(ec_point) < 2:
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


def _wrap_pkcs11_ec_point(raw_point: bytes) -> bytes:
    """
    Wrap raw 04||X||Y bytes in a DER OCTET STRING for CKA_EC_POINT storage.
    """
    n = len(raw_point)
    if n < 0x80:
        length = bytes([n])
    elif n <= 0xFF:
        length = bytes([0x81, n])
    else:
        length = bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    return b'\x04' + length + raw_point
