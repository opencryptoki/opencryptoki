# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
handlers/dvk.py — CSFPDVK: Derive Key (service tag 2).

Implements the EC-DH (CKM_ECDH1_DERIVE) and SSL-MS (CKM_SSL3_MASTER_KEY_DERIVE) variants.

Request wire format (from icsf_derive_key() in icsf.c):

    DVKInput ::= SEQUENCE {
        attrList        Attributes,         -- written by icsf_ber_put_attribute_list
        parmsListChoice DVKInputParmsList
    }

    DVKInputParmsList ::= CHOICE {
       PKCS-DH_publicValue  [0] OCTET STRING,
       SSL-TLS              [1] SSL-TLS_DVKInputParmsList,
       EC-DH                [2] EC-DH_DVKInputParmsList
    }

    SSL-TLS_DVKInputParmsList ::= SEQUENCE {
       clientRandomData    OCTET STRING,
       serverRandomData    OCTET STRING
    }

    EC-DH_DVKInputParmsList ::= SEQUENCE {
       kdfCode             OCTET STRING,    -- 1 byte: truncated CK_EC_KDF_TYPE value
       sharedData          OCTET STRING,    -- optional shared data (may be empty)
       publicValue         OCTET STRING     -- peer's uncompressed EC point 04||X||Y
    }

    Rule array: "EC-DH   " | "SSL-MS  " (8-byte padded keyword)
    Handle:     44-byte handle of the base key

Note on kdfCode encoding
    In icsf.c the kdf is truncated to CK_BYTE before being sent:
        CK_BYTE kdf = ecdh_params->kdf;
        kdfCode.bv_val = (char *)&kdf;
        kdfCode.bv_len = sizeof(kdf);   // 1 byte
    The PKCS#11 CKD_* constants are small integers (1..8) so the wire
    value is the same as the low byte of the PKCS#11 CKD_* constant.

Response:
    The derived key handle is returned in the common header handle field.
    Service data for EC-DH is empty (DVKOutputParmsList CHOICE [2] NULL).

Supported KDFs (matching ICSF z/OS documentation)
---------------------------------------------------
CKD_NULL     (0x01) — key = Z[:key_len]  (pad right with zeros if Z too short)
CKD_SHA1_KDF (0x02) — X9.63 with SHA-1
CKD_SHA224_KDF (0x05) — X9.63 with SHA-224
CKD_SHA256_KDF (0x06) — X9.63 with SHA-256
CKD_SHA384_KDF (0x07) — X9.63 with SHA-384
CKD_SHA512_KDF (0x08) — X9.63 with SHA-512

X9.63 KDF algorithm (matching mech_ec.c ckm_kdf_X9_63):
    For counter = 1, 2, ... until enough bytes produced:
        chunk_i = Hash(Z || be32(counter) || sharedData)
    key = concat(chunk_1, chunk_2, ...)[:key_len]
"""

import hashlib
import logging
import struct

from ber_codec import (
    encode_response, make_object_handle, parse_handle,
    decode_attribute_list, encode_sequence, encode_octet_string,
    _decode_tlv,
)
from token_store import OBJ_TYPE_TOKEN
from pkcs11_const import (
    CKA_VALUE, CKA_KEY_TYPE, CKA_VALUE_LEN, CKA_TOKEN, CKA_EC_PARAMS,
    CKA_PRIME, CKA_BASE,
    CKK_AES, CKK_DES, CKK_DES2, CKK_DES3, CKK_GENERIC_SECRET,
    CKM_AES_KEY_GEN, CKM_DES_KEY_GEN, CKM_DES2_KEY_GEN, CKM_DES3_KEY_GEN,
    CKM_GENERIC_SECRET_KEY_GEN,
    CKM_DH_PKCS_DERIVE,
    CKM_SSL3_MASTER_KEY_DERIVE,
)
from obj_attrs import make_secret_key_attrs
from ec_backend import ec_ecdh_derive, decode_ec_public_value
from dh_backend import dh_derive

logger = logging.getLogger(__name__)

ICSF_TAG_CSFPDVK = 2

RC_SUCCESS          = 0
RC_ERROR            = 8
RSN_TOKEN_NOT_FOUND = 3024
RSN_OBJ_NOT_FOUND   = 3025
RSN_MECH_INVALID    = 2116

# ---------------------------------------------------------------------------
# CKD_* wire values (low byte of PKCS#11 CK_EC_KDF_TYPE, as sent by icsf.c)
# Only the six values supported by ICSF z/OS are listed.
# ---------------------------------------------------------------------------
CKD_NULL       = 0x01
CKD_SHA1_KDF   = 0x02
CKD_SHA224_KDF = 0x05
CKD_SHA256_KDF = 0x06
CKD_SHA384_KDF = 0x07
CKD_SHA512_KDF = 0x08

# Map CKD wire value → hashlib algorithm name
_KDF_HASH = {
    CKD_SHA1_KDF:   'sha1',
    CKD_SHA224_KDF: 'sha224',
    CKD_SHA256_KDF: 'sha256',
    CKD_SHA384_KDF: 'sha384',
    CKD_SHA512_KDF: 'sha512',
}

# Default key sizes when CKA_VALUE_LEN is absent
_DEFAULT_KEY_LEN = {
    CKK_AES:  32,
    CKK_DES:  8,
    CKK_DES2: 16,
    CKK_DES3: 24,
}

# Mechanism used for each key type during derivation
_GEN_MECH = {
    CKK_AES:  CKM_AES_KEY_GEN,
    CKK_DES:  CKM_DES_KEY_GEN,
    CKK_DES2: CKM_DES2_KEY_GEN,
    CKK_DES3: CKM_DES3_KEY_GEN,
}


# ---------------------------------------------------------------------------
# KDF implementation
# ---------------------------------------------------------------------------

def _apply_kdf(kdf_code, z, shared_data, key_len):
    """Apply the ICSF KDF to ECDH shared secret Z.

    Parameters
    ----------
    kdf_code    : int   — wire CKD_* value (1 byte)
    z           : bytes — raw ECDH shared secret
    shared_data : bytes — optional shared info (may be b'')
    key_len     : int   — desired output length in bytes

    Returns
    -------
    bytes of length key_len

    Raises
    ------
    ValueError if kdf_code is not one of the six supported values.
    """
    if kdf_code == CKD_NULL:
        # No KDF: use leftmost bytes of Z, zero-pad on right if too short
        if len(z) >= key_len:
            return z[:key_len]
        return z + b'\x00' * (key_len - len(z))

    hash_name = _KDF_HASH.get(kdf_code)
    if hash_name is None:
        raise ValueError('unsupported KDF code 0x%02x' % kdf_code)

    # ANSI X9.63 KDF (ckm_kdf_X9_63 in mech_ec.c):
    #   chunk_i = Hash(Z || be32(counter) || sharedData),  counter = 1, 2, ...
    out = b''
    counter = 1
    while len(out) < key_len:
        msg = z + struct.pack('>I', counter) + shared_data
        out += hashlib.new(hash_name, msg).digest()
        counter += 1
    return out[:key_len]


# ---------------------------------------------------------------------------
# SSL 3.0 Master Key Derivation
# ---------------------------------------------------------------------------

def _ssl3_sha_then_md5(secret: bytes, client_random: bytes,
                       server_random: bytes, var_data: bytes) -> bytes:
    """
    MD5(secret || SHA-1(var_data || secret || client_random || server_random))
    """
    sha1_ctx = hashlib.sha1()
    sha1_ctx.update(var_data)
    sha1_ctx.update(secret)
    sha1_ctx.update(client_random)
    sha1_ctx.update(server_random)
    sha1_digest = sha1_ctx.digest()

    md5_ctx = hashlib.md5()
    md5_ctx.update(secret)
    md5_ctx.update(sha1_digest)
    return md5_ctx.digest()


def _ssl3_master_key_derive(pre_master_secret: bytes,
                            client_random: bytes,
                            server_random: bytes) -> bytes:
    """
    Derive the 48-byte SSL 3.0 master secret from pre-master secret.
    """
    block1 = _ssl3_sha_then_md5(pre_master_secret, client_random, server_random, b'A')
    block2 = _ssl3_sha_then_md5(pre_master_secret, client_random, server_random, b'BB')
    block3 = _ssl3_sha_then_md5(pre_master_secret, client_random, server_random, b'CCC')
    return block1 + block2 + block3


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

def handle_dvk(store, request):
    """
    Process a CSFPDVK request.

    Parameters
    ----------
    store   : TokenStore
    request : ICSFRequest

    Returns
    -------
    bytes — raw BER responseValue
    """
    token_name, sequence, _ = parse_handle(request.handle)
    if not token_name or sequence == 0:
        logger.error('DVK: invalid handle (token=%r seq=%d)', token_name, sequence)
        return encode_response(
            request.handle, RC_ERROR, 3001, ICSF_TAG_CSFPDVK, b'')

    rules = [r.upper() for r in request.rule_array]

    # Locate the base key object
    base_obj = store.get_object(token_name, sequence)
    if base_obj is None:
        logger.warning('DVK: base key not found token=%r seq=%d',
                       token_name, sequence)
        return encode_response(
            request.handle, RC_ERROR, RSN_OBJ_NOT_FOUND, ICSF_TAG_CSFPDVK, b'')

    base_attrs = {t: v for t, v in base_obj.get_all_attrs()}

    # -----------------------------------------------------------------------
    # EC-DH Derivation
    # -----------------------------------------------------------------------
    if 'EC-DH' in rules:
        derived_attrs = []
        kdf_code     = CKD_NULL
        shared_data  = b''
        public_value = b''

        try:
            pos = 0
            # Attribute list SEQUENCE
            tag, attr_seq_val, pos = _decode_tlv(request.service_data, pos)
            derived_attrs = decode_attribute_list(encode_sequence(attr_seq_val))

            # EC-DH parms: context-constructed [2] SEQUENCE (tag = 0xa2)
            if pos < len(request.service_data):
                tag, ec_seq_val, pos = _decode_tlv(request.service_data, pos)
                epos = 0
                tag2, kdf_bytes,    epos = _decode_tlv(ec_seq_val, epos)
                tag2, shared_data,  epos = _decode_tlv(ec_seq_val, epos)
                tag2, public_value, epos = _decode_tlv(ec_seq_val, epos)
                # kdf is 1 byte for values <= 0xFF, 4-byte big-endian for larger
                kdf_code = int.from_bytes(kdf_bytes, 'big') if kdf_bytes else CKD_NULL
        except Exception as exc:
            logger.warning('DVK: failed to decode DVKInput: %s', exc)
            return encode_response(
                request.handle, RC_ERROR, 3002, ICSF_TAG_CSFPDVK, b'')

        if not public_value:
            logger.error('DVK: missing EC-DH public value in request')
            return encode_response(
                request.handle, RC_ERROR, 3002, ICSF_TAG_CSFPDVK, b'')

        # Compute ECDH shared secret Z = d_local * Q_peer
        ec_params = base_attrs.get(CKA_EC_PARAMS, b'')
        try:
            raw_pub = decode_ec_public_value(public_value, ec_params)
            z = ec_ecdh_derive(base_attrs, raw_pub)
        except Exception as exc:
            logger.error('DVK: ECDH derivation failed: %s', exc)
            return encode_response(
                request.handle, RC_ERROR, RC_ERROR, ICSF_TAG_CSFPDVK, b'')

        derived_dict = {t: v for t, v in derived_attrs}

        key_type = derived_dict.get(CKA_KEY_TYPE)
        if isinstance(key_type, bytes):
            key_type = int.from_bytes(key_type, 'big')
        if key_type is None:
            key_type = CKK_AES

        value_len = derived_dict.get(CKA_VALUE_LEN)
        if isinstance(value_len, bytes):
            value_len = int.from_bytes(value_len, 'big')
        if not value_len:
            value_len = _DEFAULT_KEY_LEN.get(key_type, len(z))

        try:
            key_bytes = _apply_kdf(kdf_code, z, shared_data, value_len)
        except ValueError as exc:
            logger.warning('DVK: %s', exc)
            return encode_response(
                request.handle, RC_ERROR, RSN_MECH_INVALID, ICSF_TAG_CSFPDVK, b'')

        cka_token = derived_dict.get(CKA_TOKEN, b'\x00')
        is_token = bool(cka_token[0] if isinstance(cka_token, bytes) else cka_token)
        obj_type = OBJ_TYPE_TOKEN if is_token else 'S'

        gen_mech = _GEN_MECH.get(key_type, CKM_GENERIC_SECRET_KEY_GEN)
        caller_attrs = [(t, v) for t, v in derived_attrs if t != CKA_VALUE_LEN]

        final_attrs = make_secret_key_attrs(
            key_type=key_type,
            key_value=key_bytes,
            caller_attrs=caller_attrs,
            key_gen_mechanism=gen_mech,
        )

        obj = store.create_object(token_name, obj_type, final_attrs)
        if obj is None:
            logger.error('DVK: failed to create derived key in token %r', token_name)
            return encode_response(
                request.handle, RC_ERROR, RSN_TOKEN_NOT_FOUND, ICSF_TAG_CSFPDVK, b'')

        new_handle = make_object_handle(token_name, obj.sequence, obj_type)
        logger.info('DVK: EC-DH token=%r base_seq=%d derived_seq=%d '
                    'key_type=0x%x len=%d kdf=0x%02x shared_data=%d',
                    token_name, sequence, obj.sequence,
                    key_type, value_len, kdf_code, len(shared_data))

        return encode_response(new_handle, RC_SUCCESS, 0, ICSF_TAG_CSFPDVK, b'')

    # -----------------------------------------------------------------------
    # PKCS-DH Derivation
    # -----------------------------------------------------------------------
    if 'PKCS-DH' in rules:
        derived_attrs = []
        peer_public_value = b''

        try:
            pos = 0
            # Attribute list SEQUENCE
            tag, attr_seq_val, pos = _decode_tlv(request.service_data, pos)
            derived_attrs = decode_attribute_list(encode_sequence(attr_seq_val))

            # PKCS-DH parms: context-primitive [0] OCTET STRING (tag = 0x80)
            if pos < len(request.service_data):
                tag, peer_public_value, pos = _decode_tlv(request.service_data, pos)
        except Exception as exc:
            logger.warning('DVK: failed to decode DVKInput for PKCS-DH: %s', exc)
            return encode_response(
                request.handle, RC_ERROR, 3002, ICSF_TAG_CSFPDVK, b'')

        if not peer_public_value:
            logger.error('DVK: missing PKCS-DH public value in request')
            return encode_response(
                request.handle, RC_ERROR, 3002, ICSF_TAG_CSFPDVK, b'')

        prime_bytes = base_attrs.get(CKA_PRIME, b'')
        priv_bytes  = base_attrs.get(CKA_VALUE, b'')
        if not prime_bytes or not priv_bytes:
            logger.error('DVK: PKCS-DH base key missing CKA_PRIME or CKA_VALUE')
            return encode_response(
                request.handle, RC_ERROR, 3002, ICSF_TAG_CSFPDVK, b'')

        try:
            z_bytes = dh_derive(base_attrs, peer_public_value)
        except Exception as exc:
            logger.warning('DVK: OpenSSL dh_derive failed (%s), falling back to python pow', exc)
            prime_int = int.from_bytes(prime_bytes, 'big')
            priv_int  = int.from_bytes(priv_bytes, 'big')
            peer_pub_int = int.from_bytes(peer_public_value, 'big')
            z_int = pow(peer_pub_int, priv_int, prime_int)
            z_bytes = z_int.to_bytes(len(prime_bytes), 'big')

        derived_dict = {t: v for t, v in derived_attrs}
        key_type = derived_dict.get(CKA_KEY_TYPE)
        if isinstance(key_type, bytes):
            key_type = int.from_bytes(key_type, 'big')
        if key_type is None:
            key_type = CKK_GENERIC_SECRET

        value_len = derived_dict.get(CKA_VALUE_LEN)
        if isinstance(value_len, bytes):
            value_len = int.from_bytes(value_len, 'big')
        if not value_len:
            value_len = _DEFAULT_KEY_LEN.get(key_type, len(z_bytes))

        # Truncate or zero-pad if necessary
        if len(z_bytes) >= value_len:
            key_bytes = z_bytes[:value_len]
        else:
            key_bytes = z_bytes + b'\x00' * (value_len - len(z_bytes))

        cka_token = derived_dict.get(CKA_TOKEN, b'\x00')
        is_token = bool(cka_token[0] if isinstance(cka_token, bytes) else cka_token)
        obj_type = OBJ_TYPE_TOKEN if is_token else 'S'

        gen_mech = _GEN_MECH.get(key_type, CKM_DH_PKCS_DERIVE)
        caller_attrs = [(t, v) for t, v in derived_attrs if t != CKA_VALUE_LEN]

        final_attrs = make_secret_key_attrs(
            key_type=key_type,
            key_value=key_bytes,
            caller_attrs=caller_attrs,
            key_gen_mechanism=gen_mech,
        )

        obj = store.create_object(token_name, obj_type, final_attrs)
        if obj is None:
            logger.error('DVK: failed to create derived key in token %r', token_name)
            return encode_response(
                request.handle, RC_ERROR, RSN_TOKEN_NOT_FOUND, ICSF_TAG_CSFPDVK, b'')

        new_handle = make_object_handle(token_name, obj.sequence, obj_type)
        logger.info('DVK: PKCS-DH token=%r base_seq=%d derived_seq=%d key_type=0x%x len=%d',
                    token_name, sequence, obj.sequence, key_type, len(key_bytes))

        return encode_response(new_handle, RC_SUCCESS, 0, ICSF_TAG_CSFPDVK, b'')

    # -----------------------------------------------------------------------
    # SSL 3.0 Master Key Derivation (SSL-MS)
    # -----------------------------------------------------------------------
    if 'SSL-MS' in rules:
        derived_attrs = []
        client_random = b''
        server_random = b''

        try:
            pos = 0
            # Attribute list SEQUENCE
            tag, attr_seq_val, pos = _decode_tlv(request.service_data, pos)
            derived_attrs = decode_attribute_list(encode_sequence(attr_seq_val))

            # SSL-TLS parms: context-constructed [1] SEQUENCE { clientRandomData, serverRandomData }
            if pos < len(request.service_data):
                tag, ssl_seq_val, pos = _decode_tlv(request.service_data, pos)
                spos = 0
                tag2, client_random, spos = _decode_tlv(ssl_seq_val, spos)
                tag2, server_random, spos = _decode_tlv(ssl_seq_val, spos)
        except Exception as exc:
            logger.warning('DVK: failed to decode DVKInput for SSL-MS: %s', exc)
            return encode_response(
                request.handle, RC_ERROR, 3002, ICSF_TAG_CSFPDVK, b'')

        pre_master_secret = base_attrs.get(CKA_VALUE, b'')
        if len(pre_master_secret) < 2:
            logger.error('DVK: SSL-MS base key CKA_VALUE too short (%d bytes)',
                         len(pre_master_secret))
            return encode_response(
                request.handle, RC_ERROR, 3002, ICSF_TAG_CSFPDVK, b'')

        # First 2 bytes of pre-master secret are the client version
        client_version = pre_master_secret[:2]

        master_key_bytes = _ssl3_master_key_derive(pre_master_secret,
                                                   client_random,
                                                   server_random)

        derived_dict = {t: v for t, v in derived_attrs}
        key_type = derived_dict.get(CKA_KEY_TYPE)
        if isinstance(key_type, bytes):
            key_type = int.from_bytes(key_type, 'big')
        if key_type is None:
            key_type = CKK_GENERIC_SECRET

        cka_token = derived_dict.get(CKA_TOKEN, b'\x00')
        is_token = bool(cka_token[0] if isinstance(cka_token, bytes) else cka_token)
        obj_type = OBJ_TYPE_TOKEN if is_token else 'S'

        caller_attrs = [(t, v) for t, v in derived_attrs if t != CKA_VALUE_LEN]

        final_attrs = make_secret_key_attrs(
            key_type=key_type,
            key_value=master_key_bytes,
            caller_attrs=caller_attrs,
            key_gen_mechanism=CKM_SSL3_MASTER_KEY_DERIVE,
        )

        obj = store.create_object(token_name, obj_type, final_attrs)
        if obj is None:
            logger.error('DVK: failed to create derived master key in token %r', token_name)
            return encode_response(
                request.handle, RC_ERROR, RSN_TOKEN_NOT_FOUND, ICSF_TAG_CSFPDVK, b'')

        new_handle = make_object_handle(token_name, obj.sequence, obj_type)
        logger.info('DVK: SSL-MS token=%r base_seq=%d derived_seq=%d '
                    'key_type=0x%x len=%d version=%r',
                    token_name, sequence, obj.sequence,
                    key_type, len(master_key_bytes), client_version)

        # DVKOutput for SSL-MS: OCTET STRING containing the client version (2 bytes)
        svc_data = encode_octet_string(client_version)
        return encode_response(new_handle, RC_SUCCESS, 0, ICSF_TAG_CSFPDVK, svc_data)

    logger.warning('DVK: unsupported rule array %r', request.rule_array)
    return encode_response(
        request.handle, RC_ERROR, RSN_MECH_INVALID, ICSF_TAG_CSFPDVK, b'')
