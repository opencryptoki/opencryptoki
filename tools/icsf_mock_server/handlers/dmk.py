# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
handlers/dmk.py — CSFPDMK: Derive Multiple Keys (service tag 1).

Implements the SSL-KM (CKM_SSL3_KEY_AND_MAC_DERIVE) and TLS-KM (CKM_TLS_KEY_AND_MAC_DERIVE)
multi-key derivations.

Request wire format (from icsf_derive_multiple_keys() in icsf.c):

    DMKInput ::= SEQUENCE {
        attrList        Attributes,         -- written by icsf_ber_put_attribute_list
        parmsListChoice [0] SEQUENCE {      -- SSL-KM / TLS-KM choice (context-constructed tag 0)
            export              BOOLEAN,
            macSize             INTEGER,    -- in bits
            keySize             INTEGER,    -- in bits
            ivSize              INTEGER,    -- in bits
            clientRandomData    OCTET STRING,
            serverRandomData    OCTET STRING
        }
    }

    Rule array: "SSL-KM  " | "TLS-KM  " (8-byte padded keyword)
    Handle:     44-byte handle of the base (master) secret key

Response wire format:

    DMKOutput ::= SEQUENCE {
        parmsListChoice [0] SEQUENCE {      -- SSL_TLS_DMKOutputParmsList (tag 0xa0)
            clientMACHandle     OCTET STRING (44 bytes),
            serverMACHandle     OCTET STRING (44 bytes),
            clientKeyHandle     OCTET STRING (44 bytes),
            serverKeyHandle     OCTET STRING (44 bytes),
            clientIV            OCTET STRING,
            serverIV            OCTET STRING
        }
    }
"""

import hashlib
import logging

from ber_codec import (
    encode_response, make_object_handle, parse_handle,
    decode_attribute_list, encode_sequence, encode_octet_string,
    encode_ctx_cons, decode_integer, decode_boolean,
    _decode_tlv,
)
from token_store import OBJ_TYPE_TOKEN
from pkcs11_const import (
    CKA_CLASS, CKA_VALUE, CKA_KEY_TYPE, CKA_VALUE_LEN, CKA_TOKEN,
    CKK_AES, CKK_DES, CKK_DES2, CKK_DES3, CKK_GENERIC_SECRET,
    CKM_AES_KEY_GEN, CKM_DES_KEY_GEN, CKM_DES2_KEY_GEN, CKM_DES3_KEY_GEN,
    CKM_GENERIC_SECRET_KEY_GEN,
    CKM_SSL3_KEY_AND_MAC_DERIVE, CKM_TLS_KEY_AND_MAC_DERIVE,
)
from obj_attrs import make_secret_key_attrs

logger = logging.getLogger(__name__)

ICSF_TAG_CSFPDMK = 1

RC_SUCCESS              = 0
RC_ERROR                = 8
RSN_TOKEN_NOT_FOUND     = 3024
RSN_OBJ_NOT_FOUND       = 3025
RSN_MECH_INVALID        = 2116
RSN_TEMPLATE_INCOMPLETE = 3033
RSN_PARAM_INVALID       = 2116

_GEN_MECH = {
    CKK_AES:  CKM_AES_KEY_GEN,
    CKK_DES:  CKM_DES_KEY_GEN,
    CKK_DES2: CKM_DES2_KEY_GEN,
    CKK_DES3: CKM_DES3_KEY_GEN,
}


def _ssl3_sha_then_md5(secret: bytes, server_random: bytes,
                       client_random: bytes, var_data: bytes) -> bytes:
    """
    MD5(secret || SHA-1(var_data || secret || server_random || client_random))
    Used during SSL3 key and MAC material generation.
    """
    sha1_ctx = hashlib.sha1()
    sha1_ctx.update(var_data)
    sha1_ctx.update(secret)
    sha1_ctx.update(server_random)
    sha1_ctx.update(client_random)
    sha1_digest = sha1_ctx.digest()

    md5_ctx = hashlib.md5()
    md5_ctx.update(secret)
    md5_ctx.update(sha1_digest)
    return md5_ctx.digest()


def _ssl3_md5_only(first: bytes, second: bytes, third: bytes) -> bytes:
    """
    MD5(first || second || third)
    Used for SSL3 exportable cipher key material expansion.
    """
    md5_ctx = hashlib.md5()
    if first:
        md5_ctx.update(first)
    if second:
        md5_ctx.update(second)
    if third:
        md5_ctx.update(third)
    return md5_ctx.digest()


def _tls10_p_hash(secret: bytes, seed: bytes, hash_name: str, length: int) -> bytes:
    """
    P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) + HMAC_hash(secret, A(2) + seed) + ...
    where A(0) = seed, A(i) = HMAC_hash(secret, A(i-1))
    """
    import hmac
    out = b''
    a = seed
    while len(out) < length:
        a = hmac.new(secret, a, hash_name).digest()
        out += hmac.new(secret, a + seed, hash_name).digest()
    return out[:length]


def _tls10_prf(secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
    """
    TLS 1.0 / 1.1 PRF: PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR P_SHA-1(S2, label + seed)
    """
    half_len = (len(secret) + 1) // 2
    s1 = secret[:half_len]
    s2 = secret[len(secret) - half_len:]
    label_seed = label + seed
    out_md5 = _tls10_p_hash(s1, label_seed, 'md5', length)
    out_sha1 = _tls10_p_hash(s2, label_seed, 'sha1', length)
    return bytes(b1 ^ b2 for b1, b2 in zip(out_md5, out_sha1))


def handle_dmk(store, request):
    """
    Process a CSFPDMK request.

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
        logger.error('DMK: invalid handle (token=%r seq=%d)', token_name, sequence)
        return encode_response(
            request.handle, RC_ERROR, 3001, ICSF_TAG_CSFPDMK, b'')

    rules = [r.upper() for r in request.rule_array]
    is_ssl = 'SSL-KM' in rules
    is_tls = 'TLS-KM' in rules

    if not is_ssl and not is_tls:
        logger.warning('DMK: unsupported rule array %r', request.rule_array)
        return encode_response(
            request.handle, RC_ERROR, RSN_MECH_INVALID, ICSF_TAG_CSFPDMK, b'')

    # Locate the base key object (the master secret)
    base_obj = store.get_object(token_name, sequence)
    if base_obj is None:
        logger.warning('DMK: base key not found token=%r seq=%d',
                       token_name, sequence)
        return encode_response(
            request.handle, RC_ERROR, RSN_OBJ_NOT_FOUND, ICSF_TAG_CSFPDMK, b'')

    base_attrs = {t: v for t, v in base_obj.get_all_attrs()}
    master_secret = base_attrs.get(CKA_VALUE, b'')

    # Decode DMKInput:
    # 1. Attribute list SEQUENCE
    # 2. Context-constructed [0] SEQUENCE { export, macSize, keySize, ivSize, clientRandom, serverRandom }
    derived_attrs = []
    is_export = False
    mac_size_bits = 0
    key_size_bits = 0
    iv_size_bits = 0
    client_random = b''
    server_random = b''

    try:
        pos = 0
        tag, attr_seq_val, pos = _decode_tlv(request.service_data, pos)
        derived_attrs = decode_attribute_list(encode_sequence(attr_seq_val))

        if pos < len(request.service_data):
            tag, parms_seq_val, pos = _decode_tlv(request.service_data, pos)
            spos = 0
            tag2, exp_val, spos = _decode_tlv(parms_seq_val, spos)
            is_export = decode_boolean(exp_val)

            tag2, mac_val, spos = _decode_tlv(parms_seq_val, spos)
            mac_size_bits = decode_integer(mac_val)

            tag2, key_val, spos = _decode_tlv(parms_seq_val, spos)
            key_size_bits = decode_integer(key_val)

            tag2, iv_val, spos = _decode_tlv(parms_seq_val, spos)
            iv_size_bits = decode_integer(iv_val)

            tag2, client_random, spos = _decode_tlv(parms_seq_val, spos)
            tag2, server_random, spos = _decode_tlv(parms_seq_val, spos)
    except Exception as exc:
        logger.warning('DMK: failed to decode DMKInput: %s', exc)
        return encode_response(
            request.handle, RC_ERROR, 3002, ICSF_TAG_CSFPDMK, b'')

    # Validate template attributes: CKA_CLASS, CKA_KEY_TYPE, and CKA_VALUE_LEN must be present
    derived_dict = {t: v for t, v in derived_attrs}

    if CKA_CLASS not in derived_dict or CKA_KEY_TYPE not in derived_dict or CKA_VALUE_LEN not in derived_dict:
        logger.warning('DMK: template incomplete (missing CLASS, KEY_TYPE, or VALUE_LEN)')
        return encode_response(
            request.handle, RC_ERROR, RSN_TEMPLATE_INCOMPLETE, ICSF_TAG_CSFPDMK, b'')

    key_type = derived_dict.get(CKA_KEY_TYPE)
    if isinstance(key_type, bytes):
        key_type = int.from_bytes(key_type, 'big')

    mac_len = (mac_size_bits + 7) // 8
    write_len = (key_size_bits + 7) // 8
    iv_len = (iv_size_bits + 7) // 8

    # Calculate key material
    total_key_mat_len = 2 * mac_len + 2 * write_len + (0 if is_export else 2 * iv_len)

    if is_ssl:
        # SSL 3.0 key block derivation
        num_blocks = (total_key_mat_len + 15) // 16
        key_block = b''
        for i in range(num_blocks):
            var_data = bytes([ord('A') + i] * (i + 1))
            key_block += _ssl3_sha_then_md5(master_secret, server_random, client_random, var_data)

        client_mac_val = key_block[:mac_len]
        server_mac_val = key_block[mac_len:2 * mac_len]
        client_key_val = key_block[2 * mac_len:2 * mac_len + write_len]
        server_key_val = key_block[2 * mac_len + write_len:2 * mac_len + 2 * write_len]

        offset = 2 * mac_len + 2 * write_len
        if not is_export and iv_len > 0:
            client_iv = key_block[offset:offset + iv_len]
            server_iv = key_block[offset + iv_len:offset + 2 * iv_len]
        elif is_export:
            # SSL3 export key expansion
            client_key_val = _ssl3_md5_only(client_key_val, client_random, server_random)[:write_len]
            server_key_val = _ssl3_md5_only(server_key_val, server_random, client_random)[:write_len]
            if iv_len > 0:
                client_iv = _ssl3_md5_only(b'', client_random, server_random)[:iv_len]
                server_iv = _ssl3_md5_only(b'', server_random, client_random)[:iv_len]
            else:
                client_iv = b''
                server_iv = b''
        else:
            client_iv = b''
            server_iv = b''
    else:
        # TLS 1.0 / 1.1 / 1.2 PRF "key expansion"
        seed = server_random + client_random
        key_block = _tls10_prf(master_secret, b'key expansion', seed, 2 * mac_len + 2 * write_len + 2 * iv_len)
        client_mac_val = key_block[:mac_len]
        server_mac_val = key_block[mac_len:2 * mac_len]
        client_key_val = key_block[2 * mac_len:2 * mac_len + write_len]
        server_key_val = key_block[2 * mac_len + write_len:2 * mac_len + 2 * write_len]
        offset = 2 * mac_len + 2 * write_len
        client_iv = key_block[offset:offset + iv_len] if iv_len > 0 else b''
        server_iv = key_block[offset + iv_len:offset + 2 * iv_len] if iv_len > 0 else b''

    cka_token = derived_dict.get(CKA_TOKEN, b'\x00')
    is_token = bool(cka_token[0] if isinstance(cka_token, bytes) else cka_token)
    obj_type = OBJ_TYPE_TOKEN if is_token else 'S'

    caller_attrs = [(t, v) for t, v in derived_attrs if t != CKA_VALUE_LEN]
    gen_mech = CKM_SSL3_KEY_AND_MAC_DERIVE if is_ssl else CKM_TLS_KEY_AND_MAC_DERIVE

    # Create 4 key objects: client MAC, server MAC, client write, server write
    # MAC keys: CKK_GENERIC_SECRET
    client_mac_attrs = make_secret_key_attrs(
        key_type=CKK_GENERIC_SECRET,
        key_value=client_mac_val,
        caller_attrs=caller_attrs,
        key_gen_mechanism=gen_mech,
    )
    server_mac_attrs = make_secret_key_attrs(
        key_type=CKK_GENERIC_SECRET,
        key_value=server_mac_val,
        caller_attrs=caller_attrs,
        key_gen_mechanism=gen_mech,
    )
    # Write keys: caller's CKA_KEY_TYPE (e.g. CKK_AES)
    client_key_attrs = make_secret_key_attrs(
        key_type=key_type,
        key_value=client_key_val,
        caller_attrs=caller_attrs,
        key_gen_mechanism=gen_mech,
    )
    server_key_attrs = make_secret_key_attrs(
        key_type=key_type,
        key_value=server_key_val,
        caller_attrs=caller_attrs,
        key_gen_mechanism=gen_mech,
    )

    client_mac_obj = store.create_object(token_name, obj_type, client_mac_attrs)
    server_mac_obj = store.create_object(token_name, obj_type, server_mac_attrs)
    client_key_obj = store.create_object(token_name, obj_type, client_key_attrs)
    server_key_obj = store.create_object(token_name, obj_type, server_key_attrs)

    if None in (client_mac_obj, server_mac_obj, client_key_obj, server_key_obj):
        logger.error('DMK: failed to create key objects in token %r', token_name)
        return encode_response(
            request.handle, RC_ERROR, RSN_TOKEN_NOT_FOUND, ICSF_TAG_CSFPDMK, b'')

    client_mac_handle = make_object_handle(token_name, client_mac_obj.sequence, obj_type)
    server_mac_handle = make_object_handle(token_name, server_mac_obj.sequence, obj_type)
    client_key_handle = make_object_handle(token_name, client_key_obj.sequence, obj_type)
    server_key_handle = make_object_handle(token_name, server_key_obj.sequence, obj_type)

    logger.info('DMK: %s token=%r client_mac=%d server_mac=%d client_key=%d server_key=%d',
                'SSL-KM' if is_ssl else 'TLS-KM', token_name,
                client_mac_obj.sequence, server_mac_obj.sequence,
                client_key_obj.sequence, server_key_obj.sequence)

    # Encode DMKOutput (service_data contents, placed inside [ICSF_TAG_CSFPDMK] by encode_response):
    #
    # The C decoder does:
    #   ber_scanf(result, "{t{mmmmmm}}", &tag, &bv_client_mac, ...)
    # where result is positioned after the common header fields.  It opens
    # the service-tag context TLV ({), reads the inner tag (t = 0xa0), opens
    # that inner TLV ({), then reads 6 bervals (mmmmmm).
    #
    # Therefore svc_data must be exactly:
    #   [0] CONSTRUCTED {
    #       clientMACHandle  OCTET STRING,
    #       serverMACHandle  OCTET STRING,
    #       clientKeyHandle  OCTET STRING,
    #       serverKeyHandle  OCTET STRING,
    #       clientIV         OCTET STRING,
    #       serverIV         OCTET STRING
    #   }
    # with NO outer SEQUENCE wrapper (encode_response provides the outer
    # context-constructed [ICSF_TAG_CSFPDMK] envelope).
    parms_contents = (
        encode_octet_string(client_mac_handle) +
        encode_octet_string(server_mac_handle) +
        encode_octet_string(client_key_handle) +
        encode_octet_string(server_key_handle) +
        encode_octet_string(client_iv) +
        encode_octet_string(server_iv)
    )
    svc_data = encode_ctx_cons(0, parms_contents)

    return encode_response(request.handle, RC_SUCCESS, 0, ICSF_TAG_CSFPDMK, svc_data)
