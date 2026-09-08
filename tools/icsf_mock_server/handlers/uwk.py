# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
handlers/uwk.py — CSFPUWK: Unwrap Key (service tag 17).

Request (from icsf_unwrap_key() in icsf.c):

    UWKInput ::= SEQUENCE {
        wrappedKey      OCTET STRING,
        initialValue    OCTET STRING,
        attrList        Attributes
    }

    Rule array: ["PKCS-8", "AES"] for AES-CBC-PAD
                ["PKCS-1.2"]      for RSA-PKCS (not currently exercised)

    Request handle: the UNWRAPPING key (the AES key that will decrypt).

Response:
    The newly created key's handle is returned in the response header handle
    field.  The service data is empty.

    Client calls: handle_to_object_record(key, handle)  (line 1165 of icsf.c)

Implementation
--------------
For PKCS-8 / AES-CBC-PAD the mock:
  1. Decrypts the wrappedKey bytes with the unwrapping key using AES-CBC-PAD.
  2. If the template marks the key as CKO_PRIVATE_KEY, parses the decrypted
     bytes as a PKCS#8 PrivateKeyInfo DER blob.  The AlgorithmIdentifier OID
     is used to dispatch:
       - id-ecPublicKey (1.2.840.10045.2.1) → restores CKA_EC_PARAMS,
         CKA_VALUE (private scalar), and optionally CKA_EC_POINT.
       - rsaEncryption (1.2.840.113549.1.1.1) → restores RSA components.
  3. Otherwise (secret key), the decrypted bytes become CKA_VALUE.
  4. Calls complete_key_attrs so all PKCS#11 attributes are present.
  5. Returns the new object's handle in the response header.
"""

import logging

from cipher_backend import aes_decrypt, AES_BLOCK, DES_BLOCK
from rsa_backend import rsa_private_decrypt
from ber_codec import (
    encode_response, make_object_handle,
    parse_handle, _decode_tlv, decode_attribute_list, encode_sequence,
    HANDLE_LEN, pkcs8_to_rsa_attrs, pkcs8_to_ec_attrs, pkcs8_get_alg_oid,
)
from obj_attrs import make_secret_key_attrs, complete_key_attrs
from pkcs11_const import (
    CKA_CLASS, CKA_VALUE, CKA_VALUE_LEN, CKA_KEY_TYPE, CKA_TOKEN,
    CKO_PRIVATE_KEY, CKK_EC,
    CKM_UNAVAILABLE_INFORMATION,
)
from token_store import OBJ_TYPE_TOKEN

logger = logging.getLogger(__name__)

ICSF_TAG_CSFPUWK = 17

RC_SUCCESS        = 0
RC_ERROR          = 8
RSN_OBJ_NOT_FOUND = 3025


def handle_uwk(store, request):
    """Process a CSFPUWK (Unwrap Key) request."""
    # Request handle = the unwrapping key
    token_name, sequence, _ = parse_handle(request.handle)
    if not token_name or sequence == 0:
        logger.error('UWK: invalid unwrapping-key handle')
        return encode_response(request.handle, RC_ERROR, 3001, ICSF_TAG_CSFPUWK, b'')

    unwrap_obj = store.get_object(token_name, sequence)
    if unwrap_obj is None:
        logger.warning('UWK: unwrapping key not found token=%r seq=%d', token_name, sequence)
        return encode_response(request.handle, RC_ERROR, RSN_OBJ_NOT_FOUND, ICSF_TAG_CSFPUWK, b'')

    unwrapping_key_value = unwrap_obj.get_attr(CKA_VALUE) or b''

    # Parse UWKInput: wrappedKey OCTET STRING, initialValue OCTET STRING,
    #                 attrList Attributes (a SEQUENCE)
    try:
        pos = 0
        tag, wrapped_key, pos = _decode_tlv(request.service_data, pos)
        tag, iv_bytes, pos    = _decode_tlv(request.service_data, pos)
        # attrList is a SEQUENCE (the outer SEQUENCE from icsf_ber_put_attribute_list)
        tag, attr_seq_val, pos = _decode_tlv(request.service_data, pos)
        attrs = decode_attribute_list(encode_sequence(attr_seq_val))
    except Exception as exc:
        logger.warning('UWK: failed to decode UWKInput: %s', exc)
        return encode_response(request.handle, RC_ERROR, 3002, ICSF_TAG_CSFPUWK, b'')

    # Determine wrapping algorithm from rule array
    is_rsa = any(rule.strip().upper() == 'PKCS-1.2'
                 for rule in request.rule_array)
    algo = 'AES'
    for rule in request.rule_array:
        if rule.upper() in ('AES', 'DES', 'DES3'):
            algo = rule.upper()
            break

    # Decrypt the wrapped key material
    try:
        if is_rsa:
            plain_key = rsa_private_decrypt(unwrap_obj.attributes,
                                            wrapped_key, 'PKCS1')
        else:
            # Use the actual unwrapping key length to pick the correct block
            # size: DES/DES2/DES3 keys (8 or 16 bytes) use DES_BLOCK = 8.
            iv_block = AES_BLOCK if len(unwrapping_key_value) in (16, 24, 32) \
                and algo == 'AES' else DES_BLOCK
            iv = (iv_bytes or b'').ljust(iv_block, b'\x00')[:iv_block]
            plain_key = aes_decrypt(unwrapping_key_value, wrapped_key,
                                    'CBC-PAD', iv, algo=algo, pad=True)
    except Exception as exc:
        logger.error('UWK: decryption failed: %s', exc)
        return encode_response(request.handle, RC_ERROR, RC_ERROR, ICSF_TAG_CSFPUWK, b'')

    attr_dict = {t: v for t, v in attrs}

    # Determine object type (session vs token)
    cka_token = attr_dict.get(CKA_TOKEN, b'\x00')
    is_token = bool(cka_token[0] if isinstance(cka_token, bytes) else cka_token)
    obj_type = OBJ_TYPE_TOKEN if is_token else 'S'

    # Resolve the object class from the caller's template
    obj_class = attr_dict.get(CKA_CLASS)
    if isinstance(obj_class, bytes):
        obj_class = int.from_bytes(obj_class, 'big')

    if obj_class == CKO_PRIVATE_KEY:
        final_attrs = _build_private_key_attrs(plain_key, attrs, attr_dict)
        if final_attrs is None:
            logger.error('UWK: failed to decode PKCS#8 blob for private key')
            return encode_response(request.handle, RC_ERROR, RC_ERROR,
                                   ICSF_TAG_CSFPUWK, b'')
    else:
        # Secret key (or unknown) — build complete secret-key attribute set.
        key_type = attr_dict.get(CKA_KEY_TYPE)
        if key_type is None:
            logger.warning('UWK: CKA_KEY_TYPE missing from unwrap template')
            return encode_response(request.handle, RC_ERROR, 3002,
                                   ICSF_TAG_CSFPUWK, b'')
        # Strip any caller-supplied CKA_VALUE_LEN; derive it from key material.
        # key_gen_mechanism=CKM_UNAVAILABLE_INFORMATION → CKA_LOCAL=False.
        caller_attrs = [(t, v) for t, v in attrs if t != CKA_VALUE_LEN]
        final_attrs = make_secret_key_attrs(
            key_type=key_type,
            key_value=plain_key,
            caller_attrs=caller_attrs,
            key_gen_mechanism=CKM_UNAVAILABLE_INFORMATION,
        )

    new_obj = store.create_object(token_name, obj_type, final_attrs)
    if new_obj is None:
        logger.error('UWK: failed to create unwrapped key object in token %r', token_name)
        return encode_response(request.handle, RC_ERROR, RC_ERROR, ICSF_TAG_CSFPUWK, b'')

    new_handle = make_object_handle(token_name, new_obj.sequence, obj_type)

    logger.info('UWK: token=%r unwrap_seq=%d new_seq=%d algo=%s plain=%d',
                token_name, sequence, new_obj.sequence,
                'RSA-PKCS' if is_rsa else algo, len(plain_key))

    # UWK response: new key handle in the response header, empty service data
    return encode_response(new_handle, RC_SUCCESS, 0, ICSF_TAG_CSFPUWK, b'')


# ---------------------------------------------------------------------------
# Private key attribute builder — dispatches on the PKCS#8 algorithm OID
# ---------------------------------------------------------------------------

# id-ecPublicKey OID value bytes (without tag/length): 1.2.840.10045.2.1
_EC_OID_VALUE = bytes.fromhex('2a8648ce3d0201')


def _build_private_key_attrs(pkcs8_bytes, caller_attrs, attr_dict):
    """
    Decode a PKCS#8 DER blob and return a complete private-key attribute list.

    Dispatches on the AlgorithmIdentifier OID:
      - id-ecPublicKey → EC private key (restores CKA_EC_PARAMS, CKA_VALUE,
                                          and optionally CKA_EC_POINT)
      - rsaEncryption  → RSA private key (restores RSA components)

    caller_attrs  — list of (type, value) from the C unwrap template
    attr_dict     — dict view of caller_attrs (for fast lookup)

    Returns a list of (CKA_*, value) or None on decode failure.
    """
    alg_oid = pkcs8_get_alg_oid(pkcs8_bytes)
    is_ec   = (alg_oid == _EC_OID_VALUE)

    if is_ec:
        return _build_ec_private_key_attrs(pkcs8_bytes, caller_attrs, attr_dict)
    else:
        return _build_rsa_private_key_attrs(pkcs8_bytes, caller_attrs, attr_dict)


def _build_rsa_private_key_attrs(pkcs8_bytes, caller_attrs, attr_dict):
    """Decode PKCS#8 RSA blob and return a complete attribute list."""
    try:
        rsa_components = pkcs8_to_rsa_attrs(pkcs8_bytes)
    except Exception as exc:
        logger.error('UWK: pkcs8_to_rsa_attrs failed: %s', exc)
        return None

    # Start with the caller's template (class, key type, token flag, etc.)
    # then inject the RSA components decoded from the PKCS#8 blob.
    base = list(caller_attrs)
    base_dict = dict(attr_dict)

    for cka, val in rsa_components.items():
        if cka not in base_dict:
            base.append((cka, val))
            base_dict[cka] = val

    return complete_key_attrs(base, key_gen_mechanism=CKM_UNAVAILABLE_INFORMATION)


def _build_ec_private_key_attrs(pkcs8_bytes, caller_attrs, attr_dict):
    """Decode PKCS#8 EC blob and return a complete attribute list."""
    try:
        ec_components = pkcs8_to_ec_attrs(pkcs8_bytes)
    except Exception as exc:
        logger.error('UWK: pkcs8_to_ec_attrs failed: %s', exc)
        return None

    # Start with the caller's template (class, key type, token flag, etc.)
    # then inject the EC components decoded from the PKCS#8 blob.
    base = list(caller_attrs)
    base_dict = dict(attr_dict)

    for cka, val in ec_components.items():
        if cka not in base_dict:
            base.append((cka, val))
            base_dict[cka] = val

    # Ensure CKA_KEY_TYPE is CKK_EC in the attribute list.
    if CKA_KEY_TYPE not in base_dict:
        base.append((CKA_KEY_TYPE, CKK_EC))

    return complete_key_attrs(base, key_gen_mechanism=CKM_UNAVAILABLE_INFORMATION)
