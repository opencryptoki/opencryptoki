# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
handlers/gsk.py — CSFPGSK: Generate Secret Key (service tag 5).

Request (from icsf_generate_secret_key() in icsf.c):

    GSKInput ::= SEQUENCE {
        attrList     Attributes,      -- PKCS#11 attribute list
        parmsList    OCTET STRING     -- mechanism parameters (e.g. SSL/TLS version)
    }

    Rule array: "KEY     " (default) | "TLS     " | "SSL     " | "PARMS   "

Response:
    No service-specific output (service data = empty).
    The generated key's handle is returned in the common header handle field.

The mock generates a key of the requested type and size using os.urandom
for the key material, stores it in the token, and returns its handle.

Key type and length are inferred from CKA_KEY_TYPE and CKA_VALUE_LEN in the
attribute list.  All PKCS#11-defined attributes for secret keys are stored
with appropriate defaults.
"""

import logging
import os

from ber_codec import (
    encode_response, make_object_handle, parse_handle,
    decode_attribute_list, encode_sequence,
    _decode_tlv
)
from token_store import OBJ_TYPE_TOKEN
from pkcs11_const import (
    CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE, CKA_VALUE_LEN, CKA_TOKEN,
    CKO_SECRET_KEY, CKK_AES, CKK_DES, CKK_DES2, CKK_DES3,
    CKM_DES_KEY_GEN, CKM_DES2_KEY_GEN, CKM_DES3_KEY_GEN, CKM_AES_KEY_GEN,
    CKM_GENERIC_SECRET_KEY_GEN, CKM_SSL3_PRE_MASTER_KEY_GEN,
    CKM_TLS_PRE_MASTER_KEY_GEN,
)
from obj_attrs import make_secret_key_attrs

logger = logging.getLogger(__name__)

ICSF_TAG_CSFPGSK = 5

RC_SUCCESS           = 0
RC_ERROR             = 8
RSN_TOKEN_NOT_FOUND  = 3024
RSN_INVALID_ATTR     = 3003

# Default sizes when CKA_VALUE_LEN is absent
_DEFAULT_KEY_LEN = {
    CKK_AES:  32,
    CKK_DES:  8,
    CKK_DES2: 16,
    CKK_DES3: 24,
}

# Mechanism used for each key type during generation
_GEN_MECH = {
    CKK_AES:  CKM_AES_KEY_GEN,
    CKK_DES:  CKM_DES_KEY_GEN,
    CKK_DES2: CKM_DES2_KEY_GEN,
    CKK_DES3: CKM_DES3_KEY_GEN,
}


def handle_gsk(store, request):
    """
    Process a CSFPGSK request.

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
        logger.error('GSK: empty token name in handle')
        return encode_response(
            request.handle, RC_ERROR, 3001, ICSF_TAG_CSFPGSK, b'')

    if not store.token_exists(token_name):
        logger.error('GSK: token %r not found', token_name)
        return encode_response(
            request.handle, RC_ERROR, RSN_TOKEN_NOT_FOUND, ICSF_TAG_CSFPGSK, b'')

    # service_data = contents of context-constructed TLV
    # GSKInput: { attrList SEQUENCE-OF-SEQ ... } followed by parmsList OCTET STRING.
    # The attribute list is a SEQUENCE (written by icsf_ber_put_attribute_list).
    attrs = []
    parms_bytes = b''
    try:
        # The first TLV inside service_data is the attribute list SEQUENCE
        tag, attr_seq_val, pos = _decode_tlv(request.service_data, 0)
        # attr_seq_val is the contents of the SEQUENCE — re-wrap for the decoder
        wrapped = encode_sequence(attr_seq_val)
        attrs = decode_attribute_list(wrapped)
        if pos < len(request.service_data):
            tag2, parms_bytes, _ = _decode_tlv(request.service_data, pos)
    except Exception as exc:
        logger.warning('GSK: could not decode GSKInput: %s', exc)

    # Extract key type and length from attribute list
    attr_dict = {t: v for t, v in attrs}

    key_type = attr_dict.get(CKA_KEY_TYPE)
    if key_type is None:
        logger.error('GSK: CKA_KEY_TYPE missing from attribute list')
        return encode_response(
            request.handle, RC_ERROR, RSN_INVALID_ATTR, ICSF_TAG_CSFPGSK, b'')

    value_len = attr_dict.get(CKA_VALUE_LEN)
    if value_len is None:
        value_len = _DEFAULT_KEY_LEN.get(key_type, 32)
    if isinstance(value_len, bytes):
        value_len = int.from_bytes(value_len, 'big')

    # Generate random key material
    key_bytes = bytearray(os.urandom(value_len))

    # If generating SSL/TLS pre-master secret ("SSL" / "TLS" rule), embed version into the first 2 bytes
    rules = [r.upper() for r in request.rule_array]
    if ('SSL' in rules or 'TLS' in rules) and len(parms_bytes) >= 2 and len(key_bytes) >= 2:
        key_bytes[0] = parms_bytes[0]
        key_bytes[1] = parms_bytes[1]
    key_bytes = bytes(key_bytes)

    # Determine whether object persists across sessions
    cka_token = attr_dict.get(CKA_TOKEN, b'\x00')
    is_token = bool(cka_token[0] if isinstance(cka_token, bytes) else cka_token)
    obj_type = OBJ_TYPE_TOKEN if is_token else 'S'

    # Determine generating mechanism for this key type
    if 'SSL' in rules:
        gen_mech = CKM_SSL3_PRE_MASTER_KEY_GEN
    elif 'TLS' in rules:
        gen_mech = CKM_TLS_PRE_MASTER_KEY_GEN
    else:
        gen_mech = _GEN_MECH.get(key_type, CKM_GENERIC_SECRET_KEY_GEN)

    # Build the complete attribute set — make_secret_key_attrs injects
    # CKA_VALUE and CKA_CLASS and then calls complete_key_attrs to fill in
    # all PKCS#11-defined attributes with proper defaults.
    # Strip any caller-supplied CKA_VALUE_LEN first; complete_key_attrs will
    # derive it from CKA_VALUE to ensure consistency.
    caller_attrs = [(t, v) for t, v in attrs if t != CKA_VALUE_LEN]

    final_attrs = make_secret_key_attrs(
        key_type=key_type,
        key_value=key_bytes,
        caller_attrs=caller_attrs,
        key_gen_mechanism=gen_mech,
    )

    obj = store.create_object(token_name, obj_type, final_attrs)
    if obj is None:
        logger.error('GSK: failed to create object in token %r', token_name)
        return encode_response(
            request.handle, RC_ERROR, RSN_TOKEN_NOT_FOUND, ICSF_TAG_CSFPGSK, b'')

    new_handle = make_object_handle(token_name, obj.sequence, obj_type)
    logger.info('GSK: token=%r seq=%d key_type=0x%x len=%d attrs=%d',
                token_name, obj.sequence, key_type, value_len, len(final_attrs))
    return encode_response(new_handle, RC_SUCCESS, 0, ICSF_TAG_CSFPGSK, b'')
