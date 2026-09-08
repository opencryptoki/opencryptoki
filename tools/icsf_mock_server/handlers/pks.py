# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
handlers/pks.py — CSFPPKS: Private Key Sign / Decrypt (service tag 9).

Request (from icsf_private_key_sign() in icsf.c):

    PKSInput (flat, no SEQUENCE wrapper):
        inputData   OCTET STRING       -- data to sign / ciphertext to decrypt
        outputLen   INTEGER            -- requested output buffer size

    Rule array: algorithm ('RSA-PKCS', 'RSA-ZERO', 'SHA-1   SIGN-RSA', …)
                + optionally 'DECRYPT' for private-key decrypt

Response (flat, no SEQUENCE wrapper):
    outputData  OCTET STRING
    outputLen   INTEGER

    Client reads: ber_scanf(result, "{mi}", &bv_clear_text, &length)
"""

import logging

from ber_codec import (
    encode_response, encode_octet_string, encode_integer,
    parse_handle, _decode_tlv, decode_integer,
)
from pkcs11_const import (
    CKA_MODULUS, CKA_KEY_TYPE, CKA_SUBPRIME,
    CKA_EC_PARAMS, CKK_EC, CKK_DSA,
)
from rsa_backend import rsa_private_decrypt, rsa_private_sign
from ec_backend import ec_sign, ec_max_sig_len, CurveNotSupportedError
from dsa_backend import dsa_sign, dsa_max_sig_len

logger = logging.getLogger(__name__)

ICSF_TAG_CSFPPKS = 9

RC_SUCCESS        = 0
RC_ERROR          = 8
RSN_OBJ_NOT_FOUND = 3025
RSN_TOO_SHORT     = 3003


def handle_pks(store, request):
    """Process a CSFPPKS (Private Key Sign / Decrypt) request."""
    token_name, sequence, _ = parse_handle(request.handle)
    if not token_name or sequence == 0:
        logger.error('PKS: invalid handle (token=%r seq=%d)', token_name, sequence)
        return encode_response(request.handle, RC_ERROR, 3001, ICSF_TAG_CSFPPKS, b'')

    obj = store.get_object(token_name, sequence)
    if obj is None:
        logger.warning('PKS: key not found token=%r seq=%d', token_name, sequence)
        return encode_response(request.handle, RC_ERROR, RSN_OBJ_NOT_FOUND,
                               ICSF_TAG_CSFPPKS, b'')

    # Parse PKSInput: OCTET STRING + INTEGER (ber_printf "oi")
    try:
        pos = 0
        tag, input_data, pos = _decode_tlv(request.service_data, pos)
        tag, req_len_val, pos = _decode_tlv(request.service_data, pos)
        req_len = decode_integer(req_len_val)
    except Exception as exc:
        logger.warning('PKS: failed to decode PKSInput: %s', exc)
        return encode_response(request.handle, RC_ERROR, 3002, ICSF_TAG_CSFPPKS, b'')

    is_decrypt = any(r.strip() == 'DECRYPT' for r in request.rule_array)
    # The algorithm rule is the first entry (e.g. 'RSA-PKCS', 'ECDSA')
    mech_rule = request.rule_array[0].strip() if request.rule_array else 'RSA-PKCS'

    # Determine key type from stored attributes
    key_type_raw = obj.get_attr(CKA_KEY_TYPE)
    if isinstance(key_type_raw, (bytes, bytearray)):
        key_type = int.from_bytes(key_type_raw, 'big')
    else:
        key_type = key_type_raw or 0

    # Size query for EC/DSA sign: return 2*n without performing a real sign.
    if req_len == 0 and not is_decrypt:
        if key_type == CKK_EC:
            ec_params = obj.get_attr(CKA_EC_PARAMS) or b''
            sig_len = ec_max_sig_len(ec_params)
            svc_data = encode_octet_string(b'') + encode_integer(sig_len)
            return encode_response(request.handle, RC_ERROR, RSN_TOO_SHORT,
                                   ICSF_TAG_CSFPPKS, svc_data)
        if key_type == CKK_DSA:
            subprime = obj.get_attr(CKA_SUBPRIME) or b'\x00' * 20
            sig_len = dsa_max_sig_len(subprime)
            svc_data = encode_octet_string(b'') + encode_integer(sig_len)
            return encode_response(request.handle, RC_ERROR, RSN_TOO_SHORT,
                                   ICSF_TAG_CSFPPKS, svc_data)

    try:
        if key_type == CKK_DSA:
            output = dsa_sign(obj.attributes, input_data)
        elif key_type == CKK_EC:
            output = ec_sign(obj.attributes, input_data, mech_rule)
        elif is_decrypt:
            padding = 'PKCS1' if 'PKCS' in mech_rule else 'NONE'
            output = rsa_private_decrypt(obj.attributes, input_data, padding)
        else:
            output = rsa_private_sign(obj.attributes, input_data, mech_rule)
    except CurveNotSupportedError as exc:
        logger.warning('PKS: curve not supported: %s', exc)
        return encode_response(request.handle, RC_ERROR, 874, ICSF_TAG_CSFPPKS, b'')
    except Exception as exc:
        logger.error('PKS: operation failed: %s', exc)
        return encode_response(request.handle, RC_ERROR, RC_ERROR, ICSF_TAG_CSFPPKS, b'')

    # For DSA/EC the output length was returned in the size-query branch above.
    # For RSA, derive expected size from the modulus.
    mod_len = len(obj.get_attr(CKA_MODULUS) or b'') or 256

    # Size query for RSA/decrypt: req_len == 0 means caller wants output length only
    if req_len == 0 or len(output) > req_len:
        svc_data = encode_octet_string(b'') + encode_integer(len(output))
        return encode_response(request.handle, RC_ERROR, RSN_TOO_SHORT,
                               ICSF_TAG_CSFPPKS, svc_data)

    svc_data = encode_octet_string(output) + encode_integer(len(output))
    logger.info('PKS: token=%r seq=%d in=%d out=%d decrypt=%s mech=%r',
                token_name, sequence, len(input_data), len(output),
                is_decrypt, mech_rule)
    return encode_response(request.handle, RC_SUCCESS, 0, ICSF_TAG_CSFPPKS, svc_data)
