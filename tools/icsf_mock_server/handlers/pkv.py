# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
handlers/pkv.py — CSFPPKV: Public Key Verify / Encrypt (service tag 10).

Request (from icsf_public_key_verify() in icsf.c):

    PKVInput when encrypting (encrypt=True, ber_printf "oti"):
        inputData   OCTET STRING       -- plaintext to encrypt
        [0]         INTEGER            -- requested output buffer size

    PKVInput when verifying (encrypt=False, ber_printf "oto"):
        inputData   OCTET STRING       -- data that was signed (clear text / hash)
        [1]         OCTET STRING       -- signature to verify

Response when encrypting (flat, no SEQUENCE wrapper):
    outputData  OCTET STRING
    outputLen   INTEGER

    Client reads: ber_scanf(result, "{mi}", &bv_cipher_text, &length)

Response when verifying:
    No service-specific output (service data = empty).
    rc=0 means valid.
"""

import logging

from ber_codec import (
    encode_response, encode_octet_string, encode_integer,
    parse_handle, _decode_tlv, decode_integer,
)
from pkcs11_const import CKA_MODULUS, CKA_KEY_TYPE, CKK_EC, CKK_DSA
from rsa_backend import rsa_public_encrypt, rsa_public_verify
from ec_backend import ec_verify, CurveNotSupportedError
from dsa_backend import dsa_verify

logger = logging.getLogger(__name__)

ICSF_TAG_CSFPPKV = 10

RC_SUCCESS        = 0
RC_ERROR          = 8
RSN_OBJ_NOT_FOUND = 3025
RSN_TOO_SHORT     = 3003
RSN_SIG_INVALID   = 11028   # maps to CKR_SIGNATURE_INVALID in icsf_to_ock_err()


def handle_pkv(store, request):
    """Process a CSFPPKV (Public Key Verify / Encrypt) request."""
    token_name, sequence, _ = parse_handle(request.handle)
    if not token_name or sequence == 0:
        logger.error('PKV: invalid handle (token=%r seq=%d)', token_name, sequence)
        return encode_response(request.handle, RC_ERROR, 3001, ICSF_TAG_CSFPPKV, b'')

    obj = store.get_object(token_name, sequence)
    if obj is None:
        logger.warning('PKV: key not found token=%r seq=%d', token_name, sequence)
        return encode_response(request.handle, RC_ERROR, RSN_OBJ_NOT_FOUND,
                               ICSF_TAG_CSFPPKV, b'')

    is_encrypt = any(r.strip() == 'ENCRYPT' for r in request.rule_array)
    mech_rule = request.rule_array[0].strip() if request.rule_array else 'RSA-PKCS'

    # Determine key type from stored attributes
    key_type_raw = obj.get_attr(CKA_KEY_TYPE)
    if isinstance(key_type_raw, (bytes, bytearray)):
        key_type = int.from_bytes(key_type_raw, 'big')
    else:
        key_type = key_type_raw or 0

    # Parse input: layout differs for encrypt vs verify
    try:
        pos = 0
        if is_encrypt:
            # "oti": cleartext OCTET STRING, context [0] INTEGER outLen
            tag, input_data, pos = _decode_tlv(request.service_data, pos)
            tag, req_len_val, pos = _decode_tlv(request.service_data, pos)
            req_len   = decode_integer(req_len_val)
            signature = None
        else:
            # icsf_public_key_verify() encodes cipher_text first, followed by
            # clear_text with the context-specific tag [1].  The latter is a
            # primitive context tag, so its value is the clear text directly.
            tag, signature, pos = _decode_tlv(request.service_data, pos)
            tag, input_data, pos = _decode_tlv(request.service_data, pos)
            if (tag & 0xe0) != 0x80 or (tag & 0x1f) != 1:
                raise ValueError('PKV: invalid clear-text context tag')
            req_len = 0
    except Exception as exc:
        logger.warning('PKV: failed to decode PKVInput: %s', exc)
        return encode_response(request.handle, RC_ERROR, 3002, ICSF_TAG_CSFPPKV, b'')

    if is_encrypt:
        try:
            padding = 'PKCS1' if 'PKCS' in mech_rule else 'NONE'
            output = rsa_public_encrypt(obj.attributes, input_data, padding)
        except Exception as exc:
            logger.error('PKV(encrypt): operation failed: %s', exc)
            return encode_response(request.handle, RC_ERROR, RC_ERROR,
                                   ICSF_TAG_CSFPPKV, b'')

        # Size query: req_len == 0 means caller wants the output length only
        if req_len == 0 or len(output) > req_len:
            svc_data = encode_octet_string(b'') + encode_integer(len(output))
            return encode_response(request.handle, RC_ERROR, RSN_TOO_SHORT,
                                   ICSF_TAG_CSFPPKV, svc_data)

        svc_data = encode_octet_string(output) + encode_integer(len(output))
        logger.info('PKV(encrypt): token=%r seq=%d in=%d out=%d mech=%r',
                    token_name, sequence, len(input_data), len(output), mech_rule)
        return encode_response(request.handle, RC_SUCCESS, 0,
                               ICSF_TAG_CSFPPKV, svc_data)
    else:
        # Verify
        try:
            if key_type == CKK_DSA:
                valid = dsa_verify(obj.attributes, input_data,
                                   signature or b'')
            elif key_type == CKK_EC:
                valid = ec_verify(obj.attributes, input_data,
                                  signature or b'', mech_rule)
            else:
                valid = rsa_public_verify(obj.attributes, input_data,
                                          signature or b'', mech_rule)
        except CurveNotSupportedError as exc:
            logger.warning('PKV(verify): curve not supported: %s', exc)
            return encode_response(request.handle, RC_ERROR, 874,
                                   ICSF_TAG_CSFPPKV, b'')
        except Exception as exc:
            logger.error('PKV(verify): operation failed: %s', exc)
            return encode_response(request.handle, RC_ERROR, RC_ERROR,
                                   ICSF_TAG_CSFPPKV, b'')

        if not valid:
            logger.warning('PKV(verify): signature invalid token=%r seq=%d', token_name, sequence)
            return encode_response(request.handle, RC_ERROR, RSN_SIG_INVALID,
                                   ICSF_TAG_CSFPPKV, b'')

        logger.info('PKV(verify): token=%r seq=%d mech=%r — OK',
                    token_name, sequence, mech_rule)
        return encode_response(request.handle, RC_SUCCESS, 0, ICSF_TAG_CSFPPKV, b'')
