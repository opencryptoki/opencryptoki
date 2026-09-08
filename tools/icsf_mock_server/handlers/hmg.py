# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
handlers/hmg.py — CSFPHMG: HMAC Generate (service tag 6).

Request (from icsf_hmac_sign() in icsf.c):

    HMGInput ::= SEQUENCE {
        text         OCTET STRING,
        chainData    OCTET STRING,
        hmacLength   INTEGER
    }

    Rule array: algorithm (SHA-1 / SHA-256 / SHA-512 / MD5 / ...)
                + chaining mode (ONLY / FIRST / MIDDLE / LAST)

Response:
    HMGOutput ::= SEQUENCE {
        chainData    OCTET STRING,   -- opaque blob echoed by client
        hmac         OCTET STRING,   -- empty for FIRST/MIDDLE calls
        hmacLength   INTEGER         -- ignored by ICSF
    }

The C caller parses the response via:
    ber_scanf(result, "{ooi}", &bvChain, &bvHmac, &hmac_length)

The '{' opens the context TLV; 'o' reads the chainData OCTET STRING
value bytes (bvChain.bv_val, bvChain.bv_len).  The C code then copies
those bytes into chain_data[128].

For FIRST/MIDDLE we return the 16-byte session ID as the chainData value
(fits easily in 128 bytes).  For LAST/ONLY we return the final HMAC bytes.

Multi-part chaining:
    FIRST  — start a new session; accumulate text; return session ID as chainData
    MIDDLE — look up session; accumulate text; return same session ID
    LAST   — look up session; accumulate text; compute full HMAC; close session
    ONLY   — stateless single-call HMAC (no session needed)
"""

import hashlib
import logging
import hmac as _hmac_mod

from ber_codec import (
    encode_response, encode_octet_string, encode_integer,
    parse_handle, _decode_tlv, decode_integer
)
from pkcs11_const import CKA_VALUE

logger = logging.getLogger(__name__)

ICSF_TAG_CSFPHMG = 6

RC_SUCCESS        = 0
RC_ERROR          = 8
RSN_OBJ_NOT_FOUND = 3025

_HASH_MAP = {
    'SHA-1':    'sha1',
    'SHA-224':  'sha224',
    'SHA-256':  'sha256',
    'SHA-384':  'sha384',
    'SHA-512':  'sha512',
    'MD5':      'md5',
    'SHA3-224': 'sha3_224',
    'SHA3-256': 'sha3_256',
    'SHA3-384': 'sha3_384',
    'SHA3-512': 'sha3_512',
    'SSL3-SHA': 'ssl3-sha',
    'SSL3-MD5': 'ssl3-md5',
}


def _compute_mac(key: bytes, data: bytes, algo: str) -> bytes:
    """Compute MAC or HMAC according to algo."""
    if algo == 'ssl3-sha':
        inner = hashlib.sha1(key + b'\x36' * 40 + data).digest()
        return hashlib.sha1(key + b'\x5c' * 40 + inner).digest()
    elif algo == 'ssl3-md5':
        inner = hashlib.md5(key + b'\x36' * 48 + data).digest()
        return hashlib.md5(key + b'\x5c' * 48 + inner).digest()
    else:
        return _hmac_mod.new(key, data, algo).digest()


def handle_hmg(store, request, hmac_state=None):
    """
    Process a CSFPHMG request.

    Parameters
    ----------
    store      : TokenStore
    request    : ICSFRequest
    hmac_state : HmacSessionStore or None
                 Required for multi-part (FIRST/MIDDLE/LAST) calls;
                 ignored (may be None) for ONLY calls.

    Returns
    -------
    bytes — raw BER responseValue
    """
    token_name, sequence, _ = parse_handle(request.handle)

    if not token_name or sequence == 0:
        logger.error('HMG: invalid handle (token=%r seq=%d)', token_name, sequence)
        return encode_response(
            request.handle, RC_ERROR, 3001, ICSF_TAG_CSFPHMG, b'')

    obj = store.get_object(token_name, sequence)
    if obj is None:
        logger.warning('HMG: key not found token=%r seq=%d', token_name, sequence)
        return encode_response(
            request.handle, RC_ERROR, RSN_OBJ_NOT_FOUND, ICSF_TAG_CSFPHMG, b'')

    key_value = obj.get_attr(CKA_VALUE) or b''

    # Determine hash algorithm from rule array
    hash_name = 'sha256'
    for rule in request.rule_array:
        if rule.upper() in _HASH_MAP:
            hash_name = _HASH_MAP[rule.upper()]
            break

    # Determine chaining mode
    chain_mode = 'ONLY'
    for rule in request.rule_array:
        upper = rule.upper()
        if upper in ('ONLY', 'FIRST', 'MIDDLE', 'LAST'):
            chain_mode = upper
            break

    # Parse HMGInput: { text OCTET STRING, chainData OCTET STRING,
    #                   hmacLength INTEGER }
    try:
        pos = 0
        tag, text, pos       = _decode_tlv(request.service_data, pos)
        tag, chain_in, pos   = _decode_tlv(request.service_data, pos)
        tag, hlen_val, pos   = _decode_tlv(request.service_data, pos)
        hmac_len = decode_integer(hlen_val)
    except Exception as exc:
        logger.warning('HMG: failed to decode HMGInput: %s', exc)
        return encode_response(
            request.handle, RC_ERROR, 3002, ICSF_TAG_CSFPHMG, b'')

    # ----------------------------------------------------------------
    # Dispatch by chaining mode
    # ----------------------------------------------------------------

    if chain_mode == 'ONLY':
        # Single-call: compute HMAC directly from *text*
        try:
            hmac_value = _compute_mac(key_value, text, hash_name)
        except Exception as exc:
            logger.warning('HMG ONLY: HMAC failed (%s): %s', hash_name, exc)
            hmac_value = b''

        chain_out = hmac_value   # echo HMAC as chainData (ICSF convention)
        hmac_out  = hmac_value

    elif chain_mode == 'FIRST':
        if hmac_state is None:
            logger.error('HMG FIRST: no hmac_state available')
            return encode_response(
                request.handle, RC_ERROR, 3003, ICSF_TAG_CSFPHMG, b'')

        # chain_in is all-zeros on the FIRST call (C stack-initialised).
        # Create a fresh session and accumulate the text.
        sid = hmac_state.create(key_value, hash_name)
        ok  = hmac_state.append(sid, text)
        if not ok:
            logger.error('HMG FIRST: session lost immediately after creation')
            return encode_response(
                request.handle, RC_ERROR, 3003, ICSF_TAG_CSFPHMG, b'')

        # Return the 16-byte session ID as chainData.
        # The C caller stores it in chain_data[128] via bvChain.bv_val copy.
        chain_out = sid
        hmac_out  = b''   # no HMAC yet

    elif chain_mode == 'MIDDLE':
        if hmac_state is None:
            logger.error('HMG MIDDLE: no hmac_state available')
            return encode_response(
                request.handle, RC_ERROR, 3003, ICSF_TAG_CSFPHMG, b'')

        # chain_in holds the session ID returned on FIRST (first 16 bytes).
        sid = chain_in[:16]
        ok = hmac_state.append(sid, text)
        if not ok:
            logger.warning('HMG MIDDLE: session not found (sid=%s)', sid.hex())
            return encode_response(
                request.handle, RC_ERROR, 3004, ICSF_TAG_CSFPHMG, b'')

        chain_out = sid   # echo same session ID back
        hmac_out  = b''

    else:  # LAST
        if hmac_state is None:
            logger.error('HMG LAST: no hmac_state available')
            return encode_response(
                request.handle, RC_ERROR, 3003, ICSF_TAG_CSFPHMG, b'')

        # chain_in holds the session ID (first 16 bytes).
        sid = chain_in[:16]
        result = hmac_state.finalize(sid, text)
        if result is None:
            logger.warning('HMG LAST: session not found (sid=%s)', sid.hex())
            return encode_response(
                request.handle, RC_ERROR, 3004, ICSF_TAG_CSFPHMG, b'')

        k, algo, full_data = result
        try:
            hmac_value = _compute_mac(k, full_data, algo)
        except Exception as exc:
            logger.warning('HMG LAST: HMAC failed (%s): %s', algo, exc)
            hmac_value = b''

        chain_out = hmac_value   # echo HMAC as chainData on final call
        hmac_out  = hmac_value

    # Build HMGOutput: { chainData OCTET STRING, hmac OCTET STRING,
    #                    hmacLength INTEGER }
    svc_data = (
        encode_octet_string(chain_out) +
        encode_octet_string(hmac_out) +
        encode_integer(len(hmac_out))
    )

    logger.info('HMG: token=%r seq=%d algo=%s mode=%s text=%d hmac=%d',
                token_name, sequence, hash_name, chain_mode,
                len(text), len(hmac_out))

    return encode_response(request.handle, RC_SUCCESS, 0, ICSF_TAG_CSFPHMG, svc_data)
