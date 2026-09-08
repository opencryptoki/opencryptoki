# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
handlers/hmv.py — CSFPHMV: HMAC Verify (service tag 7).

Request (from icsf_hmac_verify() in icsf.c):

    HMVInput ::= SEQUENCE {
        text        OCTET STRING,
        chainData   OCTET STRING,
        hmac        OCTET STRING
    }

    Rule array: algorithm (SHA-1 / SHA-256 / SHA-512 / MD5 / ...)
                + chaining mode (ONLY / FIRST / MIDDLE / LAST)

    NOTE: chainData is always required, even on an ONLY call (per icsf.c
    comment: "an HMV ONLY call fails with reason_code=11000 when
    chain_data_length is 0").

Response:
    HMVOutput ::= chainData  OCTET STRING

    rc=0: HMAC verified successfully.
    rc=8/reason=11000: HMAC verification failed.

The C caller parses the response via:
    ber_scanf(result, "m", &bvChain)

The bare 'm' reads the context TLV value bytes directly into bvChain
(no inner OCTET STRING parsed).  The C code copies bvChain.bv_val into
chain_data[128].

For FIRST/MIDDLE we return the raw 16-byte session ID as svc_data.
The C code stores those 16 bytes in its 128-byte chain_data buffer.
On subsequent calls chain_data is sent back as a 128-byte field; we
extract the session ID from the first 16 bytes of chain_in.

Multi-part chaining:
    FIRST  — start a new session; accumulate text; return session ID
    MIDDLE — look up session; accumulate text; echo session ID
    LAST   — look up session; accumulate text; verify full HMAC; close session
    ONLY   — stateless single-call verify (no session needed)
"""

import hashlib
import logging
import hmac as _hmac_mod

from ber_codec import (
    encode_response, encode_octet_string,
    parse_handle, _decode_tlv
)
from pkcs11_const import CKA_VALUE

logger = logging.getLogger(__name__)

ICSF_TAG_CSFPHMV = 7

RC_SUCCESS       = 0
RC_ERROR         = 8
RSN_OBJ_NOT_FOUND = 3025
RSN_HMAC_INVALID  = 11000   # reason code used by ICSF for bad HMAC

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


def handle_hmv(store, request, hmac_state=None):
    """
    Process a CSFPHMV request.

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
        logger.error('HMV: invalid handle (token=%r seq=%d)', token_name, sequence)
        return encode_response(
            request.handle, RC_ERROR, 3001, ICSF_TAG_CSFPHMV, b'')

    obj = store.get_object(token_name, sequence)
    if obj is None:
        logger.warning('HMV: key not found token=%r seq=%d', token_name, sequence)
        return encode_response(
            request.handle, RC_ERROR, RSN_OBJ_NOT_FOUND, ICSF_TAG_CSFPHMV, b'')

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

    # Parse HMVInput: { text OCTET STRING, chainData OCTET STRING,
    #                   hmac OCTET STRING }
    try:
        pos = 0
        tag, text, pos          = _decode_tlv(request.service_data, pos)
        tag, chain_in, pos      = _decode_tlv(request.service_data, pos)
        tag, hmac_supplied, pos = _decode_tlv(request.service_data, pos)
    except Exception as exc:
        logger.warning('HMV: failed to decode HMVInput: %s', exc)
        return encode_response(
            request.handle, RC_ERROR, 3002, ICSF_TAG_CSFPHMV, b'')

    # ----------------------------------------------------------------
    # Dispatch by chaining mode
    # ----------------------------------------------------------------

    if chain_mode == 'ONLY':
        # Single-call: compute expected HMAC and compare.
        # chain_in is non-empty on ONLY calls (ICSF requirement), but we
        # don't need its value; we only need the key and the text.
        try:
            expected = _compute_mac(key_value, text, hash_name)
        except Exception as exc:
            logger.warning('HMV ONLY: HMAC failed (%s): %s', hash_name, exc)
            expected = b''

        if _hmac_mod.compare_digest(expected, hmac_supplied):
            logger.info('HMV: token=%r seq=%d algo=%s ONLY — VERIFIED OK',
                        token_name, sequence, hash_name)
            # Return hmac bytes as svc_data (fits in 128-byte chain_data buf)
            svc_data = hmac_supplied
            return encode_response(request.handle, RC_SUCCESS, 0,
                                   ICSF_TAG_CSFPHMV, svc_data)
        else:
            logger.info('HMV: token=%r seq=%d algo=%s ONLY — FAILED',
                        token_name, sequence, hash_name)
            svc_data = chain_in
            return encode_response(request.handle, RC_ERROR, RSN_HMAC_INVALID,
                                   ICSF_TAG_CSFPHMV, svc_data)

    elif chain_mode == 'FIRST':
        if hmac_state is None:
            logger.error('HMV FIRST: no hmac_state available')
            return encode_response(
                request.handle, RC_ERROR, 3003, ICSF_TAG_CSFPHMV, b'')

        # Create session and accumulate text.
        # chain_in is all-zeros on the FIRST call (C stack-initialised).
        sid = hmac_state.create(key_value, hash_name)
        ok  = hmac_state.append(sid, text)
        if not ok:
            logger.error('HMV FIRST: session lost immediately after creation')
            return encode_response(
                request.handle, RC_ERROR, 3003, ICSF_TAG_CSFPHMV, b'')

        # Return raw session ID as svc_data (16 bytes).
        # ber_scanf(result, "m", ...) gives bvChain.bv_val = sid (16 bytes).
        # C copies 16 bytes into its 128-byte chain_data buffer.
        logger.info('HMV: token=%r seq=%d algo=%s FIRST — started session',
                    token_name, sequence, hash_name)
        return encode_response(request.handle, RC_SUCCESS, 0,
                               ICSF_TAG_CSFPHMV, sid)

    elif chain_mode == 'MIDDLE':
        if hmac_state is None:
            logger.error('HMV MIDDLE: no hmac_state available')
            return encode_response(
                request.handle, RC_ERROR, 3003, ICSF_TAG_CSFPHMV, b'')

        # chain_in holds the 128-byte chain_data from the previous call.
        # The first 16 bytes are the session ID we returned on FIRST.
        sid = chain_in[:16]
        ok = hmac_state.append(sid, text)
        if not ok:
            logger.warning('HMV MIDDLE: session not found (sid=%s)', sid.hex())
            return encode_response(
                request.handle, RC_ERROR, 3004, ICSF_TAG_CSFPHMV, b'')

        logger.info('HMV: token=%r seq=%d algo=%s MIDDLE — accumulated text',
                    token_name, sequence, hash_name)
        return encode_response(request.handle, RC_SUCCESS, 0,
                               ICSF_TAG_CSFPHMV, sid)

    else:  # LAST
        if hmac_state is None:
            logger.error('HMV LAST: no hmac_state available')
            return encode_response(
                request.handle, RC_ERROR, 3003, ICSF_TAG_CSFPHMV, b'')

        # chain_in holds the 128-byte chain_data; first 16 bytes = session ID.
        sid = chain_in[:16]
        result = hmac_state.finalize(sid, text)
        if result is None:
            logger.warning('HMV LAST: session not found (sid=%s)', sid.hex())
            return encode_response(
                request.handle, RC_ERROR, 3004, ICSF_TAG_CSFPHMV, b'')

        k, algo, full_data = result
        try:
            expected = _compute_mac(k, full_data, algo)
        except Exception as exc:
            logger.warning('HMV LAST: HMAC failed (%s): %s', algo, exc)
            expected = b''

        if _hmac_mod.compare_digest(expected, hmac_supplied):
            logger.info('HMV: token=%r seq=%d algo=%s LAST — VERIFIED OK',
                        token_name, sequence, hash_name)
            svc_data = hmac_supplied
            return encode_response(request.handle, RC_SUCCESS, 0,
                                   ICSF_TAG_CSFPHMV, svc_data)
        else:
            logger.info('HMV: token=%r seq=%d algo=%s LAST — FAILED',
                        token_name, sequence, hash_name)
            svc_data = b'\x00' * 16
            return encode_response(request.handle, RC_ERROR, RSN_HMAC_INVALID,
                                   ICSF_TAG_CSFPHMV, svc_data)
