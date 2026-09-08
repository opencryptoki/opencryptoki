# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
handlers/owh.py — CSFPOWH: One-Way Hash with sign/verify (service tag 8).

This service is called by icsf_hash_signverify() in icsf.c for all combined
hash-then-sign / hash-then-verify mechanisms:

    CKM_SHA1_RSA_PKCS, CKM_SHA224_RSA_PKCS, CKM_SHA256_RSA_PKCS,
    CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS, CKM_MD5_RSA_PKCS,
    CKM_DSA_SHA1,
    CKM_ECDSA_SHA1..CKM_ECDSA_SHA512

Request (ber_printf "ooo" in icsf_hash_signverify):

    OWHInput ::= (flat, no outer SEQUENCE)
        clearText   OCTET STRING   -- data to hash / sign / verify
        chainData   OCTET STRING   -- opaque chaining state (zeros on FIRST)
        signature   OCTET STRING   -- sig buffer for sign (empty); sig to
                                   --   check for verify

Rule array — three 8-byte items:
    [0]  hash name         e.g. "SHA-1   "  (padded)
    [1]  operation         e.g. "SIGN-RSA"  (or VER-RSA / SIGN-EC / VER-EC)
    [2]  chaining mode     e.g. "ONLY    "

Response (ber_scanf "{ooi}" in icsf_hash_signverify):

    OWHOutput ::= (wrapped in a context TLV by encode_response)
        chainData   OCTET STRING   -- opaque chain blob (FIRST/MIDDLE only);
                                   --   EMPTY on ONLY/LAST — client buffer is
                                   --   fixed at ICSF_CHAINING_DATA_LEN=128 bytes
        signature   OCTET STRING   -- signature (ONLY/LAST) or empty (FIRST/MIDDLE)
        length      INTEGER        -- byte length of the signature

Multi-part chaining:
    FIRST  — start a new session; accumulate clearText; return session ID
    MIDDLE — look up session; accumulate clearText; return same session ID
    LAST   — look up session; accumulate clearText; compute signature/verify
    ONLY   — stateless single-call

For verify calls (VER-RSA / VER-EC / VER-DSA / VER-EC) the response carries
empty chain/sig on success and rc=8/reason=11028 on failure.  The length field
is always 0 for verify.
"""

import logging
import os

from ber_codec import (
    encode_response, encode_octet_string, encode_integer,
    parse_handle, _decode_tlv,
)
from pkcs11_const import CKA_KEY_TYPE, CKA_EC_PARAMS, CKA_SUBPRIME, CKK_EC, CKK_DSA
from rsa_backend import rsa_private_sign, rsa_public_verify
from ec_backend import ec_max_sig_len, _field_size, _der_sig_to_raw, _raw_sig_to_der
from dsa_backend import dsa_max_sig_len, dsa_sign, dsa_verify

logger = logging.getLogger(__name__)

ICSF_TAG_CSFPOWH = 8

RC_SUCCESS        = 0
RC_ERROR          = 8
RSN_OBJ_NOT_FOUND = 3025
RSN_TOO_SHORT     = 3003
RSN_SIG_INVALID   = 11028   # maps to CKR_SIGNATURE_INVALID in icsf_to_ock_err()

# ---------------------------------------------------------------------------
# Simple in-process session store for multi-part operations.
# Maps session_id (bytes) -> {'data': bytes, 'algo': str, 'op': str,
#                              'attrs': dict, 'key_type': int}
# ---------------------------------------------------------------------------
_sessions = {}
_sessions_lock = __import__('threading').Lock()


def _session_create(attrs, algo, op, key_type):
    sid = os.urandom(16)
    with _sessions_lock:
        _sessions[sid] = {
            'data':     b'',
            'algo':     algo,
            'op':       op,
            'attrs':    attrs,
            'key_type': key_type,
        }
    return sid


def _session_append(sid, data):
    with _sessions_lock:
        s = _sessions.get(sid)
        if s is None:
            return False
        s['data'] += data
        return True


def _session_finalize(sid, data):
    with _sessions_lock:
        s = _sessions.pop(sid, None)
    if s is None:
        return None
    s['data'] += data
    return s


def _session_peek(sid):
    """Return a copy of the session state without removing it (for size queries)."""
    with _sessions_lock:
        s = _sessions.get(sid)
        if s is None:
            return None
        return dict(s)  # shallow copy; 'data' is bytes (immutable), safe


# ---------------------------------------------------------------------------
# EC helpers — delegate to ec_backend which handles DER wrap/unwrap,
# curve name lookup, and OpenSSL version differences.
# ---------------------------------------------------------------------------

def _build_ec_pkey(attr_dict, private):
    """
    Build an EVP_PKEY* for an EC key from PKCS#11 attributes.
    Delegates to ec_backend._build_ec_pkey which handles the DER-wrapped
    CKA_EC_POINT, full brainpool/NIST curve table, and OpenSSL 1.1/3 paths.
    Caller must free with ec_backend._EVP_PKEY_free.
    """
    from ec_backend import _build_ec_pkey as _ec_build_ec_pkey, CurveNotSupportedError
    return _ec_build_ec_pkey(attr_dict, private)


def _ec_sign(attr_dict, data, hash_name):
    """Sign with ECDSA — delegates to EVP_DigestSign via a built pkey.

    For hash algorithms that OpenSSL 3.5 blocks in EVP_DigestSignInit (SHA-1,
    MD5), we pre-hash with EVP_DigestInit/Update/Final and pass NULL as the md
    to EVP_DigestSignInit so the sign context does no hashing of its own.
    The pre-computed digest is then passed directly to EVP_DigestSignFinal.
    """
    from rsa_backend import (
        _EVP_MD_CTX_new, _EVP_MD_CTX_free,
        _get_md, _free_md, _EVP_DigestSignInit,
        _EVP_DigestSignUpdate, _EVP_DigestSignFinal,
        _EVP_PKEY_free, _ossl_err_str,
        _OPENSSL3, _OSSL3_SIGN_BLOCKED, _compute_digest,
    )
    import ctypes

    pkey = _build_ec_pkey(attr_dict, private=True)
    ctx  = _EVP_MD_CTX_new()
    if not ctx:
        _EVP_PKEY_free(pkey)
        raise RuntimeError('EVP_MD_CTX_new failed (EC sign)')
    try:
        pctx = ctypes.c_void_p(None)
        if _OPENSSL3 and hash_name in _OSSL3_SIGN_BLOCKED:
            # Pre-hash then sign the raw digest with md=NULL in context
            digest = _compute_digest(data, hash_name)
            if _EVP_DigestSignInit(ctx, ctypes.byref(pctx),
                                   None, None, pkey) != 1:
                raise RuntimeError('EVP_DigestSignInit(md=NULL) failed (EC): %s'
                                   % _ossl_err_str())
            if _EVP_DigestSignUpdate(ctx, digest, len(digest)) != 1:
                raise RuntimeError('EVP_DigestSignUpdate failed (EC pre-hash): %s'
                                   % _ossl_err_str())
        else:
            md, md_nf = _get_md(hash_name)
            try:
                if _EVP_DigestSignInit(ctx, ctypes.byref(pctx),
                                       md, None, pkey) != 1:
                    raise RuntimeError('EVP_DigestSignInit failed (EC): %s'
                                       % _ossl_err_str())
            finally:
                _free_md(md, md_nf)
            if _EVP_DigestSignUpdate(ctx, data, len(data)) != 1:
                raise RuntimeError('EVP_DigestSignUpdate failed (EC): %s'
                                   % _ossl_err_str())
        sig_len = ctypes.c_size_t(0)
        if _EVP_DigestSignFinal(ctx, None, ctypes.byref(sig_len)) != 1:
            raise RuntimeError('EVP_DigestSignFinal size query failed (EC): %s'
                               % _ossl_err_str())
        sig_buf = ctypes.create_string_buffer(sig_len.value)
        if _EVP_DigestSignFinal(ctx, sig_buf, ctypes.byref(sig_len)) != 1:
            raise RuntimeError('EVP_DigestSignFinal failed (EC): %s' % _ossl_err_str())
        der_sig = sig_buf.raw[:sig_len.value]
        n = _field_size(attr_dict.get(CKA_EC_PARAMS, b''))
        return _der_sig_to_raw(der_sig, n)
    finally:
        _EVP_MD_CTX_free(ctx)
        _EVP_PKEY_free(pkey)


# ---------------------------------------------------------------------------
# Main handler
# ---------------------------------------------------------------------------

def handle_owh(store, request, owh_state=None):
    """
    Process a CSFPOWH (One-Way Hash sign/verify) request.

    owh_state is not used; multi-part state is kept in the module-level
    _sessions dict (same process, single mock server instance).
    """
    token_name, sequence, _ = parse_handle(request.handle)
    if not token_name or sequence == 0:
        logger.error('OWH: invalid handle (token=%r seq=%d)', token_name, sequence)
        return encode_response(request.handle, RC_ERROR, 3001, ICSF_TAG_CSFPOWH, b'')

    obj = store.get_object(token_name, sequence)
    if obj is None:
        logger.warning('OWH: key not found token=%r seq=%d', token_name, sequence)
        return encode_response(request.handle, RC_ERROR, RSN_OBJ_NOT_FOUND,
                               ICSF_TAG_CSFPOWH, b'')

    # Rule array:  rules[0] = hash name, rules[1] = op, rules[2] = chain mode
    rules     = request.rule_array
    hash_name = rules[0].strip() if len(rules) > 0 else 'SHA-256'
    op        = rules[1].strip() if len(rules) > 1 else 'SIGN-RSA'
    chain_mode = rules[2].strip() if len(rules) > 2 else 'ONLY'

    is_verify = op.startswith('VER-')

    # Determine key type so we can dispatch to the right crypto backend
    key_type_raw = obj.get_attr(CKA_KEY_TYPE)
    if isinstance(key_type_raw, int):
        key_type = key_type_raw
    elif key_type_raw:
        key_type = int.from_bytes(key_type_raw, 'big')
    else:
        key_type = 0   # assume RSA

    # Parse OWHInput: three OCTET STRINGs (flat, no outer SEQUENCE)
    try:
        pos = 0
        _, clear_text, pos  = _decode_tlv(request.service_data, pos)
        _, chain_in,   pos  = _decode_tlv(request.service_data, pos)
        _, sig_in,     pos  = _decode_tlv(request.service_data, pos)
    except Exception as exc:
        logger.warning('OWH: failed to decode OWHInput: %s', exc)
        return encode_response(request.handle, RC_ERROR, 3002, ICSF_TAG_CSFPOWH, b'')

    # Reconstruct the 16-char mech rule that rsa_backend expects.
    # The C code packs it as "SHA-1   SIGN-RSA" (hash padded to 8 chars + op).
    mech_rule = '%-8s%s' % (hash_name, op)

    # -----------------------------------------------------------------
    # Dispatch by chaining mode
    # -----------------------------------------------------------------

    if chain_mode == 'ONLY':
        # Single-call: process all of clear_text now.
        # sig_in is empty when the caller is doing a size query (signature==NULL).
        if is_verify:
            return _do_verify(request.handle, obj.attributes, clear_text,
                              sig_in, mech_rule, hash_name, op, key_type,
                              token_name, sequence)
        else:
            return _do_sign(request.handle, obj.attributes, clear_text,
                            mech_rule, hash_name, op, key_type,
                            token_name, sequence,
                            size_query=(len(sig_in) == 0))

    elif chain_mode == 'FIRST':
        # Start multi-part; chain_in is all-zeros on entry
        sid = _session_create(obj.attributes, hash_name, op, key_type)
        ok  = _session_append(sid, clear_text)
        if not ok:
            return encode_response(request.handle, RC_ERROR, 3003,
                                   ICSF_TAG_CSFPOWH, b'')
        chain_out = sid
        svc_data = (encode_octet_string(chain_out) +
                    encode_octet_string(b'') +
                    encode_integer(0))
        logger.info('OWH FIRST: token=%r seq=%d op=%s hash=%s sid=%s',
                    token_name, sequence, op, hash_name, sid.hex())
        return encode_response(request.handle, RC_SUCCESS, 0,
                               ICSF_TAG_CSFPOWH, svc_data)

    elif chain_mode == 'MIDDLE':
        sid = chain_in[:16]
        if not _session_append(sid, clear_text):
            logger.warning('OWH MIDDLE: session not found (sid=%s)', sid.hex())
            return encode_response(request.handle, RC_ERROR, 3004,
                                   ICSF_TAG_CSFPOWH, b'')
        svc_data = (encode_octet_string(sid) +
                    encode_octet_string(b'') +
                    encode_integer(0))
        return encode_response(request.handle, RC_SUCCESS, 0,
                               ICSF_TAG_CSFPOWH, svc_data)

    elif chain_mode == 'LAST':
        sid = chain_in[:16]
        # Size query: sig_in is empty when the caller passes sig==NULL to
        # icsf_hash_signverify().  Peek at the session without consuming it so
        # the subsequent real LAST call can still find it.
        is_size_query = (not is_verify) and (len(sig_in) == 0)

        if is_size_query:
            state = _session_peek(sid)
            if state is None:
                logger.warning('OWH LAST: session not found (sid=%s)', sid.hex())
                return encode_response(request.handle, RC_ERROR, 3004,
                                       ICSF_TAG_CSFPOWH, b'')
            full_data = state['data'] + clear_text
        else:
            state = _session_finalize(sid, clear_text)
            if state is None:
                logger.warning('OWH LAST: session not found (sid=%s)', sid.hex())
                return encode_response(request.handle, RC_ERROR, 3004,
                                       ICSF_TAG_CSFPOWH, b'')
            full_data = state['data']

        attrs       = state['attrs']
        kt          = state['key_type']
        mech_rule_s = '%-8s%s' % (state['algo'], state['op'])

        if is_verify:
            return _do_verify(request.handle, attrs, full_data,
                              sig_in, mech_rule_s, state['algo'], state['op'],
                              kt, token_name, sequence)
        else:
            return _do_sign(request.handle, attrs, full_data,
                            mech_rule_s, state['algo'], state['op'],
                            kt, token_name, sequence,
                            size_query=is_size_query)

    else:
        logger.warning('OWH: unknown chain mode %r', chain_mode)
        return encode_response(request.handle, RC_ERROR, 3002,
                               ICSF_TAG_CSFPOWH, b'')


def _do_sign(handle, attrs, data, mech_rule, hash_name, op, key_type,
             token_name, sequence, size_query=False):
    # Size query for EC/DSA: return the fixed raw signature size without
    # performing a real sign.
    if size_query and key_type == CKK_EC:
        ec_params = attrs.get(CKA_EC_PARAMS, b'') if isinstance(attrs, dict) else b''
        sig_len = ec_max_sig_len(ec_params)
        svc_data = (encode_octet_string(b'') +
                    encode_octet_string(b'') +
                    encode_integer(sig_len))
        return encode_response(handle, RC_ERROR, RSN_TOO_SHORT,
                               ICSF_TAG_CSFPOWH, svc_data)
    if size_query and key_type == CKK_DSA:
        sig_len = dsa_max_sig_len(attrs.get(CKA_SUBPRIME, b'')
                                  if isinstance(attrs, dict) else b'')
        svc_data = (encode_octet_string(b'') +
                    encode_octet_string(b'') +
                    encode_integer(sig_len))
        return encode_response(handle, RC_ERROR, RSN_TOO_SHORT,
                               ICSF_TAG_CSFPOWH, svc_data)

    try:
        if key_type == CKK_EC:
            sig = _ec_sign(attrs, data, hash_name)
        elif key_type == CKK_DSA:
            sig = dsa_sign(attrs, data)
        else:
            sig = rsa_private_sign(attrs, data, mech_rule)
    except Exception as exc:
        logger.error('OWH sign failed (op=%r): %s', op, exc, exc_info=True)
        return encode_response(handle, RC_ERROR, RC_ERROR, ICSF_TAG_CSFPOWH, b'')

    # Size query for RSA: performed a real sign to measure length
    if size_query:
        svc_data = (encode_octet_string(b'') +
                    encode_octet_string(b'') +
                    encode_integer(len(sig)))
        return encode_response(handle, RC_ERROR, RSN_TOO_SHORT,
                               ICSF_TAG_CSFPOWH, svc_data)

    # chainData must be EMPTY on ONLY/LAST responses.  The C client allocates
    # exactly ICSF_CHAINING_DATA_LEN (128) bytes for it; returning the full
    # signature there would overflow the buffer for keys larger than 1024 bits.
    svc_data = (encode_octet_string(b'') +
                encode_octet_string(sig) +
                encode_integer(len(sig)))
    logger.info('OWH sign: token=%r seq=%d mech=%r sig=%d bytes',
                token_name, sequence, mech_rule.strip(), len(sig))
    return encode_response(handle, RC_SUCCESS, 0, ICSF_TAG_CSFPOWH, svc_data)


def _do_verify(handle, attrs, data, signature, mech_rule, hash_name, op,
               key_type, token_name, sequence):
    try:
        if key_type == CKK_EC:
            # Build public key attrs from object for verify
            valid = _ec_verify(attrs, data, signature, hash_name)
        elif key_type == CKK_DSA:
            valid = dsa_verify(attrs, data, signature)
        else:
            valid = rsa_public_verify(attrs, data, signature, mech_rule)
    except Exception as exc:
        logger.error('OWH verify failed (op=%r): %s', op, exc)
        return encode_response(handle, RC_ERROR, RC_ERROR, ICSF_TAG_CSFPOWH, b'')

    if not valid:
        logger.warning('OWH verify: signature invalid token=%r seq=%d', token_name, sequence)
        return encode_response(handle, RC_ERROR, RSN_SIG_INVALID,
                               ICSF_TAG_CSFPOWH, b'')

    svc_data = (encode_octet_string(b'') +
                encode_octet_string(b'') +
                encode_integer(0))
    logger.info('OWH verify: token=%r seq=%d mech=%r — OK', token_name, sequence, mech_rule.strip())
    return encode_response(handle, RC_SUCCESS, 0, ICSF_TAG_CSFPOWH, svc_data)


def _ec_verify(attrs, data, signature, hash_name):
    """EC verify using OpenSSL EVP — delegates to EVP_DigestVerify via a built pkey.

    Same SHA-1/MD5 workaround as _ec_sign: pre-hash and pass md=NULL to the
    verify context on OpenSSL 3.5 to avoid the signing-policy restriction.
    """
    from rsa_backend import (
        _EVP_MD_CTX_new, _EVP_MD_CTX_free,
        _get_md, _free_md, _EVP_DigestVerifyInit,
        _EVP_DigestVerifyUpdate, _EVP_DigestVerifyFinal,
        _EVP_PKEY_free, _ossl_err_str,
        _OPENSSL3, _OSSL3_SIGN_BLOCKED, _compute_digest,
    )
    import ctypes

    pkey = _build_ec_pkey(attrs, private=False)
    ctx  = _EVP_MD_CTX_new()
    if not ctx:
        _EVP_PKEY_free(pkey)
        raise RuntimeError('EVP_MD_CTX_new failed (EC verify)')
    try:
        pctx = ctypes.c_void_p(None)
        if _OPENSSL3 and hash_name in _OSSL3_SIGN_BLOCKED:
            digest = _compute_digest(data, hash_name)
            if _EVP_DigestVerifyInit(ctx, ctypes.byref(pctx),
                                     None, None, pkey) != 1:
                raise RuntimeError('EVP_DigestVerifyInit(md=NULL) failed (EC): %s'
                                   % _ossl_err_str())
            if _EVP_DigestVerifyUpdate(ctx, digest, len(digest)) != 1:
                raise RuntimeError('EVP_DigestVerifyUpdate failed (EC pre-hash): %s'
                                   % _ossl_err_str())
        else:
            md, md_nf = _get_md(hash_name)
            try:
                if _EVP_DigestVerifyInit(ctx, ctypes.byref(pctx),
                                         md, None, pkey) != 1:
                    raise RuntimeError('EVP_DigestVerifyInit failed (EC): %s'
                                       % _ossl_err_str())
            finally:
                _free_md(md, md_nf)
            if _EVP_DigestVerifyUpdate(ctx, data, len(data)) != 1:
                raise RuntimeError('EVP_DigestVerifyUpdate failed (EC): %s'
                                   % _ossl_err_str())
        n = _field_size(attrs.get(CKA_EC_PARAMS, b''))
        der_sig = _raw_sig_to_der(signature, n)
        return _EVP_DigestVerifyFinal(ctx, der_sig, len(der_sig)) == 1
    finally:
        _EVP_MD_CTX_free(ctx)
        _EVP_PKEY_free(pkey)

