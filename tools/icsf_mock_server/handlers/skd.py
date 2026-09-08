# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
handlers/skd.py — CSFPSKD: Symmetric Key Decrypt (service tag 12).

Request (from icsf_secret_key_decrypt() in icsf.c):

    SKDInput ::= [0] OCTET STRING   initVector
                 [2] OCTET STRING   chainingData
                 [3] OCTET STRING   cipherText
                 [4] INTEGER        clearTextLen    (requested output size)

    Rule array: algorithm (AES/DES/DES3) + cipher mode (ECB/CBC/CBC-PAD)
                + chaining mode (ONLY/INITIAL/CONTINUE/FINAL)

    Note: ber_printf wrote "totototi" — explicit context tags 0,2,3,4.

Response:
    SKDOutput ::= SEQUENCE {
        chainingData   OCTET STRING,
        clearText      OCTET STRING,
        clearTextLen   INTEGER
    }

Cipher modes
------------
* ECB     — AES-ECB; IV ignored
* CBC     — AES-CBC; IV from initVector (INITIAL/ONLY) or chainingData (CONTINUE/FINAL)
* CBC-PAD — AES-CBC with PKCS#7 unpadding on the final block

The chainingData returned is the last *ciphertext* block before decryption,
so the client can chain subsequent blocks correctly.
"""

import logging

from cipher_backend import aes_decrypt, AES_BLOCK, DES_BLOCK
from ber_codec import (
    encode_response, encode_octet_string, encode_integer,
    parse_handle, _decode_tlv, decode_integer
)
from pkcs11_const import CKA_VALUE

logger = logging.getLogger(__name__)

ICSF_TAG_CSFPSKD = 12

RC_SUCCESS        = 0
RC_ERROR          = 8
RSN_OBJ_NOT_FOUND = 3025


def handle_skd(store, request):
    """
    Process a CSFPSKD request.

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
        logger.error('SKD: invalid handle (token=%r seq=%d)', token_name, sequence)
        return encode_response(
            request.handle, RC_ERROR, 3001, ICSF_TAG_CSFPSKD, b'')

    obj = store.get_object(token_name, sequence)
    if obj is None:
        logger.warning('SKD: key not found token=%r seq=%d', token_name, sequence)
        return encode_response(
            request.handle, RC_ERROR, RSN_OBJ_NOT_FOUND, ICSF_TAG_CSFPSKD, b'')

    key_value = obj.get_attr(CKA_VALUE) or b''

    # Parse SKDInput — ber_printf wrote "totototi":
    #   tag0 OCTET STRING   init_vector
    #   tag2 OCTET STRING   chaining_data
    #   tag3 OCTET STRING   cipher_text
    #   tag4 INTEGER        requested_clear_len
    try:
        pos = 0
        _, init_vec, pos    = _decode_tlv(request.service_data, pos)  # [0]
        _, chain_in, pos    = _decode_tlv(request.service_data, pos)  # [2]
        _, cipher_text, pos = _decode_tlv(request.service_data, pos)  # [3]
        _, req_len_val, pos = _decode_tlv(request.service_data, pos)  # [4]
        req_len = decode_integer(req_len_val)
    except Exception as exc:
        logger.warning('SKD: failed to decode SKDInput: %s', exc)
        return encode_response(
            request.handle, RC_ERROR, 3002, ICSF_TAG_CSFPSKD, b'')

    # Determine algorithm and cipher mode from rule array.
    # DES2 (16-byte key) uses the 'DES' rule in the ICSF protocol; the correct
    # cipher (EVP_des_ede3_*) is chosen automatically in cipher_backend based
    # on the actual key length.  Accept 'DES2' explicitly as well for any
    # future caller that sends it.
    algo        = 'AES'
    cipher_mode = 'ECB'
    chain_mode  = 'ONLY'
    for rule in request.rule_array:
        upper = rule.upper()
        if upper in ('AES', 'DES', 'DES2', 'DES3'):
            algo = upper if upper != 'DES2' else 'DES'
        elif upper in ('ECB', 'CBC', 'CBC-PAD'):
            cipher_mode = upper
        elif upper in ('ONLY', 'INITIAL', 'CONTINUE', 'FINAL'):
            chain_mode = upper

    try:
        clear_text, chain_out = _do_decrypt(
            key_value, algo, cipher_mode, chain_mode,
            init_vec, chain_in, cipher_text)
    except Exception as exc:
        logger.error('SKD: decrypt failed: %s', exc)
        return encode_response(
            request.handle, RC_ERROR, RC_ERROR, ICSF_TAG_CSFPSKD, b'')

    # Build SKDOutput: { chainingData OCTET STRING, clearText OCTET STRING,
    #                    clearTextLen INTEGER }
    svc_data = (
        encode_octet_string(chain_out) +
        encode_octet_string(clear_text) +
        encode_integer(len(clear_text))
    )

    logger.info('SKD: token=%r seq=%d algo=%s mode=%s chain=%s cipher=%d clear=%d',
                token_name, sequence, algo, cipher_mode, chain_mode,
                len(cipher_text), len(clear_text))

    return encode_response(request.handle, RC_SUCCESS, 0, ICSF_TAG_CSFPSKD, svc_data)


def _do_decrypt(key_value, algo, cipher_mode, chain_mode, init_vec, chain_in, cipher_text):
    """
    Perform real symmetric decryption.

    Returns (clear_text, chain_out) where chain_out is the last ciphertext
    block (the client uses it as the IV for the next CONTINUE/FINAL call).
    """
    block_size = AES_BLOCK if algo == 'AES' else DES_BLOCK

    # Determine IV: CONTINUE/FINAL use chain_in from previous response;
    # INITIAL/ONLY use the init_vector supplied in the request.
    if chain_mode in ('CONTINUE', 'FINAL'):
        iv = (chain_in or b'').ljust(block_size, b'\x00')[:block_size]
    else:
        iv = (init_vec or b'').ljust(block_size, b'\x00')[:block_size]

    # Save the last ciphertext block *before* decryption so we can return it
    # as chain_out (the client uses it as IV for the next chunk).
    chain_out = cipher_text[-block_size:] if len(cipher_text) >= block_size else iv

    # For CBC-PAD, PKCS#7 unpadding is only applied on the FINAL/ONLY call.
    # INITIAL/CONTINUE chunks are block-aligned with no padding to strip.
    pad = (cipher_mode == 'CBC-PAD') and (chain_mode in ('ONLY', 'FINAL'))
    clear_text = aes_decrypt(key_value, cipher_text, cipher_mode, iv,
                             algo=algo, pad=pad)
    return clear_text, chain_out
