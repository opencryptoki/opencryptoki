# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
handlers/ske.py — CSFPSKE: Symmetric Key Encrypt (service tag 13).

Request (from icsf_secret_key_encrypt() in icsf.c):

    SKEInput ::= [0] OCTET STRING   initVector
                 OCTET STRING       chainingData    (length from request)
                 OCTET STRING       clearText
                 INTEGER            cipherTextLen   (requested output size)

    Rule array: algorithm (AES/DES/DES3) + cipher mode (ECB/CBC/CBC-PAD)
                + chaining mode (ONLY/INITIAL/CONTINUE/FINAL)

Response:
    SKEOutput ::= SEQUENCE {
        chainingData   OCTET STRING,
        cipherText     OCTET STRING,
        cipherTextLen  INTEGER
    }

Cipher modes
------------
* ECB  — AES-ECB; IV is always ignored (zeros sent by client too)
* CBC  — AES-CBC; IV comes from initVector on INITIAL/ONLY; on CONTINUE/FINAL
         the IV comes from chainingData (the last ciphertext block returned by
         the previous call, echoed back by this handler)
* CBC-PAD — same as CBC but with PKCS#7 padding applied

The chainingData returned is the *last ciphertext block* (16 bytes for AES),
which the ICSF token uses as the IV for the next CONTINUE/FINAL call.
"""

import logging

from cipher_backend import aes_encrypt, AES_BLOCK, DES_BLOCK
from ber_codec import (
    encode_response, encode_octet_string, encode_integer,
    parse_handle, _decode_tlv, decode_integer
)
from pkcs11_const import CKA_VALUE

logger = logging.getLogger(__name__)

ICSF_TAG_CSFPSKE = 13

RC_SUCCESS        = 0
RC_ERROR          = 8
RSN_OBJ_NOT_FOUND = 3025
RSN_TOO_SHORT     = 3003


def handle_ske(store, request):
    """
    Process a CSFPSKE request.

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
        logger.error('SKE: invalid handle (token=%r seq=%d)', token_name, sequence)
        return encode_response(
            request.handle, RC_ERROR, 3001, ICSF_TAG_CSFPSKE, b'')

    obj = store.get_object(token_name, sequence)
    if obj is None:
        logger.warning('SKE: key not found token=%r seq=%d', token_name, sequence)
        return encode_response(
            request.handle, RC_ERROR, RSN_OBJ_NOT_FOUND, ICSF_TAG_CSFPSKE, b'')

    key_value = obj.get_attr(CKA_VALUE) or b''

    # Parse SKEInput — the fields are laid out flat inside the service context.
    # ber_printf wrote: "toooi" meaning:
    #   [0] OCTET STRING    init_vector
    #   OCTET STRING        chaining_data
    #   OCTET STRING        clear_text
    #   INTEGER             requested_cipher_len
    try:
        pos = 0
        # [0] context-primitive init vector
        _, init_vec, pos = _decode_tlv(request.service_data, pos)
        # chaining data
        _, chain_in, pos = _decode_tlv(request.service_data, pos)
        # clear text
        _, clear_text, pos = _decode_tlv(request.service_data, pos)
        # requested output size
        _, req_len_val, pos = _decode_tlv(request.service_data, pos)
        req_len = decode_integer(req_len_val)
    except Exception as exc:
        logger.warning('SKE: failed to decode SKEInput: %s', exc)
        return encode_response(
            request.handle, RC_ERROR, 3002, ICSF_TAG_CSFPSKE, b'')

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
        cipher_text, chain_out = _do_encrypt(
            key_value, algo, cipher_mode, chain_mode,
            init_vec, chain_in, clear_text)
    except Exception as exc:
        logger.error('SKE: encrypt failed: %s', exc)
        return encode_response(
            request.handle, RC_ERROR, RC_ERROR, ICSF_TAG_CSFPSKE, b'')

    # Build SKEOutput: { chainingData OCTET STRING, cipherText OCTET STRING,
    #                    cipherTextLen INTEGER }
    svc_data = (
        encode_octet_string(chain_out) +
        encode_octet_string(cipher_text) +
        encode_integer(len(cipher_text))
    )

    logger.info('SKE: token=%r seq=%d algo=%s mode=%s chain=%s clear=%d cipher=%d',
                token_name, sequence, algo, cipher_mode, chain_mode,
                len(clear_text), len(cipher_text))

    return encode_response(request.handle, RC_SUCCESS, 0, ICSF_TAG_CSFPSKE, svc_data)


def _do_encrypt(key_value, algo, cipher_mode, chain_mode, init_vec, chain_in, clear_text):
    """
    Perform real symmetric encryption.

    Returns (cipher_text, chain_out) where chain_out is the last ciphertext
    block (used as IV by the client on the next CONTINUE/FINAL call).
    """
    block_size = AES_BLOCK if algo == 'AES' else DES_BLOCK

    # Determine IV: CONTINUE/FINAL use chain_in from previous response;
    # INITIAL/ONLY use the init_vector supplied in the request.
    if chain_mode in ('CONTINUE', 'FINAL'):
        iv = (chain_in or b'').ljust(block_size, b'\x00')[:block_size]
    else:
        iv = (init_vec or b'').ljust(block_size, b'\x00')[:block_size]

    # For CBC-PAD, PKCS#7 padding is only applied on the FINAL/ONLY call.
    # INITIAL/CONTINUE chunks are block-aligned with no padding.
    pad = (cipher_mode == 'CBC-PAD') and (chain_mode in ('ONLY', 'FINAL'))
    cipher_text = aes_encrypt(key_value, clear_text, cipher_mode, iv,
                              algo=algo, pad=pad)
    chain_out = cipher_text[-block_size:] if cipher_text else b'\x00' * block_size
    return cipher_text, chain_out
