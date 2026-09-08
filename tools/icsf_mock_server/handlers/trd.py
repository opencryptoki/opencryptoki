# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
handlers/trd.py — CSFPTRD: Token/Object Destroy (service tag 15).

Both token and object destroy share the same service tag; the rule array
distinguishes them:
  TOKEN   -> destroy a token (identified by the 32-byte token name in the handle)
  OBJECT  -> destroy an object (identified by full 44-byte object handle)

No service-specific input data is required by the client (icsf.c passes NULL).
No service-specific output data is produced; the response envelope alone suffices.
"""

import logging
from ber_codec import (
    encode_response, parse_handle, make_token_handle, make_object_handle
)

logger = logging.getLogger(__name__)

ICSF_TAG_CSFPTRD = 15

RC_SUCCESS = 0
RC_ERROR   = 8
RSN_TOKEN_NOT_FOUND  = 3024
RSN_OBJECT_NOT_FOUND = 3025


def handle_trd(store, request):
    """
    Process a CSFPTRD request.

    Parameters
    ----------
    store   : TokenStore
    request : ICSFRequest

    Returns
    -------
    bytes — raw BER responseValue
    """
    rules = request.rule_array

    if 'TOKEN' in rules:
        return _handle_destroy_token(store, request)
    elif 'OBJECT' in rules:
        return _handle_destroy_object(store, request)
    else:
        logger.warning('TRD: unrecognised rule array: %s', rules)
        return encode_response(
            request.handle, RC_ERROR, 3000, ICSF_TAG_CSFPTRD, b'')


def _handle_destroy_token(store, request):
    token_name, _, _ = parse_handle(request.handle)
    if not token_name:
        return encode_response(
            request.handle, RC_ERROR, 3001, ICSF_TAG_CSFPTRD, b'')

    logger.info('TRD: destroying token name=%r', token_name)

    if not store.destroy_token(token_name):
        logger.warning('TRD TOKEN: token %r not found', token_name)
        return encode_response(
            request.handle, RC_ERROR, RSN_TOKEN_NOT_FOUND, ICSF_TAG_CSFPTRD, b'')

    # After destruction the handle is zeroed (blanked)
    blank_handle = b' ' * 44
    return encode_response(blank_handle, RC_SUCCESS, 0, ICSF_TAG_CSFPTRD, b'')


def _handle_destroy_object(store, request):
    token_name, sequence, obj_type = parse_handle(request.handle)
    if not token_name:
        return encode_response(
            request.handle, RC_ERROR, 3001, ICSF_TAG_CSFPTRD, b'')

    logger.info('TRD: destroying object token=%r seq=%d type=%s',
                token_name, sequence, obj_type)

    if not store.destroy_object(token_name, sequence):
        logger.warning('TRD OBJECT: object seq=%d not found in token %r',
                       sequence, token_name)
        return encode_response(
            request.handle, RC_ERROR, RSN_OBJECT_NOT_FOUND, ICSF_TAG_CSFPTRD, b'')

    blank_handle = b' ' * 44
    return encode_response(blank_handle, RC_SUCCESS, 0, ICSF_TAG_CSFPTRD, b'')
