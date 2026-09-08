# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
handlers/sav.py — CSFPSAV: Set Attribute Value (service tag 11).

Request (from icsf_set_attribute() in icsf.c):

    SAVInput ::= Attributes   -- same encoding as icsf_ber_put_attribute_list()

    The attribute list is the *direct contents* of the context-constructed TLV
    (no wrapping SEQUENCE around the list items — the outer SEQUENCE is the
    context TLV itself).

Response:

    SAVOutput ::= NULL   -- no service-specific output; just check rc/reason.

The handle identifies the object to update (token_name + sequence + type).

Attribute enforcement rules (mirrors the real ICSF server behaviour and the
checks that icsftok_set_attribute_value performs in icsf_specific.c):

  1. If CKA_MODIFIABLE is FALSE on the object: rc=8, reason=3034
     (mapped to CKR_ACTION_PROHIBITED in icsf_to_ock_err).
     icsf_specific.c enforces this before calling the server; the mock
     enforces it as a safety net using the same rc/reason pair.

  2. CKA_MODIFIABLE is read-only after creation: rc=8, reason=3035
     (mapped to CKR_ATTRIBUTE_READ_ONLY in icsf_to_ock_err).

  3. CKA_COPYABLE cannot be set back to TRUE once FALSE: rc=8, reason=3035
     (mapped to CKR_ATTRIBUTE_READ_ONLY in icsf_to_ock_err).

  4. CKA_TRUSTED=TRUE may only be set by the SO: the server cannot know the
     login state — this check is done exclusively in icsf_specific.c.
"""

import logging
from ber_codec import (
    encode_response, encode_sequence,
    decode_attribute_list,
    parse_handle
)
from pkcs11_const import CKA_MODIFIABLE, CKA_COPYABLE

logger = logging.getLogger(__name__)

ICSF_TAG_CSFPSAV = 11

RC_SUCCESS        = 0
RC_ERROR          = 8
RSN_OBJ_NOT_FOUND    = 3025
RSN_NOT_MODIFIABLE   = 3034   # CKA_MODIFIABLE=FALSE      (→ CKR_ACTION_PROHIBITED)
RSN_ATTR_READ_ONLY   = 3035   # attribute is read-only    (→ CKR_ATTRIBUTE_READ_ONLY)
RSN_ATTR_READ_ONLY2  = 3035   # CKA_COPYABLE once-false   (→ CKR_ATTRIBUTE_READ_ONLY)


def _get_bool(obj, attr_type):
    """Return the boolean value of *attr_type* from obj.attributes, or None."""
    v = obj.attributes.get(attr_type)
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray)):
        return bool(v[0]) if v else False
    return bool(v)


def handle_sav(store, request):
    """
    Process a CSFPSAV request.

    Parameters
    ----------
    store   : TokenStore
    request : ICSFRequest

    Returns
    -------
    bytes — raw BER responseValue
    """
    token_name, sequence, obj_type = parse_handle(request.handle)

    if not token_name or sequence == 0:
        logger.error('SAV: invalid handle (token=%r seq=%d)', token_name, sequence)
        return encode_response(
            request.handle, RC_ERROR, 3001, ICSF_TAG_CSFPSAV, b'')

    # service_data is the raw BER contents of the context-constructed TLV.
    # icsf_set_attribute() calls icsf_ber_put_attribute_list() which writes a
    # SEQUENCE OF SEQUENCE directly; we need to wrap it in a SEQUENCE tag so
    # decode_attribute_list() can parse it.
    attrs = []
    try:
        wrapped = encode_sequence(request.service_data)
        attrs = decode_attribute_list(wrapped)
    except Exception as exc:
        logger.warning('SAV: could not decode attribute list: %s', exc)

    obj = store.get_object(token_name, sequence)
    if not obj:
        logger.warning('SAV: object not found token=%r seq=%d', token_name, sequence)
        return encode_response(
            request.handle, RC_ERROR, RSN_OBJ_NOT_FOUND, ICSF_TAG_CSFPSAV, b'')

    # --- Attribute enforcement ---

    # Rule 1: CKA_MODIFIABLE=FALSE means no attribute may be changed.
    modifiable = _get_bool(obj, CKA_MODIFIABLE)
    if modifiable is False:
        logger.info('SAV: token=%r seq=%d: object not modifiable', token_name, sequence)
        return encode_response(
            request.handle, RC_ERROR, RSN_NOT_MODIFIABLE, ICSF_TAG_CSFPSAV, b'')

    # Rule 2 & 3: check each attribute being set.
    copyable = _get_bool(obj, CKA_COPYABLE)
    for attr_type, attr_value in attrs:
        if attr_type == CKA_MODIFIABLE:
            # CKA_MODIFIABLE is read-only after creation.
            logger.info('SAV: token=%r seq=%d: attempt to set CKA_MODIFIABLE',
                        token_name, sequence)
            return encode_response(
                request.handle, RC_ERROR, RSN_ATTR_READ_ONLY, ICSF_TAG_CSFPSAV, b'')

        if attr_type == CKA_COPYABLE:
            # CKA_COPYABLE can only be set to FALSE; once FALSE it cannot go back.
            new_val = bool(attr_value) if isinstance(attr_value, int) \
                else (bool(attr_value[0]) if isinstance(attr_value, (bytes, bytearray)) and attr_value
                      else False)
            if copyable is False and new_val is True:
                logger.info('SAV: token=%r seq=%d: CKA_COPYABLE cannot be set back to TRUE',
                            token_name, sequence)
                return encode_response(
                    request.handle, RC_ERROR, RSN_ATTR_READ_ONLY2, ICSF_TAG_CSFPSAV, b'')

    logger.info('SAV: token=%r seq=%d setting %d attributes',
                token_name, sequence, len(attrs))

    store.set_object_attrs(token_name, sequence, attrs)

    # SAVOutput is NULL — no service data
    return encode_response(request.handle, RC_SUCCESS, 0, ICSF_TAG_CSFPSAV, b'')
