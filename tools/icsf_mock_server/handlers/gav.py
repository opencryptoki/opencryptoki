# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
handlers/gav.py — CSFPGAV: Get Attribute Value (service tag 3).

Request (from icsf_get_attribute() in icsf.c):

    GAVInput ::= attrListLen INTEGER

    The client sends the count of attributes it wants to retrieve; the
    server returns *all* attributes stored on the object.  The client then
    picks the ones it needs from the returned list.

Response:

    GAVOutput ::= SEQUENCE {
        attrList    Attributes,       -- SEQUENCE OF SEQUENCE { type, value }
        attrListLen INTEGER           -- count of attributes returned
    }

    Where Attributes follows the same encoding as icsf_ber_put_attribute_list().

The handle identifies the object (token_name + sequence + type).
"""

import logging
from ber_codec import (
    encode_response, encode_sequence, encode_integer,
    encode_attribute_list,
    parse_handle
)
from pkcs11_const import (
    CKA_SENSITIVE,
    CKA_VALUE,
    CKA_PRIVATE_EXPONENT, CKA_PRIME_1, CKA_PRIME_2,
    CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_COEFFICIENT,
)

logger = logging.getLogger(__name__)

ICSF_TAG_CSFPGAV = 3

RC_SUCCESS          = 0
RC_ERROR            = 8
RSN_OBJ_NOT_FOUND   = 3025

# Attributes that the real ICSF server withholds when CKA_SENSITIVE is TRUE.
# Matches PKCS#11: secret-key CKA_VALUE and all RSA private-key components.
_SENSITIVE_ATTRS = frozenset({
    CKA_VALUE,
    CKA_PRIVATE_EXPONENT,
    CKA_PRIME_1,
    CKA_PRIME_2,
    CKA_EXPONENT_1,
    CKA_EXPONENT_2,
    CKA_COEFFICIENT,
})


def handle_gav(store, request):
    """
    Process a CSFPGAV request.

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
        logger.error('GAV: invalid handle (token=%r seq=%d)', token_name, sequence)
        return encode_response(
            request.handle, RC_ERROR, 3001, ICSF_TAG_CSFPGAV, b'')

    obj = store.get_object(token_name, sequence)
    if obj is None:
        logger.warning('GAV: object not found token=%r seq=%d', token_name, sequence)
        return encode_response(
            request.handle, RC_ERROR, RSN_OBJ_NOT_FOUND, ICSF_TAG_CSFPGAV, b'')

    # Determine whether this object is sensitive.  Sensitive key-material
    # attributes are omitted from the response, but the call itself must
    # succeed (rc=0): the client (icsf_get_attribute()) does not decode the
    # attribute list when rc != 0, which would make *all* attributes of a
    # sensitive object (e.g. CKA_ALWAYS_SENSITIVE) unreadable.  If the caller
    # asked for an omitted attribute, the client's own decoder reports
    # rc=8/reason=3029 (-> CKR_ATTRIBUTE_TYPE_INVALID, translated to
    # CKR_ATTRIBUTE_SENSITIVE by the common layer).
    sensitive_raw = obj.get_attr(CKA_SENSITIVE)
    is_sensitive = bool(sensitive_raw[0]) if isinstance(sensitive_raw, (bytes, bytearray)) \
        and sensitive_raw else False

    all_attrs = obj.get_all_attrs()

    if is_sensitive:
        attrs = [(t, v) for t, v in all_attrs if t not in _SENSITIVE_ATTRS]
        if len(attrs) < len(all_attrs):
            logger.info('GAV: token=%r seq=%d object is sensitive, omitting %d attrs',
                        token_name, sequence, len(all_attrs) - len(attrs))
    else:
        attrs = all_attrs

    logger.info('GAV: token=%r seq=%d returning %d attributes', token_name, sequence, len(attrs))

    # Build GAVOutput ::= SEQUENCE { Attributes, attrListLen INTEGER }
    attr_list_ber = encode_attribute_list(attrs)
    attr_count    = encode_integer(len(attrs))
    svc_data = encode_sequence(attr_list_ber + attr_count)

    return encode_response(request.handle, RC_SUCCESS, 0, ICSF_TAG_CSFPGAV, svc_data)
