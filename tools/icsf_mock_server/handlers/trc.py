# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
handlers/trc.py — CSFPTRC: Token/Object Create (service tag 14).

Request layout (inside the context-constructed TLV):

  TRCInput ::= SEQUENCE {
      trcAttrs CHOICE {
          tokenAttrString  [0] OCTET STRING,  -- 68 bytes: manuf+model+serial
          objectAttrList   [1] Attributes      -- PKCS#11 attribute list
      }
  }

Rules (from icsf.c icsf_create_token / icsf_create_object):
  TOKEN + RECREATE   -> create / recreate a token
  OBJECT             -> create an object inside the token identified by handle

Response on success:
  rc=0, reason=0, updated handle (token or object), empty service data.
"""

import logging
from ber_codec import (
    decode_attribute_list, encode_response, encode_sequence,
    make_token_handle, make_object_handle,
    parse_handle, HANDLE_LEN, TOKEN_NAME_LEN,
    _decode_tlv
)
from token_store import OBJ_TYPE_TOKEN, OBJ_TYPE_SESSION, MANUF_LEN, MODEL_LEN, SERIAL_LEN
from obj_attrs import complete_key_attrs
from pkcs11_const import (
    CKA_TOKEN, CKA_KEY_TYPE, CKA_EC_PARAMS,
    CKA_COPYABLE, CKA_SENSITIVE,
    CKK_EC, CKM_UNAVAILABLE_INFORMATION,
)
from ec_backend import ec_curve_supported

logger = logging.getLogger(__name__)

ICSF_TAG_CSFPTRC = 14

# Return / reason codes
RC_SUCCESS          = 0
RC_ERROR            = 8
RSN_TOKEN_NOT_FOUND = 3024   # approximate — used when token missing for object create
RSN_ACTION_PROHIB   = 3034   # CKA_COPYABLE=FALSE        (→ CKR_ACTION_PROHIBITED)
RSN_ATTR_READ_ONLY  = 3035   # attribute is read-only    (→ CKR_ATTRIBUTE_READ_ONLY)


def _get_bool(obj, attr_type):
    """Return the boolean value of *attr_type* from obj.attributes, or None."""
    v = obj.attributes.get(attr_type)
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray)):
        return bool(v[0]) if v else False
    return bool(v)


def handle_trc(store, request):
    """
    Process a CSFPTRC request.

    Parameters
    ----------
    store   : TokenStore
    request : ICSFRequest (parsed by ber_codec.decode_request)

    Returns
    -------
    bytes — raw BER responseValue to send back inside the LDAP extended response
    """
    rules = request.rule_array

    if 'TOKEN' in rules:
        return _handle_create_token(store, request)
    elif 'OBJECT' in rules:
        return _handle_create_object(store, request)
    else:
        logger.warning('TRC: unrecognised rule array: %s', rules)
        return encode_response(
            request.handle, RC_ERROR, 3000, ICSF_TAG_CSFPTRC, b'')


# ------------------------------------------------------------------
# Token creation
# ------------------------------------------------------------------

def _handle_create_token(store, request):
    """
    TRC with TOKEN rule.  The service_data inside the context TLV is:
        [0] OCTET STRING  (68 bytes: manuf(32) + model(16) + serial(16) + pad(4))

    The token name comes from the first 32 bytes of the handle.
    """
    token_name, _, _ = parse_handle(request.handle)
    if not token_name:
        logger.error('TRC TOKEN: empty token name in handle')
        return encode_response(
            request.handle, RC_ERROR, 3001, ICSF_TAG_CSFPTRC, b'')

    # Decode the attribute string from the service_data
    # service_data is the *value* bytes of the context-constructed TLV, which
    # contains a single context-primitive [0] OCTET STRING.
    manuf = ''
    model = ''
    serial = ''

    try:
        tag, attr_str, _ = _decode_tlv(request.service_data, 0)
        # tag should be context-primitive [0] = 0x80
        if len(attr_str) >= MANUF_LEN + MODEL_LEN + SERIAL_LEN:
            manuf  = attr_str[:MANUF_LEN].rstrip(b' ').decode('ascii', errors='replace')
            model  = attr_str[MANUF_LEN:MANUF_LEN + MODEL_LEN].rstrip(b' ').decode('ascii', errors='replace')
            serial = attr_str[MANUF_LEN + MODEL_LEN:MANUF_LEN + MODEL_LEN + SERIAL_LEN].rstrip(b' ').decode('ascii', errors='replace')
    except Exception as exc:
        logger.warning('TRC TOKEN: could not decode attribute string: %s', exc)

    logger.info('TRC: creating token name=%r manuf=%r model=%r serial=%r',
                token_name, manuf, model, serial)

    store.create_token(token_name, manufacturer=manuf, model=model, serial=serial)

    new_handle = make_token_handle(token_name)
    return encode_response(new_handle, RC_SUCCESS, 0, ICSF_TAG_CSFPTRC, b'')


# ------------------------------------------------------------------
# Object creation
# ------------------------------------------------------------------

def _handle_create_object(store, request):
    """
    TRC with OBJECT rule.  The service_data is:
        [1] Attributes  (context-constructed, contents = attribute list SEQUENCE)

    When the COPY rule is also present the handle identifies the source object.
    The service_data then contains only the *override* attributes (or an empty
    constructed TLV when there are none).  The mock must:
      1. Look up the source object from the handle's sequence number.
      2. Clone all of its attributes.
      3. Merge/override with the attributes from the request.
    """
    token_name, src_sequence, _ = parse_handle(request.handle)
    if not token_name:
        logger.error('TRC OBJECT: empty token name in handle')
        return encode_response(
            request.handle, RC_ERROR, 3001, ICSF_TAG_CSFPTRC, b'')

    if not store.token_exists(token_name):
        logger.error('TRC OBJECT: token %r not found', token_name)
        return encode_response(
            request.handle, RC_ERROR, RSN_TOKEN_NOT_FOUND, ICSF_TAG_CSFPTRC, b'')

    is_copy = 'COPY' in request.rule_array

    # For COPY, load the source object's full attribute set first.
    base_attrs = {}
    if is_copy:
        src_obj = store.get_object(token_name, src_sequence)
        if src_obj is None:
            logger.error('TRC COPY: source object seq=%d not found in token %r',
                         src_sequence, token_name)
            return encode_response(
                request.handle, RC_ERROR, RSN_TOKEN_NOT_FOUND, ICSF_TAG_CSFPTRC, b'')
        base_attrs = dict(src_obj.get_all_attrs())

        # Enforce PKCS#11 copy rules that the C layer checks before calling us,
        # but mirror here as a safety net:
        #
        #   CKA_COPYABLE=FALSE → action prohibited.
        #   CKA_SENSITIVE=TRUE in source + override sets it FALSE → read-only.
        src_copyable = _get_bool(src_obj, CKA_COPYABLE)
        if src_copyable is False:
            logger.info('TRC COPY: source object not copyable (seq=%d)', src_sequence)
            return encode_response(
                request.handle, RC_ERROR, RSN_ACTION_PROHIB, ICSF_TAG_CSFPTRC, b'')

    # Decode attribute list from [1] context-constructed TLV.
    # icsf_create_object() / icsf_copy_object() encodes:
    #   ber_printf(msg, "t{", 1|CONTEXT|CONSTRUCTED)  → tag 0xa1
    #   icsf_ber_put_attribute_list(...)               → flat item SEQUENCEs
    #   ber_printf(msg, "}")
    # For copy with no overrides: ber_printf(msg, "tn", ...) → empty constructed TLV.
    # So service_data[0] tag must be 0xa1 and inner = raw item bytes.
    override_attrs = []
    try:
        tag, inner, _ = _decode_tlv(request.service_data, 0)
        if (tag & 0xe0) != 0xa0:
            logger.warning('TRC OBJECT: unexpected outer tag 0x%02x '
                           '(expected context-constructed 0xa1)', tag)
        if inner:
            # inner is the flat SEQUENCE-OF-SEQUENCE item bytes; wrap in
            # a SEQUENCE so decode_attribute_list can parse it.
            wrapped = encode_sequence(inner)
            override_attrs = decode_attribute_list(wrapped)
    except Exception as exc:
        logger.warning('TRC OBJECT: could not decode attribute list: %s', exc)

    if is_copy:
        # Check CKA_SENSITIVE rule before applying overrides:
        # once CKA_SENSITIVE=TRUE on the source, it cannot be lowered to FALSE.
        src_sensitive = base_attrs.get(CKA_SENSITIVE)
        src_sensitive_bool = (bool(src_sensitive[0])
                              if isinstance(src_sensitive, (bytes, bytearray)) and src_sensitive
                              else bool(src_sensitive) if isinstance(src_sensitive, int)
                              else False)
        for attr_type, value in override_attrs:
            if attr_type == CKA_SENSITIVE and src_sensitive_bool:
                new_val = (bool(value[0])
                           if isinstance(value, (bytes, bytearray)) and value
                           else bool(value) if isinstance(value, int)
                           else False)
                if not new_val:
                    logger.info('TRC COPY: CKA_SENSITIVE cannot be lowered from TRUE to FALSE')
                    return encode_response(
                        request.handle, RC_ERROR, RSN_ATTR_READ_ONLY, ICSF_TAG_CSFPTRC, b'')

        # Apply overrides on top of the cloned base attributes.
        for attr_type, value in override_attrs:
            base_attrs[attr_type] = value
        attrs = list(base_attrs.items())
    else:
        attrs = override_attrs

    # Determine object type: session vs token persistent
    # CKA_TOKEN = 0x00000001; value is a CK_BBOOL (1 byte)
    obj_type = OBJ_TYPE_SESSION
    for attr_type, value in attrs:
        if attr_type == CKA_TOKEN:
            if isinstance(value, (bytes, bytearray)) and len(value) >= 1 and value[0]:
                obj_type = OBJ_TYPE_TOKEN
            elif isinstance(value, int) and value:
                obj_type = OBJ_TYPE_TOKEN
            break

    if not is_copy:
        # Complete the attribute set: fill in all PKCS#11-defined defaults.
        # C_CreateObject paths supply key material directly (not generated),
        # so CKA_LOCAL=False and CKA_KEY_GEN_MECHANISM=CK_UNAVAILABLE_INFORMATION.
        attrs = complete_key_attrs(attrs,
                                   key_gen_mechanism=CKM_UNAVAILABLE_INFORMATION)

    # For EC keys: reject unsupported curve OIDs now so C_CreateObject returns
    # CKR_CURVE_NOT_SUPPORTED rather than letting a later sign/verify fail.
    attr_dict = {t: v for t, v in attrs}
    key_type = attr_dict.get(CKA_KEY_TYPE)
    if isinstance(key_type, (bytes, bytearray)):
        key_type = int.from_bytes(key_type, 'big')
    if key_type == CKK_EC:
        ec_params = attr_dict.get(CKA_EC_PARAMS, b'')
        if not ec_curve_supported(ec_params):
            logger.warning('TRC OBJECT: unsupported EC curve OID %s',
                           ec_params.hex() if isinstance(ec_params, bytes) else repr(ec_params))
            return encode_response(
                request.handle, RC_ERROR, 874, ICSF_TAG_CSFPTRC, b'')

    logger.info('TRC: creating object token=%r type=%s attrs=%d',
                token_name, obj_type, len(attrs))

    obj = store.create_object(token_name, obj_type, attrs)
    if obj is None:
        return encode_response(
            request.handle, RC_ERROR, RSN_TOKEN_NOT_FOUND, ICSF_TAG_CSFPTRC, b'')

    new_handle = make_object_handle(token_name, obj.sequence, obj.obj_type)
    return encode_response(new_handle, RC_SUCCESS, 0, ICSF_TAG_CSFPTRC, b'')
