# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
handlers/trl.py — CSFPTRL: Token/Object List (service tag 16).

The same service tag handles both token listing and object listing;
the rule array distinguishes them.

Request (from icsf_list() in icsf.c):

    TRLInput ::= SEQUENCE {
        inListLen       INTEGER,   -- bytes already received (pagination)
        maxHandleCount  INTEGER,   -- max items to return
        searchTemplate  [0] Attributes OPTIONAL  -- only for OBJECT
    }

    The searchTemplate is a context-constructed [0] TLV whose contents are
    a flat SEQUENCE-OF-SEQUENCE attribute list (same wire format as GAV).
    icsf_list() encodes it with:
        ber_printf(msg, "t{", 0 | LBER_CLASS_CONTEXT | LBER_CONSTRUCTED)
        icsf_ber_put_attribute_list(msg, attrs, attrs_len)
        ber_printf(msg, "}")
    So the contents of the [0] TLV are raw item SEQUENCEs (no outer SEQUENCE
    of their own) — identical to how encode_attribute_list() works in
    ber_codec.py.

Response:

    TRLOutput ::= SEQUENCE {
        outList CHOICE {
            tokenList   [0] OCTET STRING,   -- N * 116-byte token records
            handleList  [1] OCTET STRING    -- N * 44-byte object handles
        },
        outListLen      INTEGER             -- total bytes in outList
    }

Pagination: the handle in the request is the "cursor" pointing to the last
item already returned.  An all-spaces (zeroed) handle means "start from the
beginning".

Rules:
  TOKEN              -> list tokens
  OBJECT             -> list session+token objects for a specific token
  OBJECT + ALL       -> list all objects (same in our implementation)
"""

import logging
from ber_codec import (
    encode_response, encode_integer,
    encode_ctx_prim, make_object_handle, make_token_handle,
    parse_handle, HANDLE_LEN, TOKEN_NAME_LEN, SEQ_LEN,
    _decode_tlv, decode_integer, LBER_SEQUENCE,
)
from pkcs11_const import NUMERIC_ATTR_TYPES as _NUMERIC_ATTR_TYPES

logger = logging.getLogger(__name__)

ICSF_TAG_CSFPTRL = 16

RC_SUCCESS        = 0
RC_PARTIAL        = 4   # more records exist (not needed — we return all at once)
RC_ERROR          = 8
RSN_TOKEN_NOT_FOUND = 3024

MAX_RECORDS = 100   # hard cap matching #define MAX_RECORDS 100 in icsf.h


def handle_trl(store, request):
    """
    Process a CSFPTRL request.

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
        return _handle_list_tokens(store, request)
    elif 'OBJECT' in rules:
        return _handle_list_objects(store, request)
    else:
        logger.warning('TRL: unrecognised rule array: %s', rules)
        return encode_response(
            request.handle, RC_ERROR, 3000, ICSF_TAG_CSFPTRL, b'')


# ------------------------------------------------------------------
# Token listing
# ------------------------------------------------------------------

def _handle_list_tokens(store, request):
    """
    Return up to maxHandleCount tokens, starting after the cursor token.
    The cursor is the token name in the request handle (all-spaces = start).
    """
    cursor_name, _, _ = parse_handle(request.handle)
    # all-spaces handle means "start from beginning"
    if not cursor_name or set(cursor_name) == {' '}:
        cursor_name = None

    list_len, max_count, _ = _decode_trl_input(request.service_data)
    if max_count == 0 or max_count > MAX_RECORDS:
        max_count = MAX_RECORDS

    logger.info('TRL TOKEN: cursor=%r max_count=%d', cursor_name, max_count)

    tokens = store.list_tokens(after_name=cursor_name)
    tokens = tokens[:max_count]

    # Build flat byte string of 116-byte token records
    records_bytes = b''.join(t.to_wire_record() for t in tokens)
    actual_len = len(records_bytes)

    # TRLOutput: [0] OCTET STRING then INTEGER — no wrapping SEQUENCE.
    # icsf_list() decodes with ber_scanf(result, "{Oi}") where { enters the
    # service context TLV directly, so the contents must be the raw fields.
    out_list   = encode_ctx_prim(0, records_bytes)
    out_len    = encode_integer(actual_len)
    svc_data   = out_list + out_len

    # Update handle to point to last returned token (for pagination)
    if tokens:
        new_handle = _make_token_cursor(tokens[-1].name)
    else:
        new_handle = request.handle

    logger.info('TRL TOKEN: returning %d token(s) (%d bytes)',
                len(tokens), actual_len)
    return encode_response(new_handle, RC_SUCCESS, 0, ICSF_TAG_CSFPTRL, svc_data)


# ------------------------------------------------------------------
# Object listing
# ------------------------------------------------------------------

def _handle_list_objects(store, request):
    """
    Return up to maxHandleCount objects for the token identified by the
    handle's token-name field, starting after the cursor object.

    The search template (if present) is used to filter objects by attribute
    values before returning handles.  This is how the real ICSF server works:
    icsf_list_objects() passes CKA_CLASS / CKA_KEY_TYPE filters and ICSF only
    returns matching handles.
    """
    token_name, cursor_seq, cursor_type = parse_handle(request.handle)

    if not token_name:
        logger.error('TRL OBJECT: empty token name in handle')
        return encode_response(
            request.handle, RC_ERROR, 3001, ICSF_TAG_CSFPTRL, b'')

    list_len, max_count, template = _decode_trl_input(request.service_data)
    if max_count == 0 or max_count > MAX_RECORDS:
        max_count = MAX_RECORDS

    # Determine whether this is a cursor or a token handle.
    # A token handle has blanks (0x20) in the sequence field; an object handle
    # has a hex sequence number.  parse_handle returns sequence=0 for both,
    # but we can check whether the sequence bytes are actually spaces.
    seq_bytes = request.handle[TOKEN_NAME_LEN:TOKEN_NAME_LEN + SEQ_LEN]
    is_token_handle = (seq_bytes.strip(b' ') == b'')
    after_seq = None if is_token_handle else cursor_seq

    logger.info('TRL OBJECT: token=%r after_seq=%s max_count=%d template=%s',
                token_name, after_seq, max_count,
                [(f'0x{t:x}', v) for t, v in template] if template else [])

    if not store.token_exists(token_name):
        logger.error('TRL OBJECT: token %r not found', token_name)
        return encode_response(
            request.handle, RC_ERROR, RSN_TOKEN_NOT_FOUND, ICSF_TAG_CSFPTRL, b'')

    objects = store.list_objects(token_name, after_seq=after_seq)

    # Apply search template filter (mirrors ICSF server-side filtering)
    if template:
        objects = [o for o in objects if _object_matches(o, template)]

    objects = objects[:max_count]

    # Build flat byte string of 44-byte object handles
    handles_bytes = b''.join(
        make_object_handle(o.token_name, o.sequence, o.obj_type)
        for o in objects
    )
    actual_len = len(handles_bytes)

    # TRLOutput: [1] OCTET STRING then INTEGER — no wrapping SEQUENCE.
    out_list = encode_ctx_prim(1, handles_bytes)
    out_len  = encode_integer(actual_len)
    svc_data = out_list + out_len

    # Update handle to last returned object (pagination cursor)
    if objects:
        last = objects[-1]
        new_handle = make_object_handle(last.token_name, last.sequence, last.obj_type)
    else:
        new_handle = request.handle

    logger.info('TRL OBJECT: returning %d object(s) (%d bytes)',
                len(objects), actual_len)
    return encode_response(new_handle, RC_SUCCESS, 0, ICSF_TAG_CSFPTRL, svc_data)


# ------------------------------------------------------------------
# Search template matching
# ------------------------------------------------------------------

def _object_matches(obj, template):
    """
    Return True if the object's attributes match ALL template entries.

    For each (attr_type, template_value) in the template:
    - The object must have an attribute with that type.
    - The stored value must compare equal to the template value.

    Numeric attributes (CKA_CLASS, CKA_KEY_TYPE, etc.) are stored as Python
    ints; the template value parsed from BER is also an int for those types.
    Boolean/bytes attributes are stored as bytes; template values are bytes.
    """
    stored = {t: v for t, v in obj.get_all_attrs()}

    for attr_type, tmpl_val in template:
        if attr_type not in stored:
            logger.debug('_object_matches seq=%d: attr 0x%x MISSING',
                         obj.sequence, attr_type)
            return False
        obj_val = stored[attr_type]

        # Normalise both sides to the same type for comparison.
        if attr_type in _NUMERIC_ATTR_TYPES:
            # Both should be int; coerce bytes if needed (shouldn't happen)
            ov = obj_val if isinstance(obj_val, int) else int.from_bytes(obj_val, 'big')
            tv = tmpl_val if isinstance(tmpl_val, int) else int.from_bytes(tmpl_val, 'big')
            if ov != tv:
                logger.debug('_object_matches seq=%d: numeric attr 0x%x '
                             'obj=%r tmpl=%r MISMATCH', obj.sequence, attr_type, ov, tv)
                return False
        else:
            # Bytes / bool comparison
            ov = obj_val if isinstance(obj_val, (bytes, bytearray)) else bytes([obj_val])
            tv = tmpl_val if isinstance(tmpl_val, (bytes, bytearray)) else bytes([tmpl_val])
            if ov != tv:
                logger.debug('_object_matches seq=%d: bytes attr 0x%x '
                             'obj=%r tmpl=%r MISMATCH', obj.sequence, attr_type, ov, tv)
                return False

    return True


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _decode_trl_input(data: bytes):
    """
    Parse TRLInput and return (inListLen, maxHandleCount, template).

    template is a list of (attr_type: int, attr_value: int|bytes) parsed
    from the optional [0] context-constructed search-template TLV.
    Falls back to sensible defaults on parse error.
    """
    try:
        pos = 0
        tag, val, pos = _decode_tlv(data, pos)
        in_list_len = decode_integer(val)
        tag, val, pos = _decode_tlv(data, pos)
        max_count = decode_integer(val)

        template = []
        if pos < len(data):
            # Optional [0] context-constructed search template
            ctx_tag, ctx_val, pos = _decode_tlv(data, pos)
            if (ctx_tag & 0xe0) == 0xa0:  # context constructed
                template = _parse_attr_items(ctx_val)

        return in_list_len, max_count, template
    except Exception as exc:
        logger.debug('TRL: could not decode TRLInput: %s', exc)
        return 0, MAX_RECORDS, []


def _parse_attr_items(data: bytes):
    """
    Parse the flat sequence of attribute item SEQUENCEs from the search
    template contents (same wire format as encode_attribute_list output).

    Returns list of (attr_type: int, attr_value: int|bytes).
    """
    attrs = []
    pos = 0
    while pos < len(data):
        tag, item_val, pos = _decode_tlv(data, pos)
        if tag != LBER_SEQUENCE:
            break
        ipos = 0
        # INTEGER: attribute type
        tag2, tval, ipos = _decode_tlv(item_val, ipos)
        attr_type = decode_integer(tval)
        # [0] OCTET STRING or [1] INTEGER: attribute value
        tag3, vval, ipos = _decode_tlv(item_val, ipos)
        tag_num = tag3 & 0x1F
        if tag_num == 1 or attr_type in _NUMERIC_ATTR_TYPES:
            # Numeric / integer attribute
            attrs.append((attr_type, decode_integer(vval)))
        else:
            # Bytes / boolean attribute
            attrs.append((attr_type, vval))
    return attrs


def _make_token_cursor(name: str) -> bytes:
    """Build a 44-byte token-style cursor handle from a name."""
    return make_token_handle(name)
