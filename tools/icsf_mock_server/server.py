# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
server.py — ICSF mock LDAPv3 server.

Implements the minimal subset of LDAPv3 (RFC 4511) that the openCryptoki
ICSF token and the pkcsicsf tool require:

  1.  BindRequest    — simple (DN + password) and SASL EXTERNAL (accepts all)
  2.  SearchRequest  — only the root DSE base search (base="", filter=*)
                       returns supportedextension with the ICSF OID
  3.  ExtendedRequest OID 1.3.18.0.2.12.83 — ICSF service calls
  4.  UnbindRequest   — close the connection

Usage
-----
    python server.py [--host HOST] [--port PORT] [--verbose]

    Default: listens on 127.0.0.1:1389  (non-root port; no TLS by default).

    To point the ICSF token at this server, set the URI in the token config:
        uri = ldap://127.0.0.1:1389

TLS / SASL EXTERNAL
-------------------
    The server optionally wraps the socket in TLS if --cert and --key are
    supplied.  This is required for SASL EXTERNAL (client-cert) authentication.

    Example (self-signed, for testing only):
        openssl req -x509 -newkey rsa:2048 -nodes \\
            -keyout server.key -out server.crt -days 365 -subj '/CN=icsf-mock'
        python server.py --cert server.crt --key server.key

LDAP message framing (RFC 4511 §5.1)
--------------------------------------
    LDAPMessage ::= SEQUENCE {
        messageID   INTEGER (1 .. maxInt),
        protocolOp  CHOICE {
            bindRequest     [APPLICATION 0]  BindRequest,
            bindResponse    [APPLICATION 1]  BindResponse,
            unbindRequest   [APPLICATION 2]  UnbindRequest,
            searchRequest   [APPLICATION 3]  SearchRequest,
            searchResEntry  [APPLICATION 4]  SearchResultEntry,
            searchResDone   [APPLICATION 5]  SearchResultDone,
            extendedReq     [APPLICATION 23] ExtendedRequest,
            extendedResp    [APPLICATION 24] ExtendedResponse,
            ...
        }
    }

Application tags (from RFC 4511):
    0  BindRequest
    1  BindResponse
    2  UnbindRequest
    3  SearchRequest
    4  SearchResultEntry
    5  SearchResultDone
   16  AbandonRequest
   23  ExtendedRequest
   24  ExtendedResponse
"""

import argparse
import logging
import socket
import ssl
import sys
import threading

from ber_codec import (
    decode_request, encode_response,
    HANDLE_LEN
)
from token_store import TokenStore, OBJ_TYPE_TOKEN, OBJ_TYPE_SESSION
from pkcs11_const import (
    CKA_CLASS, CKA_TOKEN, CKA_PRIVATE, CKA_LABEL, CKA_ID, CKA_VALUE,
    CKA_KEY_TYPE, CKA_VALUE_LEN, CKA_SENSITIVE, CKA_ENCRYPT, CKA_DECRYPT,
    CKA_SIGN, CKA_VERIFY, CKA_DERIVE, CKA_EXTRACTABLE, CKA_MODIFIABLE,
    CKA_MODULUS, CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT,
    CKA_EC_PARAMS, CKA_EC_POINT,
    CKA_PRIME, CKA_SUBPRIME, CKA_BASE,
    CKA_LOCAL, CKA_NEVER_EXTRACTABLE, CKA_ALWAYS_SENSITIVE,
    CKO_SECRET_KEY, CKO_PUBLIC_KEY, CKO_PRIVATE_KEY,
    CKK_AES, CKK_DES, CKK_DES2, CKK_DES3, CKK_GENERIC_SECRET,
    CKK_RSA, CKK_DSA, CKK_DH, CKK_EC,
    CKM_AES_KEY_GEN, CKM_DES_KEY_GEN, CKM_DES2_KEY_GEN, CKM_DES3_KEY_GEN,
    CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_EC_KEY_PAIR_GEN,
    CKM_DSA_KEY_PAIR_GEN, CKM_DH_PKCS_KEY_PAIR_GEN,
    CKM_GENERIC_SECRET_KEY_GEN,
    CKM_UNAVAILABLE_INFORMATION,
    bool_attr,
)
from obj_attrs import (
    make_secret_key_attrs, make_rsa_keypair_attrs, make_ec_keypair_attrs,
    make_dsa_keypair_attrs, make_dh_keypair_attrs,
    complete_key_attrs, make_x509_cert_attrs,
)
from ec_backend import ec_generate
from dsa_backend import dsa_generate
from dh_backend import dh_generate
from handlers.dmk import handle_dmk, ICSF_TAG_CSFPDMK
from handlers.trc import handle_trc, ICSF_TAG_CSFPTRC
from handlers.trd import handle_trd, ICSF_TAG_CSFPTRD
from handlers.trl import handle_trl, ICSF_TAG_CSFPTRL
from handlers.gav import handle_gav, ICSF_TAG_CSFPGAV
from handlers.sav import handle_sav, ICSF_TAG_CSFPSAV
from handlers.gsk import handle_gsk, ICSF_TAG_CSFPGSK
from handlers.gkp import handle_gkp, ICSF_TAG_CSFPGKP
from handlers.ske import handle_ske, ICSF_TAG_CSFPSKE
from handlers.skd import handle_skd, ICSF_TAG_CSFPSKD
from handlers.owh import handle_owh, ICSF_TAG_CSFPOWH
from handlers.pks import handle_pks, ICSF_TAG_CSFPPKS
from handlers.pkv import handle_pkv, ICSF_TAG_CSFPPKV
from handlers.hmg import handle_hmg, ICSF_TAG_CSFPHMG
from handlers.hmv import handle_hmv, ICSF_TAG_CSFPHMV
from handlers.dvk import handle_dvk, ICSF_TAG_CSFPDVK
from handlers.uwk import handle_uwk, ICSF_TAG_CSFPUWK
from handlers.wpk import handle_wpk, ICSF_TAG_CSFPWPK

logger = logging.getLogger(__name__)

# ICSF extended-operation OIDs
ICSF_REQ_OID = '1.3.18.0.2.12.83'
ICSF_RES_OID = '1.3.18.0.2.12.84'

# ---------------------------------------------------------------------------
# BER / LDAP message encoding constants
# ---------------------------------------------------------------------------

# Universal
TAG_SEQUENCE        = 0x30
TAG_INTEGER         = 0x02
TAG_OCTET_STRING    = 0x04
TAG_BOOLEAN         = 0x01
TAG_ENUMERATED      = 0x0A
TAG_NULL            = 0x05
TAG_OID             = 0x06
TAG_SET             = 0x31

# Application (constructed bit for those that are constructed = 0x60 | n)
TAG_BIND_REQUEST    = 0x60   # [APPLICATION 0] constructed
TAG_BIND_RESPONSE   = 0x61   # [APPLICATION 1] constructed
TAG_UNBIND_REQUEST  = 0x42   # [APPLICATION 2] primitive
TAG_SEARCH_REQUEST  = 0x63   # [APPLICATION 3] constructed
TAG_SEARCH_ENTRY    = 0x64   # [APPLICATION 4] constructed
TAG_SEARCH_DONE     = 0x65   # [APPLICATION 5] constructed
TAG_EXTENDED_REQ    = 0x77   # [APPLICATION 23] constructed
TAG_EXTENDED_RESP   = 0x78   # [APPLICATION 24] constructed

# Context tags inside BindRequest / BindResponse
CTX_PRIM_0 = 0x80
CTX_CONS_3 = 0xA3   # saslCredentials [3] SEQUENCE

# LDAPResult result codes (RFC 4511 §4.1.9)
LDAP_SUCCESS           = 0
LDAP_OPERATIONS_ERROR  = 1
LDAP_PROTOCOL_ERROR    = 2
LDAP_NO_SUCH_OBJECT    = 32
LDAP_INVALID_CREDENTIALS = 49
LDAP_UNWILLING_TO_PERFORM = 53
LDAP_OTHER             = 80

# The root DSE attribute we advertise
ROOT_DSE_ATTRS = {
    'supportedLDAPVersion': ['3'],
    'supportedextension': [ICSF_REQ_OID],
    'supportedSASLMechanisms': ['EXTERNAL'],
    'objectClass': ['top'],
}


# ---------------------------------------------------------------------------
# Low-level BER primitives (self-contained, no ldap dependency)
# ---------------------------------------------------------------------------

def _enc_len(n):
    if n < 0x80:
        return bytes([n])
    elif n <= 0xFF:
        return bytes([0x81, n])
    elif n <= 0xFFFF:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    elif n <= 0xFFFFFF:
        return bytes([0x83, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])
    else:
        return bytes([0x84,
                      (n >> 24) & 0xFF, (n >> 16) & 0xFF,
                      (n >> 8) & 0xFF, n & 0xFF])


def _tlv(tag, value):
    return bytes([tag]) + _enc_len(len(value)) + value


def _int_ber(n):
    if n == 0:
        return _tlv(TAG_INTEGER, b'\x00')
    out = []
    while n:
        out.append(n & 0xFF)
        n >>= 8
    out.reverse()
    if out[0] & 0x80:
        out.insert(0, 0x00)
    return _tlv(TAG_INTEGER, bytes(out))


def _enum_ber(n):
    """Encode an enumerated value (same as integer, different tag)."""
    if n == 0:
        return _tlv(TAG_ENUMERATED, b'\x00')
    out = []
    while n:
        out.append(n & 0xFF)
        n >>= 8
    out.reverse()
    if out[0] & 0x80:
        out.insert(0, 0x00)
    return _tlv(TAG_ENUMERATED, bytes(out))


def _octet_str(b):
    return _tlv(TAG_OCTET_STRING, b if isinstance(b, bytes) else b.encode())


def _sequence(data):
    return _tlv(TAG_SEQUENCE, data)


def _set(data):
    return _tlv(TAG_SET, data)


def _oid_ber(oid_str):
    """Encode a dotted OID string as BER OBJECT IDENTIFIER."""
    parts = [int(x) for x in oid_str.split('.')]
    out = [40 * parts[0] + parts[1]]
    for part in parts[2:]:
        if part == 0:
            out.append(0)
        else:
            enc = []
            while part:
                enc.append(part & 0x7F)
                part >>= 7
            enc.reverse()
            for i, b in enumerate(enc):
                if i < len(enc) - 1:
                    out.append(b | 0x80)
                else:
                    out.append(b)
    return _tlv(TAG_OID, bytes(out))


# ---------------------------------------------------------------------------
# LDAPMessage builders
# ---------------------------------------------------------------------------

def _ldap_msg(msg_id, protocol_op_bytes):
    """Wrap protocol_op_bytes in an LDAPMessage SEQUENCE."""
    return _sequence(_int_ber(msg_id) + protocol_op_bytes)


def _ldap_result(result_tag, result_code, matched_dn=b'', diag_msg=b''):
    """Build a generic LDAPResult structure."""
    inner = (_enum_ber(result_code) +
             _octet_str(matched_dn if isinstance(matched_dn, bytes) else matched_dn.encode()) +
             _octet_str(diag_msg if isinstance(diag_msg, bytes) else diag_msg.encode()))
    return _tlv(result_tag, inner)


def _bind_response(msg_id, result_code, diag=b''):
    op = _ldap_result(TAG_BIND_RESPONSE, result_code, diag_msg=diag)
    return _ldap_msg(msg_id, op)


def _search_result_done(msg_id, result_code=LDAP_SUCCESS):
    op = _ldap_result(TAG_SEARCH_DONE, result_code)
    return _ldap_msg(msg_id, op)


def _search_result_entry(msg_id, dn, attrs):
    """
    attrs: dict str -> list of str
    """
    attr_list = b''
    for attr_type, values in attrs.items():
        vals_ber = b''.join(_octet_str(v.encode() if isinstance(v, str) else v)
                            for v in values)
        vals_set = _set(vals_ber)
        attr_list += _sequence(_octet_str(attr_type.encode()) + vals_set)
    inner = _octet_str(dn.encode() if isinstance(dn, str) else dn) + _sequence(attr_list)
    op = _tlv(TAG_SEARCH_ENTRY, inner)
    return _ldap_msg(msg_id, op)


def _extended_response(msg_id, result_code, response_oid=None,
                       response_value=None, diag=b''):
    """
    ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
        COMPONENTS OF LDAPResult,
        responseName  [10] LDAPOID OPTIONAL,
        responseValue [11] OCTET STRING OPTIONAL
    }
    """
    inner = (_enum_ber(result_code) +
             _octet_str(b'') +   # matchedDN
             _octet_str(diag if isinstance(diag, bytes) else diag.encode()))
    if response_oid:
        inner += _tlv(0x8A, response_oid.encode() if isinstance(response_oid, str)
                      else response_oid)  # [10] primitive
    if response_value is not None:
        inner += _tlv(0x8B, response_value)  # [11] primitive
    op = _tlv(TAG_EXTENDED_RESP, inner)
    return _ldap_msg(msg_id, op)


# ---------------------------------------------------------------------------
# BER message reader
# ---------------------------------------------------------------------------

def _read_exactly(sock, n):
    """Read exactly n bytes from sock; raise EOFError on connection close."""
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError('Connection closed')
        buf += chunk
    return buf


def read_ldap_message(sock):
    """
    Read one complete LDAPMessage from the socket.
    Returns the raw bytes of the entire TLV (including tag and length).
    Raises EOFError when the client disconnects.
    """
    # Read tag + first length byte
    header = _read_exactly(sock, 2)
    len_byte = header[1]

    if len_byte < 0x80:
        total_len = len_byte
        data = _read_exactly(sock, total_len)
        return header + data
    else:
        num_bytes = len_byte & 0x7F
        len_bytes = _read_exactly(sock, num_bytes)
        total_len = int.from_bytes(len_bytes, 'big')
        data = _read_exactly(sock, total_len)
        return header + len_bytes + data


# ---------------------------------------------------------------------------
# BER message decoder (just enough to extract what we need)
# ---------------------------------------------------------------------------

def _decode_len(data, pos):
    b = data[pos]
    pos += 1
    if b < 0x80:
        return b, pos
    n = b & 0x7F
    length = int.from_bytes(data[pos:pos + n], 'big')
    return length, pos + n


def _decode_tlv(data, pos):
    tag = data[pos]
    pos += 1
    if (tag & 0x1F) == 0x1F:
        while data[pos] & 0x80:
            tag = (tag << 8) | data[pos]
            pos += 1
        tag = (tag << 8) | data[pos]
        pos += 1
    length, pos = _decode_len(data, pos)
    value = data[pos:pos + length]
    return tag, value, pos + length


def _decode_integer(data):
    n = 0
    for b in data:
        n = (n << 8) | b
    return n


def _decode_oid(data):
    """Decode BER OID bytes to dotted string."""
    first = data[0]
    result = [first // 40, first % 40]
    i = 1
    while i < len(data):
        val = 0
        while data[i] & 0x80:
            val = (val << 7) | (data[i] & 0x7F)
            i += 1
        val = (val << 7) | data[i]
        i += 1
        result.append(val)
    return '.'.join(str(x) for x in result)


def parse_ldap_message(raw):
    """
    Return (msg_id, op_tag, op_value_bytes).
    op_value_bytes is the raw content inside the application TLV.
    """
    tag, seq_val, _ = _decode_tlv(raw, 0)
    if tag != TAG_SEQUENCE:
        raise ValueError('Expected SEQUENCE for LDAPMessage, got 0x%02x' % tag)
    pos = 0
    tag2, mid_val, pos = _decode_tlv(seq_val, pos)
    msg_id = _decode_integer(mid_val)
    op_tag, op_val, _ = _decode_tlv(seq_val, pos)
    return msg_id, op_tag, op_val


# ---------------------------------------------------------------------------
# Protocol handlers
# ---------------------------------------------------------------------------

def _handle_bind(msg_id, op_val):
    """
    Parse BindRequest and return a BindResponse bytes.
    We accept:
      - Simple bind with any DN and password (test server)
      - SASL EXTERNAL (any client certificate)
    """
    pos = 0
    # version INTEGER
    tag, val, pos = _decode_tlv(op_val, pos)
    # version = _decode_integer(val)

    # name LDAPDN
    tag, dn_val, pos = _decode_tlv(op_val, pos)
    dn = dn_val.decode('utf-8', errors='replace')

    # authentication CHOICE
    tag, auth_val, pos = _decode_tlv(op_val, pos)

    if tag == CTX_PRIM_0:
        # simple [0] OCTET STRING — any password accepted (test server)
        logger.info('BIND simple dn=%r (accepted)', dn)
    elif tag == CTX_CONS_3:
        # sasl [3] SaslCredentials ::= SEQUENCE { mechanism, credentials }
        sp = 0
        tag2, mech_val, sp = _decode_tlv(auth_val, sp)
        mech = mech_val.decode('utf-8', errors='replace')
        logger.info('BIND SASL mechanism=%r (accepted)', mech)
    else:
        logger.warning('BIND unknown auth tag 0x%02x', tag)

    return _bind_response(msg_id, LDAP_SUCCESS)


def _handle_search(msg_id, op_val, wanted_attrs):
    """
    Handle SearchRequest.  We only respond to the root DSE search
    (baseObject="", scope=baseObject).  All other searches get
    SearchResultDone(success) with zero entries.
    """
    pos = 0
    # baseObject LDAPDN
    tag, base_val, pos = _decode_tlv(op_val, pos)
    base_dn = base_val.decode('utf-8', errors='replace')

    # scope ENUMERATED
    tag, scope_val, pos = _decode_tlv(op_val, pos)
    scope = _decode_integer(scope_val)

    # Skip derefAliases, sizeLimit, timeLimit, typesOnly, filter, attributes
    # We don't need to parse them for the root DSE response.

    logger.debug('SEARCH base=%r scope=%d', base_dn, scope)

    msgs = b''
    if base_dn == '' and scope == 0:
        # Root DSE search — return our capabilities entry
        attrs = {k: v for k, v in ROOT_DSE_ATTRS.items()
                 if not wanted_attrs or k.lower() in
                    [a.lower() for a in wanted_attrs]}
        if not wanted_attrs:
            attrs = ROOT_DSE_ATTRS
        msgs += _search_result_entry(msg_id, '', attrs)
        logger.info('SEARCH root DSE: returning supportedextension=%s', ICSF_REQ_OID)

    msgs += _search_result_done(msg_id, LDAP_SUCCESS)
    return msgs


def _parse_search_attrs(op_val):
    """Extract the requested attribute list from a SearchRequest.

    Intentionally returns [] (= return all attributes).  Parsing the full
    SearchRequest up to the AttributeSelection is not needed for the root-DSE
    response, so we skip it and always send back the complete ROOT_DSE_ATTRS.
    """
    return []


def _handle_extended(msg_id, op_val, store):
    """
    Handle ExtendedRequest.
    We only process the ICSF OID (1.3.18.0.2.12.83).
    """
    pos = 0
    # requestName [0] LDAPOID
    tag, oid_val, pos = _decode_tlv(op_val, pos)
    oid_str = oid_val.decode('ascii', errors='replace')

    if oid_str != ICSF_REQ_OID:
        logger.warning('ExtendedRequest for unknown OID %r', oid_str)
        return _extended_response(msg_id, LDAP_UNWILLING_TO_PERFORM,
                                  diag=b'Unknown OID')

    # requestValue [1] OCTET STRING (the BER-encoded ICSF request)
    if pos >= len(op_val):
        logger.error('ExtendedRequest: missing requestValue')
        return _extended_response(msg_id, LDAP_OPERATIONS_ERROR,
                                  response_oid=ICSF_RES_OID,
                                  diag=b'Missing requestValue')

    tag, req_value_bytes, pos = _decode_tlv(op_val, pos)

    # Parse and dispatch the ICSF request
    try:
        icsf_req = decode_request(req_value_bytes)
    except Exception as exc:
        logger.error('ICSF request decode error: %s', exc)
        return _extended_response(msg_id, LDAP_PROTOCOL_ERROR,
                                  response_oid=ICSF_RES_OID,
                                  diag=str(exc).encode())

    logger.debug('ICSF service tag=%d rules=%s handle=%r',
                 icsf_req.service_tag, icsf_req.rule_array,
                 icsf_req.handle[:44].rstrip(b' '))

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug('ICSF req service_data: %s', req_value_bytes.hex())

    try:
        icsf_resp = _dispatch_icsf(store, icsf_req, store.hmac_state)
    except Exception as exc:
        logger.exception('ICSF handler error (tag=%d): %s', icsf_req.service_tag, exc)
        return _extended_response(msg_id, LDAP_OPERATIONS_ERROR,
                                  response_oid=ICSF_RES_OID,
                                  diag=str(exc).encode())

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug('ICSF resp: %s', icsf_resp.hex() if icsf_resp else '(empty)')

    return _extended_response(msg_id, LDAP_SUCCESS,
                              response_oid=ICSF_RES_OID,
                              response_value=icsf_resp)


def _dispatch_icsf(store, req, hmac_state):
    """Route an ICSF request to the correct handler."""
    tag = req.service_tag

    if tag == ICSF_TAG_CSFPDMK:    # 1
        return handle_dmk(store, req)
    elif tag == ICSF_TAG_CSFPDVK:  # 2
        return handle_dvk(store, req)
    elif tag == ICSF_TAG_CSFPGAV:    # 3
        return handle_gav(store, req)
    elif tag == ICSF_TAG_CSFPGKP:  # 4
        return handle_gkp(store, req)
    elif tag == ICSF_TAG_CSFPGSK:  # 5
        return handle_gsk(store, req)
    elif tag == ICSF_TAG_CSFPHMG:  # 6
        return handle_hmg(store, req, hmac_state)
    elif tag == ICSF_TAG_CSFPHMV:  # 7
        return handle_hmv(store, req, hmac_state)
    elif tag == ICSF_TAG_CSFPOWH:  # 8
        return handle_owh(store, req)
    elif tag == ICSF_TAG_CSFPPKS:  # 9
        return handle_pks(store, req)
    elif tag == ICSF_TAG_CSFPPKV:  # 10
        return handle_pkv(store, req)
    elif tag == ICSF_TAG_CSFPSAV:  # 11
        return handle_sav(store, req)
    elif tag == ICSF_TAG_CSFPSKD:  # 12
        return handle_skd(store, req)
    elif tag == ICSF_TAG_CSFPSKE:  # 13
        return handle_ske(store, req)
    elif tag == ICSF_TAG_CSFPTRC:  # 14
        return handle_trc(store, req)
    elif tag == ICSF_TAG_CSFPTRD:  # 15
        return handle_trd(store, req)
    elif tag == ICSF_TAG_CSFPTRL:  # 16
        return handle_trl(store, req)
    elif tag == ICSF_TAG_CSFPUWK:  # 17
        return handle_uwk(store, req)
    elif tag == ICSF_TAG_CSFPWPK:  # 18
        return handle_wpk(store, req)
    else:
        logger.warning('ICSF service tag %d not implemented in this mock', tag)
        blank_handle = (req.handle or b'').ljust(HANDLE_LEN, b' ')[:HANDLE_LEN]
        return encode_response(blank_handle, rc=8, reason=3000,
                               service_tag=tag, service_data=b'')


# ---------------------------------------------------------------------------
# Connection handler
# ---------------------------------------------------------------------------

class ClientHandler(threading.Thread):
    """One thread per accepted TCP connection."""

    def __init__(self, conn, addr, store):
        super().__init__(daemon=True)
        self.conn  = conn
        self.addr  = addr
        self.store = store

    def run(self):
        logger.info('Connection from %s:%d', *self.addr)
        try:
            self._serve()
        except EOFError:
            logger.info('Client %s:%d disconnected', *self.addr)
        except Exception as exc:
            logger.exception('Error serving %s:%d: %s', *self.addr, exc)
        finally:
            try:
                self.conn.close()
            except Exception:
                pass

    def _serve(self):
        while True:
            try:
                raw = read_ldap_message(self.conn)
            except EOFError:
                break

            try:
                msg_id, op_tag, op_val = parse_ldap_message(raw)
            except Exception as exc:
                logger.error('Could not parse LDAPMessage: %s', exc)
                break

            resp = self._dispatch(msg_id, op_tag, op_val)
            if resp is None:
                # UnbindRequest — close connection
                break
            if resp:
                self.conn.sendall(resp)

    def _dispatch(self, msg_id, op_tag, op_val):
        if op_tag == TAG_BIND_REQUEST:
            return _handle_bind(msg_id, op_val)

        elif op_tag == TAG_UNBIND_REQUEST:
            logger.info('Client %s:%d unbound', *self.addr)
            return None  # signal to close

        elif op_tag == TAG_SEARCH_REQUEST:
            attrs = _parse_search_attrs(op_val)
            return _handle_search(msg_id, op_val, attrs)

        elif op_tag == TAG_EXTENDED_REQ:
            return _handle_extended(msg_id, op_val, self.store)

        else:
            logger.warning('Unsupported op tag 0x%02x (msgId=%d)', op_tag, msg_id)
            return b''


# ---------------------------------------------------------------------------
# Server bootstrap
# ---------------------------------------------------------------------------

class ICSFMockServer:
    """
    TCP server that accepts LDAPv3 connections and handles ICSF extended ops.
    """

    def __init__(self, host='127.0.0.1', port=1389,
                 tls_cert=None, tls_key=None, tls_cacert=None,
                 preload_tokens=None, preload_objects=None):
        """
        Parameters
        ----------
        host, port       — listen address
        tls_cert/tls_key — paths to PEM cert/key for TLS (SASL EXTERNAL)
        tls_cacert       — PEM CA certificate used to verify client certs;
                           required when clients present self-signed certs
        preload_tokens   — list of dicts with keys: name, manufacturer, model, serial
                           tokens to create at startup for convenience
        preload_objects  — list of dicts with keys: token, label, class
                           objects to create inside tokens at startup
                           class may be 'aes', 'des3', 'rsa-pub', 'rsa-priv',
                           'ec-pub', 'ec-priv'  (default: 'aes')
        """
        self.host     = host
        self.port     = port
        self.store    = TokenStore()
        self._ssl_ctx = None

        if preload_tokens:
            for t in preload_tokens:
                self.store.create_token(
                    t['name'],
                    manufacturer=t.get('manufacturer', 'ICSF PKCS11 token browser'),
                    model=t.get('model', 'HCR77D0'),
                    serial=t.get('serial', '00000001'),
                )
                logger.info('Pre-loaded token: %r', t['name'])

        if preload_objects:
            for o in preload_objects:
                self._seed_object(o)

        if tls_cert and tls_key:
            self._ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._ssl_ctx.load_cert_chain(tls_cert, tls_key)
            if tls_cacert:
                # Load the CA that signed client certs so verification succeeds.
                # Without this the system CA bundle is used, which rejects
                # self-signed test certificates.
                self._ssl_ctx.load_verify_locations(tls_cacert)
                self._ssl_ctx.verify_mode = ssl.CERT_OPTIONAL
                logger.info('TLS enabled: cert=%s, cacert=%s', tls_cert, tls_cacert)
            else:
                # No CA supplied — don't request client certs at all.
                self._ssl_ctx.verify_mode = ssl.CERT_NONE
                logger.info('TLS enabled: cert=%s (no client cert verification)', tls_cert)

    def _seed_object(self, spec):
        """
        Create a pre-seeded test object in a token with all PKCS#11-defined
        attributes populated.

        spec keys:
          token   — token name (must already exist)
          label   — CKA_LABEL string
          class   — one of: aes, des, des2, des3, generic-secret,
                    rsa-pub, rsa-priv, dsa-pub, dsa-priv, dh-pub, dh-priv,
                    ec-pub, ec-priv, cert  (default: aes)
          private — 'yes'/'no' (default 'no')
        """
        token_name = spec.get('token', '')
        label      = spec.get('label', 'test-object')
        cls        = spec.get('class', 'aes').lower()
        is_private = spec.get('private', 'no').lower() in ('yes', 'true', '1')

        # Auto-create token if it doesn't exist yet
        if not self.store.token_exists(token_name):
            self.store.create_token(token_name)
            logger.info('Auto-created token %r for object pre-seeding', token_name)

        # Caller-supplied common attributes
        common = [
            (CKA_TOKEN,      bool_attr(True)),
            (CKA_PRIVATE,    bool_attr(is_private)),
            (CKA_LABEL,      label.encode()),
            (CKA_ID,         b''),
            (CKA_MODIFIABLE, bool_attr(True)),
        ]

        attrs = None   # will be set below

        if cls == 'aes':
            caller = common + [
                (CKA_CLASS,       CKO_SECRET_KEY),
                (CKA_KEY_TYPE,    CKK_AES),
                (CKA_VALUE,       bytes(32)),   # 256-bit zero key (test only)
                (CKA_SENSITIVE,   bool_attr(True)),
                (CKA_ENCRYPT,     bool_attr(True)),
                (CKA_DECRYPT,     bool_attr(True)),
                (CKA_EXTRACTABLE, bool_attr(False)),
            ]
            attrs = complete_key_attrs(caller,
                                       key_gen_mechanism=CKM_AES_KEY_GEN)

        elif cls == 'des':
            caller = common + [
                (CKA_CLASS,       CKO_SECRET_KEY),
                (CKA_KEY_TYPE,    CKK_DES),
                (CKA_VALUE,       bytes(8)),    # 64-bit zero key (test only)
                (CKA_SENSITIVE,   bool_attr(True)),
                (CKA_ENCRYPT,     bool_attr(True)),
                (CKA_DECRYPT,     bool_attr(True)),
                (CKA_EXTRACTABLE, bool_attr(False)),
            ]
            attrs = complete_key_attrs(caller,
                                       key_gen_mechanism=CKM_DES_KEY_GEN)

        elif cls == 'des2':
            caller = common + [
                (CKA_CLASS,       CKO_SECRET_KEY),
                (CKA_KEY_TYPE,    CKK_DES2),
                (CKA_VALUE,       bytes(16)),   # 128-bit zero key (test only)
                (CKA_SENSITIVE,   bool_attr(True)),
                (CKA_ENCRYPT,     bool_attr(True)),
                (CKA_DECRYPT,     bool_attr(True)),
                (CKA_EXTRACTABLE, bool_attr(False)),
            ]
            attrs = complete_key_attrs(caller,
                                       key_gen_mechanism=CKM_DES2_KEY_GEN)

        elif cls == 'des3':
            caller = common + [
                (CKA_CLASS,       CKO_SECRET_KEY),
                (CKA_KEY_TYPE,    CKK_DES3),
                (CKA_VALUE,       bytes(24)),   # 192-bit zero key (test only)
                (CKA_SENSITIVE,   bool_attr(True)),
                (CKA_ENCRYPT,     bool_attr(True)),
                (CKA_DECRYPT,     bool_attr(True)),
                (CKA_EXTRACTABLE, bool_attr(False)),
            ]
            attrs = complete_key_attrs(caller,
                                       key_gen_mechanism=CKM_DES3_KEY_GEN)

        elif cls == 'generic-secret':
            caller = common + [
                (CKA_CLASS,       CKO_SECRET_KEY),
                (CKA_KEY_TYPE,    CKK_GENERIC_SECRET),
                (CKA_VALUE,       bytes(32)),   # 256-bit zero key (test only)
                (CKA_SENSITIVE,   bool_attr(True)),
                (CKA_SIGN,        bool_attr(True)),
                (CKA_VERIFY,      bool_attr(True)),
                (CKA_EXTRACTABLE, bool_attr(False)),
            ]
            attrs = complete_key_attrs(caller,
                                       key_gen_mechanism=CKM_GENERIC_SECRET_KEY_GEN)

        elif cls in ('rsa-pub', 'rsa-priv'):
            modulus         = bytes(256)        # 2048-bit zero-filled placeholder
            public_exponent = b'\x01\x00\x01'   # 65537
            pub_common = common + [
                (CKA_ENCRYPT, bool_attr(True)),
                (CKA_VERIFY,  bool_attr(True)),
            ]
            priv_common = common + [
                (CKA_SENSITIVE,   bool_attr(True)),
                (CKA_DECRYPT,     bool_attr(True)),
                (CKA_SIGN,        bool_attr(True)),
                (CKA_EXTRACTABLE, bool_attr(False)),
            ]
            pub_final, priv_final = make_rsa_keypair_attrs(
                pub_caller_attrs=pub_common,
                priv_caller_attrs=priv_common,
                modulus=modulus,
                public_exponent=public_exponent,
                key_gen_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN,
            )
            attrs = pub_final if cls == 'rsa-pub' else priv_final

        elif cls in ('dsa-pub', 'dsa-priv'):
            # 1024-bit DSA with NIST L=1024/N=160 domain parameters (test only)
            p = int(
                'fd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80'
                'b6512669455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b'
                '801d346ff26660b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c6'
                '1bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554135a169132f675'
                'f3ae2b61d72aeff22203199dd14801c7', 16)
            q = int('9760508f15230bccb292b982a2eb840bf0581cf5', 16)
            g = int(
                'f7e75992dc03aa4991b31f5a23e834a9f787252c9e6e81d2f5a97b1f'
                '2ed6f89e7d2e26bdc5e66a88ae1fc14e55c0b09bfe59e6e76b7e3d3e'
                '4fd8b3b55df88e4b26daa2ef7a6d1ffd4b4d49e4c1a5f19d1bf8a3c8'
                '43ec08a54c2fc30e9c7d9d2e9b0aa8c3c8b8ddbb898c5a72a0c9d0e9'
                '82b4c1b2e7a5e97f2b20e9a5a49f9fe8', 16)
            p_bytes = p.to_bytes(128, 'big')
            q_bytes = q.to_bytes(20,  'big')
            g_bytes = g.to_bytes(128, 'big')
            key = dsa_generate(p_bytes, q_bytes, g_bytes)
            pub_common = common + [
                (CKA_VERIFY, bool_attr(True)),
            ]
            priv_common = common + [
                (CKA_SENSITIVE,   bool_attr(True)),
                (CKA_SIGN,        bool_attr(True)),
                (CKA_EXTRACTABLE, bool_attr(False)),
                (CKA_VALUE,       key['priv_value']),
            ]
            pub_final, priv_final = make_dsa_keypair_attrs(
                pub_caller_attrs=pub_common,
                priv_caller_attrs=priv_common,
                prime=key[CKA_PRIME],
                subprime=key[CKA_SUBPRIME],
                base=key[CKA_BASE],
                pub_value=key['pub_value'],
                priv_value=key['priv_value'],
                key_gen_mechanism=CKM_DSA_KEY_PAIR_GEN,
            )
            attrs = pub_final if cls == 'dsa-pub' else priv_final

        elif cls in ('dh-pub', 'dh-priv'):
            # 1024-bit DH with RFC 2409 Group 2 parameters (test only)
            p = int(
                'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e08'
                '8a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b'
                '302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9'
                'a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe6'
                '49286651ece65381ffffffffffffffff', 16)
            g = 2
            p_bytes = p.to_bytes(128, 'big')
            g_bytes = g.to_bytes(1,   'big')
            key = dh_generate(p_bytes, g_bytes)
            pub_common = common + [
                (CKA_DERIVE, bool_attr(True)),
            ]
            priv_common = common + [
                (CKA_SENSITIVE,   bool_attr(True)),
                (CKA_DERIVE,      bool_attr(True)),
                (CKA_EXTRACTABLE, bool_attr(False)),
                (CKA_VALUE,       key['priv_value']),
            ]
            pub_final, priv_final = make_dh_keypair_attrs(
                pub_caller_attrs=pub_common,
                priv_caller_attrs=priv_common,
                prime=key[CKA_PRIME],
                base=key[CKA_BASE],
                pub_value=key['pub_value'],
                priv_value=key['priv_value'],
                key_gen_mechanism=CKM_DH_PKCS_KEY_PAIR_GEN,
            )
            attrs = pub_final if cls == 'dh-pub' else priv_final

        elif cls == 'cert':
            # Minimal self-signed placeholder — just enough DER structure so
            # tools that inspect CKA_VALUE don't crash on a zero-length value.
            # Real tests should supply an actual DER cert via C_CreateObject.
            der_placeholder = bytes.fromhex(
                '3082014a'          # SEQUENCE (certificate)
                '30820132'          # SEQUENCE (tbsCertificate)
                '020100'            # INTEGER version 0
                '300d06092a864886f70d01010b0500'  # sha256WithRSAEncryption OID
                '3000'              # SEQUENCE (issuer — empty)
                '3000'              # SEQUENCE (validity — empty)
                '3000'              # SEQUENCE (subject — empty)
                '3000'              # SEQUENCE (subjectPublicKeyInfo — empty)
            )
            caller = common + []   # common already has TOKEN/PRIVATE/LABEL/ID
            attrs = make_x509_cert_attrs(der_placeholder, caller_attrs=caller)

        elif cls in ('ec-pub', 'ec-priv'):
            # NIST P-256 OID: 1.2.840.10045.3.1.7
            ec_params = bytes.fromhex('06082a8648ce3d030107')
            key = ec_generate(ec_params)
            pub_common = common + [
                (CKA_VERIFY, bool_attr(True)),
            ]
            priv_common = common + [
                (CKA_SENSITIVE,   bool_attr(True)),
                (CKA_SIGN,        bool_attr(True)),
                (CKA_EXTRACTABLE, bool_attr(False)),
                (CKA_VALUE,       key[CKA_VALUE]),
            ]
            pub_final, priv_final = make_ec_keypair_attrs(
                pub_caller_attrs=pub_common,
                priv_caller_attrs=priv_common,
                ec_params=key[CKA_EC_PARAMS],
                ec_point=key[CKA_EC_POINT],
                key_gen_mechanism=CKM_EC_KEY_PAIR_GEN,
            )
            attrs = pub_final if cls == 'ec-pub' else priv_final

        else:
            if cls == 'data':
                logger.error('Pre-seeding class %r is not supported: only key '
                             'and certificate objects are stored by this mock. '
                             'Use aes, des, des2, des3, generic-secret, '
                             'rsa-pub, rsa-priv, dsa-pub, dsa-priv, '
                             'dh-pub, dh-priv, ec-pub, ec-priv, or cert.',
                             cls)
            else:
                logger.error('Unknown object class %r for pre-seeding. '
                             'Use aes, des, des2, des3, generic-secret, '
                             'rsa-pub, rsa-priv, dsa-pub, dsa-priv, '
                             'dh-pub, dh-priv, ec-pub, ec-priv, or cert.',
                             cls)
            return

        obj = self.store.create_object(token_name, OBJ_TYPE_TOKEN, attrs)
        if obj:
            logger.info('Pre-seeded object token=%r seq=%d label=%r class=%s attrs=%d',
                        token_name, obj.sequence, label, cls, len(attrs))
        else:
            logger.error('Failed to pre-seed object in token %r', token_name)

    def run_forever(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(16)
            logger.info('ICSF mock server listening on %s:%d', self.host, self.port)
            while True:
                conn, addr = srv.accept()
                if self._ssl_ctx:
                    try:
                        conn = self._ssl_ctx.wrap_socket(conn, server_side=True)
                    except ssl.SSLError as exc:
                        logger.warning('TLS handshake failed from %s:%d: %s', *addr, exc)
                        conn.close()
                        continue
                t = ClientHandler(conn, addr, self.store)
                t.start()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description='ICSF mock LDAP server for openCryptoki testing')
    ap.add_argument('--host',    default='127.0.0.1',
                    help='Listen address (default: 127.0.0.1)')
    ap.add_argument('--port',    type=int, default=1389,
                    help='Listen port (default: 1389)')
    ap.add_argument('--cert',    default=None,
                    help='PEM server certificate file (enables TLS / SASL EXTERNAL)')
    ap.add_argument('--key',     default=None,
                    help='PEM server private key file (requires --cert)')
    ap.add_argument('--cacert',  default=None,
                    help='PEM CA certificate used to verify client certificates '
                         '(required for SASL EXTERNAL with self-signed certs)')
    ap.add_argument('--token',   action='append', default=[],
                    metavar='NAME',
                    help='Pre-create a token with this name (repeatable)')
    ap.add_argument('--object',  action='append', default=[],
                    metavar='TOKEN:LABEL:CLASS',
                    help='Pre-seed an object (repeatable). '
                         'TOKEN is the token name, LABEL is CKA_LABEL, '
                         'CLASS is one of: aes, des, des2, des3, '
                         'generic-secret, rsa-pub, rsa-priv, '
                         'dsa-pub, dsa-priv, dh-pub, dh-priv, '
                         'ec-pub, ec-priv, cert  (default: aes). '
                         'Example: --object TESTTOKEN:mykey:aes')
    ap.add_argument('--verbose', action='store_true',
                    help='Enable DEBUG logging')
    args = ap.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(name)s: %(message)s',
        level=level,
        stream=sys.stdout)

    preload_tokens = [{'name': n} for n in args.token]

    preload_objects = []
    for obj_spec in args.object:
        parts = obj_spec.split(':', 2)
        if len(parts) < 2:
            print(f'ERROR: --object requires TOKEN:LABEL[:CLASS], got {obj_spec!r}',
                  file=sys.stderr)
            sys.exit(1)
        preload_objects.append({
            'token': parts[0],
            'label': parts[1],
            'class': parts[2] if len(parts) > 2 else 'aes',
        })

    srv = ICSFMockServer(
        host=args.host,
        port=args.port,
        tls_cert=args.cert,
        tls_key=args.key,
        tls_cacert=args.cacert,
        preload_tokens=preload_tokens if preload_tokens else None,
        preload_objects=preload_objects if preload_objects else None,
    )
    srv.run_forever()


if __name__ == '__main__':
    main()
