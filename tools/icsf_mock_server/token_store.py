# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
token_store.py — In-memory token and object registry for the ICSF mock server.

Mirrors the data model that the real z/OS ICSF service maintains:

  Token
  ├── name (up to 32 chars, space-padded on the wire)
  ├── manufacturer (up to 32 chars)
  ├── model (up to 16 chars)
  ├── serial (up to 16 chars)
  ├── date / time  (updated on every mutation, UTC)
  ├── flags (4 bytes — bit 7 of byte 0 = read-only)
  └── objects: dict[sequence -> Object]

  Object
  ├── token_name
  ├── sequence  (unique within token, hex-encoded in the 44-byte handle)
  ├── obj_type  'T' (token) | 'S' (session)
  └── attributes: dict[attr_type -> bytes|int]

Thread safety: a single threading.Lock guards all mutations so the TCP server
can serve multiple connections safely.
"""

import logging
import threading
import time

from pkcs11_const import CKA_NAME
from handlers.hmac_state import HmacSessionStore

logger = logging.getLogger(__name__)

# Object type characters — must match ICSF_SESSION_OBJECT / ICSF_TOKEN_OBJECT
OBJ_TYPE_SESSION = 'S'
OBJ_TYPE_TOKEN   = 'T'

# Token record wire sizes (from icsf.h)
TOKEN_NAME_LEN   = 32
MANUF_LEN        = 32
MODEL_LEN        = 16
SERIAL_LEN       = 16
DATE_LEN         = 8
TIME_LEN         = 8
FLAGS_LEN        = 4
TOKEN_RECORD_LEN = (TOKEN_NAME_LEN + MANUF_LEN + MODEL_LEN +
                    SERIAL_LEN + DATE_LEN + TIME_LEN + FLAGS_LEN)  # 116


def _pad(s, length):
    """Return bytes of exactly `length`, space-padded or truncated."""
    if isinstance(s, str):
        s = s.encode('ascii', errors='replace')
    return s[:length].ljust(length, b' ')


def _now_date_time():
    """Return (date_str, time_str) in ICSF format."""
    t = time.gmtime()
    date = '%04d%02d%02d' % (t.tm_year, t.tm_mon, t.tm_mday)
    time_s = '%02d%02d%02d00' % (t.tm_hour, t.tm_min, t.tm_sec)
    return date, time_s


class Object:
    """A single PKCS#11 object stored inside a token."""

    def __init__(self, token_name, sequence, obj_type):
        self.token_name = token_name
        self.sequence   = sequence
        self.obj_type   = obj_type          # 'T' or 'S'
        self.attributes = {}                # attr_type (int) -> bytes or int

    def set_attr(self, attr_type, value):
        self.attributes[attr_type] = value

    def get_attr(self, attr_type):
        return self.attributes.get(attr_type)

    def get_all_attrs(self):
        return list(self.attributes.items())


class Token:
    """A single PKCS#11 token managed by the ICSF mock."""

    def __init__(self, name, manufacturer='', model='', serial=''):
        self.name         = name[:TOKEN_NAME_LEN]
        self.manufacturer = manufacturer[:MANUF_LEN]
        self.model        = model[:MODEL_LEN]
        self.serial       = serial[:SERIAL_LEN]
        date, ts = _now_date_time()
        self.date         = date
        self.time         = ts
        self.flags        = b'\x00\x00\x00\x00'   # not read-only
        self._next_seq    = 1
        self.objects      = {}   # sequence (int) -> Object

    def _touch(self):
        self.date, self.time = _now_date_time()

    def next_sequence(self):
        seq = self._next_seq
        self._next_seq += 1
        return seq

    def add_object(self, obj_type, attrs):
        """Create a new object and return it."""
        seq = self.next_sequence()
        obj = Object(self.name, seq, obj_type)
        for attr_type, value in attrs:
            obj.set_attr(attr_type, value)
        self.objects[seq] = obj
        self._touch()
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                'create_object token=%r seq=%d type=%s attrs=%d:',
                self.name, seq, obj_type, len(attrs))
            for attr_type, value in attrs:
                name = CKA_NAME.get(attr_type, '0x%08x' % attr_type)
                display = value.hex() if isinstance(value, (bytes, bytearray)) else repr(value)
                logger.debug('  %-30s = %s', name, display)
        return obj

    def get_object(self, sequence):
        return self.objects.get(sequence)

    def destroy_object(self, sequence):
        if sequence in self.objects:
            del self.objects[sequence]
            self._touch()
            return True
        return False

    def list_objects(self, after_seq=None):
        """
        Return objects in ascending sequence order.
        If after_seq is given, return only those with sequence > after_seq.
        """
        seqs = sorted(self.objects.keys())
        if after_seq is not None:
            seqs = [s for s in seqs if s > after_seq]
        return [self.objects[s] for s in seqs]

    def to_wire_record(self):
        """
        Encode this token as a 116-byte wire record (see parse_token_record
        in icsf.c for the layout).
        """
        return (
            _pad(self.name,         TOKEN_NAME_LEN) +
            _pad(self.manufacturer, MANUF_LEN)      +
            _pad(self.model,        MODEL_LEN)       +
            _pad(self.serial,       SERIAL_LEN)      +
            _pad(self.date,         DATE_LEN)        +
            _pad(self.time,         TIME_LEN)        +
            self.flags[:FLAGS_LEN].ljust(FLAGS_LEN, b'\x00')
        )


class TokenStore:
    """
    Thread-safe registry of tokens and their objects.

    All public methods acquire self._lock before touching state.
    """

    def __init__(self):
        self._lock      = threading.Lock()
        self._tokens    = {}    # name (str) -> Token
        self.hmac_state = HmacSessionStore()

    # ------------------------------------------------------------------
    # Token operations
    # ------------------------------------------------------------------

    def create_token(self, name, manufacturer='', model='', serial=''):
        """Create or recreate a token (mirrors RECREATE rule in icsf.c)."""
        with self._lock:
            self._tokens[name] = Token(name, manufacturer, model, serial)

    def destroy_token(self, name):
        """Remove a token and all its objects. Returns True if it existed."""
        with self._lock:
            if name in self._tokens:
                del self._tokens[name]
                return True
            return False

    def get_token(self, name):
        with self._lock:
            return self._tokens.get(name)

    def list_tokens(self, after_name=None):
        """
        Return Token objects in sorted order.
        If after_name is given, return only those lexicographically after it.
        """
        with self._lock:
            names = sorted(self._tokens.keys())
            if after_name:
                names = [n for n in names if n > after_name]
            return [self._tokens[n] for n in names]

    def token_exists(self, name):
        with self._lock:
            return name in self._tokens

    # ------------------------------------------------------------------
    # Object operations (all require the token to already exist)
    # ------------------------------------------------------------------

    def create_object(self, token_name, obj_type, attrs):
        """
        Create an object inside the named token.
        Returns the Object on success, None if the token does not exist.
        """
        with self._lock:
            token = self._tokens.get(token_name)
            if token is None:
                return None
            return token.add_object(obj_type, attrs)

    def destroy_object(self, token_name, sequence):
        """Remove an object. Returns True on success."""
        with self._lock:
            token = self._tokens.get(token_name)
            if token is None:
                return False
            return token.destroy_object(sequence)

    def get_object(self, token_name, sequence):
        with self._lock:
            token = self._tokens.get(token_name)
            if token is None:
                return None
            return token.get_object(sequence)

    def set_object_attrs(self, token_name, sequence, attrs):
        """
        Update attributes on an existing object.
        attrs is a list of (attr_type, value) tuples.
        Returns True on success.
        """
        with self._lock:
            token = self._tokens.get(token_name)
            if token is None:
                return False
            obj = token.get_object(sequence)
            if obj is None:
                return False
            for attr_type, value in attrs:
                obj.set_attr(attr_type, value)
            token._touch()
            return True

    def list_objects(self, token_name, after_seq=None):
        """
        Return a list of Objects for token_name in ascending sequence order,
        optionally starting after after_seq.
        """
        with self._lock:
            token = self._tokens.get(token_name)
            if token is None:
                return []
            return token.list_objects(after_seq=after_seq)
