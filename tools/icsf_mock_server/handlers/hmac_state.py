# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
handlers/hmac_state.py — Server-side session store for multipart HMAC.

Real ICSF maintains an opaque chaining context across FIRST/MIDDLE/LAST calls.
The mock simulates this by keeping a per-session accumulator on the server and
embedding a 16-byte random session ID in the chain_data it sends back to the
client.  The client stores the chain_data blob and echoes it back on every
subsequent call, so we can look up the right accumulator.

Wire layout of the chain_data returned to the C client:

    HMG response ("{ooi}" scan — icsf_hmac_sign):
        ber_scanf enters the context TLV via '{' and reads the first field
        with 'o' (OCTET STRING value bytes).  For FIRST/MIDDLE we put the
        raw 16-byte session ID as the chainData OCTET STRING value.
        The C code copies those 16 bytes into chain_data[128].  On the next
        call chain_data (128 bytes, first 16 = session ID) is echoed back;
        we extract sid = chain_in[:16].

    HMV response (bare 'm' scan — icsf_hmac_verify):
        ber_scanf(result, "m", ...) returns the context TLV value bytes as
        bvChain (no inner BER parsing).  For FIRST/MIDDLE we return the raw
        16-byte session ID as svc_data.  The C code copies those 16 bytes
        into chain_data[128].  On the next call chain_data (128 bytes) is
        echoed back; we extract sid = chain_in[:16].

Thread safety: a single threading.Lock protects the session dict.
"""

import os
import threading

SESSION_ID_LEN = 16


class HmacSessionStore:
    """
    Holds in-progress multipart HMAC sessions for both HMG and HMV.

    Each session is a dict:
        {
            'key':   bytes,          # raw HMAC key
            'algo':  str,            # hashlib name, e.g. 'sha1'
            'data':  bytearray,      # accumulated text so far
        }
    """

    def __init__(self):
        self._lock     = threading.Lock()
        self._sessions = {}   # session_id (bytes, 16 bytes) -> dict

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    def create(self, key: bytes, algo: str) -> bytes:
        """
        Start a new session.  Returns the 16-byte session ID.
        The caller is responsible for wrapping this as appropriate
        for the wire format (HMG vs HMV differ; see each handler).
        """
        sid = os.urandom(SESSION_ID_LEN)
        with self._lock:
            self._sessions[sid] = {
                'key':  key,
                'algo': algo,
                'data': bytearray(),
            }
        return sid

    def append(self, sid: bytes, text: bytes) -> bool:
        """
        Append *text* to the session identified by *sid*.
        Returns True on success, False if the session is not found.
        """
        with self._lock:
            sess = self._sessions.get(sid)
            if sess is None:
                return False
            sess['data'] += text
        return True

    def finalize(self, sid: bytes, text: bytes):
        """
        Append *text* and remove the session.
        Returns (key, algo, full_data) or None if session not found.
        """
        with self._lock:
            sess = self._sessions.pop(sid, None)
        if sess is None:
            return None
        sess['data'] += text
        return sess['key'], sess['algo'], bytes(sess['data'])

    def discard(self, sid: bytes):
        """Remove a session without finalizing (error cleanup)."""
        with self._lock:
            self._sessions.pop(sid, None)
