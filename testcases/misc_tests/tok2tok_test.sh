#!/bin/bash
#
# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php
#
# NAME
#       tok2tok_test.sh
#
# DESCRIPTION
#       Discovers all available, initialized tokens and runs tok2tok_transport
#       for every combination of slots (including same-slot). When multiple
#       slots carry tokens of the same type/model, only the first one is used
#       to avoid redundant runs.
#
#       Each run is spawned as a background process. Its combined stdout and
#       stderr are redirected to log-tok2tok-slots_X_Y.txt where X and Y are
#       the two slot numbers used.
#
# ENVIRONMENT
#       PKCSLIB           - path to libopencryptoki.so (required)
#       PKCS11_USER_PIN   - user PIN (required)
#       SBINDIR           - directory containing pkcsconf (optional; falls back
#                           to "pkcsconf" on $PATH)
#       TOK2TOK_BINARY    - override path to tok2tok_transport binary
#                           (optional; defaults to same directory as this
#                           script)
#

TESTDIR=$(dirname "$0")

# ---------------------------------------------------------------------------
# Locate pkcsconf
# ---------------------------------------------------------------------------
if [ -n "$SBINDIR" ]; then
    PKCSCONFBIN="$SBINDIR/pkcsconf"
elif command -v pkcsconf &>/dev/null; then
    PKCSCONFBIN="pkcsconf"
else
    echo "FATAL: pkcsconf not found. Set SBINDIR or add it to PATH."
    exit 1
fi

# ---------------------------------------------------------------------------
# Locate tok2tok_transport binary
# ---------------------------------------------------------------------------
if [ -n "$TOK2TOK_BINARY" ]; then
    TOK2TOK="$TOK2TOK_BINARY"
else
    TOK2TOK="$TESTDIR/tok2tok_transport"
fi

if [ ! -x "$TOK2TOK" ]; then
    echo "FATAL: tok2tok_transport binary not found or not executable: $TOK2TOK"
    exit 1
fi

# ---------------------------------------------------------------------------
# Validate required environment variables
# ---------------------------------------------------------------------------
if [ -z "$PKCS11_USER_PIN" ]; then
    echo "FATAL: Must set PKCS11_USER_PIN"
    exit 1
fi

if [ -z "$PKCSLIB" ]; then
    echo "FATAL: Must set PKCSLIB"
    exit 1
fi

echo "** Now executing 'tok2tok_test.sh'"
echo "** Using tok2tok_transport binary: $TOK2TOK"
echo "** Using pkcsconf: $PKCSCONFBIN"

# ---------------------------------------------------------------------------
# Discover available slots and deduplicate by token type/model.
#
# Strategy:
#   1. List all slot numbers from pkcsconf -s.
#   2. For each slot query the token info with pkcsconf -c <slot> -t.
#   3. Accept only initialized tokens (TOKEN_INITIALIZED flag set).
#   4. Extract the Model: field — this is the token type key.
#   5. Keep only the first slot seen for each distinct model string.
# ---------------------------------------------------------------------------
declare -a SLOTS=()
SEEN_MODELS="|"

ALL_SLOTS=$("$PKCSCONFBIN" -s 2>/dev/null | grep -Po '^Slot #\K[0-9]+')

if [ -z "$ALL_SLOTS" ]; then
    echo "SKIP: No slots found by pkcsconf."
    exit 0
fi

for slot in $ALL_SLOTS; do
    TOKINFO=$("$PKCSCONFBIN" -c "$slot" -t 2>/dev/null)
    if [ -z "$TOKINFO" ]; then
        echo "  Slot $slot: no token info, skipping."
        continue
    fi

    # Only consider initialized tokens
    INITIALIZED=$(echo "$TOKINFO" | grep "Flags:" | grep -c "TOKEN_INITIALIZED")
    if [ "$INITIALIZED" -eq 0 ]; then
        echo "  Slot $slot: token not initialized, skipping."
        continue
    fi

    # Extract model (token type identifier)
    MODEL=$(echo "$TOKINFO" | grep "Model:" | sed 's/.*Model:[[:space:]]*//' | awk '{print $1}')
    if [ -z "$MODEL" ]; then
        echo "  Slot $slot: cannot determine token model, skipping."
        continue
    fi

    # Check whether this model was already seen; if so, extract the first slot
    # that claimed it from the "|MODEL:SLOT|" entry in SEEN_MODELS.
    if [[ "$SEEN_MODELS" == *"|${MODEL}:"* ]]; then
        FIRST_SLOT="${SEEN_MODELS##*|${MODEL}:}"
        FIRST_SLOT="${FIRST_SLOT%%|*}"
        echo "  Slot $slot: model '$MODEL' already represented by slot $FIRST_SLOT, skipping."
        continue
    fi

    SEEN_MODELS="${SEEN_MODELS}${MODEL}:${slot}|"
    SLOTS+=("$slot")
    echo "  Slot $slot: model '$MODEL' — will be used."
done

if [ "${#SLOTS[@]}" -eq 0 ]; then
    echo "SKIP: No suitable initialized slots found."
    exit 0
fi

echo ""
echo "** Slots selected for tok2tok_transport combinations: ${SLOTS[*]}"
echo ""

# ---------------------------------------------------------------------------
# Run tok2tok_transport for every ordered pair (slot_x, slot_y).
# At most MAX_JOBS processes run concurrently to avoid OOM situations.
# Each run writes its output to log-tok2tok-slots_X_Y.txt.
# ---------------------------------------------------------------------------
MAX_JOBS=4
OVERALL_RC=0
FAILED_JOBS=()
PIDS=()
LOGFILES=()
SLOTS1=()
SLOTS2=()

for slot_x in "${SLOTS[@]}"; do
    for slot_y in "${SLOTS[@]}"; do
        # Wait until the number of running jobs drops below MAX_JOBS.
        while [ "${#PIDS[@]}" -ge "$MAX_JOBS" ]; do
            # Scan for any job that has already finished.
            NEW_PIDS=()
            NEW_LOGFILES=()
            NEW_SLOTS1=()
            NEW_SLOTS2=()
            for i in "${!PIDS[@]}"; do
                if kill -0 "${PIDS[$i]}" 2>/dev/null; then
                    NEW_PIDS+=("${PIDS[$i]}")
                    NEW_LOGFILES+=("${LOGFILES[$i]}")
                    NEW_SLOTS1+=("${SLOTS1[$i]}")
                    NEW_SLOTS2+=("${SLOTS2[$i]}")
                else
                    wait "${PIDS[$i]}"
                    RC=$?
                    if [ $RC -ne 0 ]; then
                        echo "* TESTCASE tok2tok_transport slots_${SLOTS1[$i]}_${SLOTS2[$i]} FAIL exited with rc=$RC (see ${LOGFILES[$i]})"
                        OVERALL_RC=1
                        FAILED_JOBS+=("slots ${SLOTS1[$i]} and ${SLOTS2[$i]} (rc=$RC, log=${LOGFILES[$i]})")
                    else
                        echo "* TESTCASE tok2tok_transport slots_${SLOTS1[$i]}_${SLOTS2[$i]} PASS (see ${LOGFILES[$i]})"
                    fi
                fi
            done
            PIDS=("${NEW_PIDS[@]}")
            LOGFILES=("${NEW_LOGFILES[@]}")
            SLOTS1=("${NEW_SLOTS1[@]}")
            SLOTS2=("${NEW_SLOTS2[@]}")
            # If still at limit, yield briefly before re-checking.
            [ "${#PIDS[@]}" -ge "$MAX_JOBS" ] && sleep 1
        done

        LOGFILE="log-tok2tok-slots_${slot_x}_${slot_y}.txt"
        echo "** Spawning: $TOK2TOK -slot1 $slot_x -slot2 $slot_y  (output -> $LOGFILE)"
        echo "** Now executing 'tok2tok_transport -slot1 $slot_x -slot2 $slot_y'" >"$LOGFILE"
        PKCSLIB="$PKCSLIB" \
            PKCS11_USER_PIN="$PKCS11_USER_PIN" \
            "$TOK2TOK" -slot1 "$slot_x" -slot2 "$slot_y" \
            >>"$LOGFILE" 2>&1 &
        PIDS+=($!)
        LOGFILES+=("$LOGFILE")
        SLOTS1+=("$slot_x")
        SLOTS2+=("$slot_y")
    done
done

# ---------------------------------------------------------------------------
# Wait for all remaining background jobs and collect exit codes.
# ---------------------------------------------------------------------------
for i in "${!PIDS[@]}"; do
    wait "${PIDS[$i]}"
    RC=$?
    if [ $RC -ne 0 ]; then
        echo "* TESTCASE tok2tok_transport slots_${SLOTS1[$i]}_${SLOTS2[$i]} FAIL exited with rc=$RC (see ${LOGFILES[$i]})"
        OVERALL_RC=1
        FAILED_JOBS+=("slots ${SLOTS1[$i]} and ${SLOTS2[$i]} (rc=$RC, log=${LOGFILES[$i]})")
    else
        echo "* TESTCASE tok2tok_transport slots_${SLOTS1[$i]}_${SLOTS2[$i]} PASS (see ${LOGFILES[$i]})"
    fi
done

echo ""
if [ $OVERALL_RC -ne 0 ]; then
    echo "** tok2tok_test.sh FINISHED WITH ERRORS (rc=$OVERALL_RC)"
    echo "** Failed combinations:"
    for entry in "${FAILED_JOBS[@]}"; do
        echo "     $entry"
    done
else
    echo "** tok2tok_test.sh FINISHED SUCCESSFULLY"
fi

exit $OVERALL_RC
