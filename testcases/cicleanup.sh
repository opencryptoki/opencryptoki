#!/bin/bash
#
# cicleanup.sh - remove all tokens created by ciconfig.sh
#
# Usage: cicleanup.sh <sbindir> [icsf-token-name [icsf-mock-pid-file]]
#
#   sbindir             directory containing pkcsstats
#   icsf-token-name     name of the ICSF token added by pkcsicsf -a (default: icsf0)
#   icsf-mock-pid-file  PID file written by ciconfig.sh for the mock server
#                       (default: .icsf_mock_server.pid in the current directory)

SBINDIR="$1"
ICSF_MOCK_TOKEN="${2:-icsf0}"
ICSF_MOCK_PID_FILE="${3:-.icsf_mock_server.pid}"

if [ -z "${SBINDIR}" ]; then
    echo "Usage: $0 <sbindir> [icsf-token-name [icsf-mock-pid-file]]" >&2
    exit 1
fi

# Stop the ICSF mock server if its PID file is present and the process is alive.
if [ -f "${ICSF_MOCK_PID_FILE}" ]; then
    ICSF_PID=$(cat "${ICSF_MOCK_PID_FILE}")
    if kill -0 "${ICSF_PID}" 2>/dev/null; then
        echo "Stopping ICSF mock server (pid=${ICSF_PID})..."
        kill "${ICSF_PID}"
    else
        echo "WARNING: ICSF mock server PID ${ICSF_PID} is stale; nothing to stop." >&2
    fi
    rm -f "${ICSF_MOCK_PID_FILE}"
fi

# Remove all token datastores created by ciconfig.sh.
# ep5 and ep6 are conditional (CEX8 only) so failures are expected.
for tok in ica0 ica1 \
           cca0 cca1 \
           sw0  sw1  \
           ep0  ep1  ep3  ep4  ep5  ep6 \
           "${ICSF_MOCK_TOKEN}"; do
    "${SBINDIR}/pkcstok_admin" remove --token "${tok}" --force 2>/dev/null || true
done

"${SBINDIR}/pkcsstats" --delete-all || true
