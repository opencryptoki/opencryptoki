#!/bin/bash

OCKCONFDIR="$1"
EPCONFDIR="$2"
CCACONFDIR="$3"
COMBINED_EXTRACT_FILE="$4"
ICSF_MOCK_SERVER_PID_FILE="${5:-.icsf_mock_server.pid}"
ICSF_MOCK_SERVER_SCRIPT="${6:-$(dirname "$0")/../tools/icsf_mock_server/server.py}"
ICSF_MOCK_SERVER_PORT="${7:-1389}"
ICSF_MOCK_TOKEN="${8:-icsf0}"
ICSF_SLOT="${9:-50}"
ICSF_MOCK_SERVER_LOG="${10:-/tmp/icsf_mock_server.log}"

LATESTCEXP="CEX8P"

CCA_SYM_MKVP="5776993D2741EB4A"
CCA_AES_MKVP="E9A49A58CD039BED"
CCA_APKA_MKVP="5F2F27AAA2D59B4A"
EP11_WKVP="8b991263e3a8f4e4be0d5ec8f0a4df9e"

USENEWFORMAT=/bin/false

# Usage: addslot slot-num stdll slot-name [confname]
function addslot() {
    cat <<EOF >> "${OCKCONFDIR}/opencryptoki.conf"
slot $1
{
stdll = $2
tokname = $3
EOF
    if $USENEWFORMAT; then
        echo "tokversion = 3.12" >> "${OCKCONFDIR}/opencryptoki.conf"
    fi
    if [ "x$4" != "x" ]; then
       echo "confname = $4" >> "${OCKCONFDIR}/opencryptoki.conf"
    fi
    if test ! -z ${TOKEN_GROUP}; then
       echo "usergroup = ${TOKEN_GROUP}" >> "${OCKCONFDIR}/opencryptoki.conf"
    fi
    echo "}" >> "${OCKCONFDIR}/opencryptoki.conf"

    pkcstok_admin remove --token $3 --force &> /dev/null
    if test ! -z ${TOKEN_GROUP}; then
        pkcstok_admin create --token $3 --group ${TOKEN_GROUP} --force &> /dev/null
    fi
}

# Usage: genep11cfg num configline
function genep11cfg() {
    cat <<EOF > "${EPCONFDIR}/ep11tok${1}.conf"
${2}
APQN_ANY
EOF
}

# Usage: genlatestep11cfg num configline
# Return: 0 if successful
function genlatestep11cfg() {
    local res=1
    
    lszcrypt | grep "$LATESTCEXP" | perl -ne '/([0-9a-fA-F]+)\.([0-9a-fA-F]+)\s.*/ && print "0x$1 0x$2\n"' > tmp.apqns
    if test -s tmp.apqns; then
        echo "${2}" > "${EPCONFDIR}/ep11tok${1}.conf"
        echo "APQN_WHITELIST" >> "${EPCONFDIR}/ep11tok${1}.conf"
        cat tmp.apqns >> "${EPCONFDIR}/ep11tok${1}.conf"
        echo "END" >> "${EPCONFDIR}/ep11tok${1}.conf"
        res=0
    fi
    rm -f tmp.apqns
    return $res
}

# Usage: setup_icsf_mock_token
# Starts the ICSF mock server in the background, writes its PID to
# ICSF_MOCK_SERVER_PID_FILE, then runs pkcsicsf -a to register the token.
# All variables are read from the script-level globals set at the top.
function setup_icsf_mock_token() {
    if ! command -v python3 &>/dev/null; then
        echo "NOTE: python3 not found; skipping ICSF mock server setup."
        return 0
    fi
    if [ ! -f "${ICSF_MOCK_SERVER_SCRIPT}" ]; then
        echo "NOTE: ICSF mock server script not found at '${ICSF_MOCK_SERVER_SCRIPT}'; skipping ICSF mock server setup."
        return 0
    fi

    echo "Starting ICSF mock server (token=${ICSF_MOCK_TOKEN}, port=${ICSF_MOCK_SERVER_PORT})..."
    python3 "${ICSF_MOCK_SERVER_SCRIPT}" \
        --port "${ICSF_MOCK_SERVER_PORT}" \
        --token "${ICSF_MOCK_TOKEN}" \
        &>"${ICSF_MOCK_SERVER_LOG}" &
    local pid=$!
    echo "${pid}" > "${ICSF_MOCK_SERVER_PID_FILE}"
    # Wait up to 5 seconds for the mock server to start listening
    local ready=0
    for _ in $(seq 1 50); do
        if ! kill -0 "${pid}" 2>/dev/null; then
            break
        fi
        if python3 -c "import socket; s = socket.socket(); s.settimeout(0.5); s.connect(('127.0.0.1', ${ICSF_MOCK_SERVER_PORT})); s.close()" 2>/dev/null; then
            ready=1
            break
        fi
        sleep 0.1
    done

    if [ ${ready} -eq 0 ]; then
        echo "WARNING: ICSF mock server failed to start or listen on port ${ICSF_MOCK_SERVER_PORT}; skipping ICSF token setup." >&2
        kill "${pid}" 2>/dev/null || true
        rm -f "${ICSF_MOCK_SERVER_PID_FILE}"
        return 1
    fi
    echo "ICSF mock server started (pid=${pid})"

    pkcsicsf -a "${ICSF_MOCK_TOKEN}" \
        -u "ldap://127.0.0.1:${ICSF_MOCK_SERVER_PORT}" \
        -b "cn=testuser,dc=example,dc=com" \
        -m simple \
        -s "${ICSF_SLOT}" \
        -R "${ICSF_MOCK_RACF_PASSWORD:-testpassword}" \
        -S "${PKCS11_SO_PIN:-76543210}"
    local pkcsicsf_rc=$?
    if [ ${pkcsicsf_rc} -ne 0 ]; then
        echo "WARNING: pkcsicsf -a failed (rc=${pkcsicsf_rc}); ICSF slot ${ICSF_SLOT} will not be configured." >&2
        return 1
    fi
    echo "ICSF token '${ICSF_MOCK_TOKEN}' added at slot ${ICSF_SLOT}"
}

# Usage: genccacfg num
function genccacfg() {
    cat <<EOF > "${CCACONFDIR}/ccatok${1}.conf"
version cca-0
EXPECTED_MKVPS {
  SYM = "$CCA_SYM_MKVP"
  AES = "$CCA_AES_MKVP"
  APKA = "$CCA_APKA_MKVP"
}
PKEY_MODE = ENABLED
AES_KEY_MODE = CIPHER
EOF
}

if test $(($(date +%-j)%2)) == 1; then
    USENEWFORMAT=/bin/true
    echo "Using FIPS compliant token store"
else
    echo "Using legacy token store"
fi

if test ! -z ${PKCS11_TEST_USER}; then
    if test ! -z ${PKCS11_TEST_GROUP}; then
        TOKEN_GROUP=${PKCS11_TEST_GROUP}
    else
        TOKEN_GROUP="tokgroup"
    fi
    getent group ${TOKEN_GROUP} >/dev/null || groupadd -r ${TOKEN_GROUP}
    usermod -a -G ${TOKEN_GROUP} ${PKCS11_TEST_USER}
fi

# initialize opencryptoki.conf
echo "version opencryptoki-3.27" > "${OCKCONFDIR}/opencryptoki.conf"

# enable full statistics
echo "statistics (on,implicit,internal)" >> "${OCKCONFDIR}/opencryptoki.conf"

# ICA token
addslot 10 libpkcs11_ica.so ica0
addslot 11 libpkcs11_ica.so ica1

# CCA token
genccacfg 20
addslot 20 libpkcs11_cca.so cca0 ccatok20.conf
addslot 21 libpkcs11_cca.so cca1

# SW token
addslot 30 libpkcs11_sw.so sw0
addslot 31 libpkcs11_sw.so sw1

# EP11 token
# 0:
# APQN_ANY
# EXPECTED_WKVP "wkvp"
genep11cfg 40 "EXPECTED_WKVP \"$EP11_WKVP\""
addslot 40 libpkcs11_ep11.so ep0 ep11tok40.conf

# 1:
# FORCE_SENSITIVE
# APQN_ANY
genep11cfg 41 "FORCE_SENSITIVE"
addslot 41 libpkcs11_ep11.so ep1 ep11tok41.conf

# 2:
# STRICT_MODE
# APQN_ANY
# later appended: VHSM_MODE

#genep11cfg 42 "STRICT_MODE"
#addslot 42 libpkcs11_ep11.so ep2 ep11tok42.conf

# 3:
# OPTIMIZE_SINGLE_PART_OPERATIONS
# APQN_ANY
genep11cfg 43 "OPTIMIZE_SINGLE_PART_OPERATIONS"
addslot 43 libpkcs11_ep11.so ep3 ep11tok43.conf

# 4:
# DIGEST_LIBICA OFF
# APQN_ANY
genep11cfg 44 "DIGEST_LIBICA OFF"
addslot 44 libpkcs11_ep11.so ep4 ep11tok44.conf

# 5: latest (CEX8 only)
# PKEY_MODE ENABLE4NONEXTR
if genlatestep11cfg 45 "PKEY_MODE ENABLE4NONEXTR"; then
    addslot 45 libpkcs11_ep11.so ep5 ep11tok45.conf
fi

# 6: latest (CEX8 only)
# PKEY_MODE ENABLE4ALL
if genlatestep11cfg 46 "PKEY_MODE ENABLE4ALL"; then
    addslot 46 libpkcs11_ep11.so ep6 ep11tok46.conf
    echo "46" > $COMBINED_EXTRACT_FILE
fi

# ICSF token backed by the mock server (failure is non-fatal)
setup_icsf_mock_token || true

