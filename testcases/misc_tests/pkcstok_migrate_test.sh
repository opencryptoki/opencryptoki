#!/bin/bash
#
# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this software
# constitutes recipient's acceptance of CPL-1.0 terms which can be found
# in the file LICENSE file or at https://opensource.org/licenses/cpl1.0.php

# Test for pkcstok_migrate: verifies that token objects created in the pre-FIPS
# (version 0.0) repository format are preserved correctly after migration to the
# 3.12 FIPS-compliant format.
#
# When the token is already in 3.12 format (USENEWFORMAT=true CI days),
# pkcstok_migrate exits cleanly with "already in new format" and the test
# simply skips the migration verification, so it is safe to run unconditionally.
#
# Required environment variables:
#   PKCS11_USER_PIN  - user PIN of the token under test
#   PKCS11_SO_PIN    - SO PIN of the token under test
#   PKCSLIB          - path to libopencryptoki.so
#   OCK_CONFDIR      - directory containing opencryptoki.conf
#   OCK_DATASTORE    - token repository directory to migrate
#   SLOT             - slot number of the token under test
#
# Optional environment variables:
#   SBINDIR          - directory containing p11sak, pkcsconf, pkcstok_migrate,
#                      and pkcsslotd (required when tools are not in $PATH)
#
# Must be run as root (pkcstok_migrate requires root).
# sudo -E ./pkcstok_migrate_test.sh

echo "** Now executing 'pkcstok_migrate_test.sh'"

status=0

# ---------------------------------------------------------------------------
# Tool resolution
# ---------------------------------------------------------------------------

if [[ -n "$(command -v pkcsconf)" ]]; then
    PKCSCONF=pkcsconf
    P11SAK=p11sak
    PKCSTOK_MIGRATE=pkcstok_migrate
    PKCSSLOTD=pkcsslotd
elif [[ -z "$SBINDIR" ]]; then
    echo "pkcsconf and/or p11sak were not found in \$PATH."
    echo "Define \$SBINDIR to the appropriate path and try again."
    exit 1
else
    PKCSCONF=${SBINDIR}/pkcsconf
    P11SAK=${SBINDIR}/p11sak
    PKCSTOK_MIGRATE=${SBINDIR}/pkcstok_migrate
    PKCSSLOTD=${SBINDIR}/pkcsslotd
fi

# ---------------------------------------------------------------------------
# Environment validation
# ---------------------------------------------------------------------------

if [[ -z "${PKCS11_USER_PIN}" ]]; then
    echo "Please set the PKCS11_USER_PIN environment variable"
    exit 1
fi

if [[ -z "${PKCS11_SO_PIN}" ]]; then
    echo "Please set the PKCS11_SO_PIN environment variable"
    exit 1
fi

if [[ -z "${PKCSLIB}" ]]; then
    echo "Please set the PKCSLIB environment variable"
    exit 1
fi

if [[ -z "${OCK_CONFDIR}" ]]; then
    echo "Please set the OCK_CONFDIR environment variable"
    exit 1
fi

if [[ -z "${OCK_DATASTORE}" ]]; then
    echo "Please set the OCK_DATASTORE environment variable"
    exit 1
fi

SLOT=${SLOT:-30}

echo "** Using slot $SLOT, datastore $OCK_DATASTORE, confdir $OCK_CONFDIR"

# ---------------------------------------------------------------------------
# Prerequisite: must be root
# ---------------------------------------------------------------------------

if [[ $(id -u) -ne 0 ]]; then
    echo "* TESTCASE pkcstok_migrate setup SKIP pkcstok_migrate requires root - skipping"
    exit 0
fi

# ---------------------------------------------------------------------------
# Prerequisite: check that the datastore is in pre-FIPS format.
# The tool itself handles the already-migrated case gracefully, but we use
# NVTOK.DAT size to decide whether the comparison step is meaningful.
# TOKEN_DATA_OLD (pre-FIPS) is 232 bytes; TOKEN_DATA (3.12 FIPS) is 592 bytes.
# Only proceed with the migration test when the size is exactly 232; anything
# else is treated as already migrated (or an unrecognised format) and skipped.
# ---------------------------------------------------------------------------

NVTOK="${OCK_DATASTORE}/NVTOK.DAT"
if [[ ! -f "${NVTOK}" ]]; then
    echo "* TESTCASE pkcstok_migrate setup SKIP ${NVTOK} not found - skipping"
    exit 0
fi

NVTOK_SIZE=$(stat -c '%s' "${NVTOK}")
if [[ "${NVTOK_SIZE}" -ne 232 ]]; then
    echo "* TESTCASE pkcstok_migrate setup SKIP token is not in pre-FIPS format (NVTOK.DAT size=${NVTOK_SIZE}) - skipping"
    exit 0
fi

echo "** Token is in pre-FIPS format (NVTOK.DAT size=${NVTOK_SIZE}) - proceeding with migration test"

# ---------------------------------------------------------------------------
# Cleanup any leftover backup artifacts from a previous (failed) run so that
# pkcstok_migrate does not abort on backups_already_existent().
# ---------------------------------------------------------------------------

rm -rf "${OCK_DATASTORE}_BAK"
rm -rf "${OCK_DATASTORE}_PKCSTOK_MIGRATE_TMP"
rm -f  "${OCK_CONFDIR}/opencryptoki.conf_BAK"

# ---------------------------------------------------------------------------
# Temporary output files
# ---------------------------------------------------------------------------

MIGRATE_AES_PRE=pkcstok-migrate-aes-pre.out
MIGRATE_RSA_PRE=pkcstok-migrate-rsa-pre.out
MIGRATE_AES_POST=pkcstok-migrate-aes-post.out
MIGRATE_RSA_POST=pkcstok-migrate-rsa-post.out
MIGRATE_TOOL_LOG=pkcstok-migrate-tool.out

# Labels used for the test objects.
# RSA key pairs get :pub/:prv suffixes auto-appended by p11sak; use a wildcard
# when listing so both halves are captured.
AES_LABEL="pkcstok-migrate-test-aes"
RSA_LABEL="pkcstok-migrate-test-rsa"
RSA_LABEL_GLOB="pkcstok-migrate-test-rsa:*"

# ---------------------------------------------------------------------------
# Phase 1: generate token objects in pre-FIPS format
# ---------------------------------------------------------------------------

echo "** Phase 1: generating token objects in pre-FIPS format"

${P11SAK} generate-key aes 256 \
    --slot "${SLOT}" --pin "${PKCS11_USER_PIN}" \
    --label "${AES_LABEL}" --attr SE
rc=$?
if [[ $rc -eq 0 ]]; then
    echo "* TESTCASE pkcstok_migrate generate-aes PASS Generated AES-256 key"
else
    echo "* TESTCASE pkcstok_migrate generate-aes FAIL Failed to generate AES-256 key (rc=$rc)"
    status=1
fi

${P11SAK} generate-key rsa 2048 \
    --slot "${SLOT}" --pin "${PKCS11_USER_PIN}" \
    --label "${RSA_LABEL}" --attr SE
rc=$?
if [[ $rc -eq 0 ]]; then
    echo "* TESTCASE pkcstok_migrate generate-rsa PASS Generated RSA-2048 key pair"
else
    echo "* TESTCASE pkcstok_migrate generate-rsa FAIL Failed to generate RSA-2048 key pair (rc=$rc)"
    status=1
fi

# ---------------------------------------------------------------------------
# Phase 2: capture pre-migration object listing
# ---------------------------------------------------------------------------

echo "** Phase 2: capturing pre-migration object listing"

${P11SAK} list-key aes \
    --slot "${SLOT}" --pin "${PKCS11_USER_PIN}" \
    --label "${AES_LABEL}" &> "${MIGRATE_AES_PRE}"
${P11SAK} list-key rsa \
    --slot "${SLOT}" --pin "${PKCS11_USER_PIN}" \
    --label "${RSA_LABEL_GLOB}" &> "${MIGRATE_RSA_PRE}"

# ---------------------------------------------------------------------------
# Phase 3: stop pkcsslotd, run migration, restart pkcsslotd
# ---------------------------------------------------------------------------

echo "** Phase 3: running pkcstok_migrate"

killall pkcsslotd 2>/dev/null || true
# Give the daemon a moment to fully shut down
sleep 1

echo "y" | "${PKCSTOK_MIGRATE}" \
    --slotid "${SLOT}" \
    --datastore "${OCK_DATASTORE}" \
    --confdir "${OCK_CONFDIR}" \
    --sopin "${PKCS11_SO_PIN}" \
    --userpin "${PKCS11_USER_PIN}" \
    --verbose warn \
    &> "${MIGRATE_TOOL_LOG}"
MIGRATE_RC=$?

cat "${MIGRATE_TOOL_LOG}"

if [[ $MIGRATE_RC -eq 0 ]]; then
    echo "* TESTCASE pkcstok_migrate migrate PASS pkcstok_migrate succeeded"
else
    echo "* TESTCASE pkcstok_migrate migrate FAIL pkcstok_migrate failed (rc=$MIGRATE_RC)"
    status=1
fi

# Restart pkcsslotd regardless of migration outcome so subsequent CI steps work
"${PKCSSLOTD}"
sleep 1

# Bail out early if migration itself failed - comparison results would be
# meaningless and the remaining cleanup steps may not apply.
if [[ $MIGRATE_RC -ne 0 ]]; then
    exit 1
fi

# ---------------------------------------------------------------------------
# Phase 4: capture post-migration object listing
# ---------------------------------------------------------------------------

echo "** Phase 4: capturing post-migration object listing"

${P11SAK} list-key aes \
    --slot "${SLOT}" --pin "${PKCS11_USER_PIN}" \
    --label "${AES_LABEL}" &> "${MIGRATE_AES_POST}"
${P11SAK} list-key rsa \
    --slot "${SLOT}" --pin "${PKCS11_USER_PIN}" \
    --label "${RSA_LABEL_GLOB}" &> "${MIGRATE_RSA_POST}"

# ---------------------------------------------------------------------------
# Phase 5: verify objects are intact post-migration
# ---------------------------------------------------------------------------

echo "** Phase 5: verifying objects are intact after migration"

grep -q "${AES_LABEL}" "${MIGRATE_AES_POST}"
rc=$?
if [[ $rc -eq 0 ]]; then
    echo "* TESTCASE pkcstok_migrate verify-aes PASS AES key present after migration"
else
    echo "* TESTCASE pkcstok_migrate verify-aes FAIL AES key missing after migration"
    status=1
fi

# Both :pub and :prv objects must survive migration
grep -q "${RSA_LABEL}:pub" "${MIGRATE_RSA_POST}"
rc=$?
if [[ $rc -eq 0 ]]; then
    echo "* TESTCASE pkcstok_migrate verify-rsa-pub PASS RSA public key present after migration"
else
    echo "* TESTCASE pkcstok_migrate verify-rsa-pub FAIL RSA public key missing after migration"
    status=1
fi

grep -q "${RSA_LABEL}:prv" "${MIGRATE_RSA_POST}"
rc=$?
if [[ $rc -eq 0 ]]; then
    echo "* TESTCASE pkcstok_migrate verify-rsa-prv PASS RSA private key present after migration"
else
    echo "* TESTCASE pkcstok_migrate verify-rsa-prv FAIL RSA private key missing after migration"
    status=1
fi

diff "${MIGRATE_AES_PRE}" "${MIGRATE_AES_POST}"
rc=$?
if [[ $rc -eq 0 ]]; then
    echo "* TESTCASE pkcstok_migrate verify-aes-listing PASS AES key listing identical before and after migration"
else
    echo "* TESTCASE pkcstok_migrate verify-aes-listing FAIL AES key listing differs before and after migration"
    status=1
fi

diff "${MIGRATE_RSA_PRE}" "${MIGRATE_RSA_POST}"
rc=$?
if [[ $rc -eq 0 ]]; then
    echo "* TESTCASE pkcstok_migrate verify-rsa-listing PASS RSA key listing identical before and after migration"
else
    echo "* TESTCASE pkcstok_migrate verify-rsa-listing FAIL RSA key listing differs before and after migration"
    status=1
fi

# ---------------------------------------------------------------------------
# Phase 6: verify opencryptoki.conf was updated with tokversion = 3.12
# ---------------------------------------------------------------------------

echo "** Phase 6: verifying opencryptoki.conf update"

grep -q "tokversion" "${OCK_CONFDIR}/opencryptoki.conf"
rc=$?
if [[ $rc -eq 0 ]]; then
    echo "* TESTCASE pkcstok_migrate verify-tokversion PASS tokversion entry added to opencryptoki.conf"
else
    echo "* TESTCASE pkcstok_migrate verify-tokversion FAIL tokversion entry missing from opencryptoki.conf"
    status=1
fi

# ---------------------------------------------------------------------------
# Phase 7: clean up test objects and migration backup artifacts
# ---------------------------------------------------------------------------

echo "** Phase 7: cleaning up"

${P11SAK} remove-key aes \
    --slot "${SLOT}" --pin "${PKCS11_USER_PIN}" \
    --label "${AES_LABEL}" --force
${P11SAK} remove-key rsa \
    --slot "${SLOT}" --pin "${PKCS11_USER_PIN}" \
    --label "${RSA_LABEL_GLOB}" --force

rm -rf "${OCK_DATASTORE}_BAK"
rm -f  "${OCK_CONFDIR}/opencryptoki.conf_BAK"

exit $status
