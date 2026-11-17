#!/bin/bash
#
# Build and test openCryptoki in CI.
#
# This script is used by .github/workflows/ci.yml for all architectures, both
# for native runners and for QEMU based emulation (run-on-arch-action).
#
# Required environment variables:
#   CONFIG_OPTS   options passed to ./configure
# Optional environment variables:
#   CC            compiler to use (gcc or clang)
#   CFLAGS        compiler flags
#   RUN_TESTCASES set to 0 to skip the (slow) ock_tests.sh / p11sak tests

set -eo pipefail

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
fi

export DEBIAN_FRONTEND=noninteractive
ARCH="$(uname -m)"
. /etc/os-release

CC="${CC:-gcc}"
RUN_TESTCASES="${RUN_TESTCASES:-1}"

echo "::group::Install dependencies"
PKGS="build-essential autoconf automake libtool pkg-config flex bison \
      libssl-dev openssl expect libldap2-dev wget libudev-dev \
      autoconf-archive libcap-dev pv curl jq sudo procps"
if [ "$CC" = "clang" ]; then
    PKGS="$PKGS clang"
fi
if [ "$ARCH" != "x86_64" ]; then
    PKGS="$PKGS trousers libtspi-dev"
fi
if [ "$ARCH" = "s390x" ]; then
    if [ "$VERSION_ID" = "20.04" ]; then
        PKGS="$PKGS libica3 libica-dev"
    else
        PKGS="$PKGS libica4 libica-dev"
    fi
fi
$SUDO apt-get -qq update
$SUDO apt-get install -y --no-install-recommends $PKGS
echo "::endgroup::"

export CC

echo "::group::Bootstrap"
./bootstrap.sh
echo "::endgroup::"

echo "::group::Configure and build"
openssl version
./configure --silent $CONFIG_OPTS
make -j "$(nproc)" V=0
echo "::endgroup::"

echo "::group::make check"
make check V=0
echo "::endgroup::"

echo "::group::Install and start pkcsslotd"
$SUDO make install
$SUDO ldconfig
$SUDO pkcsslotd
if ! $SUDO pkcsconf -i; then
    # pkcsslotd logs to syslog only, which does not exist in plain containers
    echo "pkcsconf failed, diagnostics follow"
    ps -ef | grep '[p]kcsslotd' || echo "pkcsslotd is NOT running"
    ipcs -m || true
    ls -la /run/opencryptoki /usr/local/var/lock/opencryptoki || true
    ls -la /usr/local/var/log/opencryptoki || true
    exit 1
fi
$SUDO pkcsconf -s
$SUDO pkcsconf -t
echo "::endgroup::"

if [ "$RUN_TESTCASES" != "1" ]; then
    echo "Skipping testcases (RUN_TESTCASES=$RUN_TESTCASES)"
    exit 0
fi

cd testcases
LOGDIR="$(mktemp -d)"
rc=0

# The full test output is very large. GitHub truncates steps with too much
# output and then does not show any groups after the truncation point. So the
# full output is only written to log files; the console gets just the
# interesting lines (with some context), live while the tests run.
# The exit status of the test script is taken from PIPESTATUS, since grep
# returns non-zero when nothing matches.
# Test results are printed as "* TESTCASE <name> FAIL|ERROR ...", so match the
# result words only when surrounded by blanks. This avoids false matches such
# as "CKR_GENERAL_ERROR" or "PASS/FAIL" in messages.
TEST_FILTER=" FAIL \| ERROR \|Failed=[1-9]\|Errors=[1-9]\|Total=\|Now executing"

set +e
echo "::group::ock_tests.sh"
echo "Full output is written to $LOGDIR/ock_tests.log"
$SUDO env PKCS11_SO_PIN=76543210 PKCS11_USER_PIN=01234567 \
    PKCSLIB=/usr/local/lib/pkcs11/libopencryptoki.so \
    ./ock_tests.sh -s 3 2>&1 | tee "$LOGDIR/ock_tests.log" | \
    grep --line-buffered "$TEST_FILTER"
ock_rc=${PIPESTATUS[0]}
echo "ock_tests.sh finished, exit status=$ock_rc"
echo "::endgroup::"

echo "::group::p11sak_test.sh"
echo "Full output is written to $LOGDIR/p11sak_test.log"
$SUDO env SLOT=3 PKCS11_USER_PIN=01234567 PKCS11_SO_PIN=76543210 \
    PKCSLIB=/usr/local/lib/pkcs11/libopencryptoki.so \
    ./misc_tests/p11sak_test.sh 2>&1 | tee "$LOGDIR/p11sak_test.log" | \
    grep --line-buffered "$TEST_FILTER"
p11sak_rc=${PIPESTATUS[0]}
echo "p11sak_test.sh finished, exit status=$p11sak_rc"
echo "::endgroup::"
set -e

# On failure, show the complete log of the failed script, since the failure
# can be anywhere in it.
if [ "$ock_rc" -ne 0 ]; then
    rc=1
    echo "::group::ock_tests.sh failed - full log"
    cat "$LOGDIR/ock_tests.log"
    echo "::endgroup::"
fi
if [ "$p11sak_rc" -ne 0 ]; then
    rc=1
    echo "::group::p11sak_test.sh failed - full log"
    cat "$LOGDIR/p11sak_test.log"
    echo "::endgroup::"
fi

if [ "$rc" -ne 0 ]; then
    echo "One or more test scripts failed"
fi
exit "$rc"
