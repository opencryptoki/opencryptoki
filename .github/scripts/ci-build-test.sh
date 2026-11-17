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
#   RUN_TESTCASES set to 0 to skip the (slow) make ci-installcheck tests; only
#                 'make check' is run in that case

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
      autoconf-archive libcap-dev pv curl jq sudo procps psmisc python3"
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

# With RUN_TESTCASES=1, 'make ci-installcheck' runs 'make check' itself
# (installcheck-local depends on it), so don't run it twice.
if [ "$RUN_TESTCASES" != "1" ]; then
    echo "::group::make check"
    make check V=0
    echo "::endgroup::"
fi

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

# Run all tests even if one step fails, and report the combined result.
rc=0

echo "::group::make ci-installcheck"
$SUDO make ci-installcheck V=0 VERBOSE=1 || rc=1
echo "::endgroup::"

echo "::group::make ci-check-results"
$SUDO make ci-check-results || rc=1
echo "::endgroup::"

# Stop the ICSF mock server and clean up; this also removes the log-*.txt
# files, so it must run after ci-check-results. Failures are ignored.
echo "::group::make ci-cleanup"
$SUDO make ci-cleanup || true
echo "::endgroup::"

if [ "$rc" -ne 0 ]; then
    echo "One or more test steps failed"
fi
exit "$rc"
