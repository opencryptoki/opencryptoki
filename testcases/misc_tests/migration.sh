#!/bin/bash
#
# COPYRIGHT (c) International Business Machines Corp. 2020
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this software
# constitutes recipient's acceptance of CPL-1.0 terms which can be found
# in the file LICENSE file or at https://opensource.org/licenses/cpl1.0.php

# - Requires p11tool (gnutls) and pkcs11-tool (opensc).
# - The PKCSLIB environment must point to your system's libopencryptoki.so.
# - The PKCS11_SO_PIN environment variable must hold the SO pin.
# - The PKCS11_USER_PIN environment variable must hold the user pin.
# - The OCK_CONFDIR environment variable must point to your system's openCryptoki configuration directory.
# - The OCK_DATASTORE environment variable must point to the token's datastore directory.
# - The SLOT environment variable must hold the slot id of the token under test.
# - The PKCS11_TOKEN_URL environment variable must hold the the token url of the token under test.
#
# sodo -E ./migrate.sh

set -x

# tmp files
PKCSCONF_PRE=pkcsconf-pre.out
PKCSCONF_POST=pkcsconf-post.out
P11TOOL_PRE=p11tool-pre.out
P11TOOL_POST=p11tool-post.out
PKCS11_TOOL_PRE=pkcs11-tool-pre.out
PKCS11_TOOL_POST=pkcs11-tool-post.out
P11SAK_PRE=p11sak-pre.out
P11SAK_POST=p11sak-post.out

# set p11tool env vars
export GNUTLS_SO_PIN=$PKCS11_SO_PIN
export GNUTLS_PIN=$PKCS11_USER_PIN

# generate objects
p11tool --provider=$PKCSLIB --login --generate-rsa --bits 2048 --label p11tool-rsa "$PKCS11_TOKEN_URL"
pkcs11-tool --module=$PKCSLIB --slot $SLOT --login --pin $PKCS11_USER_PIN --keypairgen --key-type rsa:2048 --label pkcs11-tool-rsa
p11sak generate-key rsa 2048 --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-rsa

# list slots/tokens
pkcsconf -i &>> $PKCSCONF_PRE
pkcsconf -s &>> $PKCSCONF_PRE
pkcsconf -t &>> $PKCSCONF_PRE
p11tool --provider=$PKCSLIB --list-tokens &>> $P11TOOL_PRE
pkcs11-tool --module=$PKCSLIB --list-slots &>> $PKCS11_TOOL_PRE

# list objects
p11tool --provider=$PKCSLIB  --list-all "$PKCS11_TOKEN_URL" &>> $P11TOOL_PRE
p11tool --provider=$PKCSLIB  --list-all --login "$PKCS11_TOKEN_URL" &>> $P11TOOL_PRE
pkcs11-tool --module=$PKCSLIB --slot $SLOT -list-objects &>> $PKCS11_TOOL_PRE
pkcs11-tool --module=$PKCSLIB --slot $SLOT --login --pin $PKCS11_USER_PIN --list-objects &>> $PKCS11_TOOL_PRE
p11sak list-key rsa --slot $SLOT --pin $PKCS11_USER_PIN &>> $P11SAK_PRE

# migrate
killall pkcsslotd
echo -e "y\n" | pkcstok_migrate --verbose debug --slot $SLOT --sopin $PKCS11_SO_PIN --userpin $PKCS11_USER_PIN --confdir $OCK_CONFDIR --datastore $OCK_DATASTORE
pkcsslotd

# list slots/tokens
pkcsconf -i &>> $PKCSCONF_POST
pkcsconf -s &>> $PKCSCONF_POST
pkcsconf -t &>> $PKCSCONF_POST
p11tool --provider=$PKCSLIB --list-tokens &>> p11tool-post.out
pkcs11-tool --module=$PKCSLIB --list-slots &>> pkcs11-tool-post.out

# list objects
p11tool --provider=$PKCSLIB --list-all "$PKCS11_TOKEN_URL" &>> $P11TOOL_POST
p11tool --provider=$PKCSLIB --list-all --login "$PKCS11_TOKEN_URL" &>> $P11TOOL_POST
pkcs11-tool --module=$PKCSLIB --slot $SLOT -list-objects &>> $PKCS11_TOOL_POST
pkcs11-tool --module=$PKCSLIB --slot $SLOT --login --pin $PKCS11_USER_PIN --list-objects &>> $PKCS11_TOOL_POST
p11sak list-key rsa --slot $SLOT --pin $PKCS11_USER_PIN &>> $P11SAK_POST

# compare
cmp $PKCSCONF_PRE $PKCSCONF_POST
cmp $P11TOOL_PRE $P11TOOL_POST
cmp $PKCS11_TOOL_PRE $PKCS11_TOOL_POST
cmp $P11SAK_PRE $P11SAK_POST
