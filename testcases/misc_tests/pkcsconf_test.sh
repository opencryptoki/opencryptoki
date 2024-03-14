#!/bin/bash
#
# COPYRIGHT (c) International Business Machines Corp. 2022
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this software
# constitutes recipient's acceptance of CPL-1.0 terms which can be found
# in the file LICENSE file or at https://opensource.org/licenses/cpl1.0.php

# functions
print_test_result() {
	local rc=$1
	local name=$2
	local subn=$3
	local mesg=$4

	if [ ${rc} = 0 ]; then
		echo "* TESTCASE ${name} ${subn} PASS ${mesg}"
	else
		echo "* TESTCASE ${name} ${subn} FAIL ${mesg}"
	fi
}

echo "** Now executing 'pkcsconf_test.sh'"

# create temporary directory
TMP=$(mktemp -d)

# define output files
PKCSCONF_INFO=${TMP}/pkcsconf-info.out
PKCSCONF_SLOT=${TMP}/pkcsconf-slot.out
PKCSCONF_TOKEN=${TMP}/pkcsconf-token.out

# check if pkcsconf is available in the current $PATH - if it isn't, ask for
# SBINDIR to be defined before this script executes.
if [[ -n "$(command -v pkcsconf)" ]]; then
	PKCSCONF=pkcsconf
elif [[ -z "$SBINDIR" ]]; then
	echo "pkcsconf was not found in \$PATH."
	echo "Define \$SBINDIR to the appropriate path and try again."
	exit 1
else
	PKCSCONF=${SBINDIR}/pkcsconf
fi

# list info/slots/tokens
${PKCSCONF} -i &> $PKCSCONF_INFO
${PKCSCONF} -s &> $PKCSCONF_SLOT
${PKCSCONF} -t &> $PKCSCONF_TOKEN

# extract information elements
INFO_LIBVERS=$(cat ${PKCSCONF_INFO} | grep -Po 'Library Version:\s+\K[0-9]+.[0-9]+')
INFO_LIBMANU=$(cat ${PKCSCONF_INFO} | grep -Po 'Manufacturer:\s+\K\S*')
INFO_LIBDESC=$(cat ${PKCSCONF_INFO} | grep -Po 'Library Description:\s+\K\S*')

# extract information URI elements
URI_INFO_LIBVERS=$(cat ${PKCSCONF_INFO} | grep -Po 'URI:\s*pkcs11:.*library-version=\K[^;]*')
URI_INFO_LIBMANU=$(cat ${PKCSCONF_INFO} | grep -Po 'URI:\s*pkcs11:.*library-manufacturer=\K[^;]*')
URI_INFO_LIBDESC=$(cat ${PKCSCONF_INFO} | grep -Po 'URI:\s*pkcs11:.*library-description=\K[^;]*')

# extract slot elements (only first slot)
SLOT_ID=$(  cat ${PKCSCONF_SLOT} | grep -Po '^Slot #\K[0-9]+'       | head -n1)
SLOT_MANU=$(cat ${PKCSCONF_SLOT} | grep -Po 'Manufacturer:\s+\K\S*' | head -n1)
SLOT_DESC=$(cat ${PKCSCONF_SLOT} | grep -Po 'Description:\s+\K\S*'  | head -n1)

# extract slot URI elements (only first slot)
URI_SLOT_ID=$(  cat ${PKCSCONF_SLOT} | grep -Po 'URI:\s*pkcs11:.*slot-id=\K[^;]*'           | head -n1)
URI_SLOT_MANU=$(cat ${PKCSCONF_SLOT} | grep -Po 'URI:\s*pkcs11:.*slot-manufacturer=\K[^;]*' | head -n1)
URI_SLOT_DESC=$(cat ${PKCSCONF_SLOT} | grep -Po 'URI:\s*pkcs11:.*slot-description=\K[^;]*'  | head -n1)

# extract token elements (only first token)
TOKEN_LABL=$(cat ${PKCSCONF_TOKEN} | grep -Po 'Label:\s+\K\S*'        | head -n1)
TOKEN_MANU=$(cat ${PKCSCONF_TOKEN} | grep -Po 'Manufacturer:\s+\K\S*' | head -n1)
TOKEN_MODL=$(cat ${PKCSCONF_TOKEN} | grep -Po 'Model:\s+\K\S*'        | head -n1)

# extract token URI elements (only first token)
URI_TOKEN_LABL=$(cat ${PKCSCONF_TOKEN} | grep -Po 'URI:\s*pkcs11:.*token=\K[^;]*'        | head -n1)
URI_TOKEN_MANU=$(cat ${PKCSCONF_TOKEN} | grep -Po 'URI:\s*pkcs11:.*manufacturer=\K[^;]*' | head -n1)
URI_TOKEN_MODL=$(cat ${PKCSCONF_TOKEN} | grep -Po 'URI:\s*pkcs11:.*model=\K[^;]*'        | head -n1)

# information test cases
test -n "${INFO_LIBVERS}" -o \
     -n "${INFO_LIBMANU}" -o \
     -n "${INFO_LIBDESC}"
print_test_result $? "pkcsconf" "info" "check output for all required library fields"

test -n "${URI_INFO_LIBVERS}" -o \
     -n "${URI_INFO_LIBMANU}" -o \
     -n "${URI_INFO_LIBDESC}"
print_test_result $? "pkcsconf" "info" "check URI for all required library fields"

test "${INFO_LIBVERS}" = "${URI_INFO_LIBVERS}"
print_test_result $? "pkcsconf" "info" "check library version in URI"

test "${INFO_LIBMANU}" = "${URI_INFO_LIBMANU}"
print_test_result $? "pkcsconf" "info" "check library manufacturer in URI"

test "${INFO_LIBDESC}" = "${URI_INFO_LIBDESC}"
print_test_result $? "pkcsconf" "info" "check library description in URI"

# slot test cases
test -n "${SLOT_ID}"   -o \
     -n "${SLOT_MANU}" -o \
     -n "${SLOT_DESC}"
print_test_result $? "pkcsconf" "slot" "check output for all required slot fields"

test -n "${URI_SLOT_ID}"   -o \
     -n "${URI_SLOT_MANU}" -o \
     -n "${URI_SLOT_DESC}"
print_test_result $? "pkcsconf" "slot" "check URI for all required slot fields"

test "${SLOT_ID}" = "${URI_SLOT_ID}"
print_test_result $? "pkcsconf" "slot" "check slot id in URI"

test "${SLOT_MANU}" = "${URI_SLOT_MANU}"
print_test_result $? "pkcsconf" "slot" "check slot manufacturer in URI"

test "${SLOT_DESC}" = "${URI_SLOT_DESC}"
print_test_result $? "pkcsconf" "slot" "check slot description in URI"

# token test cases
test -n "${TOKEN_LABL}" -o \
     -n "${TOKEN_MANU}" -o \
     -n "${TOKEN_MODL}"
print_test_result $? "pkcsconf" "token" "check output for all required token fields"

test -n "${URI_TOKEN_LABL}" -o \
     -n "${URI_TOKEN_MANU}" -o \
     -n "${URI_TOKEN_MODL}"
print_test_result $? "pkcsconf" "token" "check URI for all required token fields"

test "${TOKEN_LABL}" = "${URI_TOKEN_LABL}"
print_test_result $? "pkcsconf" "token" "check token label in URI"

test "${TOKEN_MANU}" = "${URI_TOKEN_MANU}"
print_test_result $? "pkcsconf" "token" "check token manufacturer in URI"

test "${TOKEN_MODL}" = "${URI_TOKEN_MODL}"
print_test_result $? "pkcsconf" "token" "check token model in URI"

# remove tmp
rm -rf ${TMP} &> /dev/null
