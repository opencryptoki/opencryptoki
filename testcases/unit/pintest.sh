#!/bin/bash
#
# COPYRIGHT (c) International Business Machines Corp. 2022
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this software
# constitutes recipient's acceptance of CPL-1.0 terms which can be found
# in the file LICENSE file or at https://opensource.org/licenses/cpl1.0.php

PINTEST=testcases/unit/pintest

# functions
print_test_result() {
	local msg=$1
	local result=$2
	local result_exp=$3

	if [ "${result}" = "${result_exp}" ]; then
		printf "${msg}: PASS  result: \"${result}\", expected: \"${result_exp}\"\n"
		RC=0
	else
		printf "${msg}: FAIL  result: ${result}, expected: ${result_exp}\n"
		RC=1
	fi
	return $RC
}

unset PKCS11_USER_PIN
unset PKCS11_SO_PIN

TEST_PIN=12345678
RESULT_PIN="pin: ${TEST_PIN}"
RESULT_ERR="pin: (null)"

# prompt
RESULT=$(printf "${TEST_PIN}\n" | ${PINTEST} -p | tail -n1 )
print_test_result "pin prompt" "${RESULT}" "${RESULT_PIN}" || exit 99

RESULT=$(printf "${TEST_PIN}\n${TEST_PIN}\n" | ${PINTEST} -n | tail -n1 )
print_test_result "pin prompt-new" "${RESULT}" "${RESULT_PIN}"  || exit 99

RESULT=$(printf "\n\n" | ${PINTEST} -n | tail -n1 )
print_test_result "pin prompt-new" "${RESULT}" "${RESULT_ERR}"  || exit 99

RESULT=$(${PINTEST} -p <&- | tail -n1 )
print_test_result "pin prompt-user" "${RESULT}" "${RESULT_ERR}" || exit 99

RESULT=$(${PINTEST} -n <&- | tail -n1 )
print_test_result "pin prompt-new" "${RESULT}" "${RESULT_ERR}"  || exit 99

exit 0
