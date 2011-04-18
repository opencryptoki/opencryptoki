#!/bin/sh
#
# login_test.sh
#
# Kent Yoder <kyoder@users.sf.net>
#
# usage: login_test.sh -slot [n]
#
# By default, slot 0 is used.  This script will run through several
# scenarios WRT login's to the PKCS#11 API.  It expects a completely
# uninitialized token, such as right after installation. It is
# expected that the token will be reinitialized after running this test.
#
set -x


DEFAULT_SO_PIN=${P11_SO_PWD:=87654321}
DEFAULT_USER_PIN=${P11_USER_PWD:=12345678}

NEW_USER_PIN1=${NEW_P11_USER_PWD:=userPW1}
NEW_USER_PIN2=${NEW_P11_USER_PWD2:=userPW2}
NEW_SO_PIN1=${NEW_P11_SO_PWD:=so_PW1}
NEW_SO_PIN2=${NEW_P11_SO_PWD2:=so_PW2}
BAD_PIN=bad

CKR_PIN_EXPIRED=163
CKR_PIN_INVALID=161
CKR_PIN_INCORRECT=160
CKR_USER_PIN_NOT_INITIALIZED=2
CKR_OK=0

#init the token
./init_tok $* -pass $DEFAULT_SO_PIN
if test $? -ne $CKR_OK; then
	echo "TEST FAIL"
	exit
fi

# Try to login as SO with a bad pass
./login $* -so -pass bad
if test $? -ne $CKR_PIN_INCORRECT; then
	echo "TEST FAIL"
	exit
fi

# Try to login as USER before init
./login $* -user -pass $DEFAULT_USER_PIN
if test $? -ne $CKR_USER_PIN_NOT_INITIALIZED; then
	echo "TEST FAIL"
	exit
fi

# Try a correct SO login, should SUCCEED
./login $* -so -pass $DEFAULT_SO_PIN
if test $? -ne $CKR_OK; then
	echo "TEST FAIL"
	exit
fi

# Try to do something after logging in before PIN is set
./digest_init $* -so -pass $DEFAULT_SO_PIN
if test $? -ne $CKR_PIN_EXPIRED; then
	echo "TEST FAIL"
	exit
fi

# Try to set pin to the default value
./set_pin $* -so -old $DEFAULT_SO_PIN -new $DEFAULT_SO_PIN
if test $? -ne $CKR_PIN_INVALID; then
	echo "TEST FAIL"
	exit
fi

# Do a legitimate pin set for the SO
./set_pin $* -so -old $DEFAULT_SO_PIN -new $NEW_SO_PIN1
if test $? -ne $CKR_OK; then
	echo "TEST FAIL"
	exit
fi

# Init the USER PIN
./init_pin $* -sopass $NEW_SO_PIN1 -userpass $DEFAULT_USER_PIN
if test $? -ne $CKR_OK; then
	echo "TEST_FAIL"
	exit
fi

# Try to set pin to the default value
./set_pin $* -user -old $DEFAULT_USER_PIN -new $DEFAULT_USER_PIN
if test $? -ne $CKR_PIN_INVALID; then
	echo "TEST FAIL"
	exit
fi

# Do a legitimate pin set for the USER
./set_pin $* -user -old $DEFAULT_USER_PIN -new $NEW_USER_PIN1
if test $? -ne $CKR_OK; then
	echo "TEST FAIL"
	exit
fi

# login with the good pins
./login $* -so -pass $NEW_SO_PIN1
if test $? -ne $CKR_OK; then
	echo "TEST FAIL"
	exit
fi

./login $* -user -pass $NEW_USER_PIN1
if test $? -ne $CKR_OK; then
	echo "TEST FAIL"
	exit
fi

# Try login with bad pins
./login $* -so -pass $BAD_PIN
if test $? -ne $CKR_PIN_INCORRECT; then
	echo "TEST FAIL"
	exit
fi

./login $* -user -pass $BAD_PIN
if test $? -ne $CKR_PIN_INCORRECT; then
	echo "TEST FAIL"
	exit
fi

# try to change both pins back to defaults (should fail)
./set_pin $* -so -old $NEW_SO_PIN1 -new $DEFAULT_SO_PIN
if test $? -ne $CKR_PIN_INVALID; then
	echo "TEST FAIL"
	exit
fi

./set_pin $* -user -old $NEW_USER_PIN1 -new $DEFAULT_USER_PIN
if test $? -ne $CKR_PIN_INVALID; then
	echo "TEST FAIL"
	exit
fi

# change both pins legitimately
./set_pin $* -so -old $NEW_SO_PIN1 -new $NEW_SO_PIN2
if test $? -ne $CKR_OK; then
	echo "TEST FAIL"
	exit
fi

./set_pin $* -user -old $NEW_USER_PIN1 -new $NEW_USER_PIN2
if test $? -ne $CKR_OK; then
	echo "TEST FAIL"
	exit
fi

# login with new passes
./login $* -so -pass $NEW_SO_PIN2
if test $? -ne $CKR_OK; then
	echo "TEST FAIL"
	exit
fi

./login $* -user -pass $NEW_USER_PIN2
if test $? -ne $CKR_OK; then
	echo "TEST FAIL"
	exit
fi

echo "TEST SUCCEEDED"

echo "Currently the SO Pin is set to \"$NEW_SO_PIN2\""
echo "Currently the USER Pin is set to \"$NEW_USER_PIN2\""

exit 0
