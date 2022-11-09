#!/bin/bash
#
# COPYRIGHT (c) International Business Machines Corp. 2020
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this software
# constitutes recipient's acceptance of CPL-1.0 terms which can be found
# in the file LICENSE file or at https://opensource.org/licenses/cpl1.0.php

# - The PKCS11_USER_PIN environment variable must hold the user pin.
# - The SLOT environment variable must hold the slot id of the token under test.
#
# sudo -E ./p11sak_test.sh

status=0


echo "** Now executing 'p11sak_test.sh'"


# tmp files

P11SAK_DES_PRE=p11sak-des-pre.out
P11SAK_DES_LONG=p11sak-des-long.out
P11SAK_DES_POST=p11sak-des-post.out
P11SAK_3DES_PRE=p11sak-3des-pre.out
P11SAK_3DES_LONG=p11sak-3des-long.out
P11SAK_3DES_POST=p11sak-3des-post.out
P11SAK_AES_PRE=p11sak-aes-pre.out
P11SAK_AES_LONG=p11sak-aes-long.out
P11SAK_AES_POST=p11sak-aes-post.out
P11SAK_AES_XTS_PRE=p11sak-aes-xts-pre.out
P11SAK_AES_XTS_LONG=p11sak-aes-xts-long.out
P11SAK_AES_XTS_POST=p11sak-aes-xts-post.out
P11SAK_RSA_PRE=p11sak-rsa-pre.out
P11SAK_RSA_LONG=p11sak-rsa-long.out
P11SAK_RSA_POST=p11sak-rsa-post.out
P11SAK_EC_PRE=p11sak-ec-pre.out
P11SAK_EC_LONG=p11sak-ec-long.out
P11SAK_EC_POST=p11sak-ec-post.out
P11SAK_IBM_DIL_PRE=p11sak-ibm-dil-pre.out
P11SAK_IBM_DIL_LONG=p11sak-ibm-dil-long.out
P11SAK_IBM_DIL_POST=p11sak-ibm-dil-post.out
P11SAK_IBM_KYBER_PRE=p11sak-ibm-kyber-pre.out
P11SAK_IBM_KYBER_LONG=p11sak-ibm-kyber-long.out
P11SAK_IBM_KYBER_POST=p11sak-ibm-kyber-post.out
P11SAK_ALL_PINOPT=p11sak-all-pinopt
P11SAK_ALL_PINENV=p11sak-all-pinenv
P11SAK_ALL_PINCON=p11sak-all-pincon


echo "** Setting SLOT=30 to the Softtoken unless otherwise set - 'p11sak_test.sh'"


# setting SLOT=30 to the Softtoken

SLOT=${SLOT:-30}

echo "** Using Slot $SLOT with PKCS11_USER_PIN $PKCS11_USER_PIN and PKCSLIB $PKCSLIB - 'p11sak_test.sh'"

echo "** Now generating keys - 'p11sak_test.sh'"


# generate objects

# des
if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_DES_KEY_GEN) ]]; then
	p11sak generate-key des --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-des
else
	echo "Skip generating des keys, slot does not support CKM_DES_KEY_GEN"
fi
# 3des
p11sak generate-key 3des --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-3des
# aes [128 | 192 | 256]
p11sak generate-key aes 128 --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-aes-128
p11sak generate-key aes 192 --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-aes-192
p11sak generate-key aes 256 --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-aes-256
# aes-xts [128 | 256]
if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_AES_XTS_KEY_GEN) ]]; then
	p11sak generate-key aes-xts 128 --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-aes-xts-128
	p11sak generate-key aes-xts 256 --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-aes-xts-256
else
	echo "Skip generating aes-xts keys, slot does not support CKM_AES_XTS_KEY_GEN"
fi
# rsa [1024 | 2048 | 4096]
p11sak generate-key rsa 1024 --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-rsa-1024
p11sak generate-key rsa 2048 --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-rsa-2048
p11sak generate-key rsa 4096 --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-rsa-4096
# ec [prime256v1 | secp384r1 | secp521r1]
p11sak generate-key ec prime256v1 --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-ec-prime256v1
p11sak generate-key ec secp384r1 --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-ec-secp384r1
p11sak generate-key ec secp521r1 --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-ec-secp521r1
# ibm-dilithium
if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_IBM_DILITHIUM) ]]; then
	p11sak generate-key ibm-dilithium r2_65 --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-ibm-dilithium
else
	echo "Skip generating ibm-dilithium keys, slot does not support CKM_IBM_DILITHIUM"
fi
# ibm-kyber
if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_IBM_KYBER) ]]; then
	p11sak generate-key ibm-kyber r2_1024 --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-ibm-kyber
else
	echo "Skip generating ibm-kyber keys, slot does not support CKM_IBM_KYBER"
fi


echo "** Now list keys and redirect output to pre-files - 'p11sak_test.sh'"


# list objects
p11sak list-key des --slot $SLOT --pin $PKCS11_USER_PIN &> $P11SAK_DES_PRE
p11sak list-key 3des --slot $SLOT --pin $PKCS11_USER_PIN &> $P11SAK_3DES_PRE
p11sak list-key aes --slot $SLOT --pin $PKCS11_USER_PIN &> $P11SAK_AES_PRE
p11sak list-key aes-xts --slot $SLOT --pin $PKCS11_USER_PIN &> $P11SAK_AES_XTS_PRE
p11sak list-key rsa --slot $SLOT --pin $PKCS11_USER_PIN &> $P11SAK_RSA_PRE
p11sak list-key ec --slot $SLOT --pin $PKCS11_USER_PIN &> $P11SAK_EC_PRE
p11sak list-key ibm-dilithium --slot $SLOT --pin $PKCS11_USER_PIN &> $P11SAK_IBM_DIL_PRE

p11sak list-key des --slot $SLOT --pin $PKCS11_USER_PIN --long &> $P11SAK_DES_LONG
p11sak list-key 3des --slot $SLOT --pin $PKCS11_USER_PIN --long &> $P11SAK_3DES_LONG
p11sak list-key aes --slot $SLOT --pin $PKCS11_USER_PIN --long &> $P11SAK_AES_LONG
p11sak list-key aes-xts --slot $SLOT --pin $PKCS11_USER_PIN --long &> $P11SAK_AES_XTS_LONG
p11sak list-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --long &> $P11SAK_RSA_LONG
p11sak list-key ec --slot $SLOT --pin $PKCS11_USER_PIN --long &> $P11SAK_EC_LONG
p11sak list-key ibm-dilithium --slot $SLOT --pin $PKCS11_USER_PIN --long &> $P11SAK_IBM_DIL_LONG
p11sak list-key ibm-kyber --slot $SLOT --pin $PKCS11_USER_PIN --long &> $P11SAK_IBM_KYBER_LONG

p11sak list-key all --slot $SLOT --pin $PKCS11_USER_PIN &> $P11SAK_ALL_PINOPT
RC_P11SAK_PINOPT=$?
p11sak list-key all --slot $SLOT &> $P11SAK_ALL_PINENV
RC_P11SAK_PINENV=$?
printf "${PKCS11_USER_PIN}\n" | p11sak list-key all --slot $SLOT --force-pin-prompt | tail -n +2 &> $P11SAK_ALL_PINCON
RC_P11SAK_PINCON=$?

echo "** Now remove keys - 'p11sak_test.sh'"


# remove objects
# des
p11sak remove-key des --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-des -f
# 3des
p11sak remove-key 3des --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-3des -f
# aes [128 | 192 | 256]
p11sak remove-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-aes-128 -f
p11sak remove-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-aes-192 -f
p11sak remove-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-aes-256 -f
# aes-xts [128 | 256]
p11sak remove-key aes-xts --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-aes-xts-128 -f
p11sak remove-key aes-xts --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-aes-xts-256 -f
# rsa [1024 | 2048 | 4096]
# remove public key
p11sak remove-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-rsa-1024:pub -f
p11sak remove-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-rsa-2048:pub -f
p11sak remove-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-rsa-4096:pub -f
# remove private key
p11sak remove-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-rsa-1024:prv -f
p11sak remove-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-rsa-2048:prv -f
p11sak remove-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-rsa-4096:prv -f
# ec [prime256v1 | secp384r1 | secp521r1]
#remove public key
p11sak remove-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-ec-prime256v1:pub -f
p11sak remove-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-ec-secp384r1:pub -f
p11sak remove-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-ec-secp521r1:pub -f
# remove private key
p11sak remove-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-ec-prime256v1:prv -f
p11sak remove-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-ec-secp384r1:prv -f
p11sak remove-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-ec-secp521r1:prv -f
# remove ibm dilithium keys
p11sak remove-key ibm-dilithium --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-ibm-dilithium:pub -f
p11sak remove-key ibm-dilithium --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-ibm-dilithium:prv -f
# remove ibm kyber keys
p11sak remove-key ibm-kyber --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-ibm-kyber:pub -f
p11sak remove-key ibm-kyber --slot $SLOT --pin $PKCS11_USER_PIN --label p11sak-ibm-kyber:prv -f


echo "** Now list keys and rediirect to post-files - 'p11sak_test.sh'"


# list objects
p11sak list-key des --slot $SLOT --pin $PKCS11_USER_PIN &> $P11SAK_DES_POST
p11sak list-key 3des --slot $SLOT --pin $PKCS11_USER_PIN &> $P11SAK_3DES_POST
p11sak list-key aes --slot $SLOT --pin $PKCS11_USER_PIN &> $P11SAK_AES_POST
p11sak list-key aes-xts --slot $SLOT --pin $PKCS11_USER_PIN &> $P11SAK_AES_XTS_POST
p11sak list-key rsa --slot $SLOT --pin $PKCS11_USER_PIN &> $P11SAK_RSA_POST
p11sak list-key ec --slot $SLOT --pin $PKCS11_USER_PIN &> $P11SAK_EC_POST
p11sak list-key ibm-dilithium --slot $SLOT --pin $PKCS11_USER_PIN &> $P11SAK_IBM_DIL_POST
p11sak list-key ibm-kyber --slot $SLOT --pin $PKCS11_USER_PIN &> $P11SAK_IBM_KYBER_POST


echo "** Now checking output files to determine PASS/FAIL of tests - 'p11sak_test.sh'"


if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_DES_KEY_GEN) ]]; then
	# check DES
	grep -q 'p11sak-des' $P11SAK_DES_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE generate-key des PASS Generated random DES key"
	else
		echo "* TESTCASE generate-key des FAIL Failed to generate DES key"
		status=1
	fi
	grep -v -q 'p11sak-des' $P11SAK_DES_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-key des PASS Deleted generated DES key"
	else
		echo "* TESTCASE remove-key des FAIL Failed to delete generated DES key"
		status=1
	fi
else
	echo "* TESTCASE generate-key des SKIP Generated random DES key"
	echo "* TESTCASE remove-key des SKIP Deleted generated DES key"
fi

if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_DES_KEY_GEN) ]]; then
	# CK_BBOOL
	if [[ $(grep -A 20 'p11sak-des' $P11SAK_DES_LONG | grep -c 'CKA_IBM_PROTKEY_EXTRACTABLE: CK_FALSE') == "1" ]]; then
		echo "* TESTCASE list-key des PASS Listed random des public keys CK_BBOOL attribute"
	else
		echo "* TESTCASE list-key des FAIL Failed to list des public keys CK_BBOOL attribute"
		status=1
	fi
	# CK_ULONG
	if [[ $(grep -A 20 'p11sak-des' $P11SAK_DES_LONG | grep -c 'CKA_MODULUS_BITS:') == "0" ]]; then
		echo "* TESTCASE list-key des PASS Listed random des public keys CK_ULONG attribute"
	else
		echo "* TESTCASE list-key des FAIL Failed to list des public keys CK_ULONG attribute"
		status=1
	fi
	# CK_BYTE
	if [[ $(grep -A 20 'p11sak-des' $P11SAK_DES_LONG | grep -c 'CKA_MODULUS:') == "0" ]]; then
		echo "* TESTCASE list-key des PASS Listed random des public keys CK_BYTE attribute"
	else
		echo "* TESTCASE list-key des FAIL Failed to list des public keys CK_BYTE attribute"
		status=1
	fi
	# URI
	if [[ $(grep -A 20 'p11sak-des' $P11SAK_DES_LONG | grep -c 'URI: pkcs11:.*type=secret-key') == "1" ]]; then
		echo "* TESTCASE list-key des PASS list des key pkcs#11 URI"
	else
		echo "* TESTCASE list-key des FAIL list des key pkcs#11 URI"
		status=1
	fi
else
	echo "* TESTCASE list-key des SKIP Listed random des public keys CK_BBOOL attribute"
	echo "* TESTCASE list-key des SKIP Listed random des public keys CK_ULONG attribute"
	echo "* TESTCASE list-key des SKIP Listed random des public keys CK_BYTE attribute"
	echo "* TESTCASE list-key des SKIP list des key pkcs#11 URI"
fi


# check 3DES
grep -q 'p11sak-3des' $P11SAK_3DES_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key 3des PASS Generated random 3DES key"
else
	echo "* TESTCASE generate-key 3des FAIL Failed to generate 3DES key"
	status=1
fi
grep -v -q 'p11sak-3des' $P11SAK_3DES_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key 3des PASS Deleted generated 3DES key"
else
	echo "* TESTCASE remove-key 3des FAIL Failed to delete generated 3DES key"
	status=1
fi


# CK_BBOOL
if [[ $(grep -A 23 'p11sak-3des' $P11SAK_3DES_LONG | grep -c 'CKA_IBM_PROTKEY_EXTRACTABLE: CK_FALSE') == "1" ]]; then
	echo "* TESTCASE list-key 3des PASS Listed random 3des public keys CK_BBOOL attribute"
else
	echo "* TESTCASE list-key 3des FAIL Failed to list 3des public keys CK_BBOOL attribute"
	status=1
fi
# CK_ULONG
if [[ $(grep -A 23 'p11sak-3des' $P11SAK_3DES_LONG | grep -c 'CKA_MODULUS_BITS:') == "0" ]]; then
	echo "* TESTCASE list-key 3des PASS Listed random 3des public keys CK_ULONG attribute"
else
	echo "* TESTCASE list-key 3des FAIL Failed to list 3des public keys CK_ULONG attribute"
	status=1
fi
# CK_BYTE
if [[ $(grep -A 23 'p11sak-3des' $P11SAK_3DES_LONG | grep -c 'CKA_MODULUS:') == "0" ]]; then
	echo "* TESTCASE list-key 3des PASS Listed random 3des public keys CK_BYTE attribute"
else
	echo "* TESTCASE list-key 3des FAIL Failed to list 3des public keys CK_BYTE attribute"
	status=1
fi
# URI
if [[ $(grep -A 23 'p11sak-3des' $P11SAK_3DES_LONG | grep -c 'URI: pkcs11:.*type=secret-key') == "1" ]]; then
	echo "* TESTCASE list-key 3des PASS list 3des key pkcs#11 URI"
else
	echo "* TESTCASE list-key 3des FAIL list 3des key pkcs#11 URI"
	status=1
fi


# check AES 128
grep -q 'p11sak-aes-128' $P11SAK_AES_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key aes-128 PASS Generated random AES 128 key"
else
	echo "* TESTCASE generate-key aes-128 FAIL Failed to generate AES 128 key"
	status=1
fi
grep -v -q 'p11sak-aes-128' $P11SAK_AES_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key aes-128 PASS Deleted generated AES 128 key"
else
	echo "* TESTCASE remove-key aes-128 FAIL Failed to delete generated AES 128 key"
	status=1
fi


# check AES 192
grep -q 'p11sak-aes-192' $P11SAK_AES_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key aes-192 PASS Generated random AES 192 key"
else
	echo "* TESTCASE generate-key aes-192 FAIL Failed to generate AES 192 key"
	status=1
fi
grep -v -q 'p11sak-aes-192' $P11SAK_AES_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key aes-192 PASS Deleted generated AES 192 key"
else
	echo "* TESTCASE remove-key aes-192 FAIL Failed to delete generated AES 192 key"
	status=1
fi


# check AES 256
grep -q 'p11sak-aes-256' $P11SAK_AES_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key aes-256 PASS Generated random AES 256 key"
else
	echo "* TESTCASE generate-key aes-256 FAIL Failed to generate AES 256 key"
	status=1
fi
grep -v -q 'p11sak-aes-256' $P11SAK_AES_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key aes-256 PASS Deleted generated AES 256 key"
else
	echo "* TESTCASE remove-key aes-256 FAIL Failed to delete generated AES 256 key"
	status=1
fi


# CK_BBOOL
if [[ $(grep -A 69 'p11sak-aes-128' $P11SAK_AES_LONG | grep -c 'CKA_IBM_PROTKEY_EXTRACTABLE: CK_FALSE') == "3" ]]; then
	echo "* TESTCASE list-key aes PASS Listed random aes public keys CK_BBOOL attribute"
else
	echo "* TESTCASE list-key aes FAIL Failed to list aes public keys CK_BBOOL attribute"
	status=1
fi
# CK_ULONG
if [[ $(grep -A 69 'p11sak-aes-128' $P11SAK_AES_LONG | grep -c 'CKA_MODULUS_BITS:') == "0" ]]; then
	echo "* TESTCASE list-key aes PASS Listed random aes public keys CK_ULONG attribute"
else
	echo "* TESTCASE list-key aes FAIL Failed to list aes public keys CK_ULONG attribute"
	status=1
fi
# CK_BYTE
if [[ $(grep -A 69 'p11sak-aes-128' $P11SAK_AES_LONG | grep -c 'CKA_MODULUS:') == "0" ]]; then
	echo "* TESTCASE list-key aes PASS Listed random aes public keys CK_BYTE attribute"
else
	echo "* TESTCASE list-key aes FAIL Failed to list aes public keys CK_BYTE attribute"
	status=1
fi
# URI
if [[ $(grep -A 69 'p11sak-aes-128' $P11SAK_AES_LONG | grep -c 'URI: pkcs11:.*type=secret-key') == "3" ]]; then
	echo "* TESTCASE list-key aes PASS list aes key pkcs#11 URI"
else
	echo "* TESTCASE list-key aes FAIL list aes key pkcs#11 URI"
	status=1
fi

if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_AES_XTS_KEY_GEN) ]]; then
	# check AES-XTS 128
	grep -q 'p11sak-aes-xts-128' $P11SAK_AES_XTS_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE generate-key aes-xts-128 PASS Generated random AES-XTS 128 key"
	else
		echo "* TESTCASE generate-key aes-xts-128 FAIL Failed to generate AES-XTS 128 key"
		status=1
	fi
	grep -v -q 'p11sak-aes-xts-128' $P11SAK_AES_XTS_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-key aes-xts-128 PASS Deleted generated AES-XTS 128 key"
	else
		echo "* TESTCASE remove-key aes-xts-128 FAIL Failed to delete generated AES-XTS 128 key"
		status=1
	fi

	# check AES-XTS 256
	grep -q 'p11sak-aes-xts-256' $P11SAK_AES_XTS_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE generate-key aes-xts-256 PASS Generated random AES-XTS 256 key"
	else
		echo "* TESTCASE generate-key aes-xts-256 FAIL Failed to generate AES-XTS 256 key"
		status=1
	fi
	grep -v -q 'p11sak-aes-xts-256' $P11SAK_AES_XTS_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-key aes-xts-256 PASS Deleted generated AES-XTS 256 key"
	else
		echo "* TESTCASE remove-key aes-xts-256 FAIL Failed to delete generated AES-XTS 256 key"
		status=1
	fi
	
	# CK_BBOOL
	if [[ $(grep -A 69 'p11sak-aes-xts-128' $P11SAK_AES_XTS_LONG | grep -c 'CKA_IBM_PROTKEY_EXTRACTABLE: CK_FALSE') == "2" ]]; then
		echo "* TESTCASE list-key aes-xts PASS Listed random aes-xts public keys CK_BBOOL attribute"
	else
		echo "* TESTCASE list-key aes-xts FAIL Failed to list aes-xts public keys CK_BBOOL attribute"
		status=1
	fi
	# CK_ULONG
	if [[ $(grep -A 69 'p11sak-aes-xts-128' $P11SAK_AES_XTS_LONG | grep -c 'CKA_MODULUS_BITS:') == "0" ]]; then
		echo "* TESTCASE list-key aes-xts PASS Listed random aes-xts public keys CK_ULONG attribute"
	else
		echo "* TESTCASE list-key aes-xts FAIL Failed to list aes-xts public keys CK_ULONG attribute"
		status=1
	fi
	# CK_BYTE
	if [[ $(grep -A 69 'p11sak-aes-xts-128' $P11SAK_AES_XTS_LONG | grep -c 'CKA_MODULUS:') == "0" ]]; then
		echo "* TESTCASE list-key aes-xts PASS Listed random aes-xts public keys CK_BYTE attribute"
	else
		echo "* TESTCASE list-key aes-xts FAIL Failed to list aes-xts public keys CK_BYTE attribute"
		status=1
	fi
	# URI
	if [[ $(grep -A 69 'p11sak-aes-xts-128' $P11SAK_AES_XTS_LONG | grep -c 'URI: pkcs11:.*type=secret-key') == "2" ]]; then
		echo "* TESTCASE list-key aes-xts PASS list aes-xts key pkcs#11 URI"
	else
		echo "* TESTCASE list-key aes-xts FAIL list aes-xts key pkcs#11 URI"
		status=1
	fi
else
	echo "* TESTCASE generate-key aes-xst-128 SKIP Generated random AES-XTS 128 key"
	echo "* TESTCASE remove-key aes-xts-128 SKIP Deleted generated AES-XTS 128 key"
	echo "* TESTCASE generate-key aes-xst-256 SKIP Generated random AES-XTS 256 key"
	echo "* TESTCASE remove-key aes-xts-256 SKIP Deleted generated AES-XTS 256 key"
	echo "* TESTCASE list-key aes-xts SKIP Listed random aes-xts public keys CK_BBOOL attribute"
	echo "* TESTCASE list-key aes-xts SKIP Listed random aes-xts public keys CK_ULONG attribute"
	echo "* TESTCASE list-key aes-xts SKIP Listed random aes-xts public keys CK_BYTE attribute"
	echo "* TESTCASE list-key aes-xts SKIP list aes-xts key pkcs#11 URI"
fi

# check RSA 1024 public key
grep -q 'p11sak-rsa-1024:pub' $P11SAK_RSA_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key rsa 1024 PASS Generated random rsa 1024 public key"
else
	echo "* TESTCASE generate-key rsa 1024 FAIL Failed to generate rsa 1024 public key"
	status=1
fi
grep -v -q 'p11sak-rsa-1024:pub' $P11SAK_RSA_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key rsa PASS Deleted generated rsa 1024 public key"
else
	echo "* TESTCASE remove-key rsa FAIL Failed to delete generated rsa 1024 public key"
	status=1
fi


# check RSA 2048 public key
grep -q 'p11sak-rsa-2048:pub' $P11SAK_RSA_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key rsa 2048 PASS Generated random rsa 2048 public key"
else
	echo "* TESTCASE generate-key rsa 2048 FAIL Failed to generate rsa 2048 public key"
	status=1
fi
grep -v -q 'p11sak-rsa-2048:pub' $P11SAK_RSA_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key rsa PASS Deleted generated rsa 2048 public key"
else
	echo "* TESTCASE remove-key rsa FAIL Failed to delete generated rsa 2048 public key"
	status=1
fi


# check RSA 4096 public key
grep -q 'p11sak-rsa-4096:pub' $P11SAK_RSA_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key rsa 4096 PASS Generated random rsa 4096 public key"
else
	echo "* TESTCASE generate-key rsa 4096 FAIL Failed to generate rsa 4096 public key"
	status=1
fi
grep -v -q 'p11sak-rsa-4096:pub' $P11SAK_RSA_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key rsa PASS Deleted generated rsa 4096 public key"
else
	echo "* TESTCASE remove-key rsa FAIL Failed to delete generated rsa 4096 public key"
	status=1
fi


# check RSA 1024 private key
grep -q 'p11sak-rsa-1024:prv' $P11SAK_RSA_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key rsa 1024 PASS Generated random rsa 1024 private key"
else
	echo "* TESTCASE generate-key rsa 1024 FAIL Failed to generate rsa 1024 private key"
	status=1
fi
grep -v -q 'p11sak-rsa-1024:prv' $P11SAK_RSA_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key rsa PASS Deleted generated rsa 1024 private key"
else
	echo "* TESTCASE remove-key rsa FAIL Failed to delete generated rsa 1024 private key"
	status=1
fi


# check RSA 2048 private key
grep -q 'p11sak-rsa-2048:prv' $P11SAK_RSA_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key rsa 2048 PASS Generated random rsa 2048 private key"
else
	echo "* TESTCASE generate-key rsa 2048 FAIL Failed to generate rsa 2048 private key"
	status=1
fi
grep -v -q 'p11sak-rsa-2048:prv' $P11SAK_RSA_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key rsa PASS Deleted generated rsa 2048 private key"
else
	echo "* TESTCASE remove-key rsa FAIL Failed to delete generated rsa 2048 private key"
	status=1
fi


# check RSA 4096 private key
grep -q 'p11sak-rsa-4096:prv' $P11SAK_RSA_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key rsa 4096 PASS Generated random rsa 4096 private key"
else
	echo "* TESTCASE generate-key rsa 4096 FAIL Failed to generate rsa 4096 private key"
	status=1
fi
grep -v -q 'p11sak-rsa-4096:prv' $P11SAK_RSA_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key rsa PASS Deleted generated rsa 4096 private key"
else
	echo "* TESTCASE remove-key rsa FAIL Failed to delete generated rsa 4096 private key"
	status=1
fi


# CK_BBOOL
if [[ $(grep -A 211 'p11sak-rsa-1024:pub' $P11SAK_RSA_LONG | grep -c 'CKA_IBM_PROTKEY_EXTRACTABLE: CK_FALSE') == "6" ]]; then
	echo "* TESTCASE list-key rsa PASS Listed random rsa public keys CK_BBOOL attribute"
else
	echo "* TESTCASE list-key rsa FAIL Failed to list rsa public keys CK_BBOOL attribute"
	status=1
fi
# CK_ULONG
if [[ $(grep -A 211 'p11sak-rsa-1024:pub' $P11SAK_RSA_LONG | grep -c 'CKA_MODULUS_BITS:') == "3" ]]; then
	echo "* TESTCASE list-key rsa PASS Listed random rsa public keys CK_ULONG attribute"
else
	echo "* TESTCASE list-key rsa FAIL Failed to list rsa public keys CK_ULONG attribute"
	status=1
fi
# CK_BYTE
if [[ $(grep -A 211 'p11sak-rsa-1024:pub' $P11SAK_RSA_LONG | grep -c 'CKA_MODULUS:') == "6" ]]; then
	echo "* TESTCASE list-key rsa PASS Listed random rsa public keys CK_BYTE attribute"
else
	echo "* TESTCASE list-key rsa FAIL Failed to list rsa public keys CK_BYTE attribute"
	status=1
fi
# URI
if [[ $(grep -A 211 'p11sak-rsa-1024:pub' $P11SAK_RSA_LONG | grep -c 'URI: pkcs11:.*type=public') == "3" ]]; then
	echo "* TESTCASE list-key rsa PASS list rsa public key pkcs#11 URI"
else
	echo "* TESTCASE list-key rsa FAIL list rsa public key pkcs#11 URI"
	status=1
fi


# check EC prime256v1 public key
grep -q 'p11sak-ec-prime256v1:pub' $P11SAK_EC_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key ec prime256v1 PASS Generated random ec prime256v1 public key"
else
	echo "* TESTCASE generate-key ec prime256v1 FAIL Failed to generate ec prime256v1 public key"
	status=1
fi
grep -v -q 'p11sak-ec-prime256v1:pub' $P11SAK_EC_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key ec prime256v1 PASS Deleted generated ec prime256v1 public key"
else
	echo "* TESTCASE remove-key ec prime256v1 FAIL Failed to delete generated ec prime256v1 public key"
	status=1
fi


# check EC secp384r1 public key
grep -q 'p11sak-ec-secp384r1:pub' $P11SAK_EC_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key ec secp384r1 PASS Generated random ec secp384r1 public key"
else
	echo "* TESTCASE generate-key ec secp384r1 FAIL Failed to generate ec secp384r1 public key"
	status=1
fi
grep -v -q 'p11sak-ec-secp384r1:pub' $P11SAK_EC_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key ec secp384r1 PASS Deleted generated ec secp384r1 public key"
else
	echo "* TESTCASE remove-key ec secp384r1 FAIL Failed to delete generated ec secp384r1 public key"
	status=1
fi


# check EC secp521r1 public key
grep -q 'p11sak-ec-secp521r1:pub' $P11SAK_EC_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key ec secp521r1 PASS Generated random ec secp521r1 public key"
else
	echo "* TESTCASE generate-key ec secp521r1 FAIL Failed to generate ec secp521r1 public key"
	status=1
fi
grep -v -q 'p11sak-ec-secp521r1:pub' $P11SAK_EC_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key ec secp521r1 PASS Deleted generated ec secp521r1 public key"
else
	echo "* TESTCASE remove-key ec secp521r1 FAIL Failed to delete generated ec secp521r1 public key"
	status=1
fi


# check EC prime256v1 private key
grep -q 'p11sak-ec-prime256v1:prv' $P11SAK_EC_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key ec prime256v1 PASS Generated random ec prime256v1 private key"
else
	echo "* TESTCASE generate-key ec prime256v1 FAIL Failed to generate ec prime256v1 private key"
	status=1
fi
grep -v -q 'p11sak-ec-prime256v1:prv' $P11SAK_EC_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key ec prime256v1 PASS Deleted generated ec prime256v1 private key"
else
	echo "* TESTCASE remove-key ec prime256v1 FAIL Failed to delete generated ec prime256v1 private key"
	status=1
fi


# check EC secp384r1 private key
grep -q 'p11sak-ec-secp384r1:prv' $P11SAK_EC_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key ec secp384r1 PASS Generated random ec secp384r1 private key"
else
	echo "* TESTCASE generate-key ec secp384r1 FAIL Failed to generate ec secp384r1 private key"
	status=1
fi
grep -v -q 'p11sak-ec-secp384r1:prv' $P11SAK_EC_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key ec secp384r1 PASS Deleted generated ec secp384r1 private key"
else
	echo "* TESTCASE remove-key ec secp384r1 FAIL Failed to delete generated ec secp384r1 private key"
	status=1
fi


# check EC secp521r1 private key
grep -q 'p11sak-ec-secp521r1:prv' $P11SAK_EC_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key ec secp521r1 PASS Generated random ec secp521r1 private key"
else
	echo "* TESTCASE generate-key ec secp521r1 FAIL Failed to generate ec secp521r1 private key"
	status=1
fi
grep -v -q 'p11sak-ec-secp521r1:prv' $P11SAK_EC_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key ec secp521r1 PASS Deleted generated ec secp521r1 private key"
else
	echo "* TESTCASE remove-key ec secp521r1 FAIL Failed to delete generated ec secp521r1 private key"
	status=1
fi


# CK_BBOOL
if [[ $(grep -A 99 'p11sak-ec-prime256v1:pub' $P11SAK_EC_LONG | grep -c 'CKA_IBM_PROTKEY_EXTRACTABLE: CK_FALSE') == "6" ]]; then
	echo "* TESTCASE list-key ec PASS Listed random ec public keys CK_BBOOL attribute"
else
	echo "* TESTCASE list-key ec FAIL Failed to list ec public keys CK_BBOOL attribute"
	status=1
fi
# CK_ULONG
if [[ $(grep -A 99 'p11sak-ec-prime256v1:pub' $P11SAK_EC_LONG | grep -c 'CKA_MODULUS_BITS:') == "0" ]]; then
	echo "* TESTCASE list-key ec PASS Listed random ec public keys CK_ULONG attribute"
else
	echo "* TESTCASE list-key ec FAIL Failed to list ec public keys CK_ULONG attribute"
	status=1
fi
# CK_BYTE
if [[ $(grep -A 99 'p11sak-ec-prime256v1:pub' $P11SAK_EC_LONG | grep -c 'CKA_MODULUS:') == "0" ]]; then
	echo "* TESTCASE list-key ec PASS Listed random ec public keys CK_BYTE attribute"
else
	echo "* TESTCASE list-key ec FAIL Failed to list ec public keys CK_BYTE attribute"
	status=1
fi
# URI
if [[ $(grep -A 99 'p11sak-ec-prime256v1:pub' $P11SAK_EC_LONG | grep -c 'URI: pkcs11:.*type=public') == "3" ]]; then
	echo "* TESTCASE list-key ec PASS list ec public key pkcs#11 URI"
else
	echo "* TESTCASE list-key ec FAIL list ec public key pkcs#11 URI"
	status=1
fi


if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_IBM_DILITHIUM) ]]; then
	# CK_BBOOL
	if [[ $(grep -A 35 'p11sak-ibm-dilithium' $P11SAK_IBM_DIL_LONG | grep -c 'CK_TRUE') == "12" ]]; then
		echo "* TESTCASE list-key ibm-dilithium PASS Listed random ibm-dilithium public keys CK_BBOOL attribute"
	else
		echo "* TESTCASE list-key ibm-dilithium FAIL Failed to list ibm-dilithium public keys CK_BBOOL attribute"
		status=1
	fi
	# CK_ULONG
	if [[ $(grep -A 35 'p11sak-ibm-dilithium' $P11SAK_IBM_DIL_LONG | grep -c 'CKA_MODULUS_BITS:') == "0" ]]; then
		echo "* TESTCASE list-key ibm-dilithium PASS Listed random ibm-dilithium public keys CK_ULONG attribute"
	else
		echo "* TESTCASE list-key ibm-dilithium FAIL Failed to list ibm-dilithium public keys CK_ULONG attribute"
		status=1
	fi
	# CK_BYTE
	if [[ $(grep -A 35 'p11sak-ibm-dilithium' $P11SAK_IBM_DIL_LONG | grep -c 'CKA_MODULUS:') == "0" ]]; then
		echo "* TESTCASE list-key ibm-dilithium PASS Listed random ibm-dilithium public keys CK_BYTE attribute"
	else
		echo "* TESTCASE list-key ibm-dilithium FAIL Failed to list ibm-dilithium public keys CK_BYTE attribute"
		status=1
	fi
else
	echo "* TESTCASE list-key ibm-dilithium SKIP Listed random ibm-dilithium public keys CK_BBOOL attribute"
	echo "* TESTCASE list-key ibm-dilithium SKIP Listed random ibm-dilithium public keys CK_ULONG attribute"
	echo "* TESTCASE list-key ibm-dilithium SKIP Listed random ibm-dilithium public keys CK_BYTE attribute"
fi

if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_IBM_KYBER) ]]; then
	# CK_BBOOL
	if [[ $(grep -A 35 'p11sak-ibm-kyber' $P11SAK_IBM_KYBER_LONG | grep -c 'CK_TRUE') == "12" ]]; then
		echo "* TESTCASE list-key ibm-kyber PASS Listed random ibm-kyber public keys CK_BBOOL attribute"
	else
		echo "* TESTCASE list-key ibm-kyber FAIL Failed to list ibm-kyber public keys CK_BBOOL attribute"
		status=1
	fi
	# CK_ULONG
	if [[ $(grep -A 35 'p11sak-ibm-kyber' $P11SAK_IBM_KYBER_LONG | grep -c 'CKA_MODULUS_BITS:') == "0" ]]; then
		echo "* TESTCASE list-key ibm-kyber PASS Listed random ibm-kyber public keys CK_ULONG attribute"
	else
		echo "* TESTCASE list-key ibm-kyber FAIL Failed to list ibm-kyber public keys CK_ULONG attribute"
		status=1
	fi
	# CK_BYTE
	if [[ $(grep -A 35 'p11sak-ibm-kyber' $P11SAK_IBM_KYBER_LONG | grep -c 'CKA_MODULUS:') == "0" ]]; then
		echo "* TESTCASE list-key ibm-kyber PASS Listed random ibm-kyber public keys CK_BYTE attribute"
	else
		echo "* TESTCASE list-key ibm-kyber FAIL Failed to list ibm-kyber public keys CK_BYTE attribute"
		status=1
	fi
else
	echo "* TESTCASE list-key ibm-kyber SKIP Listed random ibm-kyber public keys CK_BBOOL attribute"
	echo "* TESTCASE list-key ibm-kyber SKIP Listed random ibm-kyber public keys CK_ULONG attribute"
	echo "* TESTCASE list-key ibm-kyber SKIP Listed random ibm-kyber public keys CK_BYTE attribute"
fi

# check token pin handling
if [ $RC_P11SAK_PINOPT = 0 ]; then
	echo "* TESTCASE list-key pin-opt PASS Token pin handling (opt)"
else
	echo "* TESTCASE list-key pin-option FAIL Token pin handling (opt)"
fi

if [ $RC_P11SAK_PINENV = 0 ]; then
	echo "* TESTCASE list-key pin-env PASS Token pin handling (env)"
else
	echo "* TESTCASE list-key pin-env FAIL Token pin handling (env)"
fi

if [ $RC_P11SAK_PINCON = 0 ]; then
	echo "* TESTCASE list-key pin-prompt PASS Token pin handling (prompt)"
else
	echo "* TESTCASE list-key pin-prompt FAIL Token pin handling (prompt)"
fi

if diff -q $P11SAK_ALL_PINOPT $P11SAK_ALL_PINENV ; then
	echo "* TESTCASE list-key pin-opt-env PASS Token pin opt/env output compare"
else
	echo "* TESTCASE list-key pin-opt-env FAIL Token pin opt/env output compare"
fi

if diff -q $P11SAK_ALL_PINOPT $P11SAK_ALL_PINCON ; then
	echo "* TESTCASE list-key pin-opt-prompt PASS Token pin opt/prompt output compare"
else
	echo "* TESTCASE list-key pin-opt-prompt FAIL Token pin opt/prompt output compare"
fi


echo "** Now remove temporary output files - 'p11sak_test.sh'"


rm -f $P11SAK_DES_PRE
rm -f $P11SAK_DES_LONG
rm -f $P11SAK_DES_POST
rm -f $P11SAK_3DES_PRE
rm -f $P11SAK_3DES_LONG
rm -f $P11SAK_3DES_POST
rm -f $P11SAK_AES_PRE
rm -f $P11SAK_AES_LONG
rm -f $P11SAK_AES_POST
rm -f $P11SAK_AES_XTS_PRE
rm -f $P11SAK_AES_XTS_LONG
rm -f $P11SAK_AES_XTS_POST
rm -f $P11SAK_RSA_PRE
rm -f $P11SAK_RSA_LONG
rm -f $P11SAK_RSA_POST
rm -f $P11SAK_EC_PRE
rm -f $P11SAK_EC_LONG
rm -f $P11SAK_EC_POST
rm -f $P11SAK_IBM_DIL_PRE
rm -f $P11SAK_IBM_DIL_LONG
rm -f $P11SAK_IBM_DIL_POST
rm -f $P11SAK_IBM_KYBER_PRE
rm -f $P11SAK_IBM_KYBER_LONG
rm -f $P11SAK_IBM_KYBER_POST
rm -f $P11SAK_ALL_PINOPT
rm -f $P11SAK_ALL_PINENV
rm -f $P11SAK_ALL_PINCON

echo "** Now DONE testing - 'p11sak_test.sh' - rc = $status"

exit $status
