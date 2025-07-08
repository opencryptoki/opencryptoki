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

DIR=$(dirname "$0")

status=0


echo "** Now executing 'p11sak_test.sh'"

# tmp files

P11SAK_DES_PRE=p11sak-des-pre.out
P11SAK_DES_LONG=p11sak-des-long.out
P11SAK_DES_POST=p11sak-des-post.out
P11SAK_3DES_PRE=p11sak-3des-pre.out
P11SAK_3DES_LONG=p11sak-3des-long.out
P11SAK_3DES_POST=p11sak-3des-post.out
P11SAK_GENERIC_PRE=p11sak-generic-pre.out
P11SAK_GENERIC_LONG=p11sak-generic-long.out
P11SAK_GENERIC_POST=p11sak-generic-post.out
P11SAK_AES_PRE=p11sak-aes-pre.out
P11SAK_AES_LONG=p11sak-aes-long.out
P11SAK_AES_POST=p11sak-aes-post.out
P11SAK_AES_XTS_PRE=p11sak-aes-xts-pre.out
P11SAK_AES_XTS_LONG=p11sak-aes-xts-long.out
P11SAK_AES_XTS_POST=p11sak-aes-xts-post.out
P11SAK_RSA_PRE=p11sak-rsa-pre.out
P11SAK_RSA_LONG=p11sak-rsa-long.out
P11SAK_RSA_POST=p11sak-rsa-post.out
P11SAK_DH_PRE=p11sak-dh-pre.out
P11SAK_DH_LONG=p11sak-dh-long.out
P11SAK_DH_POST=p11sak-dh-post.out
P11SAK_DSA_PRE=p11sak-dsa-pre.out
P11SAK_DSA_LONG=p11sak-dsa-long.out
P11SAK_DSA_POST=p11sak-dsa-post.out
P11SAK_EC_PRE=p11sak-ec-pre.out
P11SAK_EC_LONG=p11sak-ec-long.out
P11SAK_EC_POST=p11sak-ec-post.out
P11SAK_EC_EDWARDS_PRE=p11sak-ec-edwards-pre.out
P11SAK_EC_EDWARDS_LONG=p11sak-ec-edwards-long.out
P11SAK_EC_EDWARDS_POST=p11sak-ec-edwards-post.out
P11SAK_EC_MONTGOMERY_PRE=p11sak-ec-montgomery-pre.out
P11SAK_EC_MONTGOMERY_LONG=p11sak-ec-montgomery-long.out
P11SAK_EC_MONTGOMERY_POST=p11sak-ec-montgomery-post.out
P11SAK_IBM_DILITHIUM_PRE=p11sak-ibm-dilithium-pre.out
P11SAK_IBM_DILITHIUM_LONG=p11sak-ibm-dilithium-long.out
P11SAK_IBM_DILITHIUM_POST=p11sak-ibm-dilithium-post.out
P11SAK_IBM_KYBER_PRE=p11sak-ibm-kyber-pre.out
P11SAK_IBM_KYBER_LONG=p11sak-ibm-kyber-long.out
P11SAK_IBM_KYBER_POST=p11sak-ibm-kyber-post.out
P11SAK_IBM_ML_DSA_PRE=p11sak-ibm-ml-dsa-pre.out
P11SAK_IBM_ML_DSA_LONG=p11sak-ibm-ml-dsa-long.out
P11SAK_IBM_ML_DSA_POST=p11sak-ibm-ml-dsa-post.out
P11SAK_IBM_ML_KEM_PRE=p11sak-ibm-ml-kem-pre.out
P11SAK_IBM_ML_KEM_LONG=p11sak-ibm-ml-kem-long.out
P11SAK_IBM_ML_KEM_POST=p11sak-ibm-ml-kem-post.out
P11SAK_ALL_PINOPT=p11sak-all-pinopt
P11SAK_ALL_PINENV=p11sak-all-pinenv
P11SAK_ALL_PINCON=p11sak-all-pincon
P11SAK_ALL_NOLOGIN=p11sak-all-nologin
P11SAK_ALL_SO=p11sak-all-so
P11SAK_X509_PRE=p11sak-x509-pre.out
P11SAK_X509_LONG=p11sak-x509-long.out
P11SAK_X509_POST=p11sak-x509-post.out


echo "** Setting SLOT=30 to the Softtoken unless otherwise set - 'p11sak_test.sh'"

# Validate required environment variables
if [[ -z "${PKCS11_USER_PIN}" ]]; then
	echo "Please set the PKCS11_USER_PIN environment variable"
	exit 1
fi

# setting SLOT=30 to the Softtoken

SLOT=${SLOT:-30}

# check if p11sak is available in the current $PATH - if it isn't, ask for
# SBINDIR to be defined before this script executes.
# The assumption here is that p11sak and pkcsconf are installed in the same
# directory - if one is found, the other is assumed to be available as well.
if [[ -n "$(command -v pkcsconf)" ]]; then
	PKCSCONF=pkcsconf
	P11SAK=p11sak
elif [[ -z "$SBINDIR" ]]; then
	echo "pkcsconf and/or p11sak were not found in \$PATH."
	echo "Define \$SBINDIR to the appropriate path and try again."
	exit 1
else
	PKCSCONF=${SBINDIR}/pkcsconf
	P11SAK=${SBINDIR}/p11sak
fi

echo "** Using Slot $SLOT with PKCS11_USER_PIN $PKCS11_USER_PIN and PKCSLIB $PKCSLIB - 'p11sak_test.sh'"


echo "** Now generating keys - 'p11sak_test.sh'"

# generate objects
RC_P11SAK_GENERATE=0

# des
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_DES_KEY_GEN) ]]; then
	${P11SAK} generate-key des --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-des"
	RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
else
	echo "Skip generating des keys, slot does not support CKM_DES_KEY_GEN"
fi
# 3des
${P11SAK} generate-key 3des --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-3des"
RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
# generic
${P11SAK} generate-key generic 256 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-generic"
RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
# aes [128 | 192 | 256]
${P11SAK} generate-key aes 128 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-128"
RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
${P11SAK} generate-key aes 192 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-192"
RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
${P11SAK} generate-key aes 256 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-256"
RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
# aes-xts [128 | 256]
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_AES_XTS_KEY_GEN) ]]; then
	if [[ -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: EP11") || -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: CCA") ]]; then
		# EP11 needs CKA_IBM_PROTKEY_EXTRACTABLE=TRUE and CKA_EXTRACTABLE=FALSE for AES-XTS keys
		# CCA needs CKA_IBM_PROTKEY_EXTRACTABLE=TRUE for AES-XTS keys
		P11SAK_ATTR="--attr xK"
	else
		P11SAK_ATTR=""
	fi
	${P11SAK} generate-key aes-xts 128 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-xts-128" $P11SAK_ATTR
	RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
	${P11SAK} generate-key aes-xts 256 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-xts-256" $P11SAK_ATTR
	RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
else
	echo "Skip generating aes-xts keys, slot does not support CKM_AES_XTS_KEY_GEN"
fi
# rsa [1024 | 2048 | 4096]
${P11SAK} generate-key rsa 1024 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-1024"
RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
${P11SAK} generate-key rsa 2048 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-2048"
RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
${P11SAK} generate-key rsa 4096 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-4096"
RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
# dh ffdhe2048
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_DH_PKCS_KEY_PAIR_GEN) ]]; then
	${P11SAK} generate-key dh ffdhe2048 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-dh"
	RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
else
	echo "Skip generating dh keys, slot does not support CKM_DH_PKCS_KEY_PAIR_GEN"
fi
# dsa dsa-param.pem
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_DSA_KEY_PAIR_GEN) ]]; then
	${P11SAK} generate-key dsa $DIR/dsa-param.pem --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-dsa"
	RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
else
	echo "Skip generating dsa keys, slot does not support CKM_DSA_KEY_PAIR_GEN"
fi
# ec [prime256v1 | secp384r1 | secp521r1]
${P11SAK} generate-key ec prime256v1 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-prime256v1"
RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
${P11SAK} generate-key ec secp384r1 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-secp384r1"
RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
${P11SAK} generate-key ec secp521r1 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-secp521r1"
RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
# ec-edwards [ed25519 | ed448]
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_EC_EDWARDS_KEY_PAIR_GEN) ]]; then
	${P11SAK} generate-key ec-edwards ed25519 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-edwards-ed25519"
	RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
	${P11SAK} generate-key ec-edwards ed448 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-edwards-ed448"
	RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
else
	echo "Skip generating ec-edwards keys, slot does not support CKM_EC_EDWARDS_KEY_PAIR_GEN"
fi
# ec-montgomery [curve25519 | curve448]
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_EC_MONTGOMERY_KEY_PAIR_GEN) ]]; then
	${P11SAK} generate-key ec-montgomery curve25519 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-montgomery-x25519"
	RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
	${P11SAK} generate-key ec-montgomery curve448 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-montgomery-x448"
	RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
else
	echo "Skip generating ec-montgomery keys, slot does not support CKM_EC_MONTGOMERY_KEY_PAIR_GEN"
fi
# ibm-dilithium
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_IBM_DILITHIUM) ]]; then
	if [[ -z $( ${PKCSCONF} -t -c $SLOT | grep "Model: Soft") ]]; then
		${P11SAK} generate-key ibm-dilithium r2_65 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-dilithium"
		RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
	else
		${P11SAK} generate-key ibm-dilithium r3_65 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-dilithium"
		RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
	fi
else
	echo "Skip generating ibm-dilithium keys, slot does not support CKM_IBM_DILITHIUM"
fi
# ibm-kyber
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_IBM_KYBER) ]]; then
	${P11SAK} generate-key ibm-kyber r2_1024 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-kyber"
	RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
else
	echo "Skip generating ibm-kyber keys, slot does not support CKM_IBM_KYBER"
fi
# ibm-ml-dsa
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_IBM_ML_DSA) ]]; then
	${P11SAK} generate-key ibm-ml-dsa 65 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-ml-dsa"
	RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
else
	echo "Skip generating ibm-ml-dsa keys, slot does not support CKM_IBM_ML_DSA"
fi
# ibm-ml-kem
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_IBM_ML_KEM) ]]; then
	${P11SAK} generate-key ibm-ml-kem 1024 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-ml-kem"
	RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
else
	echo "Skip generating ibm-ml-kem keys, slot does not support CKM_IBM_ML_KEM"
fi


echo "** Now list keys and redirect output to pre-files - 'p11sak_test.sh'"

# list objects
RC_P11SAK_LIST=0
${P11SAK} list-key des --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-des" &> $P11SAK_DES_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))
${P11SAK} list-key 3des --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-3des" &> $P11SAK_3DES_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))
${P11SAK} list-key generic --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-generic" &> $P11SAK_GENERIC_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))
${P11SAK} list-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-*" &> $P11SAK_AES_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))
${P11SAK} list-key aes-xts --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-xts-*" &> $P11SAK_AES_XTS_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))
${P11SAK} list-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-*" &> $P11SAK_RSA_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))
${P11SAK} list-key dh --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-dh*" &> $P11SAK_DH_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))
${P11SAK} list-key dsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-dsa*" &> $P11SAK_DSA_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))
${P11SAK} list-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-*" &> $P11SAK_EC_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))
${P11SAK} list-key ec-edwards --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-edwards-*" &> $P11SAK_EC_EDWARDS_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))
${P11SAK} list-key ec-montgomery --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-*" &> $P11SAK_EC_MONTGOMERY_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))
${P11SAK} list-key ibm-dilithium --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-dilithium*" &> $P11SAK_IBM_DILITHIUM_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))
${P11SAK} list-key ibm-kyber --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-kyber*" &> $P11SAK_IBM_KYBER_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))
${P11SAK} list-key ibm-ml-dsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-ml-dsa*" &> $P11SAK_IBM_ML_DSA_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))
${P11SAK} list-key ibm-ml-kem --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-ml-kem*" &> $P11SAK_IBM_ML_KEM_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))

RC_P11SAK_LIST_LONG=0
${P11SAK} list-key des --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-des" &> $P11SAK_DES_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))
${P11SAK} list-key 3des --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-3des" &> $P11SAK_3DES_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))
${P11SAK} list-key generic --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-generic" &> $P11SAK_GENERIC_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))
${P11SAK} list-key aes --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-aes-*" &> $P11SAK_AES_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))
${P11SAK} list-key aes-xts --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-aes-xts-*" &> $P11SAK_AES_XTS_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))
${P11SAK} list-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-rsa-*" &> $P11SAK_RSA_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))
${P11SAK} list-key dh --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-dh*" &> $P11SAK_DH_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))
${P11SAK} list-key dsa --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-dsa*" &> $P11SAK_DSA_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))
${P11SAK} list-key ec --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-ec-*" &> $P11SAK_EC_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))
${P11SAK} list-key ec-edwards --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-ec-edwards*" &> $P11SAK_EC_EDWARDS_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))
${P11SAK} list-key ec-montgomery --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-ec-montgomery*" &> $P11SAK_EC_MONTGOMERY_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))
${P11SAK} list-key ibm-dilithium --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-ibm-dilithium*" &> $P11SAK_IBM_DILITHIUM_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))
${P11SAK} list-key ibm-kyber --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-ibm-kyber*" &> $P11SAK_IBM_KYBER_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))
${P11SAK} list-key ibm-ml-dsa --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-ibm-ml-dsa*" &> $P11SAK_IBM_ML_DSA_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))
${P11SAK} list-key ibm-ml-kem --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-ibm-ml-kem*" &> $P11SAK_IBM_ML_KEM_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))


${P11SAK} list-key all --slot $SLOT --pin $PKCS11_USER_PIN &> $P11SAK_ALL_PINOPT
RC_P11SAK_PINOPT=$?
${P11SAK} list-key all --slot $SLOT &> $P11SAK_ALL_PINENV
RC_P11SAK_PINENV=$?
printf "${PKCS11_USER_PIN}\n" | ${P11SAK} list-key all --slot $SLOT --force-pin-prompt | tail -n +2 &> $P11SAK_ALL_PINCON
RC_P11SAK_PINCON=$?

${P11SAK} list-key all --slot $SLOT --no-login &> $P11SAK_ALL_NOLOGIN
RC_P11SAK_NOLOGIN=$?
if [[ -n $PKCS11_SO_PIN ]]; then
	${P11SAK} list-key all --slot $SLOT --pin $PKCS11_SO_PIN --so &> $P11SAK_ALL_SO
	RC_P11SAK_SO=$?
else
	echo "Skip login as SO, PKCS11_SO_PIN is not set"
fi

echo "** Now updating keys - 'p11sak_test.sh'"

RC_P11SAK_UPDATE=0
${P11SAK} set-key-attr aes --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-*" --new-attr "ed" --force
RC_P11SAK_UPDATE=$((RC_P11SAK_UPDATE + $?))
${P11SAK} set-key-attr rsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-*" --new-id "012345" --force
RC_P11SAK_UPDATE=$((RC_P11SAK_UPDATE + $?))


echo "** Now copying keys - 'p11sak_test.sh'"

RC_P11SAK_COPY=0
${P11SAK} copy-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-*" --new-label "p11sak-aes-copied" --new-attr "ED" --force
RC_P11SAK_COPY=$((RC_P11SAK_COPY + $?))


echo "** Now extracting public keys - 'p11sak_test.sh'"

RC_P11SAK_KEY_EXTRACT=0
${P11SAK} extract-pubkey private --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-*" --new-label "p11sak-pubkey-extracted" --force
RC_P11SAK_KEY_EXTRACT=$((RC_P11SAK_KEY_EXTRACT + $?))
${P11SAK} extract-pubkey private --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-dh*" --new-label "p11sak-pubkey-extracted" --force
RC_P11SAK_KEY_EXTRACT=$((RC_P11SAK_KEY_EXTRACT + $?))
${P11SAK} extract-pubkey private --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-dsa*" --new-label "p11sak-pubkey-extracted" --force
RC_P11SAK_KEY_EXTRACT=$((RC_P11SAK_KEY_EXTRACT + $?))
${P11SAK} extract-pubkey private --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-prime256v1*" --new-label "p11sak-pubkey-extracted" --force
RC_P11SAK_KEY_EXTRACT=$((RC_P11SAK_KEY_EXTRACT + $?))
${P11SAK} extract-pubkey private --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-edwards-ed25519*" --new-label "p11sak-pubkey-extracted" --force
RC_P11SAK_KEY_EXTRACT=$((RC_P11SAK_KEY_EXTRACT + $?))
${P11SAK} extract-pubkey private --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-montgomery-curve448*" --new-label "p11sak-pubkey-extracted" --force
RC_P11SAK_KEY_EXTRACT=$((RC_P11SAK_KEY_EXTRACT + $?))
${P11SAK} extract-pubkey private --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-dilithium*" --new-label "p11sak-pubkey-extracted" --force
RC_P11SAK_KEY_EXTRACT=$((RC_P11SAK_KEY_EXTRACT + $?))
${P11SAK} extract-pubkey private --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-kyber*" --new-label "p11sak-pubkey-extracted" --force
RC_P11SAK_KEY_EXTRACT=$((RC_P11SAK_KEY_EXTRACT + $?))
${P11SAK} extract-pubkey private --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-ml-dsa*" --new-label "p11sak-pubkey-extracted" --force
RC_P11SAK_KEY_EXTRACT=$((RC_P11SAK_KEY_EXTRACT + $?))
${P11SAK} extract-pubkey private --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-ml-kem*" --new-label "p11sak-pubkey-extracted" --force
RC_P11SAK_KEY_EXTRACT=$((RC_P11SAK_KEY_EXTRACT + $?))


echo "** Now importing keys - 'p11sak_test.sh'"

RC_P11SAK_IMPORT=0
# aes
${P11SAK} import-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label "import-aes" --file $DIR/aes.key --attr sX
RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
# rsa
${P11SAK} import-key rsa private --slot $SLOT --pin $PKCS11_USER_PIN --label "import-rsa-private" --file $DIR/rsa-key.pem --attr sX
RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
${P11SAK} import-key rsa public --slot $SLOT --pin $PKCS11_USER_PIN --label "import-rsa-public" --file $DIR/rsa-key.pem --attr sX
RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
# dsa
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_DSA) ]]; then
	${P11SAK} import-key dsa private --slot $SLOT --pin $PKCS11_USER_PIN --label "import-dsa-private" --file $DIR/dsa-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	${P11SAK} import-key dsa public --slot $SLOT --pin $PKCS11_USER_PIN --label "import-dsa-public" --file $DIR/dsa-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
else
	echo "Skip importing dsa keys, slot does not support CKM_DSA"
fi
# dh
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_DH_PKCS_DERIVE) ]]; then
	${P11SAK} import-key dh private --slot $SLOT --pin $PKCS11_USER_PIN --label "import-dh-private" --file $DIR/dh-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	${P11SAK} import-key dh public --slot $SLOT --pin $PKCS11_USER_PIN --label "import-dh-public" --file $DIR/dh-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
else
	echo "Skip importing dh keys, slot does not support CKM_DH_PKCS_DERIVE"
fi
# ec
${P11SAK} import-key ec private --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-prime256v1-private" --file $DIR/ec-key-prime256v1.pem --attr sX
RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
${P11SAK} import-key ec public --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-prime256v1-public" --file $DIR/ec-key-prime256v1.pem --attr sX
RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
${P11SAK} import-key ec private --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-secp521r1-private" --file $DIR/ec-key-secp521r1.pem --attr sX
RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
${P11SAK} import-key ec public --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-secp521r1-public" --file $DIR/ec-key-secp521r1.pem --attr sX
RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
# edwards/montgomery
if [[ -n $(openssl version | grep "OpenSSL 3.") && -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: EP11") ]]; then
	${P11SAK} import-key ec private --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-ed25519-private" --file $DIR/ed25519-private-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	${P11SAK} import-key ec public --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-ed25519-public" --file $DIR/ed25519-public-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
else
	echo "Skip importing edwards/montgomery keys, OpenSSL version not supporting it or not EP11 token"
fi
# ec-edwards
if [[ -n $(openssl version | grep "OpenSSL 3.") && -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_EC_EDWARDS_KEY_PAIR_GEN) ]]; then
	${P11SAK} import-key ec-edwards private --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-edwards-ed25519-private" --file $DIR/ed25519-private-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	${P11SAK} import-key ec-edwards public --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-edwards-ed25519-public" --file $DIR/ed25519-public-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	${P11SAK} import-key ec-edwards private --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-edwards-ed448-private" --file $DIR/ed448-private-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	${P11SAK} import-key ec-edwards public --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-edwards-ed448-public" --file $DIR/ed448-public-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
else
	echo "Skip importing ec-edwards keys, OpenSSL version not supporting it or the token does nt support it"
fi
# ec-montgomery
if [[ -n $(openssl version | grep "OpenSSL 3.") && -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_EC_MONTGOMERY_KEY_PAIR_GEN) ]]; then
	${P11SAK} import-key ec-montgomery private --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-montgomery-x25519-private" --file $DIR/x25519-private-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	${P11SAK} import-key ec-montgomery public --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-montgomery-x25519-public" --file $DIR/x25519-public-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	${P11SAK} import-key ec-montgomery private --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-montgomery-x448-private" --file $DIR/x448-private-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	${P11SAK} import-key ec-montgomery public --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-montgomery-x448-public" --file $DIR/x448-public-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
else
	echo "Skip importing ec-montgomery keys, OpenSSL version not supporting it or the token does nt support it"
fi
# ibm-dilithium
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_IBM_DILITHIUM) ]]; then
	if [[ -z $( ${PKCSCONF} -t -c $SLOT | grep "Model: Soft") ]]; then
		${P11SAK} import-key ibm-dilithium private --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ibm-dilithium-private" --file $DIR/ibm-dilithium-r2-65-key.pem --attr sX
		RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
		${P11SAK} import-key ibm-dilithium public --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ibm-dilithium-public" --file $DIR/ibm-dilithium-r2-65-key.pem --attr sX
		RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	else
		${P11SAK} import-key ibm-dilithium private --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ibm-dilithium-private" --file $DIR/ibm-dilithium-r3-65-key.pem --attr sX
		RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
		${P11SAK} import-key ibm-dilithium public --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ibm-dilithium-public" --file $DIR/ibm-dilithium-r3-65-key.pem --attr sX
		RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	fi
	if [[ -n $(openssl list -providers | grep oqsprovider) && -n $(openssl list -key-managers | grep "dilithium3 @ oqsprovider") ]]; then
		openssl genpkey -algorithm dilithium3 -out oqs-dil3-priv-key.pem
		RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
		openssl pkey -in oqs-dil3-priv-key.pem -pubout -out oqs-dil3-pub-key.pem
		RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
		${P11SAK} import-key ibm-dilithium private --slot $SLOT --pin $PKCS11_USER_PIN --label "import-oqs-dilithium-private" --file oqs-dil3-priv-key.pem --oqsprovider-pem --attr sX
		RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
		${P11SAK} import-key ibm-dilithium public --slot $SLOT --pin $PKCS11_USER_PIN --label "import-oqs-dilithium-public" --file oqs-dil3-pub-key.pem --oqsprovider-pem --attr sX
		RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	else
		echo "Skip importing oqs-dilithium keys, the oqsprovider is not available or does not support dilithium3"
	fi
else
	echo "Skip importing ibm-dilithium keys, slot does not support CKM_IBM_DILITHIUM"
fi
# ibm-kyber
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_IBM_KYBER) ]]; then
	${P11SAK} import-key ibm-kyber private --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ibm-kyber-private" --file $DIR/ibm-kyber-r2-768-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	${P11SAK} import-key ibm-kyber public --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ibm-kyber-public" --file $DIR/ibm-kyber-r2-768-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
else
	echo "Skip importing ibm-kyber keys, slot does not support CKM_IBM_KYBER"
fi

# ibm-ml-dsa
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_IBM_ML_DSA) ]]; then
	if [[ -n $(openssl list -key-managers | grep -i "MLDSA65") ]]; then
		openssl genpkey -algorithm mldsa65 -out mldsa65-priv-key.pem
		RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
		openssl pkey -in mldsa65-priv-key.pem -pubout -out mldsa65-pub-key.pem
		RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
		${P11SAK} import-key ibm-ml-dsa private --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ml-dsa-private" --file mldsa65-priv-key.pem --attr sX
		RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
		${P11SAK} import-key ibm-ml-dsa public --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ml-dsa-public" --file mldsa65-pub-key.pem --attr sX
		RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	else
		echo "Skip importing ml-dsa keys, neither OpenSSL 3.5, nor the oqsprovider is available or does not support mldsa65"
	fi
else
	echo "Skip importing ibm-ml-dsa keys, slot does not support CKM_IBM_ML_DSA"
fi
# ibm-ml-kem
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_IBM_ML_KEM) ]]; then
	if [[ -n $(openssl list -key-managers | grep -i "MLKEM1024") ]]; then
		openssl genpkey -algorithm mlkem1024 -out mlkem1024-priv-key.pem
		RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
		openssl pkey -in mlkem1024-priv-key.pem -pubout -out mlkem1024-pub-key.pem
		RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
		${P11SAK} import-key ibm-ml-kem private --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ml-kem-private" --file mlkem1024-priv-key.pem --attr sX
		RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
		${P11SAK} import-key ibm-ml-kem public --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ml-kem-public" --file mlkem1024-pub-key.pem --attr sX
		RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	else
		echo "Skip importing ml-kem keys, neither OpenSSL 3.5, nor the oqsprovider is available or does not support mlkem1024"
	fi
else
	echo "Skip importing ibm-kyber keys, slot does not support CKM_IBM_ML_KEM"
fi

echo "** Now exporting keys - 'p11sak_test.sh'"

RC_P11SAK_EXPORT=0
# aes
if [[ -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: EP11") || -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: CCA") ]]; then
	${P11SAK} export-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label "import-aes" --file export-aes.opaque --force --opaque
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
else
	${P11SAK} export-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label "import-aes" --file export-aes.key --force
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	diff export-aes.key $DIR/aes.key > /dev/null
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
fi
# rsa
if [[ -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: EP11") || -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: CCA") ]]; then
	${P11SAK} export-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label "import-rsa-public" --file export-rsa-key.pem --force
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	${P11SAK} export-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label "import-rsa-private" --file export-rsa-key.opaque --force --opaque
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
else
	${P11SAK} export-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label "import-rsa-*" --file export-rsa-key.pem --force
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	openssl pkey -in export-rsa-key.pem -check -text > /dev/null
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
fi
openssl pkey -in export-rsa-key.pem -pubin -text > /dev/null
RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
# dsa
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_DSA) ]]; then
	if [[ -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: EP11") || -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: CCA") ]]; then
		${P11SAK} export-key dsa --slot $SLOT --pin $PKCS11_USER_PIN --label "import-dsa-public" --file export-dsa-key.pem --force
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		${P11SAK} export-key dsa --slot $SLOT --pin $PKCS11_USER_PIN --label "import-dsa-private" --file export-dsa-key.opaque --force --opaque
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))	
	else
		${P11SAK} export-key dsa --slot $SLOT --pin $PKCS11_USER_PIN --label "import-dsa-*" --file export-dsa-key.pem --force
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		openssl pkey -in export-dsa-key.pem -text > /dev/null
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	fi
	openssl pkey -in export-dsa-key.pem -pubin -text > /dev/null
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
else
	echo "Skip exporting dsa keys, slot does not support CKM_DSA"
fi
# dh
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_DH_PKCS_DERIVE) ]]; then
	if [[ -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: EP11") || -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: CCA") ]]; then
		${P11SAK} export-key dh --slot $SLOT --pin $PKCS11_USER_PIN --label "import-dh-public" --file export-dh-key.pem --force
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		${P11SAK} export-key dh --slot $SLOT --pin $PKCS11_USER_PIN --label "import-dh-private" --file export-dh-key.opaque --force --opaque
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	else	
		${P11SAK} export-key dh --slot $SLOT --pin $PKCS11_USER_PIN --label "import-dh-*" --file export-dh-key.pem --force
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		openssl pkey -in export-dh-key.pem -text > /dev/null
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	fi
	openssl pkey -in export-dh-key.pem -pubin -text > /dev/null
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
else
	echo "Skip exporting dh keys, slot does not support CKM_DH_PKCS_DERIVE"
fi
# ec
if [[ -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: EP11") || -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: CCA") ]]; then
	${P11SAK} export-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-prime256v1-public" --file export-ec-prime256v1-key.pem --force
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	${P11SAK} export-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-prime256v1-private" --file export-ec-prime256v1-key.opaque --force --opaque
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	${P11SAK} export-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-secp521r1-public" --file export-ec-secp521r1-key.pem --force
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	${P11SAK} export-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-secp521r1-private" --file export-ec-secp521r1-key.opaque --force --opaque
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	if [[ -n $(openssl version | grep "OpenSSL 3.") && -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: EP11") ]]; then
		${P11SAK} export-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-ed25519-public" --file export-ec-ed25519-key.pem --force
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		${P11SAK} export-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-ed25519-private" --file export-ec-ed25519-key.opaque --force --opaque
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	else
		echo "Skip exporting edwards/montgomery keys, OpenSSL version not supporting it or not EP11 token"
	fi
else
	${P11SAK} export-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-prime256v1-*" --file export-ec-prime256v1-key.pem --force
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	openssl pkey -in export-ec-prime256v1-key.pem -check -text > /dev/null
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	${P11SAK} export-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-secp521r1-*" --file export-ec-secp521r1-key.pem --force
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	openssl pkey -in export-ec-secp521r1-key.pem -check -text > /dev/null
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
fi
openssl pkey -in export-ec-prime256v1-key.pem -pubin -text > /dev/null
RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
openssl pkey -in export-ec-secp521r1-key.pem -pubin -text > /dev/null
RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
if [[ -n $(openssl version | grep "OpenSSL 3.") && -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: EP11") ]]; then
	openssl pkey -in export-ec-ed25519-key.pem -pubin -text > /dev/null
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
fi
# ec-edwards
if [[ -n $(openssl version | grep "OpenSSL 3.") && -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_EC_EDWARDS_KEY_PAIR_GEN) ]]; then
	if [[ -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: EP11") || -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: CCA") ]]; then
		${P11SAK} export-key ec-edwards --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-edwards-ed25519-public" --file export-ec-edwards-ed25519-key.pem --force
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		${P11SAK} export-key ec-edwards --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-edwards-ed25519-private" --file export-ec-edwards-ed25519-key.opaque --force --opaque
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		${P11SAK} export-key ec-edwards --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-edwards-ed448-public" --file export-ec-edwards-ed448-key.pem --force
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		${P11SAK} export-key ec-edwards --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-edwards-ed448-private" --file export-ec-edwards-ed448-key.opaque --force --opaque
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	else
		${P11SAK} export-key ec-edwards --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-edwards-ed25519-*" --file export-ec-edwards-ed25519-key.pem --force
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		openssl pkey -in export-ec-edwards-ed25519-key.pem -check -text > /dev/null
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		${P11SAK} export-key ec-edwards --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-edwards-ed448-*" --file export-ec-edwards-ed448-key.pem --force
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		openssl pkey -in export-ec-edwards-ed448-key.pem -check -text > /dev/null
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	fi
	openssl pkey -in export-ec-edwards-ed25519-key.pem -pubin -text > /dev/null
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	openssl pkey -in export-ec-edwards-ed448-key.pem -pubin -text > /dev/null
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
else
	echo "Skip exporting ec-edwards keys, OpenSSL version not supporting it or token does not support it"
fi
# ec-montgomery
if [[ -n $(openssl version | grep "OpenSSL 3.") && -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_EC_MONTGOMERY_KEY_PAIR_GEN) ]]; then
	if [[ -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: EP11") || -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: CCA") ]]; then
		${P11SAK} export-key ec-montgomery --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-montgomery-x25519-public" --file export-ec-montgomery-x25519-key.pem --force
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		${P11SAK} export-key ec-montgomery --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-montgomery-x25519-private" --file export-ec-montgomery-x25519-key.opaque --force --opaque
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		${P11SAK} export-key ec-montgomery --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-montgomery-x448-public" --file export-ec-montgomery-x448-key.pem --force
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		${P11SAK} export-key ec-montgomery --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-montgomery-x448-private" --file export-ec-montgomery-x448-key.opaque --force --opaque
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	else
		${P11SAK} export-key ec-montgomery --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-montgomery-x25519-*" --file export-ec-montgomery-x25519-key.pem --force
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		openssl pkey -in export-ec-montgomery-x25519-key.pem -check -text > /dev/null
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		${P11SAK} export-key ec-montgomery --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-montgomery-x448-*" --file export-ec-montgomery-x448-key.pem --force
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		openssl pkey -in export-ec-montgomery-x448-key.pem -check -text > /dev/null
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	fi
	openssl pkey -in export-ec-montgomery-x25519-key.pem -pubin -text > /dev/null
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	openssl pkey -in export-ec-montgomery-x448-key.pem -pubin -text > /dev/null
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
else
	echo "Skip exporting ec-montgomery keys, OpenSSL version not supporting it or token does not support it"
fi
# ibm-dilithium
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_IBM_DILITHIUM) ]]; then
	if [[ -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: EP11") || -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: CCA") ]]; then
		${P11SAK} export-key ibm-dilithium --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ibm-dilithium-public" --file export-ibm-dilithium-key.pem --force
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		${P11SAK} export-key ibm-dilithium --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ibm-dilithium-private" --file export-ibm-dilithium-key.opaque --force --opaque
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		if [[ -n $(openssl list -providers | grep oqsprovider) && -n $(openssl list -key-managers | grep "dilithium3 @ oqsprovider") ]]; then
			${P11SAK} export-key ibm-dilithium --slot $SLOT --pin $PKCS11_USER_PIN --label "import-oqs-dilithium-public" --file export-oqs-dilithium-key.pem --oqsprovider-pem --force
			RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
			${P11SAK} export-key ibm-dilithium --slot $SLOT --pin $PKCS11_USER_PIN --label "import-oqs-dilithium-private" --file export-oqs-dilithium-key.opaque --force --opaque
			RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		else
			echo "Skip exporting oqs-dilithium keys, the oqsprovider is not available or does not support dilithium3"
		fi
	else
		${P11SAK} export-key ibm-dilithium --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ibm-dilithium-*" --file export-ibm-dilithium-key.pem --force
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		if [[ -n $(openssl list -providers | grep oqsprovider) && -n $(openssl list -key-managers | grep "dilithium3 @ oqsprovider") ]]; then
			${P11SAK} export-key ibm-dilithium --slot $SLOT --pin $PKCS11_USER_PIN --label "import-oqs-dilithium-*" --file export-oqs-dilithium-key.pem --oqsprovider-pem --force
			RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		else
			echo "Skip exporting oqs-dilithium keys, the oqsprovider is not available or does not support dilithium3"
		fi
	fi
else
	echo "Skip exporting ibm-dilithium keys, slot does not support CKM_IBM_DILITHIUM"
fi
# ibm-kyber
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_IBM_KYBER) ]]; then
	if [[ -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: EP11") || -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: CCA") ]]; then
		${P11SAK} export-key ibm-kyber --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ibm-kyber-public" --file export-ibm-kyber-key.pem --force
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		${P11SAK} export-key ibm-kyber --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ibm-kyber-private" --file export-ibm-kyber-key.opaque --force --opaque
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	else
		${P11SAK} export-key ibm-kyber --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ibm-kyber-*" --file export-ibm-kyber-key.pem --force
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	fi
else
	echo "Skip exporting ibm-kyber keys, slot does not support CKM_IBM_KYBER"
fi
# ibm-ml-dsa
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_IBM_ML_DSA) ]]; then
	if [[ -n $(openssl list -key-managers | grep -i "MLDSA65") ]]; then
		if [[ -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: EP11") || -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: CCA") ]]; then
			${P11SAK} export-key ibm-ml-dsa --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ml-dsa-public" --file export-ml-dsa-key.pem --force
			RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
			${P11SAK} export-key ibm-ml-dsa --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ml-dsa-private" --file export-ml-dsa-key.opaque --force --opaque
			RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		else
			${P11SAK} export-key ibm-ml-dsa --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ml-dsa-*" --file export-ml-dsa-key.pem --force
			RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		fi
	else
		echo "Skip exporting ml-dsa keys, neither OpeNSSL 3.5, nor the oqsprovider is available or does not support mldsa65"
	fi
else
	echo "Skip exporting ibm-ml-dsa keys, slot does not support CKM_IBM_ML_DSA"
fi
# ibm-ml-kem
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_IBM_ML_KEM) ]]; then
	if [[ -n $(openssl list -key-managers | grep -i "MLKEM1024") ]]; then
		if [[ -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: EP11") || -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: CCA") ]]; then
			${P11SAK} export-key ibm-ml-kem --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ml-kem-public" --file export-ml-kem-key.pem --force
			RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
			${P11SAK} export-key ibm-ml-kem --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ml-kem-private" --file export-ml-kem-key.opaque --force --opaque
			RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		else
			${P11SAK} export-key ibm-ml-kem --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ml-kem-*" --file export-mlkem-key.pem --force
			RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		fi
	else
		echo "Skip exporting ml-kem keys, neither OpenSSL 3.5, nor the oqsprovider is available or does not support mlkem1024"
	fi
else
	echo "Skip exporting ibm-ml-kem keys, slot does not support CKM_IBM_ML_KEM"
fi
# export to URI-PEM
p11sak export-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label "import-aes" --file export-uri-pem1.pem --force --uri-pem
RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
openssl asn1parse -i -in export-uri-pem1.pem  > /dev/null
RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
p11sak export-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label "import-aes" --file export-uri-pem2.pem --force --uri-pem --uri-pin-value
RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
openssl asn1parse -i -in export-uri-pem2.pem  > /dev/null
RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
p11sak export-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label "import-aes" --file export-uri-pem3.pem --force --uri-pem --uri-pin-source pin1.txt
RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
openssl asn1parse -i -in export-uri-pem3.pem  > /dev/null
RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
if [[ $(cat pin1.txt) != $PKCS11_USER_PIN ]]; then
	echo "Pin file does not contain the PKCS#11 user pin"
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + 1))
fi


echo "** Wrap/Unwrap tests - 'p11sak_test.sh'"
RC_P11SAK_WRAP=0
${P11SAK} generate-key RSA 2048 --slot $SLOT --pin $PKCS11_USER_PIN --id 123 --label "p11sak-keywrap-rsa-kek" --attr WU
RC_P11SAK_WRAP=$((RC_P11SAK_WRAP + $?))
${P11SAK} generate-key AES 256 --slot $SLOT --pin $PKCS11_USER_PIN --id 123 --label "p11sak-keywrap-aes-to-be-wrapped" --attr XS
RC_P11SAK_WRAP=$((RC_P11SAK_WRAP + $?))
if [[ -n $( ${PKCSCONF} -t -c $SLOT | grep "Model: CCA") && -n $( ${P11SAK} list-key AES --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-keywrap-aes-to-be-wrapped" --long | grep " CKA_IBM_CCA_AES_KEY_MODE: 1") ]]; then
	# CCA can only wrap AES-DATA keys with RSA-PKCS. For AES-CIPHER keys RSA-AESKW must be used.
	if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_RSA_AES_KEY_WRAP) ]]; then
		${P11SAK} wrap-key RSA-AESKW AES --aes-key-size 256 --hash-alg SHA-1 --mgf-alg SHA-1 --slot $SLOT --pin $PKCS11_USER_PIN --kek-label "p11sak-keywrap-rsa-kek:pub" --label "p11sak-keywrap-aes-to-be-wrapped" --file wrapped-key.pem --force
		RC_P11SAK_WRAP=$((RC_P11SAK_WRAP + $?))
		${P11SAK} unwrap-key --slot $SLOT --pin $PKCS11_USER_PIN --kek-label "p11sak-keywrap-rsa-kek:prv" --label "p11sak-keywrap-aes-unwrapped" --file wrapped-key.pem --force
		RC_P11SAK_WRAP=$((RC_P11SAK_WRAP + $?))
	else
		echo "Skip wrapping AES-CIPHER keys with CCA token, slot does not support CKM_RSA_AES_KEY_WRAP"
	fi
else
	${P11SAK} wrap-key RSA-PKCS AES --slot $SLOT --pin $PKCS11_USER_PIN --kek-label "p11sak-keywrap-rsa-kek:pub" --label "p11sak-keywrap-aes-to-be-wrapped" --file wrapped-key.pem --force
	RC_P11SAK_WRAP=$((RC_P11SAK_WRAP + $?))
	${P11SAK} unwrap-key --slot $SLOT --pin $PKCS11_USER_PIN --kek-label "p11sak-keywrap-rsa-kek:prv" --label "p11sak-keywrap-aes-unwrapped" --file wrapped-key.pem --force
	RC_P11SAK_WRAP=$((RC_P11SAK_WRAP + $?))
fi


echo "** Now remove keys - 'p11sak_test.sh'"

# remove objects
RC_P11SAK_REMOVE=0
# des
${P11SAK} remove-key des --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-des" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# 3des
${P11SAK} remove-key 3des --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-3des" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# generic
${P11SAK} remove-key generic --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-generic" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# aes [128 | 192 | 256 | copied]
${P11SAK} remove-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-128" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
${P11SAK} remove-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-192" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
${P11SAK} remove-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-256" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
${P11SAK} remove-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-copied" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# aes-xts [128 | 256]
${P11SAK} remove-key aes-xts --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-xts-128" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
${P11SAK} remove-key aes-xts --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-xts-256" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# rsa [1024 | 2048 | 4096]
# remove public key
${P11SAK} remove-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-1024:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
${P11SAK} remove-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-2048:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
${P11SAK} remove-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-4096:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# remove private key
${P11SAK} remove-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-1024:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
${P11SAK} remove-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-2048:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
${P11SAK} remove-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-4096:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# dh
# remove public key
${P11SAK} remove-key dh --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-dh:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# remove private key
${P11SAK} remove-key dh --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-dh:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# dsa 
# remove public key
${P11SAK} remove-key dsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-dsa:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# remove private key
${P11SAK} remove-key dsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-dsa:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# ec [prime256v1 | secp384r1 | secp521r1]
#remove public key
${P11SAK} remove-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-prime256v1:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
${P11SAK} remove-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-secp384r1:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
${P11SAK} remove-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-secp521r1:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# remove private key
${P11SAK} remove-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-prime256v1:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
${P11SAK} remove-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-secp384r1:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
${P11SAK} remove-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-secp521r1:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# ec-edwards [ed25519 | ed448]
#remove public key
${P11SAK} remove-key ec-edwards --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-edwards-ed25519:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
${P11SAK} remove-key ec-edwards --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-edwards-ed448:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# remove private key
${P11SAK} remove-key ec-edwards --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-edwards-ed25519:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
${P11SAK} remove-key ec-edwards --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-edwards-ed448:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# ec-montgomery [curve25519 | curve448]
#remove public key
${P11SAK} remove-key ec-montgomery --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-montgomery-x25519:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
${P11SAK} remove-key ec-montgomery --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-montgomery-x448:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# remove private key
${P11SAK} remove-key ec-montgomery --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-montgomery-x25519:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
${P11SAK} remove-key ec-montgomery --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-montgomery-x448:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# remove ibm-dilithium keys
${P11SAK} remove-key ibm-dilithium --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-dilithium:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
${P11SAK} remove-key ibm-dilithium --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-dilithium:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# remove ibm-kyber keys
${P11SAK} remove-key ibm-kyber --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-kyber:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
${P11SAK} remove-key ibm-kyber --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-kyber:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# remove ibm-ml-dsa keys
${P11SAK} remove-key ibm-ml-dsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-ml-dsa:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
${P11SAK} remove-key ibm-ml-dsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-ml-dsa:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# remove ibm-ml-kem keys
${P11SAK} remove-key ibm-ml-kem --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-ml-kem:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
${P11SAK} remove-key ibm-ml-kem --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-ml-kem:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# remove imported and extracted keys
${P11SAK} remove-key --slot $SLOT --pin $PKCS11_USER_PIN --label "import*" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
${P11SAK} remove-key --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-pubkey-extracted" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
${P11SAK} remove-key --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-keywrap*" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))


echo "** Now list keys and redirect to post-files - 'p11sak_test.sh'"

# list objects
RC_P11SAK_LIST_POST=0
${P11SAK} list-key des --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-des" &> $P11SAK_DES_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))
${P11SAK} list-key 3des --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-3des" &> $P11SAK_3DES_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))
${P11SAK} list-key generic --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-generic" &> $P11SAK_GENERIC_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))
${P11SAK} list-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-*" &> $P11SAK_AES_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))
${P11SAK} list-key aes-xts --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-xts-*" &> $P11SAK_AES_XTS_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))
${P11SAK} list-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-*" &> $P11SAK_RSA_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))
${P11SAK} list-key dh --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-dh*" &> $P11SAK_DH_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))
${P11SAK} list-key dsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-dsa*" &> $P11SAK_DSA_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))
${P11SAK} list-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-*" &> $P11SAK_EC_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))
${P11SAK} list-key ec-edwards --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-edwards-*" &> $P11SAK_EC_EDWARDS_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))
${P11SAK} list-key ec-montgomery --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-montgomery-*" &> $P11SAK_EC_MONTGOMERY_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))
${P11SAK} list-key ibm-dilithium --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-dilithium*" &> $P11SAK_IBM_DILITHIUM_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))
${P11SAK} list-key ibm-kyber --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-kyber*" &> $P11SAK_IBM_KYBER_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))
${P11SAK} list-key ibm-ml-dsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-ml-dsa*" &> $P11SAK_IBM_ML_DSA_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))
${P11SAK} list-key ibm-ml-kem --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-ml-kem*" &> $P11SAK_IBM_ML_KEM_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))


echo "** Now checking output files to determine PASS/FAIL of tests - 'p11sak_test.sh'"

if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_DES_KEY_GEN) ]]; then
	# check DES
	grep -q "p11sak-des" $P11SAK_DES_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE generate-key des PASS Generated random DES key"
	else
		echo "* TESTCASE generate-key des FAIL Failed to generate DES key"
		status=1
	fi
	grep -v -q "p11sak-des" $P11SAK_DES_POST
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

if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_DES_KEY_GEN) ]]; then
	# CK_BBOOL
	if [[ $(grep -c "CKA_ENCRYPT: CK_TRUE" $P11SAK_DES_LONG) == "1" ]]; then
		echo "* TESTCASE list-key des PASS Listed random des keys CK_BBOOL attribute"
	else
		echo "* TESTCASE list-key des FAIL Failed to list des keys CK_BBOOL attribute"
		status=1
	fi
	# CK_ULONG
	if [[ $(grep -c "CKA_MODULUS_BITS:" $P11SAK_DES_LONG) == "0" ]]; then
		echo "* TESTCASE list-key des PASS Listed random des keys CK_ULONG attribute"
	else
		echo "* TESTCASE list-key des FAIL Failed to list des keys CK_ULONG attribute"
		status=1
	fi
	# CK_BYTE
	if [[ $(grep -c "CKA_VALUE:" $P11SAK_DES_LONG) == "1" ]]; then
		echo "* TESTCASE list-key des PASS Listed random des keys CK_BYTE attribute"
	else
		echo "* TESTCASE list-key des FAIL Failed to list des keys CK_BYTE attribute"
		status=1
	fi
	# URI
	if [[ $(grep -c "URI: pkcs11:.*type=secret-key" $P11SAK_DES_LONG) == "1" ]]; then
		echo "* TESTCASE list-key des PASS list des key pkcs#11 URI"
	else
		echo "* TESTCASE list-key des FAIL list des key pkcs#11 URI"
		status=1
	fi
else
	echo "* TESTCASE list-key des SKIP Listed random des keys CK_BBOOL attribute"
	echo "* TESTCASE list-key des SKIP Listed random des keys CK_ULONG attribute"
	echo "* TESTCASE list-key des SKIP Listed random des keys CK_BYTE attribute"
	echo "* TESTCASE list-key des SKIP list des key pkcs#11 URI"
fi


# check 3DES
grep -q "p11sak-3des" $P11SAK_3DES_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key 3des PASS Generated random 3DES key"
else
	echo "* TESTCASE generate-key 3des FAIL Failed to generate 3DES key"
	status=1
fi
grep -v -q "p11sak-3des" $P11SAK_3DES_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key 3des PASS Deleted generated 3DES key"
else
	echo "* TESTCASE remove-key 3des FAIL Failed to delete generated 3DES key"
	status=1
fi


# CK_BBOOL
if [[ $(grep -c "CKA_ENCRYPT: CK_TRUE" $P11SAK_3DES_LONG) == "1" ]]; then
	echo "* TESTCASE list-key 3des PASS Listed random 3des keys CK_BBOOL attribute"
else
	echo "* TESTCASE list-key 3des FAIL Failed to list 3des keys CK_BBOOL attribute"
	status=1
fi
# CK_ULONG
if [[ $(grep -c "CKA_MODULUS_BITS:" $P11SAK_3DES_LONG) == "0" ]]; then
	echo "* TESTCASE list-key 3des PASS Listed random 3des keys CK_ULONG attribute"
else
	echo "* TESTCASE list-key 3des FAIL Failed to list 3des keys CK_ULONG attribute"
	status=1
fi
# CK_BYTE
if [[ $(grep -c "CKA_VALUE:" $P11SAK_3DES_LONG) == "1" ]]; then
	echo "* TESTCASE list-key 3des PASS Listed random 3des keys CK_BYTE attribute"
else
	echo "* TESTCASE list-key 3des FAIL Failed to list 3des keys CK_BYTE attribute"
	status=1
fi
# URI
if [[ $(grep -c "URI: pkcs11:.*type=secret-key" $P11SAK_3DES_LONG) == "1" ]]; then
	echo "* TESTCASE list-key 3des PASS list 3des key pkcs#11 URI"
else
	echo "* TESTCASE list-key 3des FAIL list 3des key pkcs#11 URI"
	status=1
fi


# check generic
grep -q "p11sak-generic" $P11SAK_GENERIC_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key generic PASS Generated random GENERIC key"
else
	echo "* TESTCASE generate-key generic FAIL Failed to generate GENERIC key"
	status=1
fi
grep -v -q "p11sak-generic" $P11SAK_GENERIC_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key generic PASS Deleted generated GENERIC key"
else
	echo "* TESTCASE remove-key generic FAIL Failed to delete generated GENERIC key"
	status=1
fi


# CK_BBOOL
if [[ $(grep -c "CKA_SIGN: CK_TRUE" $P11SAK_GENERIC_LONG) == "1" ]]; then
	echo "* TESTCASE list-key generic PASS Listed random generic keys CK_BBOOL attribute"
else
	echo "* TESTCASE list-key generic FAIL Failed to list generic keys CK_BBOOL attribute"
	status=1
fi
# CK_ULONG
if [[ $(grep -c "CKA_MODULUS_BITS:" $P11SAK_GENERIC_LONG) == "0" ]]; then
	echo "* TESTCASE list-key generic PASS Listed random generic keys CK_ULONG attribute"
else
	echo "* TESTCASE list-key generic FAIL Failed to list generic keys CK_ULONG attribute"
	status=1
fi
# CK_BYTE
if [[ $(grep -c "CKA_VALUE:" $P11SAK_GENERIC_LONG) == "1" ]]; then
	echo "* TESTCASE list-key generic PASS Listed random generic keys CK_BYTE attribute"
else
	echo "* TESTCASE list-key generic FAIL Failed to list generic keys CK_BYTE attribute"
	status=1
fi
# URI
if [[ $(grep -c "URI: pkcs11:.*type=secret-key" $P11SAK_GENERIC_LONG) == "1" ]]; then
	echo "* TESTCASE list-key generic PASS list generic key pkcs#11 URI"
else
	echo "* TESTCASE list-key generic FAIL list generic key pkcs#11 URI"
	status=1
fi


# check AES 128
grep -q "p11sak-aes-128" $P11SAK_AES_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key aes-128 PASS Generated random AES 128 key"
else
	echo "* TESTCASE generate-key aes-128 FAIL Failed to generate AES 128 key"
	status=1
fi
grep -v -q "p11sak-aes-128" $P11SAK_AES_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key aes-128 PASS Deleted generated AES 128 key"
else
	echo "* TESTCASE remove-key aes-128 FAIL Failed to delete generated AES 128 key"
	status=1
fi


# check AES 192
grep -q "p11sak-aes-192" $P11SAK_AES_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key aes-192 PASS Generated random AES 192 key"
else
	echo "* TESTCASE generate-key aes-192 FAIL Failed to generate AES 192 key"
	status=1
fi
grep -v -q "p11sak-aes-192" $P11SAK_AES_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key aes-192 PASS Deleted generated AES 192 key"
else
	echo "* TESTCASE remove-key aes-192 FAIL Failed to delete generated AES 192 key"
	status=1
fi


# check AES 256
grep -q "p11sak-aes-256" $P11SAK_AES_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key aes-256 PASS Generated random AES 256 key"
else
	echo "* TESTCASE generate-key aes-256 FAIL Failed to generate AES 256 key"
	status=1
fi
grep -v -q "p11sak-aes-256" $P11SAK_AES_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key aes-256 PASS Deleted generated AES 256 key"
else
	echo "* TESTCASE remove-key aes-256 FAIL Failed to delete generated AES 256 key"
	status=1
fi


# CK_BBOOL
if [[ $(grep -c "CKA_ENCRYPT: CK_TRUE" $P11SAK_AES_LONG) == "3" ]]; then
	echo "* TESTCASE list-key aes PASS Listed random aes keys CK_BBOOL attribute"
else
	echo "* TESTCASE list-key aes FAIL Failed to list aes keys CK_BBOOL attribute"
	status=1
fi
# CK_ULONG
if [[ $(grep -c "CKA_VALUE_LEN:" $P11SAK_AES_LONG) == "3" ]]; then
	echo "* TESTCASE list-key aes PASS Listed random aes keys CK_ULONG attribute"
else
	echo "* TESTCASE list-key aes FAIL Failed to list aes keys CK_ULONG attribute"
	status=1
fi
# CK_BYTE
if [[ $(grep -c "CKA_VALUE:" $P11SAK_AES_LONG) == "3" ]]; then
	echo "* TESTCASE list-key aes PASS Listed random aes keys CK_BYTE attribute"
else
	echo "* TESTCASE list-key aes FAIL Failed to list aes keys CK_BYTE attribute"
	status=1
fi
# URI
if [[ $(grep -c "URI: pkcs11:.*type=secret-key" $P11SAK_AES_LONG) == "3" ]]; then
	echo "* TESTCASE list-key aes PASS list aes key pkcs#11 URI"
else
	echo "* TESTCASE list-key aes FAIL list aes key pkcs#11 URI"
	status=1
fi

if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_AES_XTS_KEY_GEN) ]]; then
	# check AES-XTS 128
	grep -q "p11sak-aes-xts-128" $P11SAK_AES_XTS_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE generate-key aes-xts-128 PASS Generated random AES-XTS 128 key"
	else
		echo "* TESTCASE generate-key aes-xts-128 FAIL Failed to generate AES-XTS 128 key"
		status=1
	fi
	grep -v -q "p11sak-aes-xts-128" $P11SAK_AES_XTS_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-key aes-xts-128 PASS Deleted generated AES-XTS 128 key"
	else
		echo "* TESTCASE remove-key aes-xts-128 FAIL Failed to delete generated AES-XTS 128 key"
		status=1
	fi

	# check AES-XTS 256
	grep -q "p11sak-aes-xts-256" $P11SAK_AES_XTS_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE generate-key aes-xts-256 PASS Generated random AES-XTS 256 key"
	else
		echo "* TESTCASE generate-key aes-xts-256 FAIL Failed to generate AES-XTS 256 key"
		status=1
	fi
	grep -v -q "p11sak-aes-xts-256" $P11SAK_AES_XTS_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-key aes-xts-256 PASS Deleted generated AES-XTS 256 key"
	else
		echo "* TESTCASE remove-key aes-xts-256 FAIL Failed to delete generated AES-XTS 256 key"
		status=1
	fi
	
	# CK_BBOOL
	if [[ $(grep -c "CKA_ENCRYPT: CK_TRUE" $P11SAK_AES_XTS_LONG) == "2" ]]; then
		echo "* TESTCASE list-key aes-xts PASS Listed random aes-xts keys CK_BBOOL attribute"
	else
		echo "* TESTCASE list-key aes-xts FAIL Failed to list aes-xts keys CK_BBOOL attribute"
		status=1
	fi
	# CK_ULONG
	if [[ $(grep -c "CKA_VALUE_LEN:" $P11SAK_AES_XTS_LONG) == "2" ]]; then
		echo "* TESTCASE list-key aes-xts PASS Listed random aes-xts keys CK_ULONG attribute"
	else
		echo "* TESTCASE list-key aes-xts FAIL Failed to list aes-xts keys CK_ULONG attribute"
		status=1
	fi
	# CK_BYTE
	if [[ $(grep -c "CKA_VALUE:" $P11SAK_AES_XTS_LONG) == "2" ]]; then
		echo "* TESTCASE list-key aes-xts PASS Listed random aes-xts keys CK_BYTE attribute"
	else
		echo "* TESTCASE list-key aes-xts FAIL Failed to list aes-xts keys CK_BYTE attribute"
		status=1
	fi
	# URI
	if [[ $(grep -c "URI: pkcs11:.*type=secret-key" $P11SAK_AES_XTS_LONG) == "2" ]]; then
		echo "* TESTCASE list-key aes-xts PASS list aes-xts key pkcs#11 URI"
	else
		echo "* TESTCASE list-key aes-xts FAIL list aes-xts key pkcs#11 URI"
		status=1
	fi
else
	echo "* TESTCASE generate-key aes-xts-128 SKIP Generated random AES-XTS 128 key"
	echo "* TESTCASE remove-key aes-xts-128 SKIP Deleted generated AES-XTS 128 key"
	echo "* TESTCASE generate-key aes-xts-256 SKIP Generated random AES-XTS 256 key"
	echo "* TESTCASE remove-key aes-xts-256 SKIP Deleted generated AES-XTS 256 key"
	echo "* TESTCASE list-key aes-xts SKIP Listed random aes-xts keys CK_BBOOL attribute"
	echo "* TESTCASE list-key aes-xts SKIP Listed random aes-xts keys CK_ULONG attribute"
	echo "* TESTCASE list-key aes-xts SKIP Listed random aes-xts keys CK_BYTE attribute"
	echo "* TESTCASE list-key aes-xts SKIP list aes-xts key pkcs#11 URI"
fi

# check RSA 1024 public key
grep -q "p11sak-rsa-1024:pub" $P11SAK_RSA_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key rsa 1024 PASS Generated random rsa 1024 public key"
else
	echo "* TESTCASE generate-key rsa 1024 FAIL Failed to generate rsa 1024 public key"
	status=1
fi
grep -v -q "p11sak-rsa-1024:pub" $P11SAK_RSA_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key rsa PASS Deleted generated rsa 1024 public key"
else
	echo "* TESTCASE remove-key rsa FAIL Failed to delete generated rsa 1024 public key"
	status=1
fi


# check RSA 2048 public key
grep -q "p11sak-rsa-2048:pub" $P11SAK_RSA_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key rsa 2048 PASS Generated random rsa 2048 public key"
else
	echo "* TESTCASE generate-key rsa 2048 FAIL Failed to generate rsa 2048 public key"
	status=1
fi
grep -v -q "p11sak-rsa-2048:pub" $P11SAK_RSA_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key rsa PASS Deleted generated rsa 2048 public key"
else
	echo "* TESTCASE remove-key rsa FAIL Failed to delete generated rsa 2048 public key"
	status=1
fi


# check RSA 4096 public key
grep -q "p11sak-rsa-4096:pub" $P11SAK_RSA_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key rsa 4096 PASS Generated random rsa 4096 public key"
else
	echo "* TESTCASE generate-key rsa 4096 FAIL Failed to generate rsa 4096 public key"
	status=1
fi
grep -v -q "p11sak-rsa-4096:pub" $P11SAK_RSA_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key rsa PASS Deleted generated rsa 4096 public key"
else
	echo "* TESTCASE remove-key rsa FAIL Failed to delete generated rsa 4096 public key"
	status=1
fi


# check RSA 1024 private key
grep -q "p11sak-rsa-1024:prv" $P11SAK_RSA_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key rsa 1024 PASS Generated random rsa 1024 private key"
else
	echo "* TESTCASE generate-key rsa 1024 FAIL Failed to generate rsa 1024 private key"
	status=1
fi
grep -v -q "p11sak-rsa-1024:prv" $P11SAK_RSA_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key rsa PASS Deleted generated rsa 1024 private key"
else
	echo "* TESTCASE remove-key rsa FAIL Failed to delete generated rsa 1024 private key"
	status=1
fi


# check RSA 2048 private key
grep -q "p11sak-rsa-2048:prv" $P11SAK_RSA_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key rsa 2048 PASS Generated random rsa 2048 private key"
else
	echo "* TESTCASE generate-key rsa 2048 FAIL Failed to generate rsa 2048 private key"
	status=1
fi
grep -v -q "p11sak-rsa-2048:prv" $P11SAK_RSA_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key rsa PASS Deleted generated rsa 2048 private key"
else
	echo "* TESTCASE remove-key rsa FAIL Failed to delete generated rsa 2048 private key"
	status=1
fi


# check RSA 4096 private key
grep -q "p11sak-rsa-4096:prv" $P11SAK_RSA_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key rsa 4096 PASS Generated random rsa 4096 private key"
else
	echo "* TESTCASE generate-key rsa 4096 FAIL Failed to generate rsa 4096 private key"
	status=1
fi
grep -v -q "p11sak-rsa-4096:prv" $P11SAK_RSA_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key rsa PASS Deleted generated rsa 4096 private key"
else
	echo "* TESTCASE remove-key rsa FAIL Failed to delete generated rsa 4096 private key"
	status=1
fi


# CK_BBOOL
if [[ $(grep -c "CKA_MODIFIABLE: CK_TRUE" $P11SAK_RSA_LONG) == "6" ]]; then
	echo "* TESTCASE list-key rsa PASS Listed random rsa keys CK_BBOOL attribute"
else
	echo "* TESTCASE list-key rsa FAIL Failed to list rsa keys CK_BBOOL attribute"
	status=1
fi
# CK_ULONG
if [[ $(grep -c "CKA_MODULUS_BITS:" $P11SAK_RSA_LONG) == "3" ]]; then
	echo "* TESTCASE list-key rsa PASS Listed random rsa keys CK_ULONG attribute"
else
	echo "* TESTCASE list-key rsa FAIL Failed to list rsa keys CK_ULONG attribute"
	status=1
fi
# CK_BYTE
if [[ $(grep -c "CKA_MODULUS:" $P11SAK_RSA_LONG) == "6" ]]; then
	echo "* TESTCASE list-key rsa PASS Listed random rsa keys CK_BYTE attribute"
else
	echo "* TESTCASE list-key rsa FAIL Failed to list rsa keys CK_BYTE attribute"
	status=1
fi
# URI
if [[ $(grep -c "URI: pkcs11:.*type=public" $P11SAK_RSA_LONG) == "3" ]]; then
	echo "* TESTCASE list-key rsa PASS list rsa public key pkcs#11 URI"
else
	echo "* TESTCASE list-key rsa FAIL list rsa public key pkcs#11 URI"
	status=1
fi

if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_DH_PKCS_KEY_PAIR_GEN) ]]; then
	# check DH public key
	grep -q "p11sak-dh:pub" $P11SAK_DH_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE generate-key dh PASS Generated random dh public key"
	else
		echo "* TESTCASE generate-key dh FAIL Failed to generate dh public key"
		status=1
	fi
	grep -v -q "p11sak-dh:pub" $P11SAK_DH_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-key dh PASS Deleted generated dh public key"
	else
		echo "* TESTCASE remove-key dh FAIL Failed to delete generated dh public key"
		status=1
	fi
	
	# check DH private key
	grep -q "p11sak-dh:prv" $P11SAK_DH_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE generate-key dh PASS Generated random dh private key"
	else
		echo "* TESTCASE generate-key dh FAIL Failed to generate dh private key"
		status=1
	fi
	grep -v -q "p11sak-dh:prv" $P11SAK_DH_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-key dh PASS Deleted generated dh private key"
	else
		echo "* TESTCASE remove-key dh FAIL Failed to delete generated dh private key"
		status=1
	fi
	
	
	# CK_BBOOL
	if [[ $(grep -c "CKA_MODIFIABLE: CK_TRUE" $P11SAK_DH_LONG) == "2" ]]; then
		echo "* TESTCASE list-key dh PASS Listed random dh keys CK_BBOOL attribute"
	else
		echo "* TESTCASE list-key dh FAIL Failed to list dh keys CK_BBOOL attribute"
		status=1
	fi
	# CK_ULONG
	if [[ $(grep -c "CKA_VALUE_BITS:" $P11SAK_DH_LONG) == "1" ]]; then
		echo "* TESTCASE list-key dh PASS Listed random dh keys CK_ULONG attribute"
	else
		echo "* TESTCASE list-key dh FAIL Failed to list dh keys CK_ULONG attribute"
		status=1
	fi
	# CK_BYTE
	if [[ $(grep -c "CKA_PRIME:" $P11SAK_DH_LONG) == "2" ]]; then
		echo "* TESTCASE list-key dh PASS Listed random dh keys CK_BYTE attribute"
	else
		echo "* TESTCASE list-key dh FAIL Failed to list dh keys CK_BYTE attribute"
		status=1
	fi
	# URI
	if [[ $(grep -c "URI: pkcs11:.*type=public" $P11SAK_DH_LONG) == "1" ]]; then
		echo "* TESTCASE list-key dh PASS list dh public key pkcs#11 URI"
	else
		echo "* TESTCASE list-key dh FAIL list dh public key pkcs#11 URI"
		status=1
	fi
else
	echo "* TESTCASE generate-key dh SKIP generate dh public key"
	echo "* TESTCASE remove-key dh SKIP delete generated dh public key"
	echo "* TESTCASE generate-key dh SKIP generate dh private key"
	echo "* TESTCASE remove-key dh SKIP delete generated dh private key"
	echo "* TESTCASE list-key dh SKIP list dh keys CK_BBOOL attribute"
	echo "* TESTCASE list-key dh SKIP list dh keys CK_ULONG attribute"
	echo "* TESTCASE list-key dh SKIP list dh keys CK_BYTE attribute"
	echo "* TESTCASE list-key dh SKIP list dh public key pkcs#11 URI"
fi


if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_DSA_KEY_PAIR_GEN) ]]; then
	# check DSA public key
	grep -q "p11sak-dsa:pub" $P11SAK_DSA_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE generate-key dsa PASS Generated random dsa public key"
	else
		echo "* TESTCASE generate-key dsa FAIL Failed to generate dsa public key"
		status=1
	fi
	grep -v -q "p11sak-dsa:pub" $P11SAK_DSA_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-key dsa PASS Deleted generated dsa public key"
	else
		echo "* TESTCASE remove-key dsa FAIL Failed to delete generated dsa public key"
		status=1
	fi
	
	# check DSA private key
	grep -q "p11sak-dsa:prv" $P11SAK_DSA_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE generate-key dsa PASS Generated random dsa private key"
	else
		echo "* TESTCASE generate-key dsa FAIL Failed to generate dsa private key"
		status=1
	fi
	grep -v -q "p11sak-dsa:prv" $P11SAK_DSA_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-key dsa PASS Deleted generated dsa private key"
	else
		echo "* TESTCASE remove-key dsa FAIL Failed to delete generated dsa private key"
		status=1
	fi
	
	
	# CK_BBOOL
	if [[ $(grep -c "CKA_MODIFIABLE: CK_TRUE" $P11SAK_DSA_LONG) == "2" ]]; then
		echo "* TESTCASE list-key dsa PASS Listed random dsa keys CK_BBOOL attribute"
	else
		echo "* TESTCASE list-key dsa FAIL Failed to list dsa keys CK_BBOOL attribute"
		status=1
	fi
	# CK_ULONG
	if [[ $(grep -c "CKA_VALUE_BITS:" $P11SAK_DSA_LONG) == "0" ]]; then
		echo "* TESTCASE list-key dsa PASS Listed random dsa keys CK_ULONG attribute"
	else
		echo "* TESTCASE list-key dsa FAIL Failed to list dsa keys CK_ULONG attribute"
		status=1
	fi
	# CK_BYTE
	if [[ $(grep -c "CKA_PRIME:" $P11SAK_DSA_LONG) == "2" ]]; then
		echo "* TESTCASE list-key dsa PASS Listed random dsa keys CK_BYTE attribute"
	else
		echo "* TESTCASE list-key dsa FAIL Failed to list dsa keys CK_BYTE attribute"
		status=1
	fi
	# URI
	if [[ $(grep -c "URI: pkcs11:.*type=public" $P11SAK_DSA_LONG) == "1" ]]; then
		echo "* TESTCASE list-key dsa PASS list dsa public key pkcs#11 URI"
	else
		echo "* TESTCASE list-key dsa FAIL list dsa public key pkcs#11 URI"
		status=1
	fi
else
	echo "* TESTCASE generate-key dsa SKIP generate dsa public key"
	echo "* TESTCASE remove-key dsa SKIP delete generated dsa public key"
	echo "* TESTCASE generate-key dsa SKIP generate dsa private key"
	echo "* TESTCASE remove-key dsa SKIP delete generated dsa private key"
	echo "* TESTCASE list-key dsa SKIP list dsa keys CK_BBOOL attribute"
	echo "* TESTCASE list-key dsa SKIP list dsa keys CK_ULONG attribute"
	echo "* TESTCASE list-key dsa SKIP list dsa keys CK_BYTE attribute"
	echo "* TESTCASE list-key dsa SKIP list dsa public key pkcs#11 URI"
fi

# check EC prime256v1 public key
grep -q "p11sak-ec-prime256v1:pub" $P11SAK_EC_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key ec prime256v1 PASS Generated random ec prime256v1 public key"
else
	echo "* TESTCASE generate-key ec prime256v1 FAIL Failed to generate ec prime256v1 public key"
	status=1
fi
grep -v -q "p11sak-ec-prime256v1:pub" $P11SAK_EC_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key ec prime256v1 PASS Deleted generated ec prime256v1 public key"
else
	echo "* TESTCASE remove-key ec prime256v1 FAIL Failed to delete generated ec prime256v1 public key"
	status=1
fi


# check EC secp384r1 public key
grep -q "p11sak-ec-secp384r1:pub" $P11SAK_EC_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key ec secp384r1 PASS Generated random ec secp384r1 public key"
else
	echo "* TESTCASE generate-key ec secp384r1 FAIL Failed to generate ec secp384r1 public key"
	status=1
fi
grep -v -q "p11sak-ec-secp384r1:pub" $P11SAK_EC_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key ec secp384r1 PASS Deleted generated ec secp384r1 public key"
else
	echo "* TESTCASE remove-key ec secp384r1 FAIL Failed to delete generated ec secp384r1 public key"
	status=1
fi


# check EC secp521r1 public key
grep -q "p11sak-ec-secp521r1:pub" $P11SAK_EC_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key ec secp521r1 PASS Generated random ec secp521r1 public key"
else
	echo "* TESTCASE generate-key ec secp521r1 FAIL Failed to generate ec secp521r1 public key"
	status=1
fi
grep -v -q "p11sak-ec-secp521r1:pub" $P11SAK_EC_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key ec secp521r1 PASS Deleted generated ec secp521r1 public key"
else
	echo "* TESTCASE remove-key ec secp521r1 FAIL Failed to delete generated ec secp521r1 public key"
	status=1
fi


# check EC prime256v1 private key
grep -q "p11sak-ec-prime256v1:prv" $P11SAK_EC_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key ec prime256v1 PASS Generated random ec prime256v1 private key"
else
	echo "* TESTCASE generate-key ec prime256v1 FAIL Failed to generate ec prime256v1 private key"
	status=1
fi
grep -v -q "p11sak-ec-prime256v1:prv" $P11SAK_EC_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key ec prime256v1 PASS Deleted generated ec prime256v1 private key"
else
	echo "* TESTCASE remove-key ec prime256v1 FAIL Failed to delete generated ec prime256v1 private key"
	status=1
fi


# check EC secp384r1 private key
grep -q "p11sak-ec-secp384r1:prv" $P11SAK_EC_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key ec secp384r1 PASS Generated random ec secp384r1 private key"
else
	echo "* TESTCASE generate-key ec secp384r1 FAIL Failed to generate ec secp384r1 private key"
	status=1
fi
grep -v -q "p11sak-ec-secp384r1:prv" $P11SAK_EC_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key ec secp384r1 PASS Deleted generated ec secp384r1 private key"
else
	echo "* TESTCASE remove-key ec secp384r1 FAIL Failed to delete generated ec secp384r1 private key"
	status=1
fi


# check EC secp521r1 private key
grep -q "p11sak-ec-secp521r1:prv" $P11SAK_EC_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE generate-key ec secp521r1 PASS Generated random ec secp521r1 private key"
else
	echo "* TESTCASE generate-key ec secp521r1 FAIL Failed to generate ec secp521r1 private key"
	status=1
fi
grep -v -q "p11sak-ec-secp521r1:prv" $P11SAK_EC_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-key ec secp521r1 PASS Deleted generated ec secp521r1 private key"
else
	echo "* TESTCASE remove-key ec secp521r1 FAIL Failed to delete generated ec secp521r1 private key"
	status=1
fi


# CK_BBOOL
if [[ $(grep -c "CKA_MODIFIABLE: CK_TRUE" $P11SAK_EC_LONG) == "6" ]]; then
	echo "* TESTCASE list-key ec PASS Listed random ec keys CK_BBOOL attribute"
else
	echo "* TESTCASE list-key ec FAIL Failed to list ec keys CK_BBOOL attribute"
	status=1
fi
# CK_ULONG
if [[ $(grep -c "CKA_MODULUS_BITS:" $P11SAK_EC_LONG) == "0" ]]; then
	echo "* TESTCASE list-key ec PASS Listed random ec keys CK_ULONG attribute"
else
	echo "* TESTCASE list-key ec FAIL Failed to list ec keys CK_ULONG attribute"
	status=1
fi
# CK_BYTE
if [[ $(grep -c "CKA_EC_POINT:" $P11SAK_EC_LONG) == "3" ]]; then
	echo "* TESTCASE list-key ec PASS Listed random ec keys CK_BYTE attribute"
else
	echo "* TESTCASE list-key ec FAIL Failed to list ec keys CK_BYTE attribute"
	status=1
fi
# URI
if [[ $(grep -c "URI: pkcs11:.*type=public" $P11SAK_EC_LONG) == "3" ]]; then
	echo "* TESTCASE list-key ec PASS list ec public key pkcs#11 URI"
else
	echo "* TESTCASE list-key ec FAIL list ec public key pkcs#11 URI"
	status=1
fi
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_EC_EDWARDS_KEY_PAIR_GEN) ]]; then
	# check ec-edwards ed25519 public key
	grep -q "p11sak-ec-edwards-ed25519:pub" $P11SAK_EC_EDWARDS_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE generate-key ec-edwards ed25519 PASS Generated random ec-edwards ed25519 public key"
	else
		echo "* TESTCASE generate-key ec-edwards ed25519 FAIL Failed to generate ec-edwards ed25519 public key"
		status=1
	fi
	grep -v -q "p11sak-ec-edwards-ed25519:pub" $P11SAK_EC_EDWARDS_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-key ec-edwards ed25519 PASS Delete generated ec-edwards ed25519 public key"
	else
		echo "* TESTCASE remove-key ec-edwards ed25519 FAIL Failed to delete generated ec-edwards ed25519 public key"
		status=1
	fi

	# check ec-edwards ed448 public key
	grep -q "p11sak-ec-edwards-ed448:pub" $P11SAK_EC_EDWARDS_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE generate-key ec-edwards ed448 PASS Generated random ec-edwards ed448 public key"
	else
		echo "* TESTCASE generate-key ec-edwards ed448 FAIL Failed to generate ec-edwards ed448 public key"
		status=1
	fi
	grep -v -q "p11sak-ec-edwards-ed448:pub" $P11SAK_EC_EDWARDS_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-key ec-edwards ed448 PASS Delete generated ec-edwards ed448 public key"
	else
		echo "* TESTCASE remove-key ec-edwards ed448 FAIL Failed to delete generated ec-edwards ed448 public key"
		status=1
	fi

	# check ec-edwards ed25519 private key
	grep -q "p11sak-ec-edwards-ed25519:prv" $P11SAK_EC_EDWARDS_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE generate-key ec-edwards ed25519 PASS Generated random ec-edwards ed25519 private key"
	else
		echo "* TESTCASE generate-key ec-edwards ed25519 FAIL Failed to generate ec-edwards ed25519 private key"
		status=1
	fi
	grep -v -q "p11sak-ec-edwards-ed25519:prv" $P11SAK_EC_EDWARDS_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-key ec-edwards ed25519 PASS Delete generated ec-edwards ed25519 private key"
	else
		echo "* TESTCASE remove-key ec-edwards ed25519 FAIL Failed to delete generated ec-edwards ed25519 private key"
		status=1
	fi

	# check ec-edwards ed448 private key
	grep -q "p11sak-ec-edwards-ed448:prv" $P11SAK_EC_EDWARDS_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE generate-key ec-edwards ed448 PASS Generated random ec-edwards ed448 private key"
	else
		echo "* TESTCASE generate-key ec-edwards ed448 FAIL Failed to generate ec-edwards ed448 private key"
		status=1
	fi
	grep -v -q "p11sak-ec-edwards-ed448:prv" $P11SAK_EC_EDWARDS_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-key ec-edwards ed448 PASS Delete generated ec-edwards ed448 private key"
	else
		echo "* TESTCASE remove-key ec-edwards ed448 FAIL Failed to delete generated ec-edwards ed448 private key"
		status=1
	fi

	# CK_BBOOL
	if [[ $(grep -c "CKA_MODIFIABLE: CK_TRUE" $P11SAK_EC_EDWARDS_LONG) == "4" ]]; then
		echo "* TESTCASE list-key ec-edwards PASS Listed random ec-edwards keys CK_BBOOL attribute"
	else
		echo "* TESTCASE list-key ec-edwards FAIL Failed to list ec-edwards keys CK_BBOOL attribute"
		status=1
	fi
	# CK_ULONG
	if [[ $(grep -c "CKA_MODULUS_BITS:" $P11SAK_EC_EDWARDS_LONG) == "0" ]]; then
		echo "* TESTCASE list-key ec-edwards PASS Listed random ec-edwards keys CK_ULONG attribute"
	else
		echo "* TESTCASE list-key ec-edwards FAIL Failed to list ec-edwards keys CK_ULONG attribute"
		status=1
	fi
	# CK_BYTE
	if [[ $(grep -c "CKA_EC_POINT:" $P11SAK_EC_EDWARDS_LONG) == "2" ]]; then
		echo "* TESTCASE list-key ec-edwards PASS Listed random ec-edwards keys CK_BYTE attribute"
	else
		echo "* TESTCASE list-key ec-edwards FAIL Failed to list ec-edwards keys CK_BYTE attribute"
		status=1
	fi
	# URI
	if [[ $(grep -c "URI: pkcs11:.*type=public" $P11SAK_EC_EDWARDS_LONG) == "2" ]]; then
		echo "* TESTCASE list-key ec-edwards PASS list ec-edwards public key pkcs#11 URI"
	else
		echo "* TESTCASE list-key ec-edwards FAIL list ec-edwards public key pkcs#11 URI"
		status=1
	fi
else
	echo "* TESTCASE generate-key ec-edwards ed25519 SKIP Generated random ec-edwards ed25519 public key"
	echo "* TESTCASE remove-key ec-edwards ed25519 SKIP Delete generated ec-edwards ed25519 public key"
	echo "* TESTCASE generate-key ec-edwards ed448 SKIP Generated random ec-edwards ed448 public key"
	echo "* TESTCASE remove-key ec-edwards ed448 SKIP Delete generated ec-edwards ed448 public key"
	echo "* TESTCASE generate-key ec-edwards ed25519 SKIP Generated random ec-edwards ed25519 private key"
	echo "* TESTCASE remove-key ec-edwards ed25519 SKIP Delete generated ec-edwards ed25519 private key"
	echo "* TESTCASE generate-key ec-edwards ed448 SKIP Generated random ec-edwards ed448 private key"
	echo "* TESTCASE remove-key ec-edwards ed448 SKIP Delete generated ec-edwards ed448 private key"
	echo "* TESTCASE list-key ec-edwards SKIP Listed random ec-edwards keys CK_BBOOL attribute"
	echo "* TESTCASE list-key ec-edwards SKIP Listed random ec-edwards keys CK_ULONG attribute"
	echo "* TESTCASE list-key ec-edwards SKIP Listed random ec-edwards keys CK_BYTE attribute"
	echo "* TESTCASE list-key ec-edwards SKIP Listed random ec-edwards public key pkcs#11 URI"
fi
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_EC_MONTGOMERY_KEY_PAIR_GEN) ]]; then
	# check ec-montgomery x25519 public key
	grep -q "p11sak-ec-montgomery-x25519:pub" $P11SAK_EC_MONTGOMERY_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE generate-key ec-montgomery x25519 PASS Generated random ec-montgomery x25519 public key"
	else
		echo "* TESTCASE generate-key ec-montgomery x25519 FAIL Failed to generate ec-montgomery x25519 public key"
		status=1
	fi
	grep -v -q "p11sak-ec-montgomery-x25519:pub" $P11SAK_EC_MONTGOMERY_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-key ec-montgomery x25519 PASS Delete generated ec-montgomery x25519 public key"
	else
		echo "* TESTCASE remove-key ec-montgomery x25519 FAIL Failed to delete generated ec-montgomery x25519 public key"
		status=1
	fi

	# check ec-montgomery x448 public key
	grep -q "p11sak-ec-montgomery-x448:pub" $P11SAK_EC_MONTGOMERY_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE generate-key ec-montgomery x448 PASS Generated random ec-montgomery x448 public key"
	else
		echo "* TESTCASE generate-key ec-montgomery x448 FAIL Failed to generate ec-montgomery x448 public key"
		status=1
	fi
	grep -v -q "p11sak-ec-montgomery-x448:pub" $P11SAK_EC_MONTGOMERY_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-key ec-montgomery x448 PASS Delete generated ec-montgomery x448 public key"
	else
		echo "* TESTCASE remove-key ec-montgomery x448 FAIL Failed to delete generated ec-montgomery x448 public key"
		status=1
	fi

	# check ec-montgomery x25519 private key
	grep -q "p11sak-ec-montgomery-x25519:prv" $P11SAK_EC_MONTGOMERY_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE generate-key ec-montgomery x25519 PASS Generated random ec-montgomery x25519 private key"
	else
		echo "* TESTCASE generate-key ec-montgomery x25519 FAIL Failed to generate ec-montgomery x25519 private key"
		status=1
	fi
	grep -v -q "p11sak-ec-montgomery-x25519:prv" $P11SAK_EC_MONTGOMERY_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-key ec-montgomery x25519 PASS Delete generated ec-montgomery x25519 private key"
	else
		echo "* TESTCASE remove-key ec-montgomery x25519 FAIL Failed to delete generated ec-montgomery x25519 private key"
		status=1
	fi

	# check ec-montgomery x448 private key
	grep -q "p11sak-ec-montgomery-x448:prv" $P11SAK_EC_MONTGOMERY_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE generate-key ec-montgomery x448 PASS Generated random ec-montgomery x448 private key"
	else
		echo "* TESTCASE generate-key ec-montgomery x448 FAIL Failed to generate ec-montgomery x448 private key"
		status=1
	fi
	grep -v -q "p11sak-ec-montgomery-x448:prv" $P11SAK_EC_MONTGOMERY_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-key ec-montgomery x448 PASS Delete generated ec-montgomery x448 private key"
	else
		echo "* TESTCASE remove-key ec-montgomery x448 FAIL Failed to delete generated ec-montgomery x448 private key"
		status=1
	fi

	# CK_BBOOL
	if [[ $(grep -c "CKA_MODIFIABLE: CK_TRUE" $P11SAK_EC_MONTGOMERY_LONG) == "4" ]]; then
		echo "* TESTCASE list-key ec-montgomery PASS Listed random ec-montgomery keys CK_BBOOL attribute"
	else
		echo "* TESTCASE list-key ec-montgomery FAIL Failed to list ec-montgomery keys CK_BBOOL attribute"
		status=1
	fi
	# CK_ULONG
	if [[ $(grep -c "CKA_MODULUS_BITS:" $P11SAK_EC_MONTGOMERY_LONG) == "0" ]]; then
		echo "* TESTCASE list-key ec-montgomery PASS Listed random ec-montgomery keys CK_ULONG attribute"
	else
		echo "* TESTCASE list-key ec-montgomery FAIL Failed to list ec-montgomery keys CK_ULONG attribute"
		status=1
	fi
	# CK_BYTE
	if [[ $(grep -c "CKA_EC_POINT:" $P11SAK_EC_MONTGOMERY_LONG) == "2" ]]; then
		echo "* TESTCASE list-key ec-montgomery PASS Listed random ec-montgomery keys CK_BYTE attribute"
	else
		echo "* TESTCASE list-key ec-montgomery FAIL Failed to list ec-montgomery keys CK_BYTE attribute"
		status=1
	fi
	# URI
	if [[ $(grep -c "URI: pkcs11:.*type=public" $P11SAK_EC_MONTGOMERY_LONG) == "2" ]]; then
		echo "* TESTCASE list-key ec-montgomery PASS list ec-montgomery public key pkcs#11 URI"
	else
		echo "* TESTCASE list-key ec-montgomery FAIL list ec-montgomery public key pkcs#11 URI"
		status=1
	fi
else
	echo "* TESTCASE generate-key ec-montgomery x25519 SKIP Generated random ec-montgomery x25519 public key"
	echo "* TESTCASE remove-key ec-montgomery x25519 SKIP Delete generated ec-montgomery x25519 public key"
	echo "* TESTCASE generate-key ec-montgomery x448 SKIP Generated random ec-montgomery x448 public key"
	echo "* TESTCASE remove-key ec-montgomery x448 SKIP Delete generated ec-montgomery x448 public key"
	echo "* TESTCASE generate-key ec-montgomery x25519 SKIP Generated random ec-montgomery x25519 private key"
	echo "* TESTCASE remove-key ec-montgomery x25519 SKIP Delete generated ec-montgomery x25519 private key"
	echo "* TESTCASE generate-key ec-montgomery x448 SKIP Generated random ec-montgomery x448 private key"
	echo "* TESTCASE remove-key ec-montgomery x448 SKIP Delete generated ec-montgomery x448 private key"
	echo "* TESTCASE list-key ec-montgomery SKIP Listed random ec-montgomery keys CK_BBOOL attribute"
	echo "* TESTCASE list-key ec-montgomery SKIP Listed random ec-montgomery keys CK_ULONG attribute"
	echo "* TESTCASE list-key ec-montgomery SKIP Listed random ec-montgomery keys CK_BYTE attribute"
	echo "* TESTCASE list-key ec-montgomery SKIP Listed random ec-montgomery public key pkcs#11 URI"
fi
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_IBM_DILITHIUM) ]]; then
	# CK_BBOOL
	if [[ $(grep -c "CKA_MODIFIABLE: CK_TRUE" $P11SAK_IBM_DILITHIUM_LONG) == "2" ]]; then
		echo "* TESTCASE list-key ibm-dilithium PASS Listed random ibm-dilithium keys CK_BBOOL attribute"
	else
		echo "* TESTCASE list-key ibm-dilithium FAIL Failed to list ibm-dilithium keys CK_BBOOL attribute"
		status=1
	fi
	# CK_ULONG
	if [[ $(grep -c "CKA_IBM_DILITHIUM_KEYFORM:" $P11SAK_IBM_DILITHIUM_LONG) == "2" ]]; then
		echo "* TESTCASE list-key ibm-dilithium PASS Listed random ibm-dilithium keys CK_ULONG attribute"
	else
		echo "* TESTCASE list-key ibm-dilithium FAIL Failed to list ibm-dilithium keys CK_ULONG attribute"
		status=1
	fi
	# CK_BYTE
	if [[ $(grep -c "CKA_IBM_DILITHIUM_RHO:" $P11SAK_IBM_DILITHIUM_LONG) == "2" ]]; then
		echo "* TESTCASE list-key ibm-dilithium PASS Listed random ibm-dilithium keys CK_BYTE attribute"
	else
		echo "* TESTCASE list-key ibm-dilithium FAIL Failed to list ibm-dilithium keys CK_BYTE attribute"
		status=1
	fi
else
	echo "* TESTCASE list-key ibm-dilithium SKIP Listed random ibm-dilithium keys CK_BBOOL attribute"
	echo "* TESTCASE list-key ibm-dilithium SKIP Listed random ibm-dilithium keys CK_ULONG attribute"
	echo "* TESTCASE list-key ibm-dilithium SKIP Listed random ibm-dilithium keys CK_BYTE attribute"
fi


if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_IBM_KYBER) ]]; then
	# CK_BBOOL
	if [[ $(grep -c "CKA_MODIFIABLE: CK_TRUE" $P11SAK_IBM_KYBER_LONG) == "2" ]]; then
		echo "* TESTCASE list-key ibm-kyber PASS Listed random ibm-kyber keys CK_BBOOL attribute"
	else
		echo "* TESTCASE list-key ibm-kyber FAIL Failed to list ibm-kyber keys CK_BBOOL attribute"
		status=1
	fi
	# CK_ULONG
	if [[ $(grep -c "CKA_IBM_KYBER_KEYFORM:" $P11SAK_IBM_KYBER_LONG) == "2" ]]; then
		echo "* TESTCASE list-key ibm-kyber PASS Listed random ibm-kyber keys CK_ULONG attribute"
	else
		echo "* TESTCASE list-key ibm-kyber FAIL Failed to list ibm-kyber keys CK_ULONG attribute"
		status=1
	fi
	# CK_BYTE
	if [[ $(grep -c "CKA_IBM_KYBER_PK:" $P11SAK_IBM_KYBER_LONG) == "2" ]]; then
		echo "* TESTCASE list-key ibm-kyber PASS Listed random ibm-kyber keys CK_BYTE attribute"
	else
		echo "* TESTCASE list-key ibm-kyber FAIL Failed to list ibm-kyber keys CK_BYTE attribute"
		status=1
	fi
else
	echo "* TESTCASE list-key ibm-kyber SKIP Listed random ibm-kyber keys CK_BBOOL attribute"
	echo "* TESTCASE list-key ibm-kyber SKIP Listed random ibm-kyber keys CK_ULONG attribute"
	echo "* TESTCASE list-key ibm-kyber SKIP Listed random ibm-kyber keys CK_BYTE attribute"
fi

if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_IBM_ML_DSA) ]]; then
	# CK_BBOOL
	if [[ $(grep -c "CKA_MODIFIABLE: CK_TRUE" $P11SAK_IBM_ML_DSA_LONG) == "2" ]]; then
		echo "* TESTCASE list-key ibm-ml-dsa PASS Listed random ibm-ml-dsa keys CK_BBOOL attribute"
	else
		echo "* TESTCASE list-key ibm-ml-dsa FAIL Failed to list ibm-ml-dsa keys CK_BBOOL attribute"
		status=1
	fi
	# CK_ULONG
	if [[ $(grep -c "CKA_IBM_PARAMETER_SET:" $P11SAK_IBM_ML_DSA_LONG) == "2" ]]; then
		echo "* TESTCASE list-key ibm-ml-dsa PASS Listed random ibm-ml-dsa keys CK_ULONG attribute"
	else
		echo "* TESTCASE list-key ibm-ml-dsa FAIL Failed to list ibm-ml-dsa keys CK_ULONG attribute"
		status=1
	fi
	# CK_BYTE
	if [[ $(grep -c "CKA_VALUE:" $P11SAK_IBM_ML_DSA_LONG) == "2" ]]; then
		echo "* TESTCASE list-key ibm-ml-dsa PASS Listed random ibm-ml-dsa keys CK_BYTE attribute"
	else
		echo "* TESTCASE list-key ibm-ml-dsa FAIL Failed to list ibm-ml-dsa keys CK_BYTE attribute"
		status=1
	fi
else
	echo "* TESTCASE list-key ibm-ml-dsa SKIP Listed random ibm-ml-dsa keys CK_BBOOL attribute"
	echo "* TESTCASE list-key ibm-ml-dsa SKIP Listed random ibm-ml-dsa keys CK_ULONG attribute"
	echo "* TESTCASE list-key ibm-ml-dsa SKIP Listed random ibm-ml-dsa keys CK_BYTE attribute"
fi


if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_IBM_ML_KEM) ]]; then
	# CK_BBOOL
	if [[ $(grep -c "CKA_MODIFIABLE: CK_TRUE" $P11SAK_IBM_ML_KEM_LONG) == "2" ]]; then
		echo "* TESTCASE list-key ibm-ml-kem PASS Listed random ibm-ml-kem keys CK_BBOOL attribute"
	else
		echo "* TESTCASE list-key ibm-ml-kem FAIL Failed to list ibm-ml-kem keys CK_BBOOL attribute"
		status=1
	fi
	# CK_ULONG
	if [[ $(grep -c "CKA_IBM_PARAMETER_SET:" $P11SAK_IBM_ML_KEM_LONG) == "2" ]]; then
		echo "* TESTCASE list-key ibm-ml-kem PASS Listed random ibm-ml-kem keys CK_ULONG attribute"
	else
		echo "* TESTCASE list-key ibm-ml-kem FAIL Failed to list ibm-ml-kem keys CK_ULONG attribute"
		status=1
	fi
	# CK_BYTE
	if [[ $(grep -c "CKA_VALUE:" $P11SAK_IBM_ML_KEM_LONG) == "2" ]]; then
		echo "* TESTCASE list-key ibm-ml-kem PASS Listed random ibm-ml-kem keys CK_BYTE attribute"
	else
		echo "* TESTCASE list-key ibm-ml-kem FAIL Failed to list ibm-ml-kem keys CK_BYTE attribute"
		status=1
	fi
else
	echo "* TESTCASE list-key ibm-ml-kem SKIP Listed random ibm-ml-kem keys CK_BBOOL attribute"
	echo "* TESTCASE list-key ibm-ml-kem SKIP Listed random ibm-ml-kem keys CK_ULONG attribute"
	echo "* TESTCASE list-key ibm-ml-kem SKIP Listed random ibm-ml-kem keys CK_BYTE attribute"
fi


echo "** Import the sample x.509 certificates - 'p11sak_test.sh'"
RC_P11SAK_X509_IMPORT=0
${P11SAK} import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 123 --label "p11sak-x509-rsa2048crt" --file $DIR/p11sak_rsa2048cert.crt
RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
${P11SAK} import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 234 --label "p11sak-x509-rsa2048pem" --file $DIR/p11sak_rsa2048cert.pem
RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
${P11SAK} import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 345 --label "p11sak-x509-rsa4096crt" --file $DIR/p11sak_rsa4096cert.crt
RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
${P11SAK} import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 456 --label "p11sak-x509-rsa4096pem" --file $DIR/p11sak_rsa4096cert.pem
RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
${P11SAK} import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 567 --label "p11sak-x509-ecp256crt" --file $DIR/p11sak_ecp256cert.crt
RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
${P11SAK} import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 678 --label "p11sak-x509-ecp256pem" --file $DIR/p11sak_ecp256cert.pem
RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
${P11SAK} import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 789 --label "p11sak-x509-ecp384crt" --file $DIR/p11sak_ecp384cert.crt
RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
${P11SAK} import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 89A --label "p11sak-x509-ecp384pem" --file $DIR/p11sak_ecp384cert.pem
RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
${P11SAK} import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 789 --label "p11sak-x509-ecp521crt" --file $DIR/p11sak_ecp521cert.crt
RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
${P11SAK} import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 89A --label "p11sak-x509-ecp521pem" --file $DIR/p11sak_ecp521cert.pem
RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_EDDSA) ]]; then
	${P11SAK} import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 9AB --label "p11sak-x509-ed25519crt" --file $DIR/p11sak_ed25519cert.crt
	RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
	${P11SAK} import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id ABC --label "p11sak-x509-ed25519pem" --file $DIR/p11sak_ed25519cert.pem
	RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
	${P11SAK} import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 9AB --label "p11sak-x509-ed448crt" --file $DIR/p11sak_ed448cert.crt
	RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
	${P11SAK} import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id ABC --label "p11sak-x509-ed448pem" --file $DIR/p11sak_ed448cert.pem
	RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
else
	echo "Skip importing x.509 certs with ec-edwards key, slot does not support CKM_EDDSA"
fi
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_DSA) ]]; then
	${P11SAK} import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 9AB --label "p11sak-x509-dsa3072crt" --file $DIR/p11sak_dsa3072cert.crt
	RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
	${P11SAK} import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id ABC --label "p11sak-x509-dsa3072pem" --file $DIR/p11sak_dsa3072cert.pem
	RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
	${P11SAK} import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 9AB --label "p11sak-x509-dsa4096crt" --file $DIR/p11sak_dsa4096cert.crt
	RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
	${P11SAK} import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id ABC --label "p11sak-x509-dsa4096pem" --file $DIR/p11sak_dsa4096cert.pem
	RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
else
	echo "Skip importing x.509 certs with DSA key, slot does not support CKM_DSA"
fi
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_IBM_DILITHIUM) && -n $(openssl list -providers | grep oqsprovider) && -n $(openssl list -key-managers | grep "dilithium3 @ oqsprovider") ]]; then
	openssl req -x509 -new -newkey dilithium3 -keyout dilithium3_CA.key -out dilithium3_CA.crt -nodes -subj "/CN=test CA" -days 365 2>/dev/null
	RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
	openssl genpkey -algorithm dilithium3 -out dilithium3_srv.key
	RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
	openssl req -new -newkey dilithium3 -keyout dilithium3_srv.key -out dilithium3_srv.csr -nodes -subj "/CN=test server" 2>/dev/null
	RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
	openssl x509 -req -in dilithium3_srv.csr -out dilithium3_srv.crt -CA dilithium3_CA.crt -CAkey dilithium3_CA.key -CAcreateserial -days 365 2>/dev/null
	RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
	${P11SAK} import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id ABC --label "p11sak-x509-dilithium3" --file dilithium3_srv.crt
	RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
else
	echo "Skip importing x.509 certs with IBM Dilithum key, slot does not support CKM_IBM_DILITHIUM or oqsprovider not available or does not support dilithium3"
fi
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_IBM_ML_DSA) && -n $(openssl list -key-managers | grep -i "MLDSA65") ]]; then
	openssl req -x509 -new -newkey mldsa65 -keyout mldsa65_CA.key -out mldsa65_CA.crt -nodes -subj "/CN=test CA" -days 365 2>/dev/null
	RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
	openssl genpkey -algorithm mldsa65 -out mldsa65_srv.key
	RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
	openssl req -new -newkey mldsa65 -keyout mldsa65_srv.key -out mldsa65_srv.csr -nodes -subj "/CN=test server" 2>/dev/null
	RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
	openssl x509 -req -in mldsa65_srv.csr -out mldsa65_srv.crt -CA mldsa65_CA.crt -CAkey mldsa65_CA.key -CAcreateserial -days 365 2>/dev/null
	RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
	${P11SAK} import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id ABC --label "p11sak-x509-mldsa65" --file mldsa65_srv.crt
	RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
else
	echo "Skip importing x.509 certs with IBM ML-DSA key, slot does not support CKM_IBM_ML_DSA or neither OpenSSL 3.5, nor oqsprovider not available or does not support mldsa65"
fi

echo "** Now exporting x.509 certificates - 'p11sak_test.sh'"
RC_P11SAK_X509_EXPORT=0
# x.509
${P11SAK} export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-rsa2048crt" --file p11sak_rsa2048cert_exported.crt --der --force
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
${P11SAK} export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-rsa2048pem" --file p11sak_rsa2048cert_exported.pem --force
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
${P11SAK} export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-rsa4096crt" --file p11sak_rsa4096cert_exported.crt --der --force
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
${P11SAK} export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-rsa4096pem" --file p11sak_rsa4096cert_exported.pem --force
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
${P11SAK} export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ecp256crt" --file p11sak_ecp256cert_exported.crt --der --force
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
${P11SAK} export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ecp256pem" --file p11sak_ecp256cert_exported.pem --force
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
${P11SAK} export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ecp384crt" --file p11sak_ecp384cert_exported.crt --der --force
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
${P11SAK} export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ecp384pem" --file p11sak_ecp384cert_exported.pem --force
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
${P11SAK} export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ecp521crt" --file p11sak_ecp521cert_exported.crt --der --force
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
${P11SAK} export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ecp521pem" --file p11sak_ecp521cert_exported.pem --force
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_EDDSA) ]]; then
	${P11SAK} export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ed25519crt" --file p11sak_ed25519cert_exported.crt --der --force
	RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
	${P11SAK} export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ed25519pem" --file p11sak_ed25519cert_exported.pem --force
	RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
	${P11SAK} export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ed448crt" --file p11sak_ed448cert_exported.crt --der --force
	RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
	${P11SAK} export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ed448pem" --file p11sak_ed448cert_exported.pem --force
	RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
else
	echo "Skip exporting x.509 certs with ec-edwards key, slot does not support CKM_EDDSA"
fi
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_DSA) ]]; then
	${P11SAK} export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-dsa3072crt" --file p11sak_dsa3072cert_exported.crt --der --force
	RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
	${P11SAK} export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-dsa3072pem" --file p11sak_dsa3072cert_exported.pem --force
	RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
	${P11SAK} export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-dsa4096crt" --file p11sak_dsa4096cert_exported.crt --der --force
	RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
	${P11SAK} export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-dsa4096pem" --file p11sak_dsa4096cert_exported.pem --force
	RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
else
	echo "Skip exporting x.509 certs with DSA key, slot does not support CKM_DSA"
fi
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_IBM_DILITHIUM) && -n $(openssl list -providers | grep oqsprovider) && -n $(openssl list -key-managers | grep "dilithium3 @ oqsprovider") ]]; then
	${P11SAK} export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-dilithium3" --file p11sak_dil3cert_exported.pem --force
	RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
else
	echo "Skip exporting x.509 certs with IBM Dilithum key, slot does not support CKM_IBM_DILITHIUM or the oqsprovider not available or does not support dilithium3"
fi
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_IBM_ML_DSA) && -n $(openssl list -key-managers | grep -i "MLDSA65") ]]; then
	${P11SAK} export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-mldsa65" --file p11sak_mldsa65cert_exported.pem --force
	RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
else
	echo "Skip exporting x.509 certs with IBM ML-DSA key, slot does not support CKM_IBM_ML_DSA or neither OpenSSL 3.5, nor the oqsprovider not available or does not support mldsa65"
fi
# export to URI-PEM
p11sak export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-rsa2048crt" --file export-uri-pem4.pem --force --uri-pem
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
openssl asn1parse -i -in export-uri-pem4.pem  > /dev/null
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
p11sak export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-rsa2048crt" --file export-uri-pem5.pem --force --uri-pem --uri-pin-value
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
openssl asn1parse -i -in export-uri-pem5.pem  > /dev/null
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
p11sak export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-rsa2048crt" --file export-uri-pem6.pem --force --uri-pem --uri-pin-source pin2.txt
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
openssl asn1parse -i -in export-uri-pem6.pem  > /dev/null
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
if [[ $(cat pin2.txt) != $PKCS11_USER_PIN ]]; then
	echo "Pin file does not contain the PKCS#11 user pin"
	RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + 1))
fi


echo "** Now extracting public keys from x.509 certificates - 'p11sak_test.sh'"
RC_P11SAK_X509_EXTRACT=0
${P11SAK} extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-rsa2048crt" --force
RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
${P11SAK} extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-rsa2048pem" --force
RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
${P11SAK} extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-rsa4096crt" --force
RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
${P11SAK} extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-rsa4096pem" --force
RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
${P11SAK} extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ecp256crt" --force
RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
${P11SAK} extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ecp256pem" --force
RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
${P11SAK} extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ecp384crt" --force
RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
${P11SAK} extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ecp384pem" --force
RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
${P11SAK} extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ecp521crt" --force
RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
${P11SAK} extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ecp521pem" --force
RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_EDDSA) ]]; then
	${P11SAK} extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ed25519crt" --force
	RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
	${P11SAK} extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ed25519pem" --force
	RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
	${P11SAK} extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ed448crt" --force
	RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
	${P11SAK} extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ed448pem" --force
	RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
else
	echo "Skip extracting pubkeys from x.509 certs with ec-edwards key, slot does not support CKM_EDDSA"
fi
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_DSA) ]]; then
	${P11SAK} extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-dsa3072crt" --force
	RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
	${P11SAK} extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-dsa3072pem" --force
	RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
	${P11SAK} extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-dsa4096crt" --force
	RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
	${P11SAK} extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-dsa4096pem" --force
	RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
else
	echo "Skip extracting pubkeys from x.509 certs with DSA key, slot does not support CKM_DSA"
fi
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_IBM_DILITHIUM) && -n $(openssl list -providers | grep oqsprovider) && -n $(openssl list -key-managers | grep "dilithium3 @ oqsprovider") ]]; then
${P11SAK} extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-dilithium3" --force
	RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
else
	echo "Skip extracting pubkeys from x.509 certs with IBM Dilithum key, slot does not support CKM_IBM_DILITHIUM or oqsprovider not available or does not support dilithium3"
fi
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_IBM_ML_DSA) && -n $(openssl list -key-managers | grep -i "MLDSA65") ]]; then
${P11SAK} extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-mldsa65" --force
	RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
else
	echo "Skip extracting pubkeys from x.509 certs with IBM ML-DSA key, slot does not support CKM_IBM_ML_DSA or neither OpenSSL 3.5, not the oqsprovider not available or does not support mldsa65"
fi


echo "** Now copying x.509 certificates to new token objects - 'p11sak_test.sh'"
RC_P11SAK_X509_COPY=0
${P11SAK} copy-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-*" --new-label "p11sak-x509-copied" --force
RC_P11SAK_X509_COPY=$((RC_P11SAK_X509_COPY + $?))


echo "** Now updating x.509 certs - 'p11sak_test.sh'"
RC_P11SAK_X509_UPDATE=0
${P11SAK} set-cert-attr x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-*" --new-attr "Yt" --force
RC_P11SAK_X509_UPDATE=$((RC_P11SAK_X509_UPDATE + $?))
${P11SAK} set-cert-attr x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-*" --new-id "012345" --force
RC_P11SAK_X509_UPDATE=$((RC_P11SAK_X509_UPDATE + $?))


echo "** Now list x509 certificates and extracted pubkeys and redirect output to pre-files - 'p11sak_test.sh'"
RC_P11SAK_X509_LIST=0
${P11SAK} list-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-*" --sort n:a &> $P11SAK_X509_PRE
RC_P11SAK_X509_LIST=$((RC_P11SAK_X509_LIST + $?))
${P11SAK} list-key all --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-*" &>> $P11SAK_X509_PRE
RC_P11SAK_X509_LIST=$((RC_P11SAK_X509_LIST + $?))

RC_P11SAK_X509_LIST_LONG=0
${P11SAK} list-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-x509-*" --sort l:d,n:a &> $P11SAK_X509_LONG
RC_P11SAK_X509_LIST_LONG=$((RC_P11SAK_X509_LIST_LONG + $?))
${P11SAK} list-key all --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-x509-*" &>> $P11SAK_X509_LONG
RC_P11SAK_X509_LIST_LONG=$((RC_P11SAK_X509_LIST_LONG + $?))

echo "** Now removing x.509 certificates and extracted public keys - 'p11sak_test.sh'"
# x.509
RC_P11SAK_X509_REMOVE=0
${P11SAK} remove-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-*" -f
RC_P11SAK_X509_REMOVE=$((RC_P11SAK_X509_REMOVE + $?))
${P11SAK} remove-key --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-*" -f
RC_P11SAK_X509_REMOVE=$((RC_P11SAK_X509_REMOVE + $?))


echo "** Now list certificates and extracted keys and redirect to post-files - 'p11sak_test.sh'"
# list objects: if remove was successful above, no certs and extracted keys are left
RC_P11SAK_X509_LIST_POST=0
${P11SAK} list-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-*" --sort n:d,l:a &> $P11SAK_X509_POST
RC_P11SAK_X509_LIST_POST=$((RC_P11SAK_X509_LIST_POST + $?))
${P11SAK} list-key all --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-*" &> $P11SAK_X509_POST
RC_P11SAK_X509_LIST_POST=$((RC_P11SAK_X509_LIST_POST + $?))


echo "** Now checking output files to determine PASS/FAIL of tests - 'p11sak_test.sh'"

# check if exported X509 certificates are equal to original ones
RC_P11SAK_X509_DIFF=0
diff $DIR/p11sak_rsa2048cert.crt p11sak_rsa2048cert_exported.crt > /dev/null
RC_P11SAK_X509_DIFF=$((RC_P11SAK_X509_DIFF + $?))
diff $DIR/p11sak_rsa2048cert.pem p11sak_rsa2048cert_exported.pem > /dev/null
RC_P11SAK_X509_DIFF=$((RC_P11SAK_X509_DIFF + $?))
diff $DIR/p11sak_rsa4096cert.crt p11sak_rsa4096cert_exported.crt > /dev/null
RC_P11SAK_X509_DIFF=$((RC_P11SAK_X509_DIFF + $?))
diff $DIR/p11sak_rsa4096cert.pem p11sak_rsa4096cert_exported.pem > /dev/null
RC_P11SAK_X509_DIFF=$((RC_P11SAK_X509_DIFF + $?))
diff $DIR/p11sak_ecp256cert.crt p11sak_ecp256cert_exported.crt > /dev/null
RC_P11SAK_X509_DIFF=$((RC_P11SAK_X509_DIFF + $?))
diff $DIR/p11sak_ecp256cert.pem p11sak_ecp256cert_exported.pem > /dev/null
RC_P11SAK_X509_DIFF=$((RC_P11SAK_X509_DIFF + $?))
diff $DIR/p11sak_ecp384cert.crt p11sak_ecp384cert_exported.crt > /dev/null
RC_P11SAK_X509_DIFF=$((RC_P11SAK_X509_DIFF + $?))
diff $DIR/p11sak_ecp384cert.pem p11sak_ecp384cert_exported.pem > /dev/null
RC_P11SAK_X509_DIFF=$((RC_P11SAK_X509_DIFF + $?))
diff $DIR/p11sak_ecp521cert.crt p11sak_ecp521cert_exported.crt > /dev/null
RC_P11SAK_X509_DIFF=$((RC_P11SAK_X509_DIFF + $?))
diff $DIR/p11sak_ecp521cert.pem p11sak_ecp521cert_exported.pem > /dev/null
RC_P11SAK_X509_DIFF=$((RC_P11SAK_X509_DIFF + $?))
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_EDDSA) ]]; then
	diff $DIR/p11sak_ed25519cert.crt p11sak_ed25519cert_exported.crt > /dev/null
	RC_P11SAK_X509_DIFF=$((RC_P11SAK_X509_DIFF + $?))
	diff $DIR/p11sak_ed25519cert.pem p11sak_ed25519cert_exported.pem > /dev/null
	RC_P11SAK_X509_DIFF=$((RC_P11SAK_X509_DIFF + $?))
	diff $DIR/p11sak_ed448cert.crt p11sak_ed448cert_exported.crt > /dev/null
	RC_P11SAK_X509_DIFF=$((RC_P11SAK_X509_DIFF + $?))
	diff $DIR/p11sak_ed448cert.pem p11sak_ed448cert_exported.pem > /dev/null
	RC_P11SAK_X509_DIFF=$((RC_P11SAK_X509_DIFF + $?))
else
	echo "Skip comparing exported ec-edwards x.509 certs with original certs, slot does not support CKM_EDDSA"
fi
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_DSA) ]]; then
	diff $DIR/p11sak_dsa3072cert.crt p11sak_dsa3072cert_exported.crt > /dev/null
	RC_P11SAK_X509_DIFF=$((RC_P11SAK_X509_DIFF + $?))
	diff $DIR/p11sak_dsa3072cert.pem p11sak_dsa3072cert_exported.pem > /dev/null
	RC_P11SAK_X509_DIFF=$((RC_P11SAK_X509_DIFF + $?))
	diff $DIR/p11sak_dsa4096cert.crt p11sak_dsa4096cert_exported.crt > /dev/null
	RC_P11SAK_X509_DIFF=$((RC_P11SAK_X509_DIFF + $?))
	diff $DIR/p11sak_dsa4096cert.pem p11sak_dsa4096cert_exported.pem > /dev/null
	RC_P11SAK_X509_DIFF=$((RC_P11SAK_X509_DIFF + $?))
else
	echo "Skip comparing exported DSA x.509 certs with original certs, slot does not support CKM_DSA"
fi

# check X509 certificate listings for completeness
# copied certs 
grep -q "p11sak-x509-copied" $P11SAK_X509_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE copy-cert x509 PASS Copied x509 certs"
else
	echo "* TESTCASE copy-cert x509 FAIL Failed to copy x509 certs"
	status=1
fi
grep -v -q "p11sak-x509-copied" $P11SAK_X509_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-cert x509 PASS Deleted copied x509 certs"
else
	echo "* TESTCASE remove-cert x509 FAIL Failed to delete copied x509 certs"
	status=1
fi
# rsa-2048
grep -q "p11sak-x509-rsa2048crt" $P11SAK_X509_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE import-cert x509 PASS Imported binary x509 cert with random rsa 2048 key"
else
	echo "* TESTCASE import-cert x509 FAIL Failed to import binary x509 certs with random rsa 2048 key"
	status=1
fi
grep -v -q "p11sak-x509-rsa2048crt" $P11SAK_X509_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-cert x509 PASS Deleted imported binary x509 cert with rsa 2048 public key"
else
	echo "* TESTCASE remove-cert x509 FAIL Failed to delete imported binary x509 cert with rsa 2048 public key"
	status=1
fi

grep -q "p11sak-x509-rsa2048pem" $P11SAK_X509_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE import-cert x509 PASS Imported base64-encoded x509 cert with random rsa 2048 key"
else
	echo "* TESTCASE import-cert x509 FAIL Failed to import base64-encoded x509 certs with random rsa 2048 key"
	status=1
fi
grep -v -q "p11sak-x509-rsa2048pem" $P11SAK_X509_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-cert x509 PASS Deleted imported base64-encoded x509 cert with rsa 2048 public key"
else
	echo "* TESTCASE remove-cert x509 FAIL Failed to delete imported base64-encoded x509 cert with rsa 2048 public key"
	status=1
fi

# rsa-4096
grep -q "p11sak-x509-rsa4096crt" $P11SAK_X509_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE import-cert x509 PASS Imported binary x509 cert with random rsa 4096 key"
else
	echo "* TESTCASE import-cert x509 FAIL Failed to import binary x509 certs with random rsa 4096 key"
	status=1
fi
grep -v -q "p11sak-x509-rsa4096crt" $P11SAK_X509_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-cert x509 PASS Deleted imported binary x509 cert with rsa 4096 public key"
else
	echo "* TESTCASE remove-cert x509 FAIL Failed to delete imported binary x509 cert with rsa 4096 public key"
	status=1
fi

grep -q "p11sak-x509-rsa4096pem" $P11SAK_X509_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE import-cert x509 PASS Imported base64-encoded x509 cert with random rsa 4096 key"
else
	echo "* TESTCASE import-cert x509 FAIL Failed to import base64-encoded x509 certs with random rsa 4096 key"
	status=1
fi
grep -v -q "p11sak-x509-rsa4096pem" $P11SAK_X509_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-cert x509 PASS Deleted imported base64-encoded x509 cert with rsa 4096 public key"
else
	echo "* TESTCASE remove-cert x509 FAIL Failed to delete imported base64-encoded x509 cert with rsa 4096 public key"
	status=1
fi

# EC-p256
grep -q "p11sak-x509-ecp256crt" $P11SAK_X509_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE import-cert x509 PASS Imported binary x509 cert with random EC-p256 key"
else
	echo "* TESTCASE import-cert x509 FAIL Failed to import binary x509 certs with random EC-p256 key"
	status=1
fi
grep -v -q "p11sak-x509-ecp256crt" $P11SAK_X509_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-cert x509 PASS Deleted imported binary x509 cert with EC-p256 public key"
else
	echo "* TESTCASE remove-cert x509 FAIL Failed to delete imported binary x509 cert with EC-p256 public key"
	status=1
fi

grep -q "p11sak-x509-ecp256pem" $P11SAK_X509_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE import-cert x509 PASS Imported base64-encoded x509 cert with random EC-p256 key"
else
	echo "* TESTCASE import-cert x509 FAIL Failed to import base64-encoded x509 certs with random EC-p256 key"
	status=1
fi
grep -v -q "p11sak-x509-ecp256pem" $P11SAK_X509_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-cert x509 PASS Deleted imported base64-encoded x509 cert with EC-p256 public key"
else
	echo "* TESTCASE remove-cert x509 FAIL Failed to delete imported base64-encoded x509 cert with EC-p256 public key"
	status=1
fi

# EC-p384
grep -q "p11sak-x509-ecp384crt" $P11SAK_X509_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE import-cert x509 PASS Imported binary x509 cert with random EC-p384 key"
else
	echo "* TESTCASE import-cert x509 FAIL Failed to import binary x509 certs with random EC-p384 key"
	status=1
fi
grep -v -q "p11sak-x509-ecp384crt" $P11SAK_X509_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-cert x509 PASS Deleted imported binary x509 cert with EC-p384 public key"
else
	echo "* TESTCASE remove-cert x509 FAIL Failed to delete imported binary x509 cert with EC-p384 public key"
	status=1
fi

grep -q "p11sak-x509-ecp384pem" $P11SAK_X509_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE import-cert x509 PASS Imported base64-encoded x509 cert with random EC-p384 key"
else
	echo "* TESTCASE import-cert x509 FAIL Failed to import base64-encoded x509 certs with random EC-p384 key"
	status=1
fi
grep -v -q "p11sak-x509-ecp384pem" $P11SAK_X509_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-cert x509 PASS Deleted imported base64-encoded x509 cert with EC-p384 public key"
else
	echo "* TESTCASE remove-cert x509 FAIL Failed to delete imported base64-encoded x509 cert with EC-p384 public key"
	status=1
fi

# EC-p521
grep -q "p11sak-x509-ecp521crt" $P11SAK_X509_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE import-cert x509 PASS Imported binary x509 cert with random EC-p521 key"
else
	echo "* TESTCASE import-cert x509 FAIL Failed to import binary x509 certs with random EC-p521 key"
	status=1
fi
grep -v -q "p11sak-x509-ecp521crt" $P11SAK_X509_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-cert x509 PASS Deleted imported binary x509 cert with EC-p521 public key"
else
	echo "* TESTCASE remove-cert x509 FAIL Failed to delete imported binary x509 cert with EC-p521 public key"
	status=1
fi

grep -q "p11sak-x509-ecp521pem" $P11SAK_X509_PRE
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE import-cert x509 PASS Imported base64-encoded x509 cert with random EC-p521 key"
else
	echo "* TESTCASE import-cert x509 FAIL Failed to import base64-encoded x509 certs with random EC-p521 key"
	status=1
fi
grep -v -q "p11sak-x509-ecp521pem" $P11SAK_X509_POST
rc=$?
if [ $rc = 0 ]; then
	echo "* TESTCASE remove-cert x509 PASS Deleted imported base64-encoded x509 cert with EC-p521 public key"
else
	echo "* TESTCASE remove-cert x509 FAIL Failed to delete imported base64-encoded x509 cert with EC-p521 public key"
	status=1
fi

# ec-edwards
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_EDDSA) ]]; then
	grep -q "p11sak-x509-ed25519crt" $P11SAK_X509_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE import-cert x509 PASS Imported binary x509 cert with random ed25519 key"
	else
		echo "* TESTCASE import-cert x509 FAIL Failed to import binary x509 certs with random ed25519 key"
		status=1
	fi
	grep -v -q "p11sak-x509-ed25519crt" $P11SAK_X509_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-cert x509 PASS Deleted imported binary x509 cert with ed25519 public key"
	else
		echo "* TESTCASE remove-cert x509 FAIL Failed to delete imported binary x509 cert with ed25519 public key"
		status=1
	fi
	
	grep -q "p11sak-x509-ed25519pem" $P11SAK_X509_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE import-cert x509 PASS Imported base64-encoded x509 cert with random ed255192 key"
	else
		echo "* TESTCASE import-cert x509 FAIL Failed to import base64-encoded x509 certs with random ed25519 key"
		status=1
	fi
	grep -v -q "p11sak-x509-ed25519pem" $P11SAK_X509_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-cert x509 PASS Deleted imported base64-encoded x509 cert with ed25519 public key"
	else
		echo "* TESTCASE remove-cert x509 FAIL Failed to delete imported base64-encoded x509 cert with ed25519 public key"
		status=1
	fi
	
	grep -q "p11sak-x509-ed448crt" $P11SAK_X509_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE import-cert x509 PASS Imported binary x509 cert with random ed448 key"
	else
		echo "* TESTCASE import-cert x509 FAIL Failed to import binary x509 certs with random ed448 key"
		status=1
	fi
	grep -v -q "p11sak-x509-ed448crt" $P11SAK_X509_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-cert x509 PASS Deleted imported binary x509 cert with ed448 public key"
	else
		echo "* TESTCASE remove-cert x509 FAIL Failed to delete imported binary x509 cert with ed448 public key"
		status=1
	fi
	
	grep -q "p11sak-x509-ed448pem" $P11SAK_X509_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE import-cert x509 PASS Imported base64-encoded x509 cert with random ed4482 key"
	else
		echo "* TESTCASE import-cert x509 FAIL Failed to import base64-encoded x509 certs with random ed448 key"
		status=1
	fi
	grep -v -q "p11sak-x509-ed448pem" $P11SAK_X509_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-cert x509 PASS Deleted imported base64-encoded x509 cert with ed448 public key"
	else
		echo "* TESTCASE remove-cert x509 FAIL Failed to delete imported base64-encoded x509 cert with ed448 public key"
		status=1
	fi
else
	echo "* TESTCASE import-cert x509 SKIP Import binary x509 cert with random ed25519 key. Slot does not support EdDSA."
	echo "* TESTCASE remove-cert x509 SKIP Delete imported binary x509 cert with ed25519 public key. Slot does not support EdDSA."
	echo "* TESTCASE import-cert x509 SKIP Import base64-encoded x509 cert with random ed25519 key. Slot does not support EdDSA."
	echo "* TESTCASE remove-cert x509 SKIP Delete imported base64-encoded x509 cert with ed25519 public key. Slot does not support EdDSA."
	echo "* TESTCASE import-cert x509 SKIP Import binary x509 cert with random ed448 key. Slot does not support EdDSA."
	echo "* TESTCASE remove-cert x509 SKIP Delete imported binary x509 cert with ed448 public key. Slot does not support EdDSA."
	echo "* TESTCASE import-cert x509 SKIP Import base64-encoded x509 cert with random ed448 key. Slot does not support EdDSA."
	echo "* TESTCASE remove-cert x509 SKIP Delete imported base64-encoded x509 cert with ed448 public key. Slot does not support EdDSA."
fi

# DSA-3072
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_DSA) ]]; then
	grep -q "p11sak-x509-dsa3072crt" $P11SAK_X509_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE import-cert x509 PASS Imported binary x509 cert with random DSA-3072 key"
	else
		echo "* TESTCASE import-cert x509 FAIL Failed to import binary x509 certs with random DSA-3072 key"
		status=1
	fi
	grep -v -q "p11sak-x509-dsa3072crt" $P11SAK_X509_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-cert x509 PASS Deleted imported binary x509 cert with DSA-3072 public key"
	else
		echo "* TESTCASE remove-cert x509 FAIL Failed to delete imported binary x509 cert with DSA-3072 public key"
		status=1
	fi
	
	grep -q "p11sak-x509-dsa3072pem" $P11SAK_X509_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE import-cert x509 PASS Imported base64-encoded x509 cert with random DSA-3072 key"
	else
		echo "* TESTCASE import-cert x509 FAIL Failed to import base64-encoded x509 certs with random DSA-3072 key"
		status=1
	fi
	grep -v -q "p11sak-x509-dsa3072pem" $P11SAK_X509_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-cert x509 PASS Deleted imported base64-encoded x509 cert with DSA-3072 public key"
	else
		echo "* TESTCASE remove-cert x509 FAIL Failed to delete imported base64-encoded x509 cert with DSA-3072 public key"
		status=1
	fi
else
	echo "* TESTCASE import-cert x509 SKIP Import binary x509 cert with random DSA-3072 key. Slot does not support DSA."
	echo "* TESTCASE remove-cert x509 SKIP Delete imported binary x509 cert with DSA-3072 public key. Slot does not support DSA."
	echo "* TESTCASE import-cert x509 SKIP Import base64-encoded x509 cert with random DSA-3072 key. Slot does not support DSA."
	echo "* TESTCASE remove-cert x509 SKIP Delete imported base64-encoded x509 cert with DSA-3072 public key. Slot does not support DSA."
fi

# DSA-4096
if [[ -n $( ${PKCSCONF} -m -c $SLOT | grep CKM_DSA) ]]; then
	grep -q "p11sak-x509-dsa4096crt" $P11SAK_X509_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE import-cert x509 PASS Imported binary x509 cert with random DSA-4096 key"
	else
		echo "* TESTCASE import-cert x509 FAIL Failed to import binary x509 certs with random DSA-4096 key"
		status=1
	fi
	grep -v -q "p11sak-x509-dsa4096crt" $P11SAK_X509_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-cert x509 PASS Deleted imported binary x509 cert with DSA-4096 public key"
	else
		echo "* TESTCASE remove-cert x509 FAIL Failed to delete imported binary x509 cert with DSA-4096 public key"
		status=1
	fi
	
	grep -q "p11sak-x509-dsa4096pem" $P11SAK_X509_PRE
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE import-cert x509 PASS Imported base64-encoded x509 cert with random DSA-4096 key"
	else
		echo "* TESTCASE import-cert x509 FAIL Failed to import base64-encoded x509 certs with random DSA-4096 key"
		status=1
	fi
	grep -v -q "p11sak-x509-dsa4096pem" $P11SAK_X509_POST
	rc=$?
	if [ $rc = 0 ]; then
		echo "* TESTCASE remove-cert x509 PASS Deleted imported base64-encoded x509 cert with DSA-4096 public key"
	else
		echo "* TESTCASE remove-cert x509 FAIL Failed to delete imported base64-encoded x509 cert with DSA-4096 public key"
		status=1
	fi
else
	echo "* TESTCASE import-cert x509 SKIP Import binary x509 cert with random DSA-4096 key. Slot does not support DSA."
	echo "* TESTCASE remove-cert x509 SKIP Delete imported binary x509 cert with DSA-4096 public key. Slot does not support DSA."
	echo "* TESTCASE import-cert x509 SKIP Import base64-encoded x509 cert with random DSA-4096 key. Slot does not support DSA."
	echo "* TESTCASE remove-cert x509 SKIP Delete imported base64-encoded x509 cert with DSA-4096 public key. Slot does not support DSA."
fi


# check return codes
if [ $RC_P11SAK_GENERATE = 0 ]; then
	echo "* TESTCASE generate-key PASS return code check"
else
	echo "* TESTCASE generate-key FAIL return code check"
	status=1
fi

if [ $RC_P11SAK_LIST = 0 ]; then
	echo "* TESTCASE list-key short PASS return code check"
else
	echo "* TESTCASE list-key short FAIL return code check"
	status=1
fi

if [ $RC_P11SAK_LIST_LONG = 0 ]; then
	echo "* TESTCASE list-key long PASS return code check"
else
	echo "* TESTCASE list-key long FAIL return code check"
	status=1
fi

if [ $RC_P11SAK_LIST_POST = 0 ]; then
	echo "* TESTCASE list-key post PASS return code check"
else
	echo "* TESTCASE list-key post FAIL return code check"
	status=1
fi

if [ $RC_P11SAK_UPDATE = 0 ]; then
	echo "* TESTCASE set-key-attr PASS return code check"
else
	echo "* TESTCASE set-key-attr FAIL return code check"
	status=1
fi

if [ $RC_P11SAK_COPY = 0 ]; then
	echo "* TESTCASE copy-key PASS return code check"
else
	echo "* TESTCASE copy-key FAIL return code check"
	status=1
fi

if [ $RC_P11SAK_KEY_EXTRACT = 0 ]; then
	echo "* TESTCASE extract-pubkey PASS return code check"
else
	echo "* TESTCASE extract-pubkey FAIL return code check"
	status=1
fi

if [ $RC_P11SAK_IMPORT = 0 ]; then
	echo "* TESTCASE import-key PASS return code check"
else
	echo "* TESTCASE import-key FAIL return code check"
	status=1
fi

if [ $RC_P11SAK_EXPORT = 0 ]; then
	echo "* TESTCASE export-key PASS return code check"
else
	echo "* TESTCASE export-key FAIL return code check"
	status=1
fi

if [ $RC_P11SAK_REMOVE = 0 ]; then
	echo "* TESTCASE remove-key PASS return code check"
else
	echo "* TESTCASE remove-key FAIL return code check"
	status=1
fi

# check return codes from key wrap tests
if [ $RC_P11SAK_WRAP = 0 ]; then
	echo "* TESTCASE wrap-key PASS return code check"
else
	echo "* TESTCASE wrap-key FAIL return code check"
	status=1
fi

# check return codes from certificate tests
if [ $RC_P11SAK_X509_IMPORT = 0 ]; then
	echo "* TESTCASE import-cert PASS return code check"
else
	echo "* TESTCASE import-cert FAIL return code check"
	status=1
fi

if [ $RC_P11SAK_X509_LIST = 0 ]; then
	echo "* TESTCASE list-cert short PASS return code check"
else
	echo "* TESTCASE list-cert short FAIL return code check"
	status=1
fi

if [ $RC_P11SAK_X509_LIST_LONG = 0 ]; then
	echo "* TESTCASE list-cert long PASS return code check"
else
	echo "* TESTCASE list-cert long FAIL return code check"
	status=1
fi

if [ $RC_P11SAK_X509_EXPORT = 0 ]; then
	echo "* TESTCASE export-cert PASS return code check"
else
	echo "* TESTCASE export-cert FAIL return code check"
	status=1
fi

if [ $RC_P11SAK_X509_COPY = 0 ]; then
	echo "* TESTCASE copy-cert PASS return code check"
else
	echo "* TESTCASE copy-cert FAIL return code check"
	status=1
fi

if [ $RC_P11SAK_X509_UPDATE = 0 ]; then
	echo "* TESTCASE set-cert-attr PASS return code check"
else
	echo "* TESTCASE set-cert-attr FAIL return code check"
	status=1
fi

if [ $RC_P11SAK_X509_REMOVE = 0 ]; then
	echo "* TESTCASE remove-cert PASS return code check"
else
	echo "* TESTCASE remove-cert FAIL return code check"
	status=1
fi

if [ $RC_P11SAK_X509_EXTRACT = 0 ]; then
	echo "* TESTCASE extract-cert-pubkey PASS return code check"
else
	echo "* TESTCASE extract-cert-pubkey FAIL return code check"
	status=1
fi

if [ $RC_P11SAK_X509_DIFF = 0 ]; then
	echo "* TESTCASE diff exported certs PASS return code check"
else
	echo "* TESTCASE diff exported certs FAIL return code check"
	status=1
fi

# check token pin handling
if [ $RC_P11SAK_PINOPT = 0 ]; then
	echo "* TESTCASE list-key pin-opt PASS Token pin handling (opt)"
else
	echo "* TESTCASE list-key pin-opt FAIL Token pin handling (opt)"
	status=1
fi

if [ $RC_P11SAK_PINENV = 0 ]; then
	echo "* TESTCASE list-key pin-env PASS Token pin handling (env)"
else
	echo "* TESTCASE list-key pin-env FAIL Token pin handling (env)"
	status=1
fi

if [ $RC_P11SAK_PINCON = 0 ]; then
	echo "* TESTCASE list-key pin-prompt PASS Token pin handling (prompt)"
else
	echo "* TESTCASE list-key pin-prompt FAIL Token pin handling (prompt)"
	status=1
fi

if [ $RC_P11SAK_NOLOGIN = 0 ]; then
	echo "* TESTCASE list-key no-login PASS public session"
else
	echo "* TESTCASE list-key no-login FAIL public session"
	status=1
fi

if [[ -z $PKCS11_SO_PIN ]]; then
	echo "* TESTCASE list-key so-login SKIP SO session"
elif [ $RC_P11SAK_SO = 0 ]; then
	echo "* TESTCASE list-key so-login PASS SO session"
else
	echo "* TESTCASE list-key so-login FAIL SO session"
	status=1
fi

if diff -q $P11SAK_ALL_PINOPT $P11SAK_ALL_PINENV ; then
	echo "* TESTCASE list-key pin-opt-env PASS Token pin opt/env output compare"
else
	echo "* TESTCASE list-key pin-opt-env FAIL Token pin opt/env output compare"
	status=1
fi

if diff -q $P11SAK_ALL_PINOPT $P11SAK_ALL_PINCON ; then
	echo "* TESTCASE list-key pin-opt-prompt PASS Token pin opt/prompt output compare"
else
	echo "* TESTCASE list-key pin-opt-prompt FAIL Token pin opt/prompt output compare"
	status=1
fi


echo "** Now remove temporary output files - "p11sak_test.sh""


rm -f $P11SAK_DES_PRE
rm -f $P11SAK_DES_LONG
rm -f $P11SAK_DES_POST
rm -f $P11SAK_3DES_PRE
rm -f $P11SAK_3DES_LONG
rm -f $P11SAK_3DES_POST
rm -f $P11SAK_GENERIC_PRE
rm -f $P11SAK_GENERIC_LONG
rm -f $P11SAK_GENERIC_POST
rm -f $P11SAK_AES_PRE
rm -f $P11SAK_AES_LONG
rm -f $P11SAK_AES_POST
rm -f $P11SAK_AES_XTS_PRE
rm -f $P11SAK_AES_XTS_LONG
rm -f $P11SAK_AES_XTS_POST
rm -f $P11SAK_RSA_PRE
rm -f $P11SAK_RSA_LONG
rm -f $P11SAK_RSA_POST
rm -f $P11SAK_DH_PRE
rm -f $P11SAK_DH_LONG
rm -f $P11SAK_DH_POST
rm -f $P11SAK_DSA_PRE
rm -f $P11SAK_DSA_LONG
rm -f $P11SAK_DSA_POST
rm -f $P11SAK_EC_PRE
rm -f $P11SAK_EC_LONG
rm -f $P11SAK_EC_POST
rm -f $P11SAK_EC_EDWARDS_PRE
rm -f $P11SAK_EC_EDWARDS_LONG
rm -f $P11SAK_EC_EDWARDS_POST
rm -f $P11SAK_EC_MONTGOMERY_PRE
rm -f $P11SAK_EC_MONTGOMERY_LONG
rm -f $P11SAK_EC_MONTGOMERY_POST
rm -f $P11SAK_IBM_DILITHIUM_PRE
rm -f $P11SAK_IBM_DILITHIUM_LONG
rm -f $P11SAK_IBM_DILITHIUM_POST
rm -f $P11SAK_IBM_KYBER_PRE
rm -f $P11SAK_IBM_KYBER_LONG
rm -f $P11SAK_IBM_KYBER_POST
rm -f $P11SAK_IBM_ML_DSA_PRE
rm -f $P11SAK_IBM_ML_DSA_LONG
rm -f $P11SAK_IBM_ML_DSA_POST
rm -f $P11SAK_IBM_ML_KEM_PRE
rm -f $P11SAK_IBM_ML_KEM_LONG
rm -f $P11SAK_IBM_ML_KEM_POST
rm -f $P11SAK_X509_PRE
rm -f $P11SAK_X509_LONG
rm -f $P11SAK_X509_POST
rm -f $P11SAK_ALL_PINOPT
rm -f $P11SAK_ALL_PINENV
rm -f $P11SAK_ALL_PINCON
rm -f $P11SAK_ALL_NOLOGIN
rm -f $P11SAK_ALL_SO
rm -f export-aes.key
rm -f export-*.pem
rm -f export-*.opaque
rm -f pin*.txt
rm -f oqs-*.pem
rm -f mldsa65-*.pem
rm -f mlkem1024-*.pem
rm -f dilithium3_CA.*
rm -f dilithium3_srv.*
rm -f mldsa65_CA.*
rm -f mldsa65_srv.*
rm -f wrapped-key.pem

echo "** Now remove temporary openssl files from x509 tests - "p11sak_test.sh""
rm -f p11sak_*cert_exported.crt
rm -f p11sak_*cert_exported.pem

echo "** Now DONE testing - 'p11sak_test.sh' - rc = $status"

exit $status
