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
P11SAK_IBM_DILITHIUM_PRE=p11sak-ibm-dilithium-pre.out
P11SAK_IBM_DILITHIUM_LONG=p11sak-ibm-dilithium-long.out
P11SAK_IBM_DILITHIUM_POST=p11sak-ibm-dilithium-post.out
P11SAK_IBM_KYBER_PRE=p11sak-ibm-kyber-pre.out
P11SAK_IBM_KYBER_LONG=p11sak-ibm-kyber-long.out
P11SAK_IBM_KYBER_POST=p11sak-ibm-kyber-post.out
P11SAK_ALL_PINOPT=p11sak-all-pinopt
P11SAK_ALL_PINENV=p11sak-all-pinenv
P11SAK_ALL_PINCON=p11sak-all-pincon
P11SAK_ALL_NOLOGIN=p11sak-all-nologin
P11SAK_ALL_SO=p11sak-all-so
P11SAK_X509_PRE=p11sak-x509-pre.out
P11SAK_X509_LONG=p11sak-x509-long.out
P11SAK_X509_POST=p11sak-x509-post.out


echo "** Setting SLOT=30 to the Softtoken unless otherwise set - 'p11sak_test.sh'"

# setting SLOT=30 to the Softtoken

SLOT=${SLOT:-30}

echo "** Using Slot $SLOT with PKCS11_USER_PIN $PKCS11_USER_PIN and PKCSLIB $PKCSLIB - 'p11sak_test.sh'"


echo "** Now generating keys - 'p11sak_test.sh'"

# generate objects
RC_P11SAK_GENERATE=0

# des
if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_DES_KEY_GEN) ]]; then
	p11sak generate-key des --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-des"
	RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
else
	echo "Skip generating des keys, slot does not support CKM_DES_KEY_GEN"
fi
# 3des
p11sak generate-key 3des --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-3des"
RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
# generic
p11sak generate-key generic 256 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-generic"
RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
# aes [128 | 192 | 256]
p11sak generate-key aes 128 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-128"
RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
p11sak generate-key aes 192 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-192"
RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
p11sak generate-key aes 256 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-256"
RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
# aes-xts [128 | 256]
if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_AES_XTS_KEY_GEN) ]]; then
	if [[ -n $( pkcsconf -t -c $SLOT | grep "Model: EP11") || -n $( pkcsconf -t -c $SLOT | grep "Model: CCA") ]]; then
		# EP11 needs CKA_IBM_PROTKEY_EXTRACTABLE=TRUE and CKA_EXTRACTABLE=FALSE for AES-XTS keys
		# CCA needs CKA_IBM_PROTKEY_EXTRACTABLE=TRUE for AES-XTS keys
		P11SAK_ATTR="--attr xK"
	else
		P11SAK_ATTR=""
	fi
	p11sak generate-key aes-xts 128 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-xts-128" $P11SAK_ATTR
	RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
	p11sak generate-key aes-xts 256 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-xts-256" $P11SAK_ATTR
	RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
else
	echo "Skip generating aes-xts keys, slot does not support CKM_AES_XTS_KEY_GEN"
fi
# rsa [1024 | 2048 | 4096]
p11sak generate-key rsa 1024 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-1024"
RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
p11sak generate-key rsa 2048 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-2048"
RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
p11sak generate-key rsa 4096 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-4096"
RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
# dh ffdhe2048
if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_DH_PKCS_KEY_PAIR_GEN) ]]; then
	p11sak generate-key dh ffdhe2048 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-dh"
	RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
else
	echo "Skip generating dh keys, slot does not support CKM_DH_PKCS_KEY_PAIR_GEN"
fi
# dsa dsa-param.pem
if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_DSA_KEY_PAIR_GEN) ]]; then
	p11sak generate-key dsa $DIR/dsa-param.pem --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-dsa"
	RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
else
	echo "Skip generating dsa keys, slot does not support CKM_DSA_KEY_PAIR_GEN"
fi
# ec [prime256v1 | secp384r1 | secp521r1]
p11sak generate-key ec prime256v1 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-prime256v1"
RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
p11sak generate-key ec secp384r1 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-secp384r1"
RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
p11sak generate-key ec secp521r1 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-secp521r1"
RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
# ibm-dilithium
if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_IBM_DILITHIUM) ]]; then
	p11sak generate-key ibm-dilithium r2_65 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-dilithium"
	RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
else
	echo "Skip generating ibm-dilithium keys, slot does not support CKM_IBM_DILITHIUM"
fi
# ibm-kyber
if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_IBM_KYBER) ]]; then
	p11sak generate-key ibm-kyber r2_1024 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-kyber"
	RC_P11SAK_GENERATE=$((RC_P11SAK_GENERATE + $?))
else
	echo "Skip generating ibm-kyber keys, slot does not support CKM_IBM_KYBER"
fi


echo "** Now list keys and redirect output to pre-files - 'p11sak_test.sh'"

# list objects
RC_P11SAK_LIST=0
p11sak list-key des --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-des" &> $P11SAK_DES_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))
p11sak list-key 3des --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-3des" &> $P11SAK_3DES_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))
p11sak list-key generic --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-generic" &> $P11SAK_GENERIC_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))
p11sak list-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-*" &> $P11SAK_AES_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))
p11sak list-key aes-xts --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-xts-*" &> $P11SAK_AES_XTS_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))
p11sak list-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-*" &> $P11SAK_RSA_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))
p11sak list-key dh --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-dh*" &> $P11SAK_DH_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))
p11sak list-key dsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-dsa*" &> $P11SAK_DSA_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))
p11sak list-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-*" &> $P11SAK_EC_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))
p11sak list-key ibm-dilithium --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-dilithium*" &> $P11SAK_IBM_DILITHIUM_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))
p11sak list-key ibm-kyber --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-kyber*" &> $P11SAK_IBM_KYBER_PRE
RC_P11SAK_LIST=$((RC_P11SAK_LIST + $?))

RC_P11SAK_LIST_LONG=0
p11sak list-key des --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-des" &> $P11SAK_DES_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))
p11sak list-key 3des --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-3des" &> $P11SAK_3DES_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))
p11sak list-key generic --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-generic" &> $P11SAK_GENERIC_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))
p11sak list-key aes --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-aes-*" &> $P11SAK_AES_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))
p11sak list-key aes-xts --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-aes-xts-*" &> $P11SAK_AES_XTS_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))
p11sak list-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-rsa-*" &> $P11SAK_RSA_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))
p11sak list-key dh --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-dh*" &> $P11SAK_DH_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))
p11sak list-key dsa --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-dsa*" &> $P11SAK_DSA_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))
p11sak list-key ec --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-ec-*" &> $P11SAK_EC_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))
p11sak list-key ibm-dilithium --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-ibm-dilithium*" &> $P11SAK_IBM_DILITHIUM_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))
p11sak list-key ibm-kyber --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-ibm-kyber*" &> $P11SAK_IBM_KYBER_LONG
RC_P11SAK_LIST_LONG=$((RC_P11SAK_LIST_LONG + $?))


p11sak list-key all --slot $SLOT --pin $PKCS11_USER_PIN &> $P11SAK_ALL_PINOPT
RC_P11SAK_PINOPT=$?
p11sak list-key all --slot $SLOT &> $P11SAK_ALL_PINENV
RC_P11SAK_PINENV=$?
printf "${PKCS11_USER_PIN}\n" | p11sak list-key all --slot $SLOT --force-pin-prompt | tail -n +2 &> $P11SAK_ALL_PINCON
RC_P11SAK_PINCON=$?

p11sak list-key all --slot $SLOT --no-login &> $P11SAK_ALL_NOLOGIN
RC_P11SAK_NOLOGIN=$?
if [[ -n $PKCS11_SO_PIN ]]; then
	p11sak list-key all --slot $SLOT --pin $PKCS11_SO_PIN --so &> $P11SAK_ALL_SO
	RC_P11SAK_SO=$?
else
	echo "Skip login as SO, PKCS11_SO_PIN is not set"
fi

echo "** Now updating keys - 'p11sak_test.sh'"

RC_P11SAK_UPDATE=0
p11sak set-key-attr aes --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-*" --new-attr "ed" --force
RC_P11SAK_UPDATE=$((RC_P11SAK_UPDATE + $?))
p11sak set-key-attr rsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-*" --new-id "012345" --force
RC_P11SAK_UPDATE=$((RC_P11SAK_UPDATE + $?))


echo "** Now copying keys - 'p11sak_test.sh'"

RC_P11SAK_COPY=0
p11sak copy-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-*" --new-label "p11sak-aes-copied" --new-attr "ED" --force
RC_P11SAK_COPY=$((RC_P11SAK_COPY + $?))


echo "** Now extracting public keys - 'p11sak_test.sh'"

RC_P11SAK_KEY_EXTRACT=0
p11sak extract-pubkey private --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-*" --new-label "p11sak-pubkey-extracted" --force
RC_P11SAK_KEY_EXTRACT=$((RC_P11SAK_KEY_EXTRACT + $?))
p11sak extract-pubkey private --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-dh*" --new-label "p11sak-pubkey-extracted" --force
RC_P11SAK_KEY_EXTRACT=$((RC_P11SAK_KEY_EXTRACT + $?))
p11sak extract-pubkey private --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-dsa*" --new-label "p11sak-pubkey-extracted" --force
RC_P11SAK_KEY_EXTRACT=$((RC_P11SAK_KEY_EXTRACT + $?))
p11sak extract-pubkey private --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-prime256v1*" --new-label "p11sak-pubkey-extracted" --force
RC_P11SAK_KEY_EXTRACT=$((RC_P11SAK_KEY_EXTRACT + $?))
p11sak extract-pubkey private --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-dilithium*" --new-label "p11sak-pubkey-extracted" --force
RC_P11SAK_KEY_EXTRACT=$((RC_P11SAK_KEY_EXTRACT + $?))
p11sak extract-pubkey private --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-kyber*" --new-label "p11sak-pubkey-extracted" --force
RC_P11SAK_KEY_EXTRACT=$((RC_P11SAK_KEY_EXTRACT + $?))


echo "** Now importing keys - 'p11sak_test.sh'"

RC_P11SAK_IMPORT=0
# aes
p11sak import-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label "import-aes" --file $DIR/aes.key --attr sX
RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
# rsa
p11sak import-key rsa private --slot $SLOT --pin $PKCS11_USER_PIN --label "import-rsa-private" --file $DIR/rsa-key.pem --attr sX
RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
p11sak import-key rsa public --slot $SLOT --pin $PKCS11_USER_PIN --label "import-rsa-public" --file $DIR/rsa-key.pem --attr sX
RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
# dsa
if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_DSA) ]]; then
	p11sak import-key dsa private --slot $SLOT --pin $PKCS11_USER_PIN --label "import-dsa-private" --file $DIR/dsa-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	p11sak import-key dsa public --slot $SLOT --pin $PKCS11_USER_PIN --label "import-dsa-public" --file $DIR/dsa-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
else
	echo "Skip importing dsa keys, slot does not support CKM_DSA"
fi
# dh
if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_DH_PKCS_DERIVE) ]]; then
	p11sak import-key dh private --slot $SLOT --pin $PKCS11_USER_PIN --label "import-dh-private" --file $DIR/dh-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	p11sak import-key dh public --slot $SLOT --pin $PKCS11_USER_PIN --label "import-dh-public" --file $DIR/dh-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
else
	echo "Skip importing dh keys, slot does not support CKM_DH_PKCS_DERIVE"
fi
# ec
p11sak import-key ec private --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-prime256v1-private" --file $DIR/ec-key-prime256v1.pem --attr sX
RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
p11sak import-key ec public --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-prime256v1-public" --file $DIR/ec-key-prime256v1.pem --attr sX
RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
p11sak import-key ec private --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-secp521r1-private" --file $DIR/ec-key-secp521r1.pem --attr sX
RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
p11sak import-key ec public --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-secp521r1-public" --file $DIR/ec-key-secp521r1.pem --attr sX
RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
# ibm-dilithium
if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_IBM_DILITHIUM) ]]; then
	p11sak import-key ibm-dilithium private --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ibm-dilithium-private" --file $DIR/ibm-dilithium-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	p11sak import-key ibm-dilithium public --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ibm-dilithium-public" --file $DIR/ibm-dilithium-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
else
	echo "Skip importing ibm-dilithium keys, slot does not support CKM_IBM_DILITHIUM"
fi
# ibm-kyber
if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_IBM_KYBER) ]]; then
	p11sak import-key ibm-kyber private --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ibm-kyber-private" --file $DIR/ibm-kyber-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	p11sak import-key ibm-kyber public --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ibm-kyber-public" --file $DIR/ibm-kyber-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
else
	echo "Skip importing ibm-kyber keys, slot does not support CKM_IBM_KYBER"
fi


echo "** Now exporting keys - 'p11sak_test.sh'"

RC_P11SAK_EXPORT=0
# aes
if [[ -n $( pkcsconf -t -c $SLOT | grep "Model: EP11") || -n $( pkcsconf -t -c $SLOT | grep "Model: CCA") ]]; then
	p11sak export-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label "import-aes" --file export-aes.opaque --force --opaque
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
else
	p11sak export-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label "import-aes" --file export-aes.key --force
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	diff export-aes.key $DIR/aes.key > /dev/null
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
fi
# rsa
if [[ -n $( pkcsconf -t -c $SLOT | grep "Model: EP11") || -n $( pkcsconf -t -c $SLOT | grep "Model: CCA") ]]; then
	p11sak export-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label "import-rsa-public" --file export-rsa-key.pem --force
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	p11sak export-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label "import-rsa-private" --file export-rsa-key.opaque --force --opaque
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
else
	p11sak export-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label "import-rsa-*" --file export-rsa-key.pem --force
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	openssl pkey -in export-rsa-key.pem -check -text > /dev/null
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
fi
openssl pkey -in export-rsa-key.pem -pubin -text > /dev/null
RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
# dsa
if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_DSA) ]]; then
	if [[ -n $( pkcsconf -t -c $SLOT | grep "Model: EP11") || -n $( pkcsconf -t -c $SLOT | grep "Model: CCA") ]]; then
		p11sak export-key dsa --slot $SLOT --pin $PKCS11_USER_PIN --label "import-dsa-public" --file export-dsa-key.pem --force
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		p11sak export-key dsa --slot $SLOT --pin $PKCS11_USER_PIN --label "import-dsa-private" --file export-dsa-key.opaque --force --opaque
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))	
	else
		p11sak export-key dsa --slot $SLOT --pin $PKCS11_USER_PIN --label "import-dsa-*" --file export-dsa-key.pem --force
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
if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_DH_PKCS_DERIVE) ]]; then
	if [[ -n $( pkcsconf -t -c $SLOT | grep "Model: EP11") || -n $( pkcsconf -t -c $SLOT | grep "Model: CCA") ]]; then
		p11sak export-key dh --slot $SLOT --pin $PKCS11_USER_PIN --label "import-dh-public" --file export-dh-key.pem --force
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		p11sak export-key dh --slot $SLOT --pin $PKCS11_USER_PIN --label "import-dh-private" --file export-dh-key.opaque --force --opaque
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	else	
		p11sak export-key dh --slot $SLOT --pin $PKCS11_USER_PIN --label "import-dh-*" --file export-dh-key.pem --force
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
if [[ -n $( pkcsconf -t -c $SLOT | grep "Model: EP11") || -n $( pkcsconf -t -c $SLOT | grep "Model: CCA") ]]; then
	p11sak export-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-prime256v1-public" --file export-ec-prime256v1-key.pem --force
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	p11sak export-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-prime256v1-private" --file export-ec-prime256v1-key.opaque --force --opaque
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	p11sak export-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-secp521r1-public" --file export-ec-secp521r1-key.pem --force
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	p11sak export-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-secp521r1-private" --file export-ec-secp521r1-key.opaque --force --opaque
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
else
	p11sak export-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-prime256v1-*" --file export-ec-prime256v1-key.pem --force
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	openssl pkey -in export-ec-prime256v1-key.pem -check -text > /dev/null
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	p11sak export-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ec-secp521r1-*" --file export-ec-secp521r1-key.pem --force
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	openssl pkey -in export-ec-secp521r1-key.pem -check -text > /dev/null
	RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
fi
openssl pkey -in export-ec-prime256v1-key.pem -pubin -text > /dev/null
RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
openssl pkey -in export-ec-secp521r1-key.pem -pubin -text > /dev/null
RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
# ibm-dilithium
if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_IBM_DILITHIUM) ]]; then
	if [[ -n $( pkcsconf -t -c $SLOT | grep "Model: EP11") || -n $( pkcsconf -t -c $SLOT | grep "Model: CCA") ]]; then
		p11sak export-key ibm-dilithium --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ibm-dilithium-public" --file export-ibm-dilithium-key.pem --force
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		p11sak export-key ibm-dilithium --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ibm-dilithium-private" --file export-ibm-dilithium-key.opaque --force --opaque
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	else
		p11sak export-key ibm-dilithium --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ibm-dilithium-*" --file export-ibm-dilithium-key.pem --force
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	fi
else
	echo "Skip exporting ibm-dilithium keys, slot does not support CKM_IBM_DILITHIUM"
fi
# ibm-kyber
if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_IBM_KYBER) ]]; then
	if [[ -n $( pkcsconf -t -c $SLOT | grep "Model: EP11") || -n $( pkcsconf -t -c $SLOT | grep "Model: CCA") ]]; then
		p11sak export-key ibm-kyber --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ibm-kyber-public" --file export-ibm-kyber-key.pem --force
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
		p11sak export-key ibm-kyber --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ibm-kyber-private" --file export-ibm-kyber-key.opaque --force --opaque
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	else
		p11sak export-key ibm-kyber --slot $SLOT --pin $PKCS11_USER_PIN --label "import-ibm-kyber-*" --file export-ibm-kyber-key.pem --force
		RC_P11SAK_EXPORT=$((RC_P11SAK_EXPORT + $?))
	fi
else
	echo "Skip exporting ibm-kyber keys, slot does not support CKM_IBM_KYBER"
fi


echo "** Now remove keys - 'p11sak_test.sh'"

# remove objects
RC_P11SAK_REMOVE=0
# des
p11sak remove-key des --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-des" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# 3des
p11sak remove-key 3des --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-3des" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# generic
p11sak remove-key generic --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-generic" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# aes [128 | 192 | 256 | copied]
p11sak remove-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-128" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
p11sak remove-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-192" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
p11sak remove-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-256" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
p11sak remove-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-copied" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# aes-xts [128 | 256]
p11sak remove-key aes-xts --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-xts-128" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
p11sak remove-key aes-xts --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-xts-256" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# rsa [1024 | 2048 | 4096]
# remove public key
p11sak remove-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-1024:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
p11sak remove-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-2048:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
p11sak remove-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-4096:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# remove private key
p11sak remove-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-1024:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
p11sak remove-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-2048:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
p11sak remove-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-4096:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# dh
# remove public key
p11sak remove-key dh --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-dh:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# remove private key
p11sak remove-key dh --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-dh:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# dsa 
# remove public key
p11sak remove-key dsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-dsa:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# remove private key
p11sak remove-key dsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-dsa:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# ec [prime256v1 | secp384r1 | secp521r1]
#remove public key
p11sak remove-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-prime256v1:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
p11sak remove-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-secp384r1:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
p11sak remove-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-secp521r1:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# remove private key
p11sak remove-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-prime256v1:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
p11sak remove-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-secp384r1:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
p11sak remove-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-secp521r1:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# remove ibm-dilithium keys
p11sak remove-key ibm-dilithium --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-dilithium:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
p11sak remove-key ibm-dilithium --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-dilithium:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
# remove ibm-kyber keys
p11sak remove-key ibm-kyber --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-kyber:pub" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
p11sak remove-key ibm-kyber --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-kyber:prv" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
p11sak remove-key --slot $SLOT --pin $PKCS11_USER_PIN --label "import*" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
p11sak remove-key --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-pubkey-extracted" -f
RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))


echo "** Now list keys and redirect to post-files - 'p11sak_test.sh'"

# list objects
RC_P11SAK_LIST_POST=0
p11sak list-key des --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-des" &> $P11SAK_DES_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))
p11sak list-key 3des --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-3des" &> $P11SAK_3DES_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))
p11sak list-key generic --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-generic" &> $P11SAK_GENERIC_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))
p11sak list-key aes --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-*" &> $P11SAK_AES_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))
p11sak list-key aes-xts --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-aes-xts-*" &> $P11SAK_AES_XTS_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))
p11sak list-key rsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-rsa-*" &> $P11SAK_RSA_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))
p11sak list-key dh --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-dh*" &> $P11SAK_DH_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))
p11sak list-key dsa --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-dsa*" &> $P11SAK_DSA_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))
p11sak list-key ec --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ec-*" &> $P11SAK_EC_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))
p11sak list-key ibm-dilithium --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-dilithium*" &> $P11SAK_IBM_DILITHIUM_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))
p11sak list-key ibm-kyber --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-ibm-kyber*" &> $P11SAK_IBM_KYBER_POST
RC_P11SAK_LIST_POST=$((RC_P11SAK_LIST_POST + $?))


echo "** Now checking output files to determine PASS/FAIL of tests - 'p11sak_test.sh'"

if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_DES_KEY_GEN) ]]; then
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

if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_DES_KEY_GEN) ]]; then
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

if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_AES_XTS_KEY_GEN) ]]; then
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

if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_DH_PKCS_KEY_PAIR_GEN) ]]; then
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


if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_DSA_KEY_PAIR_GEN) ]]; then
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


if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_IBM_DILITHIUM) ]]; then
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


if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_IBM_KYBER) ]]; then
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


echo "** Import the sample x.509 certificates - 'p11sak_test.sh'"
RC_P11SAK_X509_IMPORT=0
p11sak import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 123 --label "p11sak-x509-rsa2048crt" --file $DIR/p11sak_rsa2048cert.crt
RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
p11sak import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 234 --label "p11sak-x509-rsa2048pem" --file $DIR/p11sak_rsa2048cert.pem
RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
p11sak import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 345 --label "p11sak-x509-rsa4096crt" --file $DIR/p11sak_rsa4096cert.crt
RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
p11sak import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 456 --label "p11sak-x509-rsa4096pem" --file $DIR/p11sak_rsa4096cert.pem
RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
p11sak import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 567 --label "p11sak-x509-ecp256crt" --file $DIR/p11sak_ecp256cert.crt
RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
p11sak import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 678 --label "p11sak-x509-ecp256pem" --file $DIR/p11sak_ecp256cert.pem
RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
p11sak import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 789 --label "p11sak-x509-ecp384crt" --file $DIR/p11sak_ecp384cert.crt
RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
p11sak import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 89A --label "p11sak-x509-ecp384pem" --file $DIR/p11sak_ecp384cert.pem
RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
p11sak import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 789 --label "p11sak-x509-ecp521crt" --file $DIR/p11sak_ecp521cert.crt
RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
p11sak import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 89A --label "p11sak-x509-ecp521pem" --file $DIR/p11sak_ecp521cert.pem
RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_DSA) ]]; then
	p11sak import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 9AB --label "p11sak-x509-dsa3072crt" --file $DIR/p11sak_dsa3072cert.crt
	RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
	p11sak import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id ABC --label "p11sak-x509-dsa3072pem" --file $DIR/p11sak_dsa3072cert.pem
	RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
	p11sak import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id 9AB --label "p11sak-x509-dsa4096crt" --file $DIR/p11sak_dsa4096cert.crt
	RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
	p11sak import-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --id ABC --label "p11sak-x509-dsa4096pem" --file $DIR/p11sak_dsa4096cert.pem
	RC_P11SAK_X509_IMPORT=$((RC_P11SAK_X509_IMPORT + $?))
else
	echo "Skip importing x.509 certs with DSA key, slot does not support CKM_DSA"
fi


echo "** Now exporting x.509 certificates - 'p11sak_test.sh'"
RC_P11SAK_X509_EXPORT=0
# x.509
p11sak export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-rsa2048crt" --file p11sak_rsa2048cert_exported.crt --der --force
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
p11sak export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-rsa2048pem" --file p11sak_rsa2048cert_exported.pem --force
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
p11sak export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-rsa4096crt" --file p11sak_rsa4096cert_exported.crt --der --force
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
p11sak export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-rsa4096pem" --file p11sak_rsa4096cert_exported.pem --force
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
p11sak export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ecp256crt" --file p11sak_ecp256cert_exported.crt --der --force
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
p11sak export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ecp256pem" --file p11sak_ecp256cert_exported.pem --force
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
p11sak export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ecp384crt" --file p11sak_ecp384cert_exported.crt --der --force
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
p11sak export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ecp384pem" --file p11sak_ecp384cert_exported.pem --force
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
p11sak export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ecp521crt" --file p11sak_ecp521cert_exported.crt --der --force
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
p11sak export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ecp521pem" --file p11sak_ecp521cert_exported.pem --force
RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_DSA) ]]; then
	p11sak export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-dsa3072crt" --file p11sak_dsa3072cert_exported.crt --der --force
	RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
	p11sak export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-dsa3072pem" --file p11sak_dsa3072cert_exported.pem --force
	RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
	p11sak export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-dsa4096crt" --file p11sak_dsa4096cert_exported.crt --der --force
	RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
	p11sak export-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-dsa4096pem" --file p11sak_dsa4096cert_exported.pem --force
	RC_P11SAK_X509_EXPORT=$((RC_P11SAK_X509_EXPORT + $?))
else
	echo "Skip exporting x.509 certs with DSA key, slot does not support CKM_DSA"
fi


echo "** Now extracting public keys from x.509 certificates - 'p11sak_test.sh'"
RC_P11SAK_X509_EXTRACT=0
p11sak extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-rsa2048crt" --force
RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
p11sak extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-rsa2048pem" --force
RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
p11sak extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-rsa4096crt" --force
RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
p11sak extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-rsa4096pem" --force
RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
p11sak extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ecp256crt" --force
RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
p11sak extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ecp256pem" --force
RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
p11sak extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ecp384crt" --force
RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
p11sak extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ecp384pem" --force
RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
p11sak extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ecp521crt" --force
RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
p11sak extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-ecp521pem" --force
RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_DSA) ]]; then
	p11sak extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-dsa3072crt" --force
	RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
	p11sak extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-dsa3072pem" --force
	RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
	p11sak extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-dsa4096crt" --force
	RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
	p11sak extract-cert-pubkey x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-dsa4096pem" --force
	RC_P11SAK_X509_EXTRACT=$((RC_P11SAK_X509_EXTRACT + $?))
else
	echo "Skip extracting pubkeys from x.509 certs with DSA key, slot does not support CKM_DSA"
fi


echo "** Now copying x.509 certificates to new token objects - 'p11sak_test.sh'"
RC_P11SAK_X509_COPY=0
p11sak copy-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-*" --new-label "p11sak-x509-copied" --force
RC_P11SAK_X509_COPY=$((RC_P11SAK_X509_COPY + $?))


echo "** Now updating x.509 certs - 'p11sak_test.sh'"
RC_P11SAK_X509_UPDATE=0
p11sak set-cert-attr x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-*" --new-attr "Yt" --force
RC_P11SAK_X509_UPDATE=$((RC_P11SAK_X509_UPDATE + $?))
p11sak set-cert-attr x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-*" --new-id "012345" --force
RC_P11SAK_X509_UPDATE=$((RC_P11SAK_X509_UPDATE + $?))


echo "** Now list x509 certificates and extracted pubkeys and redirect output to pre-files - 'p11sak_test.sh'"
RC_P11SAK_X509_LIST=0
p11sak list-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-*" --sort n:a &> $P11SAK_X509_PRE
RC_P11SAK_X509_LIST=$((RC_P11SAK_X509_LIST + $?))
p11sak list-key all --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-*" &>> $P11SAK_X509_PRE
RC_P11SAK_X509_LIST=$((RC_P11SAK_X509_LIST + $?))

RC_P11SAK_X509_LIST_LONG=0
p11sak list-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-x509-*" --sort l:d,n:a &> $P11SAK_X509_LONG
RC_P11SAK_X509_LIST_LONG=$((RC_P11SAK_X509_LIST_LONG + $?))
p11sak list-key all --slot $SLOT --pin $PKCS11_USER_PIN --long --label "p11sak-x509-*" &>> $P11SAK_X509_LONG
RC_P11SAK_X509_LIST_LONG=$((RC_P11SAK_X509_LIST_LONG + $?))

echo "** Now removing x.509 certificates and extracted public keys - 'p11sak_test.sh'"
# x.509
RC_P11SAK_X509_REMOVE=0
p11sak remove-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-*" -f
RC_P11SAK_X509_REMOVE=$((RC_P11SAK_X509_REMOVE + $?))
p11sak remove-key --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-*" -f
RC_P11SAK_X509_REMOVE=$((RC_P11SAK_X509_REMOVE + $?))


echo "** Now list certificates and extracted keys and redirect to post-files - 'p11sak_test.sh'"
# list objects: if remove was successful above, no certs and extracted keys are left
RC_P11SAK_X509_LIST_POST=0
p11sak list-cert x509 --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-*" --sort n:d,l:a &> $P11SAK_X509_POST
RC_P11SAK_X509_LIST_POST=$((RC_P11SAK_X509_LIST_POST + $?))
p11sak list-key all --slot $SLOT --pin $PKCS11_USER_PIN --label "p11sak-x509-*" &> $P11SAK_X509_POST
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
if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_DSA) ]]; then
	diff $DIR/p11sak_dsa3072cert.crt p11sak_dsa3072cert_exported.crt > /dev/null
	RC_P11SAK_X509_DIFF=$((RC_P11SAK_X509_DIFF + $?))
	diff $DIR/p11sak_dsa3072cert.pem p11sak_dsa3072cert_exported.pem > /dev/null
	RC_P11SAK_X509_DIFF=$((RC_P11SAK_X509_DIFF + $?))
	diff $DIR/p11sak_dsa4096cert.crt p11sak_dsa4096cert_exported.crt > /dev/null
	RC_P11SAK_X509_DIFF=$((RC_P11SAK_X509_DIFF + $?))
	diff $DIR/p11sak_dsa4096cert.pem p11sak_dsa4096cert_exported.pem > /dev/null
	RC_P11SAK_X509_DIFF=$((RC_P11SAK_X509_DIFF + $?))
else
	echo "Skip comparing exported x.509 certs with original certs, slot does not support CKM_DSA"
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

# DSA-3072
if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_DSA) ]]; then
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
if [[ -n $( pkcsconf -m -c $SLOT | grep CKM_DSA) ]]; then
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
rm -f $P11SAK_IBM_DILITHIUM_PRE
rm -f $P11SAK_IBM_DILITHIUM_LONG
rm -f $P11SAK_IBM_DILITHIUM_POST
rm -f $P11SAK_IBM_KYBER_PRE
rm -f $P11SAK_IBM_KYBER_LONG
rm -f $P11SAK_IBM_KYBER_POST
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

echo "** Now remove temporary openssl files from x509 tests - "p11sak_test.sh""
rm -f p11sak_*cert_exported.crt
rm -f p11sak_*cert_exported.pem

echo "** Now DONE testing - 'p11sak_test.sh' - rc = $status"

exit $status
