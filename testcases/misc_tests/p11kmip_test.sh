#!/bin/bash
#
# COPYRIGHT (c) International Business Machines Corp. 2020
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this software
# constitutes recipient's acceptance of CPL-1.0 terms which can be found
# in the file LICENSE file or at https://opensource.org/licenses/cpl1.0.php

# sudo -E ./p11kmip_test.sh

# In order to invoke this test script, the following required environment variables 
# must be specified:
# - PKCS11_USER_PIN     : the user PIN number for the chosen PKCS#11 slot (default slot 30)
# - PKCSLIB             : path to the PKCS#11 library
# - KMIP_IP             : the IP address of the KMIP server to use for testing
# - KMIP_REST_USER      : the username to use for authenticating to the 
#                         KMIP server REST interface
# - KMIP_REST_PASSWORD	: the password to use for authenticating to the 
#                         KMIP server REST inferface
#
# Additionally, the following optional environment variables may be specified to
# override certain default values:
# - PKCS11_SLOT_ID      : the PKCS#11 slot number to use for testing. Defaults to 30.
# - KMIP_REST_URL       : the fully-qualified URL to use for the KMIP server REST 
#                         interface. Defaults to https://${KMIP_IP}:19443
# - KMIP_HOSTNAME       : the hostname to be used for the KMIP protocol connection.
#                         Defaults to ${KMIP_IP}:5696

DIR=$(dirname "$0")

status=0

# Validate required environment variables
if [[ -z "${PKCS11_USER_PIN}" ]]; then
	echo "Please set the PKCS11_USER_PIN environment variable"
	exit 1
fi

if [[ -z "${PKCSLIB}" ]]; then
	echo "Please set the PKCSLIB environment variable"
	exit 1
fi

if [[ -z "${KMIP_IP}" ]]; then
	echo "Please set the KMIP_IP environment variable"
	exit 1
fi

if [[ -z "${KMIP_REST_USER}" ]]; then
	echo "Please set the KMIP_REST_USER environment variable"
	exit 1
fi

if [[ -z "${KMIP_REST_PASSWORD}" ]]; then
	echo "Please set the KMIP_REST_PASSWORD environment variable"
	exit 1
fi

echo "** Now executing 'p11kmip_test.sh'"

P11KMIP_TMP="/tmp/p11kmip"
P11KMIP_UNIQUE_NAME="$(uname -n)-$(date +%s)"
P11KMIP_UNIQUE_NAME="${P11KMIP_UNIQUE_NAME^^}"
KMIP_CLIENT_NAME="$(echo ${P11KMIP_UNIQUE_NAME^^} | sed -r 's/[ .,;:#+*$%-]+/_/g')_CLIENT"
KMIP_CERT_ALIAS="$(echo ${P11KMIP_UNIQUE_NAME^^} | sed -r 's/[ .,;:#+*$%-]+/_/g')_CERT"

KMIP_SECRET_KEY_LABEL="remote-secret-key-${P11KMIP_UNIQUE_NAME}"
PKCS11_SECRET_KEY_LABEL="local-secret-key-${P11KMIP_UNIQUE_NAME}"
PKCS11_PUBLIC_KEY_LABEL="local-public-key-${P11KMIP_UNIQUE_NAME}"
PKCS11_PRIVATE_KEY_LABEL="local-private-key-${P11KMIP_UNIQUE_NAME}"

P11KMIP_CONF_FILE="${P11KMIP_TMP}/p11kmip.conf"

# Prepare PKCS11 variables
echo "** Setting SLOT=30 to the Softtoken unless otherwise set - 'p11kmip_test.sh'"

PKCS11_SLOT_ID=${PKCS11_SLOT_ID:-30}

echo "** Using Slot $PKCS11_SLOT_ID with PKCS11_USER_PIN $PKCS11_USER_PIN and PKCSLIB $PKCSLIB - 'p11kmip_test.sh'"

# Prepare KMIP variables
echo "** Setting KMIP_REST_URL=https://\${KMIP_IP}:19443 unless otherwise set - 'p11kmip_test.sh'"
echo "** Setting KMIP_SERVER=\${KMIP_IP}:5696 unless otherwise set - 'p11kmip_test.sh'"

KMIP_REST_URL="${KMIP_REST_URL:-https://${KMIP_IP}:19443}"
KMIP_HOSTNAME="${KMIP_SERVER:-${KMIP_IP}:5696}"

echo "Dirpath: $DIR"
KMIP_CLIENT_CERT=$P11KMIP_TMP/${P11KMIP_UNIQUE_NAME}_p11kmip_client_cert.pem
KMIP_CLIENT_KEY=$P11KMIP_TMP/${P11KMIP_UNIQUE_NAME}_p11kmip_client_key.pem

echo "** Using KMIP server $KMIP_REST_URL with KMIP_REST_USER $KMIP_REST_USER and KMIP_REST_PASSWORD ************"

mkdir -p $P11KMIP_TMP

generate_certificates() {
	openssl req -x509 -newkey rsa:4096 -keyout "$KMIP_CLIENT_KEY" -out "$KMIP_CLIENT_CERT" -nodes -days 3650 -subj '/CN=www.mydom.com/O=My Company Name LTD./C=US'
}

setup_kmip_client() {
  RETRY_COUNT=0
  UPLOAD_CERT_DONE=0
  CREATE_CLIENT_DONE=0
  ASSIGN_CERT_DONE=0

  while true; do
		if [[ $RETRY_COUNT -gt 100 ]] ; then
			RC=1
			echo "error: Too many login retries"
			break
		fi
		RETRY_COUNT=$((RETRY_COUNT+1))

		# Get a login authorization ID from SKLM
		curl --fail-with-body --location --request POST "$KMIP_REST_URL/SKLM/rest/v1/ckms/login" \
			--header "Content-Type: application/json" \
			--data "{\"userid\":\"$KMIP_REST_USER\", \"password\":\"$KMIP_REST_PASSWORD\"}" \
			--insecure --silent --show-error >$P11KMIP_TMP/curl_get_login_authid_stdout 2>$P11KMIP_TMP/curl_get_login_authid_stderr
		RC=$?
		echo "rc:" $RC
		if [[ $RC -ne 0 ]] ; then
			RC=1
			cat $P11KMIP_TMP/curl_get_login_authid_stdout
			cat $P11KMIP_TMP/curl_get_login_authid_stderr
			break
		fi

		# Parse the response data and extract the authorization id token
		# Expected to return: {"UserAuthId":"xxxxxx"}
		AUTHID=`jq .UserAuthId $P11KMIP_TMP/curl_get_login_authid_stdout -r`
		echo "AuthID:" $AUTHID
		echo "succeeded: curl_get_login_authid"

		# Upload the client certificate to SKLM
		if [[ $UPLOAD_CERT_DONE -eq 0 ]] ; then
			curl --fail-with-body --location --request POST "$KMIP_REST_URL/SKLM/rest/v1/filetransfer/upload/objectfiles" \
				--header "accept: application/json" --header "Content-Type: multipart/form-data" \
				--form "fileToUpload=@$KMIP_CLIENT_CERT" --form "destination=" --header "Authorization:SKLMAuth userAuthId=$AUTHID" \
				--insecure --silent --show-error >$P11KMIP_TMP/curl_upload_cert_stdout 2>$P11KMIP_TMP/curl_upload_cert_stderr
			RC=$?
			echo "rc:" $RC

			# Expected to return: {"code":"0","status":"CTGKM3465I File xxxx is uploaded.","messageId":"CTGKM3465I"}
			RSN=`jq .code $P11KMIP_TMP/curl_upload_cert_stdout -r`
			MSG=`jq .status $P11KMIP_TMP/curl_upload_cert_stdout -r`
			if [[ "$RSN" == "CTGKM6004E" ]]; then
				echo "warning: Login token expired, re-login and retry"
				continue
			fi
			if [[ "$MSG" == "CTGKM3466E Cannot upload the file $(basename $KMIP_CLIENT_CERT) because a file with the same name already exists on the server." ]]; then
				RC=1
				echo "info: Client certificate already uploaded to server"
				break
			fi
			if [[ "$MSG" != "CTGKM3465I File $(basename $KMIP_CLIENT_CERT) is uploaded." ]]; then
				RC=1
				echo "error: Status not as expected"
				cat $P11KMIP_TMP/curl_upload_cert_stdout
				cat $P11KMIP_TMP/curl_upload_cert_stderr
				break
			fi
			UPLOAD_CERT_DONE=1
			echo "succeeded: curl_upload_cert"
		fi

		# Create a client in SKLM
		if [[ $CREATE_CLIENT_DONE -eq 0 ]] ; then
			echo "clientname:" $KMIP_CLIENT_NAME

			curl --fail-with-body --location --request POST "$KMIP_REST_URL/SKLM/rest/v1/clients" \
				--header "Content-Type: application/json" \
				--data "{\"clientName\":\"$KMIP_CLIENT_NAME\"}" \
				--header "Authorization:SKLMAuth userAuthId=$AUTHID" \
				--insecure --silent --show-error >$P11KMIP_TMP/curl_create_client_stdout 2>$P11KMIP_TMP/curl_create_client_stderr
			RC=$?
			echo "rc:" $RC

			# Expected to return: {"message":"CTGKM3411I Successfully created client xxxx .","messageId":"CTGKM3411I"}
			MSG=`jq .message $P11KMIP_TMP/curl_create_client_stdout -r`
			if [[ "$MSG" == "CTGKM6004E User is not authenticated or has already logged out." ]]; then
				echo "warning: Login token expired, re-login and retry"
				continue
			fi
			if [[ "$MSG" != "CTGKM3411I Successfully created client $KMIP_CLIENT_NAME ." ]]; then
				RC=1
				echo "error: Message not as expected"
				cat $P11KMIP_TMP/curl_create_client_stdout
				cat $P11KMIP_TMP/curl_create_client_stderr
				break
			fi
			CREATE_CLIENT_DONE=1
			echo "succeeded: curl_create_client"
		fi

		# Assign the certificate with the client
		if [[ $ASSIGN_CERT_DONE -eq 0 ]] ; then
			curl --fail-with-body --location --request PUT "$KMIP_REST_URL/SKLM/rest/v1/clients/$KMIP_CLIENT_NAME/assignCertificate" \
				--header "Content-Type: application/json" \
				--data "{\"certUseOption\":\"IMPORT_CERT\",\"certAlias\":\"$KMIP_CERT_ALIAS\",\"importPath\":\"$(basename $KMIP_CLIENT_CERT)\"}" \
				--header "Authorization:SKLMAuth userAuthId=$AUTHID" \
				--insecure --silent --show-error >$P11KMIP_TMP/curl_assign_cert_stdout 2>$P11KMIP_TMP/curl_assign_cert_stderr
			RC=$?
			echo "rc:" $RC

			# Expected to return: {"message":"CTGKM3409I Successfully assigned certificate to client.","messageId":"CTGKM3409I"}
			MSG=`jq .message $P11KMIP_TMP/curl_assign_cert_stdout -r`
			if [[ "$MSG" == "CTGKM6004E User is not authenticated or has already logged out." ]]; then
				echo "warning: Login token expired, re-login and retry"
				continue
			fi
			if [[ "$MSG" != "CTGKM3409I Successfully assigned certificate to client." ]]; then
				RC=1
				echo "error: Message not as expected"
				cat $P11KMIP_TMP/curl_assign_cert_stdout
				cat $P11KMIP_TMP/curl_assign_cert_stderr
				break
			fi
			ASSIGN_CERT_DONE=1
			echo "succeeded: curl_assign_cert"
		fi

		break
	done
}

setup_pkcs11_keys() {
	# AES key for exporting
	p11sak import-key aes --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label "$PKCS11_SECRET_KEY_LABEL-conf" --file $DIR/aes.key --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	p11sak import-key aes --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label "$PKCS11_SECRET_KEY_LABEL-conf.2" --file $DIR/aes-128.key --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	p11sak import-key aes --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label "$PKCS11_SECRET_KEY_LABEL-conf.3" --file $DIR/aes-192.key --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	p11sak import-key aes --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label "$PKCS11_SECRET_KEY_LABEL-env" --file $DIR/aes.key --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	p11sak import-key aes --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label "$PKCS11_SECRET_KEY_LABEL-opt" --file $DIR/aes.key --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))

	# RSA keys for wrapping and importing
	p11sak import-key rsa private --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label $PKCS11_PRIVATE_KEY_LABEL --file $DIR/rsa-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))
	p11sak import-key rsa public --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label $PKCS11_PUBLIC_KEY_LABEL --file $DIR/rsa-key.pem --attr sX
	RC_P11SAK_IMPORT=$((RC_P11SAK_IMPORT + $?))

	echo "*** pkcs11 keys after import"
	p11sak list-key --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN
}

cleanup_pkcs11_keys() {
	# AES key for exporting
	p11sak remove-key aes --force --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label "$PKCS11_SECRET_KEY_LABEL-conf"
	RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
	p11sak remove-key aes --force --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label "$PKCS11_SECRET_KEY_LABEL-conf.2"
	RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
	p11sak remove-key aes --force --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label "$PKCS11_SECRET_KEY_LABEL-conf.3"
	RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
	p11sak remove-key aes --force --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label "$PKCS11_SECRET_KEY_LABEL-env"
	RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
	p11sak remove-key aes --force --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label "$PKCS11_SECRET_KEY_LABEL-opt"
	RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))

	# RSA keys for wrapping and importing
	p11sak remove-key rsa --force --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label $PKCS11_PRIVATE_KEY_LABEL
	RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
	p11sak remove-key rsa --force --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label $PKCS11_PUBLIC_KEY_LABEL
	RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))

	# Keys imported during test
	p11sak remove-key aes --force --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label $KMIP_SECRET_KEY_LABEL
	RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
	p11sak remove-key aes --force --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label "$KMIP_SECRET_KEY_LABEL.2"
	RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
	p11sak remove-key aes --force --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label "$KMIP_SECRET_KEY_LABEL.3"
	RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))
	p11sak remove-key rsa --force --slot $PKCS11_SLOT_ID --pin $PKCS11_USER_PIN --label $KMIP_PUBLIC_KEY_LABEL
	RC_P11SAK_REMOVE=$((RC_P11SAK_REMOVE + $?))


}

setup_kmip_keys() {
  RETRY_COUNT=0
  GET_LOGIN_TOKEN_DONE=1
  GEN_ASYM_KEY_DONE=0
  GEN_SYM_KEY_DONE=0
  GET_PUB_KEY_DONE=0

  while true; do
		if [[ $RETRY_COUNT -gt 100 ]] ; then
			RC_PKMIP_GENERATE=1
			echo "error: Too many login retries"
			break
		fi
		RETRY_COUNT=$((RETRY_COUNT+1))

		if [[ $GET_LOGIN_TOKEN_DONE -eq 0 ]] ; then
			# Get a login authorization ID from SKLM
			curl --fail-with-body --location --request POST "$KMIP_REST_URL/SKLM/rest/v1/ckms/login" \
				--header "Content-Type: application/json" \
				--data "{\"userid\":\"$KMIP_REST_USER\", \"password\":\"$KMIP_REST_PASSWORD\"}" \
				--insecure --silent --show-error >$P11KMIP_TMP/curl_get_login_authid_stdout 2>$P11KMIP_TMP/curl_get_login_authid_stderr
			RC=$?
			echo "rc:" $RC
			if [[ $RC -ne 0 ]] ; then
				RC_PKMIP_GENERATE=1
				cat $P11KMIP_TMP/curl_get_login_authid_stdout
				cat $P11KMIP_TMP/curl_get_login_authid_stderr
				break
			fi

			# Parse the response data and extract the authorization id token
			# Expected to return: {"UserAuthId":"xxxxxx"}
			AUTHID=`jq .UserAuthId $P11KMIP_TMP/curl_get_login_authid_stdout -r`
			echo "AuthID:" $AUTHID
			echo "succeeded: curl_get_login_authid"

			GET_LOGIN_TOKEN_DONE=1
		fi

		if [[ $GEN_ASYM_KEY_DONE -eq 0 ]] ; then
			curl --fail-with-body --location --request POST "$KMIP_REST_URL/SKLM/rest/v1/objects/keypair" \
				--header "accept: application/json" --header "Content-Type: application/json" \
				--data "{\"clientName\":\"$KMIP_CLIENT_NAME\", \"prefixName\":\"tst\", \"numberOfObjects\": \"1\", \"publicKeyCryptoUsageMask\":\"Wrap_Unwrap\", \"privateKeyCryptoUsageMask\":\"Wrap_Unwrap\"}" \
				--header "Authorization:SKLMAuth userAuthId=$AUTHID" \
				--insecure --silent --show-error >$P11KMIP_TMP/curl_generate_asym_keys_stdout 2>$P11KMIP_TMP/curl_generate_asym_keys_stderr
			RC=$?
			echo "rc:" $RC

			RSN=`jq .code $P11KMIP_TMP/curl_generate_asym_keys_stdout -r`
			if [[ "$RSN" == "CTGKM6004E" ]]; then
				echo "warning: Login token expired, re-login and retry"
				GET_LOGIN_TOKEN_DONE=0
				continue
			fi

			if [[ $RC -ne 0 ]] ; then
				RC_PKMIP_GENERATE=1
				cat $P11KMIP_TMP/curl_generate_asym_keys_stdout
				cat $P11KMIP_TMP/curl_generate_asym_keys_stderr
				break
			fi

			KMIP_PUBLIC_KEY_ID=`jq .publicKeyId $P11KMIP_TMP/curl_generate_asym_keys_stdout -r`
			KMIP_PRIVATE_KEY_ID=`jq .privateKeyId $P11KMIP_TMP/curl_generate_asym_keys_stdout -r`

			echo "succeeded: curl_generate_asym_keys"
			GEN_ASYM_KEY_DONE=1
		fi

		if [[ $GEN_SYM_KEY_DONE -eq 0 ]] ; then
			curl --fail-with-body --location --request POST "$KMIP_REST_URL/SKLM/rest/v1/objects/symmetrickey" \
				--header "accept: application/json" --header "Content-Type: application/json" \
				--data "{\"clientName\":\"$KMIP_CLIENT_NAME\", \"prefixName\":\"tst\", \"numberOfObjects\": \"1\", \"cryptoUsageMask\":\"Encrypt_Decrypt\"}" \
				--header "Authorization:SKLMAuth userAuthId=$AUTHID" \
				--insecure --silent --show-error >$P11KMIP_TMP/curl_generate_sym_key_stdout 2>$P11KMIP_TMP/curl_generate_sym_key_stderr
			RC=$?
			echo "rc:" $RC

			RSN=`jq .code $P11KMIP_TMP/curl_generate_sym_key_stdout -r`
			if [[ "$RSN" == "CTGKM6004E" ]]; then
				echo "warning: Login token expired, re-login and retry"
				GET_LOGIN_TOKEN_DONE=0
				continue
			fi

			if [[ $RC -ne 0 ]] ; then
				RC_PKMIP_GENERATE=1
				cat $P11KMIP_TMP/curl_generate_sym_key_stdout
				cat $P11KMIP_TMP/curl_generate_sym_key_stderr
				break
			fi

			KMIP_SECKEY_ID=`jq .id $P11KMIP_TMP/curl_generate_sym_key_stdout -r`

			echo "succeeded: curl_generate_sym_keys"
			GEN_SYM_KEY_DONE=1
		fi

		if [[ $GET_PUB_KEY_DONE -eq 0 ]] ; then
			curl --fail-with-body --location --request GET "$KMIP_REST_URL/SKLM/rest/v1/objects/$KMIP_PUBLIC_KEY_ID" \
				--header "accept: application/json" --header "Content-Type: application/json" \
				--header "Authorization:SKLMAuth userAuthId=$AUTHID" \
				--insecure --silent --show-error >$P11KMIP_TMP/curl_get_pubkey_stdout 2>$P11KMIP_TMP/curl_get_pubkey_stderr
			RC=$?
			echo "rc:" $RC

			RSN=`jq .code $P11KMIP_TMP/curl_get_pubkey_stdout -r`
			if [[ "$RSN" == "CTGKM6004E" ]]; then
				echo "warning: Login token expired, re-login and retry"
				GET_LOGIN_TOKEN_DONE=0
				continue
			fi

			if [[ $RC -ne 0 ]] ; then
				RC_PKMIP_GENERATE=1
				cat $P11KMIP_TMP/curl_get_pubkey_stdout
				cat $P11KMIP_TMP/curl_get_pubkey_stderr
				break
			fi

			KMIP_PUBLIC_KEY_LABEL=`jq .managedObject.alias $P11KMIP_TMP/curl_get_pubkey_stdout -r`
			KMIP_PUBLIC_KEY_LABEL=${KMIP_PUBLIC_KEY_LABEL:1:21}

			echo "succeeded: curl_get_pubkey_stdout"
			GET_PUB_KEY_DONE=1
		fi

		echo "*** kmip keys after creation"
		echo "**** kmip pubkey id: ${KMIP_PUBLIC_KEY_ID}"
		echo "**** kmip privkey id: ${KMIP_PRIVATE_KEY_ID}"
		echo "**** kmip pubkey label: ${KMIP_PUBLIC_KEY_LABEL}"

		break
	 done
}

compare_digests() {
	TEST_BASE="$1"
	TEST_STDOUT="${TEST_BASE}_stdout"

	cat "$TEST_STDOUT" | grep -A 5 "Secret Key" | grep "PKCS#11 Digest" | cut -c 22- > "${TEST_BASE}_pkcs_digest"
	cat "$TEST_STDOUT" | grep -A 5 "Secret Key" | grep "KMIP Digest" | cut -c 22- > "${TEST_BASE}_kmip_digest"

	diff -q "${TEST_BASE}_pkcs_digest" "${TEST_BASE}_kmip_digest"

	return $?
}

key_import_tests() {
	################################################################
	# Using configuration file options                             #
	################################################################

	# Build a standard configuration
	[[ -f $P11KMIP_CONF_FILE ]] && rm $P11KMIP_CONF_FILE
	echo "kmip {                                              " >> $P11KMIP_CONF_FILE
	echo "    host = \"${KMIP_HOSTNAME}\"                     " >> $P11KMIP_CONF_FILE
	echo "    tls_client_cert = \"${KMIP_CLIENT_CERT}\"       " >> $P11KMIP_CONF_FILE
	echo "    tls_client_key = \"${KMIP_CLIENT_KEY}\"         " >> $P11KMIP_CONF_FILE
	echo "                                                    " >> $P11KMIP_CONF_FILE
	echo "    wrap_key_format = \"PKCS1\"                     " >> $P11KMIP_CONF_FILE
	echo "    wrap_key_algorithm = \"RSA\"                    " >> $P11KMIP_CONF_FILE
	echo "    wrap_key_size = 2048                            " >> $P11KMIP_CONF_FILE
	echo "    wrap_padding_method = \"PKCS1.5\"               " >> $P11KMIP_CONF_FILE
	echo "}                                                   " >> $P11KMIP_CONF_FILE
	echo "pkcs11 {                                            " >> $P11KMIP_CONF_FILE
	echo "    slot = ${PKCS11_SLOT_ID}                        " >> $P11KMIP_CONF_FILE
	echo "}                                                   " >> $P11KMIP_CONF_FILE

	echo "*** Running test using configuration options"
	TEST_BASE="$P11KMIP_TMP/p11kmip_import_key_conf_test"

	P11KMIP_CONF_FILE="$P11KMIP_CONF_FILE" \
	p11kmip import-key \
		--send-wrapkey \
		--gen-targkey \
		--pin $PKCS11_USER_PIN  \
		--targkey-label $KMIP_SECRET_KEY_LABEL \
		--targkey-id "012345678" \
		--targkey-attrs "sX" \
		--wrapkey-label $PKCS11_PUBLIC_KEY_LABEL \
		--unwrapkey-label $PKCS11_PRIVATE_KEY_LABEL \
		--tls-no-verify-server-cert \
		--tls-trust-server-cert \
		>"${TEST_BASE}_stdout" 2>"${TEST_BASE}_stderr"

	RC=$?
	echo "rc = $RC"
	echo "stdout:"
	cat ${TEST_BASE}_stdout

	if [[ $RC -ne 0 ]] ; then
		echo "stderr:"
		cat "${TEST_BASE}_stderr"
		echo "* TESTCASE p11kmip_test import-key-conf FAIL Failed to import keys using config file"
		return
	fi
	echo "* TESTCASE p11kmip_test import-key-conf PASS Sucessfully imported keys using config file"

	# Store the UID of the KMIP public and secret key just created
	KMIP_GEND_TARGKEY_UID=$(cat $P11KMIP_TMP/p11kmip_import_key_conf_test_stdout | grep -A 2 "Secret Key" | tail -n 1 | cut -d . -f 9)
	KMIP_SENT_WRAPKEY_UID=$(cat $P11KMIP_TMP/p11kmip_import_key_conf_test_stdout | grep -A 2 "Public Key" | tail -n 1 | cut -d . -f 9)

	echo "*** Running import test using configuration options with 128-bit key"
	TEST_BASE="$P11KMIP_TMP/p11kmip_import_key_conf_test_128"

	P11KMIP_CONF_FILE="$P11KMIP_CONF_FILE" \
	p11kmip import-key \
		--gen-targkey \
		--targkey-length 128 \
		--pin $PKCS11_USER_PIN  \
		--targkey-label "$KMIP_SECRET_KEY_LABEL.2" \
		--wrapkey-label $PKCS11_PUBLIC_KEY_LABEL \
		--unwrapkey-label $PKCS11_PRIVATE_KEY_LABEL \
		--tls-no-verify-server-cert \
		--tls-trust-server-cert \
		>"${TEST_BASE}_stdout" 2>"${TEST_BASE}_stderr"

	RC=$?
	echo "rc = $RC"
	echo "stdout:"
	cat "${TEST_BASE}_stdout"

	if [[ $RC -ne 0 ]] ; then
		echo "stderr:"
		cat "${TEST_BASE}_stderr"
		echo "* TESTCASE p11kmip_test import-key-conf-128 FAIL Failed to import AES-128 keys using config file"
		return
	fi
	echo "* TESTCASE p11kmip_test import-key-conf-128 PASS Sucessfully imported AES-128 keys using config file"

	# Store the UID of the KMIP public and secret key just created
	KMIP_GEND_TARGKEY2_UID=$(cat "${TEST_BASE}_stdout" | grep -A 2 "Secret Key" | tail -n 1 | cut -d . -f 9)

	echo "*** Running import test using configuration options with 192-bit key"
	TEST_BASE="$P11KMIP_TMP/p11kmip_import_key_conf_test_192"

	P11KMIP_CONF_FILE="$P11KMIP_CONF_FILE" \
	p11kmip import-key \
		--gen-targkey \
		--targkey-length 192 \
		--pin $PKCS11_USER_PIN  \
		--targkey-label "$KMIP_SECRET_KEY_LABEL.3" \
		--wrapkey-label $PKCS11_PUBLIC_KEY_LABEL \
		--unwrapkey-label $PKCS11_PRIVATE_KEY_LABEL \
		--tls-no-verify-server-cert \
		--tls-trust-server-cert \
		>"${TEST_BASE}_stdout" 2>"${TEST_BASE}_stderr"

	RC=$?
	echo "rc = $RC"
	echo "stdout:"
	cat "${TEST_BASE}_stdout"

	if [[ $RC -ne 0 ]] ; then
		echo "stderr:"
		cat "${TEST_BASE}_stderr"
		echo "* TESTCASE p11kmip_test import-key-conf-192 FAIL Failed to import AES-192 keys using config file"
		return
	fi
	echo "* TESTCASE p11kmip_test import-key-conf-196 PASS Sucessfully imported AES-196 keys using config file"

	# Store the UID of the KMIP public and secret key just created
	KMIP_GEND_TARGKEY3_UID=$(cat "${TEST_BASE}_stdout" | grep -A 2 "Secret Key" | tail -n 1 | cut -d . -f 9)

	################################################################
	# Using environment variables                                  #
	################################################################

	# Fill the configuration file with bogus values
	[[ -f $P11KMIP_CONF_FILE ]] && rm $P11KMIP_CONF_FILE
	echo "kmip {                                           " >> $P11KMIP_CONF_FILE
	echo "    host = \"255.255.255.255:0\"                 " >> $P11KMIP_CONF_FILE
	echo "    tls_client_cert = \"/dev/null\"              " >> $P11KMIP_CONF_FILE
	echo "    tls_client_key = \"/dev/null\"               " >> $P11KMIP_CONF_FILE
	echo "                                                 " >> $P11KMIP_CONF_FILE
	echo "    wrap_key_format = \"PKCS1\"                  " >> $P11KMIP_CONF_FILE
	echo "    wrap_key_algorithm = \"RSA\"                 " >> $P11KMIP_CONF_FILE
	echo "    wrap_key_size = 2048                         " >> $P11KMIP_CONF_FILE
	echo "    wrap_padding_method = \"PKCS1.5\"            " >> $P11KMIP_CONF_FILE
	echo "    wrap_hashing_algorithm = \"SHA-1\"           " >> $P11KMIP_CONF_FILE
	echo "}                                                " >> $P11KMIP_CONF_FILE
	echo "pkcs11 {                                         " >> $P11KMIP_CONF_FILE
	echo "    slot = 0                                     " >> $P11KMIP_CONF_FILE
	echo "}                                                " >> $P11KMIP_CONF_FILE

	echo "*** Running test using environment variables"
	TEST_BASE="$P11KMIP_TMP/p11kmip_import_key_env_test"

	P11KMIP_CONF_FILE="$P11KMIP_CONF_FILE" \
	PKCS11_USER_PIN="$PKCS11_USER_PIN" \
	PKCS11_SLOT_ID="$PKCS11_SLOT_ID" \
	KMIP_HOSTNAME="$KMIP_HOSTNAME" \
	KMIP_CLIENT_CERT="$KMIP_CLIENT_CERT" \
	KMIP_CLIENT_KEY="$KMIP_CLIENT_KEY" p11kmip import-key \
		--targkey-label $KMIP_SECRET_KEY_LABEL \
		--wrapkey-label $PKCS11_PUBLIC_KEY_LABEL \
		--unwrapkey-label $PKCS11_PRIVATE_KEY_LABEL \
		--tls-no-verify-server-cert \
		--tls-trust-server-cert \
		>"${TEST_BASE}_stdout" 2>"${TEST_BASE}_stderr"

	RC=$?
	echo "rc = $RC"
	echo "stdout:"
	cat "${TEST_BASE}_stdout"

	if [[ $RC -ne 0 ]] ; then
		echo "stderr:"
		cat "${TEST_BASE}_stderr"
		echo "* TESTCASE p11kmip_test import-key-env FAIL Failed to import keys using env var"
		return
	fi
	echo "* TESTCASE p11kmip_test import-key-env PASS Sucessfully imported keys using env var"

	################################################################
	# Using only commandline options                               #
	################################################################

	echo "*** Running test using command line options"
	TEST_BASE="$P11KMIP_TMP/p11kmip_import_key_opt_test"

	p11kmip import-key \
		--slot $PKCS11_SLOT_ID \
		--pin $PKCS11_USER_PIN  \
		--kmip-host $KMIP_HOSTNAME \
		--kmip-client-cert $KMIP_CLIENT_CERT \
		--kmip-client-key $KMIP_CLIENT_KEY \
		--targkey-label $KMIP_SECRET_KEY_LABEL \
		--wrapkey-label $PKCS11_PUBLIC_KEY_LABEL \
		--unwrapkey-label $PKCS11_PRIVATE_KEY_LABEL \
		--tls-no-verify-server-cert \
		--tls-trust-server-cert \
		>"${TEST_BASE}_stdout" 2>"${TEST_BASE}_stderr"
	
	RC=$?
	echo "rc = $RC"
	echo "stdout:"
	cat "${TEST_BASE}_stdout"

	if [[ $RC -ne 0 ]] ; then
		echo "stderr:"
		cat "${TEST_BASE}_stderr"
		echo "* TESTCASE p11kmip_test import-key-arg FAIL FAiled to import keys using command line arguments"
		return
	fi
	echo "* TESTCASE p11kmip_test import-key-arg PASS Sucessfully imported keys using command line arguments"
}

key_export_tests() {
	################################################################
	# Using configuration file options                             #
	################################################################

	# Build a standard configuration
	[[ -f $P11KMIP_CONF_FILE ]] && rm $P11KMIP_CONF_FILE
	echo "kmip {                                              " >> $P11KMIP_CONF_FILE
	echo "    host = \"${KMIP_HOSTNAME}\"                     " >> $P11KMIP_CONF_FILE
	echo "    tls_client_cert = \"${KMIP_CLIENT_CERT}\"       " >> $P11KMIP_CONF_FILE
	echo "    tls_client_key = \"${KMIP_CLIENT_KEY}\"         " >> $P11KMIP_CONF_FILE
	echo "                                                    " >> $P11KMIP_CONF_FILE
	echo "    wrap_key_format = \"PKCS1\"                     " >> $P11KMIP_CONF_FILE
	echo "    wrap_key_algorithm = \"RSA\"                    " >> $P11KMIP_CONF_FILE
	echo "    wrap_key_size = 2048                            " >> $P11KMIP_CONF_FILE
	echo "    wrap_padding_method = \"PKCS1.5\"               " >> $P11KMIP_CONF_FILE
	echo "    wrap_hashing_algorithm = \"SHA-1\"              " >> $P11KMIP_CONF_FILE
	echo "}                                                   " >> $P11KMIP_CONF_FILE
	echo "pkcs11 {                                            " >> $P11KMIP_CONF_FILE
	echo "    slot = ${PKCS11_SLOT_ID}                        " >> $P11KMIP_CONF_FILE
	echo "}                                                   " >> $P11KMIP_CONF_FILE

	echo "*** Running test using configuration options"
	TEST_BASE="$P11KMIP_TMP/p11kmip_export_key_conf_test"

	P11KMIP_CONF_FILE="$P11KMIP_CONF_FILE" p11kmip export-key \
		--retr-wrapkey \
		--pin $PKCS11_USER_PIN  \
		--targkey-label "$PKCS11_SECRET_KEY_LABEL-conf" \
		--wrapkey-label $KMIP_PUBLIC_KEY_LABEL \
		--wrapkey-id "012345678" \
		--wrapkey-attrs "H" \
		--tls-no-verify-server-cert \
		--tls-trust-server-cert \
		>"${TEST_BASE}_stdout" 2>"${TEST_BASE}_stderr"
	
	RC=$?
	echo "rc = $RC"
	echo "stdout:"
	cat "${TEST_BASE}_stdout"

	if [[ $RC -ne 0 ]] ; then
		echo "stderr:"
		cat "${TEST_BASE}_stderr"
		echo "* TESTCASE p11kmip_test export-key-conf FAIL Failed to export keys using config file"
		return
	fi
	echo "* TESTCASE p11kmip_test export-key-conf PASS Sucessfully exported keys using config file"

	# Store the UID of the PKCS#11 public key just retrieved
	KMIP_RETR_WRAPKEY_UID=$(cat $P11KMIP_TMP/p11kmip_export_key_conf_test_stdout | grep -A 2 "Public Key" | tail -n 1 | cut -d . -f 9)

	echo "*** Running test using configuration options with 128-bit key"
	TEST_BASE="$P11KMIP_TMP/p11kmip_export_key_conf_test_128"

	P11KMIP_CONF_FILE="$P11KMIP_CONF_FILE" p11kmip export-key \
		--pin $PKCS11_USER_PIN  \
		--targkey-label "$PKCS11_SECRET_KEY_LABEL-conf.2" \
		--wrapkey-label $KMIP_PUBLIC_KEY_LABEL \
		--tls-no-verify-server-cert \
		--tls-trust-server-cert \
		>"${TEST_BASE}_stdout" 2>"${TEST_BASE}_stderr"
	
	RC=$?
	echo "rc = $RC"
	echo "stdout:"
	cat "${TEST_BASE}_stdout"

	if [[ $RC -ne 0 ]] ; then
		echo "stderr:"
		cat "${TEST_BASE}_stderr"
		echo "* TESTCASE p11kmip_test export-key-conf-128 FAIL FAiled to export AES-128 keys using config file"
		return
	fi
	echo "* TESTCASE p11kmip_test export-key-conf-128 PASS Sucessfully exported AES-128 keys using config file"

	echo "*** Running test using configuration options with 192-bit key"
	TEST_BASE="$P11KMIP_TMP/p11kmip_export_key_conf_test_192"

	P11KMIP_CONF_FILE="$P11KMIP_CONF_FILE" p11kmip export-key \
		--pin $PKCS11_USER_PIN  \
		--targkey-label "$PKCS11_SECRET_KEY_LABEL-conf.3" \
		--wrapkey-label $KMIP_PUBLIC_KEY_LABEL \
		--tls-no-verify-server-cert \
		--tls-trust-server-cert \
		>"${TEST_BASE}_stdout" 2>"${TEST_BASE}_stderr"
	
	RC=$?
	echo "rc = $RC"
	echo "stdout:"
	cat "${TEST_BASE}_stdout"

	if [[ $RC -ne 0 ]] ; then
		echo "stderr:"
		cat "${TEST_BASE}_stderr"
		echo "* TESTCASE p11kmip_test export-key-conf-192 FAIL FAiled to export AES-192 keys using config file"
		return
	fi
	echo "* TESTCASE p11kmip_test export-key-conf-192 PASS Sucessfully exported AES-192 keys using config file"

	################################################################
	# Using environment variables                                  #
	################################################################

	# Fill the configuration file with bogus values
	[[ -f $P11KMIP_CONF_FILE ]] && rm $P11KMIP_CONF_FILE
	echo "kmip {                                           " >> $P11KMIP_CONF_FILE
	echo "    host = \"255.255.255.255:0\"                 " >> $P11KMIP_CONF_FILE
	echo "    tls_client_cert = \"/dev/null\"              " >> $P11KMIP_CONF_FILE
	echo "    tls_client_key = \"/dev/null\"               " >> $P11KMIP_CONF_FILE
	echo "                                                 " >> $P11KMIP_CONF_FILE
	echo "    wrap_key_format = \"PKCS1\"                  " >> $P11KMIP_CONF_FILE
	echo "    wrap_key_algorithm = \"RSA\"                 " >> $P11KMIP_CONF_FILE
	echo "    wrap_key_size = 2048                         " >> $P11KMIP_CONF_FILE
	echo "    wrap_padding_method = \"PKCS1.5\"            " >> $P11KMIP_CONF_FILE
	echo "    wrap_hashing_algorithm = \"SHA-1\"           " >> $P11KMIP_CONF_FILE
	echo "}                                                " >> $P11KMIP_CONF_FILE
	echo "pkcs11 {                                         " >> $P11KMIP_CONF_FILE
	echo "    slot = 0                                     " >> $P11KMIP_CONF_FILE
	echo "}                                                " >> $P11KMIP_CONF_FILE

	echo "*** Running test using environment variables"
	TEST_BASE="$P11KMIP_TMP/p11kmip_export_key_env_test"

	P11KMIP_CONF_FILE="$P11KMIP_CONF_FILE" \
	PKCS11_USER_PIN="$PKCS11_USER_PIN" \
	PKCS11_SLOT_ID="$PKCS11_SLOT_ID" \
	KMIP_HOSTNAME="$KMIP_HOSTNAME" \
	KMIP_CLIENT_CERT="$KMIP_CLIENT_CERT" \
	KMIP_CLIENT_KEY="$KMIP_CLIENT_KEY" \
	p11kmip export-key \
		--targkey-label "$PKCS11_SECRET_KEY_LABEL-env" \
		--wrapkey-label $KMIP_PUBLIC_KEY_LABEL \
		--tls-no-verify-server-cert \
		--tls-trust-server-cert \
		>"${TEST_BASE}_stdout" 2>"${TEST_BASE}_stderr"

	RC=$?
	echo "rc = $RC"
	echo "stdout:"
	cat "${TEST_BASE}_stdout"

	if [[ $RC -ne 0 ]] ; then
		echo "stderr:"
		cat "${TEST_BASE}_stderr"
		echo "* TESTCASE p11kmip_test export-key-env FAIL Failed to export keys using env vars"
		return
	fi
	echo "* TESTCASE p11kmip_test export-key-env PASS Sucessfully exported keys using env vars"

	################################################################
	# Using only commandline options                               #
	################################################################

	echo "*** Running test using command line options"
	TEST_BASE="$P11KMIP_TMP/p11kmip_export_key_opt_test"

	p11kmip export-key \
		--slot $PKCS11_SLOT_ID \
		--pin $PKCS11_USER_PIN  \
		--kmip-host $KMIP_HOSTNAME \
		--kmip-client-cert $KMIP_CLIENT_CERT \
		--kmip-client-key $KMIP_CLIENT_KEY \
		--targkey-label "$PKCS11_SECRET_KEY_LABEL-opt" \
		--wrapkey-label $KMIP_PUBLIC_KEY_LABEL \
		--tls-no-verify-server-cert \
		--tls-trust-server-cert \
		>"${TEST_BASE}_stdout" 2>"${TEST_BASE}_stderr"
	
	RC=$?
	echo "rc = $RC"
	echo "stdout:"
	cat "${TEST_BASE}_stdout"

	if [[ $RC -ne 0 ]] ; then
		echo "stderr:"
		cat "${TEST_BASE}_stderr"
		echo "* TESTCASE p11kmip_test export-key-arg FAIL Failed to export keys using comand line arguments"
		return
	fi
	echo "* TESTCASE p11kmip_test export-key-arg PASS Sucessfully exported keys using comand line arguments"
}

echo "** Generating test certificates - 'p11kmip_test.sh'"

generate_certificates

echo "** Setting up KMIP client on KMIP server - 'p11kmip_test.sh'"

setup_kmip_client

if [[ $RC -ne 0 ]] ; then
	echo "* TESTCASE p11kmip_test setup-client FAIL Failed to setup KMIP client on KMIP server"
	exit $RC
fi
echo "* TESTCASE p11kmip_test setup-client PASS Sucessfully setup up KMIP client on KMIP server"

echo "** Setting up remote and local test keys - 'p11kmip_test.sh'"

setup_kmip_keys

if [[ $RC_PKMIP_GENERATE -ne 0 ]]; then
	echo "* TESTCASE p11kmip_test setup-kmip-keys FAIL Failed to setup up KMIP remote and local keys"
	exit $RC_PKMIP_GENERATE
fi
echo "* TESTCASE p11kmip_test setup-kmip-keys PASS Sucessfully setup up KMIP remote and local keys"

setup_pkcs11_keys

if [[ $RC_P11SAK_IMPORT -ne 0 ]]; then
	echo "* TESTCASE p11kmip_test setup-pkcs11-keys FAIL Failed to setup up PKCS#11 keys"
	exit $RC_PKMIP_GENERATE
fi
echo "* TESTCASE p11kmip_test setup-pkcs11-keys PASS Sucessfully setup up PKCS#11 keys"

echo "** Running key import tests - 'p11kmip_test.sh'"

key_import_tests

echo "** Running key export tests - 'p11kmip_test.sh'"

key_export_tests

echo "** Cleaning up remote and local test keys - 'p11kmip_test.sh'"

cleanup_pkcs11_keys

if [[ $RC_P11SAK_REMOVE -ne 0 ]]; then
	echo "* TESTCASE p11kmip_test remove-keys FAIL Failed to remove PKCS#11 keys"
	exit $RC_P11SAK_REMOVE
fi
echo "* TESTCASE p11kmip_test remove-keys PASS Sucessfully removed PKCS#11 keys"

exit $RC