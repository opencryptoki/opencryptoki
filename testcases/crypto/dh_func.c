/*
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/************************************************************************
*                                                                       *
*      Copyright:       Corrent Corporation (c) 2000-2003               *
*                                                                       *
*      Filename:        dh_func.c                                       *
*      Created By:      Kapil Sood                                      *
*      Created On:      April 28, 2003                                  *
*      Description:     This is the file for testing Diffie-Hellman     *
*                       key pair generation and shared key derivation   *
*                       operations.                                     *
*                                                                       *
************************************************************************/

// File: dh_func.c
//

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"
#include "common.c"


// These values were obtained from IPsec second oakley group.
// These values are in big-endian format.
// These are required for generating DH keys and secrets.

CK_BYTE DH_PUBL_PRIME[128] =  {	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,
				0x0F,0xDA,0xA2,0x21,0x68,0xC2,0x34,0xC4,0xC6,
				0x62,0x8B,0x80,0xDC,0x1C,0xD1,0x29,0x02,0x4E,
				0x08,0x8A,0x67,0xCC,0x74,0x02,0x0B,0xBE,0xA6,
				0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,
				0x34,0x04,0xDD,0xEF,0x95,0x19,0xB3,0xCD,0x3A,
				0x43,0x1B,0x30,0x2B,0x0A,0x6D,0xF2,0x5F,0x14,
				0x37,0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
				0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,0xF4,
				0x4C,0x42,0xE9,0xA6,0x37,0xED,0x6B,0x0B,0xFF,
				0x5C,0xB6,0xF4,0x06,0xB7,0xED,0xEE,0x38,0x6B,
				0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,
				0x7C,0x4B,0x1F,0xE6,0x49,0x28,0x66,0x51,0xEC,
				0xE6,0x53,0x81,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
				0xFF,0xFF };

CK_BYTE DH_PUBL_BASE[128] =   {	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x02 };

/*
 * Generate DH key-pairs for parties A and B.
 * Derive keys based on Diffie Hellman key agreement defined in PKCS#3.
 *
 */
CK_RV do_DeriveDHKey(void)
{
	CK_SESSION_HANDLE   session;
	CK_MECHANISM        mech;
	CK_OBJECT_HANDLE    publ_key, priv_key;
	CK_OBJECT_HANDLE    peer_publ_key, peer_priv_key;
	CK_OBJECT_HANDLE    secret_key, peer_secret_key;
	CK_FLAGS            flags;
	CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG            user_pin_len;
	CK_RV               rc = CKR_OK, loc_rc = CKR_OK;

	int i = 0;
	CK_BYTE clear    [32];
	CK_BYTE cipher   [32];
	CK_BYTE re_cipher[32];
	CK_ULONG cipher_len = 32;
	CK_ULONG re_cipher_len = 32;
	CK_BBOOL ltrue = 1;

	CK_OBJECT_CLASS     pub_key_class  = CKO_PUBLIC_KEY ;
	CK_KEY_TYPE         key_type   = CKK_DH ;
	CK_UTF8CHAR	    publ_label[] = "A DH public key object";
	CK_OBJECT_CLASS     priv_key_class = CKO_PRIVATE_KEY ;
        CK_UTF8CHAR	    priv_label[] = "A DH private key object";

	CK_ULONG secret_key_size = sizeof(DH_PUBL_PRIME);
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE secret_key_type = CKK_GENERIC_SECRET;
	CK_UTF8CHAR secret_label[] = "A generic secret key object";

	CK_BYTE key1_value[sizeof(DH_PUBL_PRIME)*2];
	CK_BYTE key2_value[sizeof(DH_PUBL_PRIME)*2];

	CK_ATTRIBUTE  publ_tmpl[] =
	{
		{CKA_CLASS, &pub_key_class, sizeof(pub_key_class)},
		{CKA_KEY_TYPE, &key_type, sizeof(key_type)},
		{CKA_LABEL, publ_label, sizeof(publ_label)-1},
		{CKA_PRIME, DH_PUBL_PRIME, sizeof(DH_PUBL_PRIME)},
		{CKA_BASE, DH_PUBL_BASE, sizeof(DH_PUBL_BASE)}
	};

	CK_ATTRIBUTE  priv_tmpl[] =
	{
		{CKA_CLASS, &priv_key_class, sizeof(priv_key_class)},
		{CKA_KEY_TYPE, &key_type, sizeof(key_type)},
		{CKA_LABEL, priv_label, sizeof(priv_label)-1},
		{CKA_DERIVE, &ltrue, sizeof(ltrue) }
	};

	CK_ATTRIBUTE  secret_tmpl[] =
	{
		{CKA_CLASS, &secret_key_class, sizeof(secret_key_class)},
		{CKA_KEY_TYPE, &secret_key_type, sizeof(secret_key_type)},
		{CKA_VALUE_LEN, &secret_key_size, sizeof(secret_key_size)},
		{CKA_LABEL, secret_label, sizeof(secret_label)-1}
	};

	CK_ATTRIBUTE  extr1_tmpl[] =
	{
		{CKA_VALUE, key1_value, sizeof(key1_value)}
	};

	CK_ATTRIBUTE  extr2_tmpl[] =
	{
		{CKA_VALUE, key2_value, sizeof(key2_value)}
	};

	testcase_begin("starting do_DeriveDHKey...");
	testcase_rw_session();
	testcase_user_login();

	// Testcase #1 - Generate 2 DH key pairs.
	testcase_new_assertion();

	// First, generate the DH key Pair for Party A
	mech.mechanism = CKM_DH_PKCS_KEY_PAIR_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;

	rc = funcs->C_GenerateKeyPair(session, &mech, publ_tmpl, 5,
					priv_tmpl, 4, &publ_key, &priv_key);
	if (rc != CKR_OK) {
		testcase_fail("C_GenerateKeyPair #1: rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	// Now generate a key-pair for party B (the peer)
	mech.mechanism = CKM_DH_PKCS_KEY_PAIR_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;

	rc = funcs->C_GenerateKeyPair(session, &mech, publ_tmpl, 5,
				priv_tmpl, 4, &peer_publ_key, &peer_priv_key);
	if (rc != CKR_OK) {
		testcase_fail("C_GenerateKeyPair #2: rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	// Extract the peer's public key
	rc = funcs->C_GetAttributeValue(session, peer_publ_key, extr1_tmpl, 1);
	if (rc != CKR_OK) {
		testcase_error("C_GetAttributeValue #1: rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	// Make sure peer's key is the right size
	if ((extr1_tmpl[0].ulValueLen != sizeof(DH_PUBL_PRIME)) &&
	    (extr1_tmpl[0].ulValueLen != sizeof(DH_PUBL_PRIME)-1)) {
		testcase_fail("ERROR:size error peer's key %ld",extr1_tmpl[0].ulValueLen );
		goto testcase_cleanup;
	} else
		testcase_pass("Successfully derived key");

	// Testcase #2 - Now derive the secrets...
	if (!securekey) {
		// Note: this is a clear key token testcase since comparing
		//       key values.
		testcase_new_assertion();

		/* Now, derive a generic secret key using party A's
		 * private key and peer's public key
		 */
		mech.mechanism  = CKM_DH_PKCS_DERIVE;
		mech.ulParameterLen = extr1_tmpl[0].ulValueLen ;
		mech.pParameter = key1_value;

		rc = funcs->C_DeriveKey(session, &mech, priv_key, secret_tmpl,
					4, &secret_key) ;
		if (rc != CKR_OK) {
			testcase_fail("C_DeriveKey #1: rc = %s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		// Do the same for the peer

		// Extract party A's public key
		rc = funcs->C_GetAttributeValue(session, publ_key,
						 extr2_tmpl, 1);
		if (rc != CKR_OK) {
			testcase_error("C_GetAttributeValue #2: rc = %s",
					p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		// Make sure party A's key is the right size
		if ((extr2_tmpl[0].ulValueLen != sizeof(DH_PUBL_PRIME)) &&
			(extr2_tmpl[0].ulValueLen != sizeof(DH_PUBL_PRIME)-1)) {
			testcase_fail("ERROR:size error party A's key %ld",extr2_tmpl[0].ulValueLen);
			goto testcase_cleanup;
		}

		// Now, derive a generic secret key using peer's private key
		// and A's public key
		mech.mechanism = CKM_DH_PKCS_DERIVE;
		mech.ulParameterLen = extr2_tmpl[0].ulValueLen;
		mech.pParameter = key2_value;

		rc = funcs->C_DeriveKey(session, &mech, peer_priv_key,
					secret_tmpl, 4, &peer_secret_key);
		if (rc != CKR_OK) {
			testcase_fail("C_DeriveKey #2: rc = %s",
					p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		// Extract the derived keys and compare them

		memset(key1_value,0,sizeof(key1_value));
		extr1_tmpl[0].ulValueLen= sizeof(key1_value);

		rc = funcs->C_GetAttributeValue(session, secret_key,
						extr1_tmpl, 1);
		if (rc != CKR_OK) {
			testcase_error("C_GetAttributeValue #3:rc = %s",
					p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		if (extr1_tmpl[0].ulValueLen != sizeof(DH_PUBL_PRIME) ||
			*((int*)extr1_tmpl[0].pValue) == 0) {
			testcase_fail("ERROR:derived key #1 length or value %ld", extr1_tmpl[0].ulValueLen );
			goto testcase_cleanup;
		}

		memset(key2_value,0,sizeof(key2_value));
		extr2_tmpl[0].ulValueLen= sizeof(key2_value);

		rc = funcs->C_GetAttributeValue(session, peer_secret_key,
						extr2_tmpl, 1);
		if (rc != CKR_OK) {
			testcase_error("C_GetAttributeValue #4:rc = %s",
					p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		if (extr2_tmpl[0].ulValueLen != sizeof(DH_PUBL_PRIME) ||
			*((int*)extr2_tmpl[0].pValue) == 0) {
			testcase_fail("ERROR:derived key #2 length or value %ld", extr2_tmpl[0].ulValueLen );
			goto testcase_cleanup;
		}

		if (memcmp(key1_value, key2_value, sizeof(DH_PUBL_PRIME)) != 0){
			testcase_fail("ERROR:derived key mismatch");
			goto testcase_cleanup;
		}

		testcase_pass("Generating DH key pairs and deriving secrets");

		goto testcase_cleanup;

	} else {

		// Testcase for secure key token - encode/decode with secrect key and peer secret key
		testcase_new_assertion();

		secret_key_size = 32;
		secret_key_type = CKK_AES;
		for (i = 0; i < 32; i++)
			clear[i] = i;

		/* Now, derive a generic secret key using party A's
		 * private key and peer's public key
		 */
		mech.mechanism  = CKM_DH_PKCS_DERIVE;
		mech.ulParameterLen = extr1_tmpl[0].ulValueLen ;
		mech.pParameter = key1_value;

		rc = funcs->C_DeriveKey(session, &mech, priv_key, secret_tmpl,
					4, &secret_key) ;
		if (rc != CKR_OK) {
			testcase_fail("C_DeriveKey #1: rc = %s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		// Do the same for the peer

		// Extract party A's public key
		rc = funcs->C_GetAttributeValue(session, publ_key, extr2_tmpl, 1);
		if (rc != CKR_OK) {
			testcase_error("C_GetAttributeValue #2: rc = %s",
					p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		// Make sure party A's key is the right size
		if ((extr2_tmpl[0].ulValueLen != sizeof(DH_PUBL_PRIME)) &&
			(extr2_tmpl[0].ulValueLen != sizeof(DH_PUBL_PRIME)-1)) {
			testcase_fail("ERROR:size error party A's key %ld",extr2_tmpl[0].ulValueLen);
			goto testcase_cleanup;
		}

		// Now, derive a generic secret key using peer's private key
		// and A's public key
		mech.mechanism = CKM_DH_PKCS_DERIVE;
		mech.ulParameterLen = extr2_tmpl[0].ulValueLen;
		mech.pParameter = key2_value;

		rc = funcs->C_DeriveKey(session, &mech, peer_priv_key,
					secret_tmpl, 4, &peer_secret_key);
		if (rc != CKR_OK) {
			testcase_fail("C_DeriveKey #2: rc = %s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		// Extract the derived keys and compare them

		mech.mechanism = CKM_AES_ECB;
		mech.ulParameterLen = 0;
		mech.pParameter = NULL;

		rc = funcs->C_EncryptInit(session,&mech,secret_key);
		if (rc != CKR_OK) {
			testcase_error("C_EncryptInit secret_key: rc = %s",
					p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		rc = funcs->C_Encrypt(session, clear, 32, cipher, &cipher_len);
		if (rc != CKR_OK) {
			testcase_error("C_Encrypt secret_key: rc = %s",
					p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		rc = funcs->C_DecryptInit(session, &mech, peer_secret_key);
		if (rc != CKR_OK) {
			testcase_error("C_DecryptInit peer_secret_key: rc = %s",
					p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		rc = funcs->C_Decrypt(session, cipher, cipher_len, re_cipher,
					&re_cipher_len);
		if (rc != CKR_OK) {
			testcase_error("C_Decrypt peer secret_key: rc = %s",
					p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		if (memcmp(clear, re_cipher, 32) != 0) {
			testcase_fail("ERROR:data mismatch");
			goto testcase_cleanup;
		}

		testcase_pass("Generating DH key pairs and deriving secrets");
	}

testcase_cleanup:
	funcs->C_DestroyObject(session, publ_key);
	funcs->C_DestroyObject(session, priv_key);
	funcs->C_DestroyObject(session, peer_priv_key);
	funcs->C_DestroyObject(session, peer_publ_key);
	funcs->C_DestroyObject(session, secret_key);
	funcs->C_DestroyObject(session, peer_secret_key);

	loc_rc = funcs->C_CloseSession(session);
	if (loc_rc != CKR_OK)
		testcase_error("C_CloseSession, loc_rc = %s", p11_get_ckr(loc_rc));
	return rc;
} /* end do_DeriveDHKey() */

CK_RV dh_functions()
{
	CK_RV  rv, rv2;
	CK_MECHANISM_INFO mechinfo;

	/** get mech info **/
	rv = funcs->C_GetMechanismInfo(SLOT_ID, CKM_DH_PKCS_KEY_PAIR_GEN,
					&mechinfo);
	rv2 = funcs->C_GetMechanismInfo(SLOT_ID, CKM_DH_PKCS_DERIVE, &mechinfo);

	if ((rv == CKR_OK) && (rv2 == CKR_OK))
		rv = do_DeriveDHKey();
	else {
		/*
		 ** One of the above mechanism is not available, so skip
		 ** the test but do not report any
		 ** rv = CKR_MECHANISM_INVALID;
		 ** invalid or however failures as this is not a failure.
		 **/
		return CKR_OK;
	}

	return rv;
}

int main(int argc, char **argv)
{
	CK_C_INITIALIZE_ARGS cinit_args;
	int rc;
	CK_RV rv;

	rc = do_ParseArgs(argc, argv);
	if ( rc != 1)
		return rc;

	printf("Using slot #%lu...\n\n", SLOT_ID );
	printf("With option: no_init: %d\n", no_init);

	rc = do_GetFunctionList();
	if (!rc) {
		PRINT_ERR("ERROR do_GetFunctionList() Failed , rc = 0x%0x\n", rc);
		return rc;
	}

	memset( &cinit_args, 0x0, sizeof(cinit_args) );
	cinit_args.flags = CKF_OS_LOCKING_OK;

	// SAB Add calls to ALL functions before the C_Initialize gets hit

	funcs->C_Initialize( &cinit_args );

	/*
	 * -securekey option is needed on CCA and EP11 token,
	 *  otherwise the testcase will fail. However, now this
	 *  will be done automatically here.
	 */
	if (is_ep11_token(SLOT_ID) || is_cca_token(SLOT_ID))
		securekey = 1;

	{
		CK_SESSION_HANDLE  hsess = 0;

		rc = funcs->C_GetFunctionStatus(hsess);
		if (rc  != CKR_FUNCTION_NOT_PARALLEL)
			return rc;

		rc = funcs->C_CancelFunction(hsess);
		if (rc  != CKR_FUNCTION_NOT_PARALLEL)
			return rc;
	}

	testcase_setup(0);

	rv = dh_functions();

	testcase_print_result();

	funcs->C_Finalize(NULL);

	/* make sure we return non-zero if rv is non-zero */
	return ((rv==0) || (rv % 256) ? rv : -1);
}
