/*
 * openCryptoki testcase for RSA
 *
 * August 18, 2011
 *
 * Fionnuala Gunter <fin@linux.vnet.ibm.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "common.c"
#include "regress.h"

#include "rsa.h"

/**
 * Note: do_EncryptDecryptRSA fails if we don't manually
 * remove padding from decrypted values. This might be a bug.
 **/


/* This function should test:
 * RSA Key Generation, CKM_RSA_PKCS_KEY_PAIR_GEN
 * RSA Encryption, mechanism chosen by caller
 * RSA Decryption, mechanism chosen by caller
 *
 * 1. Generate RSA Key Pair
 * 2. Generate plaintext
 * 3. Encrypt plaintext
 * 4. Decrypt encrypted data
 * 5. Compare plaintext with decrypted data
 *
 */
CK_RV do_EncryptDecryptRSA(struct GENERATED_TEST_SUITE_INFO *tsuite)
{
	int 			i, j;
	CK_BYTE			original[BIG_REQUEST];
	CK_ULONG		original_len;
	CK_BYTE			crypt[BIG_REQUEST];
	CK_ULONG		crypt_len;
	CK_BYTE			decrypt[BIG_REQUEST];
	CK_ULONG		decrypt_len;
	CK_MECHANISM		mech;
	CK_OBJECT_HANDLE	publ_key, priv_key;
	CK_SLOT_ID		slot_id = SLOT_ID;
	CK_SESSION_HANDLE	session;
	CK_FLAGS		flags;
	CK_BYTE			user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG		user_pin_len;
	CK_RV			rc, loc_rc;
	CK_RSA_PKCS_OAEP_PARAMS oaep_params;

	char 			*s;

	// begin testsuite
	testsuite_begin("%s Encrypt Decrypt.", tsuite->name);
	testcase_rw_session();
	testcase_user_login();

	// skip tests if the slot doesn't support this mechanism
        if (! mech_supported(slot_id, tsuite->mech.mechanism)) {
                testsuite_skip(tsuite->tvcount,
                        "Slot %u doesn't support %u",
                        (unsigned int) slot_id,
                        (unsigned int) tsuite->mech.mechanism );
                goto testcase_cleanup;
        }

	// iterate over test vectors
	for (i = 0; i < tsuite->tvcount; i++) {

		// get public exponent from test vector
                if ( p11_ahex_dump(&s, tsuite->tv[i].publ_exp,
                                tsuite->tv[i].publ_exp_len) == NULL) {
                        testcase_error("p11_ahex_dump() failed");
                        rc = -1;
                        goto testcase_cleanup;
                }

		// begin testcase
		testcase_begin("%s Encrypt and Decrypt with test vector %d."
			"\npubl_exp='%s', modbits=%ld, publ_exp_len=%ld, "
			"inputlen=%ld.", tsuite->name, i, s,
			tsuite->tv[i].modbits,
			tsuite->tv[i].publ_exp_len,
			tsuite->tv[i].inputlen);

		rc = CKR_OK; // set rc

		if (!keysize_supported(slot_id, tsuite->mech.mechanism,
					tsuite->tv[i].modbits)) {
			testcase_skip("Token in slot %ld cannot be used with "
					"modbits.='%ld'",
					SLOT_ID,tsuite->tv[i].modbits);
			continue;
		}

		if (is_ep11_token(slot_id)) {
			if (! is_valid_ep11_pubexp(tsuite->tv[i].publ_exp,
						  tsuite->tv[i].publ_exp_len)) {
				testcase_skip("EP11 Token cannot "
					       "be used with publ_exp.='%s'",s);
				continue;
			}
		}

		// cca special cases:
		// cca token can only use the following public exponents
		// 0x03 or 0x010001 (65537)
		// so skip test if invalid public exponent is used
		if (is_cca_token(slot_id)) {
			if (! is_valid_cca_pubexp(tsuite->tv[i].publ_exp,
				tsuite->tv[i].publ_exp_len) ) {
				testcase_skip("CCA Token cannot "
					"be used with publ_exp.='%s'",s);
				continue;
			}
		}

		// tpm special cases:
		// tpm token can only use public exponent 0x010001 (65537)
		// so skip test if invalid public exponent is used
		if (is_tpm_token(slot_id)) {
			if ((! is_valid_tpm_pubexp(tsuite->tv[i].publ_exp,
				tsuite->tv[i].publ_exp_len) ) || (! is_valid_tpm_modbits(tsuite->tv[i].modbits))) {
				testcase_skip("TPM Token cannot "
					"be used with publ_exp.='%s'",s);
				continue;
			}
		}

		if (is_icsf_token(slot_id)) {
			if (!is_valid_icsf_pubexp(tsuite->tv[i].publ_exp,
			    tsuite->tv[i].publ_exp_len) ||
			    (tsuite->tv[i].modbits < 1024)) {
				testcase_skip("ICSF Token cannot be used with "
					      "publ_exp='%s'.",s);
				continue;
			}
		}

		free(s);

		// clear buffers
                memset(original, 0, BIG_REQUEST);
                memset(crypt, 0, BIG_REQUEST);
                memset(decrypt, 0, BIG_REQUEST);

                // get test vector parameters
                original_len = tsuite->tv[i].inputlen;

		// generate key pair
		rc = generate_RSA_PKCS_KeyPair(session,
					tsuite->tv[i].modbits,
					tsuite->tv[i].publ_exp,
					tsuite->tv[i].publ_exp_len,
					&publ_key,
					&priv_key);

		if (rc != CKR_OK) {
			testcase_error("generate_RSA_PKCS_KeyPair(), "
				       "rc=%s", p11_get_ckr(rc));
                        goto testcase_cleanup;
		}

		// generate plaintext
		for (j = 0; j < original_len; j++) {
			original[j] = (j + 1) % 255;
		}

		// set cipher buffer length
		crypt_len = BIG_REQUEST;
		decrypt_len = BIG_REQUEST;

		// get mech
		mech = tsuite->mech;
		if (mech.mechanism == CKM_RSA_PKCS_OAEP) {
			oaep_params = tsuite->tv[i].oaep_params;
			mech.pParameter = &oaep_params;
			mech.ulParameterLen = sizeof(CK_RSA_PKCS_OAEP_PARAMS);
		}

		// initialize (public key) encryption
		rc = funcs->C_EncryptInit(session, &mech, publ_key);
		if (rc != CKR_OK) {
			testcase_error("C_EncryptInit, rc=%s", p11_get_ckr(rc));
		}

		// do (public key) encryption
		rc = funcs->C_Encrypt(session,
				original,
				original_len,
				crypt,
				&crypt_len);
		if (rc != CKR_OK) {
			testcase_error("C_Encrypt, rc=%s", p11_get_ckr(rc));
			goto error;
		}

		// initialize (private key) decryption
		rc = funcs->C_DecryptInit(session, &mech, priv_key);
		if (rc != CKR_OK) {
			testcase_error("C_DecryptInit, rc=%s", p11_get_ckr(rc));
			goto error;
		}

		// do (private key) decryption
		rc = funcs->C_Decrypt(session,
				crypt,
				crypt_len,
				decrypt,
				&decrypt_len);
		if (rc != CKR_OK) {
			testcase_error("C_Decrypt, rc=%s", p11_get_ckr(rc));
			goto error;
		}

		// FIXME: there shouldn't be any padding here
		// remove padding if mech is CKM_RSA_X_509
		if (mech.mechanism == CKM_RSA_X_509) {
			memmove(decrypt,
				decrypt + decrypt_len - original_len,
				original_len);
			decrypt_len = original_len;
		}

		// check results
		testcase_new_assertion();

		if (decrypt_len != original_len) {
			testcase_fail("decrypted length does not match"
				"original data length.\n expected length = %ld,"
				"but found length=%ld.\n",
				original_len, decrypt_len);
		}

		else if (memcmp(decrypt, original, original_len)) {
			testcase_fail("decrypted data does not match "
				"original data.");
		}

		else {
			testcase_pass("C_Encrypt and C_Decrypt.");
		}

		// clean up
		rc = funcs->C_DestroyObject(session, publ_key);
		if (rc != CKR_OK) {
			testcase_error("C_DestroyObject(), rc=%s.",
				p11_get_ckr(rc));
			goto error;
		}

		rc = funcs->C_DestroyObject(session, priv_key);
		if (rc != CKR_OK) {
			testcase_error("C_DestroyObject(), rc=%s.",
				p11_get_ckr(rc));
			goto error;
		}

	}
	goto testcase_cleanup;
error:
	loc_rc = funcs->C_DestroyObject(session, publ_key);
	if (loc_rc != CKR_OK) {
		testcase_error("C_DestroyObject(), rc=%s.",
			p11_get_ckr(loc_rc));
	}

	loc_rc = funcs->C_DestroyObject(session, priv_key);
	if (loc_rc != CKR_OK) {
		testcase_error("C_DestroyObject(), rc=%s.",
			p11_get_ckr(loc_rc));
	}

testcase_cleanup:
	testcase_user_logout();
	loc_rc = funcs->C_CloseAllSessions(slot_id);
	if (loc_rc != CKR_OK) {
		testcase_error("C_CloseAllSessions, rc=%s",
			p11_get_ckr(loc_rc));
	}
	return rc;

}

/* This function should test:
 * RSA Key Generation, usign CKM_RSA_PKCS_KEY_PAIR_GEN
 * RSA Sign, mechanism chosen by caller
 * RSA Verify, mechanism chosen by caller
 *
 * 1. Generate RSA Key Pair
 * 2. Generate message
 * 3. Sign message
 * 4. Verify signature
 *
 */
CK_RV do_SignVerifyRSA(struct GENERATED_TEST_SUITE_INFO *tsuite)
{
	int 			i; // test vector index
	int			j; // message byte index
	CK_BYTE			message[MAX_MESSAGE_SIZE];
	CK_ULONG		message_len;
	CK_BYTE			signature[MAX_SIGNATURE_SIZE];
	CK_ULONG		signature_len;

	CK_MECHANISM		mech;
	CK_OBJECT_HANDLE	publ_key, priv_key;

	CK_SLOT_ID		slot_id = SLOT_ID;
	CK_SESSION_HANDLE	session;
	CK_FLAGS		flags;
	CK_BYTE			user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG		user_pin_len;
	CK_RV			rc, loc_rc;

	char 			*s;

	// begin testsuite
	testsuite_begin("%s Sign Verify.", tsuite->name);
	testcase_rw_session();
	testcase_user_login();

	// skip tests if the slot doesn't support this mechanism
	if (! mech_supported(slot_id, tsuite->mech.mechanism)){
		testsuite_skip(tsuite->tvcount,
			"Slot %u doesn't support %u",
			(unsigned int) slot_id,
                        (unsigned int) tsuite->mech.mechanism );
                goto testcase_cleanup;
	}


	// iterate over test vectors
	for (i = 0; i < tsuite->tvcount; i++){

                // get public exponent from test vector
                if ( p11_ahex_dump(&s, tsuite->tv[i].publ_exp,
                                tsuite->tv[i].publ_exp_len) == NULL) {
                        testcase_error("p11_ahex_dump() failed");
                        rc = -1;
                        goto testcase_cleanup;
                }

                // begin test
                testcase_begin("%s Sign and Verify with test vector %d, "
                        "\npubl_exp='%s', mod_bits='%lu', keylen='%lu'.",
			tsuite->name, i, s,
                        tsuite->tv[i].modbits,
                        tsuite->tv[i].keylen);

		if (!keysize_supported(slot_id, tsuite->mech.mechanism,
					tsuite->tv[i].modbits)) {
			testcase_skip("Token in slot %ld cannot be used with "
					"modbits.='%ld'",
					SLOT_ID,tsuite->tv[i].modbits);
			continue;
		}

		if (is_ep11_token(slot_id)) {
			if (! is_valid_ep11_pubexp(tsuite->tv[i].publ_exp,
						  tsuite->tv[i].publ_exp_len)) {
				testcase_skip("EP11 Token cannot "
					       "be used with publ_exp.='%s'",s);
				continue;
			}
		}

		if (is_cca_token(slot_id)) {
                        if (! is_valid_cca_pubexp(tsuite->tv[i].publ_exp,
                                tsuite->tv[i].publ_exp_len)) {
                                testcase_skip("CCA Token cannot "
                                        "be used with publ_exp='%s'.",s);
                                continue;
                        }
                }

		if (is_tpm_token(slot_id)) {
                        if ((! is_valid_tpm_pubexp(tsuite->tv[i].publ_exp,
                                tsuite->tv[i].publ_exp_len)) || (!is_valid_tpm_modbits(tsuite->tv[i].modbits))) {
                                testcase_skip("TPM Token cannot "
                                        "be used with publ_exp='%s'.",s);
                                continue;
                        }
                }

		if (is_icsf_token(slot_id)) {
			if (!is_valid_icsf_pubexp(tsuite->tv[i].publ_exp,
			    tsuite->tv[i].publ_exp_len) ||
			    (tsuite->tv[i].modbits < 1024)) {
				testcase_skip("ICSF Token cannot be used with "
					      "publ_exp='%s'.",s);
				continue;
			}
		}

                // free memory
                free(s);

		rc = CKR_OK; // set rc

		// clear buffers
                memset(message, 0, MAX_MESSAGE_SIZE);
                memset(signature, 0, MAX_SIGNATURE_SIZE);

		// get test vector parameters
		message_len = tsuite->tv[i].inputlen;

		// generate key pair
                rc = generate_RSA_PKCS_KeyPair(session,
                                        tsuite->tv[i].modbits,
                                        tsuite->tv[i].publ_exp,
                                        tsuite->tv[i].publ_exp_len,
                                        &publ_key,
                                        &priv_key);
                if (rc != CKR_OK) {
                        testcase_error("generate_RSA_PKCS_KeyPair(), "
					"rc=%s", p11_get_ckr(rc));
                        goto testcase_cleanup;
                }

		// generate message
		for (j = 0; j < message_len; j++) {
			message[j] = (j + 1) % 255;
		}

		// get  mech
		mech = tsuite->mech;

		// initialize Sign (length only)
		rc = funcs->C_SignInit(session,
				&mech,
				priv_key);
		if (rc != CKR_OK){
			testcase_error("C_SignInit(), rc=%s", p11_get_ckr(rc));
			goto error;
		}

		// set buffer size
		signature_len = MAX_SIGNATURE_SIZE;

		// do Sign
		rc = funcs->C_Sign(session,
				message,
				message_len,
				signature,
				&signature_len);
		if (rc != CKR_OK) {
			testcase_error("C_Sign(), rc=%s signature len=%ld",
				p11_get_ckr(rc), signature_len);
			goto error;
		}


		// initialize Verify
		rc = funcs->C_VerifyInit(session,
				&mech,
				publ_key);
		if (rc != CKR_OK) {
			testcase_error("C_VerifyInit(), rc=%s",
				p11_get_ckr(rc));
		}

		// do Verify
		rc = funcs->C_Verify(session,
				message,
				message_len,
				signature,
				signature_len);

		// check results
		testcase_new_assertion();
		if (rc == CKR_OK) {
			testcase_pass("C_Verify.");
		}
		else {
			testcase_fail("C_Verify(), rc=%s", p11_get_ckr(rc));
		}

		// clean up
		rc = funcs->C_DestroyObject(session, publ_key);
		if (rc != CKR_OK) {
			testcase_error("C_DestroyObject(), rc=%s.",
				p11_get_ckr(rc));
		}

		rc = funcs->C_DestroyObject(session, priv_key);
		if (rc != CKR_OK) {
			testcase_error("C_DestroyObject(), rc=%s.",
				p11_get_ckr(rc));
		}
        }
	goto testcase_cleanup;
error:
	loc_rc = funcs->C_DestroyObject(session, publ_key);
	if (loc_rc != CKR_OK) {
		testcase_error("C_DestroyObject, rc=%s.", p11_get_ckr(loc_rc));
	}
	loc_rc = funcs->C_DestroyObject(session, priv_key);
	if (loc_rc != CKR_OK) {
		testcase_error("C_DestroyObject, rc=%s.", p11_get_ckr(loc_rc));
	}

testcase_cleanup:
	testcase_user_logout();
	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		testcase_error("C_CloesAllSessions, rc=%s", p11_get_ckr(rc));
	}
	return rc;
}


/* This function should test:
 * RSA Key Generation, usign CKM_RSA_PKCS_KEY_PAIR_GEN
 * RSA-PSS Sign, mechanism chosen by caller
 * RSA-PSS Verify, mechanism chosen by caller
 *
 * 1. Generate RSA Key Pair
 * 2. Generate message
 * 3. Generate hash for the message if required by mechanism.
 * 4. Sign message
 * 5. Verify signature
 *
 */
#define MAX_HASH_SIZE 64
CK_RV do_SignVerify_RSAPSS(struct GENERATED_TEST_SUITE_INFO *tsuite)
{
	int i; // test vector index
	int j; // message byte index
	CK_BYTE	message[MAX_MESSAGE_SIZE];
	CK_BYTE	signature[MAX_SIGNATURE_SIZE];
	CK_BYTE hash[MAX_HASH_SIZE];
	CK_ULONG message_len, signature_len, h_len;

	CK_MECHANISM mech;
	CK_OBJECT_HANDLE publ_key, priv_key;

	CK_SLOT_ID slot_id = SLOT_ID;
	CK_SESSION_HANDLE session;
	CK_FLAGS flags;
	CK_BYTE	user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG user_pin_len;
	CK_RV rc, loc_rc;
	CK_RSA_PKCS_PSS_PARAMS pss_params;

	char *s;

	// begin testsuite
	testsuite_begin("%s Sign Verify.", tsuite->name);
	testcase_rw_session();
	testcase_user_login();

	// skip tests if the slot doesn't support this mechanism
	if (! mech_supported(slot_id, tsuite->mech.mechanism)){
		testsuite_skip(tsuite->tvcount,
			"Slot %u doesn't support %u",
			(unsigned int) slot_id,
                        (unsigned int) tsuite->mech.mechanism );
                goto testcase_cleanup;
	}

	// iterate over test vectors
	for (i = 0; i < tsuite->tvcount; i++){

                // get public exponent from test vector
                if ( p11_ahex_dump(&s, tsuite->tv[i].publ_exp,
                                tsuite->tv[i].publ_exp_len) == NULL) {
                        testcase_error("p11_ahex_dump() failed");
                        rc = -1;
                        goto testcase_cleanup;
                }

                // begin test
                testcase_begin("%s Sign and Verify with test vector %d, "
                        "\npubl_exp='%s', mod_bits='%lu', keylen='%lu'.",
			tsuite->name, i, s,
                        tsuite->tv[i].modbits,
                        tsuite->tv[i].keylen);

		if (!keysize_supported(slot_id, tsuite->mech.mechanism,
					tsuite->tv[i].modbits)) {
			testcase_skip("Token in slot %ld cannot be used with "
					"modbits.='%ld'",
					SLOT_ID,tsuite->tv[i].modbits);
			continue;
		}

                // free memory
                free(s);

		rc = CKR_OK; // set rc

		// clear buffers
                memset(message, 0, MAX_MESSAGE_SIZE);
                memset(signature, 0, MAX_SIGNATURE_SIZE);

		// get test vector parameters
		message_len = tsuite->tv[i].inputlen;

		// generate key pair
                rc = generate_RSA_PKCS_KeyPair(session, tsuite->tv[i].modbits,
                                        tsuite->tv[i].publ_exp,
                                        tsuite->tv[i].publ_exp_len, &publ_key,
                                        &priv_key);
                if (rc != CKR_OK) {
                        testcase_error("generate_RSA_PKCS_KeyPair(), "
					"rc=%s", p11_get_ckr(rc));
                        goto error;
                }

		// generate message
		for (j = 0; j < message_len; j++) {
			message[j] = (j + 1) % 255;
		}
		
		if (tsuite->mech.mechanism == CKM_RSA_PKCS_PSS) {
			// create digest of message to pass to C_Sign
			mech.mechanism = tsuite->tv[i].pss_params.hashAlg;
			mech.pParameter = 0;
			mech.ulParameterLen = 0;

			h_len = MAX_HASH_SIZE;

			rc = funcs->C_DigestInit(session, &mech);
			if (rc != CKR_OK) {
				testcase_error("C_DigestInit rc=%s",
						p11_get_ckr(rc));
				goto testcase_cleanup;
			}
			rc = funcs->C_Digest(session, message, message_len,
					     hash, &h_len);
			if (rc != CKR_OK) {
				testcase_error("C_Digest rc=%s", p11_get_ckr(rc));
				goto testcase_cleanup;
			}
		}

		// set mechanism for signing
		mech = tsuite->mech;
		pss_params = tsuite->tv[i].pss_params;
		mech.pParameter = &pss_params;
		mech.ulParameterLen = sizeof(CK_RSA_PKCS_PSS_PARAMS);

		// initialize Sign 
		rc = funcs->C_SignInit(session, &mech, priv_key);
		if (rc != CKR_OK) {
			testcase_error("C_SignInit(), rc=%s", p11_get_ckr(rc));
			goto error;
		}

		// set buffer size
		signature_len = MAX_SIGNATURE_SIZE;

		// do Sign
		if (mech.mechanism == CKM_RSA_PKCS_PSS)
			rc = funcs->C_Sign(session, hash, h_len, signature,
					   &signature_len);
		else
			rc = funcs->C_Sign(session, message, message_len,
					   signature, &signature_len);
		if (rc != CKR_OK) {
			testcase_error("C_Sign(), rc=%s signature len=%ld",
				p11_get_ckr(rc), signature_len);
			goto error;
		}


		// initialize Verify
		rc = funcs->C_VerifyInit(session, &mech, publ_key);
		if (rc != CKR_OK) {
			testcase_error("C_VerifyInit(), rc=%s",
				p11_get_ckr(rc));
		}

		// do Verify
		if (mech.mechanism == CKM_RSA_PKCS_PSS)
			rc = funcs->C_Verify(session, hash, h_len, signature,
					     signature_len);
		else
			rc = funcs->C_Verify(session, message, message_len,
					     signature, signature_len);

		// check results
		testcase_new_assertion();
		if (rc == CKR_OK)
			testcase_pass("C_Verify.");
		else 
			testcase_fail("C_Verify(), rc=%s", p11_get_ckr(rc));

		// clean up
		rc = funcs->C_DestroyObject(session, publ_key);
		if (rc != CKR_OK) {
			testcase_error("C_DestroyObject(), rc=%s.",
				p11_get_ckr(rc));
		}

		rc = funcs->C_DestroyObject(session, priv_key);
		if (rc != CKR_OK) {
			testcase_error("C_DestroyObject(), rc=%s.",
				p11_get_ckr(rc));
		}
        }
	goto testcase_cleanup;
error:
	loc_rc = funcs->C_DestroyObject(session, publ_key);
	if (loc_rc != CKR_OK) {
		testcase_error("C_DestroyObject, rc=%s.", p11_get_ckr(loc_rc));
	}
	loc_rc = funcs->C_DestroyObject(session, priv_key);
	if (loc_rc != CKR_OK) {
		testcase_error("C_DestroyObject, rc=%s.", p11_get_ckr(loc_rc));
	}

testcase_cleanup:
	testcase_user_logout();
	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		testcase_error("C_CloesAllSessions, rc=%s", p11_get_ckr(rc));
	}
	return rc;
}


/* This function should test:
 * RSA Key Generation, using CKM_PKCS_KEY_PAIR_GEN
 * RSA Public-Key Wrap
 * RSA Private-Key Unwrap
 *
 */
CK_RV do_WrapUnwrapRSA(struct GENERATED_TEST_SUITE_INFO *tsuite)
{
	int			i = 0, j = 0;
	CK_OBJECT_HANDLE        publ_key, priv_key, secret_key, unwrapped_key;
	CK_BYTE_PTR		wrapped_key = NULL;
	CK_ULONG		wrapped_keylen, unwrapped_keylen;
	CK_MECHANISM		wrap_mech, keygen_mech, mech;
	CK_BYTE			clear[32];
	CK_BYTE			cipher[32];
	CK_BYTE			re_cipher[32];
	CK_ULONG		cipher_len = 32;
	CK_ULONG		re_cipher_len = 32;
	CK_RSA_PKCS_OAEP_PARAMS oaep_params;

	char 			*s;

	CK_SESSION_HANDLE	session;
	CK_FLAGS		flags;
	CK_SLOT_ID		slot_id = SLOT_ID;
	CK_BYTE			user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG		user_pin_len;
	CK_RV			rc, loc_rc;


	// begin test suite
	testsuite_begin("%s Wrap Unwrap.", tsuite->name);
	testcase_rw_session();
	testcase_user_login();

	// skip all tests if the slot doesn't support this mechanism
        if (! mech_supported(slot_id, tsuite->mech.mechanism)){
                testsuite_skip(tsuite->tvcount,
                           "Slot %u doesn't support %u",
                           (unsigned int) slot_id,
                           (unsigned int) tsuite->mech.mechanism );
                goto testcase_cleanup;
        }

	// skip all tests if the slot doesn't support wrapping
	else if (! wrap_supported(slot_id, tsuite->mech)) {
		testsuite_skip(tsuite->tvcount,
			"Slot %u doesn't support key wrapping",
			(unsigned int) slot_id);
		goto testcase_cleanup;

	}

	// skip all tests if the slot doesn't support unwrapping
	else if (! unwrap_supported(slot_id, tsuite->mech)) {
		testsuite_skip(tsuite->tvcount,
			"Slot %u doesn't support key unwrapping",
			(unsigned int) slot_id);
		goto testcase_cleanup;
	}

	for (i = 0; i < tsuite->tvcount; i++) {

		// wrap templates & unwrap templates
		CK_ATTRIBUTE            unwrap_tmpl[] = {
						{CKA_CLASS, NULL, 0},
						{CKA_KEY_TYPE, NULL, 0},
						{CKA_VALUE_LEN, NULL, 0}
					};
		CK_ULONG                unwrap_tmpl_len;

		// get public exponent from test vector
		if ( p11_ahex_dump(&s, tsuite->tv[i].publ_exp,
				tsuite->tv[i].publ_exp_len) == NULL) {
				testcase_error("p11_ahex_dump() failed");
			rc = -1;
			goto testcase_cleanup;
		}

		// begin test
		testcase_begin("%s Wrap Unwrap with test vector %d, "
			"\npubl_exp='%s', mod_bits='%lu', keylen='%lu', "
			"keytype='%s'", tsuite->name, i, s,
			tsuite->tv[i].modbits,
			tsuite->tv[i].keylen,
			p11_get_ckm(tsuite->tv[i].keytype.mechanism));

		// free memory
		free(s);

		// get key gen mechanism
		keygen_mech = tsuite->tv[i].keytype;

		// get wrapping mechanism
		wrap_mech = tsuite->mech;
		if (wrap_mech.mechanism == CKM_RSA_PKCS_OAEP) {
			oaep_params = tsuite->tv[i].oaep_params;
			wrap_mech.pParameter = &oaep_params;
			wrap_mech.ulParameterLen = sizeof(CK_RSA_PKCS_OAEP_PARAMS);
		}

		// skip this test if the slot doesn't support this
		// keygen mechanism
		if (! mech_supported(slot_id,
			keygen_mech.mechanism)) {
			testcase_skip();
			continue;
		}

		if (!keysize_supported(slot_id, tsuite->mech.mechanism,
					tsuite->tv[i].modbits)) {
			testcase_skip("Token in slot %ld cannot be used with "
					"modbits.='%ld'",
					SLOT_ID,tsuite->tv[i].modbits);
			continue;
		}

		if (is_ep11_token(slot_id)) {
			if (! is_valid_ep11_pubexp(tsuite->tv[i].publ_exp,
						  tsuite->tv[i].publ_exp_len)) {
				testcase_skip("EP11 Token cannot "
					       "be used with publ_exp.='%s'",s);
				continue;
			}
		}

		// initialize buffer lengths
		wrapped_keylen = PKCS11_MAX_PIN_LEN;

		// generate RSA key pair
		rc = generate_RSA_PKCS_KeyPair(session,
				tsuite->tv[i].modbits,
				tsuite->tv[i].publ_exp,
				tsuite->tv[i].publ_exp_len,
				&publ_key,
				&priv_key);
		if (rc != CKR_OK) {
                        testcase_error("C_GenerateKeyPair() rc = %s",
					p11_get_ckr(rc));
                        goto testcase_cleanup;
		}

		// generate secret key
		rc = generate_SecretKey(session,
				tsuite->tv[i].keylen,
				&keygen_mech,
				&secret_key);
		if (rc != CKR_OK) {
			testcase_error("generate_SecretKey(), rc=%s",
				p11_get_ckr(rc));
			goto error;
		}

		// extract CKA_CLASS and CKA_KEY_TYPE from generated key
		// we will use this for unwrapping

		// extract sizes first
		rc = funcs->C_GetAttributeValue(session,
						secret_key,
						unwrap_tmpl,
						2);
		if (rc != CKR_OK) {
			testcase_error("C_GetAttributeValue(), rc=%s",
					p11_get_ckr(rc));
			goto error;
		}

		// allocate memory for extraction
		unwrap_tmpl[0].pValue = calloc(sizeof(CK_BYTE),
						unwrap_tmpl[0].ulValueLen);
		unwrap_tmpl[1].pValue = calloc(sizeof(CK_BYTE),
						unwrap_tmpl[1].ulValueLen);

		if ( (unwrap_tmpl[0].pValue == NULL) ||
			(unwrap_tmpl[1].pValue == NULL) ) {
			testcase_error("Error allocating %lu bytes"
				"for unwrap template attributes",
				unwrap_tmpl[0].ulValueLen +
				unwrap_tmpl[1].ulValueLen);
			rc = -1;
			goto error;
		}

		// now extract values
		rc = funcs->C_GetAttributeValue(session,
						secret_key,
						unwrap_tmpl,
						2);
		if (rc != CKR_OK) {
			testcase_error("C_GetAttributeValue(), rc=%s",
					p11_get_ckr(rc));
			goto error;
		}

		// wrap key (length only)
		rc = funcs->C_WrapKey(session,
				&wrap_mech,
				publ_key,
				secret_key,
				NULL,
				&wrapped_keylen);
		if (rc != CKR_OK) {
			testcase_error("C_WrapKey(), rc=%s.",
				p11_get_ckr(rc));
			goto error;
		}

		// allocate memory for wrapped_key
		wrapped_key = calloc(sizeof(CK_BYTE), wrapped_keylen);
		if (wrapped_key == NULL) {
			testcase_error("Can't allocate memory "
				"for %lu bytes.",
				sizeof(CK_BYTE) * wrapped_keylen);
			rc = -1;
			goto error;
		}

		// wrap key
		rc = funcs->C_WrapKey(session,
				&wrap_mech,
				publ_key,
				secret_key,
				wrapped_key,
				&wrapped_keylen);
		if (rc != CKR_OK) {
			testcase_error("C_WrapKey, rc=%s", p11_get_ckr(rc));
			goto error;
		}

		unwrapped_keylen = tsuite->tv[i].keylen;

		// variable key length specific case:
		// According to PKCS#11 v2.2 section 12.1.12
		// CKM_RSA_X_509 does not wrap the key type, key length,
		// or any other information about the key; the application
		// must convey these separately, and supply them when
		// unwrapping the key.
		if (((keygen_mech.mechanism == CKM_AES_KEY_GEN) ||
		    (keygen_mech.mechanism == CKM_GENERIC_SECRET_KEY_GEN)) && 
		    (wrap_mech.mechanism == CKM_RSA_X_509)) {
			unwrapped_keylen = tsuite->tv[i].keylen;
			unwrap_tmpl[2].type = CKA_VALUE_LEN;
			unwrap_tmpl[2].ulValueLen = sizeof(unwrapped_keylen);
			unwrap_tmpl[2].pValue = &unwrapped_keylen;
			unwrap_tmpl_len = 3;
		}
		else {
			unwrap_tmpl_len = 2;
		}

		// unwrap key
		rc = funcs->C_UnwrapKey(session,
				&wrap_mech,
				priv_key,
				wrapped_key,
				wrapped_keylen,
				unwrap_tmpl,
				unwrap_tmpl_len,
				&unwrapped_key);
		if (rc != CKR_OK) {
			testcase_error("C_UnwrapKey, rc=%s",
				p11_get_ckr(rc));
			goto error;
		}

		testcase_new_assertion();

		// encode/decode with secrect key and peer secret key
		for (j = 0; j < 32; j++)
			clear[j] = j;

		switch (keygen_mech.mechanism) {
		case CKM_AES_KEY_GEN:
			mech.mechanism = CKM_AES_ECB;
			break;
		case CKM_GENERIC_SECRET_KEY_GEN:
		case CKM_DES3_KEY_GEN:
			mech.mechanism = CKM_DES3_ECB;
			break;
		case CKM_DES_KEY_GEN:
			mech.mechanism = CKM_DES_ECB;
			break;
		case CKM_CDMF_KEY_GEN:
			mech.mechanism = CKM_CDMF_ECB;
			break;
		default:
			testcase_error("unknowm mech");
			goto error;
		}
		
		mech.ulParameterLen = 0;
		mech.pParameter = NULL;

		rc = funcs->C_EncryptInit(session, &mech, secret_key);
		if (rc != CKR_OK) {
			testcase_error("C_EncryptInit secret_key: rc = %s",
					p11_get_ckr(rc));
			goto error;
		}

		rc = funcs->C_Encrypt(session, clear, 32, cipher, &cipher_len);
		if (rc != CKR_OK) {
			testcase_error("C_Encrypt secret_key: rc = %s",
					p11_get_ckr(rc));
			goto error;
		}

		rc = funcs->C_DecryptInit(session,&mech,unwrapped_key);
		if (rc != CKR_OK) {
			testcase_error("C_DecryptInit unwrapped_key: rc = %s",
					p11_get_ckr(rc));
			goto error;
		}

		rc = funcs->C_Decrypt(session, cipher, cipher_len, re_cipher,
					&re_cipher_len);
		if (rc != CKR_OK) {
		testcase_error("C_Decrypt unwrapped_key: rc = %s",
				p11_get_ckr(rc));
			testcase_fail("Unwrapped key differs in CKA_VALUE.");
			goto error;
		}

		if (memcmp(clear, re_cipher, 32) != 0) {
			testcase_fail("ERROR:data mismatch\n");
			goto error;
		} else
			testcase_pass("C_Wrap and C_Unwrap.");

		// clean up
		if (wrapped_key)
			free(wrapped_key);

		rc = funcs->C_DestroyObject(session, secret_key);
		if (rc != CKR_OK) {
			testcase_error("C_DestroyObject(), rc=%s.",
					p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		rc = funcs->C_DestroyObject(session, publ_key);
		if (rc != CKR_OK) {
			testcase_error("C_DestroyObject(), rc=%s.",
					p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		rc = funcs->C_DestroyObject(session, priv_key);
		if (rc != CKR_OK) {
			testcase_error("C_DestroyObject(), rc=%s.",
					p11_get_ckr(rc));
			goto testcase_cleanup;
		}
	}
	goto testcase_cleanup;

error:
	if (wrapped_key)
		free(wrapped_key);

	funcs->C_DestroyObject(session, secret_key);
	funcs->C_DestroyObject(session, publ_key);
	funcs->C_DestroyObject(session, priv_key);

testcase_cleanup:
	testcase_user_logout();
	loc_rc = funcs->C_CloseAllSessions(slot_id);
	if (loc_rc != CKR_OK) {
		testcase_error("C_CloseAllSessions(), rc=%s.",
			p11_get_ckr(rc));
	}
	return rc;
}


/* This function should test:
 * C_Sign, mechanism chosen by caller
 *
 * 1. Get message from test vector
 * 2. Get expected signature from test vector
 * 3. Sign message
 * 4. Compare expected signature with actual signature
 *
 */
CK_RV do_SignRSA(struct PUBLISHED_TEST_SUITE_INFO *tsuite)
{
	int 			i;
	CK_BYTE			message[MAX_MESSAGE_SIZE];
	CK_BYTE			actual[MAX_SIGNATURE_SIZE];
	CK_BYTE			expected[MAX_SIGNATURE_SIZE];
	CK_ULONG		message_len, actual_len, expected_len;

	CK_MECHANISM		mech;
	CK_OBJECT_HANDLE	priv_key;

	CK_SLOT_ID		slot_id = SLOT_ID;
	CK_SESSION_HANDLE	session;
	CK_FLAGS		flags;
	CK_BYTE			user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG		user_pin_len;
	CK_RV			rc, loc_rc;

	// begin testsuite
	testsuite_begin("%s Sign. ", tsuite->name);
	testcase_rw_session();
	testcase_user_login();

	// skip tests if the slot doesn't support this mechanism **/
        if (! mech_supported(slot_id, tsuite->mech.mechanism)){
                testsuite_skip(tsuite->tvcount,
                           "Slot %u doesn't support %u",
                           (unsigned int) slot_id,
                           (unsigned int) tsuite->mech.mechanism );
                goto testcase_cleanup;
        }

	// iterate over test vectors
	for (i = 0; i < tsuite->tvcount; i++){
		testcase_begin("%s Sign with test vector %d.",
				tsuite->name, i);

		rc = CKR_OK; // set return value

		// special case for ica
		// prime1, prime2, exp1, exp2, coef
		// must be size mod_len/2 or smaller
		// skip test if prime1, or prime2, or exp1,
		// or exp2 or coef are too long
		if (is_ica_token(slot_id)) {
			// check sizes
			if ((tsuite->tv[i].prime1_len >
				(tsuite->tv[i].mod_len/2)) ||
				(tsuite->tv[i].prime2_len >
				(tsuite->tv[i].mod_len/2)) ||
				(tsuite->tv[i].exp1_len >
				(tsuite->tv[i].mod_len/2)) ||
				(tsuite->tv[i].exp2_len >
				(tsuite->tv[i].mod_len/2)) ||
				(tsuite->tv[i].coef_len >
				(tsuite->tv[i].mod_len/2))) {
				testcase_skip("ICA Token cannot be used with "
					"this test vector.");
				continue;
			}

		}

		// special case for EP11
		// modulus length must be multiple of 128 byte
		// skip test if modulus length has unsuported size
		if (is_ep11_token(slot_id)) {
			if ((tsuite->tv[i].mod_len%128) != 0){
				testcase_skip("EP11 Token cannot be used with "
						"this test vector.");
				continue;
			}
		}

		if (is_tpm_token(slot_id)) {
                        if ((! is_valid_tpm_pubexp(tsuite->tv[i].pub_exp,
                                tsuite->tv[i].pubexp_len)) || (!is_valid_tpm_modbits(tsuite->tv[i].mod_len))) {
                                testcase_skip("TPM Token cannot "
                                        "be used with this test vector.");
                                continue;
                        }
                }

		// clear buffers
		memset(message, 0, MAX_MESSAGE_SIZE);
		memset(actual, 0, MAX_SIGNATURE_SIZE);
		memset(expected, 0, MAX_SIGNATURE_SIZE);

		actual_len = MAX_SIGNATURE_SIZE; // set buffer size

		// get message
		message_len = tsuite->tv[i].msg_len;
		memcpy(message, tsuite->tv[i].msg, message_len);

		// get (expected) signature
		expected_len = tsuite->tv[i].sig_len;
		memcpy(expected, tsuite->tv[i].sig, expected_len);

		// create (private) key handle
		rc = create_RSAPrivateKey(session,
                                        tsuite->tv[i].mod,
                                        tsuite->tv[i].pub_exp,
                                        tsuite->tv[i].priv_exp,
                                        tsuite->tv[i].prime1,
                                        tsuite->tv[i].prime2,
                                        tsuite->tv[i].exp1,
                                        tsuite->tv[i].exp2,
                                        tsuite->tv[i].coef,
					tsuite->tv[i].mod_len,
					tsuite->tv[i].pubexp_len,
					tsuite->tv[i].privexp_len,
					tsuite->tv[i].prime1_len,
					tsuite->tv[i].prime2_len,
					tsuite->tv[i].exp1_len,
					tsuite->tv[i].exp2_len,
					tsuite->tv[i].coef_len,
                                        &priv_key);
                if (rc != CKR_OK) {
                        testcase_error("create_RSAPrivateKey(), rc=%s",
                                p11_get_ckr(rc));
                        goto error;
                }

		// set mechanism
		mech = tsuite->mech;

		// initialize signing
		rc = funcs->C_SignInit(session, &mech, priv_key);
		if (rc != CKR_OK) {
			testcase_error("C_SignInit(), rc=%s.", p11_get_ckr(rc));
			goto error;
		}

		// do signing
		rc = funcs->C_Sign(session,
				message,
				message_len,
				actual,
				&actual_len);

		if (rc != CKR_OK) {
			testcase_error("C_Sign(), rc=%s.", p11_get_ckr(rc));
			goto error;
		}

		// check results
		testcase_new_assertion();

		if (actual_len != expected_len) {
			testcase_fail("%s Sign with test vector %d failed. "
				"Expected len=%ld, found len=%ld.",
				tsuite->name, i, expected_len, actual_len);
		}

		else if (memcmp(actual, expected, expected_len)) {
			testcase_fail("%s Sign with test vector %d failed. "
				"Signature data does not match test vector "
				"signature.", tsuite->name, i);

		}

		else {
			testcase_pass("C_Sign.");
		}

		// clean up
		rc = funcs->C_DestroyObject(session, priv_key);
		if (rc != CKR_OK) {
			testcase_error("C_DestroyObject(), rc=%s.",
				p11_get_ckr(rc));
			goto testcase_cleanup;
		}
	}
	goto testcase_cleanup;
error:
	loc_rc = funcs->C_DestroyObject(session, priv_key);
	if (loc_rc != CKR_OK) {
		testcase_error("C_DestroyObject, rc=%s.", p11_get_ckr(loc_rc));
	}
testcase_cleanup:
	testcase_user_logout();
	loc_rc = funcs->C_CloseAllSessions(slot_id);
	if (loc_rc != CKR_OK) {
		testcase_error("C_CloseAllSessions, rc=%s.", p11_get_ckr(rc));
	}
	return rc;
}

/* This function should test:
 * C_Verify, mechanism chosen by caller
 *
 * 1. Get message from test vector
 * 2. Get signature from test vector
 * 3. Verify signature
 *
 */
CK_RV do_VerifyRSA(struct PUBLISHED_TEST_SUITE_INFO *tsuite)
{
	int			i;
	CK_BYTE			actual[MAX_SIGNATURE_SIZE];
	CK_BYTE			message[MAX_MESSAGE_SIZE];
	CK_ULONG		message_len;
	CK_BYTE			signature[MAX_SIGNATURE_SIZE];
	CK_ULONG		signature_len;

	CK_MECHANISM		mech;
	CK_OBJECT_HANDLE	publ_key;

	CK_SLOT_ID		slot_id = SLOT_ID;
	CK_SESSION_HANDLE	session;
	CK_FLAGS		flags;
	CK_BYTE			user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG		user_pin_len;
	CK_RV			rc, loc_rc;

	// begin testsuite
	testsuite_begin("%s Verify.", tsuite->name);
	testcase_rw_session();
	testcase_user_login();

	// skip tests if the slot doesn't support this mechanism
        if (! mech_supported(slot_id, tsuite->mech.mechanism)){
                testsuite_skip(tsuite->tvcount,
                           "Slot %u doesn't support %u",
                           (unsigned int) slot_id,
                           (unsigned int) tsuite->mech.mechanism );
                goto testcase_cleanup;
        }

	// iterate over test vectors
	for (i = 0; i < tsuite->tvcount; i++){

		testcase_begin("%s Verify with test vector %d.",
				tsuite->name, i);

		rc = CKR_OK; // set return value

		// special case for EP11
		// modulus length must be multiple of 128 byte
		// skip test if modulus length has unsuported size
		if (is_ep11_token(slot_id)) {
			if ((tsuite->tv[i].mod_len%128) != 0){
				testcase_skip("EP11 Token cannot be used with "
						"this test vector.");
				continue;
			}
		}

		if (is_tpm_token(slot_id)) {
                        if ((! is_valid_tpm_pubexp(tsuite->tv[i].pub_exp,
                                tsuite->tv[i].pubexp_len)) || (!is_valid_tpm_modbits(tsuite->tv[i].mod_len))) {
                                testcase_skip("TPM Token cannot "
                                        "be used with this test vector.");
                                continue;
                        }
                }

		// clear buffers
		memset(message, 0, MAX_MESSAGE_SIZE);
		memset(signature, 0, MAX_SIGNATURE_SIZE);
		memset(actual, 0, MAX_SIGNATURE_SIZE);

		// get message
		message_len = tsuite->tv[i].msg_len;
		memcpy(message, tsuite->tv[i].msg, message_len);

		// get signature
		signature_len = tsuite->tv[i].sig_len;
		memcpy(signature, tsuite->tv[i].sig, signature_len);

		// create (public) key handle
		rc = create_RSAPublicKey(session,
				tsuite->tv[i].mod,
				tsuite->tv[i].pub_exp,
				tsuite->tv[i].mod_len,
				tsuite->tv[i].pubexp_len,
				&publ_key);

		if (rc != CKR_OK) {
			testcase_error("create_RSAPublicKey(), rc=%s",
				p11_get_ckr(rc));
			goto error;
		}

		// set mechanism
		mech = tsuite->mech;

		// initialize verify
		rc = funcs->C_VerifyInit(session, &mech, publ_key);
		if (rc != CKR_OK) {
			testcase_error("C_VerifyInit(), rc=%s",
				p11_get_ckr(rc));
			goto error;
		}

		// do verify
		rc = funcs->C_Verify(session,
			message,
			message_len,
			signature,
			signature_len);

		// check result
		testcase_new_assertion();

		if (rc == CKR_OK){
			testcase_pass("C_Verify.");
		}

		else {
			testcase_fail("%s Sign Verify with test vector %d "
				"failed.", tsuite->name, i);
		}

		// clean up
		rc = funcs->C_DestroyObject(session, publ_key);
		if (rc != CKR_OK) {
			testcase_error("C_DestroyObject(), rc=%s.",
				p11_get_ckr(rc));
			goto testcase_cleanup;
		}

	}
	goto testcase_cleanup;
error:
	loc_rc = funcs->C_DestroyObject(session, publ_key);
	if (loc_rc != CKR_OK) {
		testcase_error("C_DestroyObject(), rc=%s.",
			p11_get_ckr(loc_rc));
	}

testcase_cleanup:
        testcase_user_logout();
        rc = funcs->C_CloseAllSessions(slot_id);
        if (rc != CKR_OK) {
                testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
        }
        return rc;
}

CK_RV rsa_funcs()
{
	int 	i;
	CK_RV	rv = CKR_OK;

	// published (known answer) tests
	for (i = 0; i < NUM_OF_PUBLISHED_TESTSUITES; i++) {
		rv = do_SignRSA(&published_test_suites[i]);
		if (rv != CKR_OK && (!no_stop))
			break;

		rv = do_VerifyRSA(&published_test_suites[i]);
		if (rv != CKR_OK && (!no_stop))
			break;
	}

	// generated sign verify tests
	for (i = 0; i < NUM_OF_GENERATED_SIGVER_TESTSUITES; i++) {
		rv = do_SignVerifyRSA(&generated_sigver_test_suites[i]);
		if (rv != CKR_OK && (!no_stop))
			break;
	}

	for (i = 0; i < NUM_OF_GENERATED_PSS_TESTSUITES; i++) {
		rv = do_SignVerify_RSAPSS(&generated_pss_test_suites[i]);
		if (rv != CKR_OK && (!no_stop))
			break;
	}

	// generated crypto tests
	for (i = 0; i < NUM_OF_GENERATED_CRYPTO_TESTSUITES; i++) {
		rv = do_EncryptDecryptRSA(&generated_crypto_test_suites[i]);
		if (rv != CKR_OK && (!no_stop))
			break;
	}

	for (i = 0; i < NUM_OF_GENERATED_OAEP_TESTSUITES; i++) {
		rv = do_EncryptDecryptRSA(&generated_oaep_test_suites[i]);
		if (rv != CKR_OK && (!no_stop))
			break;
	}

	for ( i = 0; i < NUM_OF_GENERATED_OAEP_TESTSUITES; i++) {
		rv = do_WrapUnwrapRSA(&generated_oaep_test_suites[i]);
		if (rv != CKR_OK && (!no_stop))
			break;
	}

	// generated keywrap tests
	for ( i = 0; i < NUM_OF_GENERATED_KEYWRAP_TESTSUITES; i++) {
		rv = do_WrapUnwrapRSA(&generated_keywrap_test_suites[i]);
		if (rv != CKR_OK && (!no_stop))
			break;
	}

	return rv;
}

int main  (int argc, char **argv){
        int rc;
        CK_C_INITIALIZE_ARGS cinit_args;
        CK_RV rv;

        rc = do_ParseArgs(argc, argv);
        if(rc != 1){
                return rc;
        }

        printf("Using slot #%lu...\n\n", SLOT_ID);
        printf("With option: no_stop: %d\n", no_stop);

        rc = do_GetFunctionList();
        if(! rc) {
                PRINT_ERR("ERROR do_GetFunctionList() Failed, rx = 0x%0x\n", rc);
                return rc;
        }

        memset( &cinit_args, 0x0, sizeof(cinit_args) );
        cinit_args.flags = CKF_OS_LOCKING_OK;

        funcs->C_Initialize( &cinit_args );
        {
                CK_SESSION_HANDLE hsess = 0;
                rc = funcs->C_GetFunctionStatus(hsess);
                if (rc != CKR_FUNCTION_NOT_PARALLEL){
                    return rc;
                }

                rc = funcs->C_CancelFunction(hsess);
                if (rc != CKR_FUNCTION_NOT_PARALLEL){
                    return rc;
                }
        }

	testcase_setup(0);
	rv = rsa_funcs();
	testcase_print_result();
	return rv;
}
