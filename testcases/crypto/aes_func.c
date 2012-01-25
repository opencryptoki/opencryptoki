#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"
#include "aes.h"
#include "common.c"

CK_ULONG key_lens[] = {16, 24, 32};

/* aes-ctr has 3encck+3decck+3encsk+3decsk+3keywrap+1RSA
 * aes-ecb has 3encck+3decck+3encsk+3decsk+3keywrap+1RSA
 * aec-cbc has 3encck+3decck+3encsk+3decsk+3keywrap+3encpad+3decpad+
 * 	       3keywrappad+2RSA
 * Note: securekey and clearkey both have 3enc and 3dec, so number
 * of assertions is the same whether using clearkey or securekey.
 */

CK_RV do_EncryptDecryptAES(struct generated_test_suite_info *tsuite)
{
	int		i;
	CK_BYTE		original[BIG_REQUEST];
	CK_BYTE		crypt[BIG_REQUEST + AES_BLOCK_SIZE];
	CK_BYTE		decrypt[BIG_REQUEST + AES_BLOCK_SIZE];
	CK_BYTE		user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG	j;
	CK_ULONG	user_pin_len;
	CK_ULONG	orig_len, crypt_len, decrypt_len;

	CK_SESSION_HANDLE	session;
	CK_MECHANISM		mechkey, mech;
	CK_OBJECT_HANDLE	h_key;
	CK_FLAGS		flags;
	CK_RV			rc = 0;
	CK_SLOT_ID	       slot_id = SLOT_ID;

	testsuite_begin("%s Encryption/Decryption.",tsuite->name);
	testcase_rw_session();
	testcase_user_login();

	/** skip tests if the slot doesn't support this mechanism **/
	if (! mech_supported(slot_id, tsuite->mech.mechanism)){
		testsuite_skip(3,
			"Slot %u doesn't support %u",
			(unsigned int) slot_id,
			(unsigned int) tsuite->mech.mechanism);
		goto testcase_cleanup;
	}


	/** iterate over test key sizes **/
	for (i = 0; i < 3; i++) {

		testcase_begin("%s Encryption/Decryption with key len=%ld.",
			tsuite->name, key_lens[i]);

		/** generate key **/
		mechkey = aes_keygen;
		rc = generate_AESKey(session, key_lens[i], &mechkey, &h_key);

		if (rc != CKR_OK) {
			testcase_error("C_GenerateKey rc=%s",
				p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		/** clear buffers **/
		memset(original,0,sizeof(original));
		memset(crypt,0,sizeof(crypt));
		memset(decrypt,0,sizeof(decrypt));

		/** generate data **/
		orig_len = sizeof(original);

		for (j=0; j < orig_len; j++)
			original[j] = j % 255;

		/** set crypto mech **/
		mech = tsuite->mech;

		/** single encryption **/
		rc = funcs->C_EncryptInit(session, &mech, h_key);
		if (rc != CKR_OK) {
			testcase_error("C_EncryptInit rc=%s",
				p11_get_ckr(rc));
			goto error;
		}

		crypt_len = sizeof(crypt);

		rc = funcs->C_Encrypt(session,
				original,
				orig_len,
				crypt,
				&crypt_len);

		if (rc != CKR_OK) {
			testcase_error("C_Encrypt rc=%s",
				p11_get_ckr(rc));
			goto error;
		}

		/** single decryption **/
		rc = funcs->C_DecryptInit(session, &mech, h_key);
		if (rc != CKR_OK) {
			testcase_error("C_DecryptInit rc=%s",
				p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		decrypt_len = sizeof(decrypt);

		rc = funcs->C_Decrypt(session,
				crypt,
				crypt_len,
				decrypt,
				&decrypt_len);

		if (rc != CKR_OK) {
			testcase_error("C_Decrypt rc=%s",
				p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		/** compare actual results with expected results **/
		testcase_new_assertion();

		if (decrypt_len != orig_len) {
		       testcase_fail("decrypted data length does not "
				"match original data length.\nexpected "					"length=%ld, but found length=%ld\n",
				orig_len, decrypt_len);
		}

		else if (memcmp(decrypt, original, orig_len)){
			testcase_fail("decrypted data does not match "
				"original data");
		}

		else {
			testcase_pass("%s Encryption/Decryption with "
				"key length %ld passed.", tsuite->name, 					key_lens[i]);
		}

	}
	/** clean up **/
	rc = funcs->C_DestroyObject(session, h_key);
	if (rc != CKR_OK) {
		testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));
	}
	goto testcase_cleanup;

error:
	rc = funcs->C_DestroyObject(session, h_key);
	if (rc != CKR_OK)
		testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));

testcase_cleanup:
	testcase_user_logout();
	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
	}
	return rc;
}

CK_RV do_EncryptDecryptUpdateAES(struct generated_test_suite_info *tsuite)
{
	int		i;
	CK_BYTE		original[BIG_REQUEST];
	CK_BYTE		crypt[BIG_REQUEST + AES_BLOCK_SIZE];
	CK_BYTE		decrypt[BIG_REQUEST + AES_BLOCK_SIZE];
	CK_BYTE		user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG	j, k, tmp;
	CK_ULONG	user_pin_len;
	CK_ULONG	orig_len, crypt_len, decrypt_len;

	CK_SLOT_ID	      	slot_id = SLOT_ID;
	CK_SESSION_HANDLE	session;
	CK_MECHANISM		mechkey, mech;
	CK_OBJECT_HANDLE	h_key;
	CK_FLAGS		flags;
	CK_RV			rc = 0;

	/** begin testsuite **/
	testsuite_begin("%s Multipart Encryption/Decryption.", tsuite->name);
	testcase_rw_session();
	testcase_user_login();

	/** skip test if the slot doesn't support this mechanism **/
	if (! mech_supported(slot_id, tsuite->mech.mechanism)){
		testcase_skip("Slot %u doesn't support %u",
			(unsigned int) slot_id,
			(unsigned int)tsuite->mech.mechanism);
		goto testcase_cleanup;
	}

	/** iterate over key sizes **/
	for (i = 0; i < 3; i++) {

		testcase_begin("%s Multipart Encryption/Decryption with "
			"key len=%ld.", tsuite->name, key_lens[i]);

		/** generate key **/
		mechkey = aes_keygen;
		rc = generate_AESKey(session, key_lens[i], &mechkey, &h_key);

		if (rc != CKR_OK) {
			testcase_error("C_GenerateKey rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		/** clear buffers **/
		memset(original,0,sizeof(original));
		memset(crypt,0,sizeof(crypt));
		memset(decrypt,0,sizeof(decrypt));

		/** generate data **/
		orig_len = sizeof(original);

		for (j=0; j < orig_len; j++)
			original[j] = j % 255;

		/** set crypto mech **/
		mech = tsuite->mech;

		/** multipart encryption **/
		rc = funcs->C_EncryptInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			testcase_error("C_EncryptInit rc=%s", p11_get_ckr(rc));
			goto error;
		}

		j = k = 0;      // j indexes source buffer
				// k indexes destination buffer
		crypt_len = sizeof(crypt);
		while (j < orig_len) {
			tmp = crypt_len - k;  // room is left in mpcrypt
			rc = funcs->C_EncryptUpdate(session,
						&original[j],
						AES_BLOCK_SIZE,
						&crypt[k],
						&tmp);

			if (rc != CKR_OK) {
				testcase_error("C_EncryptUpdate rc=%s",
						p11_get_ckr(rc));
				goto error;
			}
			k += tmp;
			j += AES_BLOCK_SIZE;
		}

		crypt_len = sizeof(crypt) - k;

		rc = funcs->C_EncryptFinal(session, &crypt[k], &crypt_len);
		if (rc != CKR_OK) {
			testcase_error("C_EncryptFinal rc=%s", p11_get_ckr(rc));
			goto error;
		}

		crypt_len += k;

		/** multipart decryption **/
		rc = funcs->C_DecryptInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			testcase_error("C_DecryptInit rc=%s", p11_get_ckr(rc));
			goto error;
		}

		j = k = 0;      // j indexes source buffer,
				// k indexes destination buffer
		decrypt_len = sizeof(decrypt);
		while (j < crypt_len) {
			tmp = decrypt_len - k;	// room left in mpdecrypt
			rc = funcs->C_DecryptUpdate(session,
						&crypt[j],
						AES_BLOCK_SIZE,
						&decrypt[k],
						&tmp);
			if (rc != CKR_OK) {
				testcase_error("C_DecryptUpdate rc=%s",
						p11_get_ckr(rc));
				goto error;
			}
			k += tmp;
			j += AES_BLOCK_SIZE;
		}

		decrypt_len = sizeof(decrypt) - k;

		rc = funcs->C_DecryptFinal(session, &decrypt[k], &decrypt_len);
		if (rc != CKR_OK) {
			testcase_error("C_DecryptFinal rc=%s", p11_get_ckr(rc));
			goto error;
		}

		decrypt_len += k;

		/** compare actual results with expected results **/
		testcase_new_assertion();

		if (decrypt_len != orig_len) {
		       testcase_fail("decrypted multipart data length does not"
				" match original data length.\nexpected "
				"length=%ld, but found length=%ld\n",
				orig_len, decrypt_len);
		}

		else if (memcmp(decrypt, original, orig_len)){
			testcase_fail("decrypted multipart data does not match"
				" original data");
		}

		else {
			testcase_pass("%s Multipart Encryption/Decryption with"
				" key length %ld passed.",
				tsuite->name, key_lens[i]);
		}
	}

	/** clean up **/
	rc = funcs->C_DestroyObject(session, h_key);
	if (rc != CKR_OK) {
		testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));
	}
	goto testcase_cleanup;

error:
	rc = funcs->C_DestroyObject(session, h_key);
	if (rc != CKR_OK)
		testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));

testcase_cleanup:
	testcase_user_logout();
	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
	}
	return rc;
}

CK_RV do_EncryptAES(struct published_test_suite_info *tsuite)
{
	int			i;
	CK_BYTE			actual[BIG_REQUEST];    // encryption buffer
	CK_BYTE			expected[BIG_REQUEST];  // encrypted data
	CK_ULONG		actual_len, expected_len;
	CK_ULONG		user_pin_len;
	CK_BYTE			user_pin[PKCS11_MAX_PIN_LEN];
	CK_SESSION_HANDLE	session;
	CK_MECHANISM		mech;
	CK_OBJECT_HANDLE	h_key;
	CK_RV			rc;
	CK_FLAGS		flags;
	CK_SLOT_ID		slot_id = SLOT_ID;

	/** begin testsuite **/
	testsuite_begin("%s Encryption.", tsuite->name);
	testcase_rw_session();
	testcase_user_login();

	/** skip test if the slot doesn't support this mechanism **/
	if (! mech_supported(slot_id, tsuite->mech.mechanism)){
		testsuite_skip(tsuite->tvcount,
			"Slot %u doesn't support %u",
			(unsigned int) slot_id,
			(unsigned int)tsuite->mech.mechanism);
		goto testcase_cleanup;
	}

	for (i = 0; i < tsuite->tvcount; i++) {

		testcase_begin("%s Encryption with published test vector %d.",
			tsuite->name, i);

		rc = CKR_OK;

		/** create key handle **/
		rc = create_AESKey(session,
				tsuite->tv[i].key,
				tsuite->tv[i].klen,
				&h_key);

		if (rc != CKR_OK) {
			testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
			goto error;
		}

		/** get mech **/
		mech = tsuite->mech;

		/** clear buffers **/
		memset(expected, 0, sizeof(expected));
		memset(actual, 0, sizeof(actual));

		/** get ciphertext (expected results) **/
		expected_len = tsuite->tv[i].clen;
		memcpy(expected, tsuite->tv[i].ciphertext, expected_len);

		/** get plaintext **/
		actual_len = tsuite->tv[i].plen;
		memcpy(actual, tsuite->tv[i].plaintext, actual_len);

		/** single (in-place) encryption **/
		rc = funcs->C_EncryptInit(session, &mech, h_key);
		if (rc != CKR_OK) {
			testcase_error("C_EncryptInit rc=%s", p11_get_ckr(rc));
			goto error;
		}

		rc = funcs->C_Encrypt(session,
				actual,
				actual_len,
				actual,
				&actual_len);

		if (rc != CKR_OK) {
			testcase_error("C_Encrypt rc=%s", p11_get_ckr(rc));
			goto error;
		}

		/** compare actual results with expected results. **/
		testcase_new_assertion();

		if (actual_len != expected_len) {
			testcase_fail("encrypted data length does not match "
				"test vector's encrypted data length.\n\n"
				"expected length=%ld, but found length=%ld\n",
				expected_len, actual_len);
		}

		else if (memcmp(actual, expected, expected_len)) {
			testcase_fail("encrypted data does not match test "
				"vector's encrypted data");
		}

		else {
			testcase_pass("%s Encryption with test vector %d "
				"passed.", tsuite->name, i);
		}
	}
	/** clean up **/
	rc = funcs->C_DestroyObject(session, h_key);
	if (rc != CKR_OK) {
		testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	goto testcase_cleanup;

error:
	rc = funcs->C_DestroyObject(session, h_key);
	if (rc != CKR_OK)
		testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));

testcase_cleanup:
	testcase_user_logout();
	rc = funcs->C_CloseAllSessions(slot_id);
	if(rc != CKR_OK) {
		testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
	}
	return rc;
}

CK_RV do_EncryptUpdateAES(struct published_test_suite_info *tsuite)
{
	int			i;
	CK_BYTE			actual[BIG_REQUEST];    // encryption buffer
	CK_BYTE			expected[BIG_REQUEST];  // encrypted data
	CK_ULONG		actual_len, expected_len, original_len, k;
	CK_ULONG		user_pin_len;
	CK_BYTE			user_pin[PKCS11_MAX_PIN_LEN];
	CK_SESSION_HANDLE	session;
	CK_MECHANISM		mech;
	CK_OBJECT_HANDLE	h_key;
	CK_RV			rc;
	CK_FLAGS		flags;
	CK_SLOT_ID	      slot_id = SLOT_ID;

	testsuite_begin("%s Multipart Encryption.", tsuite->name);
	testcase_rw_session();
	testcase_user_login();

	rc = CKR_OK;

	/** skip test if the slot doesn't support this mechanism **/
	if (! mech_supported(slot_id, tsuite->mech.mechanism)){
		testsuite_skip(tsuite->tvcount, "Slot %u doesn't support %u",
			(unsigned int) slot_id,
			(unsigned int)tsuite->mech.mechanism);
		goto testcase_cleanup;
	}

	for (i = 0; i < tsuite->tvcount; i++) {

		testcase_begin("%s Multipart Encryption with published test "
			"vector %d.", tsuite->name, i);

		rc = CKR_OK;

		/** create key handle **/
		rc = create_AESKey(session,
				tsuite->tv[i].key,
				tsuite->tv[i].klen,
				&h_key);

		if (rc != CKR_OK) {
			testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
			goto error;
		}

		/** get mech **/
		mech = tsuite->mech;

		/** clear buffers **/
		memset(expected, 0, sizeof(expected));
		memset(actual, 0, sizeof(actual));

		/** get ciphertext (expected results) **/
		expected_len = tsuite->tv[i].clen;
		memcpy(expected, tsuite->tv[i].ciphertext, expected_len);

		/** get plaintext **/
		original_len = tsuite->tv[i].plen;
		actual_len = original_len;
		memcpy(actual, tsuite->tv[i].plaintext, actual_len);

		/** multipart (in-place) encryption **/
		rc = funcs->C_EncryptInit(session, &mech, h_key);
		if (rc != CKR_OK) {
			testcase_error("C_EncryptInit rc=%s", p11_get_ckr(rc));
			goto error;
		}

		k = original_len;
		actual_len = 0;
		while (actual_len < original_len) {
			rc = funcs->C_EncryptUpdate(session,
					&actual[actual_len],
					AES_BLOCK_SIZE,
					&actual[actual_len],
					&k);

			if (rc != CKR_OK) {
				testcase_error("C_EncryptUpdate rc=%s",
					p11_get_ckr(rc));
				goto error;
			}

			actual_len += k;
			k = original_len - k;
		}

		/** according to pkcs11 spec,
			nothing should be returned in final. **/
		rc = funcs->C_EncryptFinal(session, &actual[actual_len], &k);
		if (rc != CKR_OK) {
			testcase_error("C_EncryptFinal rc=%s", p11_get_ckr(rc));
			goto error;
		}

		/** compare encryption results with expected results. **/
		testcase_new_assertion();

		if (actual_len != expected_len) {
			testcase_fail("encrypted multipart data length does "
				"not match test vector's encrypted data length."				"\n\nexpected length=%ld, but found length=%ld"
				"\n", expected_len, actual_len);
		}

		else if (memcmp(actual, expected, expected_len)) {
			testcase_fail("encrypted multipart data does not match"
				" test vector's encrypted data.\n");
		}

		else {
			testcase_pass("%s Multipart Encryption with test "
				"vector %d passed.", tsuite->name, i);
		}

	}
	/** clean up **/
	rc = funcs->C_DestroyObject(session, h_key);
	if (rc != CKR_OK) {
		testcase_error("C_DestroyObject rc=%s",	p11_get_ckr(rc));
		goto testcase_cleanup;
	}
	goto testcase_cleanup;

error:
	rc = funcs->C_DestroyObject(session, h_key);
	if (rc != CKR_OK)
		testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));

testcase_cleanup:
	testcase_user_logout();
	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK){
		testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
	}
	return rc;
}

CK_RV do_DecryptAES(struct published_test_suite_info *tsuite)
{
	int			i;
	CK_BYTE			actual[BIG_REQUEST];    // decryption buffer
	CK_BYTE			expected[BIG_REQUEST];  // decrypted data
	CK_ULONG		actual_len, expected_len;
	CK_ULONG		user_pin_len;
	CK_BYTE			user_pin[PKCS11_MAX_PIN_LEN];
	CK_SESSION_HANDLE	session;
	CK_MECHANISM		mech;
	CK_OBJECT_HANDLE	h_key;
	CK_RV			rc;
	CK_FLAGS		flags;
	CK_SLOT_ID	      	slot_id = SLOT_ID;

	testsuite_begin("%s Decryption.", tsuite->name);
	testcase_rw_session();
	testcase_user_login();

	rc = CKR_OK;

	/** skip test if the slot doesn't support this mechanism **/
	if (! mech_supported(slot_id, tsuite->mech.mechanism)){
		testsuite_skip(tsuite->tvcount,
			"Slot %u doesn't support %u",
			(unsigned int) slot_id,
			(unsigned int)tsuite->mech.mechanism);
		goto testcase_cleanup;
	}

	for (i = 0; i < tsuite->tvcount; i++) {

		testcase_begin("%s Decryption with published test vector %d.",
			tsuite->name, i);

		rc = CKR_OK;

		/** create key handle **/
		rc = create_AESKey(session,
			tsuite->tv[i].key,
			tsuite->tv[i].klen,
			&h_key);

		if (rc != CKR_OK) {
			testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
			goto error;
		}

		/** get mech **/
		mech = tsuite->mech;

		/** clear buffers **/
		memset(expected, 0, sizeof(expected));
		memset(actual, 0, sizeof(actual));

		/** get plaintext (expected results) **/
		expected_len = tsuite->tv[i].plen;
		memcpy(expected, tsuite->tv[i].plaintext, expected_len);

		/** get ciphertext **/
		actual_len = tsuite->tv[i].clen;
		memcpy(actual, tsuite->tv[i].ciphertext, actual_len);

		/** single (in-place) decryption **/
		rc = funcs->C_DecryptInit(session, &mech, h_key);
		if (rc != CKR_OK) {
			testcase_error("C_DecryptInit rc=%s", p11_get_ckr(rc));
			goto error;
		}

		rc = funcs->C_Decrypt(session,
				actual,
				actual_len,
				actual,
				&actual_len);

		if (rc != CKR_OK) {
			testcase_error("C_Decrypt rc=%s", p11_get_ckr(rc));
			goto error;
		}

		/** compare actual results with expected results. **/
		testcase_new_assertion();

		if (actual_len != expected_len) {
			testcase_fail("decrypted data length does not match "
				"test vector's decrypted data length.\n\n"
				"expected length=%ld, but found length=%ld\n",
				expected_len, actual_len);
		}

		else if (memcmp(actual, expected, expected_len)) {
			testcase_fail("decrypted data does not match test "
				"vector's decrypted data");
		}

		else {
			testcase_pass("%s Decryption with test vector %d "
				"passed.", tsuite->name, i);
		}

	}
	/** clean up **/
	rc = funcs->C_DestroyObject(session, h_key);
	if (rc != CKR_OK) {
		testcase_error("C_DestroyObject rc=%s",	p11_get_ckr(rc));
	}
	goto testcase_cleanup;

error:
	rc = funcs->C_DestroyObject(session, h_key);
	if (rc != CKR_OK)
		testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));

testcase_cleanup:
	testcase_user_logout();
	rc = funcs->C_CloseAllSessions(slot_id);
        if (rc != CKR_OK) {
                testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
        }
        return rc;
}

CK_RV do_DecryptUpdateAES(struct published_test_suite_info *tsuite)
{
	int			i;
	CK_BYTE			actual[BIG_REQUEST];    // decryption buffer
	CK_BYTE			expected[BIG_REQUEST];  // decrypted data
	CK_ULONG		actual_len, expected_len, original_len, k;
	CK_ULONG		user_pin_len;
	CK_BYTE			user_pin[PKCS11_MAX_PIN_LEN];
	CK_SESSION_HANDLE	session;
	CK_MECHANISM		mech;
	CK_OBJECT_HANDLE	h_key;
	CK_RV			rc;
	CK_FLAGS		flags;
	CK_SLOT_ID	      slot_id = SLOT_ID;

	testsuite_begin("%s Multipart Decryption.", tsuite->name);
	testcase_rw_session();
	testcase_user_login();

	/** skip tests if the slot doesn't support this mechanism **/
	if (! mech_supported(slot_id, tsuite->mech.mechanism)){
		testsuite_skip(tsuite->tvcount,
			"Slot %u doesn't support %u",
			(unsigned int) slot_id,
			(unsigned int)tsuite->mech.mechanism);
		goto testcase_cleanup;
	}

	for (i = 0; i < tsuite->tvcount; i++) {

		testcase_begin("%s Multipart Decryption with published test "
			"vector %d.", tsuite->name, i);

		/** create key handle **/
		rc = create_AESKey(session,
			tsuite->tv[i].key,
			tsuite->tv[i].klen,
			&h_key);

		if (rc != CKR_OK) {
			testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
			goto error;
		}

		/** get mech **/
		mech = tsuite->mech;

		/** clear buffers **/
		memset(expected, 0, sizeof(expected));
		memset(actual, 0, sizeof(actual));

		/** get plaintext (expected results) **/
		expected_len = tsuite->tv[i].plen;
		memcpy(expected, tsuite->tv[i].plaintext, expected_len);

		/** get plaintext **/
		original_len = tsuite->tv[i].clen;
		actual_len = original_len;
		memcpy(actual, tsuite->tv[i].ciphertext, actual_len);

		/** multipart (in-place) decryption **/
		rc = funcs->C_DecryptInit(session, &mech, h_key);
		if (rc != CKR_OK) {
			testcase_error("C_DecryptInit rc=%s", p11_get_ckr(rc));
			goto error;
		}

		k = original_len;
		actual_len = 0;
		while (actual_len < original_len) {
			rc = funcs->C_DecryptUpdate(session,
						&actual[actual_len],
						AES_BLOCK_SIZE,
						&actual[actual_len],
						&k);

			if (rc != CKR_OK) {
				testcase_error("C_DecryptUpdate rc=%s",
					p11_get_ckr(rc));
				goto error;
			}

			actual_len += k;
			k = original_len - k;
		}

		/** according to pkcs11 spec,
			nothing should be returned in final. **/
		rc = funcs->C_DecryptFinal(session, &actual[actual_len], &k);
		if (rc != CKR_OK) {
			testcase_error("C_EncryptFinal rc=%s", p11_get_ckr(rc));
				goto error;
		}

		/** compare decryption results with expected results. **/
		testcase_new_assertion();

		if (actual_len != expected_len) {
			testcase_fail("decrypted multipart data length does "
				"not match test vector's decrypted data "
				"length.\n\nexpected length=%ld, but found "
				"length=%ld\n", expected_len, actual_len);
		}

		else if (memcmp(actual, expected, expected_len)) {
			testcase_fail("decrypted multipart data does not match"
				" test vector's decrypted data.\n");
		}

		else {
			testcase_pass("%s Multipart Decryption with test "
				"vector %d passed.", tsuite->name, i);
		}
	}
	/** clean up **/
	rc = funcs->C_DestroyObject(session, h_key);
	if (rc != CKR_OK) {
		testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}
	goto testcase_cleanup;

error:
	rc = funcs->C_DestroyObject(session, h_key);
	if (rc != CKR_OK)
		testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));

testcase_cleanup:
	testcase_user_logout();
        rc = funcs->C_CloseAllSessions(slot_id);
        if (rc != CKR_OK) {
                testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
        }
        return rc;
}

CK_RV do_WrapUnwrapAES(struct generated_test_suite_info *tsuite)
{
	int			i,j;
	CK_BYTE			original[BIG_REQUEST + AES_BLOCK_SIZE];
	CK_BYTE			crypt[BIG_REQUEST + AES_BLOCK_SIZE];
	CK_BYTE			decrypt[BIG_REQUEST + AES_BLOCK_SIZE];
	CK_BYTE			wrapped_data[3 * AES_BLOCK_SIZE];
	CK_BYTE			user_pin[PKCS11_MAX_PIN_LEN];
	CK_SESSION_HANDLE	session;
	CK_MECHANISM		mechkey, mech;
	CK_OBJECT_HANDLE	h_key;
	CK_OBJECT_HANDLE	w_key;
	CK_OBJECT_HANDLE	uw_key;
	CK_ULONG		wrapped_data_len;
	CK_ULONG		user_pin_len;
	CK_ULONG		orig_len, crypt_len, decrypt_len;
	CK_ULONG		tmpl_count = 3;
	CK_ULONG		key_size;
	CK_FLAGS		flags;
	CK_RV			rc;
	CK_SLOT_ID	      	slot_id = SLOT_ID;
	CK_OBJECT_CLASS		key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE		key_type  = CKK_AES;
	CK_ATTRIBUTE		template[] = {
				{CKA_CLASS, &key_class, sizeof(key_class)},
				{CKA_KEY_TYPE, &key_type, sizeof(key_type)},
				{CKA_VALUE_LEN, &key_size, sizeof(key_size)}};

	testsuite_begin("%s Wrap/Unwrap.", tsuite->name);
	testcase_rw_session();
	testcase_user_login();

	/** skip test if the slot doesn't support this mechanism **/
	if (! mech_supported(slot_id, tsuite->mech.mechanism)){
		testsuite_skip(3,
			"Slot %u doesn't support %u",
			(unsigned int) slot_id,
			(unsigned int)tsuite->mech.mechanism);
		goto testcase_cleanup;
	}

	for (i = 0; i < 3; i++) {

		testcase_begin("%s Wrap/Unwrap key test with keylength=%ld.",
			tsuite->name, key_lens[i]);

		/** set mechanisms **/
		mech = tsuite->mech;
		mechkey = aes_keygen;

		/** set key_size **/
		key_size = key_lens[i];
	
		/** clear buffers **/
		memset(original, 0, sizeof(original));
		memset(crypt, 0, sizeof(crypt));
		memset(decrypt, 0, sizeof(decrypt));
		memset(wrapped_data, 0, sizeof(wrapped_data));

		/** generate crypto key **/
		rc = generate_AESKey(session, key_lens[i], &mechkey, &h_key);
		if (rc != CKR_OK) {
			testcase_error("C_GenerateKey rc=%s", p11_get_ckr(rc));
			goto error;
		}

		/** generate wrapping key **/
		rc = generate_AESKey(session, key_lens[i], &mechkey, &w_key);
		if (rc != CKR_OK) {
			testcase_error("C_GenerateKey rc=%s", p11_get_ckr(rc));
			goto error;
		}

		/** generate data **/
		orig_len = BIG_REQUEST;
		crypt_len = BIG_REQUEST + AES_BLOCK_SIZE;
		decrypt_len = BIG_REQUEST + AES_BLOCK_SIZE;
		for (j = 0; j < orig_len; j++) {
			original[j] = j % 255;
		}

		/** initiate the encrypt **/
		rc = funcs->C_EncryptInit(session, &mech, h_key);
		if (rc != CKR_OK) {
			testcase_error("C_EncryptInit rc=%s", p11_get_ckr(rc));
			goto error;
		}

		/** continue with encrypt **/
		rc = funcs->C_Encrypt(session,
				original,
				orig_len,
				crypt,
				&crypt_len);

		if (rc != CKR_OK) {
			testcase_error("C_Encrypt rc=%s", p11_get_ckr(rc));
			goto error;
		}

		/** wrap key **/
		wrapped_data_len = 3 * AES_KEY_LEN;

		rc = funcs->C_WrapKey(session,
				&mech,
				w_key,
				h_key,
				(CK_BYTE *) &wrapped_data,
				&wrapped_data_len);

		if (rc != CKR_OK) {
			testcase_error("C_WrapKey rc=%s", p11_get_ckr(rc));
			goto error;
		}

		/** unwrap key **/
		rc = funcs->C_UnwrapKey(session,
				&mech,
				w_key,
				wrapped_data,
				wrapped_data_len,
				template,
				tmpl_count,
				&uw_key);

		if (rc != CKR_OK) {
			testcase_error("C_UnwrapKey rc=%s", p11_get_ckr(rc));
			goto error;
		}

		/** initiate decryption (with unwrapped key) **/
		rc = funcs->C_DecryptInit(session, &mech, uw_key);
		if (rc != CKR_OK) {
			testcase_error("C_DecryptInit rc=%s", p11_get_ckr(rc));
			goto error;
		}

		/** do decryption (with the unwrapped key) **/
		rc = funcs->C_Decrypt(session,
				crypt,
				crypt_len,
				decrypt,
				&decrypt_len);

		if(rc != CKR_OK) {
			testcase_error("C_Decrypt rc=%s", p11_get_ckr(rc));
			goto error;
		}

		/** compare actual results with expected results **/
		testcase_new_assertion();

		if (decrypt_len != orig_len) {
			testcase_fail("Decrypted length doesn't match the "
				"original plaintext length.");
			rc = CKR_GENERAL_ERROR;
		}

		else if (memcmp(decrypt, original, orig_len)) {
			testcase_fail("Decrypted data does not match original "
				"plaintext data.");
			rc = CKR_GENERAL_ERROR;
		}

		else {
			testcase_pass("%s Wrap/UnWrap test with key length "
				"%u passed.", tsuite->name,
				(unsigned int)key_lens[i]);
		}
		/** clean up **/
		rc = funcs->C_DestroyObject(session, h_key);
		if (rc != CKR_OK) {
			testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));
		}

		rc = funcs->C_DestroyObject(session, w_key);
		if (rc != CKR_OK) {
			testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));
		}
	
		rc = funcs->C_DestroyObject(session, uw_key);
		if (rc != CKR_OK) {
			testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));
		}
	}
	goto testcase_cleanup;
error:
	rc = funcs->C_DestroyObject(session, h_key);
	if (rc != CKR_OK) {
		testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));
	}

	rc = funcs->C_DestroyObject(session, w_key);
	if (rc != CKR_OK) {
		testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));
	}

	rc = funcs->C_DestroyObject(session, uw_key);
	if (rc != CKR_OK) {
		testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));
	}
	goto testcase_cleanup;

testcase_cleanup:
	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
	}
	return rc;
}

CK_RV do_WrapUnwrapRSA(struct generated_test_suite_info *tsuite)
{

	int			i;
	CK_BYTE			original[BIG_REQUEST];
	CK_BYTE			decipher[BIG_REQUEST + AES_BLOCK_SIZE];
	CK_BYTE			cipher[BIG_REQUEST + AES_BLOCK_SIZE];
	CK_BYTE			wrapped_data[BIG_REQUEST + AES_BLOCK_SIZE];
	CK_BYTE			user_pin[PKCS11_MAX_PIN_LEN];
	CK_BYTE			pub_exp[] = { 0x3 };
	CK_MECHANISM		mech, mech2;
	CK_MECHANISM_INFO	mech_info;
	CK_OBJECT_HANDLE	publ_key, priv_key, w_key, uw_key;
	CK_ULONG		orig_len, cipher_len, decipher_len;
	CK_ULONG		bits = 1024;
	CK_ULONG		wrapped_data_len;
	CK_ULONG		user_pin_len;
	CK_ULONG		key_size;
	CK_RV			rc;
	CK_FLAGS		flags;
	CK_SESSION_HANDLE	session;
	CK_OBJECT_CLASS		keyclass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE		keytype  = CKK_RSA;
	CK_SLOT_ID	      	slot_id = SLOT_ID;

	CK_ATTRIBUTE		pub_tmpl[] = {
				{CKA_MODULUS_BITS,  &bits, sizeof(bits)},
				{CKA_PUBLIC_EXPONENT,&pub_exp,sizeof(pub_exp)}};
	CK_ATTRIBUTE 		uw_tmpl[] = {
				{CKA_CLASS,    &keyclass,  sizeof(keyclass)},
				{CKA_KEY_TYPE, &keytype,   sizeof(keytype)}};
	CK_ATTRIBUTE		 key_gen_tmpl[] = {
				{CKA_VALUE_LEN, &key_size, sizeof(CK_ULONG)}};

	testsuite_begin("%s wrap/unwrap of RSA key.", tsuite->name);
	testcase_rw_session();
	testcase_user_login();

	/** skip test if the slot doesn't support this mechanism **/
	if (! mech_supported(slot_id, tsuite->mech.mechanism)){
		testsuite_skip(3,
			"Slot %u doesn't support %u",
			(unsigned int) slot_id,
			(unsigned int)tsuite->mech.mechanism);
		goto testcase_cleanup;
	}

	for(i = 0; i < 3; i++){

		testcase_begin("%s wrap/unwrap of RSA key for key length=%ld.",
			tsuite->name, key_lens[i]);

		key_size = key_lens[i];

		/** first mechanism generate AES wrapping key **/
		mech.mechanism = CKM_AES_KEY_GEN;
		mech.ulParameterLen = 0;
		mech.pParameter = NULL;

		/** mechanism to generate an RSA key pair to be wrapped **/
		mech2.mechanism  = CKM_RSA_PKCS_KEY_PAIR_GEN;
		mech2.ulParameterLen = 0;
		mech2.pParameter = NULL;

		/** generate an RSA key pair. **/
		rc = funcs->C_GenerateKeyPair(session,
					&mech2,
					pub_tmpl,
					2,
					NULL,
					0,
					&publ_key,
					&priv_key);

		if (rc != CKR_OK) {
			testcase_error("C_GenerateKeyPair rc=%s",
				p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		/** generate the wrapping key **/
		rc = funcs->C_GenerateKey(session,
					&mech,
					key_gen_tmpl,
					1,
					&w_key);

		if (rc != CKR_OK) {
			testcase_error("C_GenerateKey rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		/** set the mech for AES crypto **/
		mech = tsuite->mech;

		/** wrap the key **/
		wrapped_data_len = sizeof(wrapped_data);

		/** get mech info **/
		rc = funcs->C_GetMechanismInfo(slot_id,
					mech.mechanism,
					&mech_info);

		if (rc != CKR_OK){
			testcase_error("C_GetMechanismInfo rc=%s",
				p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		/** key is wrappable **/
		if (mech_info.flags & CKF_WRAP) {

			/** wrap key **/
			rc = funcs->C_WrapKey(session,
					&mech,
					w_key,
					priv_key,
					wrapped_data,
					&wrapped_data_len);

			if (rc != CKR_OK){
				testcase_error("C_WrapKey rc=%s",
					p11_get_ckr(rc));
				goto testcase_cleanup;
			}

			/** unwrap key **/
			rc = funcs->C_UnwrapKey(session,
					&mech,
					w_key,
					wrapped_data,
					wrapped_data_len,
					uw_tmpl,
					2,
					&uw_key);

			if (rc != CKR_OK) {
				testcase_error("C_UnWrapKey rc=%s",
					p11_get_ckr(rc));
				goto testcase_cleanup;
			}

			/** generate data **/
			orig_len = 30;
			for (i = 0; i < orig_len; i++)
				original[i] = i % 255;

			/** set mech2 for RSA crypto **/
			mech2.mechanism  = CKM_RSA_PKCS;
			mech2.ulParameterLen = 0;
			mech2.pParameter = NULL;

			/** initialize RSA encryption (with public key) **/
			rc = funcs->C_EncryptInit(session, &mech2, publ_key);
			if (rc != CKR_OK) {
				testcase_error("C_EncryptInit rc=%s",
					p11_get_ckr(rc));
				goto testcase_cleanup;
			}

			cipher_len = sizeof(cipher); // set cipher buffer size

			/** do RSA encryption (with public key) **/
			rc = funcs->C_Encrypt(session,
					original,
					orig_len,
					cipher,
					&cipher_len);

			if (rc != CKR_OK) {
				testcase_error("C_Encrypt rc=%s",
					p11_get_ckr(rc));
				goto testcase_cleanup;
			}

			/** initialize RSA decryption
				(with unwrapped private key) **/
			rc = funcs->C_DecryptInit(session, &mech2, uw_key);
			if (rc != CKR_OK) {
				testcase_error("C_DecryptInit rc=%s",
					p11_get_ckr(rc));
				goto testcase_cleanup;
			}

			decipher_len = sizeof(decipher);

			/** do RSA decryption (with unwrapped private key) **/
			rc = funcs->C_Decrypt(session,
					cipher,
					cipher_len,
					decipher,
					&decipher_len);

			if (rc != CKR_OK) {
				testcase_error("C_Decrypt rc=%s",
					p11_get_ckr(rc));
				goto testcase_cleanup;
			}

			/** compare actual results with expected results **/
			testcase_new_assertion();
			if (orig_len != decipher_len) {
				testcase_fail("lengths don't match: "
					"%ld vs %ld\n", orig_len, decipher_len);
				rc = CKR_GENERAL_ERROR;
			}

			else if (memcmp(original, decipher, orig_len)) {
				testcase_fail("deciphered data does not match"
					" original data");
				rc = CKR_GENERAL_ERROR;
			}

			else{
				testcase_pass("%s passed wrap/unwrap RSA key "
					"test.", tsuite->name);
			}


		}

		/** key is not wrappable **/
		else {
			testcase_new_assertion();

			/** try to wrap key **/
			rc = funcs->C_WrapKey(session,
					&mech,
					w_key,
					priv_key,
					wrapped_data,
					&wrapped_data_len);

			if (rc != CKR_KEY_NOT_WRAPPABLE){
				testcase_fail("Expected CKR_KEY_NOT_WRAPPABLE");
			}

			else{
				testcase_pass("%s passed wrap/unwrap RSA key "
					"test.", tsuite->name);
			}
		}


	}
	goto testcase_cleanup;

testcase_cleanup:
	testcase_close_session();
	return rc;
}

CK_RV aes_funcs() {
	int i, generate_key;
	CK_RV rv  = CKR_OK;

	generate_key = get_key_type(); // true if mech requires secure key
				       // generate keys and skip published tests
	if (generate_key == -1) {
		return -1;
	}

	for (i = 0; i < NUM_OF_PUBLISHED_TESTSUITES; i++) {
		if (!generate_key) {
			rv = do_EncryptAES(&published_test_suites[i]);
			if (rv != CKR_OK && (!no_stop))
				break;

			rv = do_DecryptAES(&published_test_suites[i]);
			if (rv != CKR_OK && (!no_stop))
				break;

			rv = do_EncryptUpdateAES(&published_test_suites[i]);
			if (rv != CKR_OK && (!no_stop))
				break;

			rv = do_DecryptUpdateAES(&published_test_suites[i]);
			if (rv != CKR_OK && (!no_stop))
				break;
		}

	}

	for (i = 0; i < NUM_OF_GENERATED_TESTSUITES; i++) {
		do_EncryptDecryptAES(&generated_test_suites[i]);
		if (rv != CKR_OK && (!no_stop))
			break;

		do_EncryptDecryptUpdateAES(&generated_test_suites[i]);
		if (rv != CKR_OK && (!no_stop))
			break;

		do_WrapUnwrapAES(&generated_test_suites[i]);
		if (rv != CKR_OK && (!no_stop))
			break;

		do_WrapUnwrapRSA(&generated_test_suites[i]);
		if (rv != CKR_OK && (!no_stop))
			break;

	}

	return rv;
}

int main  (int argc, char **argv) {
	int rc;
	CK_C_INITIALIZE_ARGS cinit_args;
	CK_RV rv = 0;

	rc = do_ParseArgs(argc, argv);
	if (rc != 1)
		return rc;

	printf("Using slot #%lu...\n\n", SLOT_ID );
	printf("With option: nostop: %d\n", no_stop);

	rc = do_GetFunctionList();
	if (!rc) {
		testcase_error("do_getFunctionList(), rc=%s", p11_get_ckr(rc));
		return rc;
	}

	memset( &cinit_args, 0x0, sizeof(cinit_args) );
	cinit_args.flags = CKF_OS_LOCKING_OK;

	// SAB Add calls to ALL functions before the C_Initialize gets hit

	funcs->C_Initialize( &cinit_args );

	{
		CK_SESSION_HANDLE  hsess = 0;

		rc = funcs->C_GetFunctionStatus(hsess);
		if (rc  != CKR_FUNCTION_NOT_PARALLEL)
			return rc;

		rc = funcs->C_CancelFunction(hsess);
		if (rc  != CKR_FUNCTION_NOT_PARALLEL)
			return rc;
	}

	testcase_setup(0); //TODO
	rc = aes_funcs();
	testcase_print_result();

	/* make sure we return non-zero if rv is non-zero */
	return ((rv == 0) || (rv % 256) ? rv : -1);
}
