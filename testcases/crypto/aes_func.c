#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"
#include "aes.h"
#include "common.c"
#include "mech_to_str.h"

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
	CK_RV			rc = CKR_OK;
	CK_SLOT_ID	       slot_id = SLOT_ID;

	testsuite_begin("%s Encryption/Decryption.",tsuite->name);
	testcase_rw_session();
	testcase_user_login();

	/** skip tests if the slot doesn't support this mechanism **/
	if (! mech_supported(slot_id, tsuite->mech.mechanism)){
		testsuite_skip(3,
			"Slot %u doesn't support %s (%u)",
			(unsigned int) slot_id,
			mech_to_str(tsuite->mech.mechanism),
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
			goto error;
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
			goto error;
		}

		/** compare actual results with expected results **/
		testcase_new_assertion();

		if (decrypt_len != orig_len) {
		       testcase_fail("decrypted data length does not "
				"match original data length.\nexpected "
				"length=%ld, but found length=%ld\n",
				orig_len, decrypt_len);
		}

		else if (memcmp(decrypt, original, orig_len)){
			testcase_fail("decrypted data does not match "
				"original data");
		}

		else {
			testcase_pass("%s Encryption/Decryption with "
				      "key length %ld passed.", tsuite->name,
				      key_lens[i]);
		}

		/** clean up **/
		rc = funcs->C_DestroyObject(session, h_key);
		if (rc != CKR_OK) {
			testcase_error("C_DestroyObject rc=%s",
					p11_get_ckr(rc));
			goto testcase_cleanup;
		}
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
	CK_RV			rc = CKR_OK;

	/** begin testsuite **/
	testsuite_begin("%s Multipart Encryption/Decryption.", tsuite->name);
	testcase_rw_session();
	testcase_user_login();

	/** skip test if the slot doesn't support this mechanism **/
	if (! mech_supported(slot_id, tsuite->mech.mechanism)){
		testcase_skip("Slot %u doesn't support %s (%u)",
			(unsigned int) slot_id,
			mech_to_str(tsuite->mech.mechanism),
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

		/* Encrypt in place except for CBC_PAD, since it
		 * pads and pkcs padding can make it unclear about what is
		 * output at what stage. (See pkcs11v2.20 Section 11.2)
		 */
		if (mech.mechanism != CKM_AES_CBC_PAD) {

			memcpy(crypt, original, orig_len);
			crypt_len = orig_len;
			k = 0;
			while(k < orig_len) {
				rc = funcs->C_EncryptUpdate(session,
							    &crypt[k],
							    AES_BLOCK_SIZE,
							    &crypt[k],
							    &crypt_len);
				if (rc != CKR_OK) {
					testcase_error("C_EncryptUpdate rc=%s",
							p11_get_ckr(rc));
					goto error;
				}

				k += crypt_len;		// encrypted amount
				crypt_len = orig_len - k; // space in out buf

			}
		} else {

			j = k = 0;      // j indexes source buffer
					// k indexes destination buffer
			crypt_len = sizeof(crypt);

			while (j < orig_len) {
				tmp = crypt_len - k;  // room left
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
		}

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

		/* decrypt in place.  skip for AES_CBC_PAD since it
		 * pads and pkcs padding can make it unclear about what is
		 * output at what stage. (See pkcs11v2.20 Section 11.2)
		 */
		if (mech.mechanism != CKM_AES_CBC_PAD) {

			memcpy (decrypt, crypt, crypt_len);
			k = 0;
			decrypt_len = crypt_len;
			while(k < crypt_len) {
				rc = funcs->C_DecryptUpdate(session,
							    &decrypt[k],
							    AES_BLOCK_SIZE,
							    &decrypt[k],
							    &decrypt_len);
				if (rc != CKR_OK) {
					testcase_error("C_DecryptUpdate rc=%s",
							p11_get_ckr(rc));
					goto error;
				}

				k += decrypt_len;	// decrypted amount
				decrypt_len = crypt_len - k; // space in out buf
			}
		} else {

			j = k = 0;      // j indexes source buffer,
					// k indexes destination buffer
			decrypt_len = sizeof(decrypt);
			while (j < crypt_len) {
				tmp = decrypt_len - k;	// room left in outbuf
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
		}

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

		rc = funcs->C_DestroyObject(session, h_key);
		if (rc != CKR_OK) {
			testcase_error("C_DestroyObject rc=%s",
					p11_get_ckr(rc));
			goto testcase_cleanup;
		}
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
	CK_RV			rc = CKR_OK;
	CK_FLAGS		flags;
	CK_SLOT_ID		slot_id = SLOT_ID;

	/** begin testsuite **/
	testsuite_begin("%s Encryption.", tsuite->name);
	testcase_rw_session();
	testcase_user_login();

	/** skip test if the slot doesn't support this mechanism **/
	if (! mech_supported(slot_id, tsuite->mech.mechanism)){
		testsuite_skip(tsuite->tvcount,
			"Slot %u doesn't support %s (%u)",
			(unsigned int) slot_id,
			mech_to_str(tsuite->mech.mechanism),
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

		rc = funcs->C_DestroyObject(session, h_key);
		if (rc != CKR_OK) {
			testcase_error("C_DestroyObject rc=%s",
					p11_get_ckr(rc));
			goto testcase_cleanup;
		}
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
	CK_BYTE			plaintext[BIG_REQUEST];
	CK_BYTE			expected[BIG_REQUEST];  // encrypted data
	CK_BYTE			crypt[BIG_REQUEST];
	CK_ULONG		expected_len, p_len, crypt_len, k;
	CK_ULONG		user_pin_len;
	CK_BYTE			user_pin[PKCS11_MAX_PIN_LEN];
	CK_SESSION_HANDLE	session;
	CK_MECHANISM		mech;
	CK_OBJECT_HANDLE	h_key;
	CK_RV			rc = CKR_OK;
	CK_FLAGS		flags;
	CK_SLOT_ID	      slot_id = SLOT_ID;

	testsuite_begin("%s Multipart Encryption.", tsuite->name);
	testcase_rw_session();
	testcase_user_login();

	/** skip test if the slot doesn't support this mechanism **/
	if (! mech_supported(slot_id, tsuite->mech.mechanism)){
		testsuite_skip(tsuite->tvcount,
			"Slot %u doesn't support %s (%u)",
			(unsigned int) slot_id,
			mech_to_str(tsuite->mech.mechanism),
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
		memset(plaintext, 0, sizeof(plaintext));
		memset(crypt, 0, sizeof(crypt));

		/** get ciphertext (expected results) **/
		expected_len = tsuite->tv[i].clen;
		memcpy(expected, tsuite->tv[i].ciphertext, expected_len);

		/** get plaintext **/
		p_len = tsuite->tv[i].plen;
		memcpy(plaintext, tsuite->tv[i].plaintext, p_len);

		/** multipart encryption **/
		rc = funcs->C_EncryptInit(session, &mech, h_key);
		if (rc != CKR_OK) {
			testcase_error("C_EncryptInit rc=%s", p11_get_ckr(rc));
			goto error;
		}

		/* for chunks, -1 is NULL, and 0 is empty string,
		 * and a value > 0 is amount of data from test vector's
		 * plaintext data. This way we test vary-sized chunks.
		 */
		if (tsuite->tv[i].num_chunks) {
			int j;
			CK_ULONG outlen, len;
			CK_BYTE *data_chunk = NULL;

			k = 0;
			crypt_len = 0;
			outlen = sizeof(crypt);

			for (j = 0; j < tsuite->tv[i].num_chunks; j++) {
				if (tsuite->tv[i].chunks[j] == -1) {
					len = 0;
					data_chunk = NULL;
				} else if (tsuite->tv[i].chunks[j] == 0) {
					len = 0;
					data_chunk = (CK_BYTE *)"";
				} else {
					len = tsuite->tv[i].chunks[j];
					data_chunk = plaintext + k;
				}

				rc = funcs->C_EncryptUpdate(session, data_chunk,
							   len,
							   &crypt[crypt_len],
							   &outlen);
				if (rc != CKR_OK) {
					testcase_error("C_EncryptUpdate rc=%s",
							p11_get_ckr(rc));
					goto error;
				}
				k += len;
				crypt_len += outlen;
				outlen = sizeof(crypt) - crypt_len;
			}
		} else {
			crypt_len = sizeof(crypt);
			rc = funcs->C_EncryptUpdate(session, plaintext, p_len,
						    crypt, &crypt_len);
			if (rc != CKR_OK) {
				testcase_error("C_EncryptUpdate rc=%s",
						p11_get_ckr(rc));
				goto error;
			}
		}

		k = sizeof(crypt) - crypt_len;
		rc = funcs->C_EncryptFinal(session, &crypt[crypt_len], &k);
		if (rc != CKR_OK) {
			testcase_error("C_EncryptFinal rc=%s", p11_get_ckr(rc));
			goto error;
		}

		/** compare encryption results with expected results. **/
		testcase_new_assertion();

		if (crypt_len != expected_len) {
			testcase_fail("encrypted multipart data length does "
				"not match test vector's encrypted data length."
				"\n\nexpected length=%ld, but found length=%ld"
				"\n", expected_len, crypt_len);
		}

		else if (memcmp(crypt, expected, expected_len)) {
			testcase_fail("encrypted multipart data does not match"
				" test vector's encrypted data.\n");
		}

		else {
			testcase_pass("%s Multipart Encryption with test "
				"vector %d passed.", tsuite->name, i);
		}

		rc = funcs->C_DestroyObject(session, h_key);
		if (rc != CKR_OK) {
			testcase_error("C_DestroyObject rc=%s",
					p11_get_ckr(rc));
			goto testcase_cleanup;
		}
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
	CK_RV			rc = CKR_OK;
	CK_FLAGS		flags;
	CK_SLOT_ID	      	slot_id = SLOT_ID;

	testsuite_begin("%s Decryption.", tsuite->name);
	testcase_rw_session();
	testcase_user_login();

	/** skip test if the slot doesn't support this mechanism **/
	if (! mech_supported(slot_id, tsuite->mech.mechanism)){
		testsuite_skip(tsuite->tvcount,
			"Slot %u doesn't support %s (%u)",
			(unsigned int) slot_id,
			mech_to_str(tsuite->mech.mechanism),
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

		/** clean up **/
		rc = funcs->C_DestroyObject(session, h_key);
		if (rc != CKR_OK) {
			testcase_error("C_DestroyObject rc=%s",
					p11_get_ckr(rc));
			goto testcase_cleanup;
		}
	}
	goto testcase_cleanup;

error:
	rc = funcs->C_DestroyObject(session, h_key);
	if (rc != CKR_OK)
		testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));

testcase_cleanup:
	testcase_user_logout();
	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK)
		testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
	return rc;
}

CK_RV do_DecryptUpdateAES(struct published_test_suite_info *tsuite)
{
	int			i;
	CK_BYTE			cipher[BIG_REQUEST];
	CK_BYTE			expected[BIG_REQUEST];  // decrypted data
	CK_BYTE			plaintext[BIG_REQUEST];
	CK_ULONG		cipher_len, expected_len, p_len, k;
	CK_ULONG		user_pin_len;
	CK_BYTE			user_pin[PKCS11_MAX_PIN_LEN];
	CK_SESSION_HANDLE	session;
	CK_MECHANISM		mech;
	CK_OBJECT_HANDLE	h_key;
	CK_RV			rc = CKR_OK;
	CK_FLAGS		flags;
	CK_SLOT_ID	      slot_id = SLOT_ID;

	testsuite_begin("%s Multipart Decryption.", tsuite->name);
	testcase_rw_session();
	testcase_user_login();

	/** skip tests if the slot doesn't support this mechanism **/
	if (! mech_supported(slot_id, tsuite->mech.mechanism)){
		testsuite_skip(tsuite->tvcount,
			"Slot %u doesn't support %s (%u)",
			(unsigned int) slot_id,
			mech_to_str(tsuite->mech.mechanism),
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
		memset(cipher, 0, sizeof(cipher));
		memset(plaintext, 0, sizeof(plaintext));

		/** get plaintext (expected results) **/
		expected_len = tsuite->tv[i].plen;
		memcpy(expected, tsuite->tv[i].plaintext, expected_len);

		p_len = sizeof(plaintext);
		cipher_len = tsuite->tv[i].clen;
		memcpy(cipher, tsuite->tv[i].ciphertext, cipher_len);

		/** multipart (in-place) decryption **/
		rc = funcs->C_DecryptInit(session, &mech, h_key);
		if (rc != CKR_OK) {
			testcase_error("C_DecryptInit rc=%s", p11_get_ckr(rc));
			goto error;
		}

		/* for chunks, -1 is NULL, and 0 is empty string,
		 * and a value > 0 is amount of data from test vector's
		 * plaintext data. This way we test vary-sized chunks.
		 */
		if (tsuite->tv[i].num_chunks) {
			int j;
			CK_ULONG outlen, len;
			CK_BYTE *data_chunk = NULL;

			k = 0;
			p_len = 0;
			outlen = sizeof(plaintext);
			for (j = 0; j < tsuite->tv[i].num_chunks; j++) {
				if (tsuite->tv[i].chunks[j] == -1) {
					len = 0;
					data_chunk = NULL;
				} else if (tsuite->tv[i].chunks[j] == 0) {
					len = 0;
					data_chunk = (CK_BYTE *)"";
				} else {
					len = tsuite->tv[i].chunks[j];
					data_chunk = cipher + k;
				}

				rc = funcs->C_DecryptUpdate(session, data_chunk,
							    len,
							    &plaintext[p_len],
							    &outlen);
				if (rc != CKR_OK) {
					testcase_error("C_DecryptUpdate rc=%s",
							p11_get_ckr(rc));
					goto error;
				}
				k += len;
				p_len += outlen;
				outlen = sizeof(plaintext) - p_len;
			}
		} else {
			p_len = sizeof(plaintext);
			rc = funcs->C_DecryptUpdate(session, cipher, cipher_len,
						    plaintext, &p_len);
			if (rc != CKR_OK) {
				testcase_error("C_DecryptUpdate rc=%s",
						p11_get_ckr(rc));
				goto error;
			}
		}

		k = sizeof(plaintext) - p_len;
		rc = funcs->C_DecryptFinal(session, &plaintext[p_len], &k);
		if (rc != CKR_OK) {
			testcase_error("C_DecryptFinal rc=%s", p11_get_ckr(rc));
			goto error;
		}

		/** compare decryption results with expected results. **/
		testcase_new_assertion();

		if (p_len != expected_len) {
			testcase_fail("decrypted multipart data length does "
				"not match test vector's decrypted data "
				"length.\n\nexpected length=%ld, but found "
				"length=%ld\n", expected_len, p_len);
		}

		else if (memcmp(plaintext, expected, expected_len)) {
			testcase_fail("decrypted multipart data does not match"
				" test vector's decrypted data.\n");
		}

		else {
			testcase_pass("%s Multipart Decryption with test "
				"vector %d passed.", tsuite->name, i);
		}

		rc = funcs->C_DestroyObject(session, h_key);
		if (rc != CKR_OK) {
			testcase_error("C_DestroyObject rc=%s",
					p11_get_ckr(rc));
			goto testcase_cleanup;
		}
	}
	goto testcase_cleanup;
error:
	rc = funcs->C_DestroyObject(session, h_key);
	if (rc != CKR_OK)
		testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));

testcase_cleanup:
	testcase_user_logout();
	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK)
		testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
	return rc;
}

CK_RV do_WrapUnwrapAES(struct generated_test_suite_info *tsuite)
{
	int			i,j;
	CK_BYTE			original[BIG_REQUEST + AES_BLOCK_SIZE];
	CK_BYTE			crypt[BIG_REQUEST + AES_BLOCK_SIZE];
	CK_BYTE			decrypt[BIG_REQUEST + AES_BLOCK_SIZE];
	CK_BYTE_PTR		wrapped_data = NULL;
	CK_BYTE			user_pin[PKCS11_MAX_PIN_LEN];
	CK_SESSION_HANDLE	session;
	CK_MECHANISM		mechkey, mech;
	CK_OBJECT_HANDLE	h_key;
	CK_OBJECT_HANDLE	w_key;
	CK_OBJECT_HANDLE	uw_key;
	CK_ULONG		wrapped_data_len = 0;
	CK_ULONG		user_pin_len;
	CK_ULONG		orig_len, crypt_len, decrypt_len;
	CK_ULONG		tmpl_count = 3;
	CK_ULONG		key_size;
	CK_FLAGS		flags;
	CK_RV			rc = CKR_OK;
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
			"Slot %u doesn't support %s (%u)",
			(unsigned int) slot_id,
			mech_to_str(tsuite->mech.mechanism),
			(unsigned int)tsuite->mech.mechanism);
		goto testcase_cleanup;
	}

	if (!wrap_supported(slot_id, tsuite->mech)) {
		testsuite_skip(3, "Slot %u doesn't support %s (%u)",
			(unsigned int) slot_id,
			mech_to_str(tsuite->mech.mechanism),
			(unsigned int)tsuite->mech.mechanism);
		goto testcase_cleanup;
	}

	/* key sizes must be a multiple of AES block size in order to be passed
	   in as data. Recall AES expects data in multiple of AES block size.
         */
	for (i = 0; i < 3; i++) {

		if (key_lens[i]%AES_BLOCK_SIZE != 0)
			continue;

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

		rc = funcs->C_WrapKey(session,
				&mech,
				w_key,
				h_key,
				NULL,
				&wrapped_data_len);

		if (rc != CKR_OK) {
			testcase_error("C_WrapKey rc=%s", p11_get_ckr(rc));
			goto error;
		}

		wrapped_data = malloc(wrapped_data_len);
		if (wrapped_data == NULL) {
			testcase_error("malloc failed");
			goto error;
		}
		memset(wrapped_data, 0, wrapped_data_len);
		rc = funcs->C_WrapKey(session, &mech, w_key, h_key, wrapped_data,
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

		if (wrapped_data)
			free(wrapped_data);

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
	if (wrapped_data)
		free(wrapped_data);

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
	CK_BYTE			pub_exp[] = { 0x01, 0x00, 0x01 };
	CK_MECHANISM		mech, mech2;
	CK_MECHANISM_INFO	mech_info;
	CK_OBJECT_HANDLE	publ_key, priv_key, w_key, uw_key;
	CK_ULONG		orig_len, cipher_len, decipher_len;
	CK_ULONG		bits = 1024;
	CK_ULONG		wrapped_data_len;
	CK_ULONG		user_pin_len;
	CK_ULONG		key_size;
	CK_RV			rc = CKR_OK;
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

	/** skip AES_EBC/AES_CBC (only supported for symmetric keys) **/
	if ((tsuite->mech.mechanism == CKM_AES_ECB) ||
	    (tsuite->mech.mechanism == CKM_AES_CBC)) {
		testcase_skip("Mechanism %s (%u) not supported to wrap/unwrap asymmetric Keys",
		mech_to_str(tsuite->mech.mechanism),
		(unsigned int)tsuite->mech.mechanism);
		goto testcase_cleanup;
	}

	/** skip test if the slot doesn't support this mechanism **/
	if (! mech_supported(slot_id, tsuite->mech.mechanism)){
		testsuite_skip(3,
			"Slot %u doesn't support %s (%u)",
			(unsigned int) slot_id,
			mech_to_str(tsuite->mech.mechanism),
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

			if (rc != CKR_MECHANISM_INVALID) {
				testcase_fail("Expected CKR_MECHANISM_INVALID");
			}

			else{
				testcase_pass("%s passed wrap/unwrap RSA key "
					"test.", tsuite->name);
			}
		}
	}

testcase_cleanup:
	testcase_close_session();
	return rc;
}

CK_RV do_WrapRSA_Err(struct generated_test_suite_info *tsuite)
{
	int i;
	CK_BYTE	wrapped_data[BIG_REQUEST + AES_BLOCK_SIZE];
	CK_BYTE	user_pin[PKCS11_MAX_PIN_LEN];
	CK_BYTE	pub_exp[] = { 0x01, 0x00, 0x01 };
	CK_MECHANISM mech, mech2;
	CK_MECHANISM_INFO mech_info;
	CK_OBJECT_HANDLE publ_key, priv_key, w_key;
	CK_ULONG bits = 1024;
	CK_ULONG wrapped_data_len, user_pin_len, key_size;
	CK_RV rc = CKR_OK;
	CK_FLAGS flags;
	CK_SESSION_HANDLE session;
	CK_SLOT_ID slot_id = SLOT_ID;

	CK_ATTRIBUTE pub_tmpl[] = {
				{CKA_MODULUS_BITS,  &bits, sizeof(bits)},
				{CKA_PUBLIC_EXPONENT,&pub_exp,sizeof(pub_exp)}};
	CK_ATTRIBUTE key_gen_tmpl[] = {
				{CKA_VALUE_LEN, &key_size, sizeof(CK_ULONG)}};

	testsuite_begin("%s wrap/unwrap of RSA key.", tsuite->name);
	testcase_rw_session();
	testcase_user_login();

	/** skip test if the slot doesn't support this mechanism **/
	if (! mech_supported(slot_id, tsuite->mech.mechanism)){
		testsuite_skip(3, "Slot %u doesn't support %s (%u)",
			       (unsigned int) slot_id,
			       mech_to_str(tsuite->mech.mechanism),
			       (unsigned int)tsuite->mech.mechanism);
		goto testcase_cleanup;
	}

	for (i = 0; i < 3; i++) {

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
		rc = funcs->C_GenerateKeyPair(session, &mech2, pub_tmpl, 2, NULL,
					      0, &publ_key, &priv_key);
		if (rc != CKR_OK) {
			testcase_error("C_GenerateKeyPair rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		/** generate the wrapping key **/
		rc = funcs->C_GenerateKey(session, &mech, key_gen_tmpl, 1, &w_key);
		if (rc != CKR_OK) {
			testcase_error("C_GenerateKey rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		/** set the mech for AES crypto **/
		mech = tsuite->mech;

		/** wrap the key **/
		wrapped_data_len = sizeof(wrapped_data);

		/** get mech info **/
		rc = funcs->C_GetMechanismInfo(slot_id, mech.mechanism, &mech_info);

		if (rc != CKR_OK){
			testcase_error("C_GetMechanismInfo rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		/** key is wrappable **/
		if (mech_info.flags & CKF_WRAP) {

			testcase_new_assertion();

			/** wrap key **/
			rc = funcs->C_WrapKey(session, &mech, w_key, priv_key,
					      wrapped_data, &wrapped_data_len);

			/* Expect dedicated error code here, since it's not allowed
			 * to unwrap non secret keys with AES_ECB/AES_CBC */
			if (rc != CKR_KEY_NOT_WRAPPABLE) {
				testcase_error("Expected C_WrapKey rc=%s, but returned rc=%s",
						p11_get_ckr(CKR_KEY_NOT_WRAPPABLE),
						p11_get_ckr(rc));
				goto testcase_cleanup;
			} else {
				testcase_pass("%s passed wrap RSA key test.",
					      tsuite->name);
			}
		} else {
			/** key is not wrappable **/
			testcase_new_assertion();

			/** try to wrap key **/
			rc = funcs->C_WrapKey(session, &mech, w_key, priv_key,
					      wrapped_data, &wrapped_data_len);
			if (rc != CKR_MECHANISM_INVALID)
				testcase_fail("Expected CKR_MECHANISM_INVALID");
			else
				testcase_pass("%s passed wrap/unwrap RSA key test.",
					      tsuite->name);
		}
	}

testcase_cleanup:
	testcase_close_session();
	return rc;
}



CK_RV do_UnwrapRSA_Err(struct generated_test_suite_info *tsuite)
{
	int i;
	CK_BYTE wrapped_data[BIG_REQUEST + AES_BLOCK_SIZE];
	CK_BYTE	user_pin[PKCS11_MAX_PIN_LEN];
	CK_BYTE	pub_exp[] = { 0x01, 0x00, 0x01 };
	CK_MECHANISM mech, mech1, mech2;
	CK_MECHANISM_INFO mech_info;
	CK_OBJECT_HANDLE publ_key, priv_key, w_key, uw_key;
	CK_ULONG bits = 1024;
	CK_ULONG wrapped_data_len, user_pin_len, key_size;
	CK_RV rc = CKR_OK;
	CK_FLAGS flags;
	CK_SESSION_HANDLE session;
	CK_OBJECT_CLASS	keyclass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keytype  = CKK_RSA;
	CK_SLOT_ID slot_id = SLOT_ID;

	CK_ATTRIBUTE pub_tmpl[] = {
				{CKA_MODULUS_BITS,  &bits, sizeof(bits)},
				{CKA_PUBLIC_EXPONENT,&pub_exp,sizeof(pub_exp)}};
	CK_ATTRIBUTE uw_tmpl[] = {
				{CKA_CLASS,    &keyclass,  sizeof(keyclass)},
				{CKA_KEY_TYPE, &keytype,   sizeof(keytype)}};
	CK_ATTRIBUTE key_gen_tmpl[] = {
				{CKA_VALUE_LEN, &key_size, sizeof(CK_ULONG)}};

	testsuite_begin("%s wrap/unwrap of RSA key.", tsuite->name);
	testcase_rw_session();
	testcase_user_login();

	/** skip test if the slot doesn't support this mechanism **/
	if (! mech_supported(slot_id, tsuite->mech.mechanism)){
		testsuite_skip(3,
			"Slot %u doesn't support %s (%u)",
			(unsigned int) slot_id,
			mech_to_str(tsuite->mech.mechanism),
			(unsigned int)tsuite->mech.mechanism);
		goto testcase_cleanup;
	}

	for (i = 0; i < 3; i++) {

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
		rc = funcs->C_GenerateKeyPair(session, &mech2, pub_tmpl, 2, NULL,
					      0, &publ_key, &priv_key);
		if (rc != CKR_OK) {
			testcase_error("C_GenerateKeyPair rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		/** generate the wrapping key **/
		rc = funcs->C_GenerateKey(session, &mech, key_gen_tmpl, 1, &w_key);
		if (rc != CKR_OK) {
			testcase_error("C_GenerateKey rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		/** set the mech for AES crypto **/
		mech = tsuite->mech;

		/** wrap the key **/
		wrapped_data_len = sizeof(wrapped_data);

		/** get mech info **/
		rc = funcs->C_GetMechanismInfo(slot_id, mech.mechanism, &mech_info);
		if (rc != CKR_OK){
			testcase_error("C_GetMechanismInfo rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		/** key is wrappable **/
		if (mech_info.flags & CKF_UNWRAP) {

			/** mechanism for wrapping the key **/
			mech1.mechanism = CKM_AES_CBC_PAD;
			mech1.ulParameterLen = AES_IV_SIZE;
			mech1.pParameter = &aes_iv;

			/** wrap key **/
			rc = funcs->C_WrapKey(session, &mech1, w_key, priv_key,
					      wrapped_data, &wrapped_data_len);
			if (rc != CKR_OK) {
				testcase_error("C_WrapKey rc=%s", p11_get_ckr(rc));
				goto testcase_cleanup;
			}

			testcase_new_assertion();

			/** unwrap key **/
			rc = funcs->C_UnwrapKey(session, &mech, w_key, wrapped_data,
						wrapped_data_len, uw_tmpl, 2,
						&uw_key);
			/* Expect dedicated error code here, since it's not allowed
			 * to unwrap non secret keys with AES_ECB/AES_CBC */
			if (rc != CKR_ARGUMENTS_BAD) {
				testcase_error("Expected C_UnWrapKey rc=%s, but returned rc=%s",
				p11_get_ckr(CKR_ARGUMENTS_BAD), p11_get_ckr(rc));
				goto testcase_cleanup;
			}
			testcase_pass("%s passed unwrap RSA key test.",tsuite->name);
		} else {
			/** key is not wrappable **/
			testcase_new_assertion();

			/** try to wrap key **/
			rc = funcs->C_WrapKey(session, &mech, w_key, priv_key,
					      wrapped_data, &wrapped_data_len);
			if (rc != CKR_MECHANISM_INVALID)
				testcase_fail("Expected CKR_MECHANISM_INVALID");
			else {
				testcase_pass("%s passed unwrap RSA key test.",
					      tsuite->name);
			}
		}
	}

testcase_cleanup:
	testcase_close_session();
	return rc;
}

CK_RV aes_funcs() {
	int i, generate_key;
	CK_RV rv = CKR_OK;

	generate_key = securekey; // true if mech requires secure key
				  // generate keys and skip published tests

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
		rv = do_EncryptDecryptAES(&generated_test_suites[i]);
		if (rv != CKR_OK && (!no_stop))
			break;

		rv = do_EncryptDecryptUpdateAES(&generated_test_suites[i]);
		if (rv != CKR_OK && (!no_stop))
			break;

		rv = do_WrapUnwrapAES(&generated_test_suites[i]);
		if (rv != CKR_OK && (!no_stop))
			break;

		rv = do_WrapUnwrapRSA(&generated_test_suites[i]);
		if (rv != CKR_OK && (!no_stop))
			break;

	}

	/***** Error scenarios *****/

	for (i = 0; i < NUM_OF_GENERATED_ERR_TESTSUITES; i++) {
		rv = do_WrapRSA_Err(&generated_err_test_suites[i]);
		if (rv != CKR_OK && (!no_stop))
			break;

		rv = do_UnwrapRSA_Err(&generated_err_test_suites[i]);
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
	printf("With option: securekey: %d\n", securekey);

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
	rv = aes_funcs();
	testcase_print_result();

	/* make sure we return non-zero if rv is non-zero */
	return ((rv == 0) || (rv % 256) ? rv : -1);
}
