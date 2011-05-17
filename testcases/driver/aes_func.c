#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"
#include "aes.h"

#ifndef AES_COUNTER_VALUE
#define AES_COUNTER_VALUE "0123456789012345"
#endif

#ifndef AES_IV_VALUE
#define AES_IV_VALUE "1234567890123456"
#endif

#ifndef AES_KEY_LEN
#define AES_KEY_LEN 32
#endif


CK_ULONG key_lens[] = {16, 24, 32};

CK_RV do_EncryptAES(struct test_suite_info *tsuite)
{
	int 			i, j;
	CK_SLOT_ID		slot_id;
        CK_SESSION_HANDLE	session;
        CK_MECHANISM		mech;
        CK_OBJECT_HANDLE	h_key;
        CK_BYTE			user_pin[PKCS11_MAX_PIN_LEN];
        CK_ULONG		user_pin_len;
	CK_BYTE			data[BIG_REQUEST];
	CK_BYTE			mpdata[BIG_REQUEST];
	CK_ULONG		datalen, len, mplen;
	CK_RV			rc, rv;
	CK_FLAGS		flags;
	CK_BYTE			init_v[AES_BLOCK_SIZE];
	CK_OBJECT_CLASS		keyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE		keyType = CKK_AES;
	CK_BBOOL 		true = TRUE;
	CK_BBOOL 		false = FALSE;
	CK_BYTE			value[MAX_KEY_SIZE];

	CK_AES_CTR_PARAMS aesctr;

	slot_id = SLOT_ID;
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &session);
        if (rc != CKR_OK) {
                show_error("C_OpenSession", rc);
                return rc;
        }

        if (get_user_pin(user_pin))
                return CKR_FUNCTION_FAILED;
        user_pin_len = (CK_ULONG)strlen((char *)user_pin);

        rc = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
        if (rc != CKR_OK) {
                show_error("C_Login", rc);
                goto close;
        }

	rc = 0;

	for (i = 0; i < tsuite->tvcount; i++) {

		CK_ATTRIBUTE	keyTemplate[] = {
			{CKA_CLASS,	&keyClass,	sizeof(keyClass)},
			{CKA_KEY_TYPE, 	&keyType,	sizeof(keyType)},
			{CKA_ENCRYPT, 	&true,		sizeof(true)},
			{CKA_TOKEN, 	&false,		sizeof(false)},
			{CKA_VALUE, 	value,		tsuite->ctv[i].klen}
		};

		/* Create an Object for the key. */
		memset(value, 0, sizeof(value));
		memcpy(value, tsuite->ctv[i].key, tsuite->ctv[i].klen);

		rc = funcs->C_CreateObject(session, keyTemplate, 5, &h_key);
		if (rc != CKR_OK) {
			show_error("C_CreateObject", rc);
			goto close;
		}

		/* Initialize */
		if (tsuite->ctv[i].counterlen != 0) {
			memcpy(aesctr.cb, tsuite->ctv[i].counter, tsuite->ctv[i].counterlen);
			aesctr.ulCounterBits = tsuite->ctv[i].counterbits;
			mech.ulParameterLen = sizeof (CK_AES_CTR_PARAMS);
			mech.pParameter = &aesctr ;
		} else if (tsuite->ctv[i].ivlen != 0) {
			memcpy(init_v, tsuite->ctv[i].iv, tsuite->ctv[i].ivlen);
			mech.ulParameterLen = tsuite->ctv[i].ivlen;
			mech.pParameter = init_v;
		} else {
			mech.ulParameterLen = 0;
			mech.pParameter = NULL;
		}
		mech.mechanism = tsuite->mechcrypt;
		rc = funcs->C_EncryptInit(session, &mech, h_key);
	        if (rc != CKR_OK) {
			show_error("C_EncryptInit", rc);
			goto error;
		}

		/* do some preparation */

		memset(data, 0, sizeof(data));
		memset(mpdata, 0, sizeof(mpdata));
		memcpy(data, tsuite->ctv[i].plaintext, tsuite->ctv[i].plen);
		memcpy(mpdata, tsuite->ctv[i].plaintext, tsuite->ctv[i].plen);
		datalen = len = mplen = tsuite->ctv[i].plen;


		/* now do the single encryption */
		rc = funcs->C_Encrypt(session, data, datalen, data, &len);
		if (rc != CKR_OK) {
			show_error("C_Encrypt", rc);
			goto error;
		}

		/* now do Encryption in multiple parts. */
		rc = funcs->C_EncryptInit(session, &mech, h_key);
	        if (rc != CKR_OK) {
			show_error("C_EncryptInit", rc);
			goto error;
		}

		j = 0;
		while (j < datalen) {

			rc = funcs->C_EncryptUpdate(session, &mpdata[j], AES_BLOCK_SIZE, &mpdata[j], &mplen );
			if (rc != CKR_OK) {
				show_error("C_EncryptUpdate", rc);
				goto error;
			}

			j += mplen;
			mplen = datalen - mplen;
		}

		/*
		   According to pkcs11 spec, nothing should
		   be returned in final.
		*/
		rc = funcs->C_EncryptFinal(session, &mpdata[j], &mplen);
		if (rc != CKR_OK) {
			show_error("C_EncryptFinal", rc );
			goto error;
		}

		if (mplen != 0) {
			PRINT_ERR("ERROR:%s, test %d, EncryptFinal wants to return %ld bytes\n", tsuite->name, i, len);
			goto error;
		}

		/* compare results from the single encryption,
		   multipart encryption and  expected
		   results in the test vector.
                 */
		if (len != j) {
			PRINT_ERR("ERROR:%s, test %d, single and multipart encryption lengths do not match.\n", tsuite->name, i);
			rc = -1;
			goto error;
		}

		if (len != tsuite->ctv[i].clen) {
			PRINT_ERR("ERROR:%s, test %d, lengths do not match test vector length.\n", tsuite->name, i);
			rc = -1;
			goto error;
		}

		if (memcmp(data, mpdata, tsuite->ctv[i].clen)) {
			PRINT_ERR("ERROR:%s, test %d, single and multipart encryption does not match.\n", tsuite->name, i);
			rc = -1;
			goto error;
		}

		if (memcmp(data, tsuite->ctv[i].ciphertext, tsuite->ctv[i].clen)) {
			PRINT_ERR("ERROR:%s, test %d, encrypted data does not match test vector.\n", tsuite->name, i);
			rc = -1;
			goto error;
		}

		rc = funcs->C_DestroyObject(session, h_key);
		if (rc != CKR_OK) {
			show_error("C_DestroyObject", rc );
			goto close;
		}
	}
	goto close;

error:
	rv = funcs->C_DestroyObject(session, h_key);
	if (rv != CKR_OK)
		show_error("C_DestroyObject", rv );

close:
        rv = funcs->C_CloseSession(session);
        if (rv != CKR_OK)
                show_error("C_CloseSession", rv );

	if (!rc)
		printf("%s encrypt tests Passed.\n", tsuite->name);

	return rc;
}

CK_RV do_DecryptAES(struct test_suite_info *tsuite)
{
	int 			i, j;
	CK_SLOT_ID		slot_id;
        CK_SESSION_HANDLE	session;
        CK_MECHANISM		mech;
        CK_OBJECT_HANDLE	h_key;
        CK_BYTE			user_pin[PKCS11_MAX_PIN_LEN];
        CK_ULONG		user_pin_len;
	CK_BYTE			data[BIG_REQUEST];
	CK_BYTE			mpdata[BIG_REQUEST];
	CK_ULONG		datalen, len, mplen;
	CK_RV			rc, rv;
	CK_AES_CTR_PARAMS       aesctr;
	CK_FLAGS		flags;
	CK_BYTE			init_v[AES_BLOCK_SIZE];

	CK_OBJECT_CLASS		keyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE		keyType = CKK_AES;
	CK_BBOOL 		true = TRUE;
	CK_BBOOL 		false = FALSE;
	CK_BYTE			value[MAX_KEY_SIZE];

	slot_id = SLOT_ID;
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &session);
        if (rc != CKR_OK) {
                show_error("C_OpenSession", rc);
                return rc;
        }

        if (get_user_pin(user_pin))
                return CKR_FUNCTION_FAILED;
        user_pin_len = (CK_ULONG)strlen((char *)user_pin);

        rc = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
        if (rc != CKR_OK) {
                show_error("C_Login", rc);
                goto close;
        }

	rc = 0;

	for (i = 0; i < tsuite->tvcount; i++) {

		CK_ATTRIBUTE	keyTemplate[] = {
			{CKA_CLASS,	&keyClass,	sizeof(keyClass)},
			{CKA_KEY_TYPE, 	&keyType,	sizeof(keyType)},
			{CKA_ENCRYPT, 	&true,		sizeof(true)},
			{CKA_TOKEN, 	&false,		sizeof(false)},
			{CKA_VALUE, 	value,		tsuite->ctv[i].klen}
		};

		/* Create an Object for the key. */
		memset(value, 0, sizeof(value));
		memcpy(value, tsuite->ctv[i].key, tsuite->ctv[i].klen);

		rc = funcs->C_CreateObject(session, keyTemplate, 5, &h_key);
		if (rc != CKR_OK) {
			show_error("C_CreateObject", rc);
			goto close;
		}

		/* Initialize */
		if (tsuite->ctv[i].counterlen != 0) {
			memcpy(aesctr.cb, tsuite->ctv[i].counter, tsuite->ctv[i].counterlen);
			aesctr.ulCounterBits = tsuite->ctv[i].counterbits;
			mech.ulParameterLen = sizeof (CK_AES_CTR_PARAMS);
			mech.pParameter = &aesctr;
		} else if (tsuite->ctv[i].ivlen != 0) {
			memcpy(init_v, tsuite->ctv[i].iv, tsuite->ctv[i].ivlen);
			mech.ulParameterLen = tsuite->ctv[i].ivlen;
			mech.pParameter = init_v;
		} else {
			mech.ulParameterLen = 0;
			mech.pParameter = NULL;
		}
		mech.mechanism = tsuite->mechcrypt;

		rc = funcs->C_DecryptInit(session, &mech, h_key);
	        if (rc != CKR_OK) {
			show_error("C_DecryptInit", rc);
			goto error;
		}

		/* do some preparation */

		memset(data, 0, sizeof(data));
		memset(mpdata, 0, sizeof(mpdata));
		memcpy(data, tsuite->ctv[i].ciphertext, tsuite->ctv[i].clen);
		memcpy(mpdata, tsuite->ctv[i].ciphertext, tsuite->ctv[i].clen);
		datalen = len = mplen = tsuite->ctv[i].clen;

		/* now do the single decryption */
		rc = funcs->C_Decrypt(session, data, datalen, data, &len);
		if (rc != CKR_OK) {
			show_error("C_Decrypt", rc);
			goto error;
		}

		/* now do Decryption in multiple parts. */
		rc = funcs->C_DecryptInit(session, &mech, h_key);
		if (rc != CKR_OK) {
			show_error("C_DecryptInit", rc);
			goto error;
		}

		j = 0;
		while (j < datalen) {

			rc = funcs->C_DecryptUpdate(session, &mpdata[j], AES_BLOCK_SIZE, &mpdata[j], &mplen );
			if (rc != CKR_OK) {
				show_error("C_DecryptUpdate", rc);
				goto error;
			}

			j += mplen;
			mplen = datalen - mplen;
		}

		/*
		   According to pkcs11 spec, nothing should
		   be returned in final.
		*/
		rc = funcs->C_DecryptFinal(session, &mpdata[j], &mplen);
		if (rc != CKR_OK) {
			show_error("C_DecryptFinal", rc );
			goto error;
		}

		if (mplen != 0) {
			PRINT_ERR("ERROR:%s, test %d, DecryptFinal wants to return %ld bytes\n", tsuite->name, i, len);
			goto error;
		}

		/* compare results from the single encryption,
		   multipart encryption and  expected
		   results in the test vector.
		*/
		if (len != j) {
			PRINT_ERR("ERROR:%s, test %d, single and multipart decryption lengths do not match.\n", tsuite->name, i);
			rc = -1;
			goto error;
		}

		if (len != tsuite->ctv[i].plen) {
			PRINT_ERR("ERROR:%s, test %d, lengths do not match test vector length.\n", tsuite->name, i);
			rc = -1;
			goto error;
		}

		if (memcmp(data, mpdata, tsuite->ctv[i].plen)) {
			PRINT_ERR("ERROR:%s, test %d, single and multipart decryption does not match.\n", tsuite->name, i);
			rc = -1;
			goto error;
		}

		if (memcmp(data, tsuite->ctv[i].plaintext, tsuite->ctv[i].plen)) {
			PRINT_ERR("ERROR:%s, test %d, decrypted data does not match test vector.\n", tsuite->name, i);
			rc = -1;
			goto error;
		}

		rc = funcs->C_DestroyObject(session, h_key);
		if (rc != CKR_OK) {
			show_error("C_DestroyObject", rc );
			goto close;
		}
	}
	goto close;

error:
	rv = funcs->C_DestroyObject(session, h_key);
	if (rv != CKR_OK)
		show_error("C_DestroyObject", rv );

close:
		rv = funcs->C_CloseSession(session);
		if (rv != CKR_OK)
			show_error("C_CloseAllSessions", rv );

	if (!rc)
		printf("%s decrypt tests Passed.\n", tsuite->name);

	return rc;
}

CK_RV do_PadAES(CK_ULONG key_len, struct test_suite_info *tsuite)
{
	CK_BYTE	original[BIG_REQUEST];
	CK_BYTE	crypt1[BIG_REQUEST + AES_BLOCK_SIZE];  /* account for padding */
	CK_BYTE	crypt2[BIG_REQUEST + AES_BLOCK_SIZE];
	CK_BYTE	decrypt1[BIG_REQUEST + AES_BLOCK_SIZE];
	CK_BYTE	decrypt2[BIG_REQUEST + AES_BLOCK_SIZE];

	CK_SLOT_ID		slot_id;
	CK_SESSION_HANDLE	session;
	CK_MECHANISM		mech;
	CK_OBJECT_HANDLE	h_key;
	CK_FLAGS		flags;
	CK_BYTE			init_v[AES_BLOCK_SIZE];
	CK_BYTE			user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG		user_pin_len;
	CK_ULONG		i, k;
	CK_ULONG		orig_len, crypt1_len, crypt2_len, decrypt1_len, decrypt2_len;
	CK_RV			rc = 0, key_size = key_len;
	CK_ATTRIBUTE		key_gen_tmpl[] = {
					{CKA_VALUE_LEN, &key_size, sizeof(CK_ULONG) }
				};

	slot_id = SLOT_ID;
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &session);
	if (rc != CKR_OK) {
		show_error("C_OpenSession #1", rc );
		return rc;
	}

	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	rc = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
	if (rc != CKR_OK) {
		show_error("C_Login #1", rc);
		goto error;
	}

	mech.mechanism      = CKM_AES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;

	/* first, generate a AES key */
	rc = funcs->C_GenerateKey( session, &mech, key_gen_tmpl, 1, &h_key );
	if (rc != CKR_OK) {
		show_error("C_GenerateKey #1", rc );
		goto error;
	}

	/* clear out the buffers */
	memset(original,0,sizeof(original));
	memset(crypt1,0,sizeof(crypt1));
	memset(crypt2,0,sizeof(crypt2));
	memset(decrypt1,0,sizeof(decrypt1));
	memset(decrypt2,0,sizeof(decrypt2));

	/* now, encrypt some data */
	orig_len = sizeof(original);

	for (i=0; i < orig_len; i++) {
		original[i] = i % 255;
	}

	memcpy(init_v, AES_IV_VALUE, AES_BLOCK_SIZE);

	mech.mechanism = tsuite->mechpad;
	mech.ulParameterLen = AES_BLOCK_SIZE;
	mech.pParameter = init_v;

	rc = funcs->C_EncryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		show_error("C_EncryptInit #1", rc);
		goto error;
	}

	/* use normal ecb mode to encrypt data1 */
	crypt1_len = sizeof(crypt1);
	rc = funcs->C_Encrypt(session, original, orig_len, crypt1, &crypt1_len);
	if (rc != CKR_OK) {
		show_error("C_Encrypt #1", rc);
		goto error;	
	}

	/* use multipart cbc mode to encrypt data2 in chunks */
	rc = funcs->C_EncryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		show_error("C_EncryptInit #2", rc);
		goto error;
	}

	i = k = 0;
	crypt2_len = sizeof(crypt2);
	while (i < orig_len) {
		CK_ULONG rem =  orig_len - i;
		CK_ULONG chunk, len;

		if (rem < 100)
			chunk = rem;
		else
			chunk = 100;

		len = crypt2_len - k;
		rc = funcs->C_EncryptUpdate(session, &original[i], chunk, &crypt2[k],  &len);
		if (rc != CKR_OK) {
			show_error("C_EncryptUpdate", rc);
			goto error;
		}

		k += len;
		i += chunk;
	}

	crypt2_len = sizeof(crypt2) - k;

	rc = funcs->C_EncryptFinal( session, &crypt2[k], &crypt2_len );
	if (rc != CKR_OK) {
		show_error("C_EncryptFinal #2", rc );
		goto error;
	}

	crypt2_len += k;

	if (crypt2_len != crypt1_len) {
		PRINT_ERR("ERROR:  encrypted lengths don't match\n");
		PRINT_ERR("crypt2_len == %ld,  crypt1_len == %ld\n", crypt2_len, crypt1_len );
		goto error;
	}

	/* compare both encrypted blocks.  they'd better be equal */
	if (memcmp(crypt1, crypt2, crypt2_len)) {
		PRINT_ERR("ERROR: single and multipart encryptions do not match.\n");
		goto error;
	}

	/* now, decrypt the data */
	rc = funcs->C_DecryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		show_error("C_DecryptInit", rc);
		goto error;
	}

	decrypt1_len = sizeof(decrypt1);
	rc = funcs->C_Decrypt(session, crypt1, crypt1_len, decrypt1, &decrypt1_len);
	if (rc != CKR_OK) {
		show_error("C_Decrypt", rc);
		goto error;
	}

	/* use multipart cbc mode to decrypt data2 in 1024 byte chunks */
	rc = funcs->C_DecryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		show_error("C_DecryptInit", rc);
		goto error;
	}

	i = k = 0;

	decrypt2_len = sizeof(decrypt2);

	while (i < crypt2_len) {
		CK_ULONG rem = crypt2_len - i;
		CK_ULONG chunk, len;

		if (rem < 101)
			chunk = rem;
		else
			chunk = 100;

		len = decrypt2_len - k;
		rc = funcs->C_DecryptUpdate(session, &crypt2[i], chunk, &decrypt2[k], &len);
		if (rc != CKR_OK) {
			show_error("C_DecryptUpdate", rc);
			goto error;
		}

		k += len;
		i += chunk;
	}

	decrypt2_len = sizeof(decrypt2) - k;
	rc = funcs->C_DecryptFinal(session, &decrypt2[k], &decrypt2_len);
	if (rc != CKR_OK) {
		show_error("C_DecryptFinal", rc);
		goto error;
	}

	decrypt2_len += k;

	if (decrypt2_len != decrypt1_len) {
		PRINT_ERR("ERROR: single and multipart decrypted lengths don't match\n");
		PRINT_ERR("decrypt1_len == %ld, decrypt2_len == %ld\n", decrypt1_len, decrypt2_len);
		rc = -1;
		goto error;
	}

	if (decrypt2_len != orig_len) {
		PRINT_ERR("ERROR: decrypted lengths don't match the original\n");
		PRINT_ERR("decrypt_len == %ld, orig_len == %ld\n", decrypt1_len, orig_len);
		rc = -1;
		goto error;
	}

	/* compare both decrypted blocks.  they'd better be equal */
	if (memcmp(decrypt1, decrypt2, decrypt2_len)) {
		PRINT_ERR("ERROR: single and multipart decryptions don't match.\n");
		rc = -1;
		goto error;
	}

	/* compare the multi-part decrypted block with the 'control' block */
	if (memcmp(original, decrypt2, orig_len)) {
		PRINT_ERR("ERROR: decrypted mismatch: original != decrypted\n");
		rc = -1;
		goto error;
	}

	printf("%s padding test with key length %ld,  passed.\n", tsuite->name, key_len);

error:
	rc = funcs->C_CloseSession(session);
	if (rc != CKR_OK) 
		show_error("C_CloseSession", rc);

	return rc;
}

CK_RV do_WrapUnwrapAES(CK_ULONG key_len, struct test_suite_info *tsuite)
{
	CK_BYTE		    data1[BIG_REQUEST];
	CK_BYTE		    data2[BIG_REQUEST];
	CK_BYTE		    wrapped_data[3 * AES_BLOCK_SIZE];
	CK_SLOT_ID          slot_id;
	CK_SESSION_HANDLE   session;
	CK_MECHANISM        mech;
	CK_OBJECT_HANDLE    h_key;
	CK_OBJECT_HANDLE    w_key;
	CK_OBJECT_HANDLE    uw_key;
	CK_FLAGS            flags;
	CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG            user_pin_len;
	CK_ULONG            wrapped_data_len;
	CK_ULONG            i;
	CK_ULONG            len1, len2, key_size = key_len;
	CK_RV               rc, loc_rc;
	CK_AES_CTR_PARAMS   aesctr;
	CK_BYTE		    init_v[AES_BLOCK_SIZE] = AES_IV_VALUE;
	CK_ATTRIBUTE        key_gen_tmpl[] = {
		{CKA_VALUE_LEN, &key_size, sizeof(CK_ULONG) }
	};

	CK_OBJECT_CLASS     key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE         key_type  = CKK_AES;
	CK_ULONG            tmpl_count = 3;
	CK_ATTRIBUTE   template[] =
		{
			{ CKA_CLASS,     &key_class,  sizeof(key_class) },
			{ CKA_KEY_TYPE,  &key_type,   sizeof(key_type)  },
			{ CKA_VALUE_LEN, &key_size, sizeof(key_size) }
		};

	printf("do_WrapUnwrapAES %s with key length %d\n", tsuite->name, (int)key_len);

	slot_id = SLOT_ID;
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return rc;
	}

	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
	if (rc != CKR_OK) {
		show_error("   C_Login #1", rc );
		goto error;
	}

	mech.mechanism = CKM_AES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;

	//first generate a AES Key and a wrapping key
	rc = funcs->C_GenerateKey ( session, &mech, key_gen_tmpl, 1, &h_key);
	if (rc != CKR_OK) {
		show_error(" C_GenerateKey 1 ",rc);
		goto error;
	}

	rc =  funcs->C_GenerateKey ( session, &mech, key_gen_tmpl, 1, &w_key);
	if (rc != CKR_OK) {
		show_error(" C_GenerateKey 2 ",rc);
		goto error;
	}

	// encrypt the data
	len1 = len2 = BIG_REQUEST;
	for (i=0; i<len1; i++) {
		data1[i] = i % 255;
		data2[i] = i % 255;
	}

	/* Initialize */
	if (tsuite->ctv[0].counterlen != 0) {
		aesctr.ulCounterBits = 128;
		mech.ulParameterLen = sizeof(CK_AES_CTR_PARAMS);
		mech.pParameter = &aesctr;
	} else if (tsuite->ctv[0].ivlen != 0) {
		mech.ulParameterLen = sizeof(init_v);
		mech.pParameter = init_v;
	} else {
		mech.ulParameterLen = 0;
		mech.pParameter = NULL;
	}
	mech.mechanism = tsuite->mechcrypt;

	// Initiate the encrypt
	rc = funcs->C_EncryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		show_error("C_EncryptInit", rc);
		goto error;
	}

	//Continue with encrypt
	rc = funcs->C_Encrypt( session, data1, len1, data1, &len1);
	if (rc != CKR_OK) {
		show_error("C_Encrypt",rc);
		goto error;
	}

	// now wrap the key....the mechanism is same for all the modes
	wrapped_data_len = 3 * AES_KEY_LEN;

	rc = funcs->C_WrapKey( session, &mech, w_key, h_key, (CK_BYTE *) &wrapped_data, &wrapped_data_len);
	if (rc != CKR_OK) {
		show_error("C_WrapKey ",rc);
		goto error;
	}

	rc = funcs->C_UnwrapKey( session, &mech, w_key, wrapped_data, wrapped_data_len, template, tmpl_count, &uw_key);
	if (rc != CKR_OK) {
		show_error("C_UnwrapKey ",rc);
		goto error;
	}

	// now decrypting the data using the unwrapped key
	rc = funcs->C_DecryptInit( session, &mech, uw_key);
	if (rc != CKR_OK) {
		show_error("C_DecryptInit ",rc);
		goto error;
	}

	rc = funcs->C_Decrypt( session, data1, len1, data1, &len1);
	if(rc != CKR_OK) {
		show_error ("C_Decrypt ", rc);
		goto error;
	}

	if (len1 != len2) {
		PRINT_ERR(" ERROR: lengths don't match \n");
		rc = -1;
		goto error;
	}

	if (memcmp(data1, data2, len1)) {
		PRINT_ERR(" ERROR: Bytes don't match %ld\n", i);
		rc = -1;
		goto error;
	}

	// now, try to wrap an RSA private key.  this should fail.  we'll
	// create a fake key object instead of generating a new one
	//
	{
		CK_OBJECT_CLASS keyclass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE     keytype  = CKK_RSA;

		CK_BYTE  modulus[]   = { 1,2,3,4,5,6,7,8,9,0 };
		CK_BYTE  publ_exp[]  = { 1,2,3,4,5,6,7,8,9,0 };
		CK_BYTE  priv_exp[]  = { 1,2,3,4,5,6,7,8,9,0 };
		CK_BYTE  prime_1[]   = { 1,2,3,4,5,6,7,8,9,0 };
		CK_BYTE  prime_2[]   = { 1,2,3,4,5,6,7,8,9,0 };
		CK_BYTE  exp_1[]     = { 1,2,3,4,5,6,7,8,9,0 };
		CK_BYTE  exp_2[]     = { 1,2,3,4,5,6,7,8,9,0 };
		CK_BYTE  coeff[]     = { 1,2,3,4,5,6,7,8,9,0 };

		CK_ATTRIBUTE  tmpl[] = {
			{ CKA_CLASS,           &keyclass, sizeof(keyclass) },
			{ CKA_KEY_TYPE,        &keytype,  sizeof(keytype)  },
			{ CKA_MODULUS,          modulus,  sizeof(modulus)  },
			{ CKA_PUBLIC_EXPONENT,  publ_exp, sizeof(publ_exp) },
			{ CKA_PRIVATE_EXPONENT, priv_exp, sizeof(priv_exp) },
			{ CKA_PRIME_1,          prime_1,  sizeof(prime_1)  },
			{ CKA_PRIME_2,          prime_2,  sizeof(prime_2)  },
			{ CKA_EXPONENT_1,       exp_1,    sizeof(exp_1)    },
			{ CKA_EXPONENT_2,       exp_2,    sizeof(exp_2)    },
			{ CKA_COEFFICIENT,      coeff,    sizeof(coeff)    }
		};
		CK_OBJECT_HANDLE priv_key;
		CK_BYTE data[1024];
		CK_ULONG data_len = sizeof(data);


		rc = funcs->C_CreateObject( session, tmpl, 10, &priv_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #1", rc );
			goto error;
		}

		rc = funcs->C_WrapKey( session,  &mech,
				w_key,     priv_key,
				data,     &data_len );
		if (rc != CKR_KEY_NOT_WRAPPABLE) {
			show_error("   C_WrapKey #2", rc );
			PRINT_ERR("   Expected CKR_KEY_NOT_WRAPPABLE\n" );
			goto error;
		}
	}

        rc = funcs->C_CloseAllSessions( slot_id );
        if (rc != CKR_OK) {
                show_error("   C_CloseAllSessions #1", rc );
                return rc;
        }

        printf("Success.\n");
        return 0;

error:
	loc_rc = funcs->C_CloseSession (session);
	if (loc_rc != CKR_OK)
		show_error ("   C_CloseSession #2", loc_rc);

	return rc;
}

CK_RV do_WrapUnwrapPadAES( CK_ULONG key_len, struct test_suite_info *tsuite)
{
	CK_BYTE             original[BIG_REQUEST];
	CK_BYTE             cipher  [BIG_REQUEST + AES_BLOCK_SIZE];
	CK_BYTE             decipher[BIG_REQUEST + AES_BLOCK_SIZE];

	CK_BYTE             wrapped_data[BIG_REQUEST + AES_BLOCK_SIZE];

	CK_SLOT_ID          slot_id;
	CK_SESSION_HANDLE   session;
	CK_MECHANISM        mech;
	CK_OBJECT_HANDLE    h_key;
	CK_OBJECT_HANDLE    w_key;
	CK_OBJECT_HANDLE    uw_key;
	CK_FLAGS            flags;
	CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
	CK_BYTE             init_v[AES_BLOCK_SIZE] = AES_IV_VALUE;
	CK_ULONG            user_pin_len;
	CK_ULONG            wrapped_data_len;
	CK_ULONG            i;
	CK_ULONG            orig_len, cipher_len, decipher_len;
	CK_RV               rc = 0, key_size = key_len;
	CK_ATTRIBUTE        key_gen_tmpl[] = {
		{CKA_VALUE_LEN, &key_size, sizeof(CK_ULONG) }
	};

	CK_OBJECT_CLASS     key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE         key_type  = CKK_AES;
	CK_ULONG            tmpl_count = 3;
	CK_ATTRIBUTE   template[] =
	{
		{ CKA_CLASS,     &key_class,  sizeof(key_class) },
		{ CKA_KEY_TYPE,  &key_type,   sizeof(key_type)  },
		{ CKA_VALUE_LEN, &key_size,   sizeof(key_size)  }
	};

	printf (" do_WrapUnwrapPadAES for %s with key length %d\n", tsuite->name, (int)key_len);

	slot_id = SLOT_ID;
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return rc;
	}

	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
	if (rc != CKR_OK) {
		show_error("   C_Login #1", rc );
		goto error;
	}

	mech.mechanism      = CKM_AES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;

	//first generate AES key and wrap key
	rc = funcs->C_GenerateKey ( session, &mech, key_gen_tmpl, 1, &h_key);
	if (rc != CKR_OK)
	{
		show_error(" C_GenerateKey #1", rc);
		goto error;
	}

	rc = funcs->C_GenerateKey ( session, &mech, key_gen_tmpl, 1, &w_key);
	if ( rc != CKR_OK)
	{
		show_error( " C_GenerateKey #2", rc);
		goto error;	
	}

	//now lets encrypt some data
	orig_len = sizeof(original);
	for (i=0; i < orig_len; i++)
	{
		original[i] = i % 255;
	}

	mech.mechanism = tsuite->mechpad;
	mech.ulParameterLen = sizeof(init_v);
	mech.pParameter     = init_v;

	rc = funcs->C_EncryptInit( session, &mech, h_key );
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #1", rc );
		goto error;
	}

	cipher_len = sizeof(cipher);
	rc = funcs->C_Encrypt( session, original, orig_len, cipher, &cipher_len );
	if (rc != CKR_OK) {
		show_error("   C_Encrypt #1", rc );
		goto error;
	}


	// now, wrap the key.
	//
	wrapped_data_len = sizeof(wrapped_data);

	rc = funcs->C_WrapKey( session,      &mech,
			w_key,         h_key,
			wrapped_data, &wrapped_data_len );
	if (rc != CKR_OK) {
		show_error("   C_WrapKey #1", rc );
		goto error;
	}

	rc = funcs->C_UnwrapKey( session, &mech,
			w_key,
			wrapped_data, wrapped_data_len,
			template,  tmpl_count,
			&uw_key );
	if (rc != CKR_OK) {
		show_error("   C_UnWrapKey #1", rc );
		goto error;	
	}


	// now, decrypt the data using the unwrapped key.
	//
	rc = funcs->C_DecryptInit( session, &mech, uw_key );
	if (rc != CKR_OK) {
		show_error("   C_DecryptInit #1", rc );
		goto error;	
	}

	decipher_len = sizeof(decipher);
	rc = funcs->C_Decrypt( session, cipher, cipher_len, decipher, &decipher_len );
	if (rc != CKR_OK) {
		show_error("   C_Decrypt #1", rc );
		goto error;
	}

	if (orig_len != decipher_len) {
		PRINT_ERR("   ERROR:  lengths don't match:  %ld vs %ld\n", orig_len, decipher_len );
		rc = -1;
		goto error;
	}

	for (i=0; i < orig_len; i++) {
		if (original[i] != decipher[i]) {
			PRINT_ERR("   ERROR:  mismatch at byte %ld\n", i );
			rc = -1;
			goto error;
		}
	}

	// we'll generate an RSA keypair here so we can make sure it works
	//
	{
		CK_MECHANISM      mech2;
		CK_OBJECT_HANDLE  publ_key, priv_key;

		CK_ULONG     bits = 1024;
		CK_BYTE      pub_exp[] = { 0x3 };

		CK_ATTRIBUTE pub_tmpl[] = {
			{CKA_MODULUS_BITS,    &bits,    sizeof(bits)    },
			{CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp) }
		};

		CK_OBJECT_CLASS  keyclass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE      keytype  = CKK_RSA;
		CK_ATTRIBUTE uw_tmpl[] = {
			{CKA_CLASS,    &keyclass,  sizeof(keyclass) },
			{CKA_KEY_TYPE, &keytype,   sizeof(keytype) }
		};

		mech2.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
		mech2.ulParameterLen = 0;
		mech2.pParameter     = NULL;

		rc = funcs->C_GenerateKeyPair( session,   &mech2,
				pub_tmpl,   2,
				NULL,       0,
				&publ_key, &priv_key );
		if (rc != CKR_OK) {
			show_error("   C_GenerateKeyPair #1", rc );
			goto error;
		}


		// now, wrap the key.
		//
		wrapped_data_len = sizeof(wrapped_data);

		rc = funcs->C_WrapKey( session,      &mech,
				w_key,         priv_key,
				wrapped_data, &wrapped_data_len );
		if (rc != CKR_OK) {
			show_error("   C_WrapKey #2", rc );
			goto error;
		}

		rc = funcs->C_UnwrapKey( session, &mech,
				w_key,
				wrapped_data, wrapped_data_len,
				uw_tmpl,  2,
				&uw_key );
		if (rc != CKR_OK) {
			show_error("   C_UnWrapKey #2", rc );
			goto error;
		}

		// encrypt something with the public key
		//
		mech2.mechanism      = CKM_RSA_PKCS;
		mech2.ulParameterLen = 0;
		mech2.pParameter     = NULL;

		rc = funcs->C_EncryptInit( session, &mech2, publ_key );
		if (rc != CKR_OK) {
			show_error("   C_EncryptInit #2", rc );
			goto error;
		}

		// for RSA operations, keep the input data size smaller than
		// the modulus
		//
		orig_len = 30;

		cipher_len = sizeof(cipher);
		rc = funcs->C_Encrypt( session, original, orig_len, cipher, &cipher_len );
		if (rc != CKR_OK) {
			show_error("   C_Encrypt #2", rc );
			goto error;
		}

		// now, decrypt the data using the unwrapped private key.
		//
		rc = funcs->C_DecryptInit( session, &mech2, uw_key );
		if (rc != CKR_OK) {
			show_error("   C_DecryptInit #1", rc );
			goto error;
		}

		decipher_len = sizeof(decipher);
		rc = funcs->C_Decrypt( session, cipher, cipher_len, decipher, &decipher_len );
		if (rc != CKR_OK) {
			show_error("   C_Decrypt #1", rc );
			goto error;
		}

		if (orig_len != decipher_len) {
			PRINT_ERR("   ERROR:  lengths don't match:  %ld vs %ld\n", orig_len, decipher_len );
			rc = -1;
			goto error;
		}

		for (i=0; i < orig_len; i++) {
			if (original[i] != decipher[i]) {
				PRINT_ERR("   ERROR:  mismatch at byte %ld\n", i );
				rc = -1;
				goto error;
			}
		}
	}

	printf("Success.\n");

error:
	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc );
		goto error;
	}

	return rc;
}

int main  (int argc, char **argv)
{
	int rc, i, fcount;
	CK_C_INITIALIZE_ARGS cinit_args;
	CK_RV rv;
	SYSTEMTIME t1, t2;
	CK_ULONG j;

	rc = do_ParseArgs(argc, argv);
	if (rc != 1)
		return rc;

	printf("Using slot #%lu...\n\n", SLOT_ID );
	printf("With option: no_stop: %d\n", no_stop);

	rc = do_GetFunctionList();
	if (!rc) {
		PRINT_ERR("ERROR do_GetFunctionList() Failed , rc = 0x%0x\n", rc);
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

	rv = 0;
	fcount = 0;
	for (i = 0; i < NUM_OF_TESTSUITES; i++) {
		if (test_suites[i].mechcrypt) {
			GetSystemTime(&t1);
			rv = do_EncryptAES(&test_suites[i]);
			GetSystemTime(&t2);
			process_time(t1, t2);
			if (rv) {
				PRINT_ERR("ERROR do_EncryptAES tests for %s failed, rv = 0x%lx\n", test_suites[i].name, rv);
				if (!no_stop)	
					return -1;
				else
					fcount++;
			}

			GetSystemTime(&t1);
			rv = do_DecryptAES(&test_suites[i]);
			GetSystemTime(&t2);
			process_time(t1, t2);
			if (rv) {
				PRINT_ERR("ERROR do_DecryptAES tests for %s failed, rv = 0x%lx\n", test_suites[i].name, rv);
				if (!no_stop)	
					return -1;
				else
					fcount++;
			}

			for (j = 0; j < 3; j++) {
				GetSystemTime(&t1);
				rv = do_WrapUnwrapAES(key_lens[j], &test_suites[i]);
				GetSystemTime(&t2);
				process_time(t1, t2);
				if (rv) {
					PRINT_ERR("ERROR do_WrapUnwrapAES tests for %s failed, rv = 0x%lx\n", test_suites[i].name, rv);
					if (!no_stop)	
						return -1;
					else
						fcount++;
				}
			}
		}

		if (test_suites[i].mechpad) {
			for (j = 0; j < 3; j++) {
				GetSystemTime(&t1);
				rc = do_PadAES(key_lens[j], &test_suites[i]);
				GetSystemTime(&t2);
				process_time(t1, t2);
				if (rv) {
					PRINT_ERR("ERROR do_PadAES tests for %s failed, rv = 0x%lx\n",test_suites[i].name, rv);
					if (!no_stop)	
						return -1;
					else
						fcount++;
				}
			}
			for (j = 0; j < 3; j++) {
				GetSystemTime(&t1);
				rc = do_WrapUnwrapPadAES(key_lens[j], &test_suites[i]);
				GetSystemTime(&t2);
				process_time(t1, t2);
				if (rv) {
					PRINT_ERR("ERROR do_PadAES tests for %s failed, rv = 0x%lx\n", test_suites[i].name, rv);
					if (!no_stop)	
						return -1;
					else
						fcount++;
				}
			}
		}

		if (fcount) {
			PRINT_ERR("ERROR test suite %s failed.\n", test_suites[i].name);
			rv = -1;
		}
	}

	/* make sure we return non-zero if rv is non-zero */
	return (rv);
}
