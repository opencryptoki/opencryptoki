// File: aes_func.c
//


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <dlfcn.h>

#include "pkcs11types.h"
#include "regress.h"

void		*dl_handle;
unsigned long	SlotID = 0;
int do_GetFunctionList(void);

#define AES_KEY_SIZE_256	32
#define AES_BLOCK_SIZE		16
#define AES_KEY_LEN		32

CK_FUNCTION_LIST	*funcs;
CK_SESSION_HANDLE	sess;

#define OC_ERR_MSG(a,b)	oc_err_msg(__FILE__, __LINE__, a, b)

//
//
int do_EncryptAES_ECB(void)
{
	CK_BYTE data1[BIG_REQUEST];
	CK_BYTE data2[BIG_REQUEST];
	CK_SLOT_ID slot_id;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mech;
	CK_OBJECT_HANDLE h_key;
	CK_FLAGS flags;
	CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG user_pin_len;
	CK_ULONG i;
	CK_ULONG len1, len2, key_size = AES_KEY_SIZE_256;
	CK_RV rc;
	CK_ATTRIBUTE key_gen_tmpl[] = {
		{CKA_VALUE_LEN, &key_size, sizeof(CK_ULONG) }
	};

	printf("do_EncryptAES_ECB...\n");

	slot_id = SlotID;
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &session);
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc);
		return FALSE;
	}


	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	rc = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
	if (rc != CKR_OK) {
		show_error("   C_Login #1", rc);
		return FALSE;
	}

	mech.mechanism = CKM_AES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;


	// first, generate an AES key
	//
	rc = funcs->C_GenerateKey(session, &mech, key_gen_tmpl, 1, &h_key);
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #1", rc);
		return FALSE;
	}

	// now, encrypt some data
	//
	len1 = len2 = BIG_REQUEST;

	for (i = 0; i < len1; i++) {
		data1[i] = i % 255;
		data2[i] = i % 255;
	}

	mech.mechanism = CKM_AES_ECB;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;

	rc = funcs->C_EncryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #1", rc);
		return FALSE;
	}

	rc = funcs->C_Encrypt(session, data1, len1, data1, &len1);
	if (rc != CKR_OK) {
		show_error("   C_Encrypt #1", rc);
		return FALSE;
	}
	// now, decrypt the data
	//
	rc = funcs->C_DecryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		show_error("   C_DecryptInit #1", rc);
		return FALSE;
	}

	rc = funcs->C_Decrypt(session, data1, len1, data1, &len1);
	if (rc != CKR_OK) {
		show_error("   C_Decrypt #1", rc);
		return FALSE;
	}

	if (len1 != len2) {
		printf("   ERROR:  lengths don't match\n");
		return FALSE;
	}

	for (i = 0; i < len1; i++) {
		if (data1[i] != data2[i]) {
			printf("   ERROR:  mismatch at byte %ld\n", i);
			return FALSE;
		}
	}

	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc);
		return FALSE;
	}

	printf("Looks okay...\n");
	return TRUE;
}


//
//
int do_EncryptAES_Multipart_ECB(void)
{
	CK_BYTE original[BIG_REQUEST];
	CK_BYTE crypt1[BIG_REQUEST];
	CK_BYTE crypt2[BIG_REQUEST];
	CK_BYTE decrypt1[BIG_REQUEST];
	CK_BYTE decrypt2[BIG_REQUEST];

	CK_SLOT_ID slot_id;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mech;
	CK_OBJECT_HANDLE h_key;
	CK_FLAGS flags;
	CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG user_pin_len;
	CK_ULONG i, k, key_size = AES_KEY_SIZE_256;
	CK_ULONG orig_len;
	CK_ULONG crypt1_len, crypt2_len, decrypt1_len, decrypt2_len;
	CK_ULONG tmp;
	CK_RV rc;
	CK_ATTRIBUTE key_gen_tmpl[] = {
		{CKA_VALUE_LEN, &key_size, sizeof(CK_ULONG) }
	};

	printf("do_EncryptAES_Multipart_ECB...\n");

	slot_id = SlotID;
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &session);
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc);
		return FALSE;
	}


	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	rc = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
	if (rc != CKR_OK) {
		show_error("   C_Login #1", rc);
		return FALSE;
	}

	mech.mechanism = CKM_AES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;


	// first, generate an AES key
	//
	rc = funcs->C_GenerateKey(session, &mech, key_gen_tmpl, 1, &h_key);
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #1", rc);
		return FALSE;
	}

	// now, encrypt some data
	//
	orig_len = sizeof(original);
	for (i = 0; i < orig_len; i++) {
		original[i] = i % 255;
	}

	mech.mechanism = CKM_AES_ECB;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;

	rc = funcs->C_EncryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #1", rc);
		return FALSE;
	}
	// use normal ecb mode to encrypt data1
	//
	crypt1_len = sizeof(crypt1);
	rc = funcs->C_Encrypt(session, original, orig_len, crypt1,
			      &crypt1_len);
	if (rc != CKR_OK) {
		show_error("   C_Encrypt #1", rc);
		return FALSE;
	}
	// use multipart ecb mode to encrypt data2 in 5 byte chunks
	//
	rc = funcs->C_EncryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #2", rc);
		return FALSE;
	}

	i = k = 0;
	crypt2_len = sizeof(crypt2);

	while (i < orig_len) {
		CK_ULONG rem = orig_len - i;
		CK_ULONG chunk;

		if (rem < 100)
			chunk = rem;
		else
			chunk = 100;

		tmp = crypt2_len - k;	// how much room is left in crypt2?

		rc = funcs->C_EncryptUpdate(session, &original[i], chunk,
					    &crypt2[k], &tmp);
		if (rc != CKR_OK) {
			show_error("   C_EncryptUpdate #1", rc);
			return FALSE;
		}

		k += tmp;
		i += chunk;
	}

	crypt2_len = k;

	// AES-ECB shouldn't return anything for EncryptFinal per the spec
	//
	rc = funcs->C_EncryptFinal(session, NULL, &tmp);
	if (rc != CKR_OK) {
		show_error("   C_EncryptFinal #2", rc);
		return FALSE;
	}

	if (tmp != 0) {
		printf
		    ("   ERROR:  DecryptFinal wants to return %ld bytes\n",
		     tmp);
		return FALSE;
	}

	if (crypt2_len != crypt1_len) {
		printf("   ERROR:  crypt1_len = %ld, crypt2_len = %ld\n",
		       crypt1_len, crypt2_len);
		return FALSE;
	}

	// compare both encrypted blocks.  they'd better be equal
	//
	for (i = 0; i < crypt1_len; i++) {
		if (crypt1[i] != crypt2[i]) {
			printf
			    ("   ERROR:  mismatch.  crypt1 != crypt2 at byte %ld\n",
			     i);
			return FALSE;
		}
	}

	// now, decrypt the data
	//
	rc = funcs->C_DecryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		show_error("   C_DecryptInit #1", rc);
		return FALSE;
	}

	decrypt1_len = sizeof(decrypt1);
	rc = funcs->C_Decrypt(session, crypt1, crypt1_len, decrypt1,
			      &decrypt1_len);
	if (rc != CKR_OK) {
		show_error("   C_Decrypt #1", rc);
		return FALSE;
	}
	// use multipart ecb mode to encrypt data2 in 1024 byte chunks
	//
	rc = funcs->C_DecryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		show_error("   C_DecryptInit #1", rc);
		return FALSE;
	}

	i = k = 0;
	decrypt2_len = sizeof(decrypt2);

	while (i < crypt1_len) {
		CK_ULONG rem = crypt1_len - i;
		CK_ULONG chunk;

		if (rem < 101)
			chunk = rem;
		else
			chunk = 101;

		tmp = decrypt2_len - k;

		rc = funcs->C_DecryptUpdate(session, &crypt1[i], chunk,
					    &decrypt2[k], &tmp);
		if (rc != CKR_OK) {
			show_error("   C_DecryptUpdate #1", rc);
			return FALSE;
		}

		k += tmp;
		i += chunk;
	}

	decrypt2_len = k;

	// AES-ECB shouldn't return anything for EncryptFinal per the spec
	//
	rc = funcs->C_DecryptFinal(session, NULL, &tmp);
	if (rc != CKR_OK) {
		show_error("   C_DecryptFinal #2", rc);
		return FALSE;
	}

	if (tmp != 0) {
		printf
		    ("   ERROR:  DecryptFinal wants to return %ld bytes\n",
		     tmp);
		return FALSE;
	}

	if (decrypt1_len != decrypt2_len) {
		printf("   ERROR:  decrypt1_len = %ld, decrypt2_len = %ld\n",
		       decrypt1_len, decrypt2_len);
		return FALSE;
	}

	if (decrypt1_len != orig_len) {
		printf
		    ("   ERROR:  decrypted lengths = %ld, original length = %ld\n",
		     decrypt1_len, orig_len);
		return FALSE;
	}
	// compare both decrypted blocks.  they'd better be equal
	//
	for (i = 0; i < decrypt1_len; i++) {
		if (decrypt1[i] != decrypt2[i]) {
			printf
			    ("   ERROR:  mismatch.  decrypt1 != decrypt2 at byte %ld\n",
			     i);
			return FALSE;
		}
	}

	// compare the multi-part decrypted block with the 'control' block
	//
	for (i = 0; i < orig_len; i++) {
		if (original[i] != decrypt1[i]) {
			printf
			    ("   ERROR:  decrypted mismatch: original != decrypt at byte %ld\n",
			     i);
			return FALSE;
		}
	}


	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc);
		return FALSE;
	}

	printf("Looks okay...\n");
	return TRUE;
}


//
//
int do_EncryptAES_CBC(void)
{
	CK_BYTE data1[BIG_REQUEST];
	CK_BYTE data2[BIG_REQUEST];
	CK_SLOT_ID slot_id;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mech;
	CK_OBJECT_HANDLE h_key;
	CK_FLAGS flags;
	CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG user_pin_len;
	CK_BYTE init_v[AES_BLOCK_SIZE];
	CK_ULONG i, key_size = AES_KEY_SIZE_256;
	CK_ULONG len1, len2;
	CK_RV rc;
	CK_ATTRIBUTE key_gen_tmpl[] = {
		{CKA_VALUE_LEN, &key_size, sizeof(CK_ULONG) }
	};

	printf("do_EncryptAES_CBC...\n");

	slot_id = SlotID;
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &session);
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc);
		return FALSE;
	}


	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	rc = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
	if (rc != CKR_OK) {
		show_error("   C_Login #1", rc);
		return FALSE;
	}


	mech.mechanism = CKM_AES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;


	// first, generate an AES key
	//
	rc = funcs->C_GenerateKey(session, &mech, key_gen_tmpl, 1, &h_key);
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #1", rc);
		return FALSE;
	}

	// now, encrypt some data
	//
	len1 = len2 = BIG_REQUEST;

	for (i = 0; i < len1; i++) {
		data1[i] = i % 255;
		data2[i] = i % 255;
	}

	memcpy(init_v, "0123456789abcdef", 8);

	mech.mechanism = CKM_AES_CBC;
	mech.ulParameterLen = AES_BLOCK_SIZE;
	mech.pParameter = init_v;

	rc = funcs->C_EncryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #1", rc);
		return FALSE;
	}

	rc = funcs->C_Encrypt(session, data1, len1, data1, &len1);
	if (rc != CKR_OK) {
		show_error("   C_Encrypt #1", rc);
		return FALSE;
	}
	// now, decrypt the data
	//
	rc = funcs->C_DecryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		show_error("   C_DecryptInit #1", rc);
		return FALSE;
	}

	rc = funcs->C_Decrypt(session, data1, len1, data1, &len1);
	if (rc != CKR_OK) {
		show_error("   C_Decrypt #1", rc);
		return FALSE;
	}

	if (len1 != len2) {
		printf("   ERROR:  lengths don't match\n");
		return FALSE;
	}

	for (i = 0; i < len1; i++) {
		if (data1[i] != data2[i]) {
			printf("   ERROR:  mismatch at byte %ld\n", i);
			return FALSE;
		}
	}

	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc);
		return FALSE;
	}

	printf("Looks okay...\n");
	return TRUE;
}


//
//
int do_EncryptAES_Multipart_CBC(void)
{
	CK_BYTE original[BIG_REQUEST];
	CK_BYTE crypt1[BIG_REQUEST];
	CK_BYTE crypt2[BIG_REQUEST];
	CK_BYTE decrypt1[BIG_REQUEST];
	CK_BYTE decrypt2[BIG_REQUEST];

	CK_SLOT_ID slot_id;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mech;
	CK_OBJECT_HANDLE h_key;
	CK_FLAGS flags;
	CK_BYTE init_v[AES_BLOCK_SIZE];
	CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG user_pin_len;
	CK_ULONG i, k, key_size = AES_KEY_SIZE_256;
	CK_ULONG orig_len;
	CK_ULONG crypt1_len, crypt2_len, decrypt1_len, decrypt2_len;
	CK_ULONG tmp;
	CK_RV rc;
	CK_ATTRIBUTE key_gen_tmpl[] = {
		{CKA_VALUE_LEN, &key_size, sizeof(CK_ULONG) }
	};

	printf("do_EncryptAES_Multipart_CBC...\n");

	slot_id = SlotID;
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &session);
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc);
		return FALSE;
	}


	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	rc = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
	if (rc != CKR_OK) {
		show_error("   C_Login #1", rc);
		return FALSE;
	}

	mech.mechanism = CKM_AES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;


	// first, generate an AES key
	//
	rc = funcs->C_GenerateKey(session, &mech, key_gen_tmpl, 1, &h_key);
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #1", rc);
		return FALSE;
	}

	// now, encrypt some data
	//
	orig_len = sizeof(original);
	for (i = 0; i < orig_len; i++) {
		original[i] = i % 255;
	}

	memcpy(init_v, "0123456789abcdef", 16);

	mech.mechanism = CKM_AES_CBC;
	mech.ulParameterLen = AES_BLOCK_SIZE;
	mech.pParameter = init_v;

	rc = funcs->C_EncryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #1", rc);
		return FALSE;
	}
	// use normal ecb mode to encrypt data1
	//
	crypt1_len = sizeof(crypt1);
	rc = funcs->C_Encrypt(session, original, orig_len, crypt1,
			      &crypt1_len);
	if (rc != CKR_OK) {
		show_error("   C_Encrypt #1", rc);
		return FALSE;
	}
	// use multipart cbc mode to encrypt data2 in 1024 byte chunks
	//
	rc = funcs->C_EncryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #2", rc);
		return FALSE;
	}

	i = k = 0;
	crypt2_len = sizeof(crypt2);

	while (i < orig_len) {
		CK_ULONG rem = orig_len - i;
		CK_ULONG chunk;

		if (rem < 100)
			chunk = rem;
		else
			chunk = 100;

		tmp = crypt2_len - k;	// how much room is left in crypt2?

		rc = funcs->C_EncryptUpdate(session, &original[i], chunk,
					    &crypt2[k], &tmp);
		if (rc != CKR_OK) {
			show_error("   C_EncryptUpdate #1", rc);
			return FALSE;
		}

		k += tmp;
		i += chunk;
	}

	crypt2_len = k;

	rc = funcs->C_EncryptFinal(session, NULL, &tmp);
	if (rc != CKR_OK) {
		show_error("   C_EncryptFinal #2", rc);
		return FALSE;
	}

	if (tmp != 0) {
		printf
		    ("   ERROR:  EncryptFinal wants to return %ld bytes\n",
		     tmp);
		return FALSE;
	}


	if (crypt2_len != crypt1_len) {
		printf("   ERROR:  crypt1_len = %ld, crypt2_len = %ld\n",
		       crypt1_len, crypt2_len);
		return FALSE;
	}
	// compare both encrypted blocks.  they'd better be equal
	//
	for (i = 0; i < crypt1_len; i++) {
		if (crypt1[i] != crypt2[i]) {
			printf
			    ("   ERROR:  mismatch.  crypt1 != crypt2 at byte %ld\n",
			     i);
			return FALSE;
		}
	}



	// now, decrypt the data
	//
	rc = funcs->C_DecryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		show_error("   C_DecryptInit #1", rc);
		return FALSE;
	}

	decrypt1_len = sizeof(decrypt1);
	rc = funcs->C_Decrypt(session, crypt1, crypt1_len, decrypt1,
			      &decrypt1_len);
	if (rc != CKR_OK) {
		show_error("   C_Decrypt #1", rc);
		return FALSE;
	}
	// use multipart cbc mode to encrypt data2 in 1024 byte chunks
	//
	rc = funcs->C_DecryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		show_error("   C_DecryptInit #1", rc);
		return FALSE;
	}


	i = k = 0;
	decrypt2_len = sizeof(decrypt2);

	while (i < crypt1_len) {
		CK_ULONG rem = crypt1_len - i;
		CK_ULONG chunk;

		if (rem < 101)
			chunk = rem;
		else
			chunk = 101;

		tmp = decrypt2_len - k;

		rc = funcs->C_DecryptUpdate(session, &crypt1[i], chunk,
					    &decrypt2[k], &tmp);
		if (rc != CKR_OK) {
			show_error("   C_DecryptUpdate #1", rc);
			return FALSE;
		}

		k += tmp;
		i += chunk;
	}

	decrypt2_len = k;

	rc = funcs->C_DecryptFinal(session, NULL, &tmp);
	if (rc != CKR_OK) {
		show_error("   C_DecryptFinal #2", rc);
		return FALSE;
	}

	if (tmp != 0) {
		printf
		    ("   ERROR:  DecryptFinal wants to return %ld bytes\n",
		     tmp);
		return FALSE;
	}

	if (decrypt2_len != decrypt1_len) {
		printf("   ERROR:  decrypt1_len = %ld, decrypt2_len = %ld\n",
		       decrypt1_len, decrypt2_len);
		return FALSE;
	}
	// compare both decrypted blocks.  they'd better be equal
	//
	for (i = 0; i < decrypt1_len; i++) {
		if (crypt1[i] != crypt2[i]) {
			printf
			    ("   ERROR:  mismatch.  decrypt1 != decrypt2 at byte %ld\n",
			     i);
			return FALSE;
		}
	}

	// compare the multi-part decrypted block with the 'control' block
	//
	for (i = 0; i < orig_len; i++) {
		if (original[i] != decrypt1[i]) {
			printf
			    ("   ERROR:  decrypted mismatch: original != decrypt at byte %ld\n",
			     i);
			return FALSE;
		}
	}


	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc);
		return FALSE;
	}

	printf("Looks okay...\n");
	return TRUE;
}


//
//
int do_EncryptAES_Multipart_CBC_PAD(void)
{
	CK_BYTE original[BIG_REQUEST];

	CK_BYTE crypt1[BIG_REQUEST + AES_BLOCK_SIZE];	// account for padding
	CK_BYTE crypt2[BIG_REQUEST + AES_BLOCK_SIZE];	// account for padding

	CK_BYTE decrypt1[BIG_REQUEST + AES_BLOCK_SIZE];	// account for padding
	CK_BYTE decrypt2[BIG_REQUEST + AES_BLOCK_SIZE];	// account for padding


	CK_SLOT_ID slot_id;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mech;
	CK_OBJECT_HANDLE h_key;
	CK_FLAGS flags;
	CK_BYTE init_v[AES_BLOCK_SIZE];
	CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG user_pin_len;
	CK_ULONG i, k, key_size = AES_KEY_SIZE_256;
	CK_ULONG orig_len, crypt1_len, crypt2_len, decrypt1_len,
	    decrypt2_len;
	CK_RV rc;
	CK_ATTRIBUTE key_gen_tmpl[] = {
		{CKA_VALUE_LEN, &key_size, sizeof(CK_ULONG) }
	};

	printf("do_EncryptAES_Multipart_CBC_PAD...\n");

	slot_id = SlotID;
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &session);
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc);
		return FALSE;
	}


	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	rc = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
	if (rc != CKR_OK) {
		show_error("   C_Login #1", rc);
		return FALSE;
	}

	mech.mechanism = CKM_AES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;


	// first, generate an AES key
	//
	rc = funcs->C_GenerateKey(session, &mech, key_gen_tmpl, 1, &h_key);
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #1", rc);
		return FALSE;
	}

	// now, encrypt some data
	//
	orig_len = sizeof(original);

	for (i = 0; i < orig_len; i++) {
		original[i] = i % 255;
	}

	memcpy(init_v, "0123456789abcdef", 16);

	mech.mechanism = CKM_AES_CBC_PAD;
	mech.ulParameterLen = AES_BLOCK_SIZE;
	mech.pParameter = init_v;

	rc = funcs->C_EncryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #1", rc);
		return FALSE;
	}
	// use normal ecb mode to encrypt data1
	//
	crypt1_len = sizeof(crypt1);
	rc = funcs->C_Encrypt(session, original, orig_len, crypt1,
			      &crypt1_len);
	if (rc != CKR_OK) {
		show_error("   C_Encrypt #1", rc);
		return FALSE;
	}
	// use multipart cbc mode to encrypt data2 in chunks
	//
	rc = funcs->C_EncryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #2", rc);
		return FALSE;
	}

	i = k = 0;

	crypt2_len = sizeof(crypt2);

	while (i < orig_len) {
		CK_ULONG rem = orig_len - i;
		CK_ULONG chunk, len;

		if (rem < 100)
			chunk = rem;
		else
			chunk = 100;

		len = crypt2_len - k;
		rc = funcs->C_EncryptUpdate(session, &original[i], chunk,
					    &crypt2[k], &len);
		if (rc != CKR_OK) {
			show_error("   C_EncryptUpdate #1", rc);
			return FALSE;
		}

		k += len;
		i += chunk;
	}

	crypt2_len = sizeof(crypt2) - k;

	rc = funcs->C_EncryptFinal(session, &crypt2[k], &crypt2_len);
	if (rc != CKR_OK) {
		show_error("   C_EncryptFinal #2", rc);
		return FALSE;
	}

	crypt2_len += k;

	if (crypt2_len != crypt1_len) {
		printf("   ERROR:  encrypted lengths don't match\n");
		printf("           crypt2_len == %ld,  crypt1_len == %ld\n",
		       crypt2_len, crypt1_len);
		return FALSE;
	}
	// compare both encrypted blocks.  they'd better be equal
	//
	for (i = 0; i < crypt2_len; i++) {
		if (crypt1[i] != crypt2[i]) {
			printf
			    ("   ERROR:  encrypted mismatch: crypt1 != crypt2 at byte %ld\n",
			     i);
			return FALSE;
		}
	}



	// now, decrypt the data
	//
	rc = funcs->C_DecryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		show_error("   C_DecryptInit #1", rc);
		return FALSE;
	}

	decrypt1_len = sizeof(decrypt1);
	rc = funcs->C_Decrypt(session, crypt1, crypt1_len, decrypt1,
			      &decrypt1_len);
	if (rc != CKR_OK) {
		show_error("   C_Decrypt #1", rc);
		return FALSE;
	}
	// use multipart cbc mode to encrypt data2 in 1024 byte chunks
	//
	rc = funcs->C_DecryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		show_error("   C_DecryptInit #1", rc);
		return FALSE;
	}


	i = k = 0;

	decrypt2_len = sizeof(decrypt2);

	while (i < crypt2_len) {
		CK_ULONG rem = crypt2_len - i;
		CK_ULONG chunk, len;

		if (rem < 101)
			chunk = rem;
		else
			chunk = 101;

		len = decrypt2_len - k;
		rc = funcs->C_DecryptUpdate(session, &crypt2[i], chunk,
					    &decrypt2[k], &len);
		if (rc != CKR_OK) {
			show_error("   C_DecryptUpdate #1", rc);
			return FALSE;
		}

		k += len;
		i += chunk;
	}

	decrypt2_len = sizeof(decrypt2) - k;

	rc = funcs->C_DecryptFinal(session, &decrypt2[k], &decrypt2_len);
	if (rc != CKR_OK) {
		show_error("   C_DecryptFinal #2", rc);
		return FALSE;
	}

	decrypt2_len += k;

	if (decrypt2_len != decrypt1_len) {
		printf("   ERROR:  decrypted lengths don't match\n");
		printf
		    ("           decrypt1_len == %ld,  decrypt2_len == %ld\n",
		     decrypt1_len, decrypt2_len);
		return FALSE;
	}

	if (decrypt2_len != orig_len) {
		printf
		    ("   ERROR:  decrypted lengths don't match the original\n");
		printf("           decrypt_len == %ld,  orig_len == %ld\n",
		       decrypt1_len, orig_len);
		return FALSE;
	}

	// compare both decrypted blocks.  they'd better be equal
	//
	for (i = 0; i < decrypt1_len; i++) {
		if (decrypt1[i] != decrypt2[i]) {
			printf
			    ("   ERROR:  decrypted mismatch: data1 != data2 at byte %ld\n",
			     i);
			return FALSE;
		}
	}

	// compare the multi-part decrypted block with the 'control' block
	//
	for (i = 0; i < orig_len; i++) {
		if (original[i] != decrypt2[i]) {
			printf
			    ("   ERROR:  decrypted mismatch: original != decrypted at byte %ld\n",
			     i);
			return FALSE;
		}
	}


	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc);
		return FALSE;
	}

	printf("Looks okay...\n");
	return TRUE;
}


//
//
int do_WrapUnwrapAES_ECB(void)
{
	CK_BYTE data1[BIG_REQUEST];
	CK_BYTE data2[BIG_REQUEST];
#if 0
	CK_BYTE sanity[BIG_REQUEST];
#endif
	CK_BYTE wrapped_data[AES_BLOCK_SIZE];
	CK_SLOT_ID slot_id;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mech;
	CK_OBJECT_HANDLE h_key;
	CK_OBJECT_HANDLE w_key;
	CK_OBJECT_HANDLE uw_key;
	CK_FLAGS flags;
	CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG user_pin_len;
	CK_ULONG wrapped_data_len;
	CK_ULONG i, key_size = AES_KEY_SIZE_256;
	CK_ULONG len1, len2, sanity_len;
	CK_RV rc;
	CK_ATTRIBUTE key_gen_tmpl[] = {
		{CKA_VALUE_LEN, &key_size, sizeof(CK_ULONG) }
	};

	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE key_type = CKK_AES;
	CK_ULONG tmpl_count = 3;
	CK_ATTRIBUTE template[] = {
		{CKA_CLASS, &key_class, sizeof(key_class)},
		{CKA_KEY_TYPE, &key_type, sizeof(key_type)},
		{CKA_VALUE_LEN, &key_size, sizeof(key_size)}
	};


	printf("do_WrapUnwrapAES_ECB...\n");

	slot_id = SlotID;
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &session);
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc);
		return FALSE;
	}


	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	rc = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
	if (rc != CKR_OK) {
		show_error("   C_Login #1", rc);
		return FALSE;
	}

	mech.mechanism = CKM_AES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;


	// first, generate an AES key and a wrapping key
	//
	rc = funcs->C_GenerateKey(session, &mech, key_gen_tmpl, 1, &h_key);
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #1", rc);
		return FALSE;
	}

	rc = funcs->C_GenerateKey(session, &mech, key_gen_tmpl, 1, &w_key);
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #2", rc);
		return FALSE;
	}

	// now, encrypt some data
	//
	sanity_len = len1 = len2 = BIG_REQUEST;

	for (i = 0; i < len1; i++) {
		data1[i] = i % 255;
		data2[i] = i % 255;
	}

	mech.mechanism = CKM_AES_ECB;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;

	rc = funcs->C_EncryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #1", rc);
		return FALSE;
	}

	rc = funcs->C_Encrypt(session, data1, len1, data1, &len1);
	if (rc != CKR_OK) {
		show_error("   C_Encrypt #1", rc);
		return FALSE;
	}
#if 0
        rc = funcs->C_DecryptInit(session, &mech, h_key);
        printf("Sanity chec #1: Decrypting using original, unwrapped key.\n");

        if (rc != CKR_OK) {
                show_error("   C_DecryptInit #1", rc);
                return FALSE;
        }

        rc = funcs->C_Decrypt(session, data1, len1, sanity, &sanity_len);
        if (rc != CKR_OK) {
                show_error("   C_Decrypt #1", rc);
                return FALSE;
        }
	

       if (sanity_len != len2) {
                printf("   ERROR:  lengths don't match\n");
                return FALSE;
        }

        for (i = 0; i < len1; i++) {
                if (sanity[i] != data2[i]) {
                        printf(" Sanity Check #1 Failed. ERROR:  mismatch at byte %d\n", i);
                        return FALSE;
                }
        }

	printf("Sanity Check 1 PASSED\n");
#endif	
	// now, wrap the key.  we'll just use the same ECB mechanism
	//
	wrapped_data_len = AES_KEY_LEN;

	rc = funcs->C_WrapKey(session, &mech,
			      w_key, h_key,
			      (CK_BYTE *) & wrapped_data,
			      &wrapped_data_len);
	if (rc != CKR_OK) {
		show_error("   C_WrapKey #1", rc);
		return FALSE;
	}
#if 0
        rc = funcs->C_DecryptInit(session, &mech, h_key);
        printf("Sanity Check #2: Decrypting using original, unwrapped key after C_WrapKey.\n");

        if (rc != CKR_OK) {
                show_error("   C_DecryptInit #1", rc);
                return FALSE;
        }

        rc = funcs->C_Decrypt(session, data1, len1, sanity, &sanity_len);
        if (rc != CKR_OK) {
                show_error("   C_Decrypt #1", rc);
                return FALSE;
        }


       if (sanity_len != len2) {
                printf("   ERROR:  lengths don't match\n");
                return FALSE;
        }

        for (i = 0; i < len1; i++) {
                if (sanity[i] != data2[i]) {
                        printf(" Sanity Check #2 failed.  ERROR:  mismatch at byte %d\n", i);
                        return FALSE;
                }
        }

        printf("Sanity Check 2 PASSED\n");
#endif

	rc = funcs->C_UnwrapKey(session, &mech,
				w_key,
				wrapped_data, wrapped_data_len,
				template, tmpl_count, &uw_key);
	if (rc != CKR_OK) {
		show_error("   C_UnWrapKey #1", rc);
		return FALSE;
	}

	// now, decrypt the data using the unwrapped key.
	//
	rc = funcs->C_DecryptInit(session, &mech, uw_key);

	if (rc != CKR_OK) {
		show_error("   C_DecryptInit #1", rc);
		return FALSE;
	}

	rc = funcs->C_Decrypt(session, data1, len1, data1, &len1);
	if (rc != CKR_OK) {
		show_error("   C_Decrypt #1", rc);
		return FALSE;
	}

	if (len1 != len2) {
		printf("   ERROR:  lengths don't match\n");
		return FALSE;
	}

	for (i = 0; i < len1; i++) {
		if (data1[i] != data2[i]) {
			printf("line %d  ERROR:  mismatch at byte %ld\n", __LINE__, i);
			return FALSE;
		}
	}

	// now, try to wrap an RSA private key.  this should fail.  we'll
	// create a fake key object instead of generating a new one
	//
	{
		CK_OBJECT_CLASS keyclass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE keytype = CKK_RSA;

		CK_BYTE modulus[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
		CK_BYTE publ_exp[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
		CK_BYTE priv_exp[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
		CK_BYTE prime_1[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
		CK_BYTE prime_2[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
		CK_BYTE exp_1[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
		CK_BYTE exp_2[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
		CK_BYTE coeff[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };

		CK_ATTRIBUTE tmpl[] = {
			{CKA_CLASS, &keyclass, sizeof(keyclass)},
			{CKA_KEY_TYPE, &keytype, sizeof(keytype)},
			{CKA_MODULUS, modulus, sizeof(modulus)},
			{CKA_PUBLIC_EXPONENT, publ_exp, sizeof(publ_exp)},
			{CKA_PRIVATE_EXPONENT, priv_exp, sizeof(priv_exp)},
			{CKA_PRIME_1, prime_1, sizeof(prime_1)},
			{CKA_PRIME_2, prime_2, sizeof(prime_2)},
			{CKA_EXPONENT_1, exp_1, sizeof(exp_1)},
			{CKA_EXPONENT_2, exp_2, sizeof(exp_2)},
			{CKA_COEFFICIENT, coeff, sizeof(coeff)}
		};
		CK_OBJECT_HANDLE priv_key;
		CK_BYTE data[1024];
		CK_ULONG data_len = sizeof(data);


		rc = funcs->C_CreateObject(session, tmpl, 10, &priv_key);
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #1", rc);
			return FALSE;
		}

		rc = funcs->C_WrapKey(session, &mech,
				      w_key, priv_key, data, &data_len);
		if (rc != CKR_KEY_NOT_WRAPPABLE) {
			show_error("   C_WrapKey #2", rc);
			printf("   Expected CKR_KEY_NOT_WRAPPABLE\n");
			return FALSE;
		}
	}

	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc);
		return FALSE;
	}

	printf("Looks okay...\n");
	return TRUE;
}


//
//
int do_WrapUnwrapAES_CBC(void)
{
	CK_BYTE data1[BIG_REQUEST];
	CK_BYTE data2[BIG_REQUEST];
	CK_BYTE wrapped_data[AES_KEY_SIZE_256];
	CK_SLOT_ID slot_id;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mech;
	CK_OBJECT_HANDLE h_key;
	CK_OBJECT_HANDLE w_key;
	CK_OBJECT_HANDLE uw_key;
	CK_FLAGS flags;
	CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
	CK_BYTE init_v[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 'a', 'b', 'c', 'd', 'e', 'f' };
	CK_ULONG user_pin_len;
	CK_ULONG wrapped_data_len;
	CK_ULONG i, key_size = AES_KEY_SIZE_256;
	CK_ULONG len1 = BIG_REQUEST, len2 = BIG_REQUEST;
	CK_RV rc;
	CK_ATTRIBUTE key_gen_tmpl[] = {
		{CKA_VALUE_LEN, &key_size, sizeof(CK_ULONG) }
	};

	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE key_type = CKK_AES;
	CK_ULONG tmpl_count = 3;
	CK_ATTRIBUTE template[] = {
		{CKA_CLASS, &key_class, sizeof(key_class)},
		{CKA_KEY_TYPE, &key_type, sizeof(key_type)},
		{CKA_VALUE_LEN, &key_size, sizeof(key_size)}
	};


	printf("do_WrapUnwrapAES_CBC...\n");

	slot_id = SlotID;
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &session);
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc);
		return FALSE;
	}


	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	rc = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
	if (rc != CKR_OK) {
		show_error("   C_Login #1", rc);
		return FALSE;
	}

	mech.mechanism = CKM_AES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;


	// first, generate an AES key and a wrapping key
	//
	rc = funcs->C_GenerateKey(session, &mech, key_gen_tmpl, 1, &h_key);
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #1", rc);
		return FALSE;
	}

	rc = funcs->C_GenerateKey(session, &mech, key_gen_tmpl, 1, &w_key);
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #2", rc);
		return FALSE;
	}

	// now, encrypt some data
	//
	for (i = 0; i < len1; i++) {
		data1[i] = i % 255;
		data2[i] = i % 255;
	}

	mech.mechanism = CKM_AES_CBC;
	mech.ulParameterLen = sizeof(init_v);
	mech.pParameter = init_v;

	rc = funcs->C_EncryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #1", rc);
		return FALSE;
	}

	rc = funcs->C_Encrypt(session, data1, len1, data1, &len1);
	if (rc != CKR_OK) {
		show_error("   C_Encrypt #1", rc);
		return FALSE;
	}

	// now, wrap the key.  we'll just use the same ECB mechanism
	//
	wrapped_data_len = AES_KEY_LEN;

	rc = funcs->C_WrapKey(session, &mech,
			      w_key, h_key,
			      (CK_BYTE *) & wrapped_data,
			      &wrapped_data_len);
	if (rc != CKR_OK) {
		show_error("   C_WrapKey #1", rc);
		return FALSE;
	}

	rc = funcs->C_UnwrapKey(session, &mech,
				w_key,
				wrapped_data, wrapped_data_len,
				template, tmpl_count, &uw_key);
	if (rc != CKR_OK) {
		show_error("   C_UnWrapKey #1", rc);
		return FALSE;
	}

	// now, decrypt the data using the unwrapped key.
	//
	rc = funcs->C_DecryptInit(session, &mech, uw_key);
	if (rc != CKR_OK) {
		show_error("   C_DecryptInit #1", rc);
		return FALSE;
	}

	rc = funcs->C_Decrypt(session, data1, len1, data1, &len1);
	if (rc != CKR_OK) {
		show_error("   C_Decrypt #1", rc);
		return FALSE;
	}

	if (len1 != len2) {
		printf("line %d  ERROR:  lengths don't match\n", __LINE__);
		return FALSE;
	}

	for (i = 0; i < len1; i++) {
		if (data1[i] != data2[i]) {
			printf("line %d  ERROR:  mismatch at byte %ld\n", __LINE__, i);
			return FALSE;
		}
	}

	// now, try to wrap an RSA private key.  this should fail.  we'll
	// create a fake key object instead of generating a new one
	//
	{
		CK_OBJECT_CLASS keyclass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE keytype = CKK_RSA;

		CK_BYTE modulus[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
		CK_BYTE publ_exp[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
		CK_BYTE priv_exp[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
		CK_BYTE prime_1[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
		CK_BYTE prime_2[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
		CK_BYTE exp_1[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
		CK_BYTE exp_2[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
		CK_BYTE coeff[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };

		CK_ATTRIBUTE tmpl[] = {
			{CKA_CLASS, &keyclass, sizeof(keyclass)},
			{CKA_KEY_TYPE, &keytype, sizeof(keytype)},
			{CKA_MODULUS, modulus, sizeof(modulus)},
			{CKA_PUBLIC_EXPONENT, publ_exp, sizeof(publ_exp)},
			{CKA_PRIVATE_EXPONENT, priv_exp, sizeof(priv_exp)},
			{CKA_PRIME_1, prime_1, sizeof(prime_1)},
			{CKA_PRIME_2, prime_2, sizeof(prime_2)},
			{CKA_EXPONENT_1, exp_1, sizeof(exp_1)},
			{CKA_EXPONENT_2, exp_2, sizeof(exp_2)},
			{CKA_COEFFICIENT, coeff, sizeof(coeff)}
		};
		CK_OBJECT_HANDLE priv_key;
		CK_BYTE data[1024];
		CK_ULONG data_len = sizeof(data);


		rc = funcs->C_CreateObject(session, tmpl, 10, &priv_key);
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #1", rc);
			return FALSE;
		}

		rc = funcs->C_WrapKey(session, &mech,
				      w_key, priv_key, data, &data_len);
		if (rc != CKR_KEY_NOT_WRAPPABLE) {
			show_error("   C_WrapKey #2", rc);
			printf("line %d  Expected CKR_KEY_NOT_WRAPPABLE\n", __LINE__);
			return FALSE;
		}
	}

	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc);
		return FALSE;
	}

	printf("Looks okay...\n");
	return TRUE;
}


//
//
int do_WrapUnwrapAES_CBC_PAD(void)
{
	CK_BYTE original[BIG_REQUEST];
	CK_BYTE cipher[BIG_REQUEST + AES_BLOCK_SIZE];
	CK_BYTE decipher[BIG_REQUEST + AES_BLOCK_SIZE];

	CK_BYTE wrapped_data[BIG_REQUEST + AES_BLOCK_SIZE];

	CK_SLOT_ID slot_id;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mech;
	CK_OBJECT_HANDLE h_key;
	CK_OBJECT_HANDLE w_key;
	CK_OBJECT_HANDLE uw_key;
	CK_FLAGS flags;
	CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
	CK_BYTE init_v[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 'a', 'b', 'c', 'd', 'e', 'f' };
	CK_ULONG user_pin_len;
	CK_ULONG wrapped_data_len;
	CK_ULONG i, key_size = AES_KEY_SIZE_256;
	CK_ULONG orig_len, cipher_len, decipher_len;
	CK_RV rc;
	CK_ATTRIBUTE key_gen_tmpl[] = {
		{CKA_VALUE_LEN, &key_size, sizeof(CK_ULONG) }
	};

	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE key_type = CKK_AES;
	CK_ULONG tmpl_count = 3;
	CK_ATTRIBUTE template[] = {
		{CKA_CLASS, &key_class, sizeof(key_class)},
		{CKA_KEY_TYPE, &key_type, sizeof(key_type)},
		{CKA_VALUE_LEN, &key_size, sizeof(key_size)}
	};


	printf("do_WrapUnwrapAES_CBC_PAD...\n");

	slot_id = SlotID;
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &session);
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc);
		return FALSE;
	}


	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	rc = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
	if (rc != CKR_OK) {
		show_error("   C_Login #1", rc);
		return FALSE;
	}

	mech.mechanism = CKM_AES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;


	// first, generate an AES key and a wrapping key
	//
	rc = funcs->C_GenerateKey(session, &mech, key_gen_tmpl, 1, &h_key);
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #1", rc);
		return FALSE;
	}

	rc = funcs->C_GenerateKey(session, &mech, key_gen_tmpl, 1, &w_key);
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #2", rc);
		return FALSE;
	}

	// now, encrypt some data
	//
	orig_len = sizeof(original);
	for (i = 0; i < orig_len; i++) {
		original[i] = i % 255;
	}

	mech.mechanism = CKM_AES_CBC_PAD;
	mech.ulParameterLen = sizeof(init_v);
	mech.pParameter = init_v;

	rc = funcs->C_EncryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #1", rc);
		return FALSE;
	}

	cipher_len = sizeof(cipher);
	rc = funcs->C_Encrypt(session, original, orig_len, cipher,
			      &cipher_len);
	if (rc != CKR_OK) {
		show_error("   C_Encrypt #1", rc);
		return FALSE;
	}

	// now, wrap the key.
	//
	wrapped_data_len = sizeof(wrapped_data);

	rc = funcs->C_WrapKey(session, &mech,
			      w_key, h_key,
			      wrapped_data, &wrapped_data_len);
	if (rc != CKR_OK) {
		show_error("   C_WrapKey #1", rc);
		return FALSE;
	}

	rc = funcs->C_UnwrapKey(session, &mech,
				w_key,
				wrapped_data, wrapped_data_len,
				template, tmpl_count, &uw_key);
	if (rc != CKR_OK) {
		show_error("   C_UnWrapKey #1", rc);
		return FALSE;
	}

	// now, decrypt the data using the unwrapped key.
	//
	rc = funcs->C_DecryptInit(session, &mech, uw_key);
	if (rc != CKR_OK) {
		show_error("   C_DecryptInit #1", rc);
		return FALSE;
	}

	decipher_len = sizeof(decipher);
	rc = funcs->C_Decrypt(session, cipher, cipher_len, decipher,
			      &decipher_len);
	if (rc != CKR_OK) {
		show_error("   C_Decrypt #1", rc);
		return FALSE;
	}

	if (orig_len != decipher_len) {
		printf("   ERROR:  lengths don't match:  %ld vs %ld\n",
		       orig_len, decipher_len);
		return FALSE;
	}

	for (i = 0; i < orig_len; i++) {
		if (original[i] != decipher[i]) {
			printf("   ERROR:  mismatch at byte %ld\n", i);
			return FALSE;
		}
	}

	// we'll generate an RSA keypair here so we can make sure it works
	//
	{
		CK_MECHANISM mech2;
		CK_OBJECT_HANDLE publ_key, priv_key;

		CK_ULONG bits = 1024;
		CK_BYTE pub_exp[] = { 0x3 };

		CK_ATTRIBUTE pub_tmpl[] = {
			{CKA_MODULUS_BITS, &bits, sizeof(bits)}
			,
			{CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp)}
		};

		CK_OBJECT_CLASS keyclass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE keytype = CKK_RSA;
		CK_ATTRIBUTE uw_tmpl[] = {
			{CKA_CLASS, &keyclass, sizeof(keyclass)}
			,
			{CKA_KEY_TYPE, &keytype, sizeof(keytype)}
		};

		mech2.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
		mech2.ulParameterLen = 0;
		mech2.pParameter = NULL;

		rc = funcs->C_GenerateKeyPair(session, &mech2,
					      pub_tmpl, 2,
					      NULL, 0,
					      &publ_key, &priv_key);
		if (rc != CKR_OK) {
			show_error("   C_GenerateKeyPair #1", rc);
			return FALSE;
		}

		// now, wrap the key.
		//
		wrapped_data_len = sizeof(wrapped_data);

		rc = funcs->C_WrapKey(session, &mech,
				      w_key, priv_key,
				      wrapped_data, &wrapped_data_len);
		if (rc != CKR_OK) {
			show_error("   C_WrapKey #2", rc);
			return FALSE;
		}

		rc = funcs->C_UnwrapKey(session, &mech,
					w_key,
					wrapped_data, wrapped_data_len,
					uw_tmpl, 2, &uw_key);
		if (rc != CKR_OK) {
			show_error("   C_UnWrapKey #2", rc);
			return FALSE;
		}
		// encrypt something with the public key
		//
		mech2.mechanism = CKM_RSA_PKCS;
		mech2.ulParameterLen = 0;
		mech2.pParameter = NULL;

		rc = funcs->C_EncryptInit(session, &mech2, publ_key);
		if (rc != CKR_OK) {
			show_error("   C_EncryptInit #2", rc);
			return FALSE;
		}
		// for RSA operations, keep the input data size smaller than
		// the modulus
		//
		orig_len = 30;

		cipher_len = sizeof(cipher);
		rc = funcs->C_Encrypt(session, original, orig_len, cipher,
				      &cipher_len);
		if (rc != CKR_OK) {
			show_error("   C_Encrypt #2", rc);
			return FALSE;
		}
		// now, decrypt the data using the unwrapped private key.
		//
		rc = funcs->C_DecryptInit(session, &mech2, uw_key);
		if (rc != CKR_OK) {
			show_error("   C_DecryptInit #1", rc);
			return FALSE;
		}

		decipher_len = sizeof(decipher);
		rc = funcs->C_Decrypt(session, cipher, cipher_len,
				      decipher, &decipher_len);
		if (rc != CKR_OK) {
			show_error("   C_Decrypt #1", rc);
			return FALSE;
		}

		if (orig_len != decipher_len) {
			printf
			    ("   ERROR:  lengths don't match:  %ld vs %ld\n",
			     orig_len, decipher_len);
			return FALSE;
		}

		for (i = 0; i < orig_len; i++) {
			if (original[i] != decipher[i]) {
				printf("   ERROR:  mismatch at byte %ld\n",
				       i);
				return FALSE;
			}
		}
	}

	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc);
		return FALSE;
	}

	printf("Looks okay...\n");
	return TRUE;
}

int main(int argc, char **argv)
{
	int			i;
	CK_C_INITIALIZE_ARGS	initialize_args;
	CK_RV			rc;
	SYSTEMTIME		t1, t2;

	/* Parse the command line */
	for (i = 1; i < argc; i++) {
		if (strncmp(argv[i], "-slot", 5) == 0) {
			SlotID = (unsigned long)atoi(argv[i + 1]);
			i++;
			break;
		}
	}

	printf("Using slot %ld...\n\n", SlotID);

	if (do_GetFunctionList())
		return -1;

	/* There will be no multi-threaded Cryptoki access in this app */
	memset(&initialize_args, 0, sizeof(initialize_args));

	if ((rc = funcs->C_Initialize(&initialize_args)) != CKR_OK) {
		show_error("C_Initialize", rc);
		return -1;
	}


	GetSystemTime(&t1);
	rc = do_EncryptAES_ECB();
	if (!rc)
		goto done;
	GetSystemTime(&t2);
	process_time(t1, t2);

	GetSystemTime(&t1);
	rc = do_EncryptAES_CBC();
	if (!rc)
		goto done;
	GetSystemTime(&t2);
	process_time(t1, t2);

	GetSystemTime(&t1);
	rc = do_EncryptAES_Multipart_ECB();
	if (!rc)
		goto done;
	GetSystemTime(&t2);
	process_time(t1, t2);

	GetSystemTime(&t1);
	rc = do_EncryptAES_Multipart_CBC();
	if (!rc)
		goto done;
	GetSystemTime(&t2);
	process_time(t1, t2);

	GetSystemTime(&t1);
	rc = do_EncryptAES_Multipart_CBC_PAD();
	if (!rc)
		goto done;
	GetSystemTime(&t2);
	process_time(t1, t2);

	GetSystemTime(&t1);
	rc = do_WrapUnwrapAES_ECB();
	if (!rc)
		goto done;
	GetSystemTime(&t2);
	process_time(t1, t2);

	GetSystemTime(&t1);
	rc = do_WrapUnwrapAES_CBC();
	if (!rc)
		goto done;
	GetSystemTime(&t2);
	process_time(t1, t2);

	GetSystemTime(&t1);
	rc = do_WrapUnwrapAES_CBC_PAD();
	if (!rc)
		goto done;
	GetSystemTime(&t2);
	process_time(t1, t2);

done:
        if( (rc = funcs->C_Finalize(NULL)) != CKR_OK)
                show_error("C_Finalize", rc);

        /* Decrement the reference count to libopencryptoki.so */
        dlclose(dl_handle);


	return rc;
}


