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

void oc_err_msg(char *, int, char *, CK_RV);

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
	CK_BYTE user_pin[8];
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
		OC_ERR_MSG("   C_OpenSession #1", rc);
		return FALSE;
	}


	memcpy(user_pin, "12345678", 8);
	user_pin_len = 8;

	rc = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_Login #1", rc);
		return FALSE;
	}

	mech.mechanism = CKM_AES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;


	// first, generate an AES key
	//
	rc = funcs->C_GenerateKey(session, &mech, key_gen_tmpl, 1, &h_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_GenerateKey #1", rc);
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
		OC_ERR_MSG("   C_EncryptInit #1", rc);
		return FALSE;
	}

	rc = funcs->C_Encrypt(session, data1, len1, data1, &len1);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_Encrypt #1", rc);
		return FALSE;
	}
	// now, decrypt the data
	//
	rc = funcs->C_DecryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_DecryptInit #1", rc);
		return FALSE;
	}

	rc = funcs->C_Decrypt(session, data1, len1, data1, &len1);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_Decrypt #1", rc);
		return FALSE;
	}

	if (len1 != len2) {
		printf("   ERROR:  lengths don't match\n");
		return FALSE;
	}

	for (i = 0; i < len1; i++) {
		if (data1[i] != data2[i]) {
			printf("   ERROR:  mismatch at byte %d\n", i);
			return FALSE;
		}
	}

	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_CloseAllSessions #1", rc);
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
	CK_BYTE user_pin[8];
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
		OC_ERR_MSG("   C_OpenSession #1", rc);
		return FALSE;
	}


	memcpy(user_pin, "12345678", 8);
	user_pin_len = 8;

	rc = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_Login #1", rc);
		return FALSE;
	}

	mech.mechanism = CKM_AES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;


	// first, generate an AES key
	//
	rc = funcs->C_GenerateKey(session, &mech, key_gen_tmpl, 1, &h_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_GenerateKey #1", rc);
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
		OC_ERR_MSG("   C_EncryptInit #1", rc);
		return FALSE;
	}
	// use normal ecb mode to encrypt data1
	//
	crypt1_len = sizeof(crypt1);
	rc = funcs->C_Encrypt(session, original, orig_len, crypt1,
			      &crypt1_len);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_Encrypt #1", rc);
		return FALSE;
	}
	// use multipart ecb mode to encrypt data2 in 5 byte chunks
	//
	rc = funcs->C_EncryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_EncryptInit #2", rc);
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
			OC_ERR_MSG("   C_EncryptUpdate #1", rc);
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
		OC_ERR_MSG("   C_EncryptFinal #2", rc);
		return FALSE;
	}

	if (tmp != 0) {
		printf
		    ("   ERROR:  DecryptFinal wants to return %d bytes\n",
		     tmp);
		return FALSE;
	}

	if (crypt2_len != crypt1_len) {
		printf("   ERROR:  crypt1_len = %d, crypt2_len = %d\n",
		       crypt1_len, crypt2_len);
		return FALSE;
	}

	// compare both encrypted blocks.  they'd better be equal
	//
	for (i = 0; i < crypt1_len; i++) {
		if (crypt1[i] != crypt2[i]) {
			printf
			    ("   ERROR:  mismatch.  crypt1 != crypt2 at byte %d\n",
			     i);
			return FALSE;
		}
	}

	// now, decrypt the data
	//
	rc = funcs->C_DecryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_DecryptInit #1", rc);
		return FALSE;
	}

	decrypt1_len = sizeof(decrypt1);
	rc = funcs->C_Decrypt(session, crypt1, crypt1_len, decrypt1,
			      &decrypt1_len);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_Decrypt #1", rc);
		return FALSE;
	}
	// use multipart ecb mode to encrypt data2 in 1024 byte chunks
	//
	rc = funcs->C_DecryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_DecryptInit #1", rc);
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
			OC_ERR_MSG("   C_DecryptUpdate #1", rc);
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
		OC_ERR_MSG("   C_DecryptFinal #2", rc);
		return FALSE;
	}

	if (tmp != 0) {
		printf
		    ("   ERROR:  DecryptFinal wants to return %d bytes\n",
		     tmp);
		return FALSE;
	}

	if (decrypt1_len != decrypt2_len) {
		printf("   ERROR:  decrypt1_len = %d, decrypt2_len = %d\n",
		       decrypt1_len, decrypt2_len);
		return FALSE;
	}

	if (decrypt1_len != orig_len) {
		printf
		    ("   ERROR:  decrypted lengths = %d, original length = %d\n",
		     decrypt1_len, orig_len);
		return FALSE;
	}
	// compare both decrypted blocks.  they'd better be equal
	//
	for (i = 0; i < decrypt1_len; i++) {
		if (decrypt1[i] != decrypt2[i]) {
			printf
			    ("   ERROR:  mismatch.  decrypt1 != decrypt2 at byte %d\n",
			     i);
			return FALSE;
		}
	}

	// compare the multi-part decrypted block with the 'control' block
	//
	for (i = 0; i < orig_len; i++) {
		if (original[i] != decrypt1[i]) {
			printf
			    ("   ERROR:  decrypted mismatch: original != decrypt at byte %d\n",
			     i);
			return FALSE;
		}
	}


	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_CloseAllSessions #1", rc);
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
	CK_BYTE user_pin[8];
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
		OC_ERR_MSG("   C_OpenSession #1", rc);
		return FALSE;
	}


	memcpy(user_pin, "12345678", 8);
	user_pin_len = 8;

	rc = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_Login #1", rc);
		return FALSE;
	}


	mech.mechanism = CKM_AES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;


	// first, generate an AES key
	//
	rc = funcs->C_GenerateKey(session, &mech, key_gen_tmpl, 1, &h_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_GenerateKey #1", rc);
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
		OC_ERR_MSG("   C_EncryptInit #1", rc);
		return FALSE;
	}

	rc = funcs->C_Encrypt(session, data1, len1, data1, &len1);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_Encrypt #1", rc);
		return FALSE;
	}
	// now, decrypt the data
	//
	rc = funcs->C_DecryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_DecryptInit #1", rc);
		return FALSE;
	}

	rc = funcs->C_Decrypt(session, data1, len1, data1, &len1);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_Decrypt #1", rc);
		return FALSE;
	}

	if (len1 != len2) {
		printf("   ERROR:  lengths don't match\n");
		return FALSE;
	}

	for (i = 0; i < len1; i++) {
		if (data1[i] != data2[i]) {
			printf("   ERROR:  mismatch at byte %d\n", i);
			return FALSE;
		}
	}

	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_CloseAllSessions #1", rc);
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
	CK_BYTE user_pin[8];
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
		OC_ERR_MSG("   C_OpenSession #1", rc);
		return FALSE;
	}


	memcpy(user_pin, "12345678", 8);
	user_pin_len = 8;

	rc = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_Login #1", rc);
		return FALSE;
	}

	mech.mechanism = CKM_AES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;


	// first, generate an AES key
	//
	rc = funcs->C_GenerateKey(session, &mech, key_gen_tmpl, 1, &h_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_GenerateKey #1", rc);
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
		OC_ERR_MSG("   C_EncryptInit #1", rc);
		return FALSE;
	}
	// use normal ecb mode to encrypt data1
	//
	crypt1_len = sizeof(crypt1);
	rc = funcs->C_Encrypt(session, original, orig_len, crypt1,
			      &crypt1_len);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_Encrypt #1", rc);
		return FALSE;
	}
	// use multipart cbc mode to encrypt data2 in 1024 byte chunks
	//
	rc = funcs->C_EncryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_EncryptInit #2", rc);
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
			OC_ERR_MSG("   C_EncryptUpdate #1", rc);
			return FALSE;
		}

		k += tmp;
		i += chunk;
	}

	crypt2_len = k;

	rc = funcs->C_EncryptFinal(session, NULL, &tmp);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_EncryptFinal #2", rc);
		return FALSE;
	}

	if (tmp != 0) {
		printf
		    ("   ERROR:  EncryptFinal wants to return %d bytes\n",
		     tmp);
		return FALSE;
	}


	if (crypt2_len != crypt1_len) {
		printf("   ERROR:  crypt1_len = %d, crypt2_len = %d\n",
		       crypt1_len, crypt2_len);
		return FALSE;
	}
	// compare both encrypted blocks.  they'd better be equal
	//
	for (i = 0; i < crypt1_len; i++) {
		if (crypt1[i] != crypt2[i]) {
			printf
			    ("   ERROR:  mismatch.  crypt1 != crypt2 at byte %d\n",
			     i);
			return FALSE;
		}
	}



	// now, decrypt the data
	//
	rc = funcs->C_DecryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_DecryptInit #1", rc);
		return FALSE;
	}

	decrypt1_len = sizeof(decrypt1);
	rc = funcs->C_Decrypt(session, crypt1, crypt1_len, decrypt1,
			      &decrypt1_len);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_Decrypt #1", rc);
		return FALSE;
	}
	// use multipart cbc mode to encrypt data2 in 1024 byte chunks
	//
	rc = funcs->C_DecryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_DecryptInit #1", rc);
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
			OC_ERR_MSG("   C_DecryptUpdate #1", rc);
			return FALSE;
		}

		k += tmp;
		i += chunk;
	}

	decrypt2_len = k;

	rc = funcs->C_DecryptFinal(session, NULL, &tmp);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_DecryptFinal #2", rc);
		return FALSE;
	}

	if (tmp != 0) {
		printf
		    ("   ERROR:  DecryptFinal wants to return %d bytes\n",
		     tmp);
		return FALSE;
	}

	if (decrypt2_len != decrypt1_len) {
		printf("   ERROR:  decrypt1_len = %d, decrypt2_len = %d\n",
		       decrypt1_len, decrypt2_len);
		return FALSE;
	}
	// compare both decrypted blocks.  they'd better be equal
	//
	for (i = 0; i < decrypt1_len; i++) {
		if (crypt1[i] != crypt2[i]) {
			printf
			    ("   ERROR:  mismatch.  decrypt1 != decrypt2 at byte %d\n",
			     i);
			return FALSE;
		}
	}

	// compare the multi-part decrypted block with the 'control' block
	//
	for (i = 0; i < orig_len; i++) {
		if (original[i] != decrypt1[i]) {
			printf
			    ("   ERROR:  decrypted mismatch: original != decrypt at byte %d\n",
			     i);
			return FALSE;
		}
	}


	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_CloseAllSessions #1", rc);
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
	CK_BYTE user_pin[8];
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
		OC_ERR_MSG("   C_OpenSession #1", rc);
		return FALSE;
	}


	memcpy(user_pin, "12345678", 8);
	user_pin_len = 8;

	rc = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_Login #1", rc);
		return FALSE;
	}

	mech.mechanism = CKM_AES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;


	// first, generate an AES key
	//
	rc = funcs->C_GenerateKey(session, &mech, key_gen_tmpl, 1, &h_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_GenerateKey #1", rc);
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
		OC_ERR_MSG("   C_EncryptInit #1", rc);
		return FALSE;
	}
	// use normal ecb mode to encrypt data1
	//
	crypt1_len = sizeof(crypt1);
	rc = funcs->C_Encrypt(session, original, orig_len, crypt1,
			      &crypt1_len);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_Encrypt #1", rc);
		return FALSE;
	}
	// use multipart cbc mode to encrypt data2 in chunks
	//
	rc = funcs->C_EncryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_EncryptInit #2", rc);
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
			OC_ERR_MSG("   C_EncryptUpdate #1", rc);
			return FALSE;
		}

		k += len;
		i += chunk;
	}

	crypt2_len = sizeof(crypt2) - k;

	rc = funcs->C_EncryptFinal(session, &crypt2[k], &crypt2_len);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_EncryptFinal #2", rc);
		return FALSE;
	}

	crypt2_len += k;

	if (crypt2_len != crypt1_len) {
		printf("   ERROR:  encrypted lengths don't match\n");
		printf("           crypt2_len == %d,  crypt1_len == %d\n",
		       crypt2_len, crypt1_len);
		return FALSE;
	}
	// compare both encrypted blocks.  they'd better be equal
	//
	for (i = 0; i < crypt2_len; i++) {
		if (crypt1[i] != crypt2[i]) {
			printf
			    ("   ERROR:  encrypted mismatch: crypt1 != crypt2 at byte %d\n",
			     i);
			return FALSE;
		}
	}



	// now, decrypt the data
	//
	rc = funcs->C_DecryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_DecryptInit #1", rc);
		return FALSE;
	}

	decrypt1_len = sizeof(decrypt1);
	rc = funcs->C_Decrypt(session, crypt1, crypt1_len, decrypt1,
			      &decrypt1_len);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_Decrypt #1", rc);
		return FALSE;
	}
	// use multipart cbc mode to encrypt data2 in 1024 byte chunks
	//
	rc = funcs->C_DecryptInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_DecryptInit #1", rc);
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
			OC_ERR_MSG("   C_DecryptUpdate #1", rc);
			return FALSE;
		}

		k += len;
		i += chunk;
	}

	decrypt2_len = sizeof(decrypt2) - k;

	rc = funcs->C_DecryptFinal(session, &decrypt2[k], &decrypt2_len);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_DecryptFinal #2", rc);
		return FALSE;
	}

	decrypt2_len += k;

	if (decrypt2_len != decrypt1_len) {
		printf("   ERROR:  decrypted lengths don't match\n");
		printf
		    ("           decrypt1_len == %d,  decrypt2_len == %d\n",
		     decrypt1_len, decrypt2_len);
		return FALSE;
	}

	if (decrypt2_len != orig_len) {
		printf
		    ("   ERROR:  decrypted lengths don't match the original\n");
		printf("           decrypt_len == %d,  orig_len == %d\n",
		       decrypt1_len, orig_len);
		return FALSE;
	}

	// compare both decrypted blocks.  they'd better be equal
	//
	for (i = 0; i < decrypt1_len; i++) {
		if (decrypt1[i] != decrypt2[i]) {
			printf
			    ("   ERROR:  decrypted mismatch: data1 != data2 at byte %d\n",
			     i);
			return FALSE;
		}
	}

	// compare the multi-part decrypted block with the 'control' block
	//
	for (i = 0; i < orig_len; i++) {
		if (original[i] != decrypt2[i]) {
			printf
			    ("   ERROR:  decrypted mismatch: original != decrypted at byte %d\n",
			     i);
			return FALSE;
		}
	}


	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_CloseAllSessions #1", rc);
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
	CK_BYTE sanity[BIG_REQUEST];
	CK_BYTE wrapped_data[AES_BLOCK_SIZE];
	CK_SLOT_ID slot_id;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mech;
	CK_OBJECT_HANDLE h_key;
	CK_OBJECT_HANDLE w_key;
	CK_OBJECT_HANDLE uw_key;
	CK_FLAGS flags;
	CK_BYTE user_pin[8];
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
		OC_ERR_MSG("   C_OpenSession #1", rc);
		return FALSE;
	}


	memcpy(user_pin, "12345678", 8);
	user_pin_len = 8;

	rc = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_Login #1", rc);
		return FALSE;
	}

	mech.mechanism = CKM_AES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;


	// first, generate an AES key and a wrapping key
	//
	rc = funcs->C_GenerateKey(session, &mech, key_gen_tmpl, 1, &h_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_GenerateKey #1", rc);
		return FALSE;
	}

	rc = funcs->C_GenerateKey(session, &mech, key_gen_tmpl, 1, &w_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_GenerateKey #2", rc);
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
		OC_ERR_MSG("   C_EncryptInit #1", rc);
		return FALSE;
	}

	rc = funcs->C_Encrypt(session, data1, len1, data1, &len1);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_Encrypt #1", rc);
		return FALSE;
	}
#if 0
        rc = funcs->C_DecryptInit(session, &mech, h_key);
        printf("Sanity chec #1: Decrypting using original, unwrapped key.\n");

        if (rc != CKR_OK) {
                OC_ERR_MSG("   C_DecryptInit #1", rc);
                return FALSE;
        }

        rc = funcs->C_Decrypt(session, data1, len1, sanity, &sanity_len);
        if (rc != CKR_OK) {
                OC_ERR_MSG("   C_Decrypt #1", rc);
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
		OC_ERR_MSG("   C_WrapKey #1", rc);
		return FALSE;
	}
#if 0
        rc = funcs->C_DecryptInit(session, &mech, h_key);
        printf("Sanity Check #2: Decrypting using original, unwrapped key after C_WrapKey.\n");

        if (rc != CKR_OK) {
                OC_ERR_MSG("   C_DecryptInit #1", rc);
                return FALSE;
        }

        rc = funcs->C_Decrypt(session, data1, len1, sanity, &sanity_len);
        if (rc != CKR_OK) {
                OC_ERR_MSG("   C_Decrypt #1", rc);
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
		OC_ERR_MSG("   C_UnWrapKey #1", rc);
		return FALSE;
	}

	// now, decrypt the data using the unwrapped key.
	//
	rc = funcs->C_DecryptInit(session, &mech, uw_key);

	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_DecryptInit #1", rc);
		return FALSE;
	}

	rc = funcs->C_Decrypt(session, data1, len1, data1, &len1);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_Decrypt #1", rc);
		return FALSE;
	}

	if (len1 != len2) {
		printf("   ERROR:  lengths don't match\n");
		return FALSE;
	}

	for (i = 0; i < len1; i++) {
		if (data1[i] != data2[i]) {
			printf("line %d  ERROR:  mismatch at byte %d\n", __LINE__, i);
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
			OC_ERR_MSG("   C_CreateObject #1", rc);
			return FALSE;
		}

		rc = funcs->C_WrapKey(session, &mech,
				      w_key, priv_key, data, &data_len);
		if (rc != CKR_KEY_NOT_WRAPPABLE) {
			OC_ERR_MSG("   C_WrapKey #2", rc);
			printf("   Expected CKR_KEY_NOT_WRAPPABLE\n");
			return FALSE;
		}
	}

	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_CloseAllSessions #1", rc);
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
	CK_BYTE user_pin[8];
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
		OC_ERR_MSG("   C_OpenSession #1", rc);
		return FALSE;
	}


	memcpy(user_pin, "12345678", 8);
	user_pin_len = 8;

	rc = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_Login #1", rc);
		return FALSE;
	}

	mech.mechanism = CKM_AES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;


	// first, generate an AES key and a wrapping key
	//
	rc = funcs->C_GenerateKey(session, &mech, key_gen_tmpl, 1, &h_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_GenerateKey #1", rc);
		return FALSE;
	}

	rc = funcs->C_GenerateKey(session, &mech, key_gen_tmpl, 1, &w_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_GenerateKey #2", rc);
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
		OC_ERR_MSG("   C_EncryptInit #1", rc);
		return FALSE;
	}

	rc = funcs->C_Encrypt(session, data1, len1, data1, &len1);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_Encrypt #1", rc);
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
		OC_ERR_MSG("   C_WrapKey #1", rc);
		return FALSE;
	}

	rc = funcs->C_UnwrapKey(session, &mech,
				w_key,
				wrapped_data, wrapped_data_len,
				template, tmpl_count, &uw_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_UnWrapKey #1", rc);
		return FALSE;
	}

	// now, decrypt the data using the unwrapped key.
	//
	rc = funcs->C_DecryptInit(session, &mech, uw_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_DecryptInit #1", rc);
		return FALSE;
	}

	rc = funcs->C_Decrypt(session, data1, len1, data1, &len1);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_Decrypt #1", rc);
		return FALSE;
	}

	if (len1 != len2) {
		printf("line %d  ERROR:  lengths don't match\n", __LINE__);
		return FALSE;
	}

	for (i = 0; i < len1; i++) {
		if (data1[i] != data2[i]) {
			printf("line %d  ERROR:  mismatch at byte %d\n", __LINE__, i);
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
			OC_ERR_MSG("   C_CreateObject #1", rc);
			return FALSE;
		}

		rc = funcs->C_WrapKey(session, &mech,
				      w_key, priv_key, data, &data_len);
		if (rc != CKR_KEY_NOT_WRAPPABLE) {
			OC_ERR_MSG("   C_WrapKey #2", rc);
			printf("line %d  Expected CKR_KEY_NOT_WRAPPABLE\n", __LINE__);
			return FALSE;
		}
	}

	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_CloseAllSessions #1", rc);
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
	CK_BYTE user_pin[8];
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
		OC_ERR_MSG("   C_OpenSession #1", rc);
		return FALSE;
	}


	memcpy(user_pin, "12345678", 8);
	user_pin_len = 8;

	rc = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_Login #1", rc);
		return FALSE;
	}

	mech.mechanism = CKM_AES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;


	// first, generate an AES key and a wrapping key
	//
	rc = funcs->C_GenerateKey(session, &mech, key_gen_tmpl, 1, &h_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_GenerateKey #1", rc);
		return FALSE;
	}

	rc = funcs->C_GenerateKey(session, &mech, key_gen_tmpl, 1, &w_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_GenerateKey #2", rc);
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
		OC_ERR_MSG("   C_EncryptInit #1", rc);
		return FALSE;
	}

	cipher_len = sizeof(cipher);
	rc = funcs->C_Encrypt(session, original, orig_len, cipher,
			      &cipher_len);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_Encrypt #1", rc);
		return FALSE;
	}

	// now, wrap the key.
	//
	wrapped_data_len = sizeof(wrapped_data);

	rc = funcs->C_WrapKey(session, &mech,
			      w_key, h_key,
			      wrapped_data, &wrapped_data_len);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_WrapKey #1", rc);
		return FALSE;
	}

	rc = funcs->C_UnwrapKey(session, &mech,
				w_key,
				wrapped_data, wrapped_data_len,
				template, tmpl_count, &uw_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_UnWrapKey #1", rc);
		return FALSE;
	}

	// now, decrypt the data using the unwrapped key.
	//
	rc = funcs->C_DecryptInit(session, &mech, uw_key);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_DecryptInit #1", rc);
		return FALSE;
	}

	decipher_len = sizeof(decipher);
	rc = funcs->C_Decrypt(session, cipher, cipher_len, decipher,
			      &decipher_len);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_Decrypt #1", rc);
		return FALSE;
	}

	if (orig_len != decipher_len) {
		printf("   ERROR:  lengths don't match:  %d vs %d\n",
		       orig_len, decipher_len);
		return FALSE;
	}

	for (i = 0; i < orig_len; i++) {
		if (original[i] != decipher[i]) {
			printf("   ERROR:  mismatch at byte %d\n", i);
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
			OC_ERR_MSG("   C_GenerateKeyPair #1", rc);
			return FALSE;
		}

		// now, wrap the key.
		//
		wrapped_data_len = sizeof(wrapped_data);

		rc = funcs->C_WrapKey(session, &mech,
				      w_key, priv_key,
				      wrapped_data, &wrapped_data_len);
		if (rc != CKR_OK) {
			OC_ERR_MSG("   C_WrapKey #2", rc);
			return FALSE;
		}

		rc = funcs->C_UnwrapKey(session, &mech,
					w_key,
					wrapped_data, wrapped_data_len,
					uw_tmpl, 2, &uw_key);
		if (rc != CKR_OK) {
			OC_ERR_MSG("   C_UnWrapKey #2", rc);
			return FALSE;
		}
		// encrypt something with the public key
		//
		mech2.mechanism = CKM_RSA_PKCS;
		mech2.ulParameterLen = 0;
		mech2.pParameter = NULL;

		rc = funcs->C_EncryptInit(session, &mech2, publ_key);
		if (rc != CKR_OK) {
			OC_ERR_MSG("   C_EncryptInit #2", rc);
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
			OC_ERR_MSG("   C_Encrypt #2", rc);
			return FALSE;
		}
		// now, decrypt the data using the unwrapped private key.
		//
		rc = funcs->C_DecryptInit(session, &mech2, uw_key);
		if (rc != CKR_OK) {
			OC_ERR_MSG("   C_DecryptInit #1", rc);
			return FALSE;
		}

		decipher_len = sizeof(decipher);
		rc = funcs->C_Decrypt(session, cipher, cipher_len,
				      decipher, &decipher_len);
		if (rc != CKR_OK) {
			OC_ERR_MSG("   C_Decrypt #1", rc);
			return FALSE;
		}

		if (orig_len != decipher_len) {
			printf
			    ("   ERROR:  lengths don't match:  %d vs %d\n",
			     orig_len, decipher_len);
			return FALSE;
		}

		for (i = 0; i < orig_len; i++) {
			if (original[i] != decipher[i]) {
				printf("   ERROR:  mismatch at byte %d\n",
				       i);
				return FALSE;
			}
		}
	}

	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		OC_ERR_MSG("   C_CloseAllSessions #1", rc);
		return FALSE;
	}

	printf("Looks okay...\n");
	return TRUE;
}

int do_GetFunctionList(void)
{
        char *pkcslib = "PKCS11_API.so";
        CK_RV (*func_ptr)();
        int rc;

        if( (dl_handle = dlopen(pkcslib, RTLD_NOW)) == NULL) {
                printf("dlopen: %s\n", dlerror());
                return -1;
        }

        func_ptr = (CK_RV (*)())dlsym(dl_handle, "C_GetFunctionList");

        if(func_ptr == NULL)
                return -1;

        if( (rc = func_ptr(&funcs)) != CKR_OK) {
                OC_ERR_MSG("C_GetFunctionList", rc);
                return -1;
        }

        return 0;
}

void process_time(SYSTEMTIME t1, SYSTEMTIME t2)
{
   long ms   = t2.millitm - t1.millitm;
   long s    = t2.time - t1.time;

   while (ms < 0) {
      ms += 1000;
      s--;
   }

   ms += (s*1000);



   printf("Time:  %u msec\n", ms );

}

void process_ret_code( CK_RV rc )
{
        switch (rc) {
         case CKR_OK:printf(" CKR_OK");break;
         case CKR_CANCEL:                           printf(" CKR_CANCEL");                           break;
         case CKR_HOST_MEMORY:                      printf(" CKR_HOST_MEMORY");                      break;
         case CKR_SLOT_ID_INVALID:                  printf(" CKR_SLOT_ID_INVALID");                  break;
         case CKR_GENERAL_ERROR:                    printf(" CKR_GENERAL_ERROR");                    break;
         case CKR_FUNCTION_FAILED:                  printf(" CKR_FUNCTION_FAILED");                  break;
         case CKR_ARGUMENTS_BAD:                    printf(" CKR_ARGUMENTS_BAD");                    break;
         case CKR_NO_EVENT:                         printf(" CKR_NO_EVENT");                         break;
         case CKR_NEED_TO_CREATE_THREADS:           printf(" CKR_NEED_TO_CREATE_THREADS");           break;
         case CKR_CANT_LOCK:                        printf(" CKR_CANT_LOCK");                        break;
         case CKR_ATTRIBUTE_READ_ONLY:              printf(" CKR_ATTRIBUTE_READ_ONLY");              break;
         case CKR_ATTRIBUTE_SENSITIVE:              printf(" CKR_ATTRIBUTE_SENSITIVE");              break;
         case CKR_ATTRIBUTE_TYPE_INVALID:           printf(" CKR_ATTRIBUTE_TYPE_INVALID");           break;
         case CKR_ATTRIBUTE_VALUE_INVALID:          printf(" CKR_ATTRIBUTE_VALUE_INVALID");          break;
         case CKR_DATA_INVALID:                     printf(" CKR_DATA_INVALID");                     break;
         case CKR_DATA_LEN_RANGE:                   printf(" CKR_DATA_LEN_RANGE");                   break;
         case CKR_DEVICE_ERROR:                     printf(" CKR_DEVICE_ERROR");                     break;
         case CKR_DEVICE_MEMORY:                    printf(" CKR_DEVICE_MEMORY");                    break;
         case CKR_DEVICE_REMOVED:                   printf(" CKR_DEVICE_REMOVED");                   break;
         case CKR_ENCRYPTED_DATA_INVALID:           printf(" CKR_ENCRYPTED_DATA_INVALID");           break;
         case CKR_ENCRYPTED_DATA_LEN_RANGE:         printf(" CKR_ENCRYPTED_DATA_LEN_RANGE");         break;
         case CKR_FUNCTION_CANCELED:                printf(" CKR_FUNCTION_CANCELED");                break;
         case CKR_FUNCTION_NOT_PARALLEL:            printf(" CKR_FUNCTION_NOT_PARALLEL");            break;
         case CKR_FUNCTION_NOT_SUPPORTED:           printf(" CKR_FUNCTION_NOT_SUPPORTED");           break;
         case CKR_KEY_HANDLE_INVALID:               printf(" CKR_KEY_HANDLE_INVALID");               break;
         case CKR_KEY_SIZE_RANGE:                   printf(" CKR_KEY_SIZE_RANGE");                   break;
         case CKR_KEY_TYPE_INCONSISTENT:            printf(" CKR_KEY_TYPE_INCONSISTENT");            break;
         case CKR_KEY_NOT_NEEDED:                   printf(" CKR_KEY_NOT_NEEDED");                   break;
         case CKR_KEY_CHANGED:                      printf(" CKR_KEY_CHANGED");                      break;
         case CKR_KEY_NEEDED:                       printf(" CKR_KEY_NEEDED");                       break;
         case CKR_KEY_INDIGESTIBLE:                 printf(" CKR_KEY_INDIGESTIBLE");                 break;
         case CKR_KEY_FUNCTION_NOT_PERMITTED:       printf(" CKR_KEY_FUNCTION_NOT_PERMITTED");       break;
         case CKR_KEY_NOT_WRAPPABLE:                printf(" CKR_KEY_NOT_WRAPPABLE");                break;
         case CKR_KEY_UNEXTRACTABLE:                printf(" CKR_KEY_UNEXTRACTABLE");                break;
         case CKR_MECHANISM_INVALID:                printf(" CKR_MECHANISM_INVALID");                break;
         case CKR_MECHANISM_PARAM_INVALID:          printf(" CKR_MECHANISM_PARAM_INVALID");          break;
         case CKR_OBJECT_HANDLE_INVALID:            printf(" CKR_OBJECT_HANDLE_INVALID");            break;
         case CKR_OPERATION_ACTIVE:                 printf(" CKR_OPERATION_ACTIVE");                 break;
         case CKR_OPERATION_NOT_INITIALIZED:        printf(" CKR_OPERATION_NOT_INITIALIZED");        break;
         case CKR_PIN_INCORRECT:                    printf(" CKR_PIN_INCORRECT");                    break;
         case CKR_PIN_INVALID:                      printf(" CKR_PIN_INVALID");                      break;
         case CKR_PIN_LEN_RANGE:                    printf(" CKR_PIN_LEN_RANGE");                    break;
         case CKR_PIN_EXPIRED:                      printf(" CKR_PIN_EXPIRED");                      break;
         case CKR_PIN_LOCKED:                       printf(" CKR_PIN_LOCKED");                       break;
         case CKR_SESSION_CLOSED:                   printf(" CKR_SESSION_CLOSED");                   break;
         case CKR_SESSION_COUNT:                    printf(" CKR_SESSION_COUNT");                    break;
         case CKR_SESSION_HANDLE_INVALID:           printf(" CKR_SESSION_HANDLE_INVALID");           break;
         case CKR_SESSION_PARALLEL_NOT_SUPPORTED:   printf(" CKR_SESSION_PARALLEL_NOT_SUPPORTED");   break;
         case CKR_SESSION_READ_ONLY:                printf(" CKR_SESSION_READ_ONLY");                break;
         case CKR_SESSION_EXISTS:                   printf(" CKR_SESSION_EXISTS");                   break;
         case CKR_SESSION_READ_ONLY_EXISTS:         printf(" CKR_SESSION_READ_ONLY_EXISTS");         break;
         case CKR_SESSION_READ_WRITE_SO_EXISTS:     printf(" CKR_SESSION_READ_WRITE_SO_EXISTS");     break;
         case CKR_SIGNATURE_INVALID:                printf(" CKR_SIGNATURE_INVALID");                break;
         case CKR_SIGNATURE_LEN_RANGE:              printf(" CKR_SIGNATURE_LEN_RANGE");              break;
         case CKR_TEMPLATE_INCOMPLETE:              printf(" CKR_TEMPLATE_INCOMPLETE");              break;
         case CKR_TEMPLATE_INCONSISTENT:            printf(" CKR_TEMPLATE_INCONSISTENT");            break;
         case CKR_TOKEN_NOT_PRESENT:                printf(" CKR_TOKEN_NOT_PRESENT");                break;
        case CKR_TOKEN_NOT_RECOGNIZED:             printf(" CKR_TOKEN_NOT_RECOGNIZED");             break;
        case CKR_TOKEN_WRITE_PROTECTED:            printf(" CKR_TOKEN_WRITE_PROTECTED");            break;
        case CKR_UNWRAPPING_KEY_HANDLE_INVALID:    printf(" CKR_UNWRAPPING_KEY_HANDLE_INVALID");    break;
        case CKR_UNWRAPPING_KEY_SIZE_RANGE:        printf(" CKR_UNWRAPPING_KEY_SIZE_RANGE");        break;
        case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: printf(" CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT"); break;
        case CKR_USER_ALREADY_LOGGED_IN:           printf(" CKR_USER_ALREADY_LOGGED_IN");           break;
        case CKR_USER_NOT_LOGGED_IN:               printf(" CKR_USER_NOT_LOGGED_IN");               break;
        case CKR_USER_PIN_NOT_INITIALIZED:         printf(" CKR_USER_PIN_NOT_INITIALIZED");         break;
        case CKR_USER_TYPE_INVALID:                printf(" CKR_USER_TYPE_INVALID");                break;
        case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:   printf(" CKR_USER_ANOTHER_ALREADY_LOGGED_IN");   break;
        case CKR_USER_TOO_MANY_TYPES:              printf(" CKR_USER_TOO_MANY_TYPES");              break;
        case CKR_WRAPPED_KEY_INVALID:              printf(" CKR_WRAPPED_KEY_INVALID");              break;
        case CKR_WRAPPED_KEY_LEN_RANGE:            printf(" CKR_WRAPPED_KEY_LEN_RANGE");            break;
        case CKR_WRAPPING_KEY_HANDLE_INVALID:      printf(" CKR_WRAPPING_KEY_HANDLE_INVALID");      break;
        case CKR_WRAPPING_KEY_SIZE_RANGE:          printf(" CKR_WRAPPING_KEY_SIZE_RANGE");          break;
        case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:   printf(" CKR_WRAPPING_KEY_TYPE_INCONSISTENT");   break;
        case CKR_RANDOM_SEED_NOT_SUPPORTED:        printf(" CKR_RANDOM_SEED_NOT_SUPPORTED");        break;
        case CKR_RANDOM_NO_RNG:                    printf(" CKR_RANDOM_NO_RNG");                    break;
        case CKR_BUFFER_TOO_SMALL:                 printf(" CKR_BUFFER_TOO_SMALL");                 break;
        case CKR_SAVED_STATE_INVALID:              printf(" CKR_SAVED_STATE_INVALID");              break;
        case CKR_INFORMATION_SENSITIVE:            printf(" CKR_INFORMATION_SENSITIVE");            break;
        case CKR_STATE_UNSAVEABLE:                 printf(" CKR_STATE_UNSAVEABLE");                 break;
        case CKR_CRYPTOKI_NOT_INITIALIZED:         printf(" CKR_CRYPTOKI_NOT_INITIALIZED");         break;
        case CKR_CRYPTOKI_ALREADY_INITIALIZED:     printf(" CKR_CRYPTOKI_ALREADY_INITIALIZED");     break;
        case CKR_MUTEX_BAD:                        printf(" CKR_MUTEX_BAD");break;
        case CKR_MUTEX_NOT_LOCKED:    printf(" CKR_MUTEX_NOT_LOCKED");break;
        }
}


void oc_err_msg( char *file, int line, char *str, CK_RV rc )
{
        printf("%s line %d Error: %s returned:  %d ", file, line, str, rc );
        process_ret_code( rc );
        printf("\n\n");
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

	printf("Using slot %u...\n\n", SlotID);

	if (do_GetFunctionList())
		return -1;

	/* There will be no multi-threaded Cryptoki access in this app */
	memset(&initialize_args, 0, sizeof(initialize_args));

	if ((rc = funcs->C_Initialize(&initialize_args)) != CKR_OK) {
		OC_ERR_MSG("C_Initialize", rc);
		return;
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
                OC_ERR_MSG("C_Finalize", rc);

        /* Decrement the reference count to PKCS11_API.so */
        dlclose(dl_handle);


	return rc;
}


