// File: des3_func.c
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"

//
//
CK_RV do_Encrypt3DES_ECB( void )
{
	CK_BYTE             data1[BIG_REQUEST];
	CK_BYTE             data2[BIG_REQUEST];
	CK_SLOT_ID          slot_id;
	CK_SESSION_HANDLE   session;
	CK_MECHANISM        mech;
	CK_OBJECT_HANDLE    h_key;
	CK_FLAGS            flags;
	CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG            user_pin_len;
	CK_ULONG            i;
	CK_ULONG            len1, len2;
	CK_RV               rc, loc_rc;

	printf("do_Encrypt3DES_ECB...\n");

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

	mech.mechanism      = CKM_DES3_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;


	// first, generate a DES key
	//
	rc = funcs->C_GenerateKey( session, &mech, NULL, 0, &h_key );
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #1", rc );
		goto error;
	}


	// now, encrypt some data
	//
	len1 = len2 = BIG_REQUEST;

	for (i=0; i < len1; i++) {
		data1[i] = i % 255;
		data2[i] = i % 255;
	}

	mech.mechanism      = CKM_DES3_ECB;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;

	rc = funcs->C_EncryptInit( session, &mech, h_key );
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #1", rc );
		goto error;
	}

	rc = funcs->C_Encrypt( session, data1, len1, data1, &len1 );
	if (rc != CKR_OK) {
		show_error("   C_Encrypt #1", rc );
		goto error;
	}

	// now, decrypt the data
	//
	rc = funcs->C_DecryptInit( session, &mech, h_key );
	if (rc != CKR_OK) {
		show_error("   C_DecryptInit #1", rc );
		goto error;
	}

	rc = funcs->C_Decrypt( session, data1, len1, data1, &len1 );
	if (rc != CKR_OK) {
		show_error("   C_Decrypt #1", rc );
		goto error;
	}

	if (len1 != len2) {
		PRINT_ERR("   ERROR:  lengths don't match\n");
		goto error;
	}

	for (i=0; i <len1; i++) {
		if (data1[i] != data2[i]) {
			PRINT_ERR("   ERROR:  mismatch at byte %ld\n", i );
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


//
//
CK_RV do_Encrypt3DES_Multipart_ECB( void )
{
	CK_BYTE             original[BIG_REQUEST];
	CK_BYTE             crypt1  [BIG_REQUEST];
	CK_BYTE             crypt2  [BIG_REQUEST];
	CK_BYTE             decrypt1[BIG_REQUEST];
	CK_BYTE             decrypt2[BIG_REQUEST];

	CK_SLOT_ID          slot_id;
	CK_SESSION_HANDLE   session;
	CK_MECHANISM        mech;
	CK_OBJECT_HANDLE    h_key;
	CK_FLAGS            flags;
	CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG            user_pin_len;
	CK_ULONG            i, k;
	CK_ULONG            orig_len;
	CK_ULONG            crypt1_len, crypt2_len, decrypt1_len, decrypt2_len;
	CK_ULONG            tmp;
	CK_RV               rc, loc_rc;

	printf("do_Encrypt3DES_Multipart_ECB...\n");

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

	mech.mechanism      = CKM_DES3_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;


	// first, generate a DES key
	//
	rc = funcs->C_GenerateKey( session, &mech, NULL, 0, &h_key );
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #1", rc );
		goto error;
	}


	// now, encrypt some data
	//
	orig_len    = sizeof(original);
	for (i=0; i < orig_len; i++) {
		original[i] = i % 255;
	}

	mech.mechanism      = CKM_DES3_ECB;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;

	rc = funcs->C_EncryptInit( session, &mech, h_key );
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #1", rc );
		goto error;
	}

	// use normal ecb mode to encrypt data1
	//
	crypt1_len = sizeof(crypt1);
	rc = funcs->C_Encrypt( session, original, orig_len, crypt1, &crypt1_len );
	if (rc != CKR_OK) {
		show_error("   C_Encrypt #1", rc );
		goto error;
	}

	// use multipart ecb mode to encrypt data2 in 5 byte chunks
	//
	rc = funcs->C_EncryptInit( session, &mech, h_key );
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #2", rc );
		goto error;
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

		tmp = crypt2_len - k;  // how much room is left in crypt2?

		rc = funcs->C_EncryptUpdate( session, &original[i],  chunk,
				&crypt2[k],   &tmp );
		if (rc != CKR_OK) {
			show_error("   C_EncryptUpdate #1", rc );
			goto error;
		}

		k += tmp;
		i += chunk;
	}

	crypt2_len = k;

	// DES-ECB shouldn't return anything for EncryptFinal per the spec
	//
	rc = funcs->C_EncryptFinal( session, NULL, &tmp );
	if (rc != CKR_OK) {
		show_error("   C_EncryptFinal #2", rc );
		goto error;
	}

	if (tmp != 0) {
		PRINT_ERR("   ERROR:  DecryptFinal wants to return %ld bytes\n", tmp );
		goto error;
	}

	if (crypt2_len != crypt1_len) {
		PRINT_ERR("   ERROR:  crypt1_len = %ld, crypt2_len = %ld\n", crypt1_len, crypt2_len );
		goto error;
	}


	// compare both encrypted blocks.  they'd better be equal
	//
	for (i=0; i < crypt1_len; i++) {
		if (crypt1[i] != crypt2[i]) {
			PRINT_ERR("   ERROR:  mismatch.  crypt1 != crypt2 at byte %ld\n", i );
			goto error;
		}
	}

	// now, decrypt the data
	//
	rc = funcs->C_DecryptInit( session, &mech, h_key );
	if (rc != CKR_OK) {
		show_error("   C_DecryptInit #1", rc );
		goto error;
	}

	decrypt1_len = sizeof(decrypt1);
	rc = funcs->C_Decrypt( session, crypt1, crypt1_len, decrypt1, &decrypt1_len );
	if (rc != CKR_OK) {
		show_error("   C_Decrypt #1", rc );
		goto error;
	}

	// use multipart ecb mode to encrypt data2 in 1024 byte chunks
	//
	rc = funcs->C_DecryptInit( session, &mech, h_key );
	if (rc != CKR_OK) {
		show_error("   C_DecryptInit #1", rc );
		goto error;
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

		rc = funcs->C_DecryptUpdate( session, &crypt1[i],    chunk,
				&decrypt2[k], &tmp );
		if (rc != CKR_OK) {
			show_error("   C_DecryptUpdate #1", rc );
			goto error;
		}

		k += tmp;
		i += chunk;
	}

	decrypt2_len = k;

	// DES-ECB shouldn't return anything for EncryptFinal per the spec
	//
	rc = funcs->C_DecryptFinal( session, NULL, &tmp );
	if (rc != CKR_OK) {
		show_error("   C_DecryptFinal #2", rc );
		goto error;
	}

	if (tmp != 0) {
		PRINT_ERR("   ERROR:  DecryptFinal wants to return %ld bytes\n", tmp );
		goto error;
	}

	if (decrypt1_len != decrypt2_len) {
		PRINT_ERR("   ERROR:  decrypt1_len = %ld, decrypt2_len = %ld\n", decrypt1_len, decrypt2_len );
		goto error;
	}

	if (decrypt1_len != orig_len) {
		PRINT_ERR("   ERROR:  decrypted lengths = %ld, original length = %ld\n", decrypt1_len, orig_len );
		goto error;
	}

	// compare both decrypted blocks.  they'd better be equal
	//
	for (i=0; i < decrypt1_len; i++) {
		if (decrypt1[i] != decrypt2[i]) {
			PRINT_ERR("   ERROR:  mismatch.  decrypt1 != decrypt2 at byte %ld\n", i );
			goto error;
		}
	}

	// compare the multi-part decrypted block with the 'control' block
	//
	for (i=0; i < orig_len; i++) {
		if (original[i] != decrypt1[i]) {
			PRINT_ERR("   ERROR:  decrypted mismatch: original != decrypt at byte %ld\n", i );
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


//
//
CK_RV do_Encrypt3DES_CBC( void )
{
	CK_BYTE             data1[BIG_REQUEST];
	CK_BYTE             data2[BIG_REQUEST];
	CK_SLOT_ID          slot_id;
	CK_SESSION_HANDLE   session;
	CK_MECHANISM        mech;
	CK_OBJECT_HANDLE    h_key;
	CK_FLAGS            flags;
	CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG            user_pin_len;
	CK_BYTE             init_v[8];
	CK_ULONG            i;
	CK_ULONG            len1, len2;
	CK_RV               rc;

	printf("do_Encrypt3DES_CBC...\n");

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
		return rc;
	}


	mech.mechanism      = CKM_DES3_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;


	// first, generate a DES key
	//
	rc = funcs->C_GenerateKey( session, &mech, NULL, 0, &h_key );
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #1", rc );
		return rc;
	}


	// now, encrypt some data
	//
	len1 = len2 = BIG_REQUEST;

	for (i=0; i < len1; i++) {
		data1[i] = i % 255;
		data2[i] = i % 255;
	}

	memcpy( init_v, "asdfqwer", 8 );

	mech.mechanism      = CKM_DES3_CBC;
	mech.ulParameterLen = 8;
	mech.pParameter     = init_v;

	rc = funcs->C_EncryptInit( session, &mech, h_key );
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #1", rc );
		return rc;
	}

	rc = funcs->C_Encrypt( session, data1, len1, data1, &len1 );
	if (rc != CKR_OK) {
		show_error("   C_Encrypt #1", rc );
		return rc;
	}

	// now, decrypt the data
	//
	rc = funcs->C_DecryptInit( session, &mech, h_key );
	if (rc != CKR_OK) {
		show_error("   C_DecryptInit #1", rc );
		return rc;
	}

	rc = funcs->C_Decrypt( session, data1, len1, data1, &len1 );
	if (rc != CKR_OK) {
		show_error("   C_Decrypt #1", rc );
		return rc;
	}

	if (len1 != len2) {
		PRINT_ERR("   ERROR:  lengths don't match\n");
		return -1;
	}

	for (i=0; i <len1; i++) {
		if (data1[i] != data2[i]) {
			PRINT_ERR("   ERROR:  mismatch at byte %ld\n", i );
			return -1;
		}
	}

	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc );
		return rc;
	}

	printf("Success.\n");
	return 0;
}


//
//
CK_RV do_Encrypt3DES_Multipart_CBC( void )
{
	CK_BYTE             original[BIG_REQUEST];
	CK_BYTE             crypt1  [BIG_REQUEST];
	CK_BYTE             crypt2  [BIG_REQUEST];
	CK_BYTE             decrypt1[BIG_REQUEST];
	CK_BYTE             decrypt2[BIG_REQUEST];

	CK_SLOT_ID          slot_id;
	CK_SESSION_HANDLE   session;
	CK_MECHANISM        mech;
	CK_OBJECT_HANDLE    h_key;
	CK_FLAGS            flags;
	CK_BYTE             init_v[8];
	CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG            user_pin_len;
	CK_ULONG            i, k;
	CK_ULONG            orig_len;
	CK_ULONG            crypt1_len, crypt2_len, decrypt1_len, decrypt2_len;
	CK_ULONG            tmp;
	CK_RV               rc;

	printf("do_Encrypt3DES_Multipart_CBC...\n");

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
		return rc;
	}

	mech.mechanism      = CKM_DES3_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;


	// first, generate a DES key
	//
	rc = funcs->C_GenerateKey( session, &mech, NULL, 0, &h_key );
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #1", rc );
		return rc;
	}


	// now, encrypt some data
	//
	orig_len = sizeof(original);
	for (i=0; i < orig_len; i++) {
		original[i] = i % 255;
	}

	memcpy( init_v, "asdfqwer" , 8 );

	mech.mechanism      = CKM_DES3_CBC;
	mech.ulParameterLen = 8;
	mech.pParameter     = init_v;

	rc = funcs->C_EncryptInit( session, &mech, h_key );
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #1", rc );
		return rc;
	}

	// use normal ecb mode to encrypt data1
	//
	crypt1_len = sizeof(crypt1);
	rc = funcs->C_Encrypt( session, original, orig_len, crypt1, &crypt1_len );
	if (rc != CKR_OK) {
		show_error("   C_Encrypt #1", rc );
		return rc;
	}

	// use multipart cbc mode to encrypt data2 in 1024 byte chunks
	//
	rc = funcs->C_EncryptInit( session, &mech, h_key );
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #2", rc );
		return rc;
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

		tmp = crypt2_len - k;  // how much room is left in crypt2?

		rc = funcs->C_EncryptUpdate( session, &original[i],  chunk,
				&crypt2[k],   &tmp );
		if (rc != CKR_OK) {
			show_error("   C_EncryptUpdate #1", rc );
			return rc;
		}

		k += tmp;
		i += chunk;
	}

	crypt2_len = k;

	rc = funcs->C_EncryptFinal( session, NULL, &tmp );
	if (rc != CKR_OK) {
		show_error("   C_EncryptFinal #2", rc );
		return rc;
	}

	if (tmp != 0) {
		PRINT_ERR("   ERROR:  EncryptFinal wants to return %ld bytes\n", tmp );
		return -1;
	}


	if (crypt2_len != crypt1_len) {
		PRINT_ERR("   ERROR:  crypt1_len = %ld, crypt2_len = %ld\n", crypt1_len, crypt2_len );
		return -1;
	}

	// compare both encrypted blocks.  they'd better be equal
	//
	for (i=0; i < crypt1_len; i++) {
		if (crypt1[i] != crypt2[i]) {
			PRINT_ERR("   ERROR:  mismatch.  crypt1 != crypt2 at byte %ld\n", i );
			return -1;
		}
	}



	// now, decrypt the data
	//
	rc = funcs->C_DecryptInit( session, &mech, h_key );
	if (rc != CKR_OK) {
		show_error("   C_DecryptInit #1", rc );
		return rc;
	}

	decrypt1_len = sizeof(decrypt1);
	rc = funcs->C_Decrypt( session, crypt1, crypt1_len, decrypt1, &decrypt1_len );
	if (rc != CKR_OK) {
		show_error("   C_Decrypt #1", rc );
		return rc;
	}

	// use multipart cbc mode to encrypt data2 in 1024 byte chunks
	//
	rc = funcs->C_DecryptInit( session, &mech, h_key );
	if (rc != CKR_OK) {
		show_error("   C_DecryptInit #1", rc );
		return rc;
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

		rc = funcs->C_DecryptUpdate( session, &crypt1[i],    chunk,
				&decrypt2[k], &tmp );
		if (rc != CKR_OK) {
			show_error("   C_DecryptUpdate #1", rc );
			return rc;
		}

		k += tmp;
		i += chunk;
	}

	decrypt2_len = k;

	rc = funcs->C_DecryptFinal( session, NULL, &tmp );
	if (rc != CKR_OK) {
		show_error("   C_DecryptFinal #2", rc );
		return rc;
	}

	if (tmp != 0) {
		PRINT_ERR("   ERROR:  DecryptFinal wants to return %ld bytes\n", tmp );
		return -1;
	}

	if (decrypt2_len != decrypt1_len) {
		PRINT_ERR("   ERROR:  decrypt1_len = %ld, decrypt2_len = %ld\n", decrypt1_len, decrypt2_len );
		return -1;
	}

	// compare both decrypted blocks.  they'd better be equal
	//
	for (i=0; i < decrypt1_len; i++) {
		if (crypt1[i] != crypt2[i]) {
			PRINT_ERR("   ERROR:  mismatch.  decrypt1 != decrypt2 at byte %ld\n", i );
			return -1;
		}
	}

	// compare the multi-part decrypted block with the 'control' block
	//
	for (i=0; i < orig_len; i++) {
		if (original[i] != decrypt1[i]) {
			PRINT_ERR("   ERROR:  decrypted mismatch: original != decrypt at byte %ld\n", i );
			return -1;
		}
	}


	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc );
		return rc;
	}

	printf("Success.\n");
	return 0;
}


//
//
CK_RV do_EncryptDES3_Multipart_CBC_PAD( void )
{
	CK_BYTE             original[BIG_REQUEST];

	CK_BYTE             crypt1[BIG_REQUEST + 8];  // account for padding
	CK_BYTE             crypt2[BIG_REQUEST + 8];  // account for padding

	CK_BYTE             decrypt1[BIG_REQUEST + 8];  // account for padding
	CK_BYTE             decrypt2[BIG_REQUEST + 8];  // account for padding


	CK_SLOT_ID          slot_id;
	CK_SESSION_HANDLE   session;
	CK_MECHANISM        mech;
	CK_OBJECT_HANDLE    h_key;
	CK_FLAGS            flags;
	CK_BYTE             init_v[8];
	CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG            user_pin_len;
	CK_ULONG            i, k;
	CK_ULONG            orig_len, crypt1_len, crypt2_len, decrypt1_len, decrypt2_len;
	CK_RV               rc;

	printf("do_EncryptDES3_Multipart_CBC_PAD...\n");

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
		return rc;
	}

	mech.mechanism      = CKM_DES3_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;


	// first, generate a DES key
	//
	rc = funcs->C_GenerateKey( session, &mech, NULL, 0, &h_key );
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #1", rc );
		return rc;
	}


	// now, encrypt some data
	//
	orig_len = sizeof(original);

	for (i=0; i < orig_len; i++) {
		original[i] = i % 255;
	}

	memcpy( init_v, "asdfqwer", 8 );

	mech.mechanism      = CKM_DES3_CBC_PAD;
	mech.ulParameterLen = 8;
	mech.pParameter     = init_v;

	rc = funcs->C_EncryptInit( session, &mech, h_key );
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #1", rc );
		return rc;
	}

	// use normal ecb mode to encrypt data1
	//
	crypt1_len = sizeof(crypt1);
	rc = funcs->C_Encrypt( session, original, orig_len, crypt1, &crypt1_len );
	if (rc != CKR_OK) {
		show_error("   C_Encrypt #1", rc );
		return rc;
	}

	// use multipart cbc mode to encrypt data2 in chunks
	//
	rc = funcs->C_EncryptInit( session, &mech, h_key );
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #2", rc );
		return rc;
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
		rc = funcs->C_EncryptUpdate( session, &original[i],  chunk,
				&crypt2[k],    &len );
		if (rc != CKR_OK) {
			show_error("   C_EncryptUpdate #1", rc );
			return rc;
		}

		k += len;
		i += chunk;
	}

	crypt2_len = sizeof(crypt2) - k;

	rc = funcs->C_EncryptFinal( session, &crypt2[k], &crypt2_len );
	if (rc != CKR_OK) {
		show_error("   C_EncryptFinal #2", rc );
		return rc;
	}

	crypt2_len += k;

	if (crypt2_len != crypt1_len) {
		PRINT_ERR("   ERROR:  encrypted lengths don't match\n");
		PRINT_ERR("           crypt2_len == %ld,  crypt1_len == %ld\n", crypt2_len, crypt1_len );
		return -1;
	}

	// compare both encrypted blocks.  they'd better be equal
	//
	for (i=0; i < crypt2_len; i++) {
		if (crypt1[i] != crypt2[i]) {
			PRINT_ERR("   ERROR:  encrypted mismatch: crypt1 != crypt2 at byte %ld\n", i );
			return -1;
		}
	}



	// now, decrypt the data
	//
	rc = funcs->C_DecryptInit( session, &mech, h_key );
	if (rc != CKR_OK) {
		show_error("   C_DecryptInit #1", rc );
		return rc;
	}

	decrypt1_len = sizeof(decrypt1);
	rc = funcs->C_Decrypt( session, crypt1, crypt1_len, decrypt1, &decrypt1_len );
	if (rc != CKR_OK) {
		show_error("   C_Decrypt #1", rc );
		return rc;
	}

	// use multipart cbc mode to encrypt data2 in 1024 byte chunks
	//
	rc = funcs->C_DecryptInit( session, &mech, h_key );
	if (rc != CKR_OK) {
		show_error("   C_DecryptInit #1", rc );
		return rc;
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
		rc = funcs->C_DecryptUpdate( session, &crypt2[i],   chunk,
				&decrypt2[k], &len );
		if (rc != CKR_OK) {
			show_error("   C_DecryptUpdate #1", rc );
			return rc;
		}

		k += len;
		i += chunk;
	}

	decrypt2_len = sizeof(decrypt2) - k;

	rc = funcs->C_DecryptFinal( session, &decrypt2[k], &decrypt2_len );
	if (rc != CKR_OK) {
		show_error("   C_DecryptFinal #2", rc );
		return rc;
	}

	decrypt2_len += k;

	if (decrypt2_len != decrypt1_len) {
		PRINT_ERR("   ERROR:  decrypted lengths don't match\n");
		PRINT_ERR("           decrypt1_len == %ld,  decrypt2_len == %ld\n", decrypt1_len, decrypt2_len );
		return -1;
	}

	if (decrypt2_len != orig_len) {
		PRINT_ERR("   ERROR:  decrypted lengths don't match the original\n");
		PRINT_ERR("           decrypt_len == %ld,  orig_len == %ld\n", decrypt1_len, orig_len );
		return -1;
	}


	// compare both decrypted blocks.  they'd better be equal
	//
	for (i=0; i < decrypt1_len; i++) {
		if (decrypt1[i] != decrypt2[i]) {
			PRINT_ERR("   ERROR:  decrypted mismatch: data1 != data2 at byte %ld\n", i );
			return -1;
		}
	}

	// compare the multi-part decrypted block with the 'control' block
	//
	for (i=0; i < orig_len; i++) {
		if (original[i] != decrypt2[i]) {
			PRINT_ERR("   ERROR:  decrypted mismatch: original != decrypted at byte %ld\n", i );
			return -1;
		}
	}


	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc );
		return rc;
	}

	printf("Success.\n");
	return 0;
}


//
//
CK_RV do_WrapUnwrapDES3_ECB( void )
{
	CK_BYTE             data1[BIG_REQUEST];
	CK_BYTE             data2[BIG_REQUEST];
	CK_BYTE             wrapped_data[3 * DES_BLOCK_SIZE];
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
	CK_ULONG            len1, len2;
	CK_RV               rc, loc_rc;

	CK_OBJECT_CLASS     key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE         key_type  = CKK_DES3;
	CK_ULONG            tmpl_count = 2;
	CK_ATTRIBUTE   template[] =
	{
		{ CKA_CLASS,     &key_class,  sizeof(key_class) },
		{ CKA_KEY_TYPE,  &key_type,   sizeof(key_type)  }
	};


	printf("do_WrapUnwrapDES3_ECB...\n");

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

	mech.mechanism      = CKM_DES3_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;


	// first, generate a DES key and a wrapping key
	//
	rc = funcs->C_GenerateKey( session, &mech, NULL, 0, &h_key );
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #1", rc );
		goto error;
	}

	rc = funcs->C_GenerateKey( session, &mech, NULL, 0, &w_key );
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #2", rc );
		goto error;
	}


	// now, encrypt some data
	//
	len1 = len2 = BIG_REQUEST;

	for (i=0; i < len1; i++) {
		data1[i] = i % 255;
		data2[i] = i % 255;
	}

	mech.mechanism      = CKM_DES3_ECB;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;

	rc = funcs->C_EncryptInit( session, &mech, h_key );
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #1", rc );
		goto error;
	}

	rc = funcs->C_Encrypt( session, data1, len1, data1, &len1 );
	if (rc != CKR_OK) {
		show_error("   C_Encrypt #1", rc );
		goto error;
	}


	// now, wrap the key.  we'll just use the same ECB mechanism
	//
	wrapped_data_len = 3 * DES_KEY_LEN;

	rc = funcs->C_WrapKey( session,    &mech,
			w_key,      h_key,
			(CK_BYTE *)&wrapped_data, &wrapped_data_len );
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

	rc = funcs->C_Decrypt( session, data1, len1, data1, &len1 );
	if (rc != CKR_OK) {
		show_error("   C_Decrypt #1", rc );
		goto error;
	}

	if (len1 != len2) {
		PRINT_ERR("   ERROR:  lengths don't match\n");
		goto error;
	}

	for (i=0; i <len1; i++) {
		if (data1[i] != data2[i]) {
			PRINT_ERR("   ERROR:  mismatch at byte %ld\n", i );
			goto error;
		}
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


//
//
CK_RV do_WrapUnwrapDES3_CBC( void )
{
	CK_BYTE             data1[BIG_REQUEST];
	CK_BYTE             data2[BIG_REQUEST];
	CK_BYTE             wrapped_data[3 * DES_BLOCK_SIZE];
	CK_SLOT_ID          slot_id;
	CK_SESSION_HANDLE   session;
	CK_MECHANISM        mech;
	CK_OBJECT_HANDLE    h_key;
	CK_OBJECT_HANDLE    w_key;
	CK_OBJECT_HANDLE    uw_key;
	CK_FLAGS            flags;
	CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
	CK_BYTE             init_v[] = { 1,2,3,4,5,6,7,8 };
	CK_ULONG            user_pin_len;
	CK_ULONG            wrapped_data_len;
	CK_ULONG            i;
	CK_ULONG            len1, len2;
	CK_RV               rc;

	CK_OBJECT_CLASS     key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE         key_type  = CKK_DES3;
	CK_ULONG            tmpl_count = 2;
	CK_ATTRIBUTE   template[] =
	{
		{ CKA_CLASS,     &key_class,  sizeof(key_class) },
		{ CKA_KEY_TYPE,  &key_type,   sizeof(key_type)  }
	};


	printf("do_WrapUnwrapDES3_CBC...\n");

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
		return rc;
	}

	mech.mechanism      = CKM_DES3_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;


	// first, generate a DES key and a wrapping key
	//
	rc = funcs->C_GenerateKey( session, &mech, NULL, 0, &h_key );
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #1", rc );
		return rc;
	}

	rc = funcs->C_GenerateKey( session, &mech, NULL, 0, &w_key );
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #2", rc );
		return rc;
	}


	// now, encrypt some data
	//
	len1 = len2 = BIG_REQUEST;

	for (i=0; i < len1; i++) {
		data1[i] = i % 255;
		data2[i] = i % 255;
	}

	mech.mechanism      = CKM_DES3_CBC;
	mech.ulParameterLen = sizeof(init_v);
	mech.pParameter     = init_v;

	rc = funcs->C_EncryptInit( session, &mech, h_key );
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #1", rc );
		return rc;
	}

	rc = funcs->C_Encrypt( session, data1, len1, data1, &len1 );
	if (rc != CKR_OK) {
		show_error("   C_Encrypt #1", rc );
		return rc;
	}


	// now, wrap the key.  we'll just use the same ECB mechanism
	//
	wrapped_data_len = 3 * DES_KEY_LEN;

	rc = funcs->C_WrapKey( session,    &mech,
			w_key,      h_key,
			(CK_BYTE *)&wrapped_data, &wrapped_data_len );
	if (rc != CKR_OK) {
		show_error("   C_WrapKey #1", rc );
		return rc;
	}

	rc = funcs->C_UnwrapKey( session, &mech,
			w_key,
			wrapped_data, wrapped_data_len,
			template,  tmpl_count,
			&uw_key );
	if (rc != CKR_OK) {
		show_error("   C_UnWrapKey #1", rc );
		return rc;
	}


	// now, decrypt the data using the unwrapped key.
	//
	rc = funcs->C_DecryptInit( session, &mech, uw_key );
	if (rc != CKR_OK) {
		show_error("   C_DecryptInit #1", rc );
		return rc;
	}

	rc = funcs->C_Decrypt( session, data1, len1, data1, &len1 );
	if (rc != CKR_OK) {
		show_error("   C_Decrypt #1", rc );
		return rc;
	}

	if (len1 != len2) {
		PRINT_ERR("   ERROR:  lengths don't match\n");
		return -1;
	}

	for (i=0; i <len1; i++) {
		if (data1[i] != data2[i]) {
			PRINT_ERR("   ERROR:  mismatch at byte %ld\n", i );
			return -1;
		}
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
			return rc;
		}

		rc = funcs->C_WrapKey( session,  &mech,
				w_key,     priv_key,
				data,     &data_len );
		if (rc != CKR_KEY_NOT_WRAPPABLE) {
			show_error("   C_WrapKey #2", rc );
			PRINT_ERR("   Expected CKR_KEY_NOT_WRAPPABLE\n" );
			return rc;
		}
	}

	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc );
		return rc;
	}

	printf("Success.\n");
	return 0;
}


//
//
CK_RV do_WrapUnwrapDES3_CBC_PAD( void )
{
	CK_BYTE             original[BIG_REQUEST];
	CK_BYTE             cipher  [BIG_REQUEST + 8];
	CK_BYTE             decipher[BIG_REQUEST + 8];

	CK_BYTE             wrapped_data[BIG_REQUEST + 8];

	CK_SLOT_ID          slot_id;
	CK_SESSION_HANDLE   session;
	CK_MECHANISM        mech;
	CK_OBJECT_HANDLE    h_key;
	CK_OBJECT_HANDLE    w_key;
	CK_OBJECT_HANDLE    uw_key;
	CK_FLAGS            flags;
	CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
	CK_BYTE             init_v[] = { 1,2,3,4,5,6,7,8 };
	CK_ULONG            user_pin_len;
	CK_ULONG            wrapped_data_len;
	CK_ULONG            i;
	CK_ULONG            orig_len, cipher_len, decipher_len;
	CK_RV               rc;

	CK_OBJECT_CLASS     key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE         key_type  = CKK_DES3;
	CK_ULONG            tmpl_count = 2;
	CK_ATTRIBUTE   template[] =
	{
		{ CKA_CLASS,     &key_class,  sizeof(key_class) },
		{ CKA_KEY_TYPE,  &key_type,   sizeof(key_type)  }
	};


	printf("do_WrapUnwrapDES3_CBC_PAD...\n");

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
		return rc;
	}

	mech.mechanism      = CKM_DES3_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;


	// first, generate a DES key and a wrapping key
	//
	rc = funcs->C_GenerateKey( session, &mech, NULL, 0, &h_key );
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #1", rc );
		return rc;
	}

	rc = funcs->C_GenerateKey( session, &mech, NULL, 0, &w_key );
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #2", rc );
		return rc;
	}


	// now, encrypt some data
	//
	orig_len = sizeof(original);
	for (i=0; i < orig_len; i++) {
		original[i] = i % 255;
	}

	mech.mechanism      = CKM_DES3_CBC_PAD;
	mech.ulParameterLen = sizeof(init_v);
	mech.pParameter     = init_v;

	rc = funcs->C_EncryptInit( session, &mech, h_key );
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #1", rc );
		return rc;
	}

	cipher_len = sizeof(cipher);
	rc = funcs->C_Encrypt( session, original, orig_len, cipher, &cipher_len );
	if (rc != CKR_OK) {
		show_error("   C_Encrypt #1", rc );
		return rc;
	}


	// now, wrap the key.
	//
	wrapped_data_len = sizeof(wrapped_data);

	rc = funcs->C_WrapKey( session,      &mech,
			w_key,         h_key,
			wrapped_data, &wrapped_data_len );
	if (rc != CKR_OK) {
		show_error("   C_WrapKey #1", rc );
		return rc;
	}

	rc = funcs->C_UnwrapKey( session, &mech,
			w_key,
			wrapped_data, wrapped_data_len,
			template,  tmpl_count,
			&uw_key );
	if (rc != CKR_OK) {
		show_error("   C_UnWrapKey #1", rc );
		return rc;
	}


	// now, decrypt the data using the unwrapped key.
	//
	rc = funcs->C_DecryptInit( session, &mech, uw_key );
	if (rc != CKR_OK) {
		show_error("   C_DecryptInit #1", rc );
		return rc;
	}

	decipher_len = sizeof(decipher);
	rc = funcs->C_Decrypt( session, cipher, cipher_len, decipher, &decipher_len );
	if (rc != CKR_OK) {
		show_error("   C_Decrypt #1", rc );
		return rc;
	}

	if (orig_len != decipher_len) {
		PRINT_ERR("   ERROR:  lengths don't match:  %ld vs %ld\n", orig_len, decipher_len );
		return -1;
	}

	for (i=0; i < orig_len; i++) {
		if (original[i] != decipher[i]) {
			PRINT_ERR("   ERROR:  mismatch at byte %ld\n", i );
			return -1;
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
			return rc;
		}


		// now, wrap the key.
		//
		wrapped_data_len = sizeof(wrapped_data);

		rc = funcs->C_WrapKey( session,      &mech,
				w_key,         priv_key,
				wrapped_data, &wrapped_data_len );
		if (rc != CKR_OK) {
			show_error("   C_WrapKey #2", rc );
			return rc;
		}

		rc = funcs->C_UnwrapKey( session, &mech,
				w_key,
				wrapped_data, wrapped_data_len,
				uw_tmpl,  2,
				&uw_key );
		if (rc != CKR_OK) {
			show_error("   C_UnWrapKey #2", rc );
			return rc;
		}

		// encrypt something with the public key
		//
		mech2.mechanism      = CKM_RSA_PKCS;
		mech2.ulParameterLen = 0;
		mech2.pParameter     = NULL;

		rc = funcs->C_EncryptInit( session, &mech2, publ_key );
		if (rc != CKR_OK) {
			show_error("   C_EncryptInit #2", rc );
			return rc;
		}

		// for RSA operations, keep the input data size smaller than
		// the modulus
		//
		orig_len = 30;

		cipher_len = sizeof(cipher);
		rc = funcs->C_Encrypt( session, original, orig_len, cipher, &cipher_len );
		if (rc != CKR_OK) {
			show_error("   C_Encrypt #2", rc );
			return rc;
		}

		// now, decrypt the data using the unwrapped private key.
		//
		rc = funcs->C_DecryptInit( session, &mech2, uw_key );
		if (rc != CKR_OK) {
			show_error("   C_DecryptInit #1", rc );
			return rc;
		}

		decipher_len = sizeof(decipher);
		rc = funcs->C_Decrypt( session, cipher, cipher_len, decipher, &decipher_len );
		if (rc != CKR_OK) {
			show_error("   C_Decrypt #1", rc );
			return rc;
		}

		if (orig_len != decipher_len) {
			PRINT_ERR("   ERROR:  lengths don't match:  %ld vs %ld\n", orig_len, decipher_len );
			return -1;
		}

		for (i=0; i < orig_len; i++) {
			if (original[i] != decipher[i]) {
				PRINT_ERR("   ERROR:  mismatch at byte %ld\n", i );
				return -1;
			}
		}
	}

	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc );
		return rc;
	}

	printf("Success.\n");
	return 0;
}

CK_RV des3_functions()
{
	SYSTEMTIME t1, t2;
	CK_RV rc;
	
	GetSystemTime(&t1);
	rc = do_Encrypt3DES_ECB();
	if (rc) {
		PRINT_ERR("ERROR do_Encrypt3DES_ECB failed, rc = 0x%lx\n", rc);
		if (!no_stop)
			return rc;
	}
	GetSystemTime(&t2);
	process_time( t1, t2 );

	GetSystemTime(&t1);
	rc = do_Encrypt3DES_CBC();
	if (rc) {
		PRINT_ERR("ERROR do_Encrypt3DES_CBC failed, rc = 0x%lx\n", rc);
		if (!no_stop)
			return rc;
	}
	GetSystemTime(&t2);
	process_time( t1, t2 );

	GetSystemTime(&t1);
	rc = do_Encrypt3DES_Multipart_ECB();
	if (rc) {
		PRINT_ERR("ERROR do_Encrypt3DES_Multipart_ECB failed, rc = 0x%lx\n", rc);
		if (!no_stop)
			return rc;
	}
	GetSystemTime(&t2);
	process_time( t1, t2 );

	GetSystemTime(&t1);
	rc = do_Encrypt3DES_Multipart_CBC();
	if (rc) {
		PRINT_ERR("ERROR do_Encrypt3DES_Multipart_CBC failed, rc = 0x%lx\n", rc);
		if (!no_stop)
			return rc;
	}
	GetSystemTime(&t2);
	process_time( t1, t2 );

	GetSystemTime(&t1);
	rc = do_EncryptDES3_Multipart_CBC_PAD();
	if (rc) {
		PRINT_ERR("ERROR do_EncryptDES3_Multipart_CBC_PAD failed, rc = 0x%lx\n", rc);
		if (!no_stop)
			return rc;
	}
	GetSystemTime(&t2);
	process_time( t1, t2 );

	GetSystemTime(&t1);
	rc = do_WrapUnwrapDES3_ECB();
	if (rc) {
		PRINT_ERR("ERROR do_WrapUnwrapDES3_EBC failed, rc = 0x%lx\n", rc);
		if (!no_stop)
			return rc;
	}
	GetSystemTime(&t2);
	process_time( t1, t2 );

	GetSystemTime(&t1);
	rc = do_WrapUnwrapDES3_CBC();
	if (rc) {
		PRINT_ERR("ERROR do_WrapUnwrapDES3_CBC failed, rc = 0x%lx\n", rc);
		if (!no_stop)
			return rc;
	}
	GetSystemTime(&t2);
	process_time( t1, t2 );

	GetSystemTime(&t1);
	rc = do_WrapUnwrapDES3_CBC_PAD();
	if (rc) {
		PRINT_ERR("ERROR do_WrapUnwrapDES3_CBC_PAD failed, rc = 0x%lx\n", rc);
		if (!no_stop)
			return rc;
	}
	GetSystemTime(&t2);
	process_time( t1, t2 );

	return 0;
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

	{
		CK_SESSION_HANDLE  hsess = 0;

		rc = funcs->C_GetFunctionStatus(hsess);
		if (rc  != CKR_FUNCTION_NOT_PARALLEL)
			return rc;

		rc = funcs->C_CancelFunction(hsess);
		if (rc  != CKR_FUNCTION_NOT_PARALLEL)
			return rc;

	}

	rv = des3_functions();
	/* make sure we return non-zero if rv is non-zero */
	return ((rv==0) || (rv % 256) ? rv : -1);
}


