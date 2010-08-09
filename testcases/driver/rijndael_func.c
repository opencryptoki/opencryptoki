/*
 * openCryptoki testcase
 * - Known answer testcases for the AES (Rijndael) algorithm
 * taken from http://csrc.nist.gov/CryptoToolkit/aes/rijndael/
 *
 * Mar 11, 2003
 * Kent Yoder <yoder1@us.ibm.com>
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "pkcs11types.h"
#include "regress.h"

#define AES_KEY_SIZE_256        32
#define AES_KEY_SIZE_192        24
#define AES_KEY_SIZE_128        16
#define AES_BLOCK_SIZE          16

int do_GetFunctionList(void);
int clean_up(void);

void *dl_handle;

CK_SLOT_ID		slot_id;
CK_FUNCTION_LIST	*funcs;
CK_SESSION_HANDLE	sess;

/* The known answers, from the Rijndael package */
CK_BYTE KAT_128_ECB_KEY[] = { 	0xDF,0x2F,0xC6,0x8C,0x50,0xA1,0xA6,0xEA,
	0x6E,0xBF,0x19,0xDD,0xFC,0xFA,0xC8,0x87 };
CK_BYTE KAT_128_ECB_PT[]  = { 	0x2C,0x29,0x0A,0xE7,0xC6,0x5B,0x6E,0x5B,
	0xBA,0xA3,0x2D,0xE5,0x77,0xDB,0xA3,0x43 };
CK_BYTE KAT_128_ECB_CT[]  = { 	0xA0,0x43,0x77,0xAB,0xE2,0x59,0xB0,0xD0,
	0xB5,0xBA,0x2D,0x40,0xA5,0x01,0x97,0x1B };

CK_BYTE KAT_192_ECB_KEY[] = { 	0xC9,0xDC,0x82,0xF0,0x00,0x18,0x77,0x21,
	0xD2,0xE4,0xB0,0xB8,0x72,0xCD,0x3A,0x43,
	0x11,0xD9,0x67,0xC8,0x1E,0xEE,0xF9,0x00 };
CK_BYTE KAT_192_ECB_PT[]  = { 	0xFF,0x62,0x6D,0x77,0xAE,0x14,0x4C,0x11,
	0x48,0x06,0x10,0xEC,0x1A,0xBB,0x50,0x28 };
CK_BYTE KAT_192_ECB_CT[]  = { 	0x4E,0x46,0xF8,0xC5,0x09,0x2B,0x29,0xE2,
	0x9A,0x97,0x1A,0x0C,0xD1,0xF6,0x10,0xFB };

CK_BYTE KAT_256_ECB_KEY[] = { 	0x98,0x2D,0x61,0x7A,0x0F,0x73,0x73,0x42,
	0xE9,0x91,0x23,0xA5,0xA5,0x73,0xD2,0x66,
	0xF4,0x96,0x19,0x15,0xB3,0x2D,0xCA,0x41,
	0x18,0xAD,0x5C,0xF1,0xDC,0xB6,0xED,0x00 };
CK_BYTE KAT_256_ECB_PT[]  = { 	0x6F,0x86,0x06,0xBB,0xA6,0xCC,0x03,0xA5,
	0xD0,0xA6,0x4F,0xE2,0x1E,0x27,0x7B,0x60 };
CK_BYTE KAT_256_ECB_CT[]  = { 	0x1F,0x67,0x63,0xDF,0x80,0x7A,0x7E,0x70,
	0x96,0x0D,0x4C,0xD3,0x11,0x8E,0x60,0x1A };

CK_BYTE KAT_128_CBC_KEY[] = {   0x46,0xCD,0xD1,0xC7,0xC0,0x11,0xCE,0xE7,
	0x2B,0xFE,0xCC,0xC4,0xC3,0xB5,0x96,0x8B };
CK_BYTE KAT_128_CBC_IV[]  = {	0x8D,0x4F,0xAF,0x63,0x32,0x57,0x85,0x24,
	0x30,0x1A,0xCA,0x22,0xAD,0x86,0x96,0x5B };
CK_BYTE KAT_128_CBC_PT[]  = {	0xA2,0x72,0x00,0xB5,0x1D,0x69,0xAA,0xC2,
	0x2F,0x1C,0x56,0x7F,0x8B,0xCE,0xAB,0xFA };
CK_BYTE KAT_128_CBC_CT[]  = {	0x2F,0x84,0x4C,0xBF,0x78,0xEB,0xA7,0x0D,
	0xA7,0xA4,0x96,0x01,0x38,0x8F,0x1A,0xB6 };

CK_BYTE KAT_192_CBC_KEY[] = {	0xB4,0xD1,0xBD,0xF2,0x97,0xDC,0x05,0x74,
	0x32,0x2C,0x2A,0x18,0x75,0xF8,0x49,0x5D,
	0x75,0x23,0x13,0xEF,0xD9,0x4E,0xE1,0xA1 };
CK_BYTE KAT_192_CBC_IV[]  = {	0xEE,0xDC,0x36,0x77,0xAB,0x7B,0x57,0x82,
	0x9F,0x6D,0x73,0x3F,0x80,0x90,0xDA,0x8A };
CK_BYTE KAT_192_CBC_PT[]  = {	0x51,0x0F,0x7A,0x55,0x79,0x9B,0x39,0x78,
	0x69,0x86,0xBF,0x99,0x8A,0x92,0x37,0xDC };
CK_BYTE KAT_192_CBC_CT[]  = {	0xBA,0x50,0xC9,0x44,0x40,0xC0,0x4A,0x8C,
	0x08,0x99,0xD4,0x26,0x58,0xE2,0x54,0x37 };

CK_BYTE KAT_256_CBC_KEY[] = {	0x3D,0xF2,0xBF,0x13,0xB7,0xFF,0x97,0xCA,
	0x13,0x56,0x7A,0x89,0x0E,0x11,0xC9,0x79,
	0x6F,0xBF,0xD6,0x8E,0x4A,0x26,0x52,0x50,
	0xAE,0x57,0x1B,0x04,0x70,0x0F,0x21,0x3B };
CK_BYTE KAT_256_CBC_IV[] = {	0xAB,0x69,0x57,0xC2,0xF3,0xD3,0x60,0x59,
	0x3E,0x90,0x96,0xF3,0xA3,0x92,0xA7,0x01 };
CK_BYTE KAT_256_CBC_PT[] = {	0xA5,0x8C,0x6D,0xC6,0x31,0x25,0x0D,0x7A,
	0x9F,0x0E,0x31,0x37,0xAE,0x56,0x40,0x2A };
CK_BYTE KAT_256_CBC_CT[] = {	0xC0,0xFE,0xFF,0xF0,0x75,0x06,0xA0,0xB4,
	0xCD,0x7B,0x8B,0x0C,0xF2,0x5D,0x36,0x64 };



CK_RV do_AES_KAT_128_ECB(void)
{
	int			j;
	unsigned int            i, k;
	CK_RV 			rc;
	CK_BYTE                 pt[AES_BLOCK_SIZE],
				ct[AES_BLOCK_SIZE],
				final_pt[AES_BLOCK_SIZE];
	CK_BYTE                 key128[AES_KEY_SIZE_128];
	CK_ULONG                pt_len = AES_BLOCK_SIZE;
	CK_ULONG                ct_len = AES_BLOCK_SIZE;
	CK_ULONG                key_size = AES_KEY_SIZE_128;

	CK_OBJECT_CLASS         class = CKO_SECRET_KEY;
	CK_KEY_TYPE             key_type = CKK_AES;
	CK_UTF8CHAR             label[] = "AES secret key object";
	CK_BBOOL                true = TRUE;

	CK_ATTRIBUTE            template[] = {
		{CKA_CLASS,     &class,         sizeof(class)},
		{CKA_KEY_TYPE,  &key_type,      sizeof(key_type)},
		{CKA_TOKEN,     &true,          sizeof(true)},
		{CKA_LABEL,     label,          sizeof(label)-1},
		{CKA_ENCRYPT,   &true,          sizeof(true)},
		{CKA_VALUE,     key128,         sizeof(key128)},
		{CKA_VALUE_LEN, &key_size,      sizeof(key_size)}
	};

	CK_OBJECT_HANDLE        h_key;
	CK_MECHANISM            mech;


	memset( key128, 0, sizeof(key128) );
	memset( pt, 0, sizeof(pt) );
	memset( ct, 0, sizeof(ct) );
	memset( final_pt, 0, sizeof(final_pt) );

	if( (rc = funcs->C_CreateObject(sess, template, 7, &h_key)) != CKR_OK) {
		show_error("C_CreateObject #1", rc);
		goto done;
	}

	mech.mechanism = CKM_AES_ECB;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;

	for( i=0; i<400; i++) {

		if(i==399)
			memcpy(final_pt, ct, sizeof(final_pt));

		for( j=0; j<10000; j++) {


			rc = funcs->C_EncryptInit(sess, &mech, h_key);
			if (rc != CKR_OK) {
				show_error("   C_EncryptInit #1", rc);
				goto done;
			}

			rc = funcs->C_Encrypt(sess, pt, pt_len, ct, &ct_len);
			if (rc != CKR_OK) {
				show_error("   C_Encrypt #1", rc);
				goto done;
			}

			/* After the final encrypt, we need to keep the
			 * plain text pure */
			if(i == 399 && j == 9999)
				goto print_done;
			else
				memcpy(pt, ct, sizeof(pt));
		}

		for( k=0; k<sizeof(key128); k++)
			key128[k] ^= ct[k];

		if( (rc = funcs->C_DestroyObject(sess, h_key)) != CKR_OK) {
			show_error("C_DestroyObject", rc);
			goto done;
		}

		if( (rc = funcs->C_CreateObject(sess, template, 7, &h_key)) != CKR_OK) {
			show_error("C_CreateObject #2", rc);
			goto done;
		}

		/* One status tick */
		if(!(i%5)) {
			printf(".");
			fflush(stdout);
		}
	}

print_done:
#if 0
	printf("\n\nkey: ");
	for( i=0; i<sizeof(key128); i++)
		printf("%02x", key128[i]);
	printf("\n");

	printf("pt: ");
	for( i=0; i<sizeof(final_pt); i++)
		printf("%02x", final_pt[i]);
	printf("\n");

	printf("ct: ");
	for( i=0; i<sizeof(ct); i++)
		printf("%02x", ct[i]);
	printf("\n");
#endif

	printf("\n");
	for( i=0; i<sizeof(key128); i++) {
		if(key128[i] != KAT_128_ECB_KEY[i]) {
			PRINT_ERR("Error: key data does not match known "
					"key data at byte %d.\n", i);
			goto done;
		}
	}

	for( i=0; i<sizeof(final_pt); i++) {
		if(final_pt[i] != KAT_128_ECB_PT[i]) {
			PRINT_ERR("Error: Plain text does not match known "
					"plain text at byte %d.\n", i);
			goto done;
		}
	}
	for( i=0; i<sizeof(ct); i++) {
		if(ct[i] != KAT_128_ECB_CT[i]) {
			PRINT_ERR("Error: Cipher text does not match known "
					"cipher text at byte %d.\n", i);
			goto done;
		}
	}
done:
	return rc;

}


CK_RV do_AES_KAT_192_ECB(void)
{
	int			j;
	unsigned int            i, k;
	CK_RV 			rc;
	CK_BYTE                 pt[AES_BLOCK_SIZE],
				ct[24], // larger to acct for trailing ciphertext
				final_pt[AES_BLOCK_SIZE];
	CK_BYTE                 key192[AES_KEY_SIZE_192];
	CK_ULONG                pt_len = AES_BLOCK_SIZE;
	CK_ULONG                ct_len = AES_BLOCK_SIZE;
	CK_ULONG                key_size = AES_KEY_SIZE_192;

	CK_OBJECT_CLASS         class = CKO_SECRET_KEY;
	CK_KEY_TYPE             key_type = CKK_AES;
	CK_UTF8CHAR             label[] = "AES secret key object";
	CK_BBOOL                true = TRUE;

	CK_ATTRIBUTE            template[] = {
		{CKA_CLASS,     &class,         sizeof(class)},
		{CKA_KEY_TYPE,  &key_type,      sizeof(key_type)},
		{CKA_TOKEN,     &true,          sizeof(true)},
		{CKA_LABEL,     label,          sizeof(label)-1},
		{CKA_ENCRYPT,   &true,          sizeof(true)},
		{CKA_VALUE,     key192,         sizeof(key192)},
		{CKA_VALUE_LEN, &key_size,      sizeof(key_size)}
	};

	CK_OBJECT_HANDLE        h_key;
	CK_MECHANISM            mech;


	memset( key192, 0, sizeof(key192) );
	memset( pt, 0, sizeof(pt) );
	memset( ct, 0, sizeof(ct) );
	memset( final_pt, 0, sizeof(final_pt) );

	if( (rc = funcs->C_CreateObject(sess, template, 7, &h_key)) != CKR_OK) {
		show_error("C_CreateObject #1", rc);
		goto done;
	}

	mech.mechanism = CKM_AES_ECB;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;

	for( i=0; i<400; i++) {

		if(i==399)
			memcpy(final_pt, ct+8, sizeof(final_pt));

		for( j=0; j<10000; j++) {

			memcpy(ct, ct+16, 8);

			rc = funcs->C_EncryptInit(sess, &mech, h_key);
			if (rc != CKR_OK) {
				show_error("   C_EncryptInit #1", rc);
				goto done;
			}

			rc = funcs->C_Encrypt(sess, pt, pt_len, ct+8, &ct_len);
			if (rc != CKR_OK) {
				show_error("   C_Encrypt #1", rc);
				goto done;
			}

			/* After the final encrypt, we need to keep the
			 * plain text pure */
			if(i == 399 && j == 9999)
				goto print_done;
			else {
				memcpy(pt, ct+8, sizeof(pt));
			}
		}

		for( k=0; k<sizeof(ct); k++)
			key192[k] ^= ct[k];

		if( (rc = funcs->C_DestroyObject(sess, h_key)) != CKR_OK) {
			show_error("C_DestroyObject", rc);
			goto done;
		}

		if( (rc = funcs->C_CreateObject(sess, template, 7, &h_key)) != CKR_OK) {
			show_error("C_CreateObject #2", rc);
			goto done;
		}

		/* One status tick */
		if(!(i%5)) {
			printf(".");
			fflush(stdout);
		}
	}

print_done:
	printf("\n");

	for( i=0; i<sizeof(key192); i++) {
		if(key192[i] != KAT_192_ECB_KEY[i]) {
			PRINT_ERR("Error: key data does not match known "
					"key data at byte %d.\n", i);
			rc = -1;
			goto done;
		}
	}

	for( i=0; i<sizeof(final_pt); i++) {
		if(final_pt[i] != KAT_192_ECB_PT[i]) {
			PRINT_ERR("Error: Plain text does not match known "
					"plain text at byte %d.\n", i);
			rc = -1;
			goto done;
		}
	}
	for( i=0; i<AES_BLOCK_SIZE; i++) {
		if(ct[i+8] != KAT_192_ECB_CT[i]) {
			PRINT_ERR("Error: Cipher text does not match known "
					"cipher text at byte %d.\n", i);
			rc = -1;
			goto done;
		}
	}
done:
	return rc;

}


CK_RV do_AES_KAT_256_ECB(void)
{
	int			j;
	unsigned int            i, k;
	CK_RV 			rc;
	CK_BYTE                 pt[AES_BLOCK_SIZE],
				ct[32], // larger to acct for trailing ciphertext
				final_pt[AES_BLOCK_SIZE];
	CK_BYTE                 key256[AES_KEY_SIZE_256];
	CK_ULONG                pt_len = AES_BLOCK_SIZE;
	CK_ULONG                ct_len = AES_BLOCK_SIZE;
	CK_ULONG                key_size = AES_KEY_SIZE_256;

	CK_OBJECT_CLASS         class = CKO_SECRET_KEY;
	CK_KEY_TYPE             key_type = CKK_AES;
	CK_UTF8CHAR             label[] = "AES secret key object";
	CK_BBOOL                true = TRUE;

	CK_ATTRIBUTE            template[] = {
		{CKA_CLASS,     &class,         sizeof(class)},
		{CKA_KEY_TYPE,  &key_type,      sizeof(key_type)},
		{CKA_TOKEN,     &true,          sizeof(true)},
		{CKA_LABEL,     label,          sizeof(label)-1},
		{CKA_ENCRYPT,   &true,          sizeof(true)},
		{CKA_VALUE,     key256,         sizeof(key256)},
		{CKA_VALUE_LEN, &key_size,      sizeof(key_size)}
	};

	CK_OBJECT_HANDLE        h_key;
	CK_MECHANISM            mech;


	memset( key256, 0, sizeof(key256) );
	memset( pt, 0, sizeof(pt) );
	memset( ct, 0, sizeof(ct) );
	memset( final_pt, 0, sizeof(final_pt) );

	if( (rc = funcs->C_CreateObject(sess, template, 7, &h_key)) != CKR_OK) {
		show_error("C_CreateObject #1", rc);
		goto done;
	}


	mech.mechanism = CKM_AES_ECB;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;

	for( i=0; i<400; i++) {

		if(i==399)
			memcpy(final_pt, ct+16, sizeof(final_pt));

		for( j=0; j<10000; j++) {

			memcpy(ct, ct+16, 16);

			rc = funcs->C_EncryptInit(sess, &mech, h_key);
			if (rc != CKR_OK) {
				show_error("   C_EncryptInit #1", rc);
				goto done;
			}

			rc = funcs->C_Encrypt(sess, pt, pt_len, ct+16, &ct_len);
			if (rc != CKR_OK) {
				show_error("   C_Encrypt #1", rc);
				goto done;
			}

			/* After the final encrypt, we need to keep the
			 * plain text pure */
			if(i == 399 && j == 9999)
				goto print_done;
			else {
				memcpy(pt, ct+16, sizeof(pt));
			}
		}
		for( k=0; k<sizeof(ct); k++)
			key256[k] ^= ct[k];

		if( (rc = funcs->C_DestroyObject(sess, h_key)) != CKR_OK) {
			show_error("C_DestroyObject", rc);
			goto done;
		}

		if( (rc = funcs->C_CreateObject(sess, template, 7, &h_key)) != CKR_OK) {
			show_error("C_CreateObject #2", rc);
			goto done;
		}

		/* One status tick */
		if(!(i%5)) {
			printf(".");
			fflush(stdout);
		}
	}

print_done:
	printf("\n");

	for( i=0; i<sizeof(key256); i++) {
		if(key256[i] != KAT_256_ECB_KEY[i]) {
			PRINT_ERR("Error: key data does not match known "
					"key data at byte %d.\n", i);
			rc = -1;
			goto done;
		}
	}

	for( i=0; i<sizeof(final_pt); i++) {
		if(final_pt[i] != KAT_256_ECB_PT[i]) {
			PRINT_ERR("Error: Plain text does not match known "
					"plain text at byte %d.\n", i);
			rc = -1;
			goto done;
		}
	}
	for( i=0; i<AES_BLOCK_SIZE; i++) {
		if(ct[i+16] != KAT_256_ECB_CT[i]) {
			PRINT_ERR("Error: Cipher text does not match known "
					"cipher text at byte %d.\n", i);
			rc = -1;
			goto done;
		}
	}
done:
	return rc;

}



CK_RV do_AES_KAT_128_CBC(void)
{
	int                     j;
	unsigned int            i, k;
	CK_RV                   rc;
	CK_BYTE                 pt[AES_BLOCK_SIZE],
				ct[16],
				old_ct[16],
				final_pt[AES_BLOCK_SIZE],
				key[AES_KEY_SIZE_128],
				iv[AES_BLOCK_SIZE],
				cv[AES_BLOCK_SIZE];
	CK_ULONG                pt_len = AES_BLOCK_SIZE;
	CK_ULONG                ct_len = AES_BLOCK_SIZE;
	CK_ULONG                key_size = AES_KEY_SIZE_128;

	CK_OBJECT_CLASS         class = CKO_SECRET_KEY;
	CK_KEY_TYPE             key_type = CKK_AES;
	CK_UTF8CHAR             label[] = "AES secret key object";
	CK_BBOOL                true = TRUE;

	CK_ATTRIBUTE            template[] = {
		{CKA_CLASS,     &class,         sizeof(class)},
		{CKA_KEY_TYPE,  &key_type,      sizeof(key_type)},
		{CKA_TOKEN,     &true,          sizeof(true)},
		{CKA_LABEL,     label,          sizeof(label)-1},
		{CKA_ENCRYPT,   &true,          sizeof(true)},
		{CKA_VALUE,     key,		sizeof(key)},
		{CKA_VALUE_LEN, &key_size,      sizeof(key_size)}
	};

	CK_OBJECT_HANDLE        h_key;
	CK_MECHANISM            mech;


	memset( key, 0, sizeof(key) );
	memset( pt, 0, sizeof(pt) );
	memset( ct, 0, sizeof(ct) );
	memset( old_ct, 0, sizeof(ct) );
	memset( final_pt, 0, sizeof(final_pt) );
	memset( iv, 0, sizeof(iv) );
	memset( cv, 0, sizeof(cv) );

	if( (rc = funcs->C_CreateObject(sess, template, 7, &h_key)) != CKR_OK) {
		show_error("C_CreateObject #1", rc);
		goto done;
	}


	mech.mechanism = CKM_AES_CBC;
	mech.ulParameterLen = sizeof(iv);
	mech.pParameter = iv;

	for( i=0; i<400; i++) {
		if(i==399)
			memcpy(final_pt, pt, sizeof(final_pt));
		// Record i, key, cv, pt
		for( j=0; j<10000; j++) {
			for(k=0; k<sizeof(cv); k++) 
				pt[k] ^= cv[k];

			memcpy(old_ct, ct, sizeof(old_ct));

			rc = funcs->C_EncryptInit(sess, &mech, h_key);
			if (rc != CKR_OK) {
				show_error("   C_EncryptInit #1", rc);
				goto done;
			}

			rc = funcs->C_Encrypt(sess, pt, pt_len, ct, &ct_len);
			if (rc != CKR_OK) {
				show_error("   C_Encrypt #1", rc);
				goto done;
			}

			memcpy(pt, old_ct, sizeof(pt));
			memcpy(cv, ct, sizeof(ct));

			/* After the final encrypt, we need to keep the
			 * plain text pure */
			if(i == 399 && j == 9999)
				goto print_done;
		}
		// Record ct
		for( k=0; k<sizeof(ct); k++)
			key[k] ^= ct[k];

		if( (rc = funcs->C_DestroyObject(sess, h_key)) != CKR_OK) {
			show_error("C_DestroyObject", rc);
			goto done;
		}

		if( (rc = funcs->C_CreateObject(sess, template, 7, &h_key)) != CKR_OK) {
			show_error("C_CreateObject #2", rc);
			goto done;
		}

		/* One status tick */
		if(!(i%5)) {
			printf(".");
			fflush(stdout);
		}
	}
print_done:
	printf("\n");

	for( i=0; i<sizeof(key); i++) {
		if(key[i] != KAT_128_CBC_KEY[i]) {
			PRINT_ERR("Error: key data does not match known "
					"key data at byte %d.\n", i);
			rc = -1;
			goto done;
		}
	}

	for( i=0; i<sizeof(final_pt); i++) {
		if(final_pt[i] != KAT_128_CBC_PT[i]) {
			PRINT_ERR("Error: Plain text does not match known "
					"plain text at byte %d.\n", i);
			rc = -1;
			goto done;
		}
	}
	for( i=0; i<AES_BLOCK_SIZE; i++) {
		if(ct[i] != KAT_128_CBC_CT[i]) {
			PRINT_ERR("Error: Cipher text does not match known "
					"cipher text at byte %d.\n", i);
			rc = -1;
			goto done;
		}
	}
done:
	return rc;

}


CK_RV do_AES_KAT_192_CBC(void)
{
	int                     j;
	unsigned int            i, k;
	CK_RV                   rc;
	CK_BYTE                 pt[AES_BLOCK_SIZE],
				old_ct[AES_BLOCK_SIZE],
				ct[24], // larger to acct for trailing ciphertext
				final_pt[AES_BLOCK_SIZE],
				cv[AES_BLOCK_SIZE],
				iv[AES_BLOCK_SIZE];
	CK_BYTE                 key[AES_KEY_SIZE_192];
	CK_ULONG                pt_len = AES_BLOCK_SIZE;
	CK_ULONG                ct_len = AES_BLOCK_SIZE;
	CK_ULONG                key_size = AES_KEY_SIZE_192;

	CK_OBJECT_CLASS         class = CKO_SECRET_KEY;
	CK_KEY_TYPE             key_type = CKK_AES;
	CK_UTF8CHAR             label[] = "AES secret key object";
	CK_BBOOL                true = TRUE;

	CK_ATTRIBUTE            template[] = {
		{CKA_CLASS,     &class,         sizeof(class)},
		{CKA_KEY_TYPE,  &key_type,      sizeof(key_type)},
		{CKA_TOKEN,     &true,          sizeof(true)},
		{CKA_LABEL,     label,          sizeof(label)-1},
		{CKA_ENCRYPT,   &true,          sizeof(true)},
		{CKA_VALUE,     key,            sizeof(key)},
		{CKA_VALUE_LEN, &key_size,      sizeof(key_size)}
	};

	CK_OBJECT_HANDLE        h_key;
	CK_MECHANISM            mech;


	memset( key, 0, sizeof(key) );
	memset( pt, 0, sizeof(pt) );
	memset( ct, 0, sizeof(ct) );
	memset( cv, 0, sizeof(cv) );
	memset( final_pt, 0, sizeof(final_pt) );
	memset( iv, 0, sizeof(iv) );

	if( (rc = funcs->C_CreateObject(sess, template, 7, &h_key)) != CKR_OK) {
		show_error("C_CreateObject #1", rc);
		goto done;
	}

	mech.mechanism = CKM_AES_CBC;
	mech.ulParameterLen = sizeof(iv);
	mech.pParameter = iv;

	for( i=0; i<400; i++) {
		if(i==399)
			memcpy(final_pt, pt, sizeof(final_pt));

		for( j=0; j<10000; j++) {
			for( k=0; k<sizeof(pt); k++)
				pt[k] ^= cv[k];

			memcpy(old_ct, ct+8, sizeof(old_ct));

			rc = funcs->C_EncryptInit(sess, &mech, h_key);
			if (rc != CKR_OK) {
				show_error("   C_EncryptInit #1", rc);
				goto done;
			}

			rc = funcs->C_Encrypt(sess, pt, pt_len, ct+8, &ct_len);
			if (rc != CKR_OK) {
				show_error("   C_Encrypt #1", rc);
				goto done;
			}

			memcpy(ct, old_ct+8, 8);
			memcpy(pt, old_ct, sizeof(pt));
			memcpy(cv, ct+8, sizeof(cv));

			if(i == 399 && j == 9999)
				goto print_done;
		}
		for( k=0; k<sizeof(ct); k++)
			key[k] ^= ct[k];

		if( (rc = funcs->C_DestroyObject(sess, h_key)) != CKR_OK) {
			show_error("C_DestroyObject", rc);
			goto done;
		}

		if( (rc = funcs->C_CreateObject(sess, template, 7, &h_key)) != CKR_OK) {
			show_error("C_CreateObject #2", rc);
			goto done;
		}

		/* One status tick */
		if(!(i%5)) {
			printf(".");
			fflush(stdout);
		}
	}
print_done:
	printf("\n");

	for( i=0; i<sizeof(key); i++) {
		if(key[i] != KAT_192_CBC_KEY[i]) {
			PRINT_ERR("Error: key data does not match known "
					"key data at byte %d.\n", i);
			rc = -1;
			goto done;
		}
	}

	for( i=0; i<sizeof(final_pt); i++) {
		if(final_pt[i] != KAT_192_CBC_PT[i]) {
			PRINT_ERR("Error: Plain text does not match known "
					"plain text at byte %d.\n", i);
			rc = -1;
			goto done;
		}
	}
	for( i=0; i<AES_BLOCK_SIZE; i++) {
		if(ct[i+8] != KAT_192_CBC_CT[i]) {
			PRINT_ERR("Error: Cipher text does not match known "
					"cipher text at byte %d.\n", i);
			rc = -1;
			goto done;
		}
	}
done:
	return rc;

}

CK_RV do_AES_KAT_256_CBC(void)
{
	int                     j;
	unsigned int            i, k;
	CK_RV                   rc;
	CK_BYTE                 pt[AES_BLOCK_SIZE],
				old_ct[AES_BLOCK_SIZE],
				ct[32], // larger to acct for trailing ciphertext
				final_pt[AES_BLOCK_SIZE],
				cv[AES_BLOCK_SIZE],
				iv[AES_BLOCK_SIZE];
	CK_BYTE                 key[AES_KEY_SIZE_256];
	CK_ULONG                pt_len = AES_BLOCK_SIZE;
	CK_ULONG                ct_len = AES_BLOCK_SIZE;
	CK_ULONG                key_size = AES_KEY_SIZE_256;

	CK_OBJECT_CLASS         class = CKO_SECRET_KEY;
	CK_KEY_TYPE             key_type = CKK_AES;
	CK_UTF8CHAR             label[] = "AES secret key object";
	CK_BBOOL                true = TRUE;

	CK_ATTRIBUTE            template[] = {
		{CKA_CLASS,     &class,         sizeof(class)},
		{CKA_KEY_TYPE,  &key_type,      sizeof(key_type)},
		{CKA_TOKEN,     &true,          sizeof(true)},
		{CKA_LABEL,     label,          sizeof(label)-1},
		{CKA_ENCRYPT,   &true,          sizeof(true)},
		{CKA_VALUE,     key,            sizeof(key)},
		{CKA_VALUE_LEN, &key_size,      sizeof(key_size)}
	};

	CK_OBJECT_HANDLE        h_key;
	CK_MECHANISM            mech;


	memset( key, 0, sizeof(key) );
	memset( pt, 0, sizeof(pt) );
	memset( ct, 0, sizeof(ct) );
	memset( cv, 0, sizeof(cv) );
	memset( final_pt, 0, sizeof(final_pt) );
	memset( iv, 0, sizeof(iv) );

	if( (rc = funcs->C_CreateObject(sess, template, 7, &h_key)) != CKR_OK) {
		show_error("C_CreateObject #1", rc);
		goto done;
	}


	mech.mechanism = CKM_AES_CBC;
	mech.ulParameterLen = sizeof(iv);
	mech.pParameter = iv;

	for( i=0; i<400; i++) {
		if(i==399)
			memcpy(final_pt, pt, sizeof(final_pt));

		for( j=0; j<10000; j++) {
			for( k=0; k<sizeof(pt); k++)
				pt[k] ^= cv[k];

			memcpy(old_ct, ct+16, sizeof(old_ct));

			rc = funcs->C_EncryptInit(sess, &mech, h_key);
			if (rc != CKR_OK) {
				show_error("   C_EncryptInit #1", rc);
				goto done;
			}

			rc = funcs->C_Encrypt(sess, pt, pt_len, ct+16, &ct_len);
			if (rc != CKR_OK) {
				show_error("   C_Encrypt #1", rc);
				goto done;
			}

			memcpy(ct, old_ct, 16);
			memcpy(pt, old_ct, sizeof(pt));
			memcpy(cv, ct+16, sizeof(cv));

			/* After the final encrypt, we need to keep the
			 * plain text pure */
			if(i == 399 && j == 9999)
				goto print_done;
		}
		for( k=0; k<sizeof(ct); k++)
			key[k] ^= ct[k];

		if( (rc = funcs->C_DestroyObject(sess, h_key)) != CKR_OK) {
			show_error("C_DestroyObject", rc);
			goto done;
		}

		if( (rc = funcs->C_CreateObject(sess, template, 7, &h_key)) != CKR_OK) {
			show_error("C_CreateObject #2", rc);
			goto done;
		}

		/* One status tick */
		if(!(i%5)) {
			printf(".");
			fflush(stdout);
		}
	}
print_done:
	printf("\n");

	for( i=0; i<sizeof(key); i++) {
		if(key[i] != KAT_256_CBC_KEY[i]) {
			PRINT_ERR("Error: key data does not match known "
					"key data at byte %d.\n", i);
			rc = -1;
			goto done;
		}
	}

	for( i=0; i<sizeof(final_pt); i++) {
		if(final_pt[i] != KAT_256_CBC_PT[i]) {
			PRINT_ERR("Error: Plain text does not match known "
					"plain text at byte %d.\n", i);
			rc = -1;
			goto done;
		}
	}
	for( i=0; i<AES_BLOCK_SIZE; i++) {
		if(ct[i+16] != KAT_256_CBC_CT[i]) {
			PRINT_ERR("Error: Cipher text does not match known "
					"cipher text at byte %d.\n", i);
			rc = -1;
			goto done;
		}
	}
done:
	return rc;

}

CK_RV rijndael_functions(void)
{
	CK_RV			rc, loc_rc;
	CK_C_INITIALIZE_ARGS	initialize_args;
	CK_BYTE			user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG		user_pin_len;
	CK_SLOT_ID		slot_id;

	printf("rijndael_functions...");

	slot_id = SLOT_ID;

	/* There will be no multi-threaded Cryptoki access in this app */
	memset( &initialize_args, 0, sizeof(initialize_args) );


	/* Open a session with the token */
	if( (rc = funcs->C_OpenSession(slot_id, 
					(CKF_SERIAL_SESSION|CKF_RW_SESSION), 
					NULL_PTR, 
					NULL_PTR, 
					&sess)) != CKR_OK ) {
		show_error("C_OpenSession #1", rc);
		goto done;
	}


	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	// Login correctly
	rc = funcs->C_Login(sess, CKU_USER, user_pin, user_pin_len);
	if( rc != CKR_OK ) {
		show_error("C_Login #1", rc);
		goto session_close;
	}

	printf("do_AES_KAT_128_ECB...\n");
	rc = do_AES_KAT_128_ECB();
	if(rc)
		goto logout;
	printf("Looks good...\n");

	printf("do_AES_KAT_192_ECB...\n");
	rc = do_AES_KAT_192_ECB();
	if(rc)
		goto logout;
	printf("Looks good...\n");

	printf("do_AES_KAT_256_ECB...\n");
	rc = do_AES_KAT_256_ECB();
	if(rc)
		goto logout;
	printf("Looks good...\n");

	printf("do_AES_KAT_128_CBC...\n");
	rc = do_AES_KAT_128_CBC();
	if(rc)
		goto logout;
	printf("Looks good...\n");

	printf("do_AES_KAT_192_CBC...\n");
	rc = do_AES_KAT_192_CBC();
	if(rc)
		goto logout;
	printf("Looks good...\n");

	printf("do_AES_KAT_256_CBC...\n");
	rc = do_AES_KAT_256_CBC();
	if(rc)
		goto logout;

	printf("Rijndael tests succeeded.\n");

logout:
	loc_rc = funcs->C_Logout(sess);
	if( loc_rc != CKR_OK )
		show_error("C_Logout #1", loc_rc);

session_close:

	/* Close the session */
	if( (loc_rc = funcs->C_CloseSession(sess)) != CKR_OK )
		show_error("C_CloseSession", loc_rc);

done:
	/* Call C_Finalize and dlclose the library */
	return rc;
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

	rv = rijndael_functions();
	/* make sure we return non-zero if rv is non-zero */
	return ((rv==0) || (rv % 256) ? rv : -1);
}
