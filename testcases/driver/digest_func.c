// File: digest.c
//

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"

#include "md5.h"

extern int no_stop;
//
//
int do_Digest_SHA1( void )
{
	CK_SESSION_HANDLE session;
	CK_SLOT_ID        slot_id;
	CK_MECHANISM      mech;
	CK_ULONG          flags;
	CK_ULONG          i;
	CK_RV             rc;


	printf("do_Digest_SHA1...\n");

	slot_id = SLOT_ID;
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return FALSE;
	}

	// perform the hash tests from the FIPS 180-1 document
	//
	{
		CK_BYTE  data1[] = "abc";
		CK_BYTE  data2[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
		CK_ULONG data_len;
		CK_BYTE  expected1[] = {0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D };
		CK_BYTE  expected2[] = {0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE, 0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1 };
		CK_BYTE  hash[20];
		CK_ULONG hash_len;

		mech.mechanism      = CKM_SHA_1;
		mech.ulParameterLen = 0;
		mech.pParameter     = NULL;

		//
		//
		rc = funcs->C_DigestInit( session, &mech );
		if (rc != CKR_OK) {
			show_error("   C_DigestInit #1", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		data_len = strlen((char *)data1);
		rc = funcs->C_Digest( session, data1,    data_len,
				hash,    &hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Digest #1", rc );
			return FALSE;
		}

		if (hash_len != 20) {
			printf("   ERROR #1:  hash_len == %ld, expected 20\n", hash_len );
			return FALSE;
		}

		if (memcmp(hash, expected1, hash_len) != 0) {
			printf("   ERROR #2:  hash output mismatch\n" );
			return FALSE;
		}


		//
		//
		rc = funcs->C_DigestInit( session, &mech );
		if (rc != CKR_OK) {
			show_error("   C_DigestInit #2", rc );
			return FALSE;
		}

		data_len = strlen((char *)data1);
		rc = funcs->C_DigestUpdate( session, data1, data_len );
		if (rc != CKR_OK) {
			show_error("   C_DigestUpdate #1", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_DigestFinal( session, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("   C_DigestFinal #1", rc );
			return FALSE;
		}

		if (hash_len != 20) {
			printf("   ERROR #3:  hash_len == %ld, expected 20\n", hash_len );
			return FALSE;
		}

		if (memcmp(hash, expected1, hash_len) != 0) {
			printf("   ERROR #4:  hash output mismatch\n" );
			return FALSE;
		}


		//
		//
		rc = funcs->C_DigestInit( session, &mech );
		if (rc != CKR_OK) {
			show_error("   C_DigestInit #3", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		data_len = strlen((char *)data2);
		rc = funcs->C_Digest( session, data2,    data_len,
				hash,    &hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Digest #2", rc );
			return FALSE;
		}

		if (hash_len != 20) {
			printf("   ERROR #5:  hash_len == %ld, expected 20\n", hash_len );
			return FALSE;
		}

		if (memcmp(hash, expected2, hash_len) != 0) {
			printf("   ERROR #6:  hash output mismatch\n" );
			return FALSE;
		}


		//
		//
		rc = funcs->C_DigestInit( session, &mech );
		if (rc != CKR_OK) {
			show_error("   C_DigestInit #4", rc );
			return FALSE;
		}

		data_len = strlen((char *)data2);
		rc = funcs->C_DigestUpdate( session, data2, data_len );
		if (rc != CKR_OK) {
			show_error("   C_DigestUpdate #2", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_DigestFinal( session, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("   C_DigestFinal #2", rc );
			return FALSE;
		}

		if (hash_len != 20) {
			printf("   ERROR #7:  hash_len == %ld, expected 20\n", hash_len );
			return FALSE;
		}

		if (memcmp(hash, expected2, hash_len) != 0) {
			printf("   ERROR #8:  hash output mismatch\n" );
			return FALSE;
		}
	}

	// now, do custom testing
	//
	{
		CK_BYTE           data[BIG_REQUEST];
		CK_BYTE           hash1[SHA1_HASH_LEN];
		CK_BYTE           hash2[SHA1_HASH_LEN];
		CK_BYTE           hash3[SHA1_HASH_LEN];
		CK_ULONG          data_len;
		CK_ULONG          hash_len;

		mech.mechanism      = CKM_SHA_1;
		mech.ulParameterLen = 0;
		mech.pParameter     = NULL;

		// generate some data to hash
		//
		data_len = sizeof(data);
		for (i=0; i < data_len; i++)
			data[i] = i % 255;


		// first, hash it all in 1 big block
		//
		rc = funcs->C_DigestInit( session, &mech );
		if (rc != CKR_OK) {
			show_error("   C_DigestInit #5", rc );
			return FALSE;
		}

		hash_len = sizeof(hash1);
		rc = funcs->C_Digest( session, data,     data_len,
				hash1,   &hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Digest #3", rc );
			return FALSE;
		}

		if (hash_len != SHA1_HASH_LEN) {
			printf("   ERROR #9:  expected len1 to be %d.  Got %ld instead\n\n", SHA1_HASH_LEN, hash_len );
			return FALSE;
		}


		// now, hash it in 64-byte chunks.  this is an even multiple of the SHA1
		// blocksize
		//
		rc = funcs->C_DigestInit( session, &mech );
		if (rc != CKR_OK) {
			show_error("   C_DigestInit #6", rc );
			return FALSE;
		}

		for (i=0; i < sizeof(data); i += 64) {
			CK_ULONG size = sizeof(data) - i;
			size = MIN(size, 64);

			rc = funcs->C_DigestUpdate( session, &data[i], size );
			if (rc != CKR_OK) {
				show_error("   C_DigestUpdate #3", rc );
				printf("   Offset:  %ld\n", i);
				return FALSE;
			}
		}

		hash_len = sizeof(hash2);
		rc = funcs->C_DigestFinal( session, hash2, &hash_len );
		if (rc != CKR_OK) {
			show_error("   C_DigestFinal #3", rc );
			return FALSE;
		}

		if (hash_len != SHA1_HASH_LEN) {
			printf("   ERROR #10:  expected len2 to be %d.  Got %ld instead\n\n", SHA1_HASH_LEN, hash_len );
			return FALSE;
		}


		rc = funcs->C_DigestInit( session, &mech );
		if (rc != CKR_OK) {
			show_error("   C_DigestInit #3", rc );
			return FALSE;
		}


		// finally, hash it in 47-byte chunks.  this is not a multiple of the SHA1
		// block size.  it should exercise our ability to buffer requests
		// for the internal SHA1 restrictions
		//
		for (i=0; i < sizeof(data); i += 47) {
			CK_ULONG size = sizeof(data) - i;
			size = MIN(size, 47);

			rc = funcs->C_DigestUpdate( session, &data[i], size );
			if (rc != CKR_OK) {
				show_error("   C_DigestUpdate #4", rc );
				printf("   Offset:  %ld\n", i);
				return FALSE;
			}
		}

		hash_len = sizeof(hash3);
		rc = funcs->C_DigestFinal( session, hash3, &hash_len );
		if (rc != CKR_OK) {
			show_error("   C_DigestFinal #4", rc );
			return FALSE;
		}

		if (hash_len != SHA1_HASH_LEN) {
			printf("   ERROR #11:  expected len3 to be %d.  Got %ld instead\n\n", SHA1_HASH_LEN, hash_len );
			return FALSE;
		}


		// the hashes better be the same
		//
		if (memcmp(hash1, hash2, sizeof(hash1)) != 0) {
			printf("   ERROR #12:  hashes 1 and 2 don't match\n");
			return FALSE;
		}

		if (memcmp(hash1, hash3, sizeof(hash1)) != 0) {
			printf("   ERROR #13:  hashes 1 and 3 don't match\n");
			return FALSE;
		}
	}


	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc );
		return FALSE;
	}

	printf("Looks okay...\n");
	return TRUE;
}


//
//
int do_Digest_MD2( void )
{
	CK_SESSION_HANDLE session;
	CK_SLOT_ID        slot_id;
	CK_MECHANISM      mech;
	CK_BYTE           data[BIG_REQUEST];
	CK_BYTE           hash1[MD2_HASH_LEN];
	CK_BYTE           hash2[MD2_HASH_LEN];
	CK_BYTE           hash3[MD2_HASH_LEN];
	CK_ULONG          flags;
	CK_ULONG          data_len;
	CK_ULONG          hash_len;
	CK_ULONG          i;
	CK_RV             rc;


	printf("do_Digest_MD2...\n");

	slot_id = SLOT_ID;
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return FALSE;
	}

	mech.mechanism      = CKM_MD2;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;

	// generate some data to hash
	//
	data_len = sizeof(data);
	for (i=0; i < data_len; i++)
		data[i] = i % 255;


	// first, hash it all in 1 big block
	//
	rc = funcs->C_DigestInit( session, &mech );
	if (rc != CKR_OK) {
		show_error("   C_DigestInit #1", rc );
		return FALSE;
	}

	hash_len = sizeof(hash1);
	rc = funcs->C_Digest( session, data,     data_len,
			hash1,   &hash_len );
	if (rc != CKR_OK) {
		show_error("   C_Digest #1", rc );
		return FALSE;
	}

	if (hash_len != MD2_HASH_LEN) {
		printf("   ERROR:  expected len1 to be %d.  Got %ld instead\n\n", MD2_HASH_LEN, hash_len );
		return FALSE;
	}


	// now hash in 64-byte chunks
	//
	rc = funcs->C_DigestInit( session, &mech );
	if (rc != CKR_OK) {
		show_error("   C_DigestInit #2", rc );
		return FALSE;
	}

	for (i=0; i < sizeof(data); i += 64) {
		CK_ULONG size = sizeof(data) - i;
		size = MIN(size, 64);

		rc = funcs->C_DigestUpdate( session, &data[i], size );
		if (rc != CKR_OK) {
			show_error("   C_DigestUpdate #1", rc );
			printf("   Offset:  %ld\n", i);
			return FALSE;
		}
	}

	hash_len = sizeof(hash2);
	rc = funcs->C_DigestFinal( session, hash2, &hash_len );
	if (rc != CKR_OK) {
		show_error("   C_DigestFinal #1", rc );
		return FALSE;
	}

	if (hash_len != MD2_HASH_LEN) {
		printf("   ERROR:  expected len2 to be %d.  Got %ld instead\n\n", MD2_HASH_LEN, hash_len );
		return FALSE;
	}


	rc = funcs->C_DigestInit( session, &mech );
	if (rc != CKR_OK) {
		show_error("   C_DigestInit #3", rc );
		return FALSE;
	}


	// finally, hash it in 47-byte chunks.
	//
	for (i=0; i < sizeof(data); i += 47) {
		CK_ULONG size = sizeof(data) - i;
		size = MIN(size, 47);

		rc = funcs->C_DigestUpdate( session, &data[i], size );
		if (rc != CKR_OK) {
			show_error("   C_DigestUpdate #2", rc );
			printf("   Offset:  %ld\n", i);
			return FALSE;
		}
	}

	hash_len = sizeof(hash3);
	rc = funcs->C_DigestFinal( session, hash3, &hash_len );
	if (rc != CKR_OK) {
		show_error("   C_DigestFinal #2", rc );
		return FALSE;
	}

	if (hash_len != MD2_HASH_LEN) {
		printf("   ERROR:  expected len3 to be %d.  Got %ld instead\n\n", MD2_HASH_LEN, hash_len );
		return FALSE;
	}


	// the hashes better be the same
	//
	if (memcmp(hash1, hash2, sizeof(hash1)) != 0) {
		printf("   ERROR:  hashes 1 and 2 don't match\n");
		return FALSE;
	}

	if (memcmp(hash1, hash3, sizeof(hash1)) != 0) {
		printf("   ERROR:  hashes 1 and 3 don't match\n");
		return FALSE;
	}


	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc );
		return FALSE;
	}

	printf("Looks okay...\n");
	return TRUE;
}



//
//
int do_Digest_MD5( void )
{
	CK_SESSION_HANDLE session;
	CK_SLOT_ID        slot_id;
	CK_MECHANISM      mech;
	CK_BYTE           data[BIG_REQUEST];
	CK_BYTE           hash1[MD5_HASH_LEN];
	CK_BYTE           hash2[MD5_HASH_LEN];
	CK_BYTE           hash3[MD5_HASH_LEN];
	CK_ULONG          flags;
	CK_ULONG          data_len;
	CK_ULONG          hash_len;
	CK_ULONG          i;
	CK_RV             rc;


	// SAB new
	MD5_CTX   mdContext;


	printf("do_Digest_MD5...\n");

	slot_id = SLOT_ID;
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return FALSE;
	}

	mech.mechanism      = CKM_MD5;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;

	// generate some data to hash
	//
	data_len = sizeof(data);
	for (i=0; i < data_len; i++)
		data[i] = i % 255;


	// first, hash it all in 1 big block
	//
	rc = funcs->C_DigestInit( session, &mech );
	if (rc != CKR_OK) {
		show_error("   C_DigestInit #1", rc );
		return FALSE;
	}

	hash_len = sizeof(hash1);
	rc = funcs->C_Digest( session, data,     data_len,
			hash1,   &hash_len );
	if (rc != CKR_OK) {
		show_error("   C_Digest #1", rc );
		return FALSE;
	}

	if (hash_len != MD5_HASH_LEN) {
		printf("   ERROR:  expected len1 to be %d.  Got %ld instead\n\n", MD5_HASH_LEN, hash_len );
		return FALSE;
	}

	// SAB Verify...
	MD5Init(&mdContext);
	MD5Update(&mdContext,data,data_len);
	MD5Final(&mdContext);
	if ( bcmp(hash1,mdContext.digest,MD5_HASH_LEN)){
		printf("  Error, Card value does not jive with the Software value \n");

	}

	// now hash in 64-byte chunks
	//
	rc = funcs->C_DigestInit( session, &mech );
	if (rc != CKR_OK) {
		show_error("   C_DigestInit #2", rc );
		return FALSE;
	}

	for (i=0; i < sizeof(data); i += 64) {
		CK_ULONG size = sizeof(data) - i;
		size = MIN(size, 64);

		rc = funcs->C_DigestUpdate( session, &data[i], size );
		if (rc != CKR_OK) {
			show_error("   C_DigestUpdate #1", rc );
			printf("   Offset:  %ld\n", i);
			return FALSE;
		}
	}

	hash_len = sizeof(hash2);
	rc = funcs->C_DigestFinal( session, hash2, &hash_len );
	if (rc != CKR_OK) {
		show_error("   C_DigestFinal #1", rc );
		return FALSE;
	}

	if (hash_len != MD5_HASH_LEN) {
		printf("   ERROR:  expected len2 to be %d.  Got %ld instead\n\n", MD5_HASH_LEN, hash_len );
		return FALSE;
	}


	rc = funcs->C_DigestInit( session, &mech );
	if (rc != CKR_OK) {
		show_error("   C_DigestInit #3", rc );
		return FALSE;
	}


	// finally, hash it in 47-byte chunks.
	//
	for (i=0; i < sizeof(data); i += 47) {
		CK_ULONG size = sizeof(data) - i;
		size = MIN(size, 47);

		rc = funcs->C_DigestUpdate( session, &data[i], size );
		if (rc != CKR_OK) {
			show_error("   C_DigestUpdate #2", rc );
			printf("   Offset:  %ld\n", i);
			return FALSE;
		}
	}

	hash_len = sizeof(hash3);
	rc = funcs->C_DigestFinal( session, hash3, &hash_len );
	if (rc != CKR_OK) {
		show_error("   C_DigestFinal #2", rc );
		return FALSE;
	}

	if (hash_len != MD5_HASH_LEN) {
		printf("   ERROR:  expected len3 to be %d.  Got %ld instead\n\n", MD5_HASH_LEN, hash_len );
		return FALSE;
	}


	// the hashes better be the same
	//
	if (memcmp(hash1, hash2, sizeof(hash1)) != 0) {
		printf("   ERROR:  hashes 1 and 2 don't match\n");
		return FALSE;
	}

	if (memcmp(hash1, hash3, sizeof(hash1)) != 0) {
		printf("   ERROR:  hashes 1 and 3 don't match\n");
		return FALSE;
	}


	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc );
		return FALSE;
	}

	printf("Looks okay...\n");
	return TRUE;
}


//
//
int do_Digest_SHA1_speed( void )
{
	CK_SESSION_HANDLE session;
	CK_SLOT_ID        slot_id;
	CK_MECHANISM      mech;
	CK_BYTE           data[BIG_REQUEST];
	CK_BYTE           hash1[SHA1_HASH_LEN];
	CK_ULONG          flags;
	CK_ULONG          data_len;
	CK_ULONG          hash_len;
	CK_ULONG          i;
	CK_RV             rc;


	printf("do_Digest_SHA1_speed.  Doing 819200 bytes in 8192 byte chunks...\n");

	slot_id = SLOT_ID;
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return FALSE;
	}

	mech.mechanism      = CKM_SHA_1;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;

	// generate some data to hash
	//
	data_len = sizeof(data);
	for (i=0; i < data_len; i++)
		data[i] = i % 255;


	for (i=0; i < 100; i++) {
		rc = funcs->C_DigestInit( session, &mech );
		if (rc != CKR_OK) {
			show_error("   C_DigestInit #1", rc );
			return FALSE;
		}

		hash_len = sizeof(hash1);
		rc = funcs->C_Digest( session, data,     data_len,
				hash1,   &hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Digest #1", rc );
			return FALSE;
		}

		if (hash_len != SHA1_HASH_LEN) {
			printf("   ERROR:  expected len1 to be %d.  Got %ld instead\n\n", SHA1_HASH_LEN, hash_len );
			return FALSE;
		}
	}

	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc );
		return FALSE;
	}

	printf("Looks okay...\n");
	return TRUE;
}


//
//
int do_Digest_MD5_speed( void )
{
	CK_SESSION_HANDLE session;
	CK_SLOT_ID        slot_id;
	CK_MECHANISM      mech;
	CK_BYTE           data[BIG_REQUEST];
	CK_BYTE           hash1[MD5_HASH_LEN];
	CK_ULONG          flags;
	CK_ULONG          data_len;
	CK_ULONG          hash_len;
	CK_ULONG          i;
	CK_RV             rc;


	printf("do_Digest_MD5_speed.  Doing 819200 bytes in 8192 byte chunks...\n");

	slot_id = SLOT_ID;
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return FALSE;
	}

	mech.mechanism      = CKM_MD5;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;

	// generate some data to hash
	//
	data_len = sizeof(data);
	for (i=0; i < data_len; i++)
		data[i] = i % 255;


	for (i=0; i < 100; i++) {
		rc = funcs->C_DigestInit( session, &mech );
		if (rc != CKR_OK) {
			show_error("   C_DigestInit #1", rc );
			return FALSE;
		}

		hash_len = sizeof(hash1);
		rc = funcs->C_Digest( session, data,     data_len,
				hash1,   &hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Digest #1", rc );
			return FALSE;
		}

		if (hash_len != MD5_HASH_LEN) {
			printf("   ERROR:  expected len1 to be %d.  Got %ld instead\n\n", MD5_HASH_LEN, hash_len );
			return FALSE;
		}
	}

	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc );
		return FALSE;
	}

	printf("Looks okay...\n");
	return TRUE;
}


//
//
int do_SignVerify_MD5_HMAC( void )
{
	CK_SESSION_HANDLE session;
	CK_SLOT_ID        slot_id;
	CK_MECHANISM      mech;
	CK_ULONG          flags;
	CK_RV             rc;



	printf("do_SignVerify_MD5_HMAC...\n");

	slot_id = SLOT_ID;
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return FALSE;
	}


	mech.mechanism      = CKM_MD5_HMAC;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;

	// test 1
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[MD5_HASH_LEN];
		CK_BYTE           data[10];
		CK_BYTE           expect[] = { 0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xBB,
			0x1C, 0x13, 0xf4, 0x8E, 0xf8, 0x15, 0x8b,
			0xfc, 0x9d };

		CK_BYTE           key_data[] = { 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb,
			0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		memcpy( data, "Hi There", 8 );
		data_len = 8;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #1", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #1", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Sign #1", rc );
			return FALSE;
		}

		if (hash_len != MD5_HASH_LEN) {
			printf("   Error:  C_Sign #1 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #1 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #1", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #1", rc );
			return FALSE;
		}


		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #1", rc );
			return FALSE;
		}
	}


	// test 2
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[MD5_HASH_LEN];
		CK_BYTE           data[40];
		CK_BYTE           expect[] = { 0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5,
			0x03, 0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d,
			0xb7, 0x38 };

		CK_BYTE           key_data[] = { 'J', 'e', 'f', 'e' };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		memcpy( data, "what do ya want for nothing?", 28 );
		data_len = 28;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #2", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #2", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("  C_Sign #2", rc );
			return FALSE;
		}

		if (hash_len != MD5_HASH_LEN) {
			printf("   Error:  C_Sign #2 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #2 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #2", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #2", rc );
			return FALSE;
		}

		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #2", rc );
			return FALSE;
		}
	}

	// test 3
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[MD5_HASH_LEN];
		CK_BYTE           data[50];
		CK_BYTE           expect[] = { 0x56, 0xbe, 0x34, 0x52, 0x1d, 0x14, 0x4c,
			0x88, 0xdb, 0xb8, 0xc7, 0x33, 0xf0, 0xe8,
			0xb3, 0xf6 };
		CK_BYTE           key_data[] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		memset( data, 0xDD, 50 );
		data_len = 50;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #3", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #3", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("  C_Sign #3", rc );
			return FALSE;
		}

		if (hash_len != MD5_HASH_LEN) {
			printf("   Error:  C_Sign #3 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #3 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #3", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #3", rc );
			return FALSE;
		}

		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #3", rc );
			return FALSE;
		}
	}

	// test 4
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[MD5_HASH_LEN];
		CK_BYTE           data[50];
		CK_BYTE           expect[] = { 0x69, 0x7e, 0xaf, 0x0a, 0xca, 0x3a, 0x3a,
			0xea, 0x3a, 0x75, 0x16, 0x47, 0x46, 0xff,
			0xaa, 0x79 };

		CK_BYTE           key_data[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
			0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
			0x16, 0x17, 0x18, 0x19 };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		memset( data, 0xCD, 50 );
		data_len = 50;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #4", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #4", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("  C_Sign #4", rc );
			return FALSE;
		}

		if (hash_len != MD5_HASH_LEN) {
			printf("   Error:  C_Sign #4 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #4 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #4", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #4", rc );
			return FALSE;
		}

		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #4", rc );
			return FALSE;
		}
	}

	// test 5
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[MD5_HASH_LEN];
		CK_BYTE           data[50];
		CK_BYTE           expect[] = { 0x56, 0x46, 0x1e, 0xf2, 0x34, 0x2e, 0xdc,
			0x00, 0xf9, 0xba, 0xb9, 0x95, 0x69, 0x0e,
			0xfd, 0x4c };

		CK_BYTE           key_data[] = { 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
			0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
			0x0c, 0x0c };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		strcpy((char *)data, "Test With Truncation" );
		data_len = 20;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #5", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #5", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("  C_Sign #5", rc );
			return FALSE;
		}

		if (hash_len != MD5_HASH_LEN) {
			printf("   Error:  C_Sign #5 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #5 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #5", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #5", rc );
			return FALSE;
		}

		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #5", rc );
			return FALSE;
		}
	}

	// test 6
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[MD5_HASH_LEN];
		CK_BYTE           data[60];
		CK_BYTE           expect[] = { 0x6b, 0x1a, 0xb7, 0xfe, 0x4b, 0xd7, 0xbf, 0x8f,
			0x0b, 0x62, 0xe6, 0xce, 0x61, 0xb9, 0xd0, 0xcd };

		CK_BYTE           key_data[] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		strcpy( (char *)data, "Test Using Larger Than Block-Size Key - Hash Key First" );
		data_len = 54;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #6", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #6", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("  C_Sign #6", rc );
			return FALSE;
		}

		if (hash_len != MD5_HASH_LEN) {
			printf("   Error:  C_Sign #6 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #6 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #6", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #6", rc );
			return FALSE;
		}

		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #6", rc );
			return FALSE;
		}
	}

	// test 7
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[MD5_HASH_LEN];
		CK_BYTE           data[80];
		CK_BYTE           expect[] = { 0x6f, 0x63, 0x0f, 0xad, 0x67, 0xcd, 0xa0, 0xee,
			0x1f, 0xb1, 0xf5, 0x62, 0xdb, 0x3a, 0xa5, 0x3e };

		CK_BYTE           key_data[] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		strcpy( (char *)data, "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data" );
		data_len = 73;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #7", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #7", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("  C_Sign #7", rc );
			return FALSE;
		}

		if (hash_len != MD5_HASH_LEN) {
			printf("   Error:  C_Sign #7 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #7 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #7", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #7", rc );
			return FALSE;
		}

		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #7", rc );
			return FALSE;
		}
	}


	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc );
		return FALSE;
	}

	printf("Looks okay...\n");
	return TRUE;
}


//
//
int do_SignVerify_MD5_HMAC_GENERAL( void )
{
	CK_SESSION_HANDLE session;
	CK_SLOT_ID        slot_id;
	CK_MECHANISM      mech;
	CK_ULONG          flags;
	CK_ULONG          hmac_size;
	CK_RV             rc;



	printf("do_SignVerify_MD5_HMAC_GENERAL...\n");

	slot_id = SLOT_ID;
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return FALSE;
	}


	hmac_size = 4;

	mech.mechanism      = CKM_MD5_HMAC_GENERAL;
	mech.ulParameterLen = sizeof(CK_ULONG);
	mech.pParameter     = &hmac_size;

	// test 1
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[MD5_HASH_LEN];
		CK_BYTE           data[10];
		CK_BYTE           expect[] = { 0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xBB,
			0x1C, 0x13, 0xf4, 0x8E, 0xf8, 0x15, 0x8b,
			0xfc, 0x9d };

		CK_BYTE           key_data[] = { 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb,
			0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		memcpy( data, "Hi There", 8 );
		data_len = 8;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #1", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #1", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Sign #1", rc );
			return FALSE;
		}

		if (hash_len != hmac_size) {
			printf("   Error:  C_Sign #1 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #1 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #1", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hmac_size );
		if (rc != CKR_OK) {
			show_error("   C_Verify #1", rc );
			return FALSE;
		}


		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #1", rc );
			return FALSE;
		}
	}


	// test 2
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[MD5_HASH_LEN];
		CK_BYTE           data[40];
		CK_BYTE           expect[] = { 0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5,
			0x03, 0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d,
			0xb7, 0x38 };

		CK_BYTE           key_data[] = { 'J', 'e', 'f', 'e' };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		memcpy( data, "what do ya want for nothing?", 28 );
		data_len = 28;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #2", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #2", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("  C_Sign #2", rc );
			return FALSE;
		}

		if (hash_len != hmac_size) {
			printf("   Error:  C_Sign #2 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #2 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #2", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #2", rc );
			return FALSE;
		}

		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #2", rc );
			return FALSE;
		}
	}

	// test 3
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[MD5_HASH_LEN];
		CK_BYTE           data[50];
		CK_BYTE           expect[] = { 0x56, 0xbe, 0x34, 0x52, 0x1d, 0x14, 0x4c,
			0x88, 0xdb, 0xb8, 0xc7, 0x33, 0xf0, 0xe8,
			0xb3, 0xf6 };
		CK_BYTE           key_data[] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		memset( data, 0xDD, 50 );
		data_len = 50;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #3", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #3", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("  C_Sign #3", rc );
			return FALSE;
		}

		if (hash_len != hmac_size) {
			printf("   Error:  C_Sign #3 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #3 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #3", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #3", rc );
			return FALSE;
		}

		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #3", rc );
			return FALSE;
		}
	}

	// test 4
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[MD5_HASH_LEN];
		CK_BYTE           data[50];
		CK_BYTE           expect[] = { 0x69, 0x7e, 0xaf, 0x0a, 0xca, 0x3a, 0x3a,
			0xea, 0x3a, 0x75, 0x16, 0x47, 0x46, 0xff,
			0xaa, 0x79 };

		CK_BYTE           key_data[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
			0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
			0x16, 0x17, 0x18, 0x19 };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		memset( data, 0xCD, 50 );
		data_len = 50;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #4", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #4", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("  C_Sign #4", rc );
			return FALSE;
		}

		if (hash_len != hmac_size) {
			printf("   Error:  C_Sign #4 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #4 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #4", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #4", rc );
			return FALSE;
		}

		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #4", rc );
			return FALSE;
		}
	}

	// test 5
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[MD5_HASH_LEN];
		CK_BYTE           data[50];
		CK_BYTE           expect[] = { 0x56, 0x46, 0x1e, 0xf2, 0x34, 0x2e, 0xdc,
			0x00, 0xf9, 0xba, 0xb9, 0x95, 0x69, 0x0e,
			0xfd, 0x4c };

		CK_BYTE           key_data[] = { 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
			0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
			0x0c, 0x0c };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		strcpy( (char *)data, "Test With Truncation" );
		data_len = 20;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #5", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #5", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("  C_Sign #5", rc );
			return FALSE;
		}

		if (hash_len != hmac_size) {
			printf("   Error:  C_Sign #5 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #5 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #5", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #5", rc );
			return FALSE;
		}

		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #5", rc );
			return FALSE;
		}
	}

	// test 6
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[MD5_HASH_LEN];
		CK_BYTE           data[60];
		CK_BYTE           expect[] = { 0x6b, 0x1a, 0xb7, 0xfe, 0x4b, 0xd7, 0xbf, 0x8f,
			0x0b, 0x62, 0xe6, 0xce, 0x61, 0xb9, 0xd0, 0xcd };

		CK_BYTE           key_data[] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		strcpy( (char *)data, "Test Using Larger Than Block-Size Key - Hash Key First" );
		data_len = 54;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #6", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #6", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("  C_Sign #6", rc );
			return FALSE;
		}

		if (hash_len != hmac_size) {
			printf("   Error:  C_Sign #6 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #6 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #6", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #6", rc );
			return FALSE;
		}

		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #6", rc );
			return FALSE;
		}
	}

	// test 7
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[MD5_HASH_LEN];
		CK_BYTE           data[80];
		CK_BYTE           expect[] = { 0x6f, 0x63, 0x0f, 0xad, 0x67, 0xcd, 0xa0, 0xee,
			0x1f, 0xb1, 0xf5, 0x62, 0xdb, 0x3a, 0xa5, 0x3e };

		CK_BYTE           key_data[] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		strcpy( (char *)data, "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data" );
		data_len = 73;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #7", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #7", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("  C_Sign #7", rc );
			return FALSE;
		}

		if (hash_len != hmac_size) {
			printf("   Error:  C_Sign #7 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #7 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #7", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #7", rc );
			return FALSE;
		}

		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #7", rc );
			return FALSE;
		}
	}


	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc );
		return FALSE;
	}

	printf("Looks okay...\n");
	return TRUE;
}


//
//
int do_SignVerify_SHA1_HMAC( void )
{
	CK_SESSION_HANDLE session;
	CK_SLOT_ID        slot_id;
	CK_MECHANISM      mech;
	CK_ULONG          flags;
	CK_RV             rc;



	printf("do_SignVerify_SHA1_HMAC...\n");

	slot_id = SLOT_ID;
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return FALSE;
	}


	mech.mechanism      = CKM_SHA_1_HMAC;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;

	// test 1
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[SHA1_HASH_LEN];
		CK_BYTE           data[10];
		CK_BYTE           expect[] ={ 0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64,
			0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e,
			0xf1, 0x46, 0xbe, 0x00 };

		CK_BYTE           key_data[] = { 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb,
			0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb,
			0xb, 0xb, 0xb, 0xb };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		memcpy( data, "Hi There", 8 );
		data_len = 8;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #1", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #1", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Sign #1", rc );
			return FALSE;
		}

		if (hash_len != SHA1_HASH_LEN) {
			printf("   Error:  C_Sign #1 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #1 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #1", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #1", rc );
			return FALSE;
		}


		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #1", rc );
			return FALSE;
		}
	}


	// test 2
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[SHA1_HASH_LEN];
		CK_BYTE           data[40];
		CK_BYTE           expect[] = { 0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2,
			0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84, 0xdf, 0x9c,
			0x25, 0x9a, 0x7c, 0x79 };

		CK_BYTE           key_data[] = { 'J', 'e', 'f', 'e' };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		memcpy( data, "what do ya want for nothing?", 28 );
		data_len = 28;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #2", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #2", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("  C_Sign #2", rc );
			return FALSE;
		}

		if (hash_len != SHA1_HASH_LEN) {
			printf("   Error:  C_Sign #2 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #2 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #2", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #2", rc );
			return FALSE;
		}

		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #2", rc );
			return FALSE;
		}
	}

	// test 3
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[SHA1_HASH_LEN];
		CK_BYTE           data[50];
		CK_BYTE           expect[] = { 0x12, 0x5d, 0x73, 0x42, 0xb9, 0xac, 0x11, 0xcd,
			0x91, 0xa3, 0x9a, 0xf4, 0x8a, 0xa1, 0x7b, 0x4f,
			0x63, 0xf1, 0x75, 0xd3 };

		CK_BYTE           key_data[] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		memset( data, 0xDD, 50 );
		data_len = 50;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #3", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #3", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("  C_Sign #3", rc );
			return FALSE;
		}

		if (hash_len != SHA1_HASH_LEN) {
			printf("   Error:  C_Sign #3 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #3 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #3", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #3", rc );
			return FALSE;
		}

		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #3", rc );
			return FALSE;
		}
	}

	// test 4
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[SHA1_HASH_LEN];
		CK_BYTE           data[50];
		CK_BYTE           expect[] = { 0x4c, 0x90, 0x07, 0xf4, 0x02, 0x62, 0x50, 0xc6,
			0xbc, 0x84, 0x14, 0xf9, 0xbf, 0x50, 0xc8, 0x6c,
			0x2d, 0x72, 0x35, 0xda };

		CK_BYTE           key_data[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
			0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
			0x16, 0x17, 0x18, 0x19 };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		memset( data, 0xCD, 50 );
		data_len = 50;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #4", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #4", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("  C_Sign #4", rc );
			return FALSE;
		}

		if (hash_len != SHA1_HASH_LEN) {
			printf("   Error:  C_Sign #4 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #4 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #4", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #4", rc );
			return FALSE;
		}

		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #4", rc );
			return FALSE;
		}
	}

	// test 5
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[SHA1_HASH_LEN];
		CK_BYTE           data[50];
		CK_BYTE           expect[] = { 0x4c, 0x1a, 0x03, 0x42, 0x4b, 0x55, 0xe0, 0x7f,
			0xe7, 0xf2, 0x7b, 0xe1, 0xd5, 0x8b, 0xb9, 0x32,
			0x4a, 0x9a, 0x5a, 0x04 };

		CK_BYTE           key_data[] = { 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
			0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
			0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		strcpy( (char *)data, "Test With Truncation" );
		data_len = 20;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #5", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #5", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("  C_Sign #5", rc );
			return FALSE;
		}

		if (hash_len != SHA1_HASH_LEN) {
			printf("   Error:  C_Sign #5 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #5 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #5", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #5", rc );
			return FALSE;
		}

		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #5", rc );
			return FALSE;
		}
	}

	// test 6
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[SHA1_HASH_LEN];
		CK_BYTE           data[60];
		CK_BYTE           expect[] = { 0xaa, 0x4a, 0xe5, 0xe1, 0x52, 0x72, 0xd0, 0x0e,
			0x95, 0x70, 0x56, 0x37, 0xce, 0x8a, 0x3b, 0x55,
			0xed, 0x40, 0x21, 0x12 };

		CK_BYTE           key_data[] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		strcpy( (char *)data, "Test Using Larger Than Block-Size Key - Hash Key First" );
		data_len = 54;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #6", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #6", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("  C_Sign #6", rc );
			return FALSE;
		}

		if (hash_len != SHA1_HASH_LEN) {
			printf("   Error:  C_Sign #6 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #6 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #6", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #6", rc );
			return FALSE;
		}

		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #6", rc );
			return FALSE;
		}
	}

	// test 7
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[SHA1_HASH_LEN];
		CK_BYTE           data[80];
		CK_BYTE           expect[] = { 0xe8, 0xe9, 0x9d, 0x0f, 0x45, 0x23, 0x7d, 0x78,
			0x6d, 0x6b, 0xba, 0xa7, 0x96, 0x5c, 0x78, 0x08,
			0xbb, 0xff, 0x1a, 0x91 };

		CK_BYTE           key_data[] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		strcpy( (char *)data, "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data" );
		data_len = 73;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #7", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #7", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("  C_Sign #7", rc );
			return FALSE;
		}

		if (hash_len != SHA1_HASH_LEN) {
			printf("   Error:  C_Sign #7 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #7 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #7", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #7", rc );
			return FALSE;
		}

		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #7", rc );
			return FALSE;
		}
	}


	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc );
		return FALSE;
	}

	printf("Looks okay...\n");
	return TRUE;
}


//
//
int do_SignVerify_SHA1_HMAC_GENERAL( void )
{
	CK_SESSION_HANDLE session;
	CK_SLOT_ID        slot_id;
	CK_MECHANISM      mech;
	CK_ULONG          flags;
	CK_ULONG          hmac_size;
	CK_RV             rc;



	printf("do_SignVerify_SHA1_HMAC_GENERAL...\n");

	slot_id = SLOT_ID;
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return FALSE;
	}

	hmac_size = 4;

	mech.mechanism      = CKM_SHA_1_HMAC_GENERAL;
	mech.ulParameterLen = sizeof(CK_ULONG);
	mech.pParameter     = &hmac_size;

	// test 1
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[SHA1_HASH_LEN];
		CK_BYTE           data[10];
		CK_BYTE           expect[] ={ 0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64,
			0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e,
			0xf1, 0x46, 0xbe, 0x00 };

		CK_BYTE           key_data[] = { 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb,
			0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb,
			0xb, 0xb, 0xb, 0xb };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		memcpy( data, "Hi There", 8 );
		data_len = 8;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #1", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #1", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Sign #1", rc );
			return FALSE;
		}

		if (hash_len != hmac_size) {
			printf("   Error:  C_Sign #1 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #1 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #1", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #1", rc );
			return FALSE;
		}


		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #1", rc );
			return FALSE;
		}
	}


	// test 2
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[SHA1_HASH_LEN];
		CK_BYTE           data[40];
		CK_BYTE           expect[] = { 0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2,
			0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84, 0xdf, 0x9c,
			0x25, 0x9a, 0x7c, 0x79 };

		CK_BYTE           key_data[] = { 'J', 'e', 'f', 'e' };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		memcpy( data, "what do ya want for nothing?", 28 );
		data_len = 28;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #2", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #2", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("  C_Sign #2", rc );
			return FALSE;
		}

		if (hash_len != hmac_size) {
			printf("   Error:  C_Sign #2 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #2 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #2", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #2", rc );
			return FALSE;
		}

		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #2", rc );
			return FALSE;
		}
	}

	// test 3
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[SHA1_HASH_LEN];
		CK_BYTE           data[50];
		CK_BYTE           expect[] = { 0x12, 0x5d, 0x73, 0x42, 0xb9, 0xac, 0x11, 0xcd,
			0x91, 0xa3, 0x9a, 0xf4, 0x8a, 0xa1, 0x7b, 0x4f,
			0x63, 0xf1, 0x75, 0xd3 };

		CK_BYTE           key_data[] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		memset( data, 0xDD, 50 );
		data_len = 50;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #3", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #3", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("  C_Sign #3", rc );
			return FALSE;
		}

		if (hash_len != hmac_size) {
			printf("   Error:  C_Sign #3 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #3 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #3", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #3", rc );
			return FALSE;
		}

		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #3", rc );
			return FALSE;
		}
	}

	// test 4
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[SHA1_HASH_LEN];
		CK_BYTE           data[50];
		CK_BYTE           expect[] = { 0x4c, 0x90, 0x07, 0xf4, 0x02, 0x62, 0x50, 0xc6,
			0xbc, 0x84, 0x14, 0xf9, 0xbf, 0x50, 0xc8, 0x6c,
			0x2d, 0x72, 0x35, 0xda };

		CK_BYTE           key_data[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
			0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
			0x16, 0x17, 0x18, 0x19 };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		memset( data, 0xCD, 50 );
		data_len = 50;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #4", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #4", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("  C_Sign #4", rc );
			return FALSE;
		}

		if (hash_len != hmac_size) {
			printf("   Error:  C_Sign #4 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #4 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #4", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #4", rc );
			return FALSE;
		}

		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #4", rc );
			return FALSE;
		}
	}

	// test 5
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[SHA1_HASH_LEN];
		CK_BYTE           data[50];
		CK_BYTE           expect[] = { 0x4c, 0x1a, 0x03, 0x42, 0x4b, 0x55, 0xe0, 0x7f,
			0xe7, 0xf2, 0x7b, 0xe1, 0xd5, 0x8b, 0xb9, 0x32,
			0x4a, 0x9a, 0x5a, 0x04 };

		CK_BYTE           key_data[] = { 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
			0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
			0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		strcpy( (char *)data, "Test With Truncation" );
		data_len = 20;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #5", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #5", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("  C_Sign #5", rc );
			return FALSE;
		}

		if (hash_len != hmac_size) {
			printf("   Error:  C_Sign #5 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #5 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #5", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #5", rc );
			return FALSE;
		}

		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #5", rc );
			return FALSE;
		}
	}

	// test 6
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[SHA1_HASH_LEN];
		CK_BYTE           data[60];
		CK_BYTE           expect[] = { 0xaa, 0x4a, 0xe5, 0xe1, 0x52, 0x72, 0xd0, 0x0e,
			0x95, 0x70, 0x56, 0x37, 0xce, 0x8a, 0x3b, 0x55,
			0xed, 0x40, 0x21, 0x12 };

		CK_BYTE           key_data[] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		strcpy( (char *)data, "Test Using Larger Than Block-Size Key - Hash Key First" );
		data_len = 54;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #6", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #6", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("  C_Sign #6", rc );
			return FALSE;
		}

		if (hash_len != hmac_size) {
			printf("   Error:  C_Sign #6 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #6 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #6", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #6", rc );
			return FALSE;
		}

		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #6", rc );
			return FALSE;
		}
	}

	// test 7
	//
	{
		CK_OBJECT_HANDLE  h_key;
		CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
		CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
		CK_BBOOL          false      = FALSE;
		CK_BYTE           hash[SHA1_HASH_LEN];
		CK_BYTE           data[80];
		CK_BYTE           expect[] = { 0xe8, 0xe9, 0x9d, 0x0f, 0x45, 0x23, 0x7d, 0x78,
			0x6d, 0x6b, 0xba, 0xa7, 0x96, 0x5c, 0x78, 0x08,
			0xbb, 0xff, 0x1a, 0x91 };

		CK_BYTE           key_data[] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };
		CK_ULONG          hash_len;
		CK_ULONG          data_len;
		CK_ATTRIBUTE      key_attribs[] =
		{
			{CKA_CLASS,       &key_class,        sizeof(key_class)    },
			{CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
			{CKA_TOKEN,       &false,            sizeof(false)        },
			{CKA_VALUE,       &key_data,         sizeof(key_data)     }
		};

		strcpy( (char *)data, "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data" );
		data_len = 73;

		rc = funcs->C_CreateObject( session, key_attribs, 4, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_CreateObject #7", rc );
			return FALSE;
		}

		rc = funcs->C_SignInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_SignInit #7", rc );
			return FALSE;
		}

		hash_len = sizeof(hash);
		rc = funcs->C_Sign( session, data, data_len, hash, &hash_len );
		if (rc != CKR_OK) {
			show_error("  C_Sign #7", rc );
			return FALSE;
		}

		if (hash_len != hmac_size) {
			printf("   Error:  C_Sign #7 generated bad HMAC length\n");
			return FALSE;
		}

		if (memcmp(hash, expect, hash_len) != 0) {
			printf("   Error:  C_Sign #7 generated bad HMAC\n");
			return FALSE;
		}

		rc = funcs->C_VerifyInit( session, &mech, h_key );
		if (rc != CKR_OK) {
			show_error("   C_VerifyInit #7", rc );
			return FALSE;
		}

		rc = funcs->C_Verify( session, data, data_len, hash, hash_len );
		if (rc != CKR_OK) {
			show_error("   C_Verify #7", rc );
			return FALSE;
		}

		rc = funcs->C_DestroyObject( session, h_key );
		if (rc != CKR_OK) {
			show_error("   C_DestroyObject #7", rc );
			return FALSE;
		}
	}


	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc );
		return FALSE;
	}

	printf("Looks okay...\n");
	return TRUE;
}


int digest_functions()
{
	SYSTEMTIME t1, t2;
	int        rc;


	GetSystemTime(&t1);
	rc = do_Digest_SHA1();
	if (!rc && !no_stop)
		return FALSE;
	GetSystemTime(&t2);
	process_time( t1, t2 );

#if MD2
	GetSystemTime(&t1);
	rc = do_Digest_MD2();
	if (!rc && !no_stop)
		return FALSE;
	GetSystemTime(&t2);
	process_time( t1, t2 );
#endif

	GetSystemTime(&t1);
	rc = do_Digest_MD5();
	if (!rc && !no_stop)
		return FALSE;
	GetSystemTime(&t2);
	process_time( t1, t2 );

	GetSystemTime(&t1);
	rc = do_SignVerify_MD5_HMAC();
	if (!rc && !no_stop)
		return FALSE;
	GetSystemTime(&t2);
	process_time( t1, t2 );

	GetSystemTime(&t1);
	rc = do_SignVerify_MD5_HMAC_GENERAL();
	if (!rc && !no_stop)
		return FALSE;
	GetSystemTime(&t2);
	process_time( t1, t2 );

	GetSystemTime(&t1);
	rc = do_SignVerify_SHA1_HMAC();
	if (!rc && !no_stop)
		return FALSE;
	GetSystemTime(&t2);
	process_time( t1, t2 );

	GetSystemTime(&t1);
	rc = do_SignVerify_SHA1_HMAC_GENERAL();
	if (!rc && !no_stop)
		return FALSE;
	GetSystemTime(&t2);
	process_time( t1, t2 );


	//   // these are just speed tests.  they'll take a while to complete
	//   // so don't include them in normal regression testing
	//   //
	//   GetSystemTime(&t1);
	//   rc = do_Digest_SHA1_speed();
	//   if (!rc && !no_stop)
	//      return FALSE;
	//   GetSystemTime(&t2);
	//   process_time( t1, t2 );
	//
	//   GetSystemTime(&t1);
	//   rc = do_Digest_MD5_speed();
	//   if (!rc && !no_stop)
	//      return FALSE;
	//   GetSystemTime(&t2);
	//   process_time( t1, t2 );

	return TRUE;
}

