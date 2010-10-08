//
// Licensed Materials: Property of IBM Corporation
//
// openCryptoki test suite
//
// (C) Copyright IBM Corp. 2006
//
//
// File: rsa_sign_test.c
//
//
// This test tests signing/verifying through PKCS#11, with some operations
// verified with OpenSSL.
//
// First set of tests do the following:
//   for keys of size 512, 1024, 2048
//     generate RSA keypair
//     for hashes of size 20 and keysize-11
//       C_SignInit(CKM_RSA_PKCS)
//       C_Sign
//       C_VerifyInit
//       C_Verify
//
// Second set of tests do:
//   for keys of size 512, 1024, 2048
//     generate RSA keypair
//     for data of sizes 5000, 21
//       for algorithms SHA-1, MD5
//         C_SignInit(CKM_{ALG}_RSA_PKCS)
//         C_Sign
//         C_VerifyInit
//         C_Verify
//         OpenSSL_verify, using OpenSSL generated hash
//
// Author: Kent Yoder <yoder1@us.ibm.com>
// Date: April 3, 2006
//


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include <dlfcn.h>
#include <sys/timeb.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/objects.h>

#include "pkcs11types.h"
#include "regress.h"

int do_GetFunctionList(void);

CK_FUNCTION_LIST  *funcs;

CK_RV
do_OpenSSLVerify(CK_SESSION_HANDLE session, CK_BYTE *signature,
		 CK_ULONG sig_len, CK_BYTE *data, CK_ULONG data_len,
		 CK_OBJECT_HANDLE publ_key, int nid)
{
	CK_RV rv;
	CK_BYTE n[256], e[8];
	CK_ULONG exp_size = 0, mod_size = 0;
	CK_ATTRIBUTE pub_attrs[] = {
		{ CKA_PUBLIC_EXPONENT, NULL, exp_size },
		{ CKA_MODULUS, NULL, mod_size }
	};
	CK_BYTE hash[256];
	RSA *rsa;
	int ver, n_size, e_size, rc;
	unsigned int ihash_len;
	EVP_MD_CTX dgst_ctx;
	EVP_MD *nid_alg = NULL;

	switch (nid) {
		case NID_md5:
			ihash_len = MD5_DIGEST_LENGTH;
			nid_alg = (EVP_MD *)EVP_md5();
			break;
		case NID_sha1:
			ihash_len = SHA_DIGEST_LENGTH;
			nid_alg = (EVP_MD *)EVP_sha1();
			break;
		default:
			PRINT_ERR("Internal test error: Unknown algorithm.");
			break;
	}

	EVP_MD_CTX_init(&dgst_ctx);

	rv = funcs->C_GetAttributeValue(session, publ_key, pub_attrs, 2);
	if (rv != CKR_OK) {
		show_error("   C_GetAttributeValue", rv );
		return rv;
	}

	/* The public exponent is element 0 and modulus is element 1 */
	if (pub_attrs[0].ulValueLen > 8 || pub_attrs[1].ulValueLen > 256) {
		PRINT_ERR("e_size (%lu) or n_size (%lu) too big!",
			  pub_attrs[0].ulValueLen, pub_attrs[1].ulValueLen);
		return CKR_FUNCTION_FAILED;
	}

	pub_attrs[0].pValue = e;
	pub_attrs[1].pValue = n;

	rv = funcs->C_GetAttributeValue(session, publ_key, pub_attrs, 2);
	if (rv != CKR_OK) {
		show_error("   C_GetAttributeValue", rv );
		return rv;
	}

	if ((rsa = RSA_new()) == NULL) {
		PRINT_ERR("RSA_new() failed.");
		return CKR_HOST_MEMORY;
	}

	e_size = pub_attrs[0].ulValueLen;
	n_size = pub_attrs[1].ulValueLen;

        /* set the public key value in the OpenSSL object */
        rsa->n = BN_bin2bn(n, n_size, rsa->n);
        /* set the public exponent */
        rsa->e = BN_bin2bn(e, e_size, rsa->e);

        if (rsa->n == NULL || rsa->e == NULL) {
		PRINT_ERR("Out of memory!");
                rv = CKR_HOST_MEMORY;
                goto done;
        }

	rc = EVP_DigestInit(&dgst_ctx, (const EVP_MD *)nid_alg);
	if (rc != 1) {
		PRINT_ERR("EVP_DigestInit failed.");
		rv = CKR_FUNCTION_FAILED;
		goto done;
	}

	rc = EVP_DigestUpdate(&dgst_ctx, data, data_len);
	if (rc != 1) {
		PRINT_ERR("EVP_DigestUpdate failed.");
		rv = CKR_FUNCTION_FAILED;
		goto done;
	}

	rc = EVP_DigestFinal(&dgst_ctx, hash, &ihash_len);
	if (rc != 1) {
		PRINT_ERR("EVP_DigestFinal failed.");
		rv = CKR_FUNCTION_FAILED;
		goto done;
	}
#if 0
	ver = RSA_public_decrypt(sig_len, signature, tmp, rsa, RSA_NO_PADDING);
	if (ver == -1) {
		PRINT_ERR("OpenSSL public decrypt failed!");
		ERR_print_errors_fp(stderr);
		rv = CKR_FUNCTION_FAILED;
	} else {
		if (ihash_len != ver || memcmp(tmp, hash, ver)) {
			PRINT_ERR("signature failed to verify.");
			rv = CKR_FUNCTION_FAILED;
		} else {
			PRINT("Success.");
		}
	}
#else
	/* RSA object is set up with n and e, now verify using software */
	ver = RSA_verify(nid, hash, ihash_len, signature, sig_len, rsa);
	if (ver != 1) {
		PRINT_ERR("OpenSSL verification failed!");
		rv = CKR_FUNCTION_FAILED;
	} else {
		printf("Success.\n");
		rv = CKR_OK;
	}
#endif

done:
	RSA_free(rsa);

	return rv;
}

CK_RV
do_SignVerALG_RSA_PKCS(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE publ_key,
		    CK_OBJECT_HANDLE priv_key, CK_MECHANISM_TYPE type)
{
   CK_BYTE		signature[256];
   CK_MECHANISM		mech;
   CK_ULONG		i, len1, len2, sig_len;
   CK_RV		rv;
   CK_BYTE		data1[5000];
   CK_BYTE		data2[21];
   char			*alg_string;
   int			nid;

   switch (type) {
	   case CKM_SHA1_RSA_PKCS:
		   nid = NID_sha1;
		   alg_string = "SHA-1";
		   break;
	   case CKM_MD5_RSA_PKCS:
		   nid = NID_md5;
		   alg_string = "MD5";
		   break;
	   default:
		   PRINT_ERR("Internal test error: Unknown algorithm.");
		   return CKR_FUNCTION_FAILED;
		   break;
   }

   printf("do_SignVerALG_RSA_PKCS for algorithm %s...\n", alg_string);


   len1      = sizeof(data1);
   len2      = sizeof(data2);

   for (i=0; i < len1; i++)
      data1[i] = i % 255;
   for (i=0; i < len2; i++)
      data2[i] = i % 255;

   /* sign/ver 5000 bytes with independent OpenSSL verification */

   mech.mechanism      = type;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;


   rv = funcs->C_SignInit(session, &mech, priv_key);
   if (rv != CKR_OK) {
      show_error("   C_SignInit #1", rv );
      goto err_out;
   }

   sig_len = sizeof(signature);
   rv = funcs->C_Sign(session, data1, len1, signature, &sig_len);
   if (rv != CKR_OK) {
      show_error("   C_Sign #1", rv );
      goto err_out;
   }

   rv = funcs->C_VerifyInit(session, &mech, publ_key);
   if (rv != CKR_OK) {
      show_error("   C_VerifyInit #1", rv );
      goto err_out;
   }

   rv = funcs->C_Verify(session, data1, len1, signature, sig_len);
   if (rv != CKR_OK) {
      show_error("   C_Verify #1", rv );
      goto err_out;
   }

   /* Ok, the token signed and verified itself, now lets verify
    * using OpenSSL to see if the outcomes match */
   rv = do_OpenSSLVerify(session, signature, sig_len, data1, len1, publ_key, nid);
   if (rv != CKR_OK) {
      show_error("   do_OpenSSLVerify #1", rv );
      goto err_out;
   }


   /* sign/ver 21 bytes with independent OpenSSL verification */
   rv = funcs->C_SignInit(session, &mech, priv_key);
   if (rv != CKR_OK) {
      show_error("   C_SignInit #2", rv );
      goto err_out;
   }

   sig_len = sizeof(signature);
   rv = funcs->C_Sign(session, data2, len2, signature, &sig_len);
   if (rv != CKR_OK) {
      show_error("   C_Sign #2", rv );
      goto err_out;
   }

   rv = funcs->C_VerifyInit(session, &mech, publ_key);
   if (rv != CKR_OK) {
      show_error("   C_VerifyInit #2", rv );
      goto err_out;
   }

   rv = funcs->C_Verify(session, data2, len2, signature, sig_len);
   if (rv != CKR_OK) {
      show_error("   C_Verify #2", rv );
      goto err_out;
   }

   /* Ok, the token signed and verified itself, now lets verify
    * using OpenSSL to see if the outcomes match */
   rv = do_OpenSSLVerify(session, signature, sig_len, data2, len2, publ_key, nid);
   if (rv != CKR_OK) {
      show_error("   do_OpenSSLVerify #1", rv );
      goto err_out;
   }

   printf("Success.\n");
   return rv;

err_out:
   funcs->C_DestroyObject(session, publ_key);
   funcs->C_DestroyObject(session, priv_key);

   return rv;
}

CK_RV
do_SignVerHASH_RSA_PKCS(CK_SESSION_HANDLE session, CK_ULONG bits,
			CK_BYTE *pub_exp, CK_ULONG exp_size)
{
	CK_RV rv;
	CK_MECHANISM		mech;
	CK_OBJECT_HANDLE	publ_key, priv_key;
	CK_ATTRIBUTE pub_tmpl[] = {
		{CKA_MODULUS_BITS,    &bits,    sizeof(bits)    },
		{CKA_PUBLIC_EXPONENT, pub_exp, exp_size },
	};

	printf("GENERATING %lu bit KEY \n", bits);
	mech.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;

	rv = funcs->C_GenerateKeyPair(session,   &mech,
				      pub_tmpl,   2,
				      NULL,       0,
				      &publ_key, &priv_key );
	if (rv != CKR_OK) {
		show_error("   C_GenerateKeyPair #1", rv );
		return rv;
	}


	if ((rv = do_SignVerALG_RSA_PKCS(session, publ_key, priv_key, CKM_SHA1_RSA_PKCS)))
		return rv;
#if 0
	if ((rv = do_SignVerALG_RSA_PKCS(session, publ_key, priv_key, CKM_MD2_RSA_PKCS)))
		return rv;
#endif
	return do_SignVerALG_RSA_PKCS(session, publ_key, priv_key, CKM_MD5_RSA_PKCS);
}

CK_RV
do_SignVerRSA_PKCS(CK_SESSION_HANDLE session, CK_ULONG bits,
		       CK_BYTE *pub_exp, CK_ULONG exp_size)
{
   CK_BYTE		signature[256];
   CK_MECHANISM		mech;
   CK_OBJECT_HANDLE	publ_key, priv_key;
   CK_ULONG		i;
   CK_ULONG		len1, len2, sig_len;
   CK_RV		rv;

   CK_BYTE		hash1[20];
   CK_BYTE		*hash2;

   CK_ATTRIBUTE pub_tmpl[] = {
      {CKA_MODULUS_BITS,    &bits,    sizeof(bits)    },
      {CKA_PUBLIC_EXPONENT, pub_exp, exp_size },
   };

   printf("do_SignVerRSA_PKCS(%lu bit key)...\n", bits);


   len1      = sizeof(hash1);
   len2      = (bits / 8) - 11;

   hash2 = malloc(len2);
   if (hash2 == NULL) {
	   PRINT_ERR("Out of memory.");
	   return CKR_HOST_MEMORY;
   }

   for (i=0; i < len1; i++)
      hash1[i] = i % 255;
   for (i=0; i < len2; i++)
      hash2[i] = i % 255;

   printf("GENERATING %lu bit KEY \n", bits);
   mech.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   rv = funcs->C_GenerateKeyPair( session,   &mech,
                                  pub_tmpl,   2,
                                  NULL,       0,
                                  &publ_key, &priv_key );
   if (rv != CKR_OK) {
      show_error("   C_GenerateKeyPair #1", rv );
      free(hash2);
      return rv;
   }

   mech.mechanism      = CKM_RSA_PKCS;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;


   /* sign/ver the SHA1 hash sized chunk */
   rv = funcs->C_SignInit(session, &mech, priv_key);
   if (rv != CKR_OK) {
      show_error("   C_SignInit #1", rv );
      goto err_out;
   }

   sig_len = sizeof(signature);
   rv = funcs->C_Sign(session, hash1, len1, signature, &sig_len);
   if (rv != CKR_OK) {
      show_error("   C_Sign #1", rv );
      goto err_out;
   }

   rv = funcs->C_VerifyInit(session, &mech, publ_key);
   if (rv != CKR_OK) {
      show_error("   C_VerifyInit #1", rv );
      goto err_out;
   }

   rv = funcs->C_Verify(session, hash1, len1, signature, sig_len);
   if (rv != CKR_OK) {
      show_error("   C_Verify #1", rv );
      goto err_out;
   }


   /* sign/ver the n-11 hash sized chunk */
   rv = funcs->C_SignInit(session, &mech, priv_key);
   if (rv != CKR_OK) {
      show_error("   C_SignInit #2", rv );
      goto err_out;
   }

   sig_len = sizeof(signature);
   rv = funcs->C_Sign(session, hash2, len2, signature, &sig_len);
   if (rv != CKR_OK) {
      show_error("   C_Sign #2", rv );
      goto err_out;
   }

   rv = funcs->C_VerifyInit(session, &mech, publ_key);
   if (rv != CKR_OK) {
      show_error("   C_VerifyInit #2", rv );
      goto err_out;
   }

   rv = funcs->C_Verify(session, hash2, len2, signature, sig_len);
   if (rv != CKR_OK) {
      show_error("   C_Verify #2", rv );
      goto err_out;
   }

err_out:
   free(hash2);
   funcs->C_DestroyObject(session, publ_key);
   funcs->C_DestroyObject(session, priv_key);

   printf("Success.\n");
   return rv;
}

CK_RV
do_SignVerTests(CK_SESSION_HANDLE session)
{
	CK_BYTE two_16p1[] = { 0x01, 0x00, 0x01 };
	CK_RV rv;
#if 0
	CK_BYTE three[] = { 0x03 };

	/* 3 doesn't work as a pub exp for the TPM token */

	/* 3 as public exponent */
	rv = do_SignVerRSA_PKCS(session, 512, three, sizeof(three));
	if (rv != CKR_OK) {
		show_error("do_SignVerRSA_PKCS", rv);
		return rv;
	}

	rv = do_SignVerRSA_PKCS(session, 1024, three, sizeof(three));
	if (rv != CKR_OK) {
		show_error("do_SignVerRSA_PKCS", rv);
		return rv;
	}

	rv = do_SignVerRSA_PKCS(session, 2048, three, sizeof(three));
	if (rv != CKR_OK) {
		show_error("do_SignVerRSA_PKCS", rv);
		return rv;
	}
#endif
	/* 65537 as public exponent */
	rv = do_SignVerRSA_PKCS(session, 512, two_16p1, sizeof(two_16p1));
	if (rv != CKR_OK) {
		show_error("do_SignVerRSA_PKCS", rv);
		return rv;
	}

	rv = do_SignVerRSA_PKCS(session, 1024, two_16p1, sizeof(two_16p1));
	if (rv != CKR_OK) {
		show_error("do_SignVerRSA_PKCS", rv);
		return rv;
	}

	rv = do_SignVerRSA_PKCS(session, 2048, two_16p1, sizeof(two_16p1));
	if (rv != CKR_OK) {
		show_error("do_SignVerRSA_PKCS", rv);
		return rv;
	}

	rv = do_SignVerHASH_RSA_PKCS(session, 512, two_16p1, sizeof(two_16p1));
	if (rv != CKR_OK) {
		show_error("do_SignVerHASH_RSA_PKCS", rv);
		return rv;
	}

	rv = do_SignVerHASH_RSA_PKCS(session, 1024, two_16p1, sizeof(two_16p1));
	if (rv != CKR_OK) {
		show_error("do_SignVerHASH_RSA_PKCS", rv);
		return rv;
	}

	rv = do_SignVerHASH_RSA_PKCS(session, 2048, two_16p1, sizeof(two_16p1));
	if (rv != CKR_OK) {
		show_error("do_SignVerHASH_RSA_PKCS", rv);
		return rv;
	}

	return rv;
}

//
//
int
main( int argc, char **argv )
{
   CK_C_INITIALIZE_ARGS  cinit_args;
   int        rv, i;
   CK_SESSION_HANDLE	session;
   CK_BBOOL      no_init;
   no_init = FALSE;
   CK_FLAGS flags;
   CK_BYTE		user_pin[128];
   CK_ULONG		user_pin_len;
   CK_SLOT_ID		slot_id = 0;


   for (i=1; i < argc; i++) {
      if (strcmp(argv[i], "-slot") == 0) {
         slot_id = atoi(argv[i+1]);
         i++;
      }
      if (strcmp(argv[i], "-noinit") == 0)
         no_init = TRUE;

      if (strcmp(argv[i], "-h") == 0) {
         printf("usage:  %s [-slot <num>] [-h]\n\n", argv[0] );
         printf("By default, Slot 0 is used\n\n");
         return 0;
      }
   }

   ERR_load_crypto_strings();

   printf("Using slot %d...\n\n", (int)slot_id );

   rv = do_GetFunctionList();
   if (rv != TRUE) {
	   show_error("do_GetFunctionList", rv);
	   return rv;
   }

   memset( &cinit_args, 0x0, sizeof(cinit_args) );
   cinit_args.flags = CKF_OS_LOCKING_OK;

   // SAB Add calls to ALL functions before the C_Initialize gets hit

   rv = funcs->C_Initialize( &cinit_args );
   if (rv != CKR_OK) {
	   show_error("C_Initialize", rv);
	   return rv;
   }

   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rv = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
   if (rv != CKR_OK) {
      show_error("   C_OpenSession #1", rv );
      return rv;
   }


   if (get_user_pin(user_pin))
	   return CKR_FUNCTION_FAILED;
   user_pin_len = (CK_ULONG)strlen((char *)user_pin);

   rv = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
   if (rv != CKR_OK) {
      show_error("   C_Login #1", rv );
      return rv;
   }

   rv = do_SignVerTests(session);
   if (rv != CKR_OK) {
      funcs->C_CloseAllSessions( slot_id );
      return rv;
   }

   rv = funcs->C_CloseAllSessions( slot_id );
   if (rv != CKR_OK) {
      show_error("   C_CloseAllSessions #1", rv );
      return rv;
   }

   rv = funcs->C_Finalize( NULL );
   if (rv != CKR_OK) {
	   show_error("C_Finalize", rv);
	   return rv;
   }

   return 0;
}
