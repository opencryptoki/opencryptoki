// File: rsa_func.c
//

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"



void hex_dump_to_file(char *str, unsigned char *data, int bytes)
{
   FILE *fp;
   fp = fopen("rsadump.h", "a");
   fprintf(fp, "\nunsigned char %s[] =\n                  {", str);
   while (bytes--)
   {
      fprintf(fp, " 0x%x", *data++);
      if (bytes)
      {
         fprintf(fp, ",");
         if (!(bytes % 8))
            fprintf(fp, "\n                   ");
      }
   }
   fprintf(fp, " };\n");
   fclose(fp);
}

//
//
int do_GenerateRSAKeyPair( void )
{
   CK_SLOT_ID          slot_id;
   CK_SESSION_HANDLE   session;
   CK_MECHANISM        mech;
   CK_OBJECT_HANDLE    publ_key, priv_key;
   CK_FLAGS            flags;
   CK_BYTE             user_pin[DEFAULT_USER_PIN_LEN];
   CK_ULONG            user_pin_len;
   CK_RV               rc;


   printf("do_GenerateRSAKey...\n");

   slot_id = SLOT_ID;

   memcpy( user_pin, DEFAULT_USER_PIN, DEFAULT_USER_PIN_LEN );
   user_pin_len = DEFAULT_USER_PIN_LEN;

   mech.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   {
      CK_ULONG  bits = 1024;
      CK_BYTE   pub_exp[] = { 0x3 };

      CK_ATTRIBUTE pub_tmpl[] =
      {
         {CKA_MODULUS_BITS,    &bits,    sizeof(bits)    },
         {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp) }
      };

      flags = CKF_SERIAL_SESSION;
      rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
      if (rc != CKR_OK) {
         show_error("   C_OpenSession #3", rc );
         return FALSE;
      }

      rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
      if (rc != CKR_OK) {
         show_error("   C_Login #1", rc );
         return FALSE;
      }

      rc = funcs->C_GenerateKeyPair( session,   &mech,
                                     pub_tmpl,   2,
                                     NULL,       0,
                                     &publ_key, &priv_key );
      if (rc != CKR_OK) {
         show_error("   C_GenerateKeyPair #1", rc );
         return FALSE;
      }

      rc = funcs->C_CloseSession( session );
      if (rc != CKR_OK) {
         show_error("   C_CloseSession #3", rc );
         return FALSE;
      }
   }

   printf("Looks okay...\n");
   return TRUE;
}



//
//
int do_EncryptRSA_PKCS( void )
{
   CK_BYTE             data1[100];
   CK_BYTE             data2[256];
   CK_BYTE             cipher[256];
   CK_SLOT_ID          slot_id;
   CK_SESSION_HANDLE   session;
   CK_MECHANISM        mech;
   CK_OBJECT_HANDLE    publ_key, priv_key;
   CK_FLAGS            flags;
   CK_BYTE             user_pin[DEFAULT_USER_PIN_LEN];
   CK_ULONG            user_pin_len;
   CK_ULONG            i;
   CK_ULONG            len1, len2, cipherlen;
   CK_RV               rc;

   CK_ULONG  bits = 1024;
   CK_BYTE   pub_exp[] = { 0x3 };

   CK_ATTRIBUTE pub_tmpl[] =
   {
      {CKA_MODULUS_BITS,    &bits,    sizeof(bits)    },
      {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp) }
   };

   printf("do_EncryptRSA_PKCS...\n");

   slot_id = SLOT_ID;
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      return FALSE;
   }


   memcpy( user_pin, DEFAULT_USER_PIN, DEFAULT_USER_PIN_LEN );
   user_pin_len = DEFAULT_USER_PIN_LEN;

   rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #1", rc );
      return FALSE;
   }

   mech.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   rc = funcs->C_GenerateKeyPair( session,   &mech,
                                  pub_tmpl,   2,
                                  NULL,       0,
                                  &publ_key, &priv_key );
   if (rc != CKR_OK) {
      show_error("   C_GenerateKeyPair #1", rc );
      return FALSE;
   }

   // now, encrypt some data
   //
   len1      = sizeof(data1);
   len2      = sizeof(data2);
   cipherlen = sizeof(cipher);

   for (i=0; i < len1; i++)
      data1[i] = i % 255;

   mech.mechanism      = CKM_RSA_PKCS;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   rc = funcs->C_EncryptInit( session, &mech, publ_key );
   if (rc != CKR_OK) {
      show_error("   C_EncryptInit #1", rc );
      return FALSE;
   }

   rc = funcs->C_Encrypt( session, data1, len1, cipher, &cipherlen );
   if (rc != CKR_OK) {
      show_error("   C_Encrypt #1", rc );
      return FALSE;
   }

   printf("Cipyer len %d \n",cipherlen);

   // now, decrypt the data
   //
   rc = funcs->C_DecryptInit( session, &mech, priv_key );
   if (rc != CKR_OK) {
      show_error("   C_DecryptInit #1", rc );
      return FALSE;
   }

   rc = funcs->C_Decrypt( session, cipher, cipherlen, data2, &len2 );
   if (rc != CKR_OK) {
      show_error("   C_Decrypt #1", rc );
      return FALSE;
   }

   printf("Len from encrypt %d  from decrypt %d \n",len1, len2);
   //if (len1 != len2) {
   //   printf("   ERROR:  lengths don't match\n");
   //   return FALSE;
  // }

   for (i=0; i <len1; i++) {
      if (data1[i] != data2[i]) {
         printf("   ERROR:  mismatch at byte %d\n", i );
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
int do_EncryptRSA_PKCS_Speed( void )
{
   CK_BYTE             data1[100];
   CK_BYTE             data2[256];
   CK_BYTE             cipher[256];
   CK_SLOT_ID          slot_id;
   CK_SESSION_HANDLE   session;
   CK_MECHANISM        mech;
   CK_OBJECT_HANDLE    publ_key, priv_key;
   CK_FLAGS            flags;
   CK_BYTE             user_pin[DEFAULT_USER_PIN_LEN];
   CK_ULONG            user_pin_len;
   CK_ULONG            i;
   CK_ULONG            len1, len2, cipherlen;
   CK_RV               rc;
   SYSTEMTIME          t1, t2;

   CK_ULONG  bits = 1024;
   CK_BYTE   pub_exp[] = { 0x3 };

   CK_ATTRIBUTE pub_tmpl[] =
   {
      {CKA_MODULUS_BITS,    &bits,    sizeof(bits)    },
      {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp) }
   };

   printf("do_EncryptRSA_PKCS_Speed...\n");

   slot_id = SLOT_ID;
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      return FALSE;
   }


   memcpy( user_pin, DEFAULT_USER_PIN, DEFAULT_USER_PIN_LEN );
   user_pin_len = DEFAULT_USER_PIN_LEN;

   rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #1", rc );
      return FALSE;
   }

   mech.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   rc = funcs->C_GenerateKeyPair( session,   &mech,
                                  pub_tmpl,   2,
                                  NULL,       0,
                                  &publ_key, &priv_key );
   if (rc != CKR_OK) {
      show_error("   C_GenerateKeyPair #1", rc );
      return FALSE;
   }

   // now, encrypt some data
   //
   len1      = sizeof(data1);
   len2      = sizeof(data2);
   cipherlen = sizeof(cipher);

   for (i=0; i < len1; i++)
      data1[i] = i % 255;

   mech.mechanism      = CKM_RSA_PKCS;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   printf("Doing 300 encryptions...\n");
   GetSystemTime(&t1);

#define NUM  300
   for (i=0; i < NUM; i++) {
      cipherlen = sizeof(cipher);

      rc = funcs->C_EncryptInit( session, &mech, publ_key );
      if (rc != CKR_OK) {
         show_error("   C_EncryptInit #1", rc );
         return FALSE;
      }

      rc = funcs->C_Encrypt( session, data1, len1, cipher, &cipherlen );
      if (rc != CKR_OK) {
         show_error("   C_Encrypt #1", rc );
         return FALSE;
      }
   }

   GetSystemTime(&t2);
   process_time( t1, t2 );

   printf("Doing 300 decryptions...\n");
   GetSystemTime(&t1);

   for (i=0; i < NUM; i++) {
      len2 = 256;

      rc = funcs->C_DecryptInit( session, &mech, priv_key );
      if (rc != CKR_OK) {
         show_error("   C_DecryptInit #1", rc );
         return FALSE;
      }

      rc = funcs->C_Decrypt( session, cipher, cipherlen, data2, &len2 );
      if (rc != CKR_OK) {
         show_error("   C_Decrypt #1", rc );
         return FALSE;
      }
   }

   GetSystemTime(&t2);
   process_time( t1, t2 );
   printf("\n");

   if (len1 != len2) {
      printf("   ERROR:  lengths don't match %d  %d \n",len1,len2);
      return FALSE;
   }

   for (i=0; i <len1; i++) {
      if (data1[i] != data2[i]) {
         printf("   ERROR:  mismatch at byte %d\n", i );
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
int do_SignRSA_PKCS( void )
{
   CK_BYTE             data1[100];
   CK_BYTE             data2[256];
   CK_BYTE             signature[256];
   CK_SLOT_ID          slot_id;
   CK_SESSION_HANDLE   session;
   CK_MECHANISM        mech;
   CK_OBJECT_HANDLE    publ_key, priv_key;
   CK_FLAGS            flags;
   CK_BYTE             user_pin[DEFAULT_USER_PIN_LEN];
   CK_ULONG            user_pin_len;
   CK_ULONG            i;
   CK_ULONG            len1, len2, sig_len;
   CK_RV               rc;

   CK_ULONG  bits = 1024;
   CK_BYTE   pub_exp[] = { 0x3 };

   CK_ATTRIBUTE pub_tmpl[] =
   {
      {CKA_MODULUS_BITS,    &bits,    sizeof(bits)    },
      {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp) }
   };

   printf("do_SignRSA_PKCS...\n");

   slot_id = SLOT_ID;
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      return FALSE;
   }


   memcpy( user_pin, DEFAULT_USER_PIN, DEFAULT_USER_PIN_LEN );
   user_pin_len = DEFAULT_USER_PIN_LEN;

   rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #1", rc );
      return FALSE;
   }

   mech.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   rc = funcs->C_GenerateKeyPair( session,   &mech,
                                  pub_tmpl,   2,
                                  NULL,       0,
                                  &publ_key, &priv_key );
   if (rc != CKR_OK) {
      show_error("   C_GenerateKeyPair #1", rc );
      return FALSE;
   }

   // now, encrypt some data
   //
   len1 = sizeof(data1);
   len2 = sizeof(data2);
   sig_len = sizeof(signature);

   for (i=0; i < len1; i++)
      data1[i] = i % 255;

   mech.mechanism      = CKM_RSA_PKCS;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   rc = funcs->C_SignInit( session, &mech, priv_key );
   if (rc != CKR_OK) {
      show_error("   C_SignInit #1", rc );
      return FALSE;
   }

   rc = funcs->C_Sign( session, data1, len1, signature, &sig_len );
   if (rc != CKR_OK) {
      show_error("   C_Sign #1", rc );
      return FALSE;
   }

   // now, verify the signature
   //
   rc = funcs->C_VerifyInit( session, &mech, publ_key );
   if (rc != CKR_OK) {
      show_error("   C_VerifyInit #1", rc );
      return FALSE;
   }

   rc = funcs->C_Verify( session, data1, len1, signature, sig_len );
   if (rc != CKR_OK) {
      show_error("   C_Verify #1", rc );
      return FALSE;
   }

   // now, corrupt the signature and try to re-verify.
   //
   signature[50] = signature[50] + 1;

   rc = funcs->C_VerifyInit( session, &mech, publ_key );
   if (rc != CKR_OK) {
      show_error("   C_VerifyInit #2", rc );
      return FALSE;
   }

   rc = funcs->C_Verify( session, data1, len1, signature, sig_len );
   if (rc != CKR_SIGNATURE_INVALID) {
      show_error("   C_Verify #2", rc );
      printf("   Expected CKR_SIGNATURE_INVALID\n");
      return FALSE;
   }


   // now, try a SignRecover/VerifyRecover operation
   //
   rc = funcs->C_SignRecoverInit( session, &mech, priv_key );
   if (rc != CKR_OK) {
      show_error("   C_SignRecoverInit #1", rc );
      return FALSE;
   }

   sig_len = sizeof(signature);
   rc = funcs->C_SignRecover( session, data1, len1, signature, &sig_len );
   if (rc != CKR_OK) {
      show_error("   C_SignRecover #1", rc );
      return FALSE;
   }

   // now, verify the signature
   //
   rc = funcs->C_VerifyRecoverInit( session, &mech, publ_key );
   if (rc != CKR_OK) {
      show_error("   C_VerifyRecoverInit #1", rc );
      return FALSE;
   }

   rc = funcs->C_VerifyRecover( session, signature, sig_len, data2, &len2 );
   if (rc != CKR_OK) {
      show_error("   C_VerifyRecover #1", rc );
      return FALSE;
   }

   if (len1 != len2) {
      printf("   ERROR:  recovered length mismatch\n");
      return FALSE;
   }

   if (memcmp(data1, data2, len1) != 0) {
      printf("   ERROR;  data mismatch\n");
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
int do_WrapUnwrapRSA_PKCS( void )
{
   CK_BYTE             original    [BIG_REQUEST];
   CK_BYTE             crypt       [BIG_REQUEST];
   CK_BYTE             decrypt     [BIG_REQUEST];
   CK_BYTE             wrapped_data[BIG_REQUEST];

   CK_SLOT_ID          slot_id;
   CK_SESSION_HANDLE   session;
   CK_MECHANISM        mech_des, mech_rsa;
   CK_OBJECT_HANDLE    publ_key, priv_key;
   CK_OBJECT_HANDLE    des_key;
   CK_OBJECT_HANDLE    uw_key;
   CK_FLAGS            flags;
   CK_BYTE             user_pin[DEFAULT_USER_PIN_LEN];
   CK_ULONG            user_pin_len;
   CK_ULONG            wrapped_data_len;
   CK_ULONG            i;
   CK_ULONG            orig_len, crypt_len, decrypt_len;
   CK_RV               rc;

   CK_OBJECT_CLASS     key_class = CKO_SECRET_KEY;
   CK_KEY_TYPE         key_type  = CKK_DES;
   CK_ATTRIBUTE   des_tmpl[] =
   {
      { CKA_CLASS,     &key_class,  sizeof(key_class) },
      { CKA_KEY_TYPE,  &key_type,   sizeof(key_type)  }
   };

   CK_ULONG  bits = 1024;
   CK_BYTE   pub_exp[] = { 0x3 };
   CK_ATTRIBUTE pub_tmpl[] =
   {
      {CKA_MODULUS_BITS,    &bits,    sizeof(bits)    },
      {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp) }
   };


   printf("do_WrapUnwrapRSA_PKCS...\n");

   slot_id = SLOT_ID;
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      return FALSE;
   }


   memcpy( user_pin, DEFAULT_USER_PIN, DEFAULT_USER_PIN_LEN );
   user_pin_len = DEFAULT_USER_PIN_LEN;

   rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #1", rc );
      goto error;
   }

   mech_des.mechanism      = CKM_DES_KEY_GEN;
   mech_des.ulParameterLen = 0;
   mech_des.pParameter     = NULL;


   // first, generate a DES key and a RSA keypair
   //
   rc = funcs->C_GenerateKey( session, &mech_des, NULL, 0, &des_key );
   if (rc != CKR_OK) {
      show_error("   C_GenerateKey #1", rc );
      goto error;
   }

   mech_rsa.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
   mech_rsa.ulParameterLen = 0;
   mech_rsa.pParameter     = NULL;

   rc = funcs->C_GenerateKeyPair( session,   &mech_rsa,
                                  pub_tmpl,   2,
                                  NULL,       0,
                                  &publ_key, &priv_key );
   if (rc != CKR_OK) {
      show_error("   C_GenerateKeyPair #1", rc );
      goto error;
   }


   // now, encrypt some data using the DES key
   //
   orig_len = sizeof(original);
   for (i=0; i < orig_len; i++) {
      original[i] = i % 255;
   }

   mech_des.mechanism      = CKM_DES_ECB;
   mech_des.ulParameterLen = 0;
   mech_des.pParameter     = NULL;

   rc = funcs->C_EncryptInit( session, &mech_des, des_key );
   if (rc != CKR_OK) {
      show_error("   C_EncryptInit #1", rc );
      goto error;
   }

   crypt_len = sizeof(crypt);
   rc = funcs->C_Encrypt( session, original, orig_len, crypt, &crypt_len );
   if (rc != CKR_OK) {
      show_error("   C_Encrypt #1", rc );
      goto error;
   }


   // now, wrap the DES key using the RSA private key
   //
   mech_rsa.mechanism      = CKM_RSA_PKCS;
   mech_rsa.ulParameterLen = 0;
   mech_rsa.pParameter     = NULL;

   wrapped_data_len = sizeof(wrapped_data);

   rc = funcs->C_WrapKey( session,         &mech_rsa,
                          publ_key,         des_key,
                         &wrapped_data[0], &wrapped_data_len );
   if (rc != CKR_OK) {
      show_error("   C_WrapKey #1", rc );
      goto error;
   }

   // unwrap the DES key using the public key
   //
   rc = funcs->C_UnwrapKey( session,      &mech_rsa,
                            priv_key,
                            wrapped_data, wrapped_data_len,
                            des_tmpl,     2,
                            &uw_key );
   if (rc != CKR_OK) {
      show_error("   C_UnWrapKey #1", rc );
      goto error;
   }

   // now, decrypt the data using the unwrapped key.
   //
   rc = funcs->C_DecryptInit( session, &mech_des, uw_key );
   if (rc != CKR_OK) {
      show_error("   C_DecryptInit #1", rc );
      goto error;
   }

   decrypt_len = sizeof(decrypt);
   rc = funcs->C_Decrypt( session, crypt, crypt_len, decrypt, &decrypt_len );
   if (rc != CKR_OK) {
      show_error("   C_Decrypt #1", rc );
      goto error;
   }

   if (decrypt_len != orig_len) {
      printf("   ERROR:  lengths don't match\n");
      goto error;
   }

   for (i=0; i < orig_len; i++) {
      if (original[i] != decrypt[i]) {
         printf("   ERROR:  mismatch at byte %d\n", i );
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
      CK_OBJECT_HANDLE new_priv_key;
      CK_BYTE data[1024];
      CK_ULONG data_len = sizeof(data);


      rc = funcs->C_CreateObject( session, tmpl, 10, &new_priv_key );
      if (rc != CKR_OK) {
         show_error("   C_CreateObject #1", rc );
         goto error;
      }

      rc = funcs->C_WrapKey( session,   &mech_rsa,
                             priv_key,   new_priv_key,
                             data,      &data_len );
      if (rc != CKR_KEY_NOT_WRAPPABLE) {
         show_error("   C_WrapKey #2", rc );
         printf("   Expected CKR_KEY_NOT_WRAPPABLE\n" );
         goto error;
      }
   }

   rc = funcs->C_CloseAllSessions( slot_id );
   if (rc != CKR_OK) {
      show_error("   C_CloseAllSessions #1", rc );
      return FALSE;
   }

   printf("Looks okay...\n");
   return TRUE;

error:
   rc = funcs->C_CloseSession (session);
   if (rc != CKR_OK)
      show_error ("   C_CloseSession #2", rc);
   
   return FALSE;
}


//
//
int do_EncryptRSA_X509( void )
{
   CK_BYTE             data1[100];
   CK_BYTE             data2[256];
   CK_BYTE             cipher[256];
   CK_SLOT_ID          slot_id;
   CK_SESSION_HANDLE   session;
   CK_MECHANISM        mech;
   CK_OBJECT_HANDLE    publ_key, priv_key;
   CK_FLAGS            flags;
   CK_BYTE             user_pin[DEFAULT_USER_PIN_LEN];
   CK_ULONG            user_pin_len;
   CK_ULONG            i;
   CK_ULONG            len1, len2, cipherlen, pad_len;
   CK_RV               rc;

   CK_ULONG  bits = 1024;
   CK_BYTE   pub_exp[] = { 0x3 };

   CK_ATTRIBUTE pub_tmpl[] =
   {
      {CKA_MODULUS_BITS,    &bits,    sizeof(bits)    },
      {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp) }
   };

   printf("do_EncryptRSA_X509...\n");

   slot_id = SLOT_ID;
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      return FALSE;
   }


   memcpy( user_pin, DEFAULT_USER_PIN, DEFAULT_USER_PIN_LEN );
   user_pin_len = DEFAULT_USER_PIN_LEN;

   rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #1", rc );
      return FALSE;
   }

   mech.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   rc = funcs->C_GenerateKeyPair( session,   &mech,
                                  pub_tmpl,   2,
                                  NULL,       0,
                                  &publ_key, &priv_key );
   if (rc != CKR_OK) {
      show_error("   C_GenerateKeyPair #1", rc );
      return FALSE;
   }

   // now, encrypt some data
   //
   len1      = sizeof(data1);
   len2      = sizeof(data2);
   cipherlen = sizeof(cipher);

   for (i=0; i < len1; i++)
      data1[i] = i % 255;

   mech.mechanism      = CKM_RSA_X_509;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   rc = funcs->C_EncryptInit( session, &mech, publ_key );
   if (rc != CKR_OK) {
      show_error("   C_EncryptInit #1", rc );
      return FALSE;
   }

   rc = funcs->C_Encrypt( session, data1, len1, cipher, &cipherlen );
   if (rc != CKR_OK) {
      show_error("   C_Encrypt #1", rc );
      return FALSE;
   }

   // now, decrypt the data
   //
   rc = funcs->C_DecryptInit( session, &mech, priv_key );
   if (rc != CKR_OK) {
      show_error("   C_DecryptInit #1", rc );
      return FALSE;
   }

   rc = funcs->C_Decrypt( session, cipher, cipherlen, data2, &len2 );
   if (rc != CKR_OK) {
      show_error("   C_Decrypt #1", rc );
      return FALSE;
   }

   // X509 prepads with zero bytes.  Decrypting does not remove the
   // padding according to the standard so we need to skip the padding
   // here
   //
   pad_len = len2 - len1;

   if (memcmp(data1, &data2[pad_len], len1) != 0) {
      printf("   ERROR:  mismatch at byte %d\n", i );
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
int do_SignRSA_X509( void )
{
   CK_BYTE             data1[100];
   CK_BYTE             data2[256];
   CK_BYTE             signature[256];
   CK_SLOT_ID          slot_id;
   CK_SESSION_HANDLE   session;
   CK_MECHANISM        mech;
   CK_OBJECT_HANDLE    publ_key, priv_key;
   CK_FLAGS            flags;
   CK_BYTE             user_pin[DEFAULT_USER_PIN_LEN];
   CK_ULONG            user_pin_len;
   CK_ULONG            i, pad_len;
   CK_ULONG            len1, len2, sig_len;
   CK_RV               rc;

   CK_ULONG  bits = 1024;
   CK_BYTE   pub_exp[] = { 0x3 };

   CK_ATTRIBUTE pub_tmpl[] =
   {
      {CKA_MODULUS_BITS,    &bits,    sizeof(bits)    },
      {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp) }
   };

   printf("do_SignRSA_PKCS...\n");

   slot_id = SLOT_ID;
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      return FALSE;
   }


   memcpy( user_pin, DEFAULT_USER_PIN, DEFAULT_USER_PIN_LEN );
   user_pin_len = DEFAULT_USER_PIN_LEN;

   rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #1", rc );
      return FALSE;
   }

   mech.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   rc = funcs->C_GenerateKeyPair( session,   &mech,
                                  pub_tmpl,   2,
                                  NULL,       0,
                                  &publ_key, &priv_key );
   if (rc != CKR_OK) {
      show_error("   C_GenerateKeyPair #1", rc );
      return FALSE;
   }

   // now, encrypt some data
   //
   len1 = sizeof(data1);
   len2 = sizeof(data2);
   sig_len = sizeof(signature);

   for (i=0; i < len1; i++)
      data1[i] = i % 255;

   mech.mechanism      = CKM_RSA_X_509;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   rc = funcs->C_SignInit( session, &mech, priv_key );
   if (rc != CKR_OK) {
      show_error("   C_SignInit #1", rc );
      return FALSE;
   }

   rc = funcs->C_Sign( session, data1, len1, signature, &sig_len );
   if (rc != CKR_OK) {
      show_error("   C_Sign #1", rc );
      return FALSE;
   }

   // now, verify the signature
   //
   rc = funcs->C_VerifyInit( session, &mech, publ_key );
   if (rc != CKR_OK) {
      show_error("   C_VerifyInit #1", rc );
      return FALSE;
   }

   rc = funcs->C_Verify( session, data1, len1, signature, sig_len );
   if (rc != CKR_OK) {
      show_error("   C_Verify #1", rc );
      return FALSE;
   }

   // now, corrupt the signature and try to re-verify.
   //
   signature[50] = signature[50] + 1;

   rc = funcs->C_VerifyInit( session, &mech, publ_key );
   if (rc != CKR_OK) {
      show_error("   C_VerifyInit #2", rc );
      return FALSE;
   }

   rc = funcs->C_Verify( session, data1, len1, signature, sig_len );
   if (rc != CKR_SIGNATURE_INVALID) {
      show_error("   C_Verify #2", rc );
      printf("   Expected CKR_SIGNATURE_INVALID\n");
      return FALSE;
   }


   // now, try a SignRecover/VerifyRecover operation
   //
   rc = funcs->C_SignRecoverInit( session, &mech, priv_key );
   if (rc != CKR_OK) {
      show_error("   C_SignRecoverInit #1", rc );
      return FALSE;
   }

   sig_len = sizeof(signature);
   rc = funcs->C_SignRecover( session, data1, len1, signature, &sig_len );
   if (rc != CKR_OK) {
      show_error("   C_SignRecover #1", rc );
      return FALSE;
   }

   // now, verify the signature
   //
   rc = funcs->C_VerifyRecoverInit( session, &mech, publ_key );
   if (rc != CKR_OK) {
      show_error("   C_VerifyRecoverInit #1", rc );
      return FALSE;
   }

   rc = funcs->C_VerifyRecover( session, signature, sig_len, data2, &len2 );
   if (rc != CKR_OK) {
      show_error("   C_VerifyRecover #1", rc );
      return FALSE;
   }

   // X.509 pads by prepending null bytes.  The verify recover operation
   // does not remove the padding.  We have to do it here
   //
   pad_len = len2 - len1;

   if (memcmp(data1, &data2[pad_len], len1) != 0) {
      printf("   ERROR;  data mismatch\n");
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
int do_WrapUnwrapRSA_X509( void )
{
   CK_BYTE             original    [BIG_REQUEST];
   CK_BYTE             crypt       [BIG_REQUEST];
   CK_BYTE             decrypt     [BIG_REQUEST];
   CK_BYTE             wrapped_data[BIG_REQUEST];

   CK_SLOT_ID          slot_id;
   CK_SESSION_HANDLE   session;
   CK_MECHANISM        mech_des, mech_rsa;
   CK_OBJECT_HANDLE    publ_key, priv_key;
   CK_OBJECT_HANDLE    des_key;
   CK_OBJECT_HANDLE    uw_key;
   CK_FLAGS            flags;
   CK_BYTE             user_pin[DEFAULT_USER_PIN_LEN];
   CK_ULONG            user_pin_len;
   CK_ULONG            wrapped_data_len;
   CK_ULONG            i;
   CK_ULONG            orig_len, crypt_len, decrypt_len;
   CK_RV               rc;

   CK_OBJECT_CLASS     key_class = CKO_SECRET_KEY;
   CK_KEY_TYPE         key_type  = CKK_DES;
   CK_ATTRIBUTE   des_tmpl[] =
   {
      { CKA_CLASS,     &key_class,  sizeof(key_class) },
      { CKA_KEY_TYPE,  &key_type,   sizeof(key_type)  }
   };

   CK_ULONG  bits = 1024;
   CK_BYTE   pub_exp[] = { 0x3 };
   CK_ATTRIBUTE pub_tmpl[] =
   {
      {CKA_MODULUS_BITS,    &bits,    sizeof(bits)    },
      {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp) }
   };


   printf("do_WrapUnwrapRSA_X509...\n");

   slot_id = SLOT_ID;
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      return FALSE;
   }


   memcpy( user_pin, DEFAULT_USER_PIN, DEFAULT_USER_PIN_LEN );
   user_pin_len = DEFAULT_USER_PIN_LEN;

   rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #1", rc );
      goto error;
   }

   mech_des.mechanism      = CKM_DES_KEY_GEN;
   mech_des.ulParameterLen = 0;
   mech_des.pParameter     = NULL;


   // first, generate a DES key and a RSA keypair
   //
   rc = funcs->C_GenerateKey( session, &mech_des, NULL, 0, &des_key );
   if (rc != CKR_OK) {
      show_error("   C_GenerateKey #1", rc );
      goto error;
   }

   mech_rsa.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
   mech_rsa.ulParameterLen = 0;
   mech_rsa.pParameter     = NULL;

   rc = funcs->C_GenerateKeyPair( session,   &mech_rsa,
                                  pub_tmpl,   2,
                                  NULL,       0,
                                  &publ_key, &priv_key );
   if (rc != CKR_OK) {
      show_error("   C_GenerateKeyPair #1", rc );
      goto error;
   }


   // now, encrypt some data using the DES key
   //
   orig_len = sizeof(original);
   for (i=0; i < orig_len; i++) {
      original[i] = i % 255;
   }

   mech_des.mechanism      = CKM_DES_ECB;
   mech_des.ulParameterLen = 0;
   mech_des.pParameter     = NULL;

   rc = funcs->C_EncryptInit( session, &mech_des, des_key );
   if (rc != CKR_OK) {
      show_error("   C_EncryptInit #1", rc );
      goto error;
   }

   crypt_len = sizeof(crypt);
   rc = funcs->C_Encrypt( session, original, orig_len, crypt, &crypt_len );
   if (rc != CKR_OK) {
      show_error("   C_Encrypt #1", rc );
      goto error;
   }


   // now, wrap the DES key using the RSA private key
   //
   mech_rsa.mechanism      = CKM_RSA_X_509;
   mech_rsa.ulParameterLen = 0;
   mech_rsa.pParameter     = NULL;

   wrapped_data_len = sizeof(wrapped_data);

   rc = funcs->C_WrapKey( session,         &mech_rsa,
                          publ_key,         des_key,
                         &wrapped_data[0], &wrapped_data_len );
   if (rc != CKR_OK) {
      show_error("   C_WrapKey #1", rc );
      goto error;
   }

   // unwrap the DES key using the public key
   //
   rc = funcs->C_UnwrapKey( session,      &mech_rsa,
                            priv_key,
                            wrapped_data, wrapped_data_len,
                            des_tmpl,     2,
                            &uw_key );
   if (rc != CKR_OK) {
      show_error("   C_UnWrapKey #1", rc );
      goto error;
   }

   // now, decrypt the data using the unwrapped key.
   //
   rc = funcs->C_DecryptInit( session, &mech_des, uw_key );
   if (rc != CKR_OK) {
      show_error("   C_DecryptInit #1", rc );
      goto error;
   }

   decrypt_len = sizeof(decrypt);
   rc = funcs->C_Decrypt( session, crypt, crypt_len, decrypt, &decrypt_len );
   if (rc != CKR_OK) {
      show_error("   C_Decrypt #1", rc );
      goto error;
   }

   if (decrypt_len != orig_len) {
      printf("   ERROR:  lengths don't match\n");
      goto error;
   }

   for (i=0; i < orig_len; i++) {
      if (original[i] != decrypt[i]) {
         printf("   ERROR:  mismatch at byte %d\n", i );
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
      CK_OBJECT_HANDLE new_priv_key;
      CK_BYTE data[1024];
      CK_ULONG data_len = sizeof(data);


      rc = funcs->C_CreateObject( session, tmpl, 10, &new_priv_key );
      if (rc != CKR_OK) {
         show_error("   C_CreateObject #1", rc );
         goto error;
      }

      rc = funcs->C_WrapKey( session,   &mech_rsa,
                             priv_key,   new_priv_key,
                             data,      &data_len );
      if (rc != CKR_KEY_NOT_WRAPPABLE) {
         show_error("   C_WrapKey #2", rc );
         printf("   Expected CKR_KEY_NOT_WRAPPABLE\n" );
         goto error;
      }
   }

   rc = funcs->C_CloseAllSessions( slot_id );
   if (rc != CKR_OK) {
      show_error("   C_CloseAllSessions #1", rc );
      return FALSE;
   }

   printf("Looks okay...\n");
   return TRUE;

error:
   rc = funcs->C_CloseSession (session);
   if (rc != CKR_OK)
      show_error ("   C_CloseSession #2", rc);

   return FALSE;
}


//
//
int do_SignVerifyMD2_RSA_PKCS( void )
{
   CK_BYTE             original[1024];
   CK_BYTE             sig1[256];
   CK_BYTE             sig2[256];
   CK_BYTE             user_pin[DEFAULT_USER_PIN_LEN];
   CK_SLOT_ID          slot_id;
   CK_SESSION_HANDLE   session;
   CK_MECHANISM        mech;
   CK_OBJECT_HANDLE    publ_key, priv_key;
   CK_FLAGS            flags;
   CK_ULONG            user_pin_len;
   CK_ULONG            orig_len, sig1_len, sig2_len;
   CK_ULONG            i, remain;
   CK_RV               rc;

   CK_ULONG  bits = 1024;
   CK_BYTE   pub_exp[] = { 0x3 };

   CK_ATTRIBUTE pub_tmpl[] =
   {
      {CKA_MODULUS_BITS,    &bits,    sizeof(bits)    },
      {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp) }
   };

   printf("do_SignVerifyMD2_RSA_PKCS...\n");

   slot_id = SLOT_ID;
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      return FALSE;
   }


   memcpy( user_pin, DEFAULT_USER_PIN, DEFAULT_USER_PIN_LEN );
   user_pin_len = DEFAULT_USER_PIN_LEN;

   rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #1", rc );
      return FALSE;
   }

   mech.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   rc = funcs->C_GenerateKeyPair( session,   &mech,
                                  pub_tmpl,   2,
                                  NULL,       0,
                                  &publ_key, &priv_key );
   if (rc != CKR_OK) {
      show_error("   C_GenerateKeyPair #1", rc );
      return FALSE;
   }

   // now, sign/verify some data
   //
   orig_len = sizeof(original);
   for (i=0; i < orig_len; i++)
      original[i] = i % 255;

   mech.mechanism      = CKM_MD2_RSA_PKCS;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   rc = funcs->C_SignInit( session, &mech, priv_key );
   if (rc != CKR_OK) {
      show_error("   C_SignInit #1", rc );
      return FALSE;
   }

   sig1_len = sizeof(sig1);
   rc = funcs->C_Sign( session, original, orig_len, sig1, &sig1_len );
   if (rc != CKR_OK) {
      show_error("   C_Sign #1", rc );
      return FALSE;
   }

   rc = funcs->C_SignInit( session, &mech, priv_key );
   if (rc != CKR_OK) {
      show_error("   C_SignInit #2", rc );
      return FALSE;
   }

   remain = orig_len;
   for (i=0; i < 1024; i += 53) {
      int amt;

      if (remain < 53)
         amt = remain;
      else
         amt = 53;

      rc = funcs->C_SignUpdate( session, &original[orig_len - remain], amt );
      if (rc != CKR_OK) {
         show_error("   C_SignUpdate #1", rc );
         printf("   Iteration:  i = %d\n", i );
         return FALSE;
      }

      remain -= amt;
   }

   sig2_len = sizeof(sig2);
   rc = funcs->C_SignFinal( session, sig2, &sig2_len );
   if (rc != CKR_OK) {
      show_error("   C_SignFinal #1", rc );
      return FALSE;
   }

   if (sig1_len != sig2_len) {
      printf("   ERROR:  signature lengths don't match\n");
      return FALSE;
   }

   if (memcmp(sig1, sig2, sig1_len) != 0) {
      printf("   ERROR:  signatures don't match\n");
      fprintf (stderr, "\tSig1: %02x %02x %02x %02x ...\n", 
		sig1[0], sig1[1], sig1[2], sig1[3]);
      fprintf (stderr, "\tSig2: %02x %02x %02x %02x ...\n", 
		sig2[0], sig2[1], sig2[2], sig2[3]);
      return FALSE;
   }


   // now, verify the signature
   //
   rc = funcs->C_VerifyInit( session, &mech, publ_key );
   if (rc != CKR_OK) {
      show_error("   C_VerifyInit #1", rc );
      return FALSE;
   }

   rc = funcs->C_Verify( session, original, orig_len, sig1, sig1_len );
   if (rc != CKR_OK) {
      show_error("   C_Verify #1", rc );
      return FALSE;
   }


   rc = funcs->C_VerifyInit( session, &mech, publ_key );
   if (rc != CKR_OK) {
      show_error("   C_VerifyInit #2", rc );
      return FALSE;
   }

   remain = orig_len;
   for (i=0; i < 1024; i += 53) {
      int amt;

      if (remain < 53)
         amt = remain;
      else
         amt = 53;

      rc = funcs->C_VerifyUpdate( session, &original[orig_len - remain], amt );
      if (rc != CKR_OK) {
         show_error("   C_VerifyUpdate #1", rc );
         printf("   Iteration:  i = %d\n", i );
         return FALSE;
      }

      remain -= amt;
   }

   rc = funcs->C_VerifyFinal( session, sig1, sig1_len );
   if (rc != CKR_OK) {
      show_error("   C_VerifyFinal #1", rc );
      return FALSE;
   }


   // now, corrupt the signature and try to re-verify.
   //
   sig1[50] = sig1[50] + 1;

   rc = funcs->C_VerifyInit( session, &mech, publ_key );
   if (rc != CKR_OK) {
      show_error("   C_VerifyInit #2", rc );
      return FALSE;
   }

   rc = funcs->C_Verify( session, original, orig_len, sig1, sig1_len );
   if (rc != CKR_SIGNATURE_INVALID) {
      show_error("   C_Verify #2", rc );
      printf("   Expected CKR_SIGNATURE_INVALID\n");
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
int do_SignVerifyMD5_RSA_PKCS( void )
{
   CK_BYTE             original[1024];
   CK_BYTE             sig1[256];
   CK_BYTE             sig2[256];
   CK_BYTE             user_pin[DEFAULT_USER_PIN_LEN];
   CK_SLOT_ID          slot_id;
   CK_SESSION_HANDLE   session;
   CK_MECHANISM        mech;
   CK_OBJECT_HANDLE    publ_key, priv_key;
   CK_FLAGS            flags;
   CK_ULONG            user_pin_len;
   CK_ULONG            orig_len, sig1_len, sig2_len;
   CK_ULONG            i, remain;
   CK_RV               rc;

   CK_ULONG  bits = 1024;
   CK_BYTE   pub_exp[] = { 0x3 };

   CK_ATTRIBUTE pub_tmpl[] =
   {
      {CKA_MODULUS_BITS,    &bits,    sizeof(bits)    },
      {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp) }
   };

   printf("do_SignVerifyMD5_RSA_PKCS...\n");

   slot_id = SLOT_ID;
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      return FALSE;
   }


   memcpy( user_pin, DEFAULT_USER_PIN, DEFAULT_USER_PIN_LEN );
   user_pin_len = DEFAULT_USER_PIN_LEN;

   rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #1", rc );
      goto error;
   }

   mech.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   rc = funcs->C_GenerateKeyPair( session,   &mech,
                                  pub_tmpl,   2,
                                  NULL,       0,
                                  &publ_key, &priv_key );
   if (rc != CKR_OK) {
      show_error("   C_GenerateKeyPair #1", rc );
      goto error;
   }

   // now, sign/verify some data
   //
   orig_len = sizeof(original);
   for (i=0; i < orig_len; i++)
      original[i] = i % 255;

   mech.mechanism      = CKM_MD5_RSA_PKCS;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   rc = funcs->C_SignInit( session, &mech, priv_key );
   if (rc != CKR_OK) {
      show_error("   C_SignInit #1", rc );
      goto error;
   }

   sig1_len = sizeof(sig1);
   rc = funcs->C_Sign( session, original, orig_len, sig1, &sig1_len );
   if (rc != CKR_OK) {
      show_error("   C_Sign #1", rc );
      goto error;
   }

   rc = funcs->C_SignInit( session, &mech, priv_key );
   if (rc != CKR_OK) {
      show_error("   C_SignInit #2", rc );
      goto error;
   }

   remain = orig_len;
   for (i=0; i < 1024; i += 53) {
      int amt;

      if (remain < 53)
         amt = remain;
      else
         amt = 53;

      rc = funcs->C_SignUpdate( session, &original[orig_len - remain], amt );
      if (rc != CKR_OK) {
         show_error("   C_SignUpdate #1", rc );
         printf("   Iteration:  i = %d\n", i );
         goto error;
      }

      remain -= amt;
   }

   sig2_len = sizeof(sig2);
   rc = funcs->C_SignFinal( session, sig2, &sig2_len );
   if (rc != CKR_OK) {
      show_error("   C_SignFinal #1", rc );
      goto error;
   }

   if (sig1_len != sig2_len) {
      printf("   ERROR:  signature lengths don't match\n");
      goto error;
   }

   if (memcmp(sig1, sig2, sig1_len) != 0) {
      printf("   ERROR:  signatures don't match\n");
      fprintf (stderr, "\tSig1: %02x %02x %02x %02x ...\n", 
		sig1[0], sig1[1], sig1[2], sig1[3]);
      fprintf (stderr, "\tSig2: %02x %02x %02x %02x ...\n", 
		sig2[0], sig2[1], sig2[2], sig2[3]);
      goto error;
   }


   // now, verify the signature
   //
   rc = funcs->C_VerifyInit( session, &mech, publ_key );
   if (rc != CKR_OK) {
      show_error("   C_VerifyInit #1", rc );
      goto error;
   }

   rc = funcs->C_Verify( session, original, orig_len, sig1, sig1_len );
   if (rc != CKR_OK) {
      show_error("   C_Verify #1", rc );
      goto error;
   }


   rc = funcs->C_VerifyInit( session, &mech, publ_key );
   if (rc != CKR_OK) {
      show_error("   C_VerifyInit #2", rc );
      goto error;
   }

   remain = orig_len;
   for (i=0; i < 1024; i += 53) {
      int amt;

      if (remain < 53)
         amt = remain;
      else
         amt = 53;

      rc = funcs->C_VerifyUpdate( session, &original[orig_len - remain], amt );
      if (rc != CKR_OK) {
         show_error("   C_VerifyUpdate #1", rc );
         printf("   Iteration:  i = %d\n", i );
         goto error;
      }

      remain -= amt;
   }

   rc = funcs->C_VerifyFinal( session, sig1, sig1_len );
   if (rc != CKR_OK) {
      show_error("   C_VerifyFinal #1", rc );
      goto error;
   }


   // now, corrupt the signature and try to re-verify.
   //
   sig1[50] = sig1[50] + 1;

   rc = funcs->C_VerifyInit( session, &mech, publ_key );
   if (rc != CKR_OK) {
      show_error("   C_VerifyInit #2", rc );
      goto error;
   }

   rc = funcs->C_Verify( session, original, orig_len, sig1, sig1_len );
   if (rc != CKR_SIGNATURE_INVALID) {
      show_error("   C_Verify #2", rc );
      printf("   Expected CKR_SIGNATURE_INVALID\n");
      goto error;
   }

   rc = funcs->C_CloseAllSessions( slot_id );
   if (rc != CKR_OK) {
      show_error("   C_CloseAllSessions #1", rc );
      return FALSE;
   }

   printf("Looks okay...\n");
   return TRUE;

error:
   rc = funcs->C_CloseSession (session);
   if (rc!= CKR_OK)
      show_error ("   C_CloseSession #2", rc);

   return FALSE;
}

//
//
int do_SignVerifySHA1_RSA_PKCS( void )
{
   CK_BYTE             original[1024];
   CK_BYTE             sig1[256];
   CK_BYTE             sig2[256];
   CK_BYTE             user_pin[DEFAULT_USER_PIN_LEN];
   CK_SLOT_ID          slot_id;
   CK_SESSION_HANDLE   session;
   CK_MECHANISM        mech;
   CK_OBJECT_HANDLE    publ_key, priv_key;
   CK_FLAGS            flags;
   CK_ULONG            user_pin_len;
   CK_ULONG            orig_len, sig1_len, sig2_len;
   CK_ULONG            i, remain;
   CK_RV               rc;

   CK_ULONG  bits = 1024;
   CK_BYTE   pub_exp[] = { 0x3 };

   CK_ATTRIBUTE pub_tmpl[] =
   {
      {CKA_MODULUS_BITS,    &bits,    sizeof(bits)    },
      {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp) }
   };

   printf("do_SignVerifySHA1_RSA_PKCS...\n");

   slot_id = SLOT_ID;
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      return FALSE;
   }


   memcpy( user_pin, DEFAULT_USER_PIN, DEFAULT_USER_PIN_LEN );
   user_pin_len = DEFAULT_USER_PIN_LEN;

   rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #1", rc );
      goto error;
   }

   mech.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   rc = funcs->C_GenerateKeyPair( session,   &mech,
                                  pub_tmpl,   2,
                                  NULL,       0,
                                  &publ_key, &priv_key );
   if (rc != CKR_OK) {
      show_error("   C_GenerateKeyPair #1", rc );
      goto error;
   }

   // now, sign/verify some data
   //
   orig_len = sizeof(original);
   for (i=0; i < orig_len; i++)
      original[i] = i % 255;

   mech.mechanism      = CKM_SHA1_RSA_PKCS;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   rc = funcs->C_SignInit( session, &mech, priv_key );
   if (rc != CKR_OK) {
      show_error("   C_SignInit #1", rc );
      goto error;
   }

   sig1_len = sizeof(sig1);
   rc = funcs->C_Sign( session, original, orig_len, sig1, &sig1_len );
   if (rc != CKR_OK) {
      show_error("   C_Sign #1", rc );
      goto error;
   }

   rc = funcs->C_SignInit( session, &mech, priv_key );
   if (rc != CKR_OK) {
      show_error("   C_SignInit #2", rc );
      goto error;
   }

   remain = orig_len;
   for (i=0; i < 1024; i += 53) {
      int amt;

      if (remain < 53)
         amt = remain;
      else
         amt = 53;

      rc = funcs->C_SignUpdate( session, &original[orig_len - remain], amt );
      if (rc != CKR_OK) {
         show_error("   C_SignUpdate #1", rc );
         printf("   Iteration:  i = %d\n", i );
         goto error;
      }

      remain -= amt;
   }

   sig2_len = sizeof(sig2);
   rc = funcs->C_SignFinal( session, sig2, &sig2_len );
   if (rc != CKR_OK) {
      show_error("   C_SignFinal #1", rc );
      goto error;
   }

   if (sig1_len != sig2_len) {
      printf("   ERROR:  signature lengths don't match\n");
      goto error;
   }

   if (memcmp(sig1, sig2, sig1_len) != 0) {
      printf("   ERROR:  signatures don't match\n");
      fprintf (stderr, "\tSig1: %02x %02x %02x %02x ...\n", 
		sig1[0], sig1[1], sig1[2], sig1[3]);
      fprintf (stderr, "\tSig2: %02x %02x %02x %02x ...\n", 
		sig2[0], sig2[1], sig2[2], sig2[3]);
      goto error;
   }


   // now, verify the signature
   //
   rc = funcs->C_VerifyInit( session, &mech, publ_key );
   if (rc != CKR_OK) {
      show_error("   C_VerifyInit #1", rc );
      goto error;
   }

   rc = funcs->C_Verify( session, original, orig_len, sig1, sig1_len );
   if (rc != CKR_OK) {
      show_error("   C_Verify #1", rc );
      goto error;
   }


   rc = funcs->C_VerifyInit( session, &mech, publ_key );
   if (rc != CKR_OK) {
      show_error("   C_VerifyInit #2", rc );
      goto error;
   }

   remain = orig_len;
   for (i=0; i < 1024; i += 53) {
      int amt;

      if (remain < 53)
         amt = remain;
      else
         amt = 53;

      rc = funcs->C_VerifyUpdate( session, &original[orig_len - remain], amt );
      if (rc != CKR_OK) {
         show_error("   C_VerifyUpdate #1", rc );
         printf("   Iteration:  i = %d\n", i );
         goto error;
      }

      remain -= amt;
   }

   rc = funcs->C_VerifyFinal( session, sig1, sig1_len );
   if (rc != CKR_OK) {
      show_error("   C_VerifyFinal #1", rc );
      goto error;
   }


   // now, corrupt the signature and try to re-verify.
   //
   sig1[50] = sig1[50] + 1;

   rc = funcs->C_VerifyInit( session, &mech, publ_key );
   if (rc != CKR_OK) {
      show_error("   C_VerifyInit #2", rc );
      goto error;
   }

   rc = funcs->C_Verify( session, original, orig_len, sig1, sig1_len );
   if (rc != CKR_SIGNATURE_INVALID) {
      show_error("   C_Verify #2", rc );
      printf("   Expected CKR_SIGNATURE_INVALID\n");
      goto error;
   }

   rc = funcs->C_CloseAllSessions( slot_id );
   if (rc != CKR_OK) {
      show_error("   C_CloseAllSessions #1", rc );
      return FALSE;
   }

   printf("Looks okay...\n");
   return TRUE;

error:
   rc = funcs->C_CloseSession (session);
   if (rc!= CKR_OK)
      show_error ("   C_CloseSession #2", rc);

   return FALSE;
}


int rsa_functions()
{
   SYSTEMTIME t1, t2;
   int        rc;


#if 1
   GetSystemTime(&t1);
   rc = do_GenerateRSAKeyPair();
   if (!rc)
      fprintf (stderr, "ERROR do_GenerateRSAKeyPair failed, rc = 0x%0x\n", rc);
   GetSystemTime(&t2);
   process_time( t1, t2 );

   GetSystemTime(&t1);
   rc = do_EncryptRSA_PKCS();
   if (!rc)
      fprintf (stderr, "ERROR do_EncryptRSA_PKCS failed, rc = 0x%0x\n", rc);
   GetSystemTime(&t2);
   process_time( t1, t2 );

   GetSystemTime(&t1);
   rc = do_EncryptRSA_PKCS_Speed();
   if (!rc)
      fprintf (stderr, "ERROR do_EncryptRSA_PKCS_Speed failed, rc = 0x%0x\n", rc);
   GetSystemTime(&t2);
   process_time( t1, t2 );

   GetSystemTime(&t1);
   rc = do_SignRSA_PKCS();
   if (!rc)
      fprintf (stderr, "ERROR do_SignRSA_PKCS failed, rc = 0x%0x\n", rc);
   GetSystemTime(&t2);
   process_time( t1, t2 );

   GetSystemTime(&t1);
   rc = do_WrapUnwrapRSA_PKCS();
   if (!rc)
      fprintf (stderr, "ERROR do_WrapUnwrapRSA_PKCS failed, rc = 0x%0x\n", rc);
   GetSystemTime(&t2);
   process_time( t1, t2 );

   GetSystemTime(&t1);
   rc = do_EncryptRSA_X509();
   if (!rc)
      fprintf (stderr, "ERROR do_EncryptRSA_X509 failed, rc = 0x%0x\n", rc);
   GetSystemTime(&t2);
   process_time( t1, t2 );

   GetSystemTime(&t1);
   rc = do_SignRSA_X509();
   if (!rc)
      fprintf (stderr, "ERROR do_SignRSA_X509 failed, rc = 0x%0x\n", rc);
   GetSystemTime(&t2);
   process_time( t1, t2 );

   GetSystemTime(&t1);
   rc = do_WrapUnwrapRSA_X509();
   if (!rc)
      fprintf (stderr, "ERROR do_WrapUnwrapRSA_X509 failed, rc = 0x%0x\n", rc);
   GetSystemTime(&t2);
   process_time( t1, t2 );

#if MD2
   GetSystemTime(&t1);
   rc = do_SignVerifyMD2_RSA_PKCS();
   if (!rc)
      fprintf (stderr, "ERROR do_SignVerifyMD2_RSA_PKCS failed, rc = 0x%0x\n", rc);
   GetSystemTime(&t2);
   process_time( t1, t2 );
#endif

   GetSystemTime(&t1);
   rc = do_SignVerifyMD5_RSA_PKCS();
   if (!rc)
      fprintf (stderr, "ERROR do_SignVerifyMD5_RSA_PKCS failed, rc = 0x%0x\n", rc);
   GetSystemTime(&t2);
   process_time( t1, t2 );

   GetSystemTime(&t1);
   rc = do_SignVerifySHA1_RSA_PKCS();
   if (!rc)
      fprintf (stderr, "ERROR do_SignVerifySHA1_RSA_PKCS failed, rc = 0x%0x\n", rc);
   GetSystemTime(&t2);
   process_time( t1, t2 );

//   GetSystemTime(&t1);
//   rc = do_EncryptRSA_PKCS_Speed();
//   if (!rc)
//      return FALSE;
//   GetSystemTime(&t2);
//   process_time( t1, t2 );

#endif
   return TRUE;
}

