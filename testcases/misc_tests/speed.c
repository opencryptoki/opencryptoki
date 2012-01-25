// File: speed.c
//
// Performance tests for Identrus
//
//    2048-bit RSA keygen
//    1024-bit RSA keygen
//    1024-bit RSA signature generate
//    1024-bit RSA signature verify
//    3DES encr/decr on a 10K message
//    SHA1 on a 10K message
//


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/timeb.h>
#include <dlfcn.h>

#include "pkcs11types.h"
#include "regress.h"

#define DES_BLOCK_SIZE  8
#define DES_KEY_LEN     8

#define SHA1_HASH_LEN   20
#define MD2_HASH_LEN    16
#define MD5_HASH_LEN    16

#define MIN(a, b)       ( (a) < (b) ? (a) : (b) )


int do_GetFunctionList(void);

CK_FUNCTION_LIST  *funcs;
CK_SLOT_ID  SLOT_ID;


//CK_RV _cdecl C_GetFunctionList( CK_FUNCTION_LIST ** ) ;

long speed_process_time(SYSTEMTIME t1, SYSTEMTIME t2)
{
   long ms   = t2.millitm - t1.millitm;
   long s    = t2.time - t1.time;

   while (ms < 0) {
      ms += 1000;
      s--;
   }

   ms += (s*1000);
   return ms;
}

//
//
int do_RSA_PKCS_EncryptDecrypt( void )
{
   CK_BYTE             data1[100];
   CK_BYTE             signature[256];
   CK_SLOT_ID          slot_id;
   CK_SESSION_HANDLE   session;
   CK_MECHANISM        mech;
   CK_OBJECT_HANDLE    publ_key, priv_key;
   CK_FLAGS            flags;
   CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
   CK_ULONG            user_pin_len;
   CK_ULONG            i;
   CK_ULONG            len1, sig_len;
   CK_RV               rc;

   SYSTEMTIME          t1, t2;
   CK_ULONG            diff, min_time, max_time, avg_time;

   CK_ULONG  bits = 1024;
   CK_BYTE   pub_exp[] = { 0x3 };

   CK_ATTRIBUTE pub_tmpl[] =
   {
      {CKA_MODULUS_BITS,    &bits,    sizeof(bits)    },
      {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp) }
   };

   printf("do_RSA_PKCS_EncryptDecrypt...\n");

   slot_id = SLOT_ID;
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      return FALSE;
   }


   if (get_user_pin(user_pin))
	   return CKR_FUNCTION_FAILED;
   user_pin_len = (CK_ULONG)strlen((char *)user_pin);

   rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #1", rc );
      return FALSE;
   }

   mech.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   printf("Generating a 1024-bit keypair...\n");

   rc = funcs->C_GenerateKeyPair( session,   &mech,
                                  pub_tmpl,   2,
                                  NULL,       0,
                                  &publ_key, &priv_key );
   if (rc != CKR_OK) {
      show_error("   C_GenerateKeyPair #1", rc );
      return FALSE;
   }

   printf("Done...computing Encrypts...\n");


   // now, encrypt some data
   //
   len1 = sizeof(data1);
   sig_len = sizeof(signature);

   for (i=0; i < len1; i++)
      data1[i] = i % 255;

   mech.mechanism      = CKM_RSA_PKCS;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   avg_time = 0;
   max_time = 0;
   min_time = 0xFFFFFFFF;

   for (i=0; i < 1000; i++) {
      GetSystemTime(&t1);

      rc = funcs->C_EncryptInit( session, &mech, publ_key );
      if (rc != CKR_OK) {
         show_error("   C_EncryptInit #1", rc );
         return FALSE;
      }

      sig_len = sizeof(signature);
      rc = funcs->C_Encrypt( session, data1, len1, signature, &sig_len );
      if (rc != CKR_OK) {
         show_error("   C_Encrypt #1", rc );
         return FALSE;
      }

      GetSystemTime(&t2);

      diff = speed_process_time(t1, t2);

      avg_time += diff;

      if (diff < min_time)
         min_time = diff;

      if (diff > max_time)
         max_time = diff;
   }

   avg_time -= min_time;
   avg_time -= max_time;

   printf("1000 RSA PKCS Encrypt operations:  %ld \n", avg_time );
   printf("Minimum:                        %ld \n", min_time );
   printf("Maximum:                        %ld \n", max_time );

   printf("\n");

   avg_time = 0;
   max_time = 0;
   min_time = 0xFFFFFFFF;

   for (i=0; i < 1000; i++) {
      GetSystemTime(&t1);

      rc = funcs->C_DecryptInit( session, &mech, priv_key );
      if (rc != CKR_OK) {
         show_error("   C_DecryptInit #1", rc );
         return FALSE;
      }

      rc = funcs->C_Decrypt( session, signature,sig_len,data1, &len1 );
      if (rc != CKR_OK) {
         show_error("   C_Decrypt #1", rc );
         return FALSE;
      }

      GetSystemTime(&t2);

      diff = speed_process_time(t1, t2);

      avg_time += diff;

      if (diff < min_time)
         min_time = diff;

      if (diff > max_time)
         max_time = diff;
   }

   avg_time -= min_time;
   avg_time -= max_time;

   printf("1000 RSA PKCS Decrypt operations:  %ld ms  \n", avg_time );
   printf("Minimum:                          %ld ms\n", min_time );
   printf("Maximum:                          %ld ms\n", max_time );

   printf("\n");
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
int do_RSA_KeyGen_2048( void )
{
   CK_SLOT_ID          slot_id;
   CK_SESSION_HANDLE   session;
   CK_MECHANISM        mech;
   CK_OBJECT_HANDLE    publ_key, priv_key;
   CK_FLAGS            flags;
   CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
   CK_ULONG            user_pin_len;
   CK_ULONG            diff, max_time, min_time, avg_time, i;
   CK_RV               rc;


   printf("do_RSA_KeyGen_2048...\n");

   slot_id = SLOT_ID;

   if (get_user_pin(user_pin))
	   return CKR_FUNCTION_FAILED;
   user_pin_len = (CK_ULONG)strlen((char *)user_pin);

   mech.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   {
      SYSTEMTIME  t1, t2;
      CK_ULONG  bits = 2048;
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

      // skip the first one
      //
      rc = funcs->C_GenerateKeyPair( session,   &mech,
                                     pub_tmpl,   2,
                                     NULL,       0,
                                     &publ_key, &priv_key );
      if (rc != CKR_OK) {
         show_error("   C_GenerateKeyPair #1", rc );
         return FALSE;
      }

      min_time = 0xFFFFFFFF;
      max_time = 0x00000000;
      avg_time = 0x00000000;

      for (i=0; i < 12; i++) {
         GetSystemTime(&t1);
         rc = funcs->C_GenerateKeyPair( session,   &mech,
                                        pub_tmpl,   2,
                                        NULL,       0,
                                        &publ_key, &priv_key );
         if (rc != CKR_OK) {
            show_error("   C_GenerateKeyPair #2", rc );
            return FALSE;
         }
         GetSystemTime(&t2);

         diff = speed_process_time( t1, t2 );
         printf("   %3ld: %ld\n", i, diff );

         avg_time += diff;

         if (diff < min_time)
            min_time = diff;

         if (diff > max_time)
            max_time = diff;
      }

      avg_time -= min_time;
      avg_time -= max_time;

      printf("10 iterations:  %ldms\n", avg_time );
      printf("Minimum:        %ldms\n", min_time );
      printf("Maximum:        %ldms\n", max_time );

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
int do_RSA_KeyGen_1024( void )
{
   CK_SLOT_ID          slot_id;
   CK_SESSION_HANDLE   session;
   CK_MECHANISM        mech;
   CK_OBJECT_HANDLE    publ_key, priv_key;
   CK_FLAGS            flags;
   CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
   CK_ULONG            user_pin_len;
   CK_ULONG            diff, max_time, min_time, avg_time, i;
   CK_RV               rc;


   printf("do_RSA_KeyGen_1024...\n");

   slot_id = SLOT_ID;

   if (get_user_pin(user_pin))
	   return CKR_FUNCTION_FAILED;
   user_pin_len = (CK_ULONG)strlen((char *)user_pin);

   mech.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   {
      SYSTEMTIME  t1, t2;
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

      // skip the first one
      //
      rc = funcs->C_GenerateKeyPair( session,   &mech,
                                     pub_tmpl,   2,
                                     NULL,       0,
                                     &publ_key, &priv_key );
      if (rc != CKR_OK) {
         show_error("   C_GenerateKeyPair #1", rc );
         return FALSE;
      }

      min_time = 0xFFFFFFFF;
      max_time = 0x00000000;
      avg_time = 0x00000000;

      for (i=0; i < 12; i++) {
         GetSystemTime(&t1);
         rc = funcs->C_GenerateKeyPair( session,   &mech,
                                        pub_tmpl,   2,
                                        NULL,       0,
                                        &publ_key, &priv_key );
         if (rc != CKR_OK) {
            show_error("   C_GenerateKeyPair #2", rc );
            return FALSE;
         }
         GetSystemTime(&t2);

         diff = speed_process_time( t1, t2 );
         printf("   %3d: %d\n", (int)i, (int)diff );

         avg_time += diff;

         if (diff < min_time)
            min_time = diff;

         if (diff > max_time)
            max_time = diff;
      }

      avg_time -= min_time;
      avg_time -= max_time;

      printf("10 iterations:  %ldms\n", avg_time );
      printf("Minimum:        %ldms\n", min_time );
      printf("Maximum:        %ldms\n", max_time );

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
int do_RSA_PKCS_SignVerify_1024( void )
{
   CK_BYTE             data1[100];
   CK_BYTE             signature[256];
   CK_SLOT_ID          slot_id;
   CK_SESSION_HANDLE   session;
   CK_MECHANISM        mech;
   CK_OBJECT_HANDLE    publ_key, priv_key;
   CK_FLAGS            flags;
   CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
   CK_ULONG            user_pin_len;
   CK_ULONG            i;
   CK_ULONG            len1, sig_len;
   CK_RV               rc;

   SYSTEMTIME          t1, t2;
   CK_ULONG            diff, min_time, max_time, avg_time;

   CK_ULONG  bits = 1024;
   CK_BYTE   pub_exp[] = { 0x3 };

   CK_ATTRIBUTE pub_tmpl[] =
   {
      {CKA_MODULUS_BITS,    &bits,    sizeof(bits)    },
      {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp) }
   };

   printf("do_RSA_PKCS_Sign_1024...\n");

   slot_id = SLOT_ID;
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      return FALSE;
   }


   if (get_user_pin(user_pin))
	   return CKR_FUNCTION_FAILED;
   user_pin_len = (CK_ULONG)strlen((char *)user_pin);

   rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #1", rc );
      return FALSE;
   }

   mech.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   printf("Generating a 1024-bit keypair...\n");

   rc = funcs->C_GenerateKeyPair( session,   &mech,
                                  pub_tmpl,   2,
                                  NULL,       0,
                                  &publ_key, &priv_key );
   if (rc != CKR_OK) {
      show_error("   C_GenerateKeyPair #1", rc );
      return FALSE;
   }

   printf("Done...computing signatures...\n");


   // now, encrypt some data
   //
   len1 = sizeof(data1);
   sig_len = sizeof(signature);

   for (i=0; i < len1; i++)
      data1[i] = i % 255;

   mech.mechanism      = CKM_RSA_PKCS;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   avg_time = 0;
   max_time = 0;
   min_time = 0xFFFFFFFF;

   for (i=0; i < 1000; i++) {
      GetSystemTime(&t1);

      rc = funcs->C_SignInit( session, &mech, priv_key );
      if (rc != CKR_OK) {
         show_error("   C_SignInit #1", rc );
         return FALSE;
      }

      sig_len = sizeof(signature);
      rc = funcs->C_Sign( session, data1, len1, signature, &sig_len );
      if (rc != CKR_OK) {
         show_error("   C_Sign #1", rc );
         return FALSE;
      }

      GetSystemTime(&t2);

      diff = speed_process_time(t1, t2);

      avg_time += diff;

      if (diff < min_time)
         min_time = diff;

      if (diff > max_time)
         max_time = diff;
   }

   avg_time -= min_time;
   avg_time -= max_time;

   printf("1000 RSA PKCS Sign operations:  %ld ms\n", avg_time );
   printf("Minimum:                        %ld ms\n", min_time );
   printf("Maximum:                        %ld ms\n", max_time );

   printf("\n");

   avg_time = 0;
   max_time = 0;
   min_time = 0xFFFFFFFF;

   for (i=0; i < 1000; i++) {
      GetSystemTime(&t1);

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

      GetSystemTime(&t2);

      diff = speed_process_time(t1, t2);

      avg_time += diff;

      if (diff < min_time)
         min_time = diff;

      if (diff > max_time)
         max_time = diff;
   }

   avg_time -= min_time;
   avg_time -= max_time;

   printf("1000 RSA PKCS Verify operations:  %ld ms\n", avg_time );
   printf("Minimum:                          %ld ms\n", min_time );
   printf("Maximum:                          %ld ms\n", max_time );

   printf("\n");
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
int do_DES3_ECB_EncrDecr( void )
{
   CK_BYTE            *original;
   CK_BYTE            *cipher;
   CK_BYTE            *clear;

   CK_SLOT_ID          slot_id;
   CK_SESSION_HANDLE   session;
   CK_MECHANISM        mech;
   CK_OBJECT_HANDLE    h_key;
   CK_FLAGS            flags;
   CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
   CK_ULONG            user_pin_len;
   CK_ULONG            i;
   CK_ULONG            orig_len, cipher_len, clear_len;
   CK_RV               rc;

   SYSTEMTIME          t1, t2;
   CK_ULONG            avg_time, min_time, max_time, diff;

   printf("do_DES3_ECB_EncrDecr\n");

   original = (CK_BYTE *)malloc(BIG_REQUEST);
   cipher   = (CK_BYTE *)malloc(BIG_REQUEST);
   clear    = (CK_BYTE *)malloc(BIG_REQUEST);

   if (!original || !cipher || !clear) {
      if (original)  free( original );
      if (cipher)    free( cipher );
      if (clear)     free( clear );

      printf("HOST MEMORY ERROR\n");
      return FALSE;
   }


   slot_id = SLOT_ID;
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      return FALSE;
   }

   if (get_user_pin(user_pin))
	   return CKR_FUNCTION_FAILED;
   user_pin_len = (CK_ULONG)strlen((char *)user_pin);

   rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #1", rc );
      return FALSE;
   }

   mech.mechanism      = CKM_DES3_KEY_GEN;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   // first, generate a DES key
   //
   rc = funcs->C_GenerateKey( session, &mech, NULL, 0, &h_key );
   if (rc != CKR_OK) {
      show_error("   C_GenerateKey #1", rc );
      return FALSE;
   }


   // now, encrypt some data
   //
   orig_len = BIG_REQUEST;
   for (i=0; i < orig_len; i++) {
      original[i] = i % 255;
   }

   mech.mechanism      = CKM_DES3_ECB;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   avg_time = 0;
   max_time = 0;
   min_time = 0xFFFFFFFF;

   for (i=0; i < 1000; i++) {
      GetSystemTime(&t1);
      rc = funcs->C_EncryptInit( session, &mech, h_key );
      if (rc != CKR_OK) {
         show_error("   C_EncryptInit #1", rc );
         return FALSE;
      }

      cipher_len = BIG_REQUEST;
      rc = funcs->C_Encrypt( session, original, orig_len, cipher, &cipher_len );
      if (rc != CKR_OK) {
         show_error("   C_Encrypt #1", rc );
         return FALSE;
      }

      GetSystemTime(&t2);

      diff = speed_process_time(t1, t2);

      avg_time += diff;

      if (diff < min_time)
         min_time = diff;

      if (diff > max_time)
         max_time = diff;
   }

   avg_time -= min_time;
   avg_time -= max_time;

   printf("1000 DES3 %d byte ENCR operations:  %ld ms\n", BIG_REQUEST, avg_time );
   printf("Minimum:                        %ld ms\n", min_time );
   printf("Maximum:                        %ld ms\n", max_time );

   printf("\n");

   avg_time = 0;
   max_time = 0;
   min_time = 0xFFFFFFFF;

   for (i=0; i < 1000; i++) {
      GetSystemTime(&t1);

      rc = funcs->C_DecryptInit( session, &mech, h_key );
      if (rc != CKR_OK) {
         show_error("   C_DecryptInit #1", rc );
         return FALSE;
      }

      clear_len = BIG_REQUEST;
      rc = funcs->C_Decrypt( session, cipher, cipher_len, clear, &clear_len );
      if (rc != CKR_OK) {
         show_error("   C_Decrypt #1", rc );
         return FALSE;
      }

      GetSystemTime(&t2);

      diff = speed_process_time(t1, t2);

      avg_time += diff;

      if (diff < min_time)
         min_time = diff;

      if (diff > max_time)
         max_time = diff;
   }

   avg_time -= min_time;
   avg_time -= max_time;

   printf("1000 DES3 %d byte DECR operations:  %ld ms\n", BIG_REQUEST, avg_time );
   printf("Minimum:                        %ld ms\n", min_time );
   printf("Maximum:                        %ld ms\n", max_time );

   rc = funcs->C_CloseAllSessions( slot_id );
   if (rc != CKR_OK) {
      show_error("   C_CloseAllSessions #1", rc );
      return FALSE;
   }

   if (original)  free( original );
   if (cipher)    free( cipher );
   if (clear)     free( clear );

   printf("Looks okay...\n");
   return TRUE;
}


//
//
int do_DES3_CBC_EncrDecr( void )
{
   CK_BYTE            *original;
   CK_BYTE            *cipher;
   CK_BYTE            *clear;

   CK_SLOT_ID          slot_id;
   CK_SESSION_HANDLE   session;
   CK_MECHANISM        mech;
   CK_OBJECT_HANDLE    h_key;
   CK_FLAGS            flags;
   CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
   CK_BYTE             init_v[8] = { 1,2,3,4,5,6,7,8 };
   CK_ULONG            user_pin_len;
   CK_ULONG            i;
   CK_ULONG            orig_len, cipher_len, clear_len;
   CK_RV               rc;

   SYSTEMTIME          t1, t2;
   CK_ULONG            avg_time, min_time, max_time, diff;

   printf("do_DES3_CBC_EncrDecr\n");

   original = (CK_BYTE *)malloc(BIG_REQUEST);
   cipher   = (CK_BYTE *)malloc(BIG_REQUEST);
   clear    = (CK_BYTE *)malloc(BIG_REQUEST);
   if (!original || !cipher || !clear) {
      if (original)  free( original );
      if (cipher)    free( cipher );
      if (clear)     free( clear );

      printf("HOST MEMORY ERROR\n");
      return FALSE;
   }


   slot_id = SLOT_ID;
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      return FALSE;
   }

   if (get_user_pin(user_pin))
	   return CKR_FUNCTION_FAILED;
   user_pin_len = (CK_ULONG)strlen((char *)user_pin);

   rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #1", rc );
      return FALSE;
   }

   mech.mechanism      = CKM_DES3_KEY_GEN;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   // first, generate a DES key
   //
   rc = funcs->C_GenerateKey( session, &mech, NULL, 0, &h_key );
   if (rc != CKR_OK) {
      show_error("   C_GenerateKey #1", rc );
      return FALSE;
   }


   // now, encrypt some data
   //
   orig_len = BIG_REQUEST;
   for (i=0; i < orig_len; i++) {
      original[i] = i % 255;
   }

   mech.mechanism      = CKM_DES3_CBC;
   mech.ulParameterLen = 8;
   mech.pParameter     = init_v;

   avg_time = 0;
   max_time = 0;
   min_time = 0xFFFFFFFF;

   for (i=0; i < 1000; i++) {
      GetSystemTime(&t1);
      rc = funcs->C_EncryptInit( session, &mech, h_key );
      if (rc != CKR_OK) {
         show_error("   C_EncryptInit #1", rc );
         return FALSE;
      }

      cipher_len = BIG_REQUEST;
      rc = funcs->C_Encrypt( session, original, orig_len, cipher, &cipher_len );
      if (rc != CKR_OK) {
         show_error("   C_Encrypt #1", rc );
         return FALSE;
      }

      GetSystemTime(&t2);

      diff = speed_process_time(t1, t2);

      avg_time += diff;

      if (diff < min_time)
         min_time = diff;

      if (diff > max_time)
         max_time = diff;
   }

   avg_time -= min_time;
   avg_time -= max_time;

   printf("1000 DES3 %d byte ENCR operations:  %ld ms\n", BIG_REQUEST, avg_time );
   printf("Minimum:                        %ld ms\n", min_time );
   printf("Maximum:                        %ld ms\n", max_time );

   printf("\n");

   avg_time = 0;
   max_time = 0;
   min_time = 0xFFFFFFFF;

   for (i=0; i < 1000; i++) {
      GetSystemTime(&t1);

      rc = funcs->C_DecryptInit( session, &mech, h_key );
      if (rc != CKR_OK) {
         show_error("   C_DecryptInit #1", rc );
         return FALSE;
      }

      clear_len = BIG_REQUEST;
      rc = funcs->C_Decrypt( session, cipher, cipher_len, clear, &clear_len );
      if (rc != CKR_OK) {
         show_error("   C_Decrypt #1", rc );
         return FALSE;
      }

      GetSystemTime(&t2);

      diff = speed_process_time(t1, t2);

      avg_time += diff;

      if (diff < min_time)
         min_time = diff;

      if (diff > max_time)
         max_time = diff;
   }

   avg_time -= min_time;
   avg_time -= max_time;

   printf("1000 DES3 %d byte DECR operations:  %ld ms\n", BIG_REQUEST, avg_time );
   printf("Minimum:                        %ld ms\n", min_time );
   printf("Maximum:                        %ld ms\n", max_time );

   rc = funcs->C_CloseAllSessions( slot_id );
   if (rc != CKR_OK) {
      show_error("   C_CloseAllSessions #1", rc );
      return FALSE;
   }

   if (original)  free( original );
   if (cipher)    free( cipher );
   if (clear)     free( clear );

   printf("Looks okay...\n");
   return TRUE;
}


//
//
int do_SHA1( void )
{
   CK_SESSION_HANDLE session;
   CK_SLOT_ID        slot_id;
   CK_MECHANISM      mech;
   CK_ULONG          flags;
   CK_ULONG          i;
   CK_RV             rc;


   printf("do_SHA1...\n");

   slot_id = SLOT_ID;
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      return FALSE;
   }

   {
      CK_BYTE           *data;
      CK_BYTE           hash1[SHA1_HASH_LEN];
      CK_ULONG          data_len;
      CK_ULONG          hash_len;

      SYSTEMTIME        t1, t2;
      CK_ULONG          diff, avg_time, min_time, max_time;

      data = (CK_BYTE *)malloc( BIG_REQUEST );
      if (!data) {
         printf("HOST MEMORY ERROR\n");
         return FALSE;
      }

      mech.mechanism      = CKM_SHA_1;
      mech.ulParameterLen = 0;
      mech.pParameter     = NULL;

      // generate some data to hash
      //
      data_len = BIG_REQUEST;
      for (i=0; i < data_len; i++)
         data[i] = i % 255;

      avg_time = 0;
      max_time = 0;
      min_time = 0xFFFFFFFF;

      for (i=0; i < 1000; i++) {
         GetSystemTime(&t1);

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

         GetSystemTime(&t2);

         diff = speed_process_time(t1, t2);

         avg_time += diff;

         if (diff < min_time)
            min_time = diff;

         if (diff > max_time)
            max_time = diff;
      }

      avg_time -= min_time;
      avg_time -= max_time;

      printf("1000 SHA-1 %d byte operations:  %ld ms\n", BIG_REQUEST, avg_time );
      printf("Minimum:                    %ld ms\n", min_time );
      printf("Maximum:                    %ld ms\n", max_time );

      free( data );
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
int do_DummyFunction( void )
{
#if DUMMY
   CK_SLOT_ID        slot_id;
   CK_ULONG          i;
   CK_ULONG          diff, avg_time, min_time, max_time;
   SYSTEMTIME        t1, t2;


   printf("do_DummyFunction...\n");
   slot_id = SLOT_ID;

   avg_time = 0;
   max_time = 0;
   min_time = 0xFFFFFFFF;

   for (i=0; i < 1000; i++) {
      GetSystemTime(&t1);


      DummyFunction( slot_id );

      GetSystemTime(&t2);

      diff = speed_process_time(t1, t2);

      avg_time += diff;

      if (diff < min_time)
         min_time = diff;

      if (diff > max_time)
         max_time = diff;
   }

   avg_time -= min_time;
   avg_time -= max_time;

   printf("1000 DummyFunction %d byte operations:  %ld ms\n", 1024, avg_time );
   printf("Minimum:                    %ld ms\n", min_time );
   printf("Maximum:                    %ld ms\n", max_time );
#endif

   return TRUE;
}


//
//
int main( int argc, char **argv )
{
   CK_C_INITIALIZE_ARGS  cinit_args;
   int        rc, i;

   SLOT_ID = 0;

   for (i=1; i < argc; i++) {
      if (strcmp(argv[i], "-slot") == 0) {
         SLOT_ID = atoi(argv[i+1]);
         i++;
      }

      if (strcmp(argv[i], "-h") == 0) {
         printf("usage:  %s [-slot <num>] [-h]\n\n", argv[0] );
         printf("By default, Slot #1 is used\n\n");
         return -1;
      }
   }

   printf("Using slot #%lu...\n\n", SLOT_ID );

   rc = do_GetFunctionList();
   if (!rc)
      return rc;

   memset( &cinit_args, 0x0, sizeof(cinit_args) );
   cinit_args.flags = CKF_OS_LOCKING_OK;

   funcs->C_Initialize( &cinit_args );

#if 1
   rc = do_RSA_KeyGen_2048();
   if (!rc)
      return rc;

   rc = do_RSA_KeyGen_1024();
   if (!rc)
      return rc;

#endif
#if 1
   rc = do_RSA_PKCS_SignVerify_1024();
   if (!rc)
      return rc;

#endif
#if 1
   rc = do_RSA_PKCS_EncryptDecrypt( );
   if (!rc)
      return rc;

   rc = do_DES3_ECB_EncrDecr();
   if (!rc)
      return rc;

   rc = do_DES3_CBC_EncrDecr();
   if (!rc)
      return rc;

   rc = do_SHA1();
   if (!rc)
      return rc;
#endif

//   rc = do_DES_ECB_EncrDecr();
//   if (!rc)
//      return;

#if 1
   rc = do_DES3_ECB_EncrDecr();
   if (!rc)
      return rc;

   rc = do_DES3_CBC_EncrDecr();
   if (!rc)
      return rc;

   rc = do_SHA1();
   if (!rc)
      return rc;
#endif

   funcs->C_Finalize( NULL );

   return 0;
}


