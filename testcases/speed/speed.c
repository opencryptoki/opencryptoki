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

//#define SYSTEMTIME  struct timeval
#define SYSTEMTIME  struct timeb
#define GetSystemTime(x)   ftime(x)

#include "pkcs11types.h"

#if !defined(TRUE)
#define TRUE 1
#endif

#if !defined(FALSE)
#define FALSE 0
#endif

#define DES_BLOCK_SIZE  8
#define DES_KEY_LEN     8

#define SHA1_HASH_LEN   20
#define MD2_HASH_LEN    16
#define MD5_HASH_LEN    16

#define BIG_REQUEST     10240
//#define BIG_REQUEST     16384
//#define BIG_REQUEST     128000

#define MIN(a, b)       ( (a) < (b) ? (a) : (b) )



int skip_token_obj;

CK_FUNCTION_LIST  *funcs;
CK_SLOT_ID  SLOT_ID;

// these values are required when generating a PKCS DSA value.  they were
// obtained by generating a DSA key pair on the 4758 with the default (random)
// values.  these values are in big-endian format
//
CK_BYTE DSA_PUBL_PRIME[128] =
{
   0xba, 0xa2, 0x5b, 0xd9, 0x77, 0xb3, 0xf0, 0x2d, 0xa1, 0x65, 0xf1, 0x83, 0xa7, 0xc9, 0xf0,
   0x8a, 0x51, 0x3f, 0x74, 0xe8, 0xeb, 0x1f, 0xd7, 0x0a, 0xd5, 0x41, 0xfa, 0x52, 0x3c, 0x1f,
   0x79, 0x15, 0x55, 0x18, 0x45, 0x41, 0x29, 0x27, 0x12, 0x4a, 0xb4, 0x32, 0xa6, 0xd2, 0xec,
   0xe2, 0x82, 0x73, 0xf4, 0x30, 0x66, 0x1a, 0x31, 0x06, 0x37, 0xd2, 0xb0, 0xe4, 0x26, 0x39,
   0x2a, 0x0e, 0x48, 0xf6, 0x77, 0x94, 0x47, 0xea, 0x7d, 0x99, 0x22, 0xce, 0x65, 0x61, 0x82,
   0xd5, 0xe3, 0xfc, 0x15, 0x3f, 0xff, 0xff, 0xc8, 0xb9, 0x4f, 0x37, 0xbf, 0x7a, 0xa6, 0x6a,
   0xbe, 0xff, 0xa9, 0xdf, 0xfd, 0xed, 0x4a, 0xb6, 0x83, 0xd6, 0x0f, 0xea, 0xf6, 0x90, 0x4f,
   0x12, 0x8e, 0x09, 0x6e, 0x3c, 0x0a, 0x6d, 0x2e, 0xfb, 0xb3, 0x79, 0x90, 0x8e, 0x39, 0xc0,
   0x86, 0x0e, 0x5d, 0xf0, 0x56, 0xcd, 0x26, 0x45
};

CK_BYTE DSA_PUBL_SUBPRIME[20] =
{
   0x9f, 0x3d, 0x47, 0x13, 0xa3, 0xff, 0x93, 0xbb, 0x4a, 0xa6, 0xb0, 0xf1, 0x7e, 0x54, 0x1e,
   0xba, 0xf0, 0x66, 0x03, 0x61
};


CK_BYTE DSA_PUBL_BASE[128] =
{
   0x1a, 0x5b, 0xfe, 0x12, 0xba, 0x85, 0x8e, 0x9b, 0x08, 0x86, 0xd1, 0x43, 0x9b, 0x4a, 0xaf,
   0x44, 0x31, 0xdf, 0xa1, 0x57, 0xd8, 0xe0, 0xec, 0x34, 0x07, 0x4b, 0x78, 0x8e, 0x3c, 0x62,
   0x47, 0x4c, 0x2f, 0x5d, 0xd3, 0x31, 0x2c, 0xe9, 0xdd, 0x59, 0xc5, 0xe7, 0x2e, 0x06, 0x40,
   0x6c, 0x72, 0x9c, 0x95, 0xc6, 0xa4, 0x2a, 0x1c, 0x1c, 0x45, 0xb9, 0xf3, 0xdc, 0x83, 0xb6,
   0xc6, 0xdd, 0x94, 0x45, 0x4f, 0x74, 0xc6, 0x55, 0x36, 0x54, 0xba, 0x20, 0xad, 0x9a, 0xb6,
   0xe3, 0x20, 0xf2, 0xdd, 0xd3, 0x66, 0x19, 0xeb, 0x53, 0xf5, 0x88, 0x35, 0xe1, 0xea, 0xe8,
   0xd4, 0x57, 0xe1, 0x3d, 0xea, 0xd5, 0x00, 0xc2, 0xa4, 0xf5, 0xff, 0xfb, 0x0b, 0xfb, 0xa2,
   0xb9, 0xf1, 0x49, 0x46, 0x9d, 0x11, 0xa5, 0xb1, 0x94, 0x52, 0x47, 0x6e, 0x2e, 0x79, 0x4b,
   0xc5, 0x18, 0xe9, 0xbc, 0xff, 0xae, 0x34, 0x7f
};

long process_time(SYSTEMTIME t1, SYSTEMTIME t2)
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
void process_ret_code( CK_RV rc )
{
   switch (rc) {
      case CKR_OK:                               printf(" CKR_OK");                               break;
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
      case CKR_MUTEX_BAD:                        printf(" CKR_MUTEX_BAD");                        break;
      case CKR_MUTEX_NOT_LOCKED:                 printf(" CKR_MUTEX_NOT_LOCKED");                 break;
   }
}


//
//
void show_error( CK_BYTE *str, CK_RV rc )
{
   printf("%s returned:  %d (0x%0x)", str, rc, rc );
   process_ret_code( rc );
   printf("\n");
}


//
//
void print_hex( CK_BYTE *buf, CK_ULONG len )
{
   CK_ULONG i, j;

   i = 0;

   while (i < len) {
      for (j=0; (j < 15) && (i < len); j++, i++)
         printf("%03x ", buf[i] );
      printf("\n");
   }
   printf("\n");
}


//
//
int do_GetFunctionList( void )
{
   CK_RV            rc;
   CK_RV  (*pfoo)();
   void    *d;
   char    *e;
   char    *f="libopencryptoki.so";

   printf("do_GetFunctionList...\n");

   e = getenv("PKCSLIB");
   if ( e == NULL) {
      e = f;
   }
   d = dlopen(e,RTLD_NOW);
   if ( d == NULL ) {
      return FALSE;
   }

   pfoo = (CK_RV (*)())dlsym(d,"C_GetFunctionList");
   if (pfoo == NULL ) {
      return FALSE;
   }
   rc = pfoo(&funcs);

   if (rc != CKR_OK) {
      show_error("   C_GetFunctionList", rc );
      return FALSE;
   }

   printf("Looks okay...\n");
   return TRUE;
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
   CK_BYTE             user_pin[8];
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


   memcpy( user_pin, "12345678", 8 );
   user_pin_len = 8;

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

      diff = process_time(t1, t2);

      avg_time += diff;

      if (diff < min_time)
         min_time = diff;

      if (diff > max_time)
         max_time = diff;
   }

   avg_time -= min_time;
   avg_time -= max_time;

   printf("1000 RSA PKCS Encrypt operations:  %d \n", avg_time );
   printf("Minimum:                        %d \n", min_time );
   printf("Maximum:                        %d \n", max_time );

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

      diff = process_time(t1, t2);

      avg_time += diff;

      if (diff < min_time)
         min_time = diff;

      if (diff > max_time)
         max_time = diff;
   }

   avg_time -= min_time;
   avg_time -= max_time;

   printf("1000 RSA PKCS Decrypt operations:  %d ms  \n", avg_time );
   printf("Minimum:                          %d ms\n", min_time );
   printf("Maximum:                          %d ms\n", max_time );

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
   CK_BYTE             user_pin[8];
   CK_ULONG            user_pin_len;
   CK_ULONG            diff, max_time, min_time, avg_time, i;
   CK_RV               rc;


   printf("do_RSA_KeyGen_2048...\n");

   slot_id = SLOT_ID;

   memcpy( user_pin, "12345678", 8 );
   user_pin_len = 8;

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

         diff = process_time( t1, t2 );
         printf("   %3d: %d\n", i, diff );

         avg_time += diff;

         if (diff < min_time)
            min_time = diff;

         if (diff > max_time)
            max_time = diff;
      }

      avg_time -= min_time;
      avg_time -= max_time;

      printf("10 iterations:  %dms\n", avg_time );
      printf("Minimum:        %dms\n", min_time );
      printf("Maximum:        %dms\n", max_time );

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
   CK_BYTE             user_pin[8];
   CK_ULONG            user_pin_len;
   CK_ULONG            diff, max_time, min_time, avg_time, i;
   CK_RV               rc;


   printf("do_RSA_KeyGen_1024...\n");

   slot_id = SLOT_ID;

   memcpy( user_pin, "12345678", 8 );
   user_pin_len = 8;

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

         diff = process_time( t1, t2 );
         printf("   %3d: %d\n", i, diff );

         avg_time += diff;

         if (diff < min_time)
            min_time = diff;

         if (diff > max_time)
            max_time = diff;
      }

      avg_time -= min_time;
      avg_time -= max_time;

      printf("10 iterations:  %dms\n", avg_time );
      printf("Minimum:        %dms\n", min_time );
      printf("Maximum:        %dms\n", max_time );

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
   CK_BYTE             user_pin[8];
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


   memcpy( user_pin, "12345678", 8 );
   user_pin_len = 8;

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

      diff = process_time(t1, t2);

      avg_time += diff;

      if (diff < min_time)
         min_time = diff;

      if (diff > max_time)
         max_time = diff;
   }

   avg_time -= min_time;
   avg_time -= max_time;

   printf("1000 RSA PKCS Sign operations:  %d ms\n", avg_time );
   printf("Minimum:                        %d ms\n", min_time );
   printf("Maximum:                        %d ms\n", max_time );

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

      diff = process_time(t1, t2);

      avg_time += diff;

      if (diff < min_time)
         min_time = diff;

      if (diff > max_time)
         max_time = diff;
   }

   avg_time -= min_time;
   avg_time -= max_time;

   printf("1000 RSA PKCS Verify operations:  %d ms\n", avg_time );
   printf("Minimum:                          %d ms\n", min_time );
   printf("Maximum:                          %d ms\n", max_time );

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
   CK_BYTE             user_pin[8];
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

   memcpy( user_pin, "12345678", 8 );
   user_pin_len = 8;

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

      diff = process_time(t1, t2);

      avg_time += diff;

      if (diff < min_time)
         min_time = diff;

      if (diff > max_time)
         max_time = diff;
   }

   avg_time -= min_time;
   avg_time -= max_time;

   printf("1000 DES3 %d byte ENCR operations:  %d ms\n", BIG_REQUEST, avg_time );
   printf("Minimum:                        %d ms\n", min_time );
   printf("Maximum:                        %d ms\n", max_time );

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

      diff = process_time(t1, t2);

      avg_time += diff;

      if (diff < min_time)
         min_time = diff;

      if (diff > max_time)
         max_time = diff;
   }

   avg_time -= min_time;
   avg_time -= max_time;

   printf("1000 DES3 %d byte DECR operations:  %d ms\n", BIG_REQUEST, avg_time );
   printf("Minimum:                        %d ms\n", min_time );
   printf("Maximum:                        %d ms\n", max_time );

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
   CK_BYTE             user_pin[8];
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

   memcpy( user_pin, "12345678", 8 );
   user_pin_len = 8;

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

      diff = process_time(t1, t2);

      avg_time += diff;

      if (diff < min_time)
         min_time = diff;

      if (diff > max_time)
         max_time = diff;
   }

   avg_time -= min_time;
   avg_time -= max_time;

   printf("1000 DES3 %d byte ENCR operations:  %d ms\n", BIG_REQUEST, avg_time );
   printf("Minimum:                        %d ms\n", min_time );
   printf("Maximum:                        %d ms\n", max_time );

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

      diff = process_time(t1, t2);

      avg_time += diff;

      if (diff < min_time)
         min_time = diff;

      if (diff > max_time)
         max_time = diff;
   }

   avg_time -= min_time;
   avg_time -= max_time;

   printf("1000 DES3 %d byte DECR operations:  %d ms\n", BIG_REQUEST, avg_time );
   printf("Minimum:                        %d ms\n", min_time );
   printf("Maximum:                        %d ms\n", max_time );

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

         diff = process_time(t1, t2);

         avg_time += diff;

         if (diff < min_time)
            min_time = diff;

         if (diff > max_time)
            max_time = diff;
      }

      avg_time -= min_time;
      avg_time -= max_time;

      printf("1000 SHA-1 %d byte operations:  %d ms\n", BIG_REQUEST, avg_time );
      printf("Minimum:                    %d ms\n", min_time );
      printf("Maximum:                    %d ms\n", max_time );

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
   CK_SLOT_ID        slot_id;
   CK_ULONG          i;
   CK_ULONG          diff, avg_time, min_time, max_time;
   SYSTEMTIME        t1, t2;


   printf("do_DummyFunction...\n");
#if DUMMY
   slot_id = SLOT_ID;

   avg_time = 0;
   max_time = 0;
   min_time = 0xFFFFFFFF;

   for (i=0; i < 1000; i++) {
      GetSystemTime(&t1);


      DummyFunction( slot_id );

      GetSystemTime(&t2);

      diff = process_time(t1, t2);

      avg_time += diff;

      if (diff < min_time)
         min_time = diff;

      if (diff > max_time)
         max_time = diff;
   }

   avg_time -= min_time;
   avg_time -= max_time;

   printf("1000 DummyFunction %d byte operations:  %d ms\n", 1024, avg_time );
   printf("Minimum:                    %d ms\n", min_time );
   printf("Maximum:                    %d ms\n", max_time );
#endif
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

   printf("Using slot #%d...\n\n", SLOT_ID );

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


