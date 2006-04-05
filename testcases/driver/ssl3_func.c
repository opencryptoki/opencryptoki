// File: ssl3_func.c
//

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"

static CK_BBOOL  true  = TRUE;
static CK_BBOOL  false = FALSE;

//
//
int do_SignVerify_SSL3_MD5_MAC( void )
{
   CK_SESSION_HANDLE session;
   CK_SLOT_ID        slot_id;
   CK_MECHANISM      mech;
   CK_ULONG          flags;
   CK_ULONG          mac_size;
   CK_ULONG          i;
   CK_RV             rc;



   printf("do_SignVerify_SSL3_MD5_MAC...\n");

   slot_id = SLOT_ID;
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      return FALSE;
   }

   mac_size = 8;

   mech.mechanism      = CKM_SSL3_MD5_MAC;
   mech.ulParameterLen = sizeof(CK_ULONG);
   mech.pParameter     = &mac_size;

   {
      CK_OBJECT_HANDLE  h_key;
      CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
      CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
      CK_BBOOL          false      = FALSE;
      CK_BYTE           hash[SHA1_HASH_LEN];
      CK_BYTE           data[50];
      CK_BYTE           key_data[48];
      CK_ULONG          hash_len;
      CK_ULONG          data_len;
      CK_ATTRIBUTE      key_attribs[] =
      {
          {CKA_CLASS,       &key_class,        sizeof(key_class)    },
          {CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
          {CKA_TOKEN,       &false,            sizeof(false)        },
          {CKA_VALUE,       &key_data,         sizeof(key_data)     }
      };

      for (i=0; i < 48; i++)
         key_data[i] = i;

      memset( data, 0xb, 50 );
      data_len = 50;

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

      if (hash_len != mac_size) {
         printf("   Error:  C_Sign #1 generated bad MAC length\n");
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

   {
      CK_OBJECT_HANDLE  h_key;
      CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
      CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
      CK_BBOOL          false      = FALSE;
      CK_BYTE           hash[20];
      CK_BYTE           data[500];
      CK_BYTE           key_data[48];
      CK_ULONG          hash_len;
      CK_ULONG          data_len;
      CK_ATTRIBUTE      key_attribs[] =
      {
          {CKA_CLASS,       &key_class,        sizeof(key_class)    },
          {CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
          {CKA_TOKEN,       &false,            sizeof(false)        },
          {CKA_VALUE,       &key_data,         sizeof(key_data)     }
      };

      for (i=0; i < 48; i++)
         key_data[i] = i;

      memset( data, 0xb, 500 );
      data_len = 500;

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

      for (i=0; i < 500; i+=100) {
         rc = funcs->C_SignUpdate( session, &data[i], 100 );
         if (rc != CKR_OK) {
            show_error("   C_SignUpdate #1", rc );
            printf("   Iteration #%ld\n", i / 100 );
            return FALSE;
         }
      }

      hash_len = sizeof(hash);
      rc = funcs->C_SignFinal( session, hash, &hash_len );
      if (rc != CKR_OK) {
         show_error("   C_SignFinal #1", rc );
         return FALSE;
      }

      if (hash_len != mac_size) {
         printf("   Error:  C_SignUpdate/Final #1 generated bad MAC length\n");
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


      rc = funcs->C_VerifyInit( session, &mech, h_key );
      if (rc != CKR_OK) {
         show_error("   C_VerifyInit #3", rc );
         return FALSE;
      }

      for (i=0; i < 500; i+=100) {
         rc = funcs->C_VerifyUpdate( session, &data[i], 100 );
         if (rc != CKR_OK) {
            show_error("   C_VerifyUpdate #1", rc );
            printf("   Iteration #%ld\n", i / 100 );
            return FALSE;
         }
      }

      rc = funcs->C_VerifyFinal( session, hash, hash_len );
      if (rc != CKR_OK) {
         show_error("   C_VerifyFinal #1", rc );
         return FALSE;
      }


      rc = funcs->C_DestroyObject( session, h_key );
      if (rc != CKR_OK) {
         show_error("   C_DestroyObject #1", rc );
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
int do_SignVerify_SSL3_SHA1_MAC( void )
{
   CK_SESSION_HANDLE session;
   CK_SLOT_ID        slot_id;
   CK_MECHANISM      mech;
   CK_ULONG          flags;
   CK_ULONG          mac_size;
   CK_ULONG          i;
   CK_RV             rc;



   printf("do_SignVerify_SSL3_SHA1_MAC...\n");

   slot_id = SLOT_ID;
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      return FALSE;
   }

   mac_size = 8;

   mech.mechanism      = CKM_SSL3_SHA1_MAC;
   mech.ulParameterLen = sizeof(CK_ULONG);
   mech.pParameter     = &mac_size;

   {
      CK_OBJECT_HANDLE  h_key;
      CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
      CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
      CK_BBOOL          false      = FALSE;
      CK_BYTE           hash[SHA1_HASH_LEN];
      CK_BYTE           data[50];
      CK_BYTE           key_data[48];
      CK_ULONG          hash_len;
      CK_ULONG          data_len;
      CK_ATTRIBUTE      key_attribs[] =
      {
          {CKA_CLASS,       &key_class,        sizeof(key_class)    },
          {CKA_KEY_TYPE,    &key_type,         sizeof(key_type)     },
          {CKA_TOKEN,       &false,            sizeof(false)        },
          {CKA_VALUE,       &key_data,         sizeof(key_data)     }
      };

      for (i=0; i < 48; i++)
         key_data[i] = i;

      memset( data, 0xb, 50 );
      data_len = 50;

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

      if (hash_len != mac_size) {
         printf("   Error:  C_Sign #1 generated bad MAC length\n");
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
int do_SSL3_PreMasterKeyGen( void )
{
   CK_SESSION_HANDLE session;
   CK_SLOT_ID        slot_id;
   CK_MECHANISM      mech;
   CK_VERSION        version;
   CK_OBJECT_HANDLE  h_key;
   CK_ULONG          flags;
   CK_RV             rc;


   printf("do_SSL3_PreMasterKeyGen...\n");

   slot_id = SLOT_ID;
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      return FALSE;
   }

   version.major = 3;
   version.minor = 0;

   mech.mechanism      = CKM_SSL3_PRE_MASTER_KEY_GEN;
   mech.pParameter     = &version;
   mech.ulParameterLen = sizeof(CK_VERSION);


   rc = funcs->C_GenerateKey( session, &mech, NULL, 0, &h_key );
   if (rc != CKR_OK) {
      show_error("   C_GenerateKey #1", rc );
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
int do_SSL3_MasterKeyDerive( void )
{
   CK_SESSION_HANDLE session;
   CK_SLOT_ID        slot_id;
   CK_MECHANISM      mech;
   CK_OBJECT_HANDLE  h_pm_secret;
   CK_OBJECT_HANDLE  h_mk;
   CK_ULONG          flags;
   CK_RV             rc;


   printf("do_SSL3_MasterKeyDerive...\n");

   slot_id = SLOT_ID;
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      return FALSE;
   }

   // generate the pre-master secret key
   //
   {
      CK_VERSION    version    = { 3, 0 };
      CK_ATTRIBUTE  pm_tmpl[] =
      {
         {CKA_SENSITIVE,   &false, sizeof(CK_BBOOL) },
         {CKA_EXTRACTABLE, &true,  sizeof(CK_BBOOL) }
      };

      mech.mechanism      = CKM_SSL3_PRE_MASTER_KEY_GEN;
      mech.pParameter     = &version;
      mech.ulParameterLen = sizeof(CK_VERSION);

      rc = funcs->C_GenerateKey( session, &mech, pm_tmpl, 2, &h_pm_secret );
      if (rc != CKR_OK) {
         show_error("   C_GenerateKey #1", rc );
         return FALSE;
      }
   }

   // derive a master key
   //
   {
      CK_BYTE  client_random_data[256];
      CK_BYTE  server_random_data[256];

      CK_VERSION                        version = {3, 0};
      CK_SSL3_MASTER_KEY_DERIVE_PARAMS  mk_params;
      CK_ULONG i;

      for (i=0; i < 256; i++) {
         client_random_data[i] = i;
         server_random_data[i] = 256 - i;
      }

      mk_params.pVersion = &version;

      mk_params.RandomInfo.pClientRandom     = client_random_data;
      mk_params.RandomInfo.pServerRandom     = server_random_data;
      mk_params.RandomInfo.ulClientRandomLen = 256;
      mk_params.RandomInfo.ulServerRandomLen = 256;

      mech.mechanism      = CKM_SSL3_MASTER_KEY_DERIVE;
      mech.pParameter     = &mk_params;
      mech.ulParameterLen = sizeof(CK_SSL3_MASTER_KEY_DERIVE_PARAMS);

      rc = funcs->C_DeriveKey( session, &mech, h_pm_secret, NULL, 0, &h_mk );
      if (rc != CKR_OK) {
         show_error("   C_Derive #1", rc );
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


int ssl3_functions()
{
   SYSTEMTIME t1, t2;
   int        rc;


   GetSystemTime(&t1);
   rc = do_SignVerify_SSL3_MD5_MAC();
   if (!rc)
      return FALSE;
   GetSystemTime(&t2);
   process_time( t1, t2 );

   GetSystemTime(&t1);
   rc = do_SignVerify_SSL3_SHA1_MAC();
   if (!rc)
      return FALSE;
   GetSystemTime(&t2);
   process_time( t1, t2 );

   GetSystemTime(&t1);
   rc = do_SSL3_PreMasterKeyGen();
   if (!rc)
      return FALSE;
   GetSystemTime(&t2);
   process_time( t1, t2 );

   GetSystemTime(&t1);
   rc = do_SSL3_MasterKeyDerive();
   if (!rc)
      return FALSE;
   GetSystemTime(&t2);
   process_time( t1, t2 );

   return TRUE;
}
