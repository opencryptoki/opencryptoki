// File: dsa_func.c
//

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"


//
//
int do_GenerateDSAKeyPair( void )
{
   CK_SLOT_ID          slot_id;
   CK_SESSION_HANDLE   session;
   CK_MECHANISM        mech;
   CK_OBJECT_HANDLE    publ_key, priv_key;
   CK_FLAGS            flags;
   CK_BYTE             user_pin[DEFAULT_USER_PIN_LEN];
   CK_ULONG            user_pin_len;
   CK_RV               rc;

   CK_ATTRIBUTE  publ_tmpl[] =
   {
      {CKA_PRIME,    DSA_PUBL_PRIME,    sizeof(DSA_PUBL_PRIME)    },
      {CKA_SUBPRIME, DSA_PUBL_SUBPRIME, sizeof(DSA_PUBL_SUBPRIME) },
      {CKA_BASE,     DSA_PUBL_BASE,     sizeof(DSA_PUBL_BASE)     }
   };


   printf("do_GenerateDSAKeyPair...\n");

   slot_id = SLOT_ID;

   memcpy( user_pin, DEFAULT_USER_PIN, DEFAULT_USER_PIN_LEN );
   user_pin_len = DEFAULT_USER_PIN_LEN;

   mech.mechanism      = CKM_DSA_KEY_PAIR_GEN;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;


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
                                  publ_tmpl,  3,
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

   printf("Looks okay...\n");
   return TRUE;
}


// the generic DSA mechanism assumes that the data to be signed has already
// been hashed by SHA-1.  so the input data length must be 20 bytes
//
int do_SignDSA( void )
{
   CK_BYTE             data1[20];
   CK_BYTE             signature[256];
   CK_SLOT_ID          slot_id;
   CK_SESSION_HANDLE   session;
   CK_MECHANISM        mech;
   CK_OBJECT_HANDLE    publ_key, priv_key;
   CK_FLAGS            flags;
   CK_BYTE             user_pin[DEFAULT_USER_PIN_LEN];
   CK_ULONG            user_pin_len;
   CK_ULONG            i;
   CK_ULONG            len1, sig_len;
   CK_RV               rc;

   CK_ATTRIBUTE  publ_tmpl[] =
   {
      {CKA_PRIME,    DSA_PUBL_PRIME,    sizeof(DSA_PUBL_PRIME)    },
      {CKA_SUBPRIME, DSA_PUBL_SUBPRIME, sizeof(DSA_PUBL_SUBPRIME) },
      {CKA_BASE,     DSA_PUBL_BASE,     sizeof(DSA_PUBL_BASE)     }
   };

   printf("do_SignDSA...\n");

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

   mech.mechanism      = CKM_DSA_KEY_PAIR_GEN;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   rc = funcs->C_GenerateKeyPair( session,   &mech,
                                  publ_tmpl,  3,
                                  NULL,       0,
                                  &publ_key, &priv_key );
   if (rc != CKR_OK) {
      show_error("   C_GenerateKeyPair #1", rc );
      return FALSE;
   }

   // now, encrypt some data
   //
   len1 = sizeof(data1);
   sig_len = sizeof(signature);

   for (i=0; i < len1; i++)
      data1[i] = i % 255;

   mech.mechanism      = CKM_DSA;
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
   memcpy( signature, "ABCDEFGHIJKLMNOPQRSTUV", 26 );

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

   rc = funcs->C_CloseAllSessions( slot_id );
   if (rc != CKR_OK) {
      show_error("   C_CloseAllSessions #1", rc );
      return FALSE;
   }

   printf("Looks okay...\n");
   return TRUE;
}


int dsa_functions()
{
   SYSTEMTIME t1, t2;
   int        rc;

   GetSystemTime(&t1);
   rc = do_GenerateDSAKeyPair();
   if (!rc)
      return FALSE;
   GetSystemTime(&t2);
   process_time( t1, t2 );

   GetSystemTime(&t1);
   rc = do_SignDSA();
   if (!rc)
      return FALSE;
   GetSystemTime(&t2);
   process_time( t1, t2 );

   return TRUE;
}
