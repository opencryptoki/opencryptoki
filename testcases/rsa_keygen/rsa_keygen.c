// File: driver.c
//
//
// Test driver.  In-depth regression test for PKCS #11
//

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <dlfcn.h>
#include <sys/timeb.h>

#include "pkcs11types.h"
#include "regress.h"

int skip_token_obj;

int do_GetFunctionList(void);

CK_FUNCTION_LIST  *funcs;
CK_SLOT_ID  SLOT_ID;

CK_RV
do_GenerateRSAKeyPair(CK_ULONG bits)
{
   CK_SLOT_ID          slot_id;
   CK_SESSION_HANDLE   session;
   CK_MECHANISM        mech;
   CK_OBJECT_HANDLE    publ_key, priv_key;
   CK_FLAGS            flags;
   CK_BYTE             user_pin[128];
   CK_ULONG            user_pin_len;
   CK_RV               rc;


   printf("do_GenerateRSAKey...\n");

   slot_id = SLOT_ID;

   if (get_user_pin(user_pin))
	   return CKR_FUNCTION_FAILED;
   user_pin_len = (CK_ULONG)strlen((char *)user_pin);

   mech.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

      flags = CKF_SERIAL_SESSION;
      rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
      if (rc != CKR_OK) {
         show_error("   C_OpenSession #3", rc );
	   return rc;
      }

      rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
      if (rc != CKR_OK) {
         show_error("   C_Login #1", rc );
	   return rc;
      }

   // Use 3 as pub exp
   {
      CK_BYTE   pub_exp[] = { 0x3 };

      CK_ATTRIBUTE pub_tmpl[] =
      {
         {CKA_MODULUS_BITS,    &bits,    sizeof(bits)    },
         {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp) }
      };

      rc = funcs->C_GenerateKeyPair( session,   &mech,
                                     pub_tmpl,   2,
                                     NULL,       0,
                                     &publ_key, &priv_key );
      if (rc != CKR_OK) {
         show_error("   C_GenerateKeyPair #1", rc );
         return rc;
      }

   }

   // Use 65537 as pub exp
   {
      CK_BYTE   pub_exp[] = { 0x1, 0x0, 0x1 };

      CK_ATTRIBUTE pub_tmpl[] =
      {
         {CKA_MODULUS_BITS,    &bits,    sizeof(bits)    },
         {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp) }
      };

      rc = funcs->C_GenerateKeyPair( session,   &mech,
                                     pub_tmpl,   2,
                                     NULL,       0,
                                     &publ_key, &priv_key );
      if (rc != CKR_OK) {
         show_error("   C_GenerateKeyPair #2", rc );
         return rc;
   }

   }

   // Use an invalid pub exp
   {
      CK_BYTE   pub_exp[] = { 0x1, 0x0, 0x2 };

      CK_ATTRIBUTE pub_tmpl[] =
      {
         {CKA_MODULUS_BITS,    &bits,    sizeof(bits)    },
         {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp) }
      };

      rc = funcs->C_GenerateKeyPair( session,   &mech,
                                     pub_tmpl,   2,
                                     NULL,       0,
                                     &publ_key, &priv_key );
      if (rc != CKR_FUNCTION_FAILED) {
         show_error("   C_GenerateKeyPair #3", rc );
         return rc;
   }

   }

   // Use no pub exp
   {
      CK_BYTE   pub_exp[] = { 0x1, 0x0, 0x2 };

      CK_ATTRIBUTE pub_tmpl[] =
      {
         {CKA_MODULUS_BITS,    &bits,    sizeof(bits)    }
      };

      rc = funcs->C_GenerateKeyPair( session,   &mech,
                                     pub_tmpl,   1,
                                     NULL,       0,
                                     &publ_key, &priv_key );
      if (rc != CKR_TEMPLATE_INCOMPLETE) {
         show_error("   C_GenerateKeyPair #3", rc );
         return rc;
   }

   }

   rc = funcs->C_CloseSession( session );
   if (rc != CKR_OK) {
	   show_error("   C_CloseSession #3", rc );
	   return rc;
   }

   printf("%s: Success\n", __FUNCTION__);
   return CKR_OK;
}


//
//
int
main( int argc, char **argv )
{
   CK_C_INITIALIZE_ARGS  cinit_args;
   int  i;
   CK_RV rv;
   SLOT_ID = 0;


   for (i=1; i < argc; i++) {
      if (strcmp(argv[i], "-slot") == 0) {
         ++i;
         SLOT_ID = atoi(argv[i]);
      }

      if (strcmp(argv[i], "-h") == 0) {
         printf("usage:  %s [-noskip] [-slot <num>] [-h]\n\n", argv[0] );
         printf("By default, Slot #1 is used\n\n");
         printf("By default we skip anything that creates or modifies\n");
         printf("token objects to preserve flash lifetime.\n");
         return -1;
      }
   }

   printf("Using slot #%d...\n\n", (int)SLOT_ID );

   rv = do_GetFunctionList();
   if (rv != TRUE) {
	   show_error("do_GetFunctionList", rv);
	   return -1;
   }

   memset( &cinit_args, 0x0, sizeof(cinit_args) );
   cinit_args.flags = CKF_OS_LOCKING_OK;

   // SAB Add calls to ALL functions before the C_Initialize gets hit

   if ((rv = funcs->C_Initialize( &cinit_args ))) {
	   show_error("C_Initialize", rv);
	   return -1;
   }

   rv = do_GenerateRSAKeyPair(512);
   if (rv != CKR_OK) {
	   show_error("do_GenerateRSAKeyPair(512)", rv);
	   return -1;
   }

   rv = do_GenerateRSAKeyPair(1024);
   if (rv != CKR_OK) {
	   show_error("do_GenerateRSAKeyPair(1024)", rv);
	   return -1;
   }

   rv = do_GenerateRSAKeyPair(2048);
   if (rv != CKR_OK) {
	   show_error("do_GenerateRSAKeyPair(2048)", rv);
	   return -1;
   }

   rv = funcs->C_Finalize( NULL );
   if (rv != CKR_OK) {
	   show_error("C_Finalize", rv);
	   return -1;
   }

   return 0;
}
