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
#if 0
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
#endif
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

   // try creating a key using C_CreateObject and specifying
   // CKA_MODULUS_BITS, which must NOT be specified according
   // to table 15
   {
      CK_BYTE   pub_exp[] = { 0x1, 0x0, 0x1 };
      CK_BYTE   *modulus = malloc(bits/8);
      CK_KEY_TYPE keyType = CKK_RSA;
      CK_ULONG    keyClass = CKO_PUBLIC_KEY, attr_bits;

      CK_ATTRIBUTE pub_tmpl[] =
      {
	 {CKA_CLASS, &keyClass, sizeof(keyClass)},
	 {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
	 {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp) },
	 {CKA_MODULUS, modulus, bits/8 },
	 {CKA_MODULUS_BITS,    &bits,    sizeof(bits)    }
      };
      CK_ATTRIBUTE mod_bits_tmpl[] =
      {
	 {CKA_MODULUS_BITS,    &attr_bits,    sizeof(attr_bits)    }
      };

      if (!modulus) {
	 testcase_error("malloc of %lu bytes failed", bits/8);
	 return -1;
      }

      rc = funcs->C_CreateObject(session, pub_tmpl, 5, &publ_key);
      if (rc != CKR_ATTRIBUTE_READ_ONLY && rc != CKR_TEMPLATE_INCONSISTENT) {
	 free(modulus);
	 show_error("   C_CreateObject", rc );
	 return rc;
      }

      // Create the object correctly, without CKA_MODULUS_BITS
      rc = funcs->C_CreateObject(session, pub_tmpl, 4, &publ_key);
      if (rc != CKR_OK) {
	 free(modulus);
	 show_error("   C_CreateObject", rc );
	 return rc;
      }

      // Check that PKCS#11 added the CKA_MODULUS_BITS attribute
      rc = funcs->C_GetAttributeValue(session, publ_key, mod_bits_tmpl, 1);
      if (rc != CKR_OK) {
	 free(modulus);
	 show_error("   C_CreateObject", rc );
	 return rc;
      }

      if (bits != attr_bits) {
	 free(modulus);
	 testcase_fail("modulus bits(%lu) != requested size of "
		       "modulus(%lu) in created object", attr_bits, bits);
	 return -1;
      }

      free(modulus);
   }

   // Use no pub exp
   {
      CK_ATTRIBUTE pub_tmpl[] =
      {
         {CKA_MODULUS_BITS,    &bits,    sizeof(bits)    }
      };

      rc = funcs->C_GenerateKeyPair( session,   &mech,
                                     pub_tmpl,   1,
                                     NULL,       0,
                                     &publ_key, &priv_key );
      if (rc != CKR_TEMPLATE_INCOMPLETE) {
         show_error("   C_GenerateKeyPair #1", rc );
         return rc;
   }

   }

   // Leave out required attribute CKA_MODULUS_BITS
   {
      CK_BYTE   pub_exp[] = { 0x1, 0x0, 0x1 };

      CK_ATTRIBUTE pub_tmpl[] =
      {
         {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp) }
      };

      rc = funcs->C_GenerateKeyPair( session,   &mech,
                                     pub_tmpl,   1,
                                     NULL,       0,
                                     &publ_key, &priv_key );
      if (rc != CKR_TEMPLATE_INCOMPLETE) {
         show_error("   C_GenerateKeyPair #2", rc );
         return rc;
      }

   }

   // Check for public exponent in the private key, SF bug 3131950
   // Prior implementations of opencryptoki created CKA_PUBLIC_EXPONENT
   // in the private key, but left its value as 0
   {
      CK_BYTE   pub_exp[] = { 0x1, 0x0, 0x1 }, test_exp[3];

      CK_ATTRIBUTE pub_tmpl[] =
      {
         {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp) },
         {CKA_MODULUS_BITS,    &bits,    sizeof(bits)    }
      };
      CK_ATTRIBUTE test_tmpl[] =
      {
	 {CKA_PUBLIC_EXPONENT, NULL, 0}
      };

      rc = funcs->C_GenerateKeyPair( session,   &mech,
                                     pub_tmpl,   2,
                                     NULL,       0,
                                     &publ_key, &priv_key );
      if (rc != CKR_OK) {
         show_error("   C_GenerateKeyPair #3", rc );
         return rc;
      }

      rc = funcs->C_GetAttributeValue( session, priv_key, test_tmpl, 1);
      if (rc != CKR_OK) {
         show_error("   C_GetAttributeValue #1", rc );
         return rc;
      }

      if (test_tmpl[0].ulValueLen != pub_tmpl[0].ulValueLen) {
	 testcase_fail("length of private key's public exponent value (%lu)"
		       " doesn't match public key's (%lu)", test_tmpl[0].ulValueLen,
		       pub_tmpl[0].ulValueLen);
         rc = -1;
	 goto done;
      }

      test_tmpl[0].pValue = test_exp;
      rc = funcs->C_GetAttributeValue( session, priv_key, test_tmpl, 1);
      if (rc != CKR_OK) {
         show_error("   C_GetAttributeValue #2", rc );
         goto done;
      }

      if (memcmp(test_exp, pub_exp, sizeof(test_exp))) {
	 testcase_fail("value of private key's public exponent value"
		       " doesn't match public key's");
         rc = -1;
	 goto done;
      }

   }

done:
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

   printf("Using slot #%lu...\n\n", SLOT_ID );

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
