// File: driver.c
// G
//
// Test driver.  In-depth regression test for PKCS #11
//

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"
#include "pkcs32.h"

// Purpose:  to cause a variety of crashes to test that the Cryptoki.DLL
//           DLL Init-Term routine properly detaches from the coprocessor
//           in the event of a abnormal program termination.
//
CK_BYTE
do_crash()
{
   // dereferencing a NULL pointer detaches correctly
   CK_BYTE *ptr = NULL;
   CK_BYTE  a;

   a = *ptr;
   return a;
}


//
//
int do_DummySpeed( void )
{
#if 0
   CK_SLOT_ID        slot_id;
   CK_ULONG          i;
   CK_RV             rc;


   printf("do_DummySpeed.  1000 iterations to the card...\n");


   slot_id = SLOT_ID;

   for (i=0; i < 1000; i++) {
      rc = DummyFunction( slot_id );
      if (rc != CKR_OK) {
         show_error("   DummyFunction", rc );
         return FALSE;
      }
   }

   printf("Done...\n");
#endif
   return TRUE;
}


//
//
int do_GetInfo( void )
{
   CK_INFO info;
   CK_RV   rc;

   printf("do_GetInfo...\n");

   rc = funcs->C_GetInfo( &info );

   if (rc != CKR_OK) {
      show_error("   C_GetInfo", rc );
      return FALSE;
   }

   printf("Looks okay...\n");
   return TRUE;
}


//
//
int do_GetSlotList( void )
{
   CK_BBOOL        tokenPresent;
   CK_SLOT_ID_PTR  pSlotList;
   CK_ULONG        ulCount;
   CK_RV           rc;


   printf("do_GetSlotList...\n");

   // first, get the count
   //
   tokenPresent = TRUE;  // this is the only case with this implementation

   rc = funcs->C_GetSlotList( tokenPresent, NULL, &ulCount );
   if (rc != CKR_OK) {
      show_error("   C_GetSlotList", rc );
      return FALSE;
   }

   pSlotList = (CK_SLOT_ID *)malloc( ulCount * sizeof(CK_SLOT_ID) );
   if (!pSlotList) {
      printf("   DRIVER ERROR:  CANNOT ALLOCATE MEMORY FOR SLOT LIST\n");
      return FALSE;
   }

   // now, get the slots
   //
   rc = funcs->C_GetSlotList( tokenPresent, pSlotList, &ulCount );
   if (rc != CKR_OK) {
      show_error("   C_GetSlotList", rc );
      return FALSE;
   }

   free( pSlotList );

   printf("Looks okay...\n");
   return TRUE;
}


//
//
int do_GetSlotInfo( void )
{
   CK_SLOT_ID    slot_id;
   CK_SLOT_INFO  info;
   CK_RV         rc;


   printf("do_GetSlotInfo...\n");

   slot_id = SLOT_ID;

   rc = funcs->C_GetSlotInfo( slot_id, &info );
   if (rc != CKR_OK) {
      show_error("   C_GetSlotInfo", rc );
      return FALSE;
   }

   printf("   CK_SLOT_INFO for slot #1:  \n");
   printf("      slotDescription:  %64.64s\n",  info.slotDescription );
   printf("      manufacturerID:   %32.32s\n",  info.manufacturerID );
   printf("      flags:            %p\n",       (void *)info.flags );
   printf("      hardwareVersion:  %d.%d\n",    info.hardwareVersion.major, info.hardwareVersion.minor );
   printf("      firmwareVersion:  %d.%d\n",    info.firmwareVersion.major, info.firmwareVersion.minor );

   printf("Looks Okay...\n");

   return TRUE;
}


//
//
int do_GetTokenInfo( void )
{
   CK_SLOT_ID     slot_id;
   CK_TOKEN_INFO  info;
   CK_RV          rc;

   printf("do_GetTokenInfo...\n");

   slot_id = SLOT_ID;

   rc = funcs->C_GetTokenInfo( slot_id, &info );
   if (rc != CKR_OK) {
      show_error("   C_GetTokenInfo", rc );
      return FALSE;
   }


   printf("   CK_TOKEN_INFO for slot #1:  \n");
   printf("      label:                   %32.32s\n",  info.label );
   printf("      manufacturerID:          %32.32s\n",  info.manufacturerID );
   printf("      model:                   %16.16s\n",  info.model );
   printf("      serialNumber:            %16.16s\n",  info.serialNumber );
   printf("      flags:                   %p\n",       (void *)info.flags );
   printf("      ulMaxSessionCount:       %ld\n",      info.ulMaxSessionCount );
   printf("      ulSessionCount:          %ld\n",      info.ulSessionCount );
   printf("      ulMaxRwSessionCount:     %ld\n",      info.ulMaxRwSessionCount );
   printf("      ulRwSessionCount:        %ld\n",      info.ulRwSessionCount );
   printf("      ulMaxPinLen:             %ld\n",      info.ulMaxPinLen );
   printf("      ulMinPinLen:             %ld\n",      info.ulMinPinLen );
   printf("      ulTotalPublicMemory:     %ld\n",      info.ulTotalPublicMemory );
   printf("      ulFreePublicMemory:      %ld\n",      info.ulFreePublicMemory );
   printf("      ulTotalPrivateMemory:    %ld\n",      info.ulTotalPrivateMemory );
   printf("      ulFreePrivateMemory:     %ld\n",      info.ulFreePrivateMemory );
   printf("      hardwareVersion:         %d.%d\n",    info.hardwareVersion.major, info.hardwareVersion.minor );
   printf("      firmwareVersion:         %d.%d\n",    info.firmwareVersion.major, info.firmwareVersion.minor );
   printf("      time:                    %16.16s\n",  info.utcTime );

   printf("Looks okay...\n");

   return TRUE;
}


//
//
int do_GetMechanismList( void )
{
   CK_SLOT_ID         slot_id;
   CK_ULONG           count;
   CK_MECHANISM_TYPE *mech_list;
   CK_RV              rc;


   printf("do_GetMechanismList...\n");

   slot_id = SLOT_ID;

   rc = funcs->C_GetMechanismList( slot_id, NULL, &count );
   if (rc != CKR_OK) {
      show_error("   C_GetMechanismList #1", rc );
      return FALSE;
   }

   printf("   C_GetMechanismList #1 returned %ld mechanisms\n", count );

   mech_list = (CK_MECHANISM_TYPE *)malloc( count * sizeof(CK_MECHANISM_TYPE) );
   if (!mech_list)
      return CKR_HOST_MEMORY;

   rc = funcs->C_GetMechanismList( slot_id, mech_list, &count );
   if (rc != CKR_OK) {
      show_error("   C_GetMechanismList #2", rc );
      return FALSE;
   }

   free( mech_list );

   printf("Looks okay...\n");

   return TRUE;
}


//
//
int do_GetMechanismInfo( void )
{
   CK_ULONG           count;
   CK_MECHANISM_TYPE *mech_list;
   CK_RV              rc;

   CK_SLOT_ID         slot_id;
   CK_MECHANISM_INFO  info;
   CK_ULONG           i;


   printf("do_GetMechanismInfo...\n");

   slot_id = SLOT_ID;

   rc = funcs->C_GetMechanismList( slot_id, NULL, &count );
   if (rc != CKR_OK) {
      show_error("   C_GetMechanismList #1", rc );
      return FALSE;
   }

   mech_list = (CK_MECHANISM_TYPE *)malloc( count * sizeof(CK_MECHANISM_TYPE) );
   if (!mech_list)
      return CKR_HOST_MEMORY;

   rc = funcs->C_GetMechanismList( slot_id, mech_list, &count );
   if (rc != CKR_OK) {
      show_error("   C_GetMechanismList #2", rc );
      return FALSE;
   }

   for (i=0; i < count; i++) {
      rc = funcs->C_GetMechanismInfo( slot_id, mech_list[i], &info );
      if (rc != CKR_OK) {
         show_error("   C_GetMechanismInfo", rc );
         printf("   Tried to get info on mechanism # %ld\n", mech_list[i] );
         return FALSE;
      }

      printf("   Mechanism #%ld\n",  mech_list[i] );
      printf("      ulMinKeySize:  %ld\n",  info.ulMinKeySize );
      printf("      ulMaxKeySize:  %ld\n",  info.ulMaxKeySize );
      printf("      flags:         %p\n",   (void *)info.flags );
   }

   free( mech_list );

   printf("Looks okay...\n");

   return TRUE;
}


//
//
int do_InitPIN( void )
{
   CK_SLOT_ID         slot_id;
   CK_FLAGS           flags;
   CK_SESSION_HANDLE  session;
   CK_CHAR            so_pin[PKCS11_MAX_PIN_LEN];
   CK_CHAR            user_pin[PKCS11_MAX_PIN_LEN];
   CK_ULONG           so_pin_len;
   CK_ULONG           user_pin_len;
   CK_RV              rc;

   printf("do_InitPIN...\n");

   if (get_user_pin(user_pin))
	   return CKR_FUNCTION_FAILED;
   user_pin_len = (CK_ULONG)strlen((char *)user_pin);

   if (get_so_pin(so_pin))
	   return CKR_FUNCTION_FAILED;
   so_pin_len = (CK_ULONG)strlen((char *)so_pin);

   slot_id = SLOT_ID;
   flags   = CKF_SERIAL_SESSION | CKF_RW_SESSION;

   // try to call C_InitPIN from a public session
   //
   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      return FALSE;
   }

   rc = funcs->C_InitPIN( session, user_pin, user_pin_len );
   if (rc != CKR_USER_NOT_LOGGED_IN) {
      show_error("   C_InitPIN #1", rc );
      printf("   Expected CKR_USER_NOT_LOGGED_IN\n" );
      return FALSE;
   }

   // try to call C_InitPIN from an SO session
   //
   rc = funcs->C_Login( session, CKU_SO, so_pin, so_pin_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #2", rc );
      return FALSE;
   }

   rc = funcs->C_InitPIN( session, user_pin, user_pin_len );
   if (rc != CKR_OK) {
      show_error("   C_InitPIN #2", rc );
      return FALSE;
   }

   rc = funcs->C_Logout( session );
   if (rc != CKR_OK) {
      show_error("   C_Logout #1", rc );
      return FALSE;
   }


   // try to call C_InitPIN from a normal user session
   //
   rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #1", rc );
      return FALSE;
   }

   rc = funcs->C_InitPIN( session, user_pin, user_pin_len );
   if (rc != CKR_USER_NOT_LOGGED_IN) {
      show_error("   C_InitPIN #2", rc );
      printf("   Expected CKR_USER_NOT_LOGGED_IN\n" );
      return FALSE;
   }

   rc = funcs->C_Logout( session );
   if (rc != CKR_OK) {
      show_error("   C_Logout #2", rc );
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
int do_SetPIN( void )
{
   CK_SLOT_ID        slot_id;
   CK_FLAGS          flags;
   CK_SESSION_HANDLE session;
   CK_CHAR           old_pin[PKCS11_MAX_PIN_LEN];
   CK_CHAR           new_pin[PKCS11_MAX_PIN_LEN];
   CK_ULONG          old_len;
   CK_ULONG          new_len;
   CK_RV             rc;

   printf("do_SetPIN...\n");

   // first, try to set the user PIN
   //

   if (get_user_pin(old_pin))
	   return CKR_FUNCTION_FAILED;
   old_len = (CK_ULONG)strlen((char *)old_pin);

   memcpy( new_pin, "ABCDEF", 6 );
   new_len = 6;

   slot_id = SLOT_ID;
   flags   = CKF_SERIAL_SESSION | CKF_RW_SESSION;


   // try to call C_SetPIN from a public session
   //
   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      return FALSE;
   }

   rc = funcs->C_SetPIN( session, old_pin, old_len, new_pin, new_len );
   if (rc != CKR_SESSION_READ_ONLY) {
      show_error("   C_SetPIN #1", rc );
      printf("   Expected CKR_SESSION_READ_ONLY\n");
      return FALSE;
   }

   // try to call C_SetPIN from a normal user session
   //
   rc = funcs->C_Login( session, CKU_USER, old_pin, old_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #1", rc );
      return FALSE;
   }

   rc = funcs->C_SetPIN( session, old_pin, old_len, new_pin, new_len );
   if (rc != CKR_OK) {
      show_error("   C_SetPIN #2", rc );
      return FALSE;
   }

   rc = funcs->C_Logout( session );
   if (rc != CKR_OK) {
      show_error("   C_Logout #1", rc );
      return FALSE;
   }

   // now, try to log in with the old PIN
   //
   rc = funcs->C_Login( session, CKU_USER, old_pin, old_len );
   if (rc != CKR_PIN_INCORRECT) {
      show_error("   C_Login #2", rc );
      printf("   Expected CKR_PIN_INCORRECT\n");
      return FALSE;
   }

   rc = funcs->C_Login( session, CKU_USER, new_pin, new_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #3", rc );
      return FALSE;
   }

   // change the PIN back to the original so the rest of this program
   // doesn't break
   //
   rc = funcs->C_SetPIN( session, new_pin, new_len, old_pin, old_len );
   if (rc != CKR_OK) {
      show_error("   C_SetPIN #3", rc );
      return FALSE;
   }

   rc = funcs->C_Logout( session );
   if (rc != CKR_OK) {
      show_error("   C_Logout #2", rc );
      return FALSE;
   }

   //
   // done with user tests...now try with the SO
   //
   if (get_so_pin(old_pin))
	   return CKR_FUNCTION_FAILED;


   // try to call C_SetPIN from a normal user session
   //
   rc = funcs->C_Login( session, CKU_SO, old_pin, old_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #3", rc );
      return FALSE;
   }

   rc = funcs->C_SetPIN( session, old_pin, old_len, new_pin, new_len );
   if (rc != CKR_OK) {
      show_error("   C_SetPIN #4", rc );
      return FALSE;
   }

   rc = funcs->C_Logout( session );
   if (rc != CKR_OK) {
      show_error("   C_Logout #3", rc );
      return FALSE;
   }

   // now, try to log in with the old PIN
   //
   rc = funcs->C_Login( session, CKU_SO, old_pin, old_len );
   if (rc != CKR_PIN_INCORRECT) {
      show_error("   C_Login #4", rc );
      printf("   Expected CKR_PIN_INCORRECT\n");
      return FALSE;
   }

   rc = funcs->C_Login( session, CKU_SO, new_pin, new_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #5", rc );
      return FALSE;
   }

   // change the PIN back to the original so the rest of this program
   // doesn't break
   //
   rc = funcs->C_SetPIN( session, new_pin, new_len, old_pin, old_len );
   if (rc != CKR_OK) {
      show_error("   C_SetPIN #5", rc );
      return FALSE;
   }

   rc = funcs->C_Logout( session );
   if (rc != CKR_OK) {
      show_error("   C_Logout #4", rc );
      return FALSE;
   }

   printf("Success.\n");

   return TRUE;
}


//
//
int do_GenerateRandomData( void )
{
   CK_SLOT_ID        slot_id;
   CK_SESSION_HANDLE h1;
   CK_FLAGS          flags;
   CK_BYTE           rand_data1[8];
   CK_BYTE           rand_data2[8192];
   CK_BYTE	     rand_seed[1024];
   CK_RV             rc;

   printf("do_GenerateRandomData...\n");

   slot_id = SLOT_ID;
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h1 );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #2", rc );
      return FALSE;
   }


   rc = funcs->C_SeedRandom(h1, rand_seed,sizeof(rand_seed));
   if (rc != CKR_OK){
      show_error("   C_SeedRandom #1",rc);
      return FALSE;
   }

   rc = funcs->C_GenerateRandom( h1, rand_data1, sizeof(rand_data1) );
   if (rc != CKR_OK) {
      show_error("   C_GenerateRandom #1", rc );
      return FALSE;
   }

   rc = funcs->C_GenerateRandom( h1, rand_data2, sizeof(rand_data2) );
   if (rc != CKR_OK) {
      show_error("   C_GenerateRandom #2", rc );
      return FALSE;
   }

   rc = funcs->C_CloseSession( h1 );
   if (rc != CKR_OK) {
      show_error("   C_CloseSession #2", rc );
      return FALSE;
   }

   printf("Looks okay...\n");

   return TRUE;
}


//  //1) generate a DES key from a RO, PUBLIC session.  should fail
//  //2) generate a DES key from a RW, PUBLIC session.  should fail
//  3) generate a DES key from a RO, USER   session.
//  4) generate a DES key from a RW, USER   session.
//
//  5) generate a DES key from a RO, PUBLIC session.  specify template for PUBLIC object
//  6) generate a DES key from a RO, PUBLIC session.  specify template for PUBLIC object
//
//  7) generate a DES key from a RW, USER   session.  specify wrong class
//  8) generate a DES key from a RW, USER   session.  specify right class
//  9) generate a DES key from a RW, USER   session.  specify wrong key type
// 10) generate a DES key from a RW, USER   session.  specify right key type
//
//
int do_GenerateKey( void )
{
   CK_SLOT_ID          slot_id;
   CK_SESSION_HANDLE   session;
   CK_MECHANISM        mech;
   CK_OBJECT_HANDLE    h_key;
   CK_FLAGS            flags;
   CK_BYTE             user_pin[8];
   CK_ULONG            user_pin_len;
   CK_RV               rc;


   printf("do_GenerateKey...\n");

   slot_id = SLOT_ID;

   if (get_user_pin(user_pin))
	   return CKR_FUNCTION_FAILED;
   user_pin_len = (CK_ULONG)strlen((char *)user_pin);

   mech.mechanism      = CKM_DES_KEY_GEN;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;


//   //
//   //
//   flags = CKF_SERIAL_SESSION;
//   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
//   if (rc != CKR_OK) {
//      show_error("   C_OpenSession #1", rc );
//      return FALSE;
//   }
//   rc = funcs->C_GenerateKey( session, &mech, NULL, 0, &h_key );
//   if (rc != CKR_USER_NOT_LOGGED_IN) {
//      show_error("   C_GenerateKey #1", rc );
//      printf("   Expected CKR_USER_NOT_LOGGED_IN\n" );
//      return FALSE;
//   }
//
//   rc = funcs->C_CloseSession( session );
//   if (rc != CKR_OK) {
//      show_error("   C_CloseSession #1", rc );
//      return FALSE;
//   }
//
//
//   // 2) generate a DES key from RW PUBLIC session.  this should also fail.
//   //
//   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
//   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
//   if (rc != CKR_OK) {
//      show_error("   C_OpenSession #2", rc );
//      return FALSE;
//   }
//
//   rc = funcs->C_GenerateKey( session, &mech, NULL, 0, &h_key );
//   if (rc != CKR_USER_NOT_LOGGED_IN) {
//      show_error("   C_GenerateKey #2", rc );
//      printf("   Expected CKR_USER_NOT_LOGGED_IN\n" );
//      return FALSE;
//   }
//
//   rc = funcs->C_CloseSession( session );
//   if (rc != CKR_OK) {
//      show_error("   C_CloseSession #2", rc );
//      return FALSE;
//   }


   // 3) generate a DES key from RO USER session
   //
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

   rc = funcs->C_GenerateKey( session, &mech, NULL, 0, &h_key );
   if (rc != CKR_OK) {
      show_error("   C_GenerateKey #3", rc );
      return FALSE;
   }

   rc = funcs->C_CloseSession( session );
   if (rc != CKR_OK) {
      show_error("   C_CloseSession #3", rc );
      return FALSE;
   }


   // 4) generate a DES key from RW USER session
   //
   flags = CKF_SERIAL_SESSION;
   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #4", rc );
      return FALSE;
   }

   rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #2", rc );
      return FALSE;
   }

   rc = funcs->C_GenerateKey( session, &mech, NULL, 0, &h_key );
   if (rc != CKR_OK) {
      show_error("   C_GenerateKey #4", rc );
      return FALSE;
   }

   rc = funcs->C_CloseSession( session );
   if (rc != CKR_OK) {
      show_error("   C_CloseSession #4", rc );
      return FALSE;
   }


   // 5) generate a DES key from a RO PUBLIC session.  specify a template
   //    to indicate this is a public object
   //
   {
      CK_BBOOL    false = FALSE;
      CK_ATTRIBUTE  tmpl[] =
      {
         {CKA_PRIVATE,  &false, sizeof(CK_BBOOL) }
      };

      flags = CKF_SERIAL_SESSION;
      rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
      if (rc != CKR_OK) {
         show_error("   C_OpenSession #5", rc );
         return FALSE;
      }
      rc = funcs->C_GenerateKey( session, &mech, tmpl, 1, &h_key );
      if (rc != CKR_OK) {
         show_error("   C_GenerateKey #5", rc );
         return FALSE;
      }

      rc = funcs->C_CloseSession( session );
      if (rc != CKR_OK) {
         show_error("   C_CloseSession #5", rc );
         return FALSE;
      }
   }


   // 6) generate a DES key from a RW PUBLIC session.  specify a template
   //    to indicate this is a public object
   //
   {
      CK_BBOOL    false = FALSE;
      CK_ATTRIBUTE  tmpl[] =
      {
         {CKA_PRIVATE,  &false, sizeof(CK_BBOOL) }
      };

      flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
      rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
      if (rc != CKR_OK) {
         show_error("   C_OpenSession #6", rc );
         return FALSE;
      }
      rc = funcs->C_GenerateKey( session, &mech, tmpl, 1, &h_key );
      if (rc != CKR_OK) {
         show_error("   C_GenerateKey #6", rc );
         return FALSE;
      }

      rc = funcs->C_CloseSession( session );
      if (rc != CKR_OK) {
         show_error("   C_CloseSession #6", rc );
         return FALSE;
      }
   }


   // 7) generate a DES key from a RW USER session.  specify a template
   //    to that specifies the wrong CKA_CLASS
   //
   {
      CK_OBJECT_CLASS   class = CKO_DATA;
      CK_ATTRIBUTE  tmpl[] =
      {
         {CKA_CLASS,  &class, sizeof(class) }
      };

      flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
      rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
      if (rc != CKR_OK) {
         show_error("   C_OpenSession #7", rc );
         return FALSE;
      }

      rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
      if (rc != CKR_OK) {
         show_error("   C_Login #3", rc );
         return FALSE;
      }

      rc = funcs->C_GenerateKey( session, &mech, tmpl, 1, &h_key );
      if (rc != CKR_TEMPLATE_INCONSISTENT) {
         show_error("   C_GenerateKey #7", rc );
         printf("   Expected CKR_TEMPLATE_INCONSISTENT\n");
         return FALSE;
      }

      rc = funcs->C_CloseSession( session );
      if (rc != CKR_OK) {
         show_error("   C_CloseSession #7", rc );
         return FALSE;
      }
   }


   // 8) generate a DES key from a RW USER session.  specify a template
   //    to that specifies the correct CKA_CLASS
   //
   {
      CK_OBJECT_CLASS   class = CKO_SECRET_KEY;
      CK_ATTRIBUTE  tmpl[] =
      {
         {CKA_CLASS,  &class, sizeof(class) }
      };

      flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
      rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
      if (rc != CKR_OK) {
         show_error("   C_OpenSession #8", rc );
         return FALSE;
      }

      rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
      if (rc != CKR_OK) {
         show_error("   C_Login #4", rc );
         return FALSE;
      }

      rc = funcs->C_GenerateKey( session, &mech, tmpl, 1, &h_key );
      if (rc != CKR_OK) {
         show_error("   C_GenerateKey #8", rc );
         return FALSE;
      }

      rc = funcs->C_CloseSession( session );
      if (rc != CKR_OK) {
         show_error("   C_CloseSession #8", rc );
         return FALSE;
      }
   }


   // 9) generate a DES key from a RW USER session.  specify a template
   //    to that specifies the wrong CKA_KEY_TYPE
   //
   {
      CK_KEY_TYPE   keytype  = CKK_CAST5;
      CK_ATTRIBUTE  tmpl[] =
      {
         {CKA_KEY_TYPE,  &keytype, sizeof(keytype) }
      };

      flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
      rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
      if (rc != CKR_OK) {
         show_error("   C_OpenSession #9", rc );
         return FALSE;
      }

      rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
      if (rc != CKR_OK) {
         show_error("   C_Login #5", rc );
         return FALSE;
      }

      rc = funcs->C_GenerateKey( session, &mech, tmpl, 1, &h_key );
      if (rc != CKR_TEMPLATE_INCONSISTENT) {
         show_error("   C_GenerateKey #9", rc );
         printf("   Expected CKR_TEMPLATE_INCONSISTENT\n");
         return FALSE;
      }

      rc = funcs->C_CloseSession( session );
      if (rc != CKR_OK) {
         show_error("   C_CloseSession #9", rc );
         return FALSE;
      }
   }


   // 10) generate a DES key from a RW USER session.  specify a template
   //     to that specifies the correct CKA_KEY_TYPE
   //
   {
      CK_KEY_TYPE   keytype  = CKK_DES;
      CK_ATTRIBUTE  tmpl[] =
      {
         {CKA_KEY_TYPE,  &keytype, sizeof(keytype) }
      };

      flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
      rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
      if (rc != CKR_OK) {
         show_error("   C_OpenSession #9", rc );
         return FALSE;
      }

      rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
      if (rc != CKR_OK) {
         show_error("   C_Login #5", rc );
         return FALSE;
      }

      rc = funcs->C_GenerateKey( session, &mech, tmpl, 1, &h_key );
      if (rc != CKR_OK) {
         show_error("   C_GenerateKey #9", rc );
         return FALSE;
      }

      rc = funcs->C_CloseSession( session );
      if (rc != CKR_OK) {
         show_error("   C_CloseSession #9", rc );
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


int misc_functions()
{
   SYSTEMTIME  t1, t2;
   int         rc;


   GetSystemTime(&t1);
   rc = do_GetInfo();
   if (!rc)
      return FALSE;
   GetSystemTime(&t2);
   process_time( t1, t2 );

   GetSystemTime(&t1);
   rc = do_GetSlotList();
   if (!rc)
      return FALSE;
   GetSystemTime(&t2);
   process_time( t1, t2 );

   GetSystemTime(&t1);
   rc = do_GetSlotInfo();
   if (!rc)
      return FALSE;
   GetSystemTime(&t2);
   process_time( t1, t2 );

   GetSystemTime(&t1);
   rc = do_GetTokenInfo();
   if (!rc)
      return FALSE;
   GetSystemTime(&t2);
   process_time( t1, t2 );

   //
   // C_WaitForSlotEvent should not be implemented
   //

   GetSystemTime(&t1);
   rc = do_GetMechanismList();
   if (!rc)
      return FALSE;
   GetSystemTime(&t2);
   process_time( t1, t2 );

   GetSystemTime(&t1);
   rc = do_GetMechanismInfo();
   if (!rc)
      return FALSE;
   GetSystemTime(&t2);
   process_time( t1, t2 );

   GetSystemTime(&t1);
   rc = do_GenerateRandomData();
   if (!rc)
      return FALSE;
   GetSystemTime(&t2);
   process_time( t1, t2 );


#if 0
   GetSystemTime(&t1);
   rc = do_GenerateKey();
   if (!rc)
      return FALSE;
   GetSystemTime(&t2);
   process_time( t1, t2 );
#endif

   if (skip_token_obj == TRUE) {
      printf("Skipping do_InitPIN()...\n\n");
   }
   else {
      rc = do_InitPIN();
      if (!rc)
         return FALSE;
   }

   if (skip_token_obj == TRUE) {
      printf("Skipping do_SetPIN()...\n\n");
   }
   else {
      rc = do_SetPIN();
      if (!rc)
         return FALSE;
   }

   return TRUE;
}
