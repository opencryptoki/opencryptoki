// File: tok_obj.c
//
// Test driver for testing the proper storage of token objects
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "p11util.h"


int  do_GetInfo(void);

void init_coprocessor(void);

CK_RV C_GetFunctionList( CK_FUNCTION_LIST ** ) ;

CK_FUNCTION_LIST  *funcs;

CK_SLOT_ID  SLOT_ID;



//
//
void show_error( CK_BYTE *str, CK_RV rc )
{
   printf("%s returned:  %ld - %s\n", str, rc, p11_get_ckr(rc) );
}


//
//
int do_GetFunctionList( void )
{
   CK_RV            rc;

   printf("do_GetFunctionList...\n");

   rc = C_GetFunctionList( &funcs ) ;

   if (rc != CKR_OK) {
      show_error("   C_GetFunctionList", rc );
      return FALSE;
   }

   printf("Looks okay...\n");
   return TRUE;

}



// do_create_token_object()
//
int do_create_token_object( void )
{
   CK_FLAGS          flags;
   CK_SESSION_HANDLE h_session;
   CK_RV             rc;
   CK_BYTE           user_pin[DEFAULT_USER_PIN_LEN];
   CK_ULONG          user_pin_len;

   CK_BYTE           true  = TRUE;
   CK_BYTE           false = FALSE;

   CK_OBJECT_HANDLE    h_cert1;
   CK_OBJECT_CLASS     cert1_class         = CKO_CERTIFICATE;
   CK_CERTIFICATE_TYPE cert1_type          = CKC_X_509;
   CK_BYTE             cert1_subject[]     = "Certificate subject #1";
   CK_BYTE             cert1_id[]          = "Certificate ID #1";
   CK_BYTE             cert1_value[]       = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";

   CK_ATTRIBUTE        cert1_attribs[] =
   {
       {CKA_CLASS,            &cert1_class,       sizeof(cert1_class)   },
       {CKA_TOKEN,            &true,              sizeof(true)          },
       {CKA_CERTIFICATE_TYPE, &cert1_type,        sizeof(cert1_type)    },
       {CKA_SUBJECT,          &cert1_subject,     sizeof(cert1_subject) },
       {CKA_VALUE,            &cert1_value,       sizeof(cert1_value)   },
       {CKA_PRIVATE,          &true,              sizeof(false)         }
       //{CKA_PRIVATE,          &false,              sizeof(false)         }
   };
   CK_ATTRIBUTE  cert_id_attr[] =
   {
       {CKA_ID,               &cert1_id,          sizeof(cert1_id)      }
   };
   CK_OBJECT_HANDLE   obj_list[20];
   CK_ULONG           objcount;



   memcpy( user_pin, DEFAULT_USER_PIN, DEFAULT_USER_PIN_LEN );
   user_pin_len = DEFAULT_USER_PIN_LEN;

   // create a USER R/W session
   //
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   printf("open ing session \n");
   rc = funcs->C_OpenSession( SLOT_ID, flags, NULL, NULL, &h_session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      rc = FALSE;
      goto done;
   }

   printf("login ing session \n");
   rc = funcs->C_Login( h_session, CKU_USER, user_pin, user_pin_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #1", rc );
      rc = FALSE;
      goto done;
   }

   // create the token objects
   //
   printf("create ing session \n");
   rc = funcs->C_CreateObject( h_session, cert1_attribs, 7, &h_cert1 );
   if (rc != CKR_OK) {
      show_error("   C_CreateObject #1", rc );
      rc = FALSE;
      goto done;
   }

   printf("set ing session \n");
   rc = funcs->C_SetAttributeValue(h_session,h_cert1,cert_id_attr,1);
   if (rc != CKR_OK) {
      show_error("   C_SetAttribute #1", rc );
      rc = FALSE;
      goto done;
   }
   // now, retrieve a list of all object handles
   //
   printf("find init ing session \n");
   rc = funcs->C_FindObjectsInit( h_session, cert_id_attr, 1 );
   if (rc != CKR_OK) {
      show_error("   C_FindObjectsInit #1", rc );
      rc = FALSE;
      goto done;
   }

   printf("find  session \n");
   rc = funcs->C_FindObjects( h_session, obj_list, 20, &objcount );
   if (rc != CKR_OK) {
      show_error("   C_FindObjects #1", rc );
      rc = FALSE;
      goto done;
   }

   printf("find final  session \n");
   rc = funcs->C_FindObjectsFinal( h_session );
   if (rc != CKR_OK) {
      show_error("   C_FindObjectsFinal #1", rc );
      rc = FALSE;
      goto done;
   }

   rc = TRUE;

done:
   printf("close all  session \n");
   funcs->C_CloseAllSessions( SLOT_ID );
   return rc;
}


// do_count_token_objects()
//
int do_count_token_objects( void )
{
   CK_FLAGS          flags;
   CK_SESSION_HANDLE h_session;
   CK_RV             rc;
   CK_BYTE           user_pin[DEFAULT_USER_PIN_LEN];
   CK_ULONG          user_pin_len;
   CK_OBJECT_HANDLE  obj_list[20];
   CK_ULONG          find_count;



   memcpy( user_pin, DEFAULT_USER_PIN, DEFAULT_USER_PIN_LEN );
   user_pin_len = DEFAULT_USER_PIN_LEN;


   // create a USER R/W session
   //
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( SLOT_ID, flags, NULL, NULL, &h_session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      rc = FALSE;
      goto done;
   }

   rc = funcs->C_Login( h_session, CKU_USER, user_pin, user_pin_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #1", rc );
      rc = FALSE;
      goto done;
   }

   //
   //---------------------------------------------------------------------
   //

   // now, retrieve a list of all object handles
   //
   rc = funcs->C_FindObjectsInit( h_session, NULL, 0 );
   if (rc != CKR_OK) {
      show_error("   C_FindObjectsInit #1", rc );
      rc = FALSE;
      goto done;
   }

   do { 
   rc = funcs->C_FindObjects( h_session, obj_list, 1, &find_count );
   if (rc != CKR_OK) {
      show_error("   C_FindObjects #1", rc );
      rc = FALSE;
      goto done;
   }
   printf("Found:  %d objects\n", find_count);
   } while (find_count != 0);

   rc = funcs->C_FindObjectsFinal( h_session );
   if (rc != CKR_OK) {
      show_error("   C_FindObjectsFinal #1", rc );
      rc = FALSE;
      goto done;
   }

   rc = TRUE;

done:
   funcs->C_CloseAllSessions( SLOT_ID );
   return rc;
}


// do_verify_token_object()
//
int do_verify_token_object( void )
{
   CK_FLAGS          flags;
   CK_SESSION_HANDLE h_session;
   CK_RV             rc;
   CK_BYTE           user_pin[DEFAULT_USER_PIN_LEN];
   CK_ULONG          user_pin_len;
   CK_OBJECT_HANDLE  obj_list[20];
   CK_ULONG          find_count;

   CK_BYTE           cert1_id[]          = "Certificate ID #1";

   CK_BYTE           buf1[100];
   CK_ATTRIBUTE      verify_attribs[] =
   {
      {CKA_ID, &buf1, sizeof(buf1) }
   };



   memcpy( user_pin, DEFAULT_USER_PIN, DEFAULT_USER_PIN_LEN );
   user_pin_len = DEFAULT_USER_PIN_LEN;


   // create a USER R/W session
   //
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( SLOT_ID, flags, NULL, NULL, &h_session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      rc = FALSE;
      goto done;
   }

   rc = funcs->C_Login( h_session, CKU_USER, user_pin, user_pin_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #1", rc );
      rc = FALSE;
      goto done;
   }

   //
   //---------------------------------------------------------------------
   //

   // now, retrieve a list of all object handles
   //
   rc = funcs->C_FindObjectsInit( h_session, NULL, 0 );
   if (rc != CKR_OK) {
      show_error("   C_FindObjectsInit #1", rc );
      rc = FALSE;
      goto done;
   }

   rc = funcs->C_FindObjects( h_session, obj_list, 20, &find_count );
   if (rc != CKR_OK) {
      show_error("   C_FindObjects #1", rc );
      rc = FALSE;
      goto done;
   }

   if (find_count == 0) {
      printf("ERROR:  no objects to examine\n");
      rc = FALSE;
      goto done;
   }

   // now, try to extract the CKA_APPLICATION attribute from the original
   // this will pull in the token's default value for CKA_APPLICATION which
   //
   verify_attribs[0].ulValueLen = sizeof(buf1);
   rc = funcs->C_GetAttributeValue( h_session, obj_list[0], verify_attribs, 1 );
   if (rc != CKR_OK) {
      show_error("   C_GetAttributeValue #1", rc );
      rc = FALSE;
      goto done;
   }

   if (memcmp( &cert1_id, verify_attribs[0].pValue, sizeof(cert1_id) ) != 0) {
      printf("   ERROR:  extracted attribute doesn't match\n");
      rc = FALSE;
      goto done;
   }

   printf("Attribute matches!  Good.\n");
   rc = TRUE;

done:
   funcs->C_CloseAllSessions( SLOT_ID );
   return rc;
}



int do_destroy_all_token_objects( void )
{
   CK_FLAGS          flags;
   CK_SESSION_HANDLE h_session;
   CK_RV             rc;
   CK_BYTE           user_pin[DEFAULT_USER_PIN_LEN];
   CK_ULONG          user_pin_len;

   CK_OBJECT_HANDLE  obj_list[20];
   CK_ULONG          find_count;
   CK_ULONG          i;


   memcpy( user_pin, DEFAULT_USER_PIN, DEFAULT_USER_PIN_LEN );
   user_pin_len = DEFAULT_USER_PIN_LEN;


   // create a USER R/W session
   //
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( SLOT_ID, flags, NULL, NULL, &h_session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      rc = FALSE;
      goto done;
   }

   rc = funcs->C_Login( h_session, CKU_USER, user_pin, user_pin_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #1", rc );
      rc = FALSE;
      goto done;
   }

   //
   //---------------------------------------------------------------------
   //

   // now, retrieve a list of all object handles
   //
   rc = funcs->C_FindObjectsInit( h_session, NULL, 0 );
   if (rc != CKR_OK) {
      show_error("   C_FindObjectsInit #1", rc );
      rc = FALSE;
      goto done;
   }

   do {
      rc = funcs->C_FindObjects( h_session, obj_list, 20, &find_count );
      if (rc != CKR_OK) {
         show_error("   C_FindObjects #1", rc );
         rc = FALSE;
         goto done;
      }

      for (i=0; i < find_count; i++) {
         rc = funcs->C_DestroyObject( h_session, obj_list[i] );
         if (rc != CKR_OK) {
            printf("   C_DestroyObject #%d returned", i);
            show_error(" ", rc );
            rc = FALSE;
            goto done;
         }
      }
   } while (find_count != 0);

   rc = funcs->C_FindObjectsFinal( h_session );
   if (rc != CKR_OK) {
      show_error("   C_FindObjectsFinal #1", rc );
      rc = FALSE;
      goto done;
   }

   rc = TRUE;

done:
   funcs->C_CloseAllSessions( SLOT_ID );
   return rc;
}


int do_inittoken( void )
{
   CK_BYTE           label[32];
   CK_BYTE           so_pin[DEFAULT_SO_PIN_LEN];
   CK_ULONG          so_pin_len;
   int               len;
   CK_RV             rc;


   memcpy( so_pin, DEFAULT_SO_PIN, DEFAULT_SO_PIN_LEN );
   so_pin_len = DEFAULT_SO_PIN_LEN;

//   memcpy( label, "A new label                           ", 32 );
   memcpy( label,   "                                      ", 32 );

   printf("Enter Token Label:");
   scanf("%32s",label);
   printf("\nLabel is %s:",label);

   for (len = 0; len <31;len++){
      if (label[len] == '\0'){
         label[len] = ' ';
         break;
      }
   }
   printf("\n");

//   memcpy( label,   "RemoteLeeds                           ", 32 );

   rc = funcs->C_InitToken( SLOT_ID, NULL, so_pin_len, label );
   if (rc != CKR_ARGUMENTS_BAD) {
      show_error(" C_InitToken Fail #1",rc);
      rc = FALSE;
      goto done;
   }

   rc = funcs->C_InitToken( SLOT_ID, so_pin, so_pin_len, NULL );
   if (rc != CKR_ARGUMENTS_BAD) {
      show_error(" C_InitToken Fail #2",rc);
      rc = FALSE;
      goto done;
   }

   rc = funcs->C_InitToken( SLOT_ID, so_pin, so_pin_len, label );
   if (rc != CKR_OK) {
      show_error("   C_InitToken #1", rc );
      rc = FALSE;
      goto done;
   }

   rc = TRUE;

done:
   return rc;
}


int do_setUserPIN( void )
{
   CK_BYTE  so_pin[DEFAULT_SO_PIN_LEN];
   CK_BYTE  user_pin[DEFAULT_USER_PIN_LEN];
   CK_ULONG user_pin_len, so_pin_len;
   CK_FLAGS flags;
   CK_SESSION_HANDLE h_session;
   CK_ULONG rc;

   memcpy( so_pin,   DEFAULT_SO_PIN, DEFAULT_SO_PIN_LEN );
   memcpy( user_pin, DEFAULT_USER_PIN, DEFAULT_USER_PIN_LEN );

   so_pin_len = DEFAULT_SO_PIN_LEN;
   user_pin_len = DEFAULT_USER_PIN_LEN;


   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( SLOT_ID, flags, NULL, NULL, &h_session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      rc = FALSE;
      goto done;
   }

   rc = funcs->C_Login( h_session, CKU_SO, so_pin, so_pin_len );
   if (rc != CKR_OK) {
      show_error("   C_Login #1", rc );
      rc = FALSE;
      goto done;
   }

   rc = funcs->C_InitPIN( h_session, user_pin, user_pin_len );
   if (rc != CKR_OK) {
      show_error("   C_InitPIN #1", rc );
      rc = FALSE;
      goto done;
   }

   rc = TRUE;

done:
   funcs->C_CloseAllSessions( SLOT_ID );
   return rc;
}


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
   printf("      flags:                   %0x\n",      info.flags );
   printf("      ulMaxSessionCount:       %d\n",       info.ulMaxSessionCount );
   printf("      ulSessionCount:          %d\n",       info.ulSessionCount );
   printf("      ulMaxRwSessionCount:     %d\n",       info.ulMaxRwSessionCount );
   printf("      ulRwSessionCount:        %d\n",       info.ulRwSessionCount );
   printf("      ulMaxPinLen:             %d\n",       info.ulMaxPinLen );
   printf("      ulMinPinLen:             %d\n",       info.ulMinPinLen );
   printf("      ulTotalPublicMemory:     %d\n",       info.ulTotalPublicMemory );
   printf("      ulFreePublicMemory:      %d\n",       info.ulFreePublicMemory );
   printf("      ulTotalPrivateMemory:    %d\n",       info.ulTotalPrivateMemory );
   printf("      ulFreePrivateMemory:     %d\n",       info.ulFreePrivateMemory );
   printf("      hardwareVersion:         %d.%d\n",    info.hardwareVersion.major, info.hardwareVersion.minor );
   printf("      firmwareVersion:         %d.%d\n",    info.firmwareVersion.major, info.firmwareVersion.minor );
   printf("      time:                    %16.16s\n",  info.utcTime );

   printf("Looks okay...\n");

   return TRUE;
}


//
//
int main( int argc, char **argv )
{
   CK_BYTE            line[20];
   CK_ULONG           val, i;
   int rc;

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

   funcs->C_Initialize( NULL );


   while (1) {
      printf("\n1.  Create a token object\n");
      printf("2.  Count token objects\n");
      printf("3.  Verify contents of the first token object\n");
      printf("4.  Destroy all token objects\n");
      printf("5.  Initialize Token\n");
      printf("6.  Set USER PIN\n");
      printf("7.  Get Token Info\n");
      printf("9.  Exit\n");
      printf("Selection:   ");  fflush(stdout);

      fgets(line, 10, stdin);

      val = atoi(line);

      switch (val) {
         case 1:  do_create_token_object();
                  break;

         case 2:  do_count_token_objects();
                  break;

         case 3:  do_verify_token_object();
                  break;

         case 4:  do_destroy_all_token_objects();
                  break;

         case 5:  do_inittoken();
                  break;

         case 6:  do_setUserPIN();
                  break;

         case 7:  do_GetTokenInfo();
                  break;

         case 9:  goto done;
                  break;
      }
   }

done:

   rc = funcs->C_Finalize( NULL );

   return rc;
}
