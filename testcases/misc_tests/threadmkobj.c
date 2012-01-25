// File: tok_obj.c
//
// Test driver for testing the proper storage of token objects
//
//

#define _REENTRANT

#include <pthread.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <dlfcn.h>

#include "pkcs11types.h"
#include "regress.h"

int  do_GetInfo(void);
int  do_GetFunctionList(void);

void init_coprocessor(void);

CK_RV _C_GetFunctionList( CK_FUNCTION_LIST ** ) ;

CK_FUNCTION_LIST  *funcs;

CK_SLOT_ID  SLOT_ID;

CK_RV
open_session_and_login(void)
{
CK_FLAGS          flags;
CK_SESSION_HANDLE h_session;
CK_RV             rc;
CK_BYTE           user_pin[PKCS11_MAX_PIN_LEN];
CK_ULONG          user_pin_len;

   if (get_user_pin(user_pin))
	   return CKR_FUNCTION_FAILED;
   user_pin_len = (CK_ULONG)strlen((char *)user_pin);

   // create a USER R/W session
   //
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( SLOT_ID, flags, NULL, NULL, &h_session );

   rc = funcs->C_Login( h_session, CKU_USER, user_pin, user_pin_len );

   return rc;
}

// do_create_token_object()
//
int do_create_token_object( void )
{
   CK_FLAGS          flags;
   CK_SESSION_HANDLE h_session;
   CK_RV             rc;
   CK_BYTE           user_pin[PKCS11_MAX_PIN_LEN];
   CK_ULONG          user_pin_len;

   CK_BYTE           true  = TRUE;
   CK_BYTE           false = FALSE;

   CK_OBJECT_HANDLE    h_cert1;
   CK_OBJECT_CLASS     cert1_class         = CKO_CERTIFICATE;
   CK_CERTIFICATE_TYPE cert1_type          = CKC_X_509;
   CK_BYTE             cert1_subject[]     = "Certificate subject #1";
   CK_BYTE             cert1_value[]       = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";

   CK_ATTRIBUTE        cert1_attribs[] =
   {
       {CKA_CLASS,            &cert1_class,       sizeof(cert1_class)   },
       {CKA_TOKEN,            &true,              sizeof(true)          },
       {CKA_CERTIFICATE_TYPE, &cert1_type,        sizeof(cert1_type)    },
       {CKA_SUBJECT,          &cert1_subject,     sizeof(cert1_subject) },
       {CKA_VALUE,            &cert1_value,       sizeof(cert1_value)   },
       {CKA_PRIVATE,          &true,              sizeof(false)         }
   };



   if (get_user_pin(user_pin))
	   return CKR_FUNCTION_FAILED;
   user_pin_len = (CK_ULONG)strlen((char *)user_pin);

   // create a USER R/W session
   //
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( SLOT_ID, flags, NULL, NULL, &h_session );
   if (rc != CKR_OK) {
      show_error("   C_OpenSession #1", rc );
      rc = FALSE;
      goto done;
   }

//   rc = funcs->C_Login( h_session, CKU_USER, user_pin, user_pin_len );
//   if (rc != CKR_OK) {
//      show_error("   C_Login #1", rc );
//      rc = FALSE;
//      goto done;
//   }

   // create the token objects
   //
   rc = funcs->C_CreateObject( h_session, cert1_attribs, 6, &h_cert1 );
   if (rc != CKR_OK) {
      show_error("   C_CreateObject #1", rc );
      rc = FALSE;
      goto done;
   }


   rc = TRUE;

done:
   funcs->C_CloseSession( h_session );
   return rc;
}

#define NUMOBJS 10

int
thread_func(void *thid)
{
   int   i=0;
   CK_RV  rv;
   int   *id ;

   id = (int *)thid;
  
   do {
     rv = do_create_token_object();
     if (rv != 1) return rv;
   } while (++i < NUMOBJS );

   return rv;
}

//
//
#define THREADCNT 5
int
main( int argc, char **argv )
{
   int i, rc;
   pthread_t		id[100];
   int thid[100];


   SLOT_ID = 0;

   for (i=1; i < argc; i++) {
      if (strcmp(argv[i], "-slot") == 0) {
         SLOT_ID = atoi(argv[i+1]);
         i++;
      }

      if (strcmp(argv[i], "-h") == 0) {
         printf("usage:  %s [-slot <num>] [-h]\n\n", argv[0] );
         printf("By default, Slot #1 is used\n\n");
         return 0;
      }
   }

   printf("Using slot #%lu...\n\n", SLOT_ID );

   rc = do_GetFunctionList();
   if (!rc)
      return -1;

   funcs->C_Initialize( NULL );


   if ((rc = open_session_and_login()) != CKR_OK)
	   return rc;

   for (i=0;i<THREADCNT;i++){
	   thid[i] = i;
	   printf("Creating thread %d \n",thid[i]);
	   pthread_create(&id[i],NULL,(void*(*)(void *))thread_func,(void *)&(thid[i]));
   }

   for (i=0;i<THREADCNT;i++){
	 printf("Joining thread %ld\n",id[i]);
	 pthread_join(id[i],NULL);
   }

   rc = funcs->C_Finalize( NULL );
   if (rc != CKR_OK)
     return -1;

   return 0;
}
