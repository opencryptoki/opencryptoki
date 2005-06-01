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


void process_ret_code( CK_RV rc );
int  do_GetInfo(void);

void init_coprocessor(void);

CK_RV _C_GetFunctionList( CK_FUNCTION_LIST ** ) ;

CK_FUNCTION_LIST  *funcs;

CK_SLOT_ID  SLOT_ID;


//
//
void process_ret_code( CK_RV rc )
{
   switch (rc) {
      case CKR_OK: printf(" CKR_OK"); break;
      case CKR_CANCEL: printf(" CKR_CANCEL"); break;
      case CKR_HOST_MEMORY: printf(" CKR_HOST_MEMORY"); break;
      case CKR_SLOT_ID_INVALID: printf(" CKR_SLOT_ID_INVALID"); break;
      case CKR_GENERAL_ERROR: printf(" CKR_GENERAL_ERROR"); break;
      case CKR_FUNCTION_FAILED: printf(" CKR_FUNCTION_FAILED"); break;
      case CKR_ARGUMENTS_BAD: printf(" CKR_ARGUMENTS_BAD"); break;
      case CKR_NO_EVENT: printf(" CKR_NO_EVENT"); break;
      case CKR_NEED_TO_CREATE_THREADS: printf(" CKR_NEED_TO_CREATE_THREADS"); break;
      case CKR_CANT_LOCK: printf(" CKR_CANT_LOCK"); break;
      case CKR_ATTRIBUTE_READ_ONLY: printf(" CKR_ATTRIBUTE_READ_ONLY"); break;
      case CKR_ATTRIBUTE_SENSITIVE: printf(" CKR_ATTRIBUTE_SENSITIVE"); break;
      case CKR_ATTRIBUTE_TYPE_INVALID: printf(" CKR_ATTRIBUTE_TYPE_INVALID"); break;
      case CKR_ATTRIBUTE_VALUE_INVALID: printf(" CKR_ATTRIBUTE_VALUE_INVALID"); break;
      case CKR_DATA_INVALID: printf(" CKR_DATA_INVALID"); break;
      case CKR_DATA_LEN_RANGE: printf(" CKR_DATA_LEN_RANGE"); break;
      case CKR_DEVICE_ERROR: printf(" CKR_DEVICE_ERROR"); break;
      case CKR_DEVICE_MEMORY: printf(" CKR_DEVICE_MEMORY"); break;
      case CKR_DEVICE_REMOVED: printf(" CKR_DEVICE_REMOVED"); break;
      case CKR_ENCRYPTED_DATA_INVALID: printf(" CKR_ENCRYPTED_DATA_INVALID"); break;
      case CKR_ENCRYPTED_DATA_LEN_RANGE: printf(" CKR_ENCRYPTED_DATA_LEN_RANGE"); break;
      case CKR_FUNCTION_CANCELED: printf(" CKR_FUNCTION_CANCELED"); break;
      case CKR_FUNCTION_NOT_PARALLEL: printf(" CKR_FUNCTION_NOT_PARALLEL"); break;
      case CKR_FUNCTION_NOT_SUPPORTED: printf(" CKR_FUNCTION_NOT_SUPPORTED"); break;
      case CKR_KEY_HANDLE_INVALID: printf(" CKR_KEY_HANDLE_INVALID"); break;
      case CKR_KEY_SIZE_RANGE: printf(" CKR_KEY_SIZE_RANGE"); break;
      case CKR_KEY_TYPE_INCONSISTENT: printf(" CKR_KEY_TYPE_INCONSISTENT"); break;
      case CKR_KEY_NOT_NEEDED: printf(" CKR_KEY_NOT_NEEDED"); break;
      case CKR_KEY_CHANGED: printf(" CKR_KEY_CHANGED"); break;
      case CKR_KEY_NEEDED: printf(" CKR_KEY_NEEDED"); break;
      case CKR_KEY_INDIGESTIBLE: printf(" CKR_KEY_INDIGESTIBLE"); break;
      case CKR_KEY_FUNCTION_NOT_PERMITTED: printf(" CKR_KEY_FUNCTION_NOT_PERMITTED"); break;
      case CKR_KEY_NOT_WRAPPABLE: printf(" CKR_KEY_NOT_WRAPPABLE"); break;
      case CKR_KEY_UNEXTRACTABLE: printf(" CKR_KEY_UNEXTRACTABLE"); break;
      case CKR_MECHANISM_INVALID: printf(" CKR_MECHANISM_INVALID"); break;
      case CKR_MECHANISM_PARAM_INVALID: printf(" CKR_MECHANISM_PARAM_INVALID"); break;
      case CKR_OBJECT_HANDLE_INVALID: printf(" CKR_OBJECT_HANDLE_INVALID"); break;
      case CKR_OPERATION_ACTIVE: printf(" CKR_OPERATION_ACTIVE"); break;
      case CKR_OPERATION_NOT_INITIALIZED: printf(" CKR_OPERATION_NOT_INITIALIZED"); break;
      case CKR_PIN_INCORRECT: printf(" CKR_PIN_INCORRECT"); break;
      case CKR_PIN_INVALID: printf(" CKR_PIN_INVALID"); break;
      case CKR_PIN_LEN_RANGE: printf(" CKR_PIN_LEN_RANGE"); break;
      case CKR_PIN_EXPIRED: printf(" CKR_PIN_EXPIRED"); break;
      case CKR_PIN_LOCKED: printf(" CKR_PIN_LOCKED"); break;
      case CKR_SESSION_CLOSED: printf(" CKR_SESSION_CLOSED"); break;
      case CKR_SESSION_COUNT: printf(" CKR_SESSION_COUNT"); break;
      case CKR_SESSION_HANDLE_INVALID: printf(" CKR_SESSION_HANDLE_INVALID"); break;
      case CKR_SESSION_PARALLEL_NOT_SUPPORTED: printf(" CKR_SESSION_PARALLEL_NOT_SUPPORTED"); break;
      case CKR_SESSION_READ_ONLY: printf(" CKR_SESSION_READ_ONLY"); break;
      case CKR_SESSION_EXISTS: printf(" CKR_SESSION_EXISTS"); break;
      case CKR_SESSION_READ_ONLY_EXISTS: printf(" CKR_SESSION_READ_ONLY_EXISTS"); break;
      case CKR_SESSION_READ_WRITE_SO_EXISTS: printf(" CKR_SESSION_READ_WRITE_SO_EXISTS"); break;
      case CKR_SIGNATURE_INVALID: printf(" CKR_SIGNATURE_INVALID"); break;
      case CKR_SIGNATURE_LEN_RANGE: printf(" CKR_SIGNATURE_LEN_RANGE"); break;
      case CKR_TEMPLATE_INCOMPLETE: printf(" CKR_TEMPLATE_INCOMPLETE"); break;
      case CKR_TEMPLATE_INCONSISTENT: printf(" CKR_TEMPLATE_INCONSISTENT"); break;
      case CKR_TOKEN_NOT_PRESENT: printf(" CKR_TOKEN_NOT_PRESENT"); break;
      case CKR_TOKEN_NOT_RECOGNIZED: printf(" CKR_TOKEN_NOT_RECOGNIZED"); break;
      case CKR_TOKEN_WRITE_PROTECTED: printf(" CKR_TOKEN_WRITE_PROTECTED"); break;
      case CKR_UNWRAPPING_KEY_HANDLE_INVALID: printf(" CKR_UNWRAPPING_KEY_HANDLE_INVALID"); break;
      case CKR_UNWRAPPING_KEY_SIZE_RANGE: printf(" CKR_UNWRAPPING_KEY_SIZE_RANGE"); break;
      case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: printf(" CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT"); break;
      case CKR_USER_ALREADY_LOGGED_IN: printf(" CKR_USER_ALREADY_LOGGED_IN"); break;
      case CKR_USER_NOT_LOGGED_IN: printf(" CKR_USER_NOT_LOGGED_IN"); break;
      case CKR_USER_PIN_NOT_INITIALIZED: printf(" CKR_USER_PIN_NOT_INITIALIZED"); break;
      case CKR_USER_TYPE_INVALID: printf(" CKR_USER_TYPE_INVALID"); break;
      case CKR_USER_ANOTHER_ALREADY_LOGGED_IN: printf(" CKR_USER_ANOTHER_ALREADY_LOGGED_IN"); break;
      case CKR_USER_TOO_MANY_TYPES: printf(" CKR_USER_TOO_MANY_TYPES"); break;
      case CKR_WRAPPED_KEY_INVALID: printf(" CKR_WRAPPED_KEY_INVALID"); break;
      case CKR_WRAPPED_KEY_LEN_RANGE: printf(" CKR_WRAPPED_KEY_LEN_RANGE"); break;
      case CKR_WRAPPING_KEY_HANDLE_INVALID: printf(" CKR_WRAPPING_KEY_HANDLE_INVALID"); break;
      case CKR_WRAPPING_KEY_SIZE_RANGE: printf(" CKR_WRAPPING_KEY_SIZE_RANGE"); break;
      case CKR_WRAPPING_KEY_TYPE_INCONSISTENT: printf(" CKR_WRAPPING_KEY_TYPE_INCONSISTENT"); break;
      case CKR_RANDOM_SEED_NOT_SUPPORTED: printf(" CKR_RANDOM_SEED_NOT_SUPPORTED"); break;
      case CKR_RANDOM_NO_RNG: printf(" CKR_RANDOM_NO_RNG"); break;
      case CKR_BUFFER_TOO_SMALL: printf(" CKR_BUFFER_TOO_SMALL"); break;
      case CKR_SAVED_STATE_INVALID: printf(" CKR_SAVED_STATE_INVALID"); break;
      case CKR_INFORMATION_SENSITIVE: printf(" CKR_INFORMATION_SENSITIVE"); break;
      case CKR_STATE_UNSAVEABLE: printf(" CKR_STATE_UNSAVEABLE"); break;
      case CKR_CRYPTOKI_NOT_INITIALIZED: printf(" CKR_CRYPTOKI_NOT_INITIALIZED"); break;
      case CKR_CRYPTOKI_ALREADY_INITIALIZED: printf(" CKR_CRYPTOKI_ALREADY_INITIALIZED"); break;
      case CKR_MUTEX_BAD: printf(" CKR_MUTEX_BAD"); break;
      case CKR_MUTEX_NOT_LOCKED: printf(" CKR_MUTEX_NOT_LOCKED"); break;
      case CKR_VENDOR_DEFINED: printf(" CKR_VENDOR_DEFINED"); break;
   }
}


//
//
void show_error( CK_BYTE *str, CK_RV rc )
{
   printf("%s returned:  %d", str, rc );
   process_ret_code( rc );
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
   char 	*z="libopencryptoki.so";

   printf("do_GetFunctionList...\n");

   e = getenv("PKCSLIB");
   if ( e == NULL) {
      e = z;
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



int
open_session_and_login(void)
{
CK_FLAGS          flags;
CK_SESSION_HANDLE h_session;
CK_RV             rc;
CK_BYTE           user_pin[8];
CK_ULONG          user_pin_len;

CK_BYTE           true  = TRUE;

   memcpy( user_pin, "12345678", 8 );
   user_pin_len = 8;

   // create a USER R/W session
   //
   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   rc = funcs->C_OpenSession( SLOT_ID, flags, NULL, NULL, &h_session );

   rc = funcs->C_Login( h_session, CKU_USER, user_pin, user_pin_len );


}

// do_create_token_object()
//
int do_create_token_object( void )
{
   CK_FLAGS          flags;
   CK_SESSION_HANDLE h_session;
   CK_RV             rc;
   CK_BYTE           user_pin[8];
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
   };
   CK_ATTRIBUTE  cert_id_attr[] =
   {
       {CKA_ID,               &cert1_id,          sizeof(cert1_id)      }
   };
   CK_OBJECT_HANDLE   obj_list[20];
   CK_ULONG           objcount;



   memcpy( user_pin, "12345678", 8 );
   user_pin_len = 8;

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
   CK_BYTE            line[20];
   CK_ULONG           val, i;
   int rc;
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
         return;
      }
   }

   printf("Using slot #%d...\n\n", SLOT_ID );

   rc = do_GetFunctionList();
   if (!rc)
      return;

   funcs->C_Initialize( NULL );


   open_session_and_login();
   for (i=0;i<THREADCNT;i++){
	   thid[i] = i;
	   printf("Creating thread %d \n",thid[i]);
	   pthread_create(&id[i],NULL,(void*(*)(void *))thread_func,(void *)&(thid[i]));
   }

   for (i=0;i<THREADCNT;i++){
	 printf("Joining thread %d\n",id[i]);
	 pthread_join(id[i],NULL);
   }

   rc = funcs->C_Finalize( NULL );
   if (rc != CKR_OK)
      return;
}
