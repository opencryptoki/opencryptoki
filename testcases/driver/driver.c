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


void process_time(SYSTEMTIME t1, SYSTEMTIME t2)
{
   long ms   = t2.millitm - t1.millitm;
   long s    = t2.time - t1.time;

   while (ms < 0) {
      ms += 1000;
      s--;
   }

   ms += (s*1000);



   printf("Time:  %ld msec\n", ms );

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
void show_error( char *str, CK_RV rc )
{
   printf("%s returned:  %ld (%p)", str, rc, (void *)rc );
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
   char    *f = "libopencryptoki.so";

   printf("do_GetFunctionList...\n");

   e = getenv("PKCSLIB");
   if ( e == NULL) {
      e = f;
     // return FALSE;
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


void usage (char *fct)
{
	printf("usage:  %s [-noskip] [-noinit] [-slot <num>] [-h]\n\n", fct );
	printf("By default, Slot #1 (ie: Slot_Id 0) is used\n\n");
	printf("By default we skip anything that creates or modifies\n");
	printf("token objects to preserve flash lifetime.\n");

	return;
}

//
//
int main (int argc, char **argv)
{
   CK_C_INITIALIZE_ARGS  cinit_args;
   int        rc, i;
   CK_BBOOL      no_init;
   
   SLOT_ID = 0;
   skip_token_obj = TRUE;
   no_init = FALSE;

   for (i = 1; i < argc; i++) {
      if (strcmp (argv[i], "-h") == 0 || strcmp (argv[i], "--help") == 0) {
	 usage (argv [0]);
	 return 0;
      }
      else if (strcmp (argv[i], "-noskip") == 0)
         skip_token_obj = FALSE;

      else if (strcmp (argv[i], "-slot") == 0) {
         SLOT_ID = atoi (argv[i+1]);
         i++;
      }
      else if (strcmp (argv[i], "-noinit") == 0)
         no_init = TRUE;
      else {
	 printf ("Invalid argument passed as option: %s\n", argv [i]);
	 usage (argv [0]);
	 return -1;
      }
   }

   printf("Using slot #%ld...\n\n", SLOT_ID );
   printf("With option: no_init: %d, noskip: %d\n", no_init, skip_token_obj);
   
   rc = do_GetFunctionList();
   if (!rc)
      return rc;

   memset( &cinit_args, 0x0, sizeof(cinit_args) );
   cinit_args.flags = CKF_OS_LOCKING_OK;

   // SAB Add calls to ALL functions before the C_Initialize gets hit

   funcs->C_Initialize( &cinit_args );

{
   CK_SESSION_HANDLE  hsess;

   rc = funcs->C_GetFunctionStatus(hsess);
   if (rc  != CKR_FUNCTION_NOT_PARALLEL)  
	return rc;

   rc = funcs->C_CancelFunction(hsess);
   if (rc  != CKR_FUNCTION_NOT_PARALLEL)
	return rc;

}


{  int i=0;
   while(i<1){

   fprintf (stderr, "\tMisc Functions tests...\n");
    rc = misc_functions(); 
   if (!rc)
      return rc;

   fprintf (stderr, "\tSession Mgmt Functions tests...\n");
   rc = sess_mgmt_functions();
   if (!rc)
      return rc;

   fprintf (stderr, "\tObject Mgmt Functions tests...\n");
   rc = obj_mgmt_functions();
   if (!rc)
      return rc;

   rc = des_functions();
   if (!rc)
      return rc;

   rc = des3_functions();
   if (!rc)
      return rc;

   rc = aes_functions();
   if (!rc) {
          printf("Error executing AES functions\n");
   }

   rc = digest_functions();
   if (!rc)
      return rc;

   rc = rsa_functions();
   if (!rc)
      return rc;

/* Begin code contributed by Corrent corp. */
   rc = dh_functions();
   if (!rc)
      return rc;
/* End code contributed by Corrent corp. */
   
   rc = ssl3_functions();
   if (!rc)
      return rc;
   printf("------------------ Completed pass %d --------------------\n",i);
   i++;

   }
}

   funcs->C_Finalize( NULL );

   return 0;
}
