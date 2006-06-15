
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "pkcs11types.h"
#include "regress.h"

int
get_so_pin(CK_BYTE *dest)
{
	char *val;

	val = getenv(PKCS11_SO_PIN_ENV_VAR);
	if (val == NULL) {
		fprintf(stderr, "The environment variable %s must be set "
			"before this testcase is run.\n", PKCS11_SO_PIN_ENV_VAR);
		return -1;
	}

	if ((strlen(val) + 1) > PKCS11_MAX_PIN_LEN) {
		fprintf(stderr, "The environment variable %s must hold a "
			"value less than %d chars in length.\n",
			PKCS11_SO_PIN_ENV_VAR, (int)PKCS11_MAX_PIN_LEN);
		return -1;
	}

	memcpy(dest, val, strlen(val) + 1);

	return 0;
}

int
get_user_pin(CK_BYTE *dest)
{
	char *val;

	val = getenv(PKCS11_USER_PIN_ENV_VAR);
	if (val == NULL) {
		fprintf(stderr, "The environment variable %s must be set "
			"before this testcase is run.\n", PKCS11_USER_PIN_ENV_VAR);
		return -1;
	}

	if ((strlen(val) + 1) > PKCS11_MAX_PIN_LEN) {
		fprintf(stderr, "The environment variable %s must hold a "
			"value less than %d chars in length.\n",
			PKCS11_SO_PIN_ENV_VAR, (int)PKCS11_MAX_PIN_LEN);
		return -1;
	}

	memcpy(dest, val, strlen(val) + 1);

	return 0;
}



void process_time(SYSTEMTIME t1, SYSTEMTIME t2)
{
   long ms   = t2.millitm - t1.millitm;
   long s    = t2.time - t1.time;

   while (ms < 0) {
      ms += 1000;
      s--;
   }

   ms += (s*1000);

   printf("Time:  %u msec\n", (unsigned int)ms );
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
   printf("%s returned:  %d (0x%0x)", str, (int)rc, (unsigned int)rc );
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
      for (j=0; (j < 16) && (i < len); j++, i++)
         printf("%02x ", buf[i] );
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

   return TRUE;

}
