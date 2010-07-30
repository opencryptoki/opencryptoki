
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
char *process_ret_code( CK_RV rc )
{
   switch (rc) {
      case CKR_OK:				return " CKR_OK";
      case CKR_CANCEL:				return " CKR_CANCEL";
      case CKR_HOST_MEMORY:			return " CKR_HOST_MEMORY";
      case CKR_SLOT_ID_INVALID:			return " CKR_SLOT_ID_INVALID";
      case CKR_GENERAL_ERROR:			return " CKR_GENERAL_ERROR";
      case CKR_FUNCTION_FAILED:			return " CKR_FUNCTION_FAILED";
      case CKR_ARGUMENTS_BAD:			return " CKR_ARGUMENTS_BAD";
      case CKR_NO_EVENT:			return " CKR_NO_EVENT";
      case CKR_NEED_TO_CREATE_THREADS:		return " CKR_NEED_TO_CREATE_THREADS";
      case CKR_CANT_LOCK:			return " CKR_CANT_LOCK";
      case CKR_ATTRIBUTE_READ_ONLY:		return " CKR_ATTRIBUTE_READ_ONLY";
      case CKR_ATTRIBUTE_SENSITIVE:		return " CKR_ATTRIBUTE_SENSITIVE";
      case CKR_ATTRIBUTE_TYPE_INVALID:		return " CKR_ATTRIBUTE_TYPE_INVALID";
      case CKR_ATTRIBUTE_VALUE_INVALID:		return " CKR_ATTRIBUTE_VALUE_INVALID";
      case CKR_DATA_INVALID:			return " CKR_DATA_INVALID";
      case CKR_DATA_LEN_RANGE:			return " CKR_DATA_LEN_RANGE";
      case CKR_DEVICE_ERROR:			return " CKR_DEVICE_ERROR";
      case CKR_DEVICE_MEMORY:			return " CKR_DEVICE_MEMORY";
      case CKR_DEVICE_REMOVED:			return " CKR_DEVICE_REMOVED";
      case CKR_ENCRYPTED_DATA_INVALID:		return " CKR_ENCRYPTED_DATA_INVALID";
      case CKR_ENCRYPTED_DATA_LEN_RANGE:	return " CKR_ENCRYPTED_DATA_LEN_RANGE";
      case CKR_FUNCTION_CANCELED:		return " CKR_FUNCTION_CANCELED";
      case CKR_FUNCTION_NOT_PARALLEL:		return " CKR_FUNCTION_NOT_PARALLEL";
      case CKR_FUNCTION_NOT_SUPPORTED:		return " CKR_FUNCTION_NOT_SUPPORTED";
      case CKR_KEY_HANDLE_INVALID:		return " CKR_KEY_HANDLE_INVALID";
      case CKR_KEY_SIZE_RANGE:			return " CKR_KEY_SIZE_RANGE";
      case CKR_KEY_TYPE_INCONSISTENT:		return " CKR_KEY_TYPE_INCONSISTENT";
      case CKR_KEY_NOT_NEEDED:			return " CKR_KEY_NOT_NEEDED";
      case CKR_KEY_CHANGED:			return " CKR_KEY_CHANGED";
      case CKR_KEY_NEEDED:			return " CKR_KEY_NEEDED";
      case CKR_KEY_INDIGESTIBLE:		return " CKR_KEY_INDIGESTIBLE";
      case CKR_KEY_FUNCTION_NOT_PERMITTED:	return " CKR_KEY_FUNCTION_NOT_PERMITTED";
      case CKR_KEY_NOT_WRAPPABLE:		return " CKR_KEY_NOT_WRAPPABLE";
      case CKR_KEY_UNEXTRACTABLE:		return " CKR_KEY_UNEXTRACTABLE";
      case CKR_MECHANISM_INVALID:		return " CKR_MECHANISM_INVALID";
      case CKR_MECHANISM_PARAM_INVALID:		return " CKR_MECHANISM_PARAM_INVALID";
      case CKR_OBJECT_HANDLE_INVALID:		return " CKR_OBJECT_HANDLE_INVALID";
      case CKR_OPERATION_ACTIVE:		return " CKR_OPERATION_ACTIVE";
      case CKR_OPERATION_NOT_INITIALIZED:	return " CKR_OPERATION_NOT_INITIALIZED";
      case CKR_PIN_INCORRECT:			return " CKR_PIN_INCORRECT";
      case CKR_PIN_INVALID:			return " CKR_PIN_INVALID";
      case CKR_PIN_LEN_RANGE:			return " CKR_PIN_LEN_RANGE";
      case CKR_PIN_EXPIRED:			return " CKR_PIN_EXPIRED";
      case CKR_PIN_LOCKED:			return " CKR_PIN_LOCKED";
      case CKR_SESSION_CLOSED:			return " CKR_SESSION_CLOSED";
      case CKR_SESSION_COUNT:			return " CKR_SESSION_COUNT";
      case CKR_SESSION_HANDLE_INVALID:		return " CKR_SESSION_HANDLE_INVALID";
      case CKR_SESSION_PARALLEL_NOT_SUPPORTED:	return " CKR_SESSION_PARALLEL_NOT_SUPPORTED";
      case CKR_SESSION_READ_ONLY:		return " CKR_SESSION_READ_ONLY";
      case CKR_SESSION_EXISTS:			return " CKR_SESSION_EXISTS";
      case CKR_SESSION_READ_ONLY_EXISTS:	return " CKR_SESSION_READ_ONLY_EXISTS";
      case CKR_SESSION_READ_WRITE_SO_EXISTS:	return " CKR_SESSION_READ_WRITE_SO_EXISTS";
      case CKR_SIGNATURE_INVALID:		return " CKR_SIGNATURE_INVALID";
      case CKR_SIGNATURE_LEN_RANGE:		return " CKR_SIGNATURE_LEN_RANGE";
      case CKR_TEMPLATE_INCOMPLETE:		return " CKR_TEMPLATE_INCOMPLETE";
      case CKR_TEMPLATE_INCONSISTENT:		return " CKR_TEMPLATE_INCONSISTENT";
      case CKR_TOKEN_NOT_PRESENT:		return " CKR_TOKEN_NOT_PRESENT";
      case CKR_TOKEN_NOT_RECOGNIZED:		return " CKR_TOKEN_NOT_RECOGNIZED";
      case CKR_TOKEN_WRITE_PROTECTED:		return " CKR_TOKEN_WRITE_PROTECTED";
      case CKR_UNWRAPPING_KEY_HANDLE_INVALID:	return " CKR_UNWRAPPING_KEY_HANDLE_INVALID";
      case CKR_UNWRAPPING_KEY_SIZE_RANGE:	return " CKR_UNWRAPPING_KEY_SIZE_RANGE";
      case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:return " CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
      case CKR_USER_ALREADY_LOGGED_IN:		return " CKR_USER_ALREADY_LOGGED_IN";
      case CKR_USER_NOT_LOGGED_IN:		return " CKR_USER_NOT_LOGGED_IN";
      case CKR_USER_PIN_NOT_INITIALIZED:	return " CKR_USER_PIN_NOT_INITIALIZED";
      case CKR_USER_TYPE_INVALID:		return " CKR_USER_TYPE_INVALID";
      case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:	return " CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
      case CKR_USER_TOO_MANY_TYPES:		return " CKR_USER_TOO_MANY_TYPES";
      case CKR_WRAPPED_KEY_INVALID:		return " CKR_WRAPPED_KEY_INVALID";
      case CKR_WRAPPED_KEY_LEN_RANGE:		return " CKR_WRAPPED_KEY_LEN_RANGE";
      case CKR_WRAPPING_KEY_HANDLE_INVALID:	return " CKR_WRAPPING_KEY_HANDLE_INVALID";
      case CKR_WRAPPING_KEY_SIZE_RANGE:		return " CKR_WRAPPING_KEY_SIZE_RANGE";
      case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:	return " CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
      case CKR_RANDOM_SEED_NOT_SUPPORTED:	return " CKR_RANDOM_SEED_NOT_SUPPORTED";
      case CKR_RANDOM_NO_RNG:			return " CKR_RANDOM_NO_RNG";
      case CKR_BUFFER_TOO_SMALL:		return " CKR_BUFFER_TOO_SMALL";
      case CKR_SAVED_STATE_INVALID:		return " CKR_SAVED_STATE_INVALID";
      case CKR_INFORMATION_SENSITIVE:		return " CKR_INFORMATION_SENSITIVE";
      case CKR_STATE_UNSAVEABLE:		return " CKR_STATE_UNSAVEABLE";
      case CKR_CRYPTOKI_NOT_INITIALIZED:	return " CKR_CRYPTOKI_NOT_INITIALIZED";
      case CKR_CRYPTOKI_ALREADY_INITIALIZED:	return " CKR_CRYPTOKI_ALREADY_INITIALIZED";
      case CKR_MUTEX_BAD:			return " CKR_MUTEX_BAD";
      case CKR_MUTEX_NOT_LOCKED:		return " CKR_MUTEX_NOT_LOCKED";
      default:					return " UNKNOWN";
   }
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

void usage (char *fct)
{
	printf("usage:  %s [-noskip] [-noinit] [-slot <num>] [-h]\n\n", fct );
	printf("By default, Slot #1 (ie: Slot_Id 0) is used\n\n");
	printf("By default we skip anything that creates or modifies\n");
	printf("token objects to preserve flash lifetime.\n");

	return;
}
	

int do_ParseArgs(int argc, char **argv)
{
	int i;

	skip_token_obj = TRUE;
	no_stop = FALSE;
	no_init = FALSE;
	SLOT_ID = 0;


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
		
		else if (strcmp (argv[i], "-nostop") == 0)
			no_stop = TRUE;
		else {
			printf ("Invalid argument passed as option: %s\n", argv [i]);
			usage (argv [0]);
			return -1;
		}
	}
	return 1;
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
