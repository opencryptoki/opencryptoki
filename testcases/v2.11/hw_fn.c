
/*
 * openCryptoki testcase
 *
 * Mar 14, 2003
 * Kent Yoder <yoder1@us.ibm.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "pkcs11types.h"
#include "regress.h"

#define OC_ERR_MSG(x,y)		oc_err_msg(__FILE__,__LINE__,x,y)

#define AES_KEY_SIZE_128	16

void oc_err_msg(char *, int, char *, CK_RV);
int do_GetFunctionList(void);
int clean_up(void);

void *dl_handle;

CK_SLOT_ID		slot_id;
CK_FUNCTION_LIST	*funcs;
CK_SESSION_HANDLE	sess;

/*
 * do_HW_Feature_Seatch Test:
 * 
 * 1. Create 5 objects, 3 of which are HW_FEATURE objects.
 * 2. Search for objects using a template that does not have its
 *    HW_FEATURE attribute set.
 * 3. Result should be that the other 2 objects are returned, and
 *    not the HW_FEATURE objects.
 * 4. Search for objects using a template that does have its
 *    HW_FEATURE attribute set.
 * 5. Result should be that the 3 hardware feature objects are returned.
 *
 */ 

int do_HW_Feature_Search(void)
{
	int			j, k;
	unsigned int            i;
	CK_RV 			rc;
	CK_ULONG		find_count;

	CK_BBOOL		false = FALSE;
        CK_BBOOL                true = TRUE;

	// A counter object
        CK_OBJECT_CLASS         counter1_class = CKO_HW_FEATURE;
        CK_HW_FEATURE_TYPE      feature1_type = CKH_MONOTONIC_COUNTER;
        CK_UTF8CHAR             counter1_label[] = "Monotonic counter";
	CK_CHAR			counter1_value[16];
        CK_ATTRIBUTE            counter1_template[] = {
                {CKA_CLASS,		&counter1_class, sizeof(counter1_class)},
                {CKA_HW_FEATURE_TYPE,	&feature1_type,  sizeof(feature1_type)},
                {CKA_LABEL,		counter1_label,  sizeof(counter1_label)-1},
		{CKA_VALUE,		counter1_value,	sizeof(counter1_value)},
		{CKA_RESET_ON_INIT,	&true,		sizeof(true)},
		{CKA_HAS_RESET,		&false,		sizeof(false)}
        };
	// Another counter object
        CK_OBJECT_CLASS         counter2_class = CKO_HW_FEATURE;
        CK_HW_FEATURE_TYPE      feature2_type = CKH_MONOTONIC_COUNTER;
        CK_UTF8CHAR             counter2_label[] = "Monotonic counter";
	CK_CHAR			counter2_value[16];
        CK_ATTRIBUTE            counter2_template[] = {
                {CKA_CLASS,		&counter2_class, sizeof(counter2_class)},
                {CKA_HW_FEATURE_TYPE,	&feature2_type,  sizeof(feature2_type)},
                {CKA_LABEL,		counter2_label,  sizeof(counter2_label)-1},
		{CKA_VALUE,		counter2_value,	sizeof(counter2_value)},
		{CKA_RESET_ON_INIT,	&true,		sizeof(true)},
		{CKA_HAS_RESET,		&false,		sizeof(false)}
        };
	// A clock object
        CK_OBJECT_CLASS         clock_class = CKO_HW_FEATURE;
        CK_HW_FEATURE_TYPE      clock_type = CKH_CLOCK;
        CK_UTF8CHAR             clock_label[] = "Clock";
	CK_CHAR			clock_value[16];
        CK_ATTRIBUTE            clock_template[] = {
                {CKA_CLASS,		&clock_class, sizeof(clock_class)},
                {CKA_HW_FEATURE_TYPE,	&clock_type,  sizeof(clock_type)},
                {CKA_LABEL,		clock_label,  sizeof(clock_label)-1},
		{CKA_VALUE,		clock_value,	sizeof(clock_value)}
        };
	// A data object
	CK_OBJECT_CLASS		obj1_class = CKO_DATA;
        CK_UTF8CHAR             obj1_label[] = "Object 1";
	CK_BYTE			obj1_data[] = "Object 1's data";
        CK_ATTRIBUTE            obj1_template[] = {
                {CKA_CLASS,		&obj1_class,    sizeof(obj1_class)},
                {CKA_TOKEN,		&true,          sizeof(true)},
                {CKA_LABEL,		obj1_label,     sizeof(obj1_label)-1},
		{CKA_VALUE,		obj1_data,	sizeof(obj1_data)}
        };
	// A secret key object
	CK_OBJECT_CLASS		obj2_class = CKO_SECRET_KEY;
	CK_KEY_TYPE		obj2_type = CKK_AES;
        CK_UTF8CHAR             obj2_label[] = "Object 2";
	CK_BYTE			obj2_data[AES_KEY_SIZE_128];
        CK_ATTRIBUTE            obj2_template[] = {
                {CKA_CLASS,		&obj2_class,    sizeof(obj2_class)},
                {CKA_TOKEN,		&true,          sizeof(true)},
		{CKA_KEY_TYPE,		&obj2_type,	sizeof(obj2_type)},
                {CKA_LABEL,		obj2_label,     sizeof(obj2_label)-1},
		{CKA_VALUE,		obj2_data,	sizeof(obj2_data)}
        };

        CK_OBJECT_HANDLE        h_counter1,
				h_counter2,
				h_clock,
				h_obj1, 
				h_obj2, 
				obj_list[10];
        CK_MECHANISM            mech;
	CK_ATTRIBUTE		find_tmpl[] = {
		{CKA_CLASS,	&counter1_class, sizeof(counter1_class)}
	};


	/* Create the 3 test objects */
	if( (rc = funcs->C_CreateObject(sess, obj1_template, 4, &h_obj1)) != CKR_OK) {
		OC_ERR_MSG("C_CreateObject #1", rc);
		return rc;
	}
	
	if( (rc = funcs->C_CreateObject(sess, obj2_template, 5, &h_obj2)) != CKR_OK) {
		OC_ERR_MSG("C_CreateObject #2", rc);
		goto destroy_1;
	}
	
	if( (rc = funcs->C_CreateObject(sess, counter1_template, 6, &h_counter1)) != CKR_OK) {
		OC_ERR_MSG("C_CreateObject #3", rc);
		goto destroy_2;
	}

	if( (rc = funcs->C_CreateObject(sess, counter2_template, 6, &h_counter2)) != CKR_OK) {
		OC_ERR_MSG("C_CreateObject #4", rc);
		goto destroy_3;
	}

	if( (rc = funcs->C_CreateObject(sess, clock_template, 4, &h_clock)) != CKR_OK) {
		OC_ERR_MSG("C_CreateObject #5", rc);
		goto destroy_4;
	}

	
	// Search for the 2 objects w/o HW_FEATURE set
	//
   
	// A NULL template here should return all objects in v2.01, but
	// in v2.11, it should return all objects *except* HW_FEATURE
	// objects. - KEY
	rc = funcs->C_FindObjectsInit( sess, NULL, 0 );
     	if (rc != CKR_OK) {
	  	OC_ERR_MSG("   C_FindObjectsInit #1", rc );
	  	goto done;
     	}

     	rc = funcs->C_FindObjects( sess, obj_list, 10, &find_count );
     	if (rc != CKR_OK) {
	  	OC_ERR_MSG("   C_FindObjects #1", rc );
	  	goto done;
     	}

	/* So, we created 3 objects before here, and then searched with a NULL
	 * template, so that should return all objects except our hardware
	 * feature object. -KEY */
     	if (find_count != 2) {
	  	printf("%s:%d ERROR:  C_FindObjects #1 should have found 2 objects!\n"
	  	       "           It found %ld objects\n", __FILE__, __LINE__,
		       find_count);
		rc = -1;
	  	goto done;
     	}

     	if (obj_list[0] != h_obj1 && obj_list[0] != h_obj2) {
	  	printf("%s:%d ERROR:  C_FindObjects #1 found the wrong objects!",
				__FILE__, __LINE__);
		rc = -1;
	  	goto done;
     	}

     	if (obj_list[1] != h_obj1 && obj_list[1] != h_obj2) {
	  	printf("%s:%d ERROR:  C_FindObjects #1 found the wrong objects!",
				__FILE__, __LINE__);
		rc = -1;
	  	goto done;
     	}

     	rc = funcs->C_FindObjectsFinal( sess );
     	if (rc != CKR_OK) {
	  	OC_ERR_MSG("   C_FindObjectsFinal #1", rc );
	  	goto done;
     	}


	// Now find the hardware feature objects	
        rc = funcs->C_FindObjectsInit( sess, find_tmpl, 1 );
        if (rc != CKR_OK) {
                OC_ERR_MSG("   C_FindObjectsInit #2", rc );
                goto done;
        }

        rc = funcs->C_FindObjects( sess, obj_list, 10, &find_count );
        if (rc != CKR_OK) {
                OC_ERR_MSG("   C_FindObjects #2", rc );
                goto done;
        }

        if (find_count != 3) {
                printf("%s:%d ERROR:  C_FindObjects #2 should have found 3 objects!\n"
                       "           It found %ld objects\n", __FILE__, __LINE__,
		       find_count);
                funcs->C_FindObjectsFinal( sess );
		rc = -1;
                goto done;
        }

	/* Make sure we got the right ones */
	for( i=0; i < find_count; i++) {
		if(	obj_list[i] != h_counter1 &&
			obj_list[i] != h_counter2 &&
			obj_list[i] != h_clock) 
		{

			printf("%s:%d ERROR:  C_FindObjects #2 found the wrong"
					" objects!", __FILE__, __LINE__);
			rc = -1;
		}
        }

        rc = funcs->C_FindObjectsFinal( sess );
        if (rc != CKR_OK) {
                OC_ERR_MSG("   C_FindObjectsFinal #2", rc );
        }

done:
	/* Destroy the created objects, don't clobber the rc */
	funcs->C_DestroyObject(sess, h_clock);
destroy_4:
	funcs->C_DestroyObject(sess, h_counter2);
destroy_3:
	funcs->C_DestroyObject(sess, h_counter1);
destroy_2:
	funcs->C_DestroyObject(sess, h_obj2);
destroy_1:
	funcs->C_DestroyObject(sess, h_obj1);

	return rc;
}



int main(int argc, char **argv)
{
	int 			i;
	CK_RV 			rc;
	CK_C_INITIALIZE_ARGS	initialize_args;
	
	/* Set default slot to 0 */
	slot_id = 0;
	
	/* Parse the command line */
	for( i = 1; i < argc; i++ ) {
		if(strncmp(argv[i], "-slot", 5) == 0) {
			slot_id = atoi(argv[i + 1]);
			i++;
			break;
		}
	}
	
	printf("Using slot %ld...\n\n", slot_id);
	
	if(do_GetFunctionList())
		return -1;
	
	/* There will be no multi-threaded Cryptoki access in this app */
	memset( &initialize_args, 0, sizeof(initialize_args) );
	
	if( (rc = funcs->C_Initialize( &initialize_args )) != CKR_OK ) {
		OC_ERR_MSG("C_Initialize", rc);
		return -1;
	}

	/* Open a session with the token */
	if( (rc = funcs->C_OpenSession(slot_id, 
					(CKF_SERIAL_SESSION|CKF_RW_SESSION), 
					NULL_PTR, 
					NULL_PTR, 
					&sess)) != CKR_OK ) {
		OC_ERR_MSG("C_OpenSession #1", rc);
		goto done;
	}


	
	// Login correctly
	rc = funcs->C_Login(sess, CKU_USER, (CK_CHAR_PTR)DEFAULT_USER_PIN, DEFAULT_USER_PIN_LEN);
	if( rc != CKR_OK ) {
		OC_ERR_MSG("C_Login #1", rc);
		goto session_close;
	}

	printf("do_HW_Feature_Search...\n");
	rc = do_HW_Feature_Search();
	if(rc)
		goto logout;
	
	printf("Hardware Feature tests succeeded.\n");
	
logout:
        rc = funcs->C_Logout(sess);
        if( rc != CKR_OK )
                OC_ERR_MSG("C_Logout #1", rc);

session_close:
	
	/* Close the session */
	if( (rc = funcs->C_CloseSession(sess)) != CKR_OK )
		OC_ERR_MSG("C_CloseSession", rc);
	
done:
	/* Call C_Finalize and dlclose the library */
	return clean_up();
}

int clean_up(void)
{
	int rc;
	
        if( (rc = funcs->C_Finalize(NULL)) != CKR_OK)
		OC_ERR_MSG("C_Finalize", rc);

	/* Decrement the reference count to libopencryptoki.so */
	dlclose(dl_handle);
	
	return rc;
}

int do_GetFunctionList(void)
{
	char *pkcslib = "libopencryptoki.so";
	CK_RV (*func_ptr)();
	int rc;

	if( (dl_handle = dlopen(pkcslib, RTLD_NOW)) == NULL) {
		printf("dlopen: %s\n", dlerror());
		return -1;
	}
	
	func_ptr = (CK_RV (*)())dlsym(dl_handle, "C_GetFunctionList");

	if(func_ptr == NULL)
		return -1;

	if( (rc = func_ptr(&funcs)) != CKR_OK) {
		OC_ERR_MSG("C_GetFunctionList", rc);
		return -1;
	}

	return 0;
}

void process_ret_code( CK_RV rc )
{
	switch (rc) {
	 case CKR_OK:printf(" CKR_OK");break;
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
	case CKR_MUTEX_BAD:                        printf(" CKR_MUTEX_BAD");break;
	case CKR_MUTEX_NOT_LOCKED:    printf(" CKR_MUTEX_NOT_LOCKED");break;
	}
}


void oc_err_msg( char *file, int line, char *str, CK_RV rc )
{
	printf("%s:%d Error: %s returned:  %ld ", file, line, str, rc );
	process_ret_code( rc );
	printf("\n\n");
}

