
/*
 * openCryptoki testcase
 * - Tests the new login flags for v2.11
 *
 * Feb 12, 2002
 * Kent Yoder <yoder1@us.ibm.com>
 *
 */

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "pkcs11types.h"

#define BAD_USER_PIN		"534566346"
#define BAD_USER_PIN_LEN	strlen(BAD_USER_PIN)
#define GOOD_USER_PIN		"12345678"
#define GOOD_USER_PIN_LEN	8

void oc_err_msg(char *, CK_RV);
int do_GetFunctionList(void);
int clean_up(void);

CK_SLOT_ID		slot_id;
CK_FUNCTION_LIST	*funcs;
CK_SESSION_HANDLE	session_handle;
CK_SESSION_INFO		si;
CK_TOKEN_INFO		ti;

void *dl_handle;

int main(int argc, char **argv)
{
	int i;
	CK_RV rc;
	CK_C_INITIALIZE_ARGS initialize_args;

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
	
	printf("Using slot %d...\n\n", slot_id);
	
	if(do_GetFunctionList())
		return -1;
	
	/* There will be no multi-threaded Cryptoki access in this app */
	memset( &initialize_args, 0, sizeof(initialize_args) );
	memset( &si, 0, sizeof(CK_SESSION_INFO) );
	
	if( (rc = funcs->C_Initialize( &initialize_args )) != CKR_OK ) {
		oc_err_msg("C_Initialize", rc);
		return;
	}

	//
	// Tests:
	//
	// 1. Open Session
	// 2. Check that the session looks normal
	// 3. Login/Logout as USER with correct PIN
	// 4. Login as USER with an incorrect PIN
	// 5. Check that USER PIN COUNT LOW set
	// 6. Login as USER with an incorrect PIN
	// 7. Check that USER PIN LAST TRY set
	// 8. Login correctly
	// 9. Check that flags are reset
	// 10. Try to set a new PIN, but with newPIN == oldPIN
	// 11. Check that we get CKR_PIN_INVALID
	// 12. Login as USER with an incorrect PIN
	// 13. Check that USER PIN COUNT LOW set
	// 14. Login as USER with an incorrect PIN
	// 15. Check that USER PIN LAST TRY set
	// 16. Login as USER with incorrect PIN
	// 17. Check that USER PIN LOCKED set
	// 

	/* 1. Open a session with the token */
	if( (rc = funcs->C_OpenSession(slot_id, 
					(CKF_SERIAL_SESSION|CKF_RW_SESSION), 
					NULL_PTR, 
					NULL_PTR, 
					&session_handle)) != CKR_OK ) {
		oc_err_msg("C_OpenSession #1", rc);
		goto done;
	}

	
	if( (rc = funcs->C_GetSessionInfo(session_handle, &si)) != CKR_OK) {
		oc_err_msg("C_GetSessionInfo #1", rc);
		goto session_close;
	}

	/* 2. Test the slot_id change.  This used to be hard coded to 1. 
	 * It should now be the slot number of the token we're using 
	 */
	if(si.slotID != slot_id) {
		printf("Test #2 failed. Slot ID was %d, expected %d\n", si.slotID, slot_id);
		goto session_close;
	}

	if( (rc = funcs->C_GetTokenInfo(slot_id, &ti)) != CKR_OK) {
		oc_err_msg("C_GetTokenInfo #2", rc);
		goto session_close;
	}

	if(ti.flags & CKF_USER_PIN_LOCKED) {
		printf("The USER's PIN is locked for the token in slot %d.\n"
			"Please reset the USER's PIN and re-run this test.\n", slot_id);
		goto session_close;
	}

	if(!(ti.flags & CKF_TOKEN_INITIALIZED)) {
		printf("The token in slot %d is uninitialized.\n", slot_id);
		goto session_close;
	}

	// 3. Login/Logout with correct USER PIN
	rc = funcs->C_Login(session_handle, CKU_USER, GOOD_USER_PIN, GOOD_USER_PIN_LEN);
	if( rc != CKR_OK ) {
		oc_err_msg("C_Login #3", rc);
		goto session_close;
	}
	
	rc = funcs->C_Logout(session_handle);
	if( rc != CKR_OK ) {
		oc_err_msg("C_Logout #3", rc);
		goto session_close;
	}

	
	// 4. Login as USER with an incorrect PIN
	rc = funcs->C_Login(session_handle, CKU_USER, BAD_USER_PIN, BAD_USER_PIN_LEN);
	if( rc != CKR_PIN_INCORRECT ) {
		oc_err_msg("Test #4", rc);
		goto session_close;
	}

	if( (rc = funcs->C_GetTokenInfo(slot_id, &ti)) != CKR_OK) {
		oc_err_msg("C_GetTokenInfo #4", rc);
		goto session_close;
	}

	// 5. Check that USER PIN COUNT LOW set
	if(((ti.flags & CKF_USER_PIN_COUNT_LOW) == 0) || 
		(ti.flags & CKF_USER_PIN_FINAL_TRY)   ||
		(ti.flags & CKF_USER_PIN_LOCKED)) {
		printf("Test #5 failed. Token flags: 0x%x.\n", ti.flags);
		goto session_close;
	}

	// 6. Login as USER with an incorrect PIN
	rc = funcs->C_Login(session_handle, CKU_USER, BAD_USER_PIN, BAD_USER_PIN_LEN);
	if( rc != CKR_PIN_INCORRECT ) {
		oc_err_msg("C_Login #6", rc);
		goto session_close;
	}

	if( (rc = funcs->C_GetTokenInfo(slot_id, &ti)) != CKR_OK) {
		oc_err_msg("C_GetTokenInfo #6", rc);
		goto session_close;
	}

	// 7. Check that USER PIN LAST TRY set
	if((ti.flags & CKF_USER_PIN_COUNT_LOW) || 
		((ti.flags & CKF_USER_PIN_FINAL_TRY) == 0) ||
		(ti.flags & CKF_USER_PIN_LOCKED)) {
		printf("Test #7 failed. Token flags: %d.\n", ti.flags);
		goto session_close;
	}
	
	// 8. Login correctly
	rc = funcs->C_Login(session_handle, CKU_USER, GOOD_USER_PIN, GOOD_USER_PIN_LEN);
	if( rc != CKR_OK ) {
		oc_err_msg("C_Login #8", rc);
		goto session_close;
	}

	if( (rc = funcs->C_GetTokenInfo(slot_id, &ti)) != CKR_OK) {
		oc_err_msg("C_GetTokenInfo #8", rc);
		goto session_close;
	}

	// 9. Check that flags are reset
	if((ti.flags & CKF_USER_PIN_COUNT_LOW) || 
		(ti.flags & CKF_USER_PIN_FINAL_TRY)  ||
		(ti.flags & CKF_USER_PIN_LOCKED) ) {

		printf("Test #9 failed. Token flags: %d.\n", ti.flags);
		goto session_close;
	}

        // 10. Try to set a new PIN, but with newPIN == oldPIN
	// 11. Check that we get CKR_PIN_INVALID
	rc = funcs->C_SetPIN(session_handle, GOOD_USER_PIN, GOOD_USER_PIN_LEN,
       				GOOD_USER_PIN, GOOD_USER_PIN_LEN);
	if(rc != CKR_PIN_INVALID) {
		oc_err_msg("Test #10", rc);
		goto session_close;
	}
	
        // 12. Login as USER with an incorrect PIN
        rc = funcs->C_Login(session_handle, CKU_USER, BAD_USER_PIN, BAD_USER_PIN_LEN);
        if( rc != CKR_PIN_INCORRECT ) {
                oc_err_msg("C_Login #12", rc);
                goto session_close;
        }

        if( (rc = funcs->C_GetTokenInfo(slot_id, &ti)) != CKR_OK) {
                oc_err_msg("C_GetTokenInfo #12", rc);
                goto session_close;
        }

        // 13. Check that USER PIN COUNT LOW set
        if(((ti.flags & CKF_USER_PIN_COUNT_LOW) == 0) ||
                (ti.flags & CKF_USER_PIN_FINAL_TRY)   ||
                (ti.flags & CKF_USER_PIN_LOCKED)) {
                printf("Test #13 failed. Token flags: 0x%x.\n", ti.flags);
                goto session_close;
        }

        // 14. Login as USER with an incorrect PIN
        rc = funcs->C_Login(session_handle, CKU_USER, BAD_USER_PIN, BAD_USER_PIN_LEN);
        if( rc != CKR_PIN_INCORRECT ) {
                oc_err_msg("C_Login #14", rc);
                goto session_close;
        }

        if( (rc = funcs->C_GetTokenInfo(slot_id, &ti)) != CKR_OK) {
                oc_err_msg("C_GetTokenInfo #14", rc);
                goto session_close;
        }

        // 15. Check that USER PIN LAST TRY set
        if((ti.flags & CKF_USER_PIN_COUNT_LOW) ||
                ((ti.flags & CKF_USER_PIN_FINAL_TRY) == 0) ||
                (ti.flags & CKF_USER_PIN_LOCKED)) {
                printf("Test #15 failed. Token flags: %d.\n", ti.flags);
                goto session_close;
        }

	
	
	// 16. Login as USER with incorrect PIN
	rc = funcs->C_Login(session_handle, CKU_USER, BAD_USER_PIN, BAD_USER_PIN_LEN);
	if( rc != CKR_PIN_INCORRECT ) {
		oc_err_msg("C_Login #16", rc);
		goto session_close;
	}

	if( (rc = funcs->C_GetTokenInfo(slot_id, &ti)) != CKR_OK) {
		oc_err_msg("C_GetTokenInfo #16", rc);
		goto session_close;
	}

	// 17. Check that USER PIN LOCKED set
	if((ti.flags & CKF_USER_PIN_COUNT_LOW) || 
		(ti.flags & CKF_USER_PIN_FINAL_TRY)  ||
		((ti.flags & CKF_USER_PIN_LOCKED) == 0)) {

		printf("Test #17 failed. Token flags: %d.\n", ti.flags);
		goto session_close;
	}
	
	printf("Tests succeeded. USER PIN is now locked for slot %d.\n"
		"Re-running this test should return CKR_PIN_LOCKED.\n"
		"To unlock this slot, run the init_tok testcase on the slot.\n", slot_id);
	
session_close:
	
	/* Close the session */
	if( (rc = funcs->C_CloseSession(session_handle)) != CKR_OK )
		oc_err_msg("C_CloseSession", rc);
	
done:
	/* Call C_Finalize and dlclose the library */
	return clean_up();
}

int clean_up(void)
{
	int rc;
	
        if( (rc = funcs->C_Finalize(NULL)) != CKR_OK)
		oc_err_msg("C_Finalize", rc);

	/* Decrement the reference count to PKCS11_API.so */
	dlclose(dl_handle);
	
	return rc;
}

int do_GetFunctionList(void)
{
	char *pkcslib = "/usr/lib/pkcs11/PKCS11_API.so";
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
		oc_err_msg("C_GetFunctionList", rc);
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


void oc_err_msg( char *str, CK_RV rc )
{
	printf("Error: %s returned:  %d ", str, rc );
	process_ret_code( rc );
	printf("\n\n");
}

