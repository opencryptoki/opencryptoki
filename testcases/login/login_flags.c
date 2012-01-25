
/*
 * openCryptoki testcase
 * - Tests the new login flags for v2.11
 *
 * Feb 12, 2002
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

#define BAD_USER_PIN		"534566346"
#define BAD_USER_PIN_LEN	strlen(BAD_USER_PIN)

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
	CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG user_pin_len;

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
	memset( &si, 0, sizeof(CK_SESSION_INFO) );

	if( (rc = funcs->C_Initialize( &initialize_args )) != CKR_OK ) {
		show_error("C_Initialize", rc);
		return -1;
	}

	if (get_user_pin(user_pin))
		return -1;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

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
		show_error("C_OpenSession #1", rc);
		goto done;
	}

	
	if( (rc = funcs->C_GetSessionInfo(session_handle, &si)) != CKR_OK) {
		show_error("C_GetSessionInfo #1", rc);
		goto session_close;
	}

	/* 2. Test the slot_id change.  This used to be hard coded to 1. 
	 * It should now be the slot number of the token we're using 
	 */
	if(si.slotID != slot_id) {
		printf("Test #2 failed. Slot ID was %ld, expected %ld\n", si.slotID, slot_id);
		goto session_close;
	}

	if( (rc = funcs->C_GetTokenInfo(slot_id, &ti)) != CKR_OK) {
		show_error("C_GetTokenInfo #2", rc);
		goto session_close;
	}

	if(ti.flags & CKF_USER_PIN_LOCKED) {
		printf("The USER's PIN is locked for the token in slot %ld.\n"
			"Please reset the USER's PIN and re-run this test.\n", slot_id);
		goto session_close;
	}

	if(!(ti.flags & CKF_TOKEN_INITIALIZED)) {
		printf("The token in slot %ld is uninitialized.\n", slot_id);
		goto session_close;
	}

	// 3. Login/Logout with correct USER PIN
	rc = funcs->C_Login(session_handle, CKU_USER, user_pin, user_pin_len);
	if( rc != CKR_OK ) {
		show_error("C_Login #3", rc);
		goto session_close;
	}
	
	rc = funcs->C_Logout(session_handle);
	if( rc != CKR_OK ) {
		show_error("C_Logout #3", rc);
		goto session_close;
	}

	
	// 4. Login as USER with an incorrect PIN
	rc = funcs->C_Login(session_handle, CKU_USER, (CK_CHAR_PTR)BAD_USER_PIN, BAD_USER_PIN_LEN);
	if( rc != CKR_PIN_INCORRECT ) {
		show_error("Test #4", rc);
		goto session_close;
	}

	if( (rc = funcs->C_GetTokenInfo(slot_id, &ti)) != CKR_OK) {
		show_error("C_GetTokenInfo #4", rc);
		goto session_close;
	}

	// 5. Check that USER PIN COUNT LOW set
	if(((ti.flags & CKF_USER_PIN_COUNT_LOW) == 0) || 
		(ti.flags & CKF_USER_PIN_FINAL_TRY)   ||
		(ti.flags & CKF_USER_PIN_LOCKED)) {
	  printf("Test #5 failed. Token flags: %p.\n", (void *)ti.flags);
		goto session_close;
	}

	// 6. Login as USER with an incorrect PIN
	rc = funcs->C_Login(session_handle, CKU_USER, (CK_CHAR_PTR)BAD_USER_PIN, BAD_USER_PIN_LEN);
	if( rc != CKR_PIN_INCORRECT ) {
		show_error("C_Login #6", rc);
		goto session_close;
	}

	if( (rc = funcs->C_GetTokenInfo(slot_id, &ti)) != CKR_OK) {
		show_error("C_GetTokenInfo #6", rc);
		goto session_close;
	}

	// 7. Check that USER PIN LAST TRY set
	if((ti.flags & CKF_USER_PIN_COUNT_LOW) || 
		((ti.flags & CKF_USER_PIN_FINAL_TRY) == 0) ||
		(ti.flags & CKF_USER_PIN_LOCKED)) {
	        printf("Test #7 failed. Token flags: %p.\n", (void *)ti.flags);
		goto session_close;
	}
	
	// 8. Login correctly
	rc = funcs->C_Login(session_handle, CKU_USER, user_pin, user_pin_len);
	if( rc != CKR_OK ) {
		show_error("C_Login #8", rc);
		goto session_close;
	}

	if( (rc = funcs->C_GetTokenInfo(slot_id, &ti)) != CKR_OK) {
		show_error("C_GetTokenInfo #8", rc);
		goto session_close;
	}

	// 9. Check that flags are reset
	if((ti.flags & CKF_USER_PIN_COUNT_LOW) || 
		(ti.flags & CKF_USER_PIN_FINAL_TRY)  ||
		(ti.flags & CKF_USER_PIN_LOCKED) ) {

                printf("Test #9 failed. Token flags: %p.\n", (void *)ti.flags);
		goto session_close;
	}

        // 10. Try to set a new PIN, but with newPIN == oldPIN
	// 11. Check that we get CKR_PIN_INVALID
	rc = funcs->C_SetPIN(session_handle, user_pin, user_pin_len,
       				user_pin, user_pin_len);
	if(rc != CKR_PIN_INVALID) {
		show_error("Test #10", rc);
		goto session_close;
	}
	
        // 12. Login as USER with an incorrect PIN
        rc = funcs->C_Login(session_handle, CKU_USER, (CK_CHAR_PTR)BAD_USER_PIN, BAD_USER_PIN_LEN);
        if( rc != CKR_PIN_INCORRECT ) {
                show_error("C_Login #12", rc);
                goto session_close;
        }

        if( (rc = funcs->C_GetTokenInfo(slot_id, &ti)) != CKR_OK) {
                show_error("C_GetTokenInfo #12", rc);
                goto session_close;
        }

        // 13. Check that USER PIN COUNT LOW set
        if(((ti.flags & CKF_USER_PIN_COUNT_LOW) == 0) ||
                (ti.flags & CKF_USER_PIN_FINAL_TRY)   ||
                (ti.flags & CKF_USER_PIN_LOCKED)) {
                printf("Test #13 failed. Token flags: %p.\n", (void *)ti.flags);
                goto session_close;
        }

        // 14. Login as USER with an incorrect PIN
        rc = funcs->C_Login(session_handle, CKU_USER, (CK_CHAR_PTR)BAD_USER_PIN, BAD_USER_PIN_LEN);
        if( rc != CKR_PIN_INCORRECT ) {
                show_error("C_Login #14", rc);
                goto session_close;
        }

        if( (rc = funcs->C_GetTokenInfo(slot_id, &ti)) != CKR_OK) {
                show_error("C_GetTokenInfo #14", rc);
                goto session_close;
        }

        // 15. Check that USER PIN LAST TRY set
        if((ti.flags & CKF_USER_PIN_COUNT_LOW) ||
                ((ti.flags & CKF_USER_PIN_FINAL_TRY) == 0) ||
                (ti.flags & CKF_USER_PIN_LOCKED)) {
                printf("Test #15 failed. Token flags: %p.\n", (void *)ti.flags);
                goto session_close;
        }

	
	
	// 16. Login as USER with incorrect PIN
	rc = funcs->C_Login(session_handle, CKU_USER, (CK_CHAR_PTR)BAD_USER_PIN, BAD_USER_PIN_LEN);
	if( rc != CKR_PIN_INCORRECT ) {
		show_error("C_Login #16", rc);
		goto session_close;
	}

	if( (rc = funcs->C_GetTokenInfo(slot_id, &ti)) != CKR_OK) {
		show_error("C_GetTokenInfo #16", rc);
		goto session_close;
	}

	// 17. Check that USER PIN LOCKED set
	if((ti.flags & CKF_USER_PIN_COUNT_LOW) || 
		(ti.flags & CKF_USER_PIN_FINAL_TRY)  ||
		((ti.flags & CKF_USER_PIN_LOCKED) == 0)) {

                printf("Test #17 failed. Token flags: %p.\n", (void *)ti.flags);
		goto session_close;
	}
	
	printf("Tests succeeded. USER PIN is now locked for slot %ld.\n"
		"Re-running this test should return CKR_PIN_LOCKED.\n"
		"To unlock this slot, run the init_tok testcase on the slot.\n", slot_id);
	
session_close:
	
	/* Close the session */
	if( (rc = funcs->C_CloseSession(session_handle)) != CKR_OK )
		show_error("C_CloseSession", rc);
	
done:
	/* Call C_Finalize and dlclose the library */
	return clean_up();
}

int clean_up(void)
{
	CK_RV rc;
	
        if( (rc = funcs->C_Finalize(NULL)) != CKR_OK)
		show_error("C_Finalize", rc);

	/* Decrement the reference count to libopencryptoki.so */
	dlclose(dl_handle);
	
	return rc;
}


