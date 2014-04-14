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

#define BAD_USER_PIN		"534566346"
#define BAD_USER_PIN_LEN	strlen(BAD_USER_PIN)

CK_BBOOL            false = FALSE;
CK_BBOOL            true = TRUE;

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
#if 0
CK_RV do_Login( void )
{
	int i;
	CK_RV rc;
	CK_C_INITIALIZE_ARGS 	initialize_args;
	CK_BYTE 		user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG 		user_pin_len;
	CK_SLOT_ID 		slot_id;
	CK_TOKEN_INFO		ti;
	CK_SESSION_INFO		si;
	CK_SESSION_HANDLE	session_handle;

	CK_CHAR            so_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG           so_pin_len;

	slot_id = SLOT_ID;

	printf("do_Login...\n");
#if 0
	if(!do_GetFunctionList())
		return -1;

	/* There will be no multi-threaded Cryptoki access in this app */
	memset( &initialize_args, 0, sizeof(initialize_args) );
	memset( &si, 0, sizeof(CK_SESSION_INFO) );

	if( (rc = funcs->C_Initialize( &initialize_args )) != CKR_OK ) {
		show_error("C_Initialize", rc);
		return -1;
	}
#endif
	if (get_user_pin(user_pin))
		return -1;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);


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
		PRINT_ERR("Test #2 failed. Slot ID was %ld, expected %ld\n", si.slotID, slot_id);
		goto session_close;
	}

	if( (rc = funcs->C_GetTokenInfo(slot_id, &ti)) != CKR_OK) {
		show_error("C_GetTokenInfo #2", rc);
		goto session_close;
	}

	if(ti.flags & CKF_USER_PIN_LOCKED) {
		PRINT_ERR("The USER's PIN is locked for the token in slot %ld.\n"
				"Please reset the USER's PIN and re-run this test.\n", slot_id);
		goto session_close;
	}

	if(!(ti.flags & CKF_TOKEN_INITIALIZED)) {
		PRINT_ERR("The token in slot %ld is uninitialized.\n", slot_id);
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
		PRINT_ERR("Test #5 failed. Token flags: %p.\n", (void *)ti.flags);
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
		PRINT_ERR("Test #7 failed. Token flags: %p.\n", (void *)ti.flags);
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

		PRINT_ERR("Test #9 failed. Token flags: %p.\n", (void *)ti.flags);
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
			(ti.flags & CKF_USER_PIN_FINAL_TRY) ||
			(ti.flags & CKF_USER_PIN_LOCKED)) {
		PRINT_ERR("Test #13 failed. Token flags: %p.\n", (void *)ti.flags);
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
		PRINT_ERR("Test #15 failed. Token flags: %p.\n", (void *)ti.flags);
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

		PRINT_ERR("Test #17 failed. Token flags: %p.\n", (void *)ti.flags);
		goto session_close;
	}

	printf("Tests succeeded. USER PIN is now locked for slot %ld.\n"
			"Re-running this test should return CKR_PIN_LOCKED.\n"
			"To unlock this slot, run the init_tok testcase on the slot.\n", slot_id);

	if (get_so_pin(so_pin))
		return CKR_FUNCTION_FAILED;
	so_pin_len = (CK_ULONG)strlen((char *)so_pin);

	rc = funcs->C_Logout(session_handle);
	if (rc != CKR_OK) {
		show_error("C_Logout", rc);
		return rc;
	}

	rc = funcs->C_Login(session_handle, CKU_SO, so_pin, so_pin_len);
	if (rc != CKR_OK) {
		show_error("   C_Login", rc );
		goto session_close;
	}

	rc = funcs->C_InitPIN(session_handle, user_pin, user_pin_len);
	if (rc != CKR_OK) {
		show_error("C_InitPIN", rc);
		goto session_close;
	}


	rc = funcs->C_Logout(session_handle);
	if (rc != CKR_OK) {
		show_error("C_Logout", rc);
		return rc;
	}
session_close:

	/* Close the session */
	if( (rc = funcs->C_CloseSession(session_handle)) != CKR_OK )
		show_error("C_CloseSession", rc);

done:

	return 0;
}
#endif

CK_RV do_InitToken( void )
{
	CK_BYTE           label[32];
	int               len;
	CK_RV             rc;
	CK_CHAR            so_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG           so_pin_len;

	memcpy( label,   "L13                                   ", 32 );

	//label in this case 
	for (len = 0; len <31;len++){
		if (label[len] == '\0'){
			label[len] = ' ';
			break;
		}
	}
	if (get_so_pin(so_pin))
		return CKR_FUNCTION_FAILED;
	so_pin_len = (CK_ULONG)strlen((char *)so_pin);

	rc = funcs->C_InitToken( SLOT_ID, NULL, strlen((char *)so_pin), label );
	if (rc != CKR_ARGUMENTS_BAD) {
		show_error(" C_InitToken Fail #1",rc);
		goto done;
	}

	rc = funcs->C_InitToken( SLOT_ID, so_pin, strlen((char *)so_pin), NULL );
	if (rc != CKR_ARGUMENTS_BAD) {
		show_error(" C_InitToken Fail #2",rc);
		goto done;
	}

	rc = funcs->C_InitToken( SLOT_ID, so_pin, strlen((char *)so_pin), label );
	if (rc != CKR_OK) {
		show_error(" C_InitToken #1", rc );
		goto done;
	}

done:
	return TRUE;
}
//
//
CK_RV do_DummySpeed( void )
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
			return rc;
		}
	}

	printf("Done...\n");
#endif
	return 0;
}


//
//
CK_RV do_GetInfo( void )
{
	CK_INFO info;
	CK_RV   rc;

	printf("do_GetInfo...\n");

	rc = funcs->C_GetInfo( &info );

	if (rc != CKR_OK) {
		show_error("   C_GetInfo", rc );
		return rc;
	}

	printf("Looks okay...\n");
	return 0;
}


//
//
CK_RV do_GetSlotList( void )
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
		return rc;
	}

	pSlotList = (CK_SLOT_ID *)malloc( ulCount * sizeof(CK_SLOT_ID) );
	if (!pSlotList) {
		PRINT_ERR("   DRIVER ERROR:  CANNOT ALLOCATE MEMORY FOR SLOT LIST\n");
		return -1;
	}

	// now, get the slots
	//
	rc = funcs->C_GetSlotList( tokenPresent, pSlotList, &ulCount );
	if (rc != CKR_OK) {
		show_error("   C_GetSlotList", rc );
		return rc;
	}

	free( pSlotList );

	printf("Looks okay...\n");
	return 0;
}


//
//
CK_RV do_GetSlotInfo( void )
{
	CK_SLOT_ID    slot_id;
	CK_SLOT_INFO  info;
	CK_RV         rc;


	printf("do_GetSlotInfo...\n");

	slot_id = SLOT_ID;

	rc = funcs->C_GetSlotInfo( slot_id, &info );
	if (rc != CKR_OK) {
		show_error("   C_GetSlotInfo", rc );
		return rc;
	}

	printf("   CK_SLOT_INFO for slot #1:  \n");
	printf("      slotDescription:  %64.64s\n",  info.slotDescription );
	printf("      manufacturerID:   %32.32s\n",  info.manufacturerID );
	printf("      flags:            %p\n",       (void *)info.flags );
	printf("      hardwareVersion:  %d.%d\n",    info.hardwareVersion.major, info.hardwareVersion.minor );
	printf("      firmwareVersion:  %d.%d\n",    info.firmwareVersion.major, info.firmwareVersion.minor );

	printf("Looks Okay...\n");

	return 0;
}


//
//
CK_RV do_GetTokenInfo( void )
{
	CK_SLOT_ID     slot_id;
	CK_TOKEN_INFO  info;
	CK_RV          rc;

	printf("do_GetTokenInfo...\n");

	slot_id = SLOT_ID;

	rc = funcs->C_GetTokenInfo( slot_id, &info );
	if (rc != CKR_OK) {
		show_error("   C_GetTokenInfo", rc );
		return rc;
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

	return 0;
}


//
//
CK_RV do_GetMechanismList( void )
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
		return rc;
	}

	printf("   C_GetMechanismList #1 returned %ld mechanisms\n", count );

	mech_list = (CK_MECHANISM_TYPE *)malloc( count * sizeof(CK_MECHANISM_TYPE) );
	if (!mech_list)
		return CKR_HOST_MEMORY;

	rc = funcs->C_GetMechanismList( slot_id, mech_list, &count );
	if (rc != CKR_OK) {
		show_error("   C_GetMechanismList #2", rc );
		return rc;
	}

	free( mech_list );

	printf("Looks okay...\n");

	return 0;
}


//
//
CK_RV do_GetMechanismInfo( void )
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
		return rc;
	}

	mech_list = (CK_MECHANISM_TYPE *)malloc( count * sizeof(CK_MECHANISM_TYPE) );
	if (!mech_list)
		return CKR_HOST_MEMORY;

	rc = funcs->C_GetMechanismList( slot_id, mech_list, &count );
	if (rc != CKR_OK) {
		show_error("   C_GetMechanismList #2", rc );
		return rc;
	}

	for (i=0; i < count; i++) {
		rc = funcs->C_GetMechanismInfo( slot_id, mech_list[i], &info );
		if (rc != CKR_OK) {
			show_error("   C_GetMechanismInfo", rc );
			PRINT_ERR("   Tried to get info on mechanism # %ld\n", mech_list[i] );
			return rc;
		}

		printf("   Mechanism #%ld %s\n", mech_list[i],
		       p11_get_ckm(mech_list[i]) );
		printf("      ulMinKeySize:  %ld\n",  info.ulMinKeySize );
		printf("      ulMaxKeySize:  %ld\n",  info.ulMaxKeySize );
		printf("      flags:         %p\n",   (void *)info.flags );
	}

	free( mech_list );

	printf("Looks okay...\n");

	return 0;
}


//
//
CK_RV do_InitPIN( void )
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
		return rc;
	}

	rc = funcs->C_InitPIN( session, user_pin, user_pin_len );
	if (rc != CKR_USER_NOT_LOGGED_IN) {
		show_error("   C_InitPIN #1", rc );
		PRINT_ERR("   Expected CKR_USER_NOT_LOGGED_IN\n" );
		return rc;
	}

	// try to call C_InitPIN from an SO session
	//
	rc = funcs->C_Login( session, CKU_SO, so_pin, so_pin_len );
	if (rc != CKR_OK) {
		show_error("   C_Login #2", rc );
		return rc;
	}

	rc = funcs->C_InitPIN( session, user_pin, user_pin_len );
	if (rc != CKR_OK) {
		show_error("   C_InitPIN #2", rc );
		return rc;
	}

	rc = funcs->C_Logout( session );
	if (rc != CKR_OK) {
		show_error("   C_Logout #1", rc );
		return rc;
	}


	// try to call C_InitPIN from a normal user session
	//
	rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
	if (rc != CKR_OK) {
		show_error("   C_Login #1", rc );
		return rc;
	}

	rc = funcs->C_InitPIN( session, user_pin, user_pin_len );
	if (rc != CKR_USER_NOT_LOGGED_IN) {
		show_error("   C_InitPIN #2", rc );
		PRINT_ERR("   Expected CKR_USER_NOT_LOGGED_IN\n" );
		return rc;
	}

	rc = funcs->C_Logout( session );
	if (rc != CKR_OK) {
		show_error("   C_Logout #2", rc );
		return rc;
	}

	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc );
		return rc;
	}

	printf("Looks okay...\n");

	return 0;
}


//
//
CK_RV do_SetPIN( void )
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
		return rc;
	}

	rc = funcs->C_SetPIN( session, old_pin, old_len, new_pin, new_len );
	if (rc != CKR_SESSION_READ_ONLY) {
		show_error("   C_SetPIN #1", rc );
		PRINT_ERR("   Expected CKR_SESSION_READ_ONLY\n");
		return rc;
	}

	// try to call C_SetPIN from a normal user session
	//
	rc = funcs->C_Login( session, CKU_USER, old_pin, old_len );
	if (rc != CKR_OK) {
		show_error("   C_Login #1", rc );
		return rc;
	}

	rc = funcs->C_SetPIN( session, old_pin, old_len, new_pin, new_len );
	if (rc != CKR_OK) {
		show_error("   C_SetPIN #2", rc );
		return rc;
	}

	rc = funcs->C_Logout( session );
	if (rc != CKR_OK) {
		show_error("   C_Logout #1", rc );
		return rc;
	}

	// now, try to log in with the old PIN
	//
	rc = funcs->C_Login( session, CKU_USER, old_pin, old_len );
	if (rc != CKR_PIN_INCORRECT) {
		show_error("   C_Login #2", rc );
		PRINT_ERR("   Expected CKR_PIN_INCORRECT\n");
		return rc;
	}

	rc = funcs->C_Login( session, CKU_USER, new_pin, new_len );
	if (rc != CKR_OK) {
		show_error("   C_Login #3", rc );
		return rc;
	}

	// change the PIN back to the original so the rest of this program
	// doesn't break
	//
	rc = funcs->C_SetPIN( session, new_pin, new_len, old_pin, old_len );
	if (rc != CKR_OK) {
		show_error("   C_SetPIN #3", rc );
		return rc;
	}

	rc = funcs->C_Logout( session );
	if (rc != CKR_OK) {
		show_error("   C_Logout #2", rc );
		return rc;
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
		return rc;
	}

	rc = funcs->C_SetPIN( session, old_pin, old_len, new_pin, new_len );
	if (rc != CKR_OK) {
		show_error("   C_SetPIN #4", rc );
		return rc;
	}

	rc = funcs->C_Logout( session );
	if (rc != CKR_OK) {
		show_error("   C_Logout #3", rc );
		return rc;
	}

	// now, try to log in with the old PIN
	//
	rc = funcs->C_Login( session, CKU_SO, old_pin, old_len );
	if (rc != CKR_PIN_INCORRECT) {
		show_error("   C_Login #4", rc );
		PRINT_ERR("   Expected CKR_PIN_INCORRECT\n");
		return rc;
	}

	rc = funcs->C_Login( session, CKU_SO, new_pin, new_len );
	if (rc != CKR_OK) {
		show_error("   C_Login #5", rc );
		return rc;
	}

	// change the PIN back to the original so the rest of this program
	// doesn't break
	//
	rc = funcs->C_SetPIN( session, new_pin, new_len, old_pin, old_len );
	if (rc != CKR_OK) {
		show_error("   C_SetPIN #5", rc );
		return rc;
	}

	rc = funcs->C_Logout( session );
	if (rc != CKR_OK) {
		show_error("   C_Logout #4", rc );
		return rc;
	}

	printf("Success.\n");

	return 0;
}


//
//
CK_RV do_GenerateRandomData( void )
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
		return rc;
	}


	rc = funcs->C_SeedRandom(h1, rand_seed,sizeof(rand_seed));
	if (rc != CKR_OK){
		show_error("   C_SeedRandom #1",rc);
		return rc;
	}

	rc = funcs->C_GenerateRandom( h1, rand_data1, sizeof(rand_data1) );
	if (rc != CKR_OK) {
		show_error("   C_GenerateRandom #1", rc );
		return rc;
	}

	rc = funcs->C_GenerateRandom( h1, rand_data2, sizeof(rand_data2) );
	if (rc != CKR_OK) {
		show_error("   C_GenerateRandom #2", rc );
		return rc;
	}

	rc = funcs->C_CloseSession( h1 );
	if (rc != CKR_OK) {
		show_error("   C_CloseSession #2", rc );
		return rc;
	}

	printf("Looks okay...\n");

	return 0;
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
CK_RV do_GenerateKey( void )
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
	//      return rc;
	//   }
	//   rc = funcs->C_GenerateKey( session, &mech, NULL, 0, &h_key );
	//   if (rc != CKR_USER_NOT_LOGGED_IN) {
	//      show_error("   C_GenerateKey #1", rc );
	//      PRINT_ERR("   Expected CKR_USER_NOT_LOGGED_IN\n" );
	//      return rc;
	//   }
	//
	//   rc = funcs->C_CloseSession( session );
	//   if (rc != CKR_OK) {
	//      show_error("   C_CloseSession #1", rc );
	//      return rc;
	//   }
	//
	//
	//   // 2) generate a DES key from RW PUBLIC session.  this should also fail.
	//   //
	//   flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	//   rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
	//   if (rc != CKR_OK) {
	//      show_error("   C_OpenSession #2", rc );
	//      return rc;
	//   }
	//
	//   rc = funcs->C_GenerateKey( session, &mech, NULL, 0, &h_key );
	//   if (rc != CKR_USER_NOT_LOGGED_IN) {
	//      show_error("   C_GenerateKey #2", rc );
	//      PRINT_ERR("   Expected CKR_USER_NOT_LOGGED_IN\n" );
	//      return rc;
	//   }
	//
	//   rc = funcs->C_CloseSession( session );
	//   if (rc != CKR_OK) {
	//      show_error("   C_CloseSession #2", rc );
	//      return rc;
	//   }


	// 3) generate a DES key from RO USER session
	//
	flags = CKF_SERIAL_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #3", rc );
		return rc;
	}

	rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
	if (rc != CKR_OK) {
		show_error("   C_Login #1", rc );
		return rc;
	}

	rc = funcs->C_GenerateKey( session, &mech, NULL, 0, &h_key );
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #3", rc );
		return rc;
	}

	rc = funcs->C_CloseSession( session );
	if (rc != CKR_OK) {
		show_error("   C_CloseSession #3", rc );
		return rc;
	}


	// 4) generate a DES key from RW USER session
	//
	flags = CKF_SERIAL_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #4", rc );
		return rc;
	}

	rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
	if (rc != CKR_OK) {
		show_error("   C_Login #2", rc );
		return rc;
	}

	rc = funcs->C_GenerateKey( session, &mech, NULL, 0, &h_key );
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #4", rc );
		return rc;
	}

	rc = funcs->C_CloseSession( session );
	if (rc != CKR_OK) {
		show_error("   C_CloseSession #4", rc );
		return rc;
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
			return rc;
		}
		rc = funcs->C_GenerateKey( session, &mech, tmpl, 1, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_GenerateKey #5", rc );
			return rc;
		}

		rc = funcs->C_CloseSession( session );
		if (rc != CKR_OK) {
			show_error("   C_CloseSession #5", rc );
			return rc;
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
			return rc;
		}
		rc = funcs->C_GenerateKey( session, &mech, tmpl, 1, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_GenerateKey #6", rc );
			return rc;
		}

		rc = funcs->C_CloseSession( session );
		if (rc != CKR_OK) {
			show_error("   C_CloseSession #6", rc );
			return rc;
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
			return rc;
		}

		rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
		if (rc != CKR_OK) {
			show_error("   C_Login #3", rc );
			return rc;
		}

		rc = funcs->C_GenerateKey( session, &mech, tmpl, 1, &h_key );
		if (rc != CKR_TEMPLATE_INCONSISTENT) {
			show_error("   C_GenerateKey #7", rc );
			PRINT_ERR("   Expected CKR_TEMPLATE_INCONSISTENT\n");
			return rc;
		}

		rc = funcs->C_CloseSession( session );
		if (rc != CKR_OK) {
			show_error("   C_CloseSession #7", rc );
			return rc;
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
			return rc;
		}

		rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
		if (rc != CKR_OK) {
			show_error("   C_Login #4", rc );
			return rc;
		}

		rc = funcs->C_GenerateKey( session, &mech, tmpl, 1, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_GenerateKey #8", rc );
			return rc;
		}

		rc = funcs->C_CloseSession( session );
		if (rc != CKR_OK) {
			show_error("   C_CloseSession #8", rc );
			return rc;
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
			return rc;
		}

		rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
		if (rc != CKR_OK) {
			show_error("   C_Login #5", rc );
			return rc;
		}

		rc = funcs->C_GenerateKey( session, &mech, tmpl, 1, &h_key );
		if (rc != CKR_TEMPLATE_INCONSISTENT) {
			show_error("   C_GenerateKey #9", rc );
			PRINT_ERR("   Expected CKR_TEMPLATE_INCONSISTENT\n");
			return rc;
		}

		rc = funcs->C_CloseSession( session );
		if (rc != CKR_OK) {
			show_error("   C_CloseSession #9", rc );
			return rc;
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
			return rc;
		}

		rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
		if (rc != CKR_OK) {
			show_error("   C_Login #5", rc );
			return rc;
		}

		rc = funcs->C_GenerateKey( session, &mech, tmpl, 1, &h_key );
		if (rc != CKR_OK) {
			show_error("   C_GenerateKey #9", rc );
			return rc;
		}

		rc = funcs->C_CloseSession( session );
		if (rc != CKR_OK) {
			show_error("   C_CloseSession #9", rc );
			return rc;
		}
	}


	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc );
		return rc;
	}

	printf("Looks okay...\n");
	return 0;
}

CK_RV
test_ExtractableAndSensitive(CK_SESSION_HANDLE  session,
			     CK_MECHANISM      *mech,
			     CK_ATTRIBUTE      *tmpl,
			     CK_ULONG           tmpl_size,
			     char              *str)
{
	CK_OBJECT_HANDLE    h_key;
	CK_RV               rc, lrc;
	CK_BYTE             key[32];
	CK_ATTRIBUTE        value_tmpl[] = {
		{ CKA_VALUE, &key, 32 }
	};

	rc = funcs->C_GenerateKey( session, mech, tmpl, tmpl_size, &h_key );
	if (rc != CKR_OK) {
		testcase_error("C_GenerateKey");
		return rc;
	}

	rc = funcs->C_GetAttributeValue(session, h_key, value_tmpl, 1);
	/* XXX verify that this is the correct return code for an attempt to get the
	 * attribute value on a non-extractable key */
	if (rc != CKR_ATTRIBUTE_SENSITIVE) {
		testcase_fail("%s", str);
		rc = -1;
	} else {
		testcase_pass("%s", str);
	}

	lrc = funcs->C_DestroyObject(session, h_key);
	if (lrc != CKR_OK) {
		show_error("   C_DestroyObject", lrc);
	}

	return rc;
}

/* XXX this only tests secret keys, need to test private keys too */
CK_RV
do_ExtractableSensitiveTest()
{
	CK_SLOT_ID          slot_id;
	CK_SESSION_HANDLE   session;
	CK_MECHANISM        mech;
	CK_FLAGS            flags;
	CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG            user_pin_len, aes_key_len;
	CK_RV               rc, lrc;
	CK_VERSION          version = { 3, 0 };
	CK_ATTRIBUTE        ext_tmpl[] = {
		{ CKA_EXTRACTABLE, &false, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &aes_key_len, sizeof(CK_ULONG) }
	};
	CK_ATTRIBUTE        sens_tmpl[] = {
		{ CKA_SENSITIVE, &true, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &aes_key_len, sizeof(CK_ULONG) }
	};

	testcase_begin();

	slot_id = SLOT_ID;

	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	flags = CKF_SERIAL_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession", rc );
		return rc;
	}

	rc = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
	if (rc != CKR_OK) {
		show_error("   C_Login", rc );
		return rc;
	}

	/* TEST 1: DES key */
	mech.mechanism      = CKM_DES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;

	rc |= test_ExtractableAndSensitive(session, &mech, sens_tmpl, 1, "Sensitive DES key");
	rc |= test_ExtractableAndSensitive(session, &mech, ext_tmpl, 1, "Extractable DES key");

	/* TEST 2: 3DES key */
	mech.mechanism      = CKM_DES3_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;

	rc |= test_ExtractableAndSensitive(session, &mech, sens_tmpl, 1, "Sensitive 3DES key");
	rc |= test_ExtractableAndSensitive(session, &mech, ext_tmpl, 1, "Extractable 3DES key");

	/* TEST 3: SSLv3 key */
	mech.mechanism      = CKM_SSL3_PRE_MASTER_KEY_GEN;
	mech.ulParameterLen = sizeof(CK_VERSION);
	mech.pParameter     = &version;

	rc |= test_ExtractableAndSensitive(session, &mech, sens_tmpl, 1, "Sensitive SSLv3 key");
	rc |= test_ExtractableAndSensitive(session, &mech, ext_tmpl, 1, "Extractable SSLv3 key");

	/* TEST 4: AES 128 key */
	mech.mechanism      = CKM_AES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;

	aes_key_len = 16;
	rc |= test_ExtractableAndSensitive(session, &mech, sens_tmpl, 2, "Sensitive AES 128 key");
	rc |= test_ExtractableAndSensitive(session, &mech, ext_tmpl, 2, "Extractable AES 128 key");

	aes_key_len = 24;
	rc |= test_ExtractableAndSensitive(session, &mech, sens_tmpl, 2, "Sensitive AES 192 key");
	rc |= test_ExtractableAndSensitive(session, &mech, ext_tmpl, 2, "Extractable AES 192 key");

	aes_key_len = 32;
	rc |= test_ExtractableAndSensitive(session, &mech, sens_tmpl, 2, "Sensitive AES 256 key");
	rc |= test_ExtractableAndSensitive(session, &mech, ext_tmpl, 2, "Extractable AES 256 key");

	lrc = funcs->C_CloseSession( session );
	if (lrc != CKR_OK) {
		show_error("   C_CloseSession", lrc );
	}

	return rc;
}

CK_RV misc_functions()
{
	SYSTEMTIME  t1, t2;
	CK_RV         rc;


	GetSystemTime(&t1);
	rc = do_GetInfo();
	if ( rc && !no_stop)
		return rc;
	GetSystemTime(&t2);
	process_time( t1, t2 );

	GetSystemTime(&t1);
	rc = do_GetSlotList();
	if ( rc && !no_stop)
		return rc;
	GetSystemTime(&t2);
	process_time( t1, t2 );

	GetSystemTime(&t1);
	rc = do_GetSlotInfo();
	if ( rc && !no_stop)
		return rc;
	GetSystemTime(&t2);
	process_time( t1, t2 );

	GetSystemTime(&t1);
	rc = do_GetTokenInfo();
	if ( rc && !no_stop)
		return rc;
	GetSystemTime(&t2);
	process_time( t1, t2 );

	//
	// C_WaitForSlotEvent should not be implemented
	//

	GetSystemTime(&t1);
	rc = do_GetMechanismList();
	if ( rc && !no_stop)
		return rc;
	GetSystemTime(&t2);
	process_time( t1, t2 );

	GetSystemTime(&t1);
	rc = do_GetMechanismInfo();
	if ( rc && !no_stop)
		return rc;
	GetSystemTime(&t2);
	process_time( t1, t2 );

	GetSystemTime(&t1);
	rc = do_GenerateRandomData();
	if ( rc && !no_stop)
		return rc;
	GetSystemTime(&t2);
	process_time( t1, t2 );
#if 0
	GetSystemTime(&t1);
	rc = do_Login();
	if ( rc && !no_stop)
		return rc;
	GetSystemTime(&t2);
	process_time( t1, t2 );
#endif
#if 0
	GetSystemTime(&t1);
	rc = do_InitToken();
	if ( rc && !no_stop)
		return rc;
	GetSystemTime(&t2);
	process_time( t1, t2 );
#endif
#if 0
	GetSystemTime(&t1);
	rc = do_GenerateKey();
	if ( rc && !no_stop)
		return rc;
	GetSystemTime(&t2);
	process_time( t1, t2 );
#endif
	rc = do_ExtractableSensitiveTest();
	if  (rc && !no_stop)
		return rc;

	if (skip_token_obj == TRUE) {
		printf("Skipping do_InitPIN()...\n\n");
	}
	else {
		rc = do_InitPIN();
		if ( rc && !no_stop)
			return rc;
	}

	if (skip_token_obj == TRUE) {
		printf("Skipping do_SetPIN()...\n\n");
	}
	else {
		rc = do_SetPIN();
		if ( rc && !no_stop)
			return rc;
	}

	return rc;
}

int main(int argc, char **argv)
{
	CK_C_INITIALIZE_ARGS cinit_args;
	int rc;
	CK_RV rv;

	rc = do_ParseArgs(argc, argv);
	if ( rc != 1)
		return rc;

	printf("Using slot #%lu...\n\n", SLOT_ID );
	printf("With option: no_init: %d\n", no_init);

	rc = do_GetFunctionList();
	if (!rc) {
		PRINT_ERR("ERROR do_GetFunctionList() Failed , rc = 0x%0x\n", rc);
		return rc;
	}

	memset( &cinit_args, 0x0, sizeof(cinit_args) );
	cinit_args.flags = CKF_OS_LOCKING_OK;

	// SAB Add calls to ALL functions before the C_Initialize gets hit

	funcs->C_Initialize( &cinit_args );

	{
		CK_SESSION_HANDLE  hsess = 0;

		rc = funcs->C_GetFunctionStatus(hsess);
		if (rc  != CKR_FUNCTION_NOT_PARALLEL)
			return rc;

		rc = funcs->C_CancelFunction(hsess);
		if (rc  != CKR_FUNCTION_NOT_PARALLEL)
			return rc;

	}

	rv = misc_functions();
	/* make sure we return non-zero if rv is non-zero */
	return ((rv==0) || (rv % 256) ? rv : -1);
}
