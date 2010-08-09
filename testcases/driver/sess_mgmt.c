// File: sess_mgmt.c
//

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"

//
//
void dump_session_info( CK_SESSION_INFO *info )
{
	printf("   CK_SESSION_INFO:\n");
	printf("      slotID:         %ld\n", info->slotID );
	printf("      state:          ");
	switch (info->state) {
		case CKS_RO_PUBLIC_SESSION:   printf("CKS_RO_PUBLIC_SESSION\n");
					      break;
		case CKS_RW_PUBLIC_SESSION:   printf("CKS_RW_PUBLIC_SESSION\n");
					      break;
		case CKS_RO_USER_FUNCTIONS:   printf("CKS_RO_USER_FUNCTIONS\n");
					      break;
		case CKS_RW_USER_FUNCTIONS:   printf("CKS_RW_USER_FUNCTIONS\n");
					      break;
		case CKS_RW_SO_FUNCTIONS:     printf("CKS_RW_SO_FUNCTIONS\n");
					      break;
	}
	printf("      flags:          %p\n",    (void *)info->flags );
	printf("      ulDeviceError:  %ld\n",    info->ulDeviceError );
}



//
//
CK_RV do_OpenSession( void )
{
	CK_SLOT_ID        slot_id;
	CK_FLAGS          flags;
	CK_SESSION_HANDLE handle;
	CK_RV             rc;

	printf("do_OpenSession...\n");

	slot_id = SLOT_ID;
	flags   = CKF_SERIAL_SESSION;   // read-only session

	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &handle );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return rc;
	}

	rc = funcs->C_CloseSession( handle );
	if (rc != CKR_OK) {
		show_error("   C_CloseSession #1", rc );
		return rc;
	}

	printf("Looks okay...\n");

	return rc;
}


//
//
CK_RV do_OpenSession2( void )
{
	CK_SLOT_ID        slot_id;
	CK_FLAGS          flags;
	CK_SESSION_HANDLE h1, h2;
	CK_RV             rc;

	printf("do_OpenSession2...\n");

	slot_id = SLOT_ID;
	flags   = CKF_SERIAL_SESSION;   // read-only session

	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h1 );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return rc;
	}

	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h2 );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #2", rc );
		return rc;
	}

	rc = funcs->C_CloseSession( h1 );
	if (rc != CKR_OK) {
		show_error("   C_CloseSession #1", rc );
		return rc;
	}

	rc = funcs->C_CloseSession( h2 );
	if (rc != CKR_OK) {
		show_error("   C_CloseSession #2", rc );
		return rc;
	}

	printf("Looks okay...\n");

	return rc;
}


//
//
CK_RV do_CloseAllSessions( void )
{
	CK_SLOT_ID        slot_id;
	CK_FLAGS          flags;
	CK_SESSION_HANDLE h1, h2, h3;
	CK_RV             rc;

	printf("do_CloseAllSessions...\n");

	slot_id = SLOT_ID;
	flags   = CKF_SERIAL_SESSION;   // read-only session

	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h1 );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return rc;
	}

	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h2 );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #2", rc );
		return rc;
	}

	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h3 );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #3", rc );
		return rc;
	}

	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions", rc );
		return rc;
	}

	printf("Looks okay...\n");

	return rc;
}


//
//
CK_RV do_GetSessionInfo( void )
{
	CK_SLOT_ID        slot_id;
	CK_FLAGS          flags;
	CK_SESSION_HANDLE h1, h2, h3;
	CK_SESSION_INFO   info;
	CK_RV             rc;

	printf("do_GetSessionInfo...\n");

	slot_id = SLOT_ID;
	flags   = CKF_SERIAL_SESSION;   // read-only session

	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h1 );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return rc;
	}

	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h2 );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #2", rc );
		return rc;
	}

	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h3 );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #3", rc );
		return rc;
	}

	rc = funcs->C_GetSessionInfo( h1, &info );
	if (rc != CKR_OK) {
		show_error("   C_GetSessionInfo #1", rc );
		return rc;
	}

	dump_session_info( &info );

	rc = funcs->C_GetSessionInfo( h2, &info );
	if (rc != CKR_OK) {
		show_error("   C_GetSessionInfo #2", rc );
		return rc;
	}

	dump_session_info( &info );

	rc = funcs->C_GetSessionInfo( h2, &info );
	if (rc != CKR_OK) {
		show_error("   C_GetSessionInfo #3", rc );
		return rc;
	}

	dump_session_info( &info );

	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions", rc );
		return rc;
	}

	printf("Looks okay...\n");

	return rc;
}



// This is a messy function but it does alot of tests:
//
//  1) Create 1 RO session and 2 RW sessions
//  2) Log the USER into session #1.  Verify that all 3 become USER sessions.
//  3) Try to login again, this time to session #2.  Verify that it fails
//  4) Logout session #1
//  5) Try to logout from session #2.  Verify that this fails.
//  6) Try to log the SO into session #1.  Verify that it fails (RO session exists)
//  7) Try to log the SO into session #2.  Verify that it fails (RO session exists)
//  8) Close all sessions
//  9) Creaate 2 RW sessions
//  A) Log the SO into one.  Verify that both are now SO sessions.
//  B) Create a 3rd RW session.  Verify that it immediately becomes an SO session
//  C) Try to create a RO session.  Verify that it fails (SO session exists)
//  D) Close all sessions and return
//
CK_RV do_LoginLogout( void )
{
	CK_SLOT_ID        slot_id;
	CK_FLAGS          flags;
	CK_SESSION_HANDLE h1, h2, h3, h4;
	CK_SESSION_INFO   info;
	CK_RV             rc;
	CK_BYTE           user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG          user_pin_len;
	CK_BYTE           so_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG          so_pin_len;

	printf("do_LoginLogout...\n");

	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	if (get_so_pin(so_pin))
		return CKR_FUNCTION_FAILED;
	so_pin_len = (CK_ULONG)strlen((char *)so_pin);

	slot_id = SLOT_ID;
	flags   = CKF_SERIAL_SESSION;   // read-only session

	//
	// create 3 sessions.  1 RO, two RW
	//
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h1 );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return rc;
	}

	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h2 );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #2", rc );
		return rc;
	}

	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h3 );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #3", rc );
		return rc;
	}

	//
	// log the first session in.  all sessions should become USER sessions
	//
	rc = funcs->C_Login( h1, CKU_USER, user_pin, user_pin_len );
	if (rc != CKR_OK) {
		show_error("   C_Login #1", rc );
		return rc;
	}

	rc = funcs->C_GetSessionInfo( h1, &info );
	if (rc != CKR_OK) {
		show_error("   C_GetSessionInfo #1", rc );
		return rc;
	}

	dump_session_info( &info );

	rc = funcs->C_GetSessionInfo( h2, &info );
	if (rc != CKR_OK) {
		show_error("   C_GetSessionInfo #2", rc );
		return rc;
	}

	dump_session_info( &info );

	rc = funcs->C_GetSessionInfo( h2, &info );
	if (rc != CKR_OK) {
		show_error("   C_GetSessionInfo #3", rc );
		return rc;
	}

	dump_session_info( &info );


	//
	// now, try to log in session #2.  this should fail (already logged in)
	//
	rc = funcs->C_Login( h2, CKU_USER, user_pin, user_pin_len );
	if (rc != CKR_USER_ALREADY_LOGGED_IN) {
		show_error("   C_Login #2", rc );
		PRINT_ERR("   Expected CKR_USER_ALREADY_LOGGED_IN\n");
		return -1;
	}

	//
	// now, try to logout twice
	//
	rc = funcs->C_Logout( h1 );
	if (rc != CKR_OK) {
		show_error("   C_Logout #1", rc );
		return rc;
	}

	rc = funcs->C_Logout( h2 );
	if (rc != CKR_USER_NOT_LOGGED_IN) {
		show_error("   C_Logout #2", rc );
		PRINT_ERR("   Expected CKR_USER_NOT_LOGGED_IN\n");
		return rc;
	}

	//
	// now, try to log the SO in.  this should fail since H1 is a RO session
	//
	rc = funcs->C_Login( h1, CKU_SO, so_pin, so_pin_len );
	if (rc != CKR_SESSION_READ_ONLY_EXISTS) {
		show_error("   C_Login #4", rc );
		PRINT_ERR("   Expected CKR_SESSION_READ_ONLY_EXISTS\n");
		return -1;
	}

	rc = funcs->C_Login( h2, CKU_SO, so_pin, so_pin_len );
	if (rc != CKR_SESSION_READ_ONLY_EXISTS) {
		show_error("   C_Login #5", rc );
		PRINT_ERR("   Expected CKR_SESSION_READ_ONLY_EXISTS\n");
		return -1;
	}

	//
	// log completely out
	//

	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc );
		return rc;
	}

	//
	// now, start two RW sessions
	//
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h1 );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #4", rc );
		return rc;
	}

	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h2 );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #5", rc );
		return rc;
	}

	//
	// now, try to log the SO in.  this should work
	//
	rc = funcs->C_Login( h1, CKU_SO, so_pin, so_pin_len );
	if (rc != CKR_OK) {
		show_error("   C_Login #6", rc );
		return rc;
	}

	rc = funcs->C_GetSessionInfo( h1, &info );
	if (rc != CKR_OK) {
		show_error("   C_GetSessionInfo #4", rc );
		return rc;
	}

	dump_session_info( &info );

	rc = funcs->C_GetSessionInfo( h2, &info );
	if (rc != CKR_OK) {
		show_error("   C_GetSessionInfo #5", rc );
		return rc;
	}

	dump_session_info( &info );

	//
	// now, create a 3rd RW session.  verify that it is automatically an SO session
	//
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h3 );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #6", rc );
		return rc;
	}

	rc = funcs->C_GetSessionInfo( h3, &info );
	if (rc != CKR_OK) {
		show_error("   C_GetSessionInfo #6", rc );
		return rc;
	}

	dump_session_info( &info );

	//
	// now, try to create a 4th session.  RO this time.  Should fail
	//
	flags = CKF_SERIAL_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h4 );
	if (rc != CKR_SESSION_READ_WRITE_SO_EXISTS) {
		show_error("   C_OpenSession #6", rc );
		PRINT_ERR("   Expected CKR_SESSION_READ_WRITE_SO_EXISTS\n");
		return -1;
	}


	//
	// we're done...close all sessions
	//
	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #2:  %d", rc );
		return rc;
	}


	printf("Looks okay...\n");

	return rc;
}


//
//
CK_RV do_OperationState1( void )
{
	CK_SLOT_ID          slot_id;
	CK_SESSION_HANDLE   session1, session2;
	CK_FLAGS            flags;
	CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG            user_pin_len;
	CK_RV               rc;

	CK_BYTE       original[1024];
	CK_BYTE       crypt1  [1024];
	CK_BYTE       crypt2  [1024];
	CK_BYTE       trash1  [8];
	CK_BYTE       trash2  [8];

	CK_BYTE      *op_state = NULL;
	CK_ULONG      op_state_len;

	CK_ULONG      orig_len, crypt1_len, crypt2_len, trash1_len, trash2_len;
	CK_ULONG      i;

	CK_MECHANISM     mech;
	CK_OBJECT_HANDLE h_key;


	printf("do_OperationState1...\n");
	slot_id = SLOT_ID;

	//
	// here's the goal:
	//
	//  All the hash values should be the same
	//    1) session #1 starts a multi-part encryption
	//    2) save session #1 operation state
	//    3) session #1 passes garbage to encrypt update
	//    4) session #2's operation state is set to what we saved
	//    5) sessoin #2 finishes the encryption operation
	//
	//  Session #2's results should be the same as the single-part version
	//

	// create two USER RW sessions
	//
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session1 );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return rc;
	}

	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session2 );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #2", rc );
		return rc;
	}

	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	rc = funcs->C_Login( session1, CKU_USER, user_pin, user_pin_len );
	if (rc != CKR_OK) {
		show_error("   C_Login #1", rc );
		return rc;
	}

	orig_len = sizeof(original);
	for (i=0; i < orig_len; i++)
		original[i] = i % 255;

	trash1_len = sizeof(trash1);
	memcpy( trash1, "asdflkjasdlkjadslkj", trash1_len );


	// first generate a DES key
	//
	mech.mechanism      = CKM_DES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;

	rc = funcs->C_GenerateKey( session1, &mech, NULL, 0, &h_key );
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #1", rc );
		return rc;
	}

	// now encrypt the original data all at once using CBC
	//
	mech.mechanism = CKM_DES_CBC;
	mech.ulParameterLen = 8;
	mech.pParameter     = "asdfqwer";

	rc = funcs->C_EncryptInit( session1, &mech, h_key );
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #1", rc );
		return rc;
	}

	crypt1_len = sizeof(crypt1);
	rc = funcs->C_Encrypt( session1, original, orig_len, crypt1, &crypt1_len );
	if (rc != CKR_OK) {
		show_error("   C_Encrypt #1", rc );
		return rc;
	}


	// now, begin encrypting multipart
	//
	rc = funcs->C_EncryptInit( session1, &mech, h_key );
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #2", rc );
		return rc;
	}

	crypt2_len = sizeof(crypt2);
	rc = funcs->C_EncryptUpdate( session1, original,  orig_len / 2,
			crypt2,   &crypt2_len );
	if (rc != CKR_OK) {
		show_error("   C_EncryptUpdate #1", rc );
		return rc;
	}

	// save session #1's operation state
	//
	rc = funcs->C_GetOperationState( session1, NULL, &op_state_len );
	if (rc != CKR_OK) {
		show_error("   C_GetOperationState #1", rc );
		return rc;
	}

	op_state = (CK_BYTE *)malloc(op_state_len);
	if (!op_state) {
		show_error("   HOST MEMORY ERROR", (CK_ULONG)CKR_HOST_MEMORY );
		return -1;
	}

	rc = funcs->C_GetOperationState( session1, op_state, &op_state_len );
	if (rc != CKR_OK) {
		show_error("   C_GetOperationState #1", rc );
		return rc;
	}

	// now, encrypt some garbage.  this will affect the CBC even if
	// we throw the encrypted garbage away
	//
	trash2_len = sizeof(trash2);
	rc = funcs->C_EncryptUpdate( session1, trash1,  trash1_len,
			trash2, &trash2_len );
	if (rc != CKR_OK) {
		show_error("   C_EncryptUpdate #2", rc );
		return rc;
	}

	// restore session #1's operation state that we just saved back
	// into session #2 and continue with the encryption
	//
	rc = funcs->C_SetOperationState( session2, op_state, op_state_len,
			h_key, 0 );
	if (rc != CKR_OK) {
		show_error("   C_SetOperationState #1", rc );
		return rc;
	}

	free( op_state );

	// now, encrypt the rest of the original data
	//
	i = crypt2_len;
	crypt2_len = sizeof(crypt2) - crypt2_len;
	rc = funcs->C_EncryptUpdate( session2,
			original + orig_len/2,  orig_len/2,
			crypt2 + i,            &crypt2_len );
	if (rc != CKR_OK) {
		show_error("   C_EncryptUpdate #3", rc );
		return rc;
	}

	crypt2_len += i;

	trash2_len = sizeof(trash2);
	rc = funcs->C_EncryptFinal( session2, trash2, &trash2_len );
	if (rc != CKR_OK) {
		show_error("   C_EncryptFinal #1", rc );
		return rc;
	}

	if (crypt2_len != crypt1_len) {
		PRINT_ERR("   ERROR:  Lengths don't match\n");
		return -1;
	}

	if (memcmp(crypt1, crypt2, crypt1_len) != 0) {
		PRINT_ERR("   ERROR:  crypt1 != crypt2\n");
		return -1;
	}

	rc = funcs->C_CloseSession( session1 );
	if (rc != CKR_OK) {
		show_error("   C_CloseSession #1", rc );
		return rc;
	}

	rc = funcs->C_CloseSession( session2 );
	if (rc != CKR_OK) {
		show_error("   C_CloseSession #2", rc );
		return rc;
	}

	printf("Looks okay...\n");
	return rc;
}


//
//
CK_RV do_OperationState2( void )
{
	CK_SLOT_ID          slot_id;
	CK_SESSION_HANDLE   session1, session2, session3;
	CK_FLAGS            flags;
	CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG            user_pin_len;
	CK_RV               rc;

	CK_BYTE     original[1024];
	CK_BYTE     digest1[16];
	CK_BYTE     digest2[16];
	CK_BYTE     digest3[16];

	CK_ULONG    orig_len;
	CK_ULONG    digest1_len, digest2_len, digest3_len;

	CK_BYTE    *op_state1 = NULL;
	CK_BYTE    *op_state2 = NULL;
	CK_ULONG    op_state1_len;
	CK_ULONG    op_state2_len;

	CK_ULONG    i;

	CK_MECHANISM   mech;


	printf("do_OperationState2...\n");
	slot_id = SLOT_ID;

	//
	// here's the goal:
	//  1) session #1 digests the first 499 bytes
	//  2) session #2 digests the first 27 bytes
	//  3) session #3 digests the whole thing
	//  3) we save both operation states
	//  4) we set the operation states to the 'other' session thereby
	//     switching sessions.  Session #2 picks up where session #1 was
	//     saved, session #1 picks up where session #2 was saved.
	//  5) session #1 digests the final (1024 - 27) bytes
	//  6) session #2 digests the final (1024 - 499) bytes
	//
	//  All the hash values should be the same
	//

	// create three USER RW sessions
	//
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session1 );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return rc;
	}

	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session2 );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #2", rc );
		return rc;
	}

	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session3 );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #3", rc );
		return rc;
	}

	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	rc = funcs->C_Login( session1, CKU_USER, user_pin, user_pin_len );
	if (rc != CKR_OK) {
		show_error("   C_Login #1", rc );
		return rc;
	}

	orig_len = sizeof(original);
	for (i=0; i < orig_len; i++)
		original[i] = i % 255;

	mech.mechanism      = CKM_MD5;
	mech.pParameter     = NULL;
	mech.ulParameterLen = 0;

	rc = funcs->C_DigestInit( session1, &mech );
	if (rc != CKR_OK) {
		show_error("   C_DigestInit #1", rc );
		return rc;
	}

	rc = funcs->C_DigestInit( session2, &mech );
	if (rc != CKR_OK) {
		show_error("   C_DigestInit #2", rc );
		return rc;
	}

	rc = funcs->C_DigestInit( session3, &mech );
	if (rc != CKR_OK) {
		show_error("   C_DigestInit #3", rc );
		return rc;
	}

	rc = funcs->C_DigestUpdate( session1, original, 499 );
	if (rc != CKR_OK) {
		show_error("   C_DigestUpdate #1", rc );
		return rc;
	}

	rc = funcs->C_DigestUpdate( session2, original, 27 );
	if (rc != CKR_OK) {
		show_error("   C_DigestUpdate #2", rc );
		return rc;
	}

	orig_len = sizeof(original);
	digest3_len = sizeof(digest3);
	rc = funcs->C_Digest( session3, original,  orig_len,
			digest3,  &digest3_len );
	if (rc != CKR_OK) {
		show_error("   C_Digest #1", rc );
		return rc;
	}

	// save the operation states of sessions 1 and 2
	//
	rc = funcs->C_GetOperationState( session1, NULL, &op_state1_len );
	if (rc != CKR_OK) {
		show_error("   C_GetOperationState #1", rc );
		return rc;
	}
	op_state1 = (CK_BYTE *)malloc(op_state1_len);
	if (!op_state1) {
		show_error("   HOST MEMORY ERROR", (CK_ULONG)CKR_HOST_MEMORY );
		return -1;
	}
	rc = funcs->C_GetOperationState( session1, op_state1, &op_state1_len );
	if (rc != CKR_OK) {
		show_error("   C_GetOperationState #2", rc );
		return rc;
	}

	rc = funcs->C_GetOperationState( session2, NULL, &op_state2_len );
	if (rc != CKR_OK) {
		show_error("   C_GetOperationState #3", rc );
		return rc;
	}
	op_state2 = (CK_BYTE *)malloc(op_state2_len);
	if (!op_state2) {
		show_error("   HOST MEMORY ERROR", (CK_ULONG)CKR_HOST_MEMORY );
		return -1;
	}
	rc = funcs->C_GetOperationState( session2, op_state2, &op_state2_len );
	if (rc != CKR_OK) {
		show_error("   C_GetOperationState #4", rc );
		return rc;
	}

	// switch the states
	//
	rc = funcs->C_SetOperationState( session1, op_state2, op_state2_len,
			0, 0 );
	if (rc != CKR_OK) {
		show_error("   C_SetOperationState #2", rc );
		return rc;
	}

	rc = funcs->C_SetOperationState( session2, op_state1, op_state1_len,
			0, 0 );
	if (rc != CKR_OK) {
		show_error("   C_SetOperationState #3", rc );
		return rc;
	}

	// now, finish the digest operations
	//
	rc = funcs->C_DigestUpdate( session2, original+499, (orig_len - 499) );
	if (rc != CKR_OK) {
		show_error("   C_DigestUpdate #3", rc );
		return rc;
	}

	rc = funcs->C_DigestUpdate( session1, original+27, orig_len - 27 );
	if (rc != CKR_OK) {
		show_error("   C_DigestUpdate #4", rc );
		return rc;
	}

	digest1_len = sizeof(digest1);
	rc = funcs->C_DigestFinal( session1, digest1, &digest1_len );
	if (rc != CKR_OK) {
		show_error("   C_DigestFinal #1", rc );
		return rc;
	}

	digest2_len = sizeof(digest2);
	rc = funcs->C_DigestFinal( session2, digest2, &digest2_len );
	if (rc != CKR_OK) {
		show_error("   C_DigestFinal #2", rc );
		return rc;
	}

	if (digest1_len != digest2_len || digest1_len != digest3_len) {
		PRINT_ERR("   ERROR:  digested lengths don't match\n");
		return -1;
	}

	if (memcmp(digest1, digest2, digest1_len) != 0) {
		PRINT_ERR("   ERROR:  digest1 != digest2\n");
		return -1;
	}

	if (memcmp(digest1, digest3, digest1_len) != 0) {
		PRINT_ERR("   ERROR:  digest1 != digest3\n");
		return -1;
	}

	rc = funcs->C_CloseSession( session1 );
	if (rc != CKR_OK) {
		show_error("   C_CloseSession #3", rc );
		return rc;
	}
	rc = funcs->C_CloseSession( session2 );
	if (rc != CKR_OK) {
		show_error("   C_CloseSession #4", rc );
		return rc;
	}
	rc = funcs->C_CloseSession( session3 );
	if (rc != CKR_OK) {
		show_error("   C_CloseSession #5", rc );
		return rc;
	}

	printf("Looks okay...\n");
	return rc;
}


//
//
CK_RV do_OperationState3( void )
{
	CK_SLOT_ID          slot_id;
	CK_SESSION_HANDLE   session1, session2, session3;
	CK_FLAGS            flags;
	CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG            user_pin_len;
	CK_RV               rc;

	CK_BYTE     original[1024];
	CK_BYTE     digest1[16];
	CK_BYTE     digest2[16];
	CK_BYTE     digest3[16];
	CK_BYTE     junk[1024];

	CK_ULONG    orig_len, junk_len;
	CK_ULONG    digest1_len, digest2_len, digest3_len;

	CK_BYTE    *op_state2 = NULL;
	CK_ULONG    op_state2_len;

	CK_ULONG    i;

	CK_MECHANISM      mech1, mech2;
	CK_OBJECT_HANDLE  key;


	printf("do_OperationState3...\n");
	slot_id = SLOT_ID;

	//
	// here's the goal:
	//  1) session #1 starts a multi-part encrypt
	//  2) session #2 starts a multi-part digest
	//  3) session #3 digests the whole thing
	//  4) assign session #2's operating state to session #1
	//  5) session #1 tries C_EncryptUpdate.  Should fail.
	//  6) session #1 finishes the multi-part digest
	//  7) session #2 finishes the multi-part digest
	//
	//  All the hash values should be the same
	//

	// create three USER RW sessions
	//
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session1 );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return rc;
	}

	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session2 );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #2", rc );
		return rc;
	}

	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session3 );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #3", rc );
		return rc;
	}

	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	rc = funcs->C_Login( session1, CKU_USER, user_pin, user_pin_len );
	if (rc != CKR_OK) {
		show_error("   C_Login #1", rc );
		return rc;
	}

	orig_len = sizeof(original);
	for (i=0; i < orig_len; i++)
		original[i] = i % 255;


	mech1.mechanism      = CKM_DES_KEY_GEN;
	mech1.pParameter     = NULL;
	mech1.ulParameterLen = 0;

	rc = funcs->C_GenerateKey( session1, &mech1, NULL, 0, &key );
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #1", rc );
		return rc;
	}


	mech1.mechanism      = CKM_DES_ECB;
	mech1.pParameter     = NULL;
	mech1.ulParameterLen = 0;

	rc = funcs->C_EncryptInit( session1, &mech1, key );
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #1", rc );
		return rc;
	}

	mech2.mechanism      = CKM_MD5;
	mech2.pParameter     = NULL;
	mech2.ulParameterLen = 0;

	rc = funcs->C_DigestInit( session2, &mech2 );
	if (rc != CKR_OK) {
		show_error("   C_DigestInit #1", rc );
		return rc;
	}

	rc = funcs->C_DigestInit( session3, &mech2 );
	if (rc != CKR_OK) {
		show_error("   C_DigestInit #2", rc );
		return rc;
	}

	rc = funcs->C_DigestUpdate( session2, original, 499 );
	if (rc != CKR_OK) {
		show_error("   C_DigestUpdate #1", rc );
		return rc;
	}

	orig_len = sizeof(original);
	digest3_len = sizeof(digest3);
	rc = funcs->C_Digest( session3, original,  orig_len,
			digest3,  &digest3_len );
	if (rc != CKR_OK) {
		show_error("   C_Digest #1", rc );
		return rc;
	}


	rc = funcs->C_GetOperationState( session2, NULL, &op_state2_len );
	if (rc != CKR_OK) {
		show_error("   C_GetOperationState #1", rc );
		return rc;
	}
	op_state2 = (CK_BYTE *)malloc(op_state2_len);
	if (!op_state2) {
		show_error("   HOST MEMORY ERROR #1", (CK_ULONG)CKR_HOST_MEMORY );
		return -1;
	}
	rc = funcs->C_GetOperationState( session2, op_state2, &op_state2_len );
	if (rc != CKR_OK) {
		show_error("   C_GetOperationState #2", rc );
		return rc;
	}

	rc = funcs->C_SetOperationState( session1, op_state2, op_state2_len, 0, 0 );
	if (rc != CKR_OK) {
		show_error("   C_SetOperationState #1", rc );
		return rc;
	}

	// session #1 should not be set to do digest not encryption
	//
	junk_len = sizeof(junk);
	rc = funcs->C_EncryptUpdate( session1, original, 499, junk, &junk_len );
	if (rc != CKR_OPERATION_NOT_INITIALIZED) {
		show_error("   C_EncryptUpdate #1", rc );
		PRINT_ERR("   Expected CKR_OPERATION_NOT_INITIALIZED\n" );
		return -1;
	}


	// now, finish the digest operations
	//
	rc = funcs->C_DigestUpdate( session1, original+499, (orig_len - 499) );
	if (rc != CKR_OK) {
		show_error("   C_DigestUpdate #2", rc );
		return rc;
	}

	rc = funcs->C_DigestUpdate( session2, original+499, (orig_len - 499) );
	if (rc != CKR_OK) {
		show_error("   C_DigestUpdate #3", rc );
		return rc;
	}


	digest1_len = sizeof(digest1);
	rc = funcs->C_DigestFinal( session1, digest1, &digest1_len );
	if (rc != CKR_OK) {
		show_error("   C_DigestFinal #1", rc );
		return rc;
	}

	digest2_len = sizeof(digest2);
	rc = funcs->C_DigestFinal( session2, digest2, &digest2_len );
	if (rc != CKR_OK) {
		show_error("   C_DigestFinal #2", rc );
		return rc;
	}

	if (digest1_len != digest2_len || digest1_len != digest3_len) {
		PRINT_ERR("   ERROR:  digested lengths don't match\n");
		return -1;
	}

	if (memcmp(digest1, digest2, digest1_len) != 0) {
		PRINT_ERR("   ERROR:  digest1 != digest2\n");
		return -1;
	}

	if (memcmp(digest1, digest3, digest1_len) != 0) {
		PRINT_ERR("   ERROR:  digest1 != digest3\n");
		return -1;
	}

	rc = funcs->C_CloseSession( session1 );
	if (rc != CKR_OK) {
		show_error("   C_CloseSession #3", rc );
		return rc;
	}
	rc = funcs->C_CloseSession( session2 );
	if (rc != CKR_OK) {
		show_error("   C_CloseSession #4", rc );
		return rc;
	}
	rc = funcs->C_CloseSession( session3 );
	if (rc != CKR_OK) {
		show_error("   C_CloseSession #5", rc );
		return rc;
	}

	printf("Looks okay...\n");
	return rc;
}

CK_RV sess_mgmt_functions()
{
	SYSTEMTIME  t1, t2;
	CK_RV         rc;


	GetSystemTime(&t1);
	rc = do_OpenSession();
	if (rc && !no_stop)
		return rc;
	GetSystemTime(&t2);
	process_time( t1, t2 );


	GetSystemTime(&t1);
	rc = do_OpenSession2();
	if (rc && !no_stop)
		return rc;
	GetSystemTime(&t2);
	process_time( t1, t2 );


	GetSystemTime(&t1);
	rc = do_CloseAllSessions();
	if (rc && !no_stop)
		return rc;
	GetSystemTime(&t2);
	process_time( t1, t2 );

	GetSystemTime(&t1);
	rc = do_GetSessionInfo();
	if (rc && !no_stop)
		return rc;
	GetSystemTime(&t2);
	process_time( t1, t2 );


	GetSystemTime(&t1);
	rc = do_LoginLogout();
	if (rc && !no_stop)
		return rc;
	GetSystemTime(&t2);
	process_time( t1, t2 );


	GetSystemTime(&t1);
	rc = do_OperationState1();
	if (rc && !no_stop)
		return rc;
	GetSystemTime(&t2);
	process_time( t1, t2 );


	GetSystemTime(&t1);
	rc = do_OperationState2();
	if (rc && !no_stop)
		return rc;
	GetSystemTime(&t2);
	process_time( t1, t2 );


	GetSystemTime(&t1);
	rc = do_OperationState3();
	if (rc && !no_stop)
		return rc;
	GetSystemTime(&t2);
	process_time( t1, t2 );

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

	rv = sess_mgmt_functions();
	/* make sure we return non-zero if rv is non-zero */
	return ((rv==0) || (rv % 256) ? rv : -1);
}
