// File: obj_mgmt.c
//

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"


#define AES_KEY_SIZE_128	16

extern int no_stop;

// 1) create a data object
// 2) create a certificate
// 3) create a key object
//
int do_CreateSessionObject( void )
{
	CK_SLOT_ID        slot_id;
	CK_FLAGS          flags;
	CK_SESSION_HANDLE h_session;
	CK_RV             rc;
	CK_BYTE           user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG          user_pin_len;

	CK_BYTE           true  = TRUE;
	CK_BYTE           false = FALSE;

	CK_OBJECT_HANDLE  h_data;
	CK_OBJECT_CLASS   data_class         = CKO_DATA;
	CK_BYTE           data_application[] = "Test Application";
	CK_BYTE           data_value[]       = "1234567890abcedfghijklmnopqrstuvwxyz";
	CK_ATTRIBUTE      data_attribs[] =
	{
		{CKA_CLASS,       &data_class,       sizeof(data_class)       },
		{CKA_TOKEN,       &false,            sizeof(false)            },
		{CKA_APPLICATION, &data_application, sizeof(data_application) },
		{CKA_VALUE,       &data_value,       sizeof(data_value)       }
	};

	CK_OBJECT_HANDLE    h_cert;
	CK_OBJECT_CLASS     cert_class         = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE cert_type          = CKC_X_509;
	CK_BYTE             cert_subject[]     = "Certificate subject";
	CK_BYTE             cert_id[]          = "Certificate ID";
	CK_BYTE             cert_value[]       = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";
	CK_ATTRIBUTE        cert_attribs[] =
	{
		{CKA_CLASS,            &cert_class,       sizeof(cert_class)   },
		{CKA_TOKEN,            &false,            sizeof(false)        },
		{CKA_CERTIFICATE_TYPE, &cert_type,        sizeof(cert_type)    },
		{CKA_SUBJECT,          &cert_subject,     sizeof(cert_subject) },
		{CKA_ID,               &cert_id,          sizeof(cert_id)      },
		{CKA_VALUE,            &cert_value,       sizeof(cert_value)   }
	};

	CK_OBJECT_HANDLE  h_key;
	CK_OBJECT_CLASS   key_class          = CKO_PUBLIC_KEY;
	CK_KEY_TYPE       key_type           = CKK_RSA;
	CK_BYTE           key_modulus[]      = "1234567890987654321";
	CK_BYTE           key_exponent[]     = "123";
	CK_ATTRIBUTE      key_attribs[] =
	{
		{CKA_CLASS,           &key_class,    sizeof(key_class)    },
		{CKA_KEY_TYPE,        &key_type,     sizeof(key_type)     },
		{CKA_WRAP,            &true,         sizeof(true)         },
		{CKA_MODULUS,         &key_modulus,  sizeof(key_modulus)  },
		{CKA_PUBLIC_EXPONENT, &key_exponent, sizeof(key_exponent) }
	};


	printf("do_CreateSessionObject...\n");

	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	slot_id = SLOT_ID;


	// create a USER R/W session
	//
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h_session );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return FALSE;
	}

	rc = funcs->C_Login( h_session, CKU_USER, user_pin, user_pin_len );
	if (rc != CKR_OK) {
		show_error("   C_Login #1", rc );
		return FALSE;
	}


	//
	// now, create the objects
	//

	rc = funcs->C_CreateObject( h_session, data_attribs, 4, &h_data );
	if (rc != CKR_OK) {
		show_error("   C_CreateObject #1", rc );
		return FALSE;
	}

	rc = funcs->C_CreateObject( h_session, cert_attribs, 6, &h_cert );
	if (rc != CKR_OK) {
		show_error("   C_CreateObject #2", rc );
		return FALSE;
	}

	rc = funcs->C_CreateObject( h_session, key_attribs, 5, &h_key );
	if (rc != CKR_OK) {
		show_error("   C_CreateObject #3", rc );
		return FALSE;
	}

	// done...close the session and verify the object is deleted
	//
	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #2:  %d", rc );
		return FALSE;
	}


	printf("Looks okay...\n");


	return TRUE;
}

// do_CopyObject()
//
// API routines exercised:
//    C_CreateObject
//    C_CopyObject
//    C_DestroyObject
//    C_GetAttributeValue
//    C_GetObjectSize
//
// 1) create a data object with no CKA_APPLICATION attribute
// 2) create a copy of the object specifying the CKA_APPLICATION attribute
// 3) extract the CK_VALUE attribute from the copy.  ensure this matches the original
// 4) extract the CKA_APPLICATION attribute from the original.  ensure it is empty.
// 5) extract the CKA_APPLICATION attribute from the copy.  ensure is correct.
// 6) attempt to extract CK_PRIME from the original.  ensure this fails correctly.
// 7) attempt to extract CK_PRIME from a non-existant object.  ensure this fails correctly.
// 8) get the size of the original object and copied objects
// 9) destroy the original object.  ensure this succeeds.
// A) destroy a non-existant object.  ensure this fails correctly.
// B) get the size of the original object.  ensure this fails correctly.
// C) attempt to reference the original object.  ensure this fails correctly.
// D) attempt to reference the copied object after the session has been closed.  ensure
//    that this fails with an CKR_INVALID_SESSION_HANDLE.
//
int do_CopyObject( void )
{
	CK_SLOT_ID        slot_id;
	CK_FLAGS          flags;
	CK_SESSION_HANDLE h_session;
	CK_RV             rc;
	CK_BYTE           user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG          user_pin_len;
	CK_ULONG          obj_size;

	CK_BYTE           false = FALSE;

	CK_OBJECT_HANDLE  h_data;
	CK_OBJECT_CLASS   data_class         = CKO_DATA;
	CK_BYTE           data_application[] = "Test Application";
	CK_BYTE           data_value[]       = "1234567890abcedfghijklmnopqrstuvwxyz";
	CK_ATTRIBUTE      data_attribs[] =
	{
		{CKA_CLASS,       &data_class,       sizeof(data_class)       },
		{CKA_TOKEN,       &false,            sizeof(false)            },
		{CKA_VALUE,       &data_value,       sizeof(data_value)       }
	};

	CK_OBJECT_HANDLE  h_copy;
	CK_ATTRIBUTE      copy_attribs[] =
	{
		{CKA_APPLICATION, &data_application, sizeof(data_application) }
	};

	CK_BYTE           buf1[100];
	CK_ATTRIBUTE      verify_attribs[] =
	{
		{CKA_APPLICATION, &buf1, sizeof(buf1) }
	};

	CK_BYTE           buf2[100];
	CK_ATTRIBUTE      prime_attribs[] =
	{
		{CKA_PRIME, &buf2, sizeof(buf2) }
	};



	printf("do_CopyObject...\n");

	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	slot_id = SLOT_ID;


	// create a USER R/W session
	//
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h_session );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return FALSE;
	}

	rc = funcs->C_Login( h_session, CKU_USER, user_pin, user_pin_len );
	if (rc != CKR_OK) {
		show_error("   C_Login #1", rc );
		return FALSE;
	}


	// create the object
	//
	rc = funcs->C_CreateObject( h_session, data_attribs, 3, &h_data );
	if (rc != CKR_OK) {
		show_error("   C_CreateObject #1", rc );
		return FALSE;
	}

	// create the copy
	//
	rc = funcs->C_CopyObject( h_session, h_data, copy_attribs, 1, &h_copy );
	if (rc != CKR_OK) {
		show_error("   C_CopyObject #1", rc );
		return FALSE;
	}

	// now, try to extract the CKA_APPLICATION attribute from the original
	// this will pull in the token's default value for CKA_APPLICATION which
	//
	verify_attribs[0].ulValueLen = sizeof(buf1);
	rc = funcs->C_GetAttributeValue( h_session, h_data, verify_attribs, 1 );
	if (rc != CKR_OK) {
		show_error("   C_GetAttributeValue #1", rc );
		return FALSE;
	}

	// now, try to extract the CKA_APPLICATION attribute from the copy
	//
	verify_attribs[0].ulValueLen = sizeof(buf1);
	rc = funcs->C_GetAttributeValue( h_session, h_copy, verify_attribs, 1 );
	if (rc != CKR_OK) {
		show_error("   C_GetAttributeValue #2", rc );
		return FALSE;
	}

	if (memcmp( &data_application, verify_attribs[0].pValue, sizeof(data_application) ) != 0) {
		printf("   ERROR:  extracted attribute doesn't match\n");
		return FALSE;
	}

	// now, try to extract CKA_PRIME from the original.  this should not exist
	//
	prime_attribs[0].ulValueLen = sizeof(buf2);
	rc = funcs->C_GetAttributeValue( h_session, h_data, prime_attribs, 1 );
	if (rc != CKR_ATTRIBUTE_TYPE_INVALID) {
		show_error("   C_GetAttributeValue #3", rc );
		printf("   Expected CKR_ATTRIBUTE_TYPE_INVALID\n");
		return FALSE;
	}


	// now, try to extract CKA_PRIME from a bogus object handle.  this should not exist
	//
	rc = funcs->C_GetAttributeValue( h_session, 98765, prime_attribs, 1 );
	if (rc != CKR_OBJECT_HANDLE_INVALID) {
		show_error("   C_GetAttributeValue #4", rc );
		printf("   Expected CKR_OBJECT_HANDLE_INVALID\n");
		return FALSE;
	}

	// now, get the size of the original object
	//
	rc = funcs->C_GetObjectSize( h_session, h_data, &obj_size );
	if (rc != CKR_OK) {
		show_error("   C_GetObjectSize #1", rc );
		return FALSE;
	}

	// now, destroy the original object
	//
	rc = funcs->C_DestroyObject( h_session, h_data );
	if (rc != CKR_OK) {
		show_error("   C_DestroyObject #1", rc );
		return FALSE;
	}

	// now, destroy a non-existant object
	//
	rc = funcs->C_DestroyObject( h_session, h_data );
	if (rc != CKR_OBJECT_HANDLE_INVALID) {
		show_error("   C_DestroyObject #2", rc );
		printf("   Expected CKR_OBJECT_HANDLE_INVALID\n");
		return FALSE;
	}


	// now, get the size of a non-existent object
	//
	rc = funcs->C_GetObjectSize( h_session, h_data, &obj_size );
	if (rc != CKR_OBJECT_HANDLE_INVALID) {
		show_error("   C_GetObjectSize #2", rc );
		printf("   Expected CKR_OBJECT_HANDLE_INVALID\n");
		return FALSE;
	}


	// now, try to extract CKA_PRIME from the original.  the object should not exist
	//
	prime_attribs[0].ulValueLen = sizeof(buf2);
	rc = funcs->C_GetAttributeValue( h_session, h_data, prime_attribs, 1 );
	if (rc != CKR_OBJECT_HANDLE_INVALID) {
		show_error("   C_GetAttributeValue #5", rc );
		printf("   Expected CKR_OBJECT_HANDLE_INVALID\n");
		return FALSE;
	}


	// done...close the session and verify the object is deleted
	//
	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1:  %d", rc );
		return FALSE;
	}

	// try to extract CKA_APPLICATION from the copy.  this should fail since all sessions
	// are now closed.
	//
	verify_attribs[0].ulValueLen = sizeof(buf1);
	rc = funcs->C_GetAttributeValue( h_session, h_copy, verify_attribs, 1 );
	if (rc != CKR_SESSION_HANDLE_INVALID) {
		show_error("   C_GetAttributeValue #6", rc );
		printf("   Expected CKR_SESSION_HANDLE_INVALID\n");
		return FALSE;
	}


	printf("Looks okay...\n");
	return TRUE;
}


// do_SetAttributeValues()
//
// API routines exercised:
//    C_CreateObject
//    C_GetAttributeValue
//    C_SetAttributeValue
//
// 1) create a certificate object with no CKA_SERIAL_NUMBER or CKA_ISSUER
// 2) add CKA_SERIAL_NUMBER and CKA_ISSUER and modify CKA_ID.  verify this works.
// 3) try to modify CKA_VALUE and CKA_ID in a single call to C_SetAttributeValue.  verify
//    that this fails correctly and that the object is not modified.
//
int do_SetAttributeValues( void )
{
	CK_SLOT_ID        slot_id;
	CK_FLAGS          flags;
	CK_SESSION_HANDLE h_session;
	CK_RV             rc;
	CK_BYTE           user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG          user_pin_len;

	CK_BYTE           false = FALSE;

	CK_OBJECT_HANDLE    h_cert;
	CK_OBJECT_CLASS     cert_class         = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE cert_type          = CKC_X_509;
	CK_BYTE             cert_subject[]     = "Certificate subject";
	CK_BYTE             cert_id[]          = "Certificate ID";
	CK_BYTE             cert_value[]       = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";

	CK_ATTRIBUTE        cert_attribs[] =
	{
		{CKA_CLASS,            &cert_class,       sizeof(cert_class)   },
		{CKA_TOKEN,            &false,            sizeof(false)        },
		{CKA_CERTIFICATE_TYPE, &cert_type,        sizeof(cert_type)    },
		{CKA_SUBJECT,          &cert_subject,     sizeof(cert_subject) },
		{CKA_ID,               &cert_id,          sizeof(cert_id)      },
		{CKA_VALUE,            &cert_value,       sizeof(cert_value)   }
	};

	CK_BYTE       cert_id2[]    = "New ID";
	CK_BYTE       cert_issuer[] = "Certificate Issuer";
	CK_BYTE       cert_ser_no[] = "Serial Number: 12345";
	CK_ATTRIBUTE  update_attr[] =
	{
		{CKA_SERIAL_NUMBER, &cert_ser_no,  sizeof(cert_ser_no) },
		{CKA_ISSUER,        &cert_issuer,  sizeof(cert_issuer) },
		{CKA_ID,            &cert_id2,     sizeof(cert_id2)    }
	};

	CK_BYTE       cert_value2[] = "Invalid Value";
	CK_BYTE       cert_id3[]    = "ID #3";
	CK_ATTRIBUTE  invalid_attr[] =
	{
		{CKA_VALUE, &cert_value2,  sizeof(cert_value2) },
		{CKA_ID,    &cert_id3,     sizeof(cert_id3)    }
	};


	printf("do_SetAttributeValues...\n");

	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	slot_id = SLOT_ID;


	// create a USER R/W session
	//
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h_session );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return FALSE;
	}

	rc = funcs->C_Login( h_session, CKU_USER, user_pin, user_pin_len );
	if (rc != CKR_OK) {
		show_error("   C_Login #1", rc );
		return FALSE;
	}


	// create the object
	//
	rc = funcs->C_CreateObject( h_session, cert_attribs, 6, &h_cert );
	if (rc != CKR_OK) {
		show_error("   C_CreateObject #1", rc );
		return FALSE;
	}

	// Add CKA_SERIAL_NUMBER and CKA_ISSUER and change the existing CKA_ID
	//
	rc = funcs->C_SetAttributeValue( h_session, h_cert, update_attr, 3 );
	if (rc != CKR_OK) {
		show_error("   C_SetAttributeValue #1", rc );
		return FALSE;
	}
	else {
		CK_BYTE       buf1[100];
		CK_BYTE       buf2[100];
		CK_BYTE       buf3[100];
		CK_ATTRIBUTE  check1[] =
		{
			{CKA_ISSUER,        &buf1, sizeof(buf1)},
			{CKA_SERIAL_NUMBER, &buf2, sizeof(buf2)},
			{CKA_ID,            &buf3, sizeof(buf3)}
		};

		rc = funcs->C_GetAttributeValue( h_session, h_cert, (CK_ATTRIBUTE *)&check1, 3 );
		if (rc != CKR_OK) {
			show_error("   C_GetAttributeValue #1", rc );
			return FALSE;
		}

		if (memcmp(check1[0].pValue, cert_issuer, check1[0].ulValueLen) != 0) {
			printf("   ERROR : CKA_ISSUER doesn't match\n");
			return FALSE;
		}

		if (memcmp(check1[1].pValue, cert_ser_no, check1[1].ulValueLen) != 0) {
			printf("   ERROR : CKA_SERIAL_NUMBER doesn't match\n");
			return FALSE;
		}

		if (memcmp(check1[2].pValue, cert_id2, check1[2].ulValueLen) != 0) {
			printf("   ERROR : CKA_ID doesn't match\n");
			return FALSE;
		}
	}

	// the next template tries to update a CK_ID (valid) and CKA_VALUE (read-only)
	// the entire operation should fail -- no attributes should get modified
	//
	rc = funcs->C_SetAttributeValue( h_session, h_cert, invalid_attr, 2 );
	if (rc != CKR_ATTRIBUTE_READ_ONLY) {
		show_error("   C_SetAttributeValue #2", rc );
		printf("   Expected CKR_ATTRIBUTE_READ_ONLY\n");
		return FALSE;
	}
	else {
		CK_BYTE       buf1[100];
		CK_ATTRIBUTE  check1[] =
		{
			{CKA_ID, &buf1, sizeof(buf1)}
		};

		rc = funcs->C_GetAttributeValue( h_session, h_cert, check1, 1 );
		if (rc != CKR_OK) {
			show_error("   C_GetAttributeValue #2", rc );
			return FALSE;
		}

		if (memcmp(check1[0].pValue, cert_id2, check1[0].ulValueLen) != 0) {
			printf("   ERROR : CKA_ID doesn't match cert_id2\n");
			return FALSE;
		}
	}

	// done...close the session and verify the object is deleted
	//
	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1:  %d", rc );
		return FALSE;
	}


	printf("Looks okay...\n");
	return TRUE;
}



// do_FindObjects()
//
// 1) Create 3 certificates with different CKA_ID attributes
// 2) Search for a particular CKA_ID.  Verify this works.
// 3) Search for a non-existant CKA_ID.  Verify this returns nothing.
// 4) Specify an empty template.  Verify that all 3 objects are returned.
//
//
int do_FindObjects( void )
{
	CK_SLOT_ID        slot_id;
	CK_FLAGS          flags;
	CK_SESSION_HANDLE h_session;
	CK_RV             rc;
	CK_BYTE           user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG          user_pin_len;

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
		{CKA_TOKEN,            &false,             sizeof(false)         },
		{CKA_CERTIFICATE_TYPE, &cert1_type,        sizeof(cert1_type)    },
		{CKA_SUBJECT,          &cert1_subject,     sizeof(cert1_subject) },
		{CKA_ID,               &cert1_id,          sizeof(cert1_id)      },
		{CKA_VALUE,            &cert1_value,       sizeof(cert1_value)   }
	};

	CK_OBJECT_HANDLE    h_cert2;
	CK_OBJECT_CLASS     cert2_class        = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE cert2_type         = CKC_X_509;
	CK_BYTE             cert2_subject[]    = "Certificate subject #2";
	CK_BYTE             cert2_id[]         = "Certificate ID #2";
	CK_BYTE             cert2_value[]      = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";

	CK_ATTRIBUTE        cert2_attribs[] =
	{
		{CKA_CLASS,            &cert2_class,       sizeof(cert2_class)   },
		{CKA_TOKEN,            &false,             sizeof(false)         },
		{CKA_CERTIFICATE_TYPE, &cert2_type,        sizeof(cert2_type)    },
		{CKA_SUBJECT,          &cert2_subject,     sizeof(cert2_subject) },
		{CKA_ID,               &cert2_id,          sizeof(cert2_id)      },
		{CKA_VALUE,            &cert2_value,       sizeof(cert2_value)   }
	};

	CK_OBJECT_HANDLE    h_cert3;
	CK_OBJECT_CLASS     cert3_class        = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE cert3_type         = CKC_X_509;
	CK_BYTE             cert3_subject[]    = "Certificate subject #3";
	CK_BYTE             cert3_id[]         = "Certificate ID #3";
	CK_BYTE             cert3_value[]      = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";

	CK_ATTRIBUTE        cert3_attribs[] =
	{
		{CKA_CLASS,            &cert3_class,       sizeof(cert3_class)   },
		{CKA_TOKEN,            &false,             sizeof(false)         },
		{CKA_CERTIFICATE_TYPE, &cert3_type,        sizeof(cert3_type)    },
		{CKA_SUBJECT,          &cert3_subject,     sizeof(cert3_subject) },
		{CKA_ID,               &cert3_id,          sizeof(cert3_id)      },
		{CKA_VALUE,            &cert3_value,       sizeof(cert3_value)   }
	};

	CK_BYTE  find1_id[] = "Certificate ID #2";
	CK_ATTRIBUTE   find1_attribs[] =
	{
		{CKA_ID, &find1_id,  sizeof(find1_id)}
	};

	CK_BYTE  find2_id[] = "Certificate ID #12345";
	CK_ATTRIBUTE   find2_attribs[] =
	{
		{CKA_ID, &find2_id,  sizeof(find2_id)}
	};

	CK_OBJECT_HANDLE  obj_list[10];
	CK_ULONG          find_count;
	CK_ULONG          num_existing_objects;


	printf("do_FindObjects...\n");

	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	slot_id = SLOT_ID;


	// create a USER R/W session
	//
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h_session );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return FALSE;
	}

	rc = funcs->C_Login( h_session, CKU_USER, user_pin, user_pin_len );
	if (rc != CKR_OK) {
		show_error("   C_Login #1", rc );
		return FALSE;
	}

	//
	//---------------------------------------------------------------------
	//

	// Get a count on all currently existing session objects
	// If any objects existed before, then after we create three new objects
	// we expect there to be a total of current_num_objects+3 tokens.
	//
	rc = funcs->C_FindObjectsInit( h_session, NULL, 0 );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsInit #0", rc );
		return FALSE;
	}

	rc = funcs->C_FindObjects( h_session, obj_list, 10, &num_existing_objects);
	if (rc != CKR_OK) {
		show_error("   C_FindObjects #0", rc );
		return FALSE;
	}

	rc = funcs->C_FindObjectsFinal( h_session );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsFinal #0", rc );
		return FALSE;
	}

	/* Since we'll only be checking for max 10 objects...  */
	if (num_existing_objects > 7)
		num_existing_objects = 7;

	// create the objects
	//
	rc = funcs->C_CreateObject( h_session, cert1_attribs, 6, &h_cert1 );
	if (rc != CKR_OK) {
		show_error("   C_CreateObject #1", rc );
		return FALSE;
	}

	rc = funcs->C_CreateObject( h_session, cert2_attribs, 6, &h_cert2 );
	if (rc != CKR_OK) {
		show_error("   C_CreateObject #2", rc );
		return FALSE;
	}

	rc = funcs->C_CreateObject( h_session, cert3_attribs, 6, &h_cert3 );
	if (rc != CKR_OK) {
		show_error("   C_CreateObject #3", rc );
		return FALSE;
	}

	//
	//---------------------------------------------------------------------
	//

	// now, search for the 2nd objects
	//
	rc = funcs->C_FindObjectsInit( h_session, find1_attribs, 1 );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsInit #1", rc );
		return FALSE;
	}

	rc = funcs->C_FindObjects( h_session, obj_list, 10, &find_count );
	if (rc != CKR_OK) {
		show_error("   C_FindObjects #1", rc );
		return FALSE;
	}

	if (find_count != 1) {
		printf("   ERROR:  C_FindObjects #1 should have found 1 object!\n");
		printf("           it found %ld objects\n", find_count);
		return FALSE;
	}

	if (obj_list[0] != h_cert2) {
		printf("   ERROR:  C_FindObjects #1 found the wrong object!");
		return FALSE;
	}

	rc = funcs->C_FindObjectsFinal( h_session );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsFinal #1", rc );
		return FALSE;
	}

	//
	//---------------------------------------------------------------------
	//

	// now, search for a non-existant object
	//
	rc = funcs->C_FindObjectsInit( h_session, find2_attribs, 1 );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsInit #2", rc );
		return FALSE;
	}

	rc = funcs->C_FindObjects( h_session, obj_list, 10, &find_count );
	if (rc != CKR_OK) {
		show_error("   C_FindObjects #2", rc );
		return FALSE;
	}

	if (find_count != 0) {
		printf("   ERROR:  C_FindObjects #2 should have found 0 object!\n");
		printf("           it found %ld objects\n", find_count);
		return FALSE;
	}

	rc = funcs->C_FindObjectsFinal( h_session );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsFinal #2", rc );
		return FALSE;
	}

	//
	//---------------------------------------------------------------------
	//

	// now, try to retrieve a list of all the objects
	//
	rc = funcs->C_FindObjectsInit( h_session, NULL, 0 );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsInit #3", rc );
		return FALSE;
	}

	rc = funcs->C_FindObjects( h_session, obj_list, 10, &find_count );
	if (rc != CKR_OK) {
		show_error("   C_FindObjects #3", rc );
		return FALSE;
	}

	if (find_count != num_existing_objects + 3) {
		printf("   ERROR:  C_FindObjects #3 should have found %ld objects!\n",
				num_existing_objects+3);
		printf("           it found %ld objects\n", find_count);
		return FALSE;
	}

	rc = funcs->C_FindObjectsFinal( h_session );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsFinal #3", rc );
		return FALSE;
	}

	//
	//---------------------------------------------------------------------
	//

	// done...close the session and verify the object is deleted
	//
	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc );
		return FALSE;
	}

	printf("Looks okay...\n");
	return TRUE;
}


// do_CreateTokenObjects()
//
//  1) Create 3 certificates as PUBLIC token objects
//  2) Search for a particular CKA_ID.  Verify that this works.
//  3) Do FindObjects with a NULL template.  Verify that all 3 token objects
//     are found.
//  4) Search for a particular CKA_ID.  Verify it works.
//  5) Search for a non-existant CKA_ID.  Verify it returns nothing.
//  6) Close all sessions.  Then create a new session.
//  7) Do FindObjects with a NULL template.  Verify that all 3 token objects
//     are found.
//  8) Search for a particular CKA_ID.  Verify it works.
//  9) Search for a non-existant CKA_ID.  Verify it returns nothing.
// 10) Destroy all 3 token objects
// 11) Do FindObjects with a NULL template.  Verify that nothing is returned.
//
int do_CreateTokenObjects( void )
{
	CK_SLOT_ID        slot_id;
	CK_FLAGS          flags;
	CK_RV             rc;
	CK_BYTE           user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG          user_pin_len;

	CK_SESSION_HANDLE h_session;

	CK_BYTE           true = TRUE;
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
		{CKA_ID,               &cert1_id,          sizeof(cert1_id)      },
		{CKA_VALUE,            &cert1_value,       sizeof(cert1_value)   },
		{CKA_PRIVATE,          &false,             sizeof(false)         }
	};

	CK_OBJECT_HANDLE    h_cert2;
	CK_OBJECT_CLASS     cert2_class        = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE cert2_type         = CKC_X_509;
	CK_BYTE             cert2_subject[]    = "Certificate subject #2";
	CK_BYTE             cert2_id[]         = "Certificate ID #2";
	CK_BYTE             cert2_value[]      = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";

	CK_ATTRIBUTE        cert2_attribs[] =
	{
		{CKA_CLASS,            &cert2_class,       sizeof(cert2_class)   },
		{CKA_TOKEN,            &true,              sizeof(true)          },
		{CKA_CERTIFICATE_TYPE, &cert2_type,        sizeof(cert2_type)    },
		{CKA_SUBJECT,          &cert2_subject,     sizeof(cert2_subject) },
		{CKA_ID,               &cert2_id,          sizeof(cert2_id)      },
		{CKA_VALUE,            &cert2_value,       sizeof(cert2_value)   },
		{CKA_PRIVATE,          &false,             sizeof(false)         }
	};

	CK_OBJECT_HANDLE    h_cert3;
	CK_OBJECT_CLASS     cert3_class        = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE cert3_type         = CKC_X_509;
	CK_BYTE             cert3_subject[]    = "Certificate subject #3";
	CK_BYTE             cert3_id[]         = "Certificate ID #3";
	CK_BYTE             cert3_value[]      = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";

	CK_ATTRIBUTE        cert3_attribs[] =
	{
		{CKA_CLASS,            &cert3_class,       sizeof(cert3_class)   },
		{CKA_TOKEN,            &true,              sizeof(true)          },
		{CKA_CERTIFICATE_TYPE, &cert3_type,        sizeof(cert3_type)    },
		{CKA_SUBJECT,          &cert3_subject,     sizeof(cert3_subject) },
		{CKA_ID,               &cert3_id,          sizeof(cert3_id)      },
		{CKA_VALUE,            &cert3_value,       sizeof(cert3_value)   },
		{CKA_PRIVATE,          &false,             sizeof(false)         }
	};

	CK_BYTE  find1_id[] = "Certificate ID #2";
	CK_ATTRIBUTE   find1_attribs[] =
	{
		{CKA_ID, &find1_id,  sizeof(find1_id)}
	};

	CK_BYTE  find2_id[] = "Certificate ID #123456";
	CK_ATTRIBUTE   find2_attribs[] =
	{
		{CKA_ID, &find2_id,  sizeof(find2_id)}
	};

	CK_OBJECT_HANDLE  obj_list[10];
	CK_ULONG          find_count;



	printf("do_CreateTokenObjects...\n");

	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	slot_id = SLOT_ID;


	// create a USER R/W session
	//
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h_session );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return FALSE;
	}

	rc = funcs->C_Login( h_session, CKU_USER, user_pin, user_pin_len );
	if (rc != CKR_OK) {
		show_error("   C_Login #1", rc );
		return FALSE;
	}

	//
	//---------------------------------------------------------------------
	//

	// create the token objects
	//
	rc = funcs->C_CreateObject( h_session, cert1_attribs, 7, &h_cert1 );
	if (rc != CKR_OK) {
		show_error("   C_CreateObject #1", rc );
		return FALSE;
	}

	rc = funcs->C_CreateObject( h_session, cert2_attribs, 7, &h_cert2 );
	if (rc != CKR_OK) {
		show_error("   C_CreateObject #2", rc );
		return FALSE;
	}

	rc = funcs->C_CreateObject( h_session, cert3_attribs, 7, &h_cert3 );
	if (rc != CKR_OK) {
		show_error("   C_CreateObject #3", rc );
		return FALSE;
	}

	//
	//---------------------------------------------------------------------
	//

	// now, retrieve a list of all object handles
	//
	rc = funcs->C_FindObjectsInit( h_session, NULL, 0 );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsInit #1", rc );
		return FALSE;
	}

	rc = funcs->C_FindObjects( h_session, obj_list, 10, &find_count );
	if (rc != CKR_OK) {
		show_error("   C_FindObjects #1", rc );
		return FALSE;
	}

	if (find_count != 3) {
		printf("   ERROR:  expected C_FindObjects #1 to find 3 objects\n");
		printf("           it found %ld objects\n", find_count );
		return FALSE;
	}

	rc = funcs->C_FindObjectsFinal( h_session );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsFinal #1", rc );
		return FALSE;
	}

	//
	//---------------------------------------------------------------------
	//

	// now, search for the 2nd object
	//
	rc = funcs->C_FindObjectsInit( h_session, find1_attribs, 1 );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsInit #2", rc );
		return FALSE;
	}

	rc = funcs->C_FindObjects( h_session, obj_list, 10, &find_count );
	if (rc != CKR_OK) {
		show_error("   C_FindObjects #2", rc );
		return FALSE;
	}

	if (find_count != 1) {
		printf("   ERROR:  C_FindObjects #2 should have found 1 object!\n");
		return FALSE;
	}

	if (obj_list[0] != h_cert2) {
		printf("   ERROR:  C_FindObjects #2 found the wrong object!");
		return FALSE;
	}

	rc = funcs->C_FindObjectsFinal( h_session );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsFinal #2", rc );
		return FALSE;
	}

	//
	//---------------------------------------------------------------------
	//

	// now, search for a non-existant attribute
	//
	rc = funcs->C_FindObjectsInit( h_session, find2_attribs, 1 );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsInit #3", rc );
		return FALSE;
	}

	rc = funcs->C_FindObjects( h_session, obj_list, 10, &find_count );
	if (rc != CKR_OK) {
		show_error("   C_FindObjects #3", rc );
		return FALSE;
	}

	if (find_count != 0) {
		printf("   ERROR:  C_FindObjects #3 should have found 0 objects!\n");
		return FALSE;
	}

	rc = funcs->C_FindObjectsFinal( h_session );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsFinal #3", rc );
		return FALSE;
	}

	//
	//---------------------------------------------------------------------
	//

	// done...close all sessions and open a new one
	//
	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc );
		return FALSE;
	}

	// create a USER R/W session
	//
	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &h_session );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #2", rc );
		return FALSE;
	}

	rc = funcs->C_Login( h_session, CKU_USER, user_pin, user_pin_len );
	if (rc != CKR_OK) {
		show_error("   C_Login #2", rc );
		return FALSE;
	}

	//
	//---------------------------------------------------------------------
	//

	// now, retrieve a list of all object handles
	//
	rc = funcs->C_FindObjectsInit( h_session, NULL, 0 );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsInit #4", rc );
		return FALSE;
	}

	rc = funcs->C_FindObjects( h_session, obj_list, 10, &find_count );
	if (rc != CKR_OK) {
		show_error("   C_FindObjects #4", rc );
		return FALSE;
	}

	if (find_count != 3) {
		printf("   ERROR:  expected C_FindObjects #4 to find 3 objects\n");
		printf("           it found %ld objects\n", find_count );
		return FALSE;
	}

	rc = funcs->C_FindObjectsFinal( h_session );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsFinal #4", rc );
		return FALSE;
	}

	//
	//---------------------------------------------------------------------
	//

	// now, search for the 2nd object
	//
	rc = funcs->C_FindObjectsInit( h_session, find1_attribs, 1 );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsInit #5", rc );
		return FALSE;
	}

	rc = funcs->C_FindObjects( h_session, obj_list, 10, &find_count );
	if (rc != CKR_OK) {
		show_error("   C_FindObjects #5", rc );
		return FALSE;
	}

	if (find_count != 1) {
		printf("   ERROR:  C_FindObjects #5 should have found 1 object!\n");
		return FALSE;
	}

	if (obj_list[0] != h_cert2) {
		printf("   ERROR:  C_FindObjects #5 found the wrong object!");
		return FALSE;
	}

	rc = funcs->C_FindObjectsFinal( h_session );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsFinal #5", rc );
		return FALSE;
	}

	//
	//---------------------------------------------------------------------
	//

	// now, search for a non-existant attribute
	//
	rc = funcs->C_FindObjectsInit( h_session, find2_attribs, 1 );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsInit #6", rc );
		return FALSE;
	}

	rc = funcs->C_FindObjects( h_session, obj_list, 10, &find_count );
	if (rc != CKR_OK) {
		show_error("   C_FindObjects #6", rc );
		return FALSE;
	}

	if (find_count != 0) {
		printf("   ERROR:  C_FindObjects #6 should have found 0 objects!\n");
		return FALSE;
	}

	rc = funcs->C_FindObjectsFinal( h_session );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsFinal #6", rc );
		return FALSE;
	}

	//
	//---------------------------------------------------------------------
	//

	// now, destroy the objects
	//
	rc = funcs->C_DestroyObject( h_session, h_cert1 );
	if (rc != CKR_OK) {
		show_error("   C_DestroyObject #1", rc );
		return FALSE;
	}

	rc = funcs->C_DestroyObject( h_session, h_cert2 );
	if (rc != CKR_OK) {
		show_error("   C_DestroyObject #2", rc );
		return FALSE;
	}

	rc = funcs->C_DestroyObject( h_session, h_cert3 );
	if (rc != CKR_OK) {
		show_error("   C_DestroyObject #3", rc );
		return FALSE;
	}

	//
	//---------------------------------------------------------------------
	//

	// now, retrieve a list of all object handles
	//
	rc = funcs->C_FindObjectsInit( h_session, NULL, 0 );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsInit #7", rc );
		return FALSE;
	}

	rc = funcs->C_FindObjects( h_session, obj_list, 10, &find_count );
	if (rc != CKR_OK) {
		show_error("   C_FindObjects #7", rc );
		return FALSE;
	}

	if (find_count != 0) {
		printf("   ERROR:  expected C_FindObjects #7 to find 0 objects\n");
		printf("           it found %ld objects\n", find_count );
		return FALSE;
	}

	rc = funcs->C_FindObjectsFinal( h_session );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsFinal #7", rc );
		return FALSE;
	}

	//
	//---------------------------------------------------------------------
	//

	// done...close the session
	//
	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #2", rc );
		return FALSE;
	}


	printf("Looks okay...\n");
	return TRUE;
}

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

int do_HWFeatureSearch(void)
{
	unsigned int            i;
	CK_RV 			rc;
	CK_ULONG		find_count;
	CK_SLOT_ID		slot_id;
	CK_BBOOL		false = FALSE;
	CK_BBOOL                true = TRUE;

	CK_SESSION_HANDLE 	h_session;
	CK_BYTE           	user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG          	user_pin_len;

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
	CK_ATTRIBUTE		find_tmpl[] = {
		{CKA_CLASS,	&counter1_class, sizeof(counter1_class)}
	};

	slot_id = SLOT_ID;

	printf("do_HWFeatureSearch...");

	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	/* Open a session with the token */
	if( (rc = funcs->C_OpenSession(slot_id, 
					(CKF_SERIAL_SESSION|CKF_RW_SESSION), 
					NULL_PTR, 
					NULL_PTR, 
					&h_session)) != CKR_OK ) {
		show_error("C_OpenSession #1", rc);
		goto done;
	}

	// Login correctly
	rc = funcs->C_Login(h_session, CKU_USER, user_pin, user_pin_len);
	if( rc != CKR_OK ) {
		show_error("C_Login #1", rc);
		goto session_close;
	}

	printf("do_HW_Feature_Search...\n");

	/* Create the 3 test objects */
	if( (rc = funcs->C_CreateObject(h_session, obj1_template, 4, &h_obj1)) != CKR_OK) {
		show_error("C_CreateObject #1", rc);
		return rc;
	}

	if( (rc = funcs->C_CreateObject(h_session, obj2_template, 5, &h_obj2)) != CKR_OK) {
		show_error("C_CreateObject #2", rc);
		goto destroy_1;
	}

	if( (rc = funcs->C_CreateObject(h_session, counter1_template, 6, &h_counter1)) != CKR_OK) {
		show_error("C_CreateObject #3", rc);
		goto destroy_2;
	}

	if( (rc = funcs->C_CreateObject(h_session, counter2_template, 6, &h_counter2)) != CKR_OK) {
		show_error("C_CreateObject #4", rc);
		goto destroy_3;
	}

	if( (rc = funcs->C_CreateObject(h_session, clock_template, 4, &h_clock)) != CKR_OK) {
		show_error("C_CreateObject #5", rc);
		goto destroy_4;
	}


	// Search for the 2 objects w/o HW_FEATURE set
	//

	// A NULL template here should return all objects in v2.01, but
	// in v2.11, it should return all objects *except* HW_FEATURE
	// objects. - KEY
	rc = funcs->C_FindObjectsInit(h_session, NULL, 0 );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsInit #1", rc );
		goto destroy;
	}

	rc = funcs->C_FindObjects(h_session, obj_list, 10, &find_count );
	if (rc != CKR_OK) {
		show_error("   C_FindObjects #1", rc );
		goto destroy;
	}

	/* So, we created 3 objects before here, and then searched with a NULL
	 * template, so that should return all objects except our hardware
	 * feature object. -KEY */
	if (find_count != 2) {
		printf("%s:%d ERROR:  C_FindObjects #1 should have found 2 objects!\n"
				"           It found %ld objects\n", __FILE__, __LINE__,
				find_count);
		rc = -1;
		goto destroy;
	}

	if (obj_list[0] != h_obj1 && obj_list[0] != h_obj2) {
		printf("%s:%d ERROR:  C_FindObjects #1 found the wrong objects!",
				__FILE__, __LINE__);
		rc = -1;
		goto destroy;
	}

	if (obj_list[1] != h_obj1 && obj_list[1] != h_obj2) {
		printf("%s:%d ERROR:  C_FindObjects #1 found the wrong objects!",
				__FILE__, __LINE__);
		rc = -1;
		goto destroy;
	}

	rc = funcs->C_FindObjectsFinal(h_session);
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsFinal #1", rc );
		goto destroy;
	}


	// Now find the hardware feature objects
	rc = funcs->C_FindObjectsInit(h_session, find_tmpl, 1 );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsInit #2", rc );
		goto destroy;
	}

	rc = funcs->C_FindObjects(h_session, obj_list, 10, &find_count );
	if (rc != CKR_OK) {
		show_error("   C_FindObjects #2", rc );
		goto destroy;
	}

	if (find_count != 3) {
		printf("%s:%d ERROR:  C_FindObjects #2 should have found 3 objects!\n"
				"           It found %ld objects\n", __FILE__, __LINE__,
				find_count);
		funcs->C_FindObjectsFinal(h_session);
		rc = -1;
		goto destroy;
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

	rc = funcs->C_FindObjectsFinal(h_session );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsFinal #2", rc );
	}

	printf("Hardware Feature tests succeeded.\n");

destroy:
	/* Destroy the created objects, don't clobber the rc */
	funcs->C_DestroyObject(h_session, h_clock);
destroy_4:
	funcs->C_DestroyObject(h_session, h_counter2);
destroy_3:
	funcs->C_DestroyObject(h_session, h_counter1);
destroy_2:
	funcs->C_DestroyObject(h_session, h_obj2);
destroy_1:
	funcs->C_DestroyObject(h_session, h_obj1);
logout:
	rc = funcs->C_Logout(h_session);
	if( rc != CKR_OK )
		show_error("C_Logout #1", rc);

session_close:
	/* Close the session */
	if( (rc = funcs->C_CloseSession(h_session)) != CKR_OK )
		show_error("C_CloseSession", rc);
done:
	return TRUE;
}

int obj_mgmt_functions()
{
	SYSTEMTIME  t1, t2;
	int         rc;


	GetSystemTime(&t1);
	rc = do_CreateSessionObject();
	if (!rc && !no_stop)
		return FALSE;
	GetSystemTime(&t2);
	process_time( t1, t2 );


	GetSystemTime(&t1);
	rc = do_CopyObject();
	if (!rc && !no_stop)
		return FALSE;
	GetSystemTime(&t2);
	process_time( t1, t2 );


	GetSystemTime(&t1);
	rc = do_SetAttributeValues();
	if (!rc && !no_stop)
		return FALSE;
	GetSystemTime(&t2);
	process_time( t1, t2 );

	GetSystemTime(&t1);
	rc = do_FindObjects();
	if (!rc && !no_stop)
		return FALSE;
	GetSystemTime(&t2);
	process_time( t1, t2 );

	GetSystemTime(&t1);
	rc = do_HWFeatureSearch();
	if (!rc && !no_stop)
		return FALSE;
	GetSystemTime(&t2);
	process_time( t1, t2 );

	if (skip_token_obj == TRUE) {
		printf("Skipping do_CreateTokenObjects()...\n\n");
	}
	else {
		GetSystemTime(&t1);
		rc = do_CreateTokenObjects();
		if (!rc && !no_stop)
			return FALSE;
		GetSystemTime(&t2);
		process_time( t1, t2 );
	}

	return TRUE;
}
