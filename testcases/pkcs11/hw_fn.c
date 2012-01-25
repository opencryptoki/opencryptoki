
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

#define AES_KEY_SIZE_128	16

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
	CK_ATTRIBUTE		find_tmpl[] = {
		{CKA_CLASS,	&counter1_class, sizeof(counter1_class)}
	};


	/* Create the 3 test objects */
	if( (rc = funcs->C_CreateObject(sess, obj1_template, 4, &h_obj1)) != CKR_OK) {
		show_error("C_CreateObject #1", rc);
		return rc;
	}

	if( (rc = funcs->C_CreateObject(sess, obj2_template, 5, &h_obj2)) != CKR_OK) {
		show_error("C_CreateObject #2", rc);
		goto destroy_1;
	}

	if( (rc = funcs->C_CreateObject(sess, counter1_template, 6, &h_counter1)) != CKR_OK) {
		show_error("C_CreateObject #3", rc);
		goto destroy_2;
	}

	if( (rc = funcs->C_CreateObject(sess, counter2_template, 6, &h_counter2)) != CKR_OK) {
		show_error("C_CreateObject #4", rc);
		goto destroy_3;
	}

	if( (rc = funcs->C_CreateObject(sess, clock_template, 4, &h_clock)) != CKR_OK) {
		show_error("C_CreateObject #5", rc);
		goto destroy_4;
	}


	// Search for the 2 objects w/o HW_FEATURE set
	//

	// A NULL template here should return all objects in v2.01, but
	// in v2.11, it should return all objects *except* HW_FEATURE
	// objects. - KEY
	rc = funcs->C_FindObjectsInit( sess, NULL, 0 );
	if (rc != CKR_OK) {
		show_error("   C_FindObjectsInit #1", rc );
		goto done;
	}

	rc = funcs->C_FindObjects( sess, obj_list, 10, &find_count );
	if (rc != CKR_OK) {
		show_error("   C_FindObjects #1", rc );
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
		show_error("   C_FindObjectsFinal #1", rc );
		goto done;
	}


	// Now find the hardware feature objects
        rc = funcs->C_FindObjectsInit( sess, find_tmpl, 1 );
        if (rc != CKR_OK) {
                show_error("   C_FindObjectsInit #2", rc );
                goto done;
        }

        rc = funcs->C_FindObjects( sess, obj_list, 10, &find_count );
        if (rc != CKR_OK) {
                show_error("   C_FindObjects #2", rc );
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
                show_error("   C_FindObjectsFinal #2", rc );
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
	CK_BYTE			user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG		user_pin_len;

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
		show_error("C_Initialize", rc);
		return -1;
	}

	/* Open a session with the token */
	if( (rc = funcs->C_OpenSession(slot_id, 
					(CKF_SERIAL_SESSION|CKF_RW_SESSION), 
					NULL_PTR, 
					NULL_PTR, 
					&sess)) != CKR_OK ) {
		show_error("C_OpenSession #1", rc);
		goto done;
	}

	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	// Login correctly
	rc = funcs->C_Login(sess, CKU_USER, user_pin, user_pin_len);
	if( rc != CKR_OK ) {
		show_error("C_Login #1", rc);
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
                show_error("C_Logout #1", rc);

session_close:

	/* Close the session */
	if( (rc = funcs->C_CloseSession(sess)) != CKR_OK )
		show_error("C_CloseSession", rc);

done:
	/* Call C_Finalize and dlclose the library */
	return clean_up();
}

int clean_up(void)
{
	CK_RV rc = 0;

        if( (rc = funcs->C_Finalize(NULL)) != CKR_OK)
		show_error("C_Finalize", rc);

	/* Decrement the reference count to libopencryptoki.so */
	dlclose(dl_handle);

	return rc;
}

