
/*
 * Licensed materials - Property of IBM
 *
 * pkcs11_migrate - A tool to migrate PKCS#11 CCA key objects from one
 * master key to another.
 *
 * Copyright (C) International Business Machines Corp. 2007
 *
 */

/*
 * There are two things that need migration in a CCA-based PKCS#11 data
 * store in openCryptoki:
 *
 * 1. All the objects in the data store with a CKA_IBM_OPAQUE attribute
 * 2. The CCA key used to encrypt those objects
 *
 * The CCA key used to encrypt the data store's objects is stored in two
 * files (there are two copies of it), data_store/MK_SO and
 * data_store/MK_USER. MK_SO is the key encrypted using the md5 hash of
 * the SO's PIN as the key and likewise MK_USER is encrypted with the md5
 * hash of the USER's PIN.
 *
 * The shell-script that launches this program needs to do a few things:
 *
 * 1. Verify the slot that the user selects
 * 2. Gather the USER and SO PINs
 * 3. Locate the data store on disk
 *   -- The data store location will differ deponding on whether we're
 *      migrating on a SLES9 or SLES10 system
 * 4. Back-up the data store in case of failure
 *
 * Items 1-3 above will be passed as args to this program, then the steps
 * will be:
 *
 * 1. Read in all the CCA-based object attributes from the data store
 * 2. Migrate the CCA-based attributes to the new master key using the CCA APIs
 * 3. Delete the old unmigrated attributes
 * 4. Replace the old attributes with the migrated attributes
 * 5. Close the PKCS#11 data store
 * 6. Open the data store encryption key files using the SO and USER pins
 * 7. Migrate those keys using the CCA APIs
 * 8. Write them back out
 * 9. Migration is complete
 *
 *
 * Author: Kent Yoder <yoder1@us.ibm.com>
 * April 18, 2007
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include <pkcs11types.h>
#include "cca_migrate.h"


int n_flag = 0;
int v_flag = 0;
void *p11_lib = NULL;
void (*CSNDKTC)();
void (*CSNBKTC)();
void *lib_csulcca;

CK_FUNCTION_LIST *
p11_init(void)
{
	CK_RV            rv;
	CK_RV		 (*pfoo)();
	char		 *loc1_lib = "/usr/lib/pkcs11/PKCS11_API.so64";
	char		 *loc2_lib = "libopencryptoki.so";
	CK_FUNCTION_LIST *funcs = NULL;


	p11_lib = dlopen(loc1_lib, RTLD_NOW);
	if (p11_lib != NULL)
		goto get_list;

	p11_lib = dlopen(loc2_lib, RTLD_NOW);
	if (p11_lib == NULL) {
		print_error("Couldn't get a handle to the PKCS#11 library.");
		return NULL;
	}

get_list:
	pfoo = (CK_RV (*)())dlsym(p11_lib,"C_GetFunctionList");
	if (pfoo == NULL) {
		print_error("Couldn't get the address of the C_GetFunctionList routine.");
		dlclose(p11_lib);
		return NULL;
	}

	rv = pfoo(&funcs);
	if (rv != CKR_OK) {
		p11_error("C_GetFunctionList", rv);
		dlclose(p11_lib);
		return NULL;
	}

	rv = funcs->C_Initialize(NULL_PTR);
	if (rv != CKR_OK) {
		p11_error("C_Initialize", rv);
		dlclose(p11_lib);
		return NULL;
	}

	if (v_flag > 1)
		printf("PKCS#11 library initialized\n");

	return funcs;
}

void
p11_fini(CK_FUNCTION_LIST *funcs)
{
	funcs->C_Finalize(NULL_PTR);

	if (p11_lib)
		dlclose(p11_lib);
}

/* Expect attribute array to have 3 entries,
 * 0 CKA_IBM_OPAQUE
 * 1 CKA_CLASS
 * 2 CKA_KEY_TYPE
 */
int
add_object(CK_OBJECT_HANDLE handle,
	   CK_ATTRIBUTE  *attrs,
	   struct object **objs_to_migrate)
{
	struct object *new_obj;
	CK_ULONG key_type = *(CK_ULONG *)attrs[2].pValue;

	new_obj = malloc(sizeof(struct object));
	if (!new_obj) {
		print_error("Malloc of %zd bytes failed!", sizeof(struct object));
		return 1;
	}

	switch (key_type) {
		case CKK_RSA:
		case CKK_DES:
		case CKK_DES3:
			break;

		default:
			free(new_obj);
			return 0;
	}

	new_obj->type = key_type;
	new_obj->opaque_attr = malloc(attrs[0].ulValueLen);
	if (!new_obj->opaque_attr) {
		print_error("Malloc of %lu bytes failed!", attrs[0].ulValueLen);
		return 2;
	}
	new_obj->handle = handle;
	new_obj->attr_len = attrs[0].ulValueLen;
	memcpy(new_obj->opaque_attr, attrs[0].pValue, attrs[0].ulValueLen);

	new_obj->next = *objs_to_migrate;
	*objs_to_migrate = new_obj;

	if (v_flag > 1) {
		char *type_name;

		if (new_obj->type == CKK_RSA)
			type_name = RSA_NAME;
		else if (new_obj->type == CKK_DES)
			type_name = DES_NAME;
		else if (new_obj->type == CKK_DES3)
			type_name = DES3_NAME;
		else
			type_name = BAD_NAME;

		printf("Migratable key object found: type=%s, handle=%lu\n", type_name, handle);
	}

	return 0;
}

int
find_opaque_objects(CK_FUNCTION_LIST  *funcs,
		    CK_SESSION_HANDLE sess,
		    struct object     **objs_to_migrate)
{
	CK_RV		 rv;
	CK_OBJECT_HANDLE *handles = NULL, tmp;
	CK_ULONG	 ulObjectCount = 0, ulTotalCount = 0;
	CK_ATTRIBUTE	 attrs[] = {
		{ CKA_IBM_OPAQUE, NULL, 0 },
		{ CKA_CLASS, NULL, 0 },
		{ CKA_KEY_TYPE, NULL, 0 }
	};
	int	i, rc;

	/* Find all objects in the store */
	rv = funcs->C_FindObjectsInit(sess, NULL_PTR, 0);
	if (rv != CKR_OK) {
		p11_error("C_FindObjectsInit", rv);
		print_error("Error finding CCA key objects");
		return 1;
	}

	while (1) {
		rv = funcs->C_FindObjects(sess, &tmp, 1, &ulObjectCount);
		if (rv != CKR_OK) {
			p11_error("C_FindObjects", rv);
			print_error("Error finding CCA key objects");
			free(handles);
			return 1;
		}

		if (ulObjectCount == 0)
			break;

		handles = realloc(handles, sizeof(CK_OBJECT_HANDLE) * (++ulTotalCount));
		if (!handles) {
			print_error("Malloc of %lu bytes failed!", ulTotalCount);
			break;
		}

		handles[ulTotalCount - 1] = tmp;
	}
	if (v_flag > 1)
		printf("Found %lu PKCS#11 objects to examine\n", ulTotalCount);

	/* Don't care if this fails */
	funcs->C_FindObjectsFinal(sess);

	/* At this point we have an array with handles to every object in the store. We only care
	 * about those with a CKA_IBM_OPAQUE attribute, so whittle down the list accordingly */
	for (tmp = 0; tmp < ulTotalCount; tmp++) {
		rv = funcs->C_GetAttributeValue(sess, handles[tmp], attrs, 3);
		if (rv != CKR_OK) {
			p11_error("C_GetAttributeValue", rv);
			print_error("Error finding CCA key objects");
			free(handles);
			return 1;
		}

		/* If the opaque attr DNE for this object, move to the next one */
		if (attrs[0].ulValueLen == ((CK_ULONG)-1))
			continue;

		/* Allocate space in the template for the actual data */
		for (i = 0; i < 3; i++) {
			attrs[i].pValue = malloc(attrs[i].ulValueLen);
			if (!attrs[i].pValue) {
				print_error("Malloc of %lu bytes failed!", attrs[i].ulValueLen);
				free(handles);
				return 1;
			}
		}

		/* Pull in the actual data */
		rv = funcs->C_GetAttributeValue(sess, handles[tmp], attrs, 3);
		if (rv != CKR_OK) {
			p11_error("C_GetAttributeValue", rv);
			print_error("Error getting object attributes");
			free(handles);
			return 1;
		}

		rc = add_object(handles[tmp], attrs, objs_to_migrate);
		if (rc) {
			free(handles);
			return 1;
		}

		for (i = 0; i < 3; i++) {
			free(attrs[i].pValue);
			attrs[i].pValue = NULL_PTR;
			attrs[i].ulValueLen = 0;
		}
	}

	free(handles);

	return 0;
}

int
replace_objects(CK_FUNCTION_LIST  *funcs,
		CK_SESSION_HANDLE sess,
		struct object     *objs_to_migrate)
{
	CK_RV rv;
	CK_ATTRIBUTE new_attr[] = { { CKA_IBM_OPAQUE, NULL, 0 } };
	struct object *tmp;

	for (tmp = objs_to_migrate; tmp; tmp = tmp->next) {
		new_attr->pValue = tmp->opaque_attr;
		new_attr->ulValueLen = tmp->attr_len;

		if (n_flag == 0) {
			rv = funcs->C_SetAttributeValue(sess, tmp->handle, new_attr, 1);
			if (rv != CKR_OK) {
				p11_error("C_SetAttributeValue", rv);
				print_error("Error replacing old key with migrated key.");
				return 1;
			}
		}

		if (v_flag > 0) {
			char *type_name;

			if (tmp->type == CKK_RSA)
				type_name = RSA_NAME;
			else if (tmp->type == CKK_DES)
				type_name = DES_NAME;
			else if (tmp->type == CKK_DES3)
				type_name = DES3_NAME;
			else
				type_name = BAD_NAME;

			printf("Key object successfully migrated: type=%s, handle=%lu\n", type_name, tmp->handle);
		}
	}

	printf("Successfully migrated the key objects\n");

	return 0;
}

int
cca_migrate_des(char *blob, unsigned long blob_size, char **out)
{
	long return_code, reason_code, exit_data_length, rule_array_count;
	unsigned char *rule_array;
	unsigned char *key_identifier;
	//unsigned char exit_data[CCA_KEY_ID_SIZE] = { 0, };

	rule_array_count = 1;
	rule_array = (unsigned char *)"RTCMK   ";
	exit_data_length = 0;

	key_identifier = calloc(1, blob_size);
	if (!key_identifier) {
		print_error("Malloc of %lu bytes failed!", blob_size);
		return 1;
	}
	memcpy(key_identifier, blob, blob_size);

	CSNBKTC(&return_code,
		&reason_code,
		&exit_data_length,
		NULL,//&exit_data,
		&rule_array_count,
		rule_array,
		key_identifier);

	if (return_code != CCA_SUCCESS) {
		cca_error("CSNBKTC (DES Key Token Change)", return_code, reason_code);
		print_error("Migrating a DES key failed.");
		return 1;
	}

	*out = (char *)key_identifier;

	return 0;
}

int
cca_migrate_rsa(char *blob, unsigned long blob_size, char **out)
{
	long return_code, reason_code, exit_data_length, rule_array_count, key_identifier_length;
	unsigned char *rule_array;
	unsigned char *key_identifier;
	//unsigned char exit_data[CCA_KEY_ID_SIZE] = { 0, };

	rule_array_count = 1;
	rule_array = (unsigned char *)"RTCMK   ";
	exit_data_length = 0;
	key_identifier_length = blob_size;

	key_identifier = calloc(1, blob_size);
	if (!key_identifier) {
		print_error("Malloc of %lu bytes failed!", blob_size);
		return 1;
	}
	memcpy(key_identifier, blob, blob_size);

	CSNDKTC(&return_code,
		&reason_code,
		&exit_data_length,
		NULL,//&exit_data,
		&rule_array_count,
		rule_array,
		&key_identifier_length,
		key_identifier);

	if (return_code != CCA_SUCCESS) {
		cca_error("CSNDKTC (RSA Key Token Change)", return_code, reason_code);
		print_error("Migrating an RSA key failed.");
		return 1;
	}

	*out = (char *)key_identifier;

	return 0;
}

int
migrate_master_key(char *path, char *pin)
{
	char master_key[MASTER_KEY_SIZE], *migrated_master_key;
	char pin_md5_hash[MD5_HASH_SIZE];
	int rc;
	CK_RV rv;

	rc = compute_md5(pin, strlen(pin), pin_md5_hash);
	if (rc) {
		print_error("Error calculating MD5 of PIN!");
		return rc;
	}

	rv = load_masterkey(path, pin_md5_hash, master_key);
	if (rv != CKR_OK) {
		print_error("Error loading master key to migrate: %s", path);
		return 1;
	}

	rc = cca_migrate_des(master_key, MASTER_KEY_SIZE, &migrated_master_key);
	if (rc) {
		print_error("Error migrating master key: %s", path);
		return rc;
	}

	if (n_flag == 0) {
		rv = save_masterkey(path, pin_md5_hash, migrated_master_key);
		if (rv != CKR_OK) {
			print_error("Error saving migrated master key: %s", path);
			return 1;
		}
	}

	return 0;
}

int
migrate_master_keys(char *so_pin, char *user_pin, char *data_store)
{
	struct stat sbuf;
	char *path;
	int path_len = strlen(data_store) + 32;
	int rc;

	path = calloc(1, path_len);
	if (!path) {
		print_error("Malloc of %d bytes failed!", path_len);
		return 1;
	}

	/* Do the SO blob */
	snprintf(path, path_len, "%s/MK_SO", data_store);

	errno = 0;
	rc = stat(path, &sbuf);
	if (rc == -1) {
		print_error("Stat failed for %s: %s\n", path, strerror(errno));
		free(path);
		return 1;
	}

	rc = migrate_master_key(path, so_pin);
	if (rc) {
		print_error("Migration of the SO's master key failed.");
		free(path);
		return 1;
	}
	printf("Successfully migrated the SO's master key\n");

	/* Do the USER blob */
	snprintf(path, path_len, "%s/MK_USER", data_store);

	errno = 0;
	rc = stat(path, &sbuf);
	if (rc == -1) {
		print_error("Stat failed for %s: %s\n", path, strerror(errno));
		free(path);
		return 1;
	}

	rc = migrate_master_key(path, user_pin);
	if (rc) {
		print_error("Migration of the USER's master key failed.");
		free(path);
		return 1;
	}
	printf("Successfully migrated the USER's master key\n");

	free(path);

	return 0;
}

/* @objs: A linked list of data to migrate and the PKCS#11 handle for the object in
 * the data store.
 */
int
migrate_objects(struct object *objs_to_migrate)
{
	struct object *tmp;
	char *migrated_data = NULL;
	int rc;

	for (tmp = objs_to_migrate; tmp; tmp = tmp->next) {
		migrated_data = NULL;

		if (tmp->type == CKK_RSA) {
			rc = cca_migrate_rsa((char *)tmp->opaque_attr, tmp->attr_len, &migrated_data);
			if (rc) {
				print_error("Migration of RSA key failed.");
				return rc;
			}
		} else if (tmp->type == CKK_DES) {
			rc = cca_migrate_des((char *)tmp->opaque_attr, tmp->attr_len, &migrated_data);
			if (rc) {
				print_error("Migration of DES key failed.");
				return rc;
			}
		} else if (tmp->type == CKK_DES3) {
			rc = cca_migrate_des((char *)tmp->opaque_attr, tmp->attr_len, &migrated_data);
			if (rc) {
				print_error("Migration of 3DES key failed.");
				return rc;
			}
		} else {
			print_error("Attempted to migrate an unknown object type: 0x%lX."
				    " Ignoring.", tmp->type);
		}

		/* replace the original data with the migrated data in the object list */
		if (migrated_data) {
			free(tmp->opaque_attr);
			tmp->opaque_attr = (CK_BYTE *)migrated_data;
			if (v_flag > 1) {
				char *type_name;

				if (tmp->type == CKK_RSA)
					type_name = RSA_NAME;
				else if (tmp->type == CKK_DES)
					type_name = DES_NAME;
				else if (tmp->type == CKK_DES3)
					type_name = DES3_NAME;
				else
					type_name = BAD_NAME;

				printf("Key data successfully changed: type=%s, handle=%lu\n", type_name, tmp->handle);
			}
		}
	}

	return 0;
}

void
usage(char *pgm)
{
	printf("Usage: %s [-h] [-n] [-v] -c SLOT -d PATH -s PIN -u PIN\n", pgm);
	printf("\t-c SLOT     Migrate the token in slot number SLOT (required)\n");
	printf("\t-d PATH     Migrate the internal PKCS#11 files located in PATH (required)\n");
	printf("\t-s PIN      Use PIN as the security officer pin (required)\n");
	printf("\t-u PIN      Use PIN as the user pin (required)\n");
	printf("\t-n          Perform the migration steps but don't write the migrated data\n");
	printf("\t-v          Increase the verbosity of the command output\n");
	printf("\t-h          Display this usage message\n");
}

int
main(int argc, char *argv[])
{
	int               opt, c_flag = 0;
	CK_SLOT_ID	  slot_id = 0;
	char		 *so_pin = NULL, *user_pin = NULL, *data_store = NULL;

	CK_FUNCTION_LIST *funcs;
	CK_ULONG	  slot_count;
	CK_SESSION_HANDLE sess;
	CK_RV		  rv;
	struct object    *objs_to_migrate = NULL, *tmp, *to_free;
	int		  exit_code = 0, rc;
	
	lib_csulcca = dlopen("libcsulcca.so", (RTLD_GLOBAL | RTLD_NOW));
	if (lib_csulcca == NULL) {
		print_error("Couldn't get a handle to the CCA library.");
		return NULL;
	}

	CSNDKTC = dlsym(lib_csulcca, "CSNDKTC_32");
	CSNBKTC = dlsym(lib_csulcca, "CSNBKTC_32");	

	while ((opt = getopt(argc, argv, "c:d:s:u:nvh")) != -1) {
		switch (opt) {
		case 'c':
			c_flag++;
			slot_id = atoi(optarg);
			break;

		case 'd':
			data_store = strdup(optarg);
			break;

		case 's':
			so_pin = strdup(optarg);
			break;

		case 'u':
			user_pin = strdup(optarg);
			break;

		case 'n':
			n_flag++;
			break;

		case 'v':
			v_flag++;
			break;

		case 'h':
			usage(argv[0]);
			return 0;

		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (!c_flag || !data_store || !so_pin || !user_pin) {
		usage(argv[0]);
		return 1;
	}

	if (n_flag)
		printf("Dry-run of migration in progress\n");

	funcs = p11_init();
	if (!funcs) {
		return 2;
	}

	rv = funcs->C_GetSlotList(TRUE, NULL_PTR, &slot_count);
	if (rv != CKR_OK) {
		p11_error("C_GetSlotList", rv);
		exit_code = 3;
		goto finalize;
	}

	if (slot_id >= slot_count) {
		print_error("%lu is not a valid slot ID.", slot_id);
		exit_code = 4;
		goto finalize;
	}
	if (v_flag > 1)
		printf("Slot id %lu is valid\n", slot_id);

	/* Open a r/w session */
	rv = funcs->C_OpenSession(slot_id, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sess);
	if (rv != CKR_OK) {
		p11_error("C_OpenSession", rv);
		exit_code = 5;
		goto finalize;
	}
	if (v_flag > 1)
		printf("PKCS#11 r/w session opened\n");

	/* Login as the SO just validate the supplied pin */
	rv = funcs->C_Login(sess, CKU_SO, (CK_BYTE *)so_pin, strlen(so_pin));
	if (rv != CKR_OK) {
		p11_error("C_Login (SO)", rv);
		exit_code = 6;
		goto finalize;
	}
	if (v_flag > 1)
		printf("PKCS#11 SO login successful\n");

	/* Logout the SO */
	rv = funcs->C_Logout(sess);
	if (rv != CKR_OK) {
		p11_error("C_Logout", rv);
		exit_code = 7;
		goto finalize;
	}

	/* Login as the USER to validate the supplied pin and do the migration */
	rv = funcs->C_Login(sess, CKU_USER, (CK_BYTE *)user_pin, strlen(user_pin));
	if (rv != CKR_OK) {
		p11_error("C_Login (USER)", rv);
		exit_code = 8;
		goto finalize;
	}
	if (v_flag > 1)
		printf("PKCS#11 USER login successful\n");

	/* Find the affected PKCS#11 objects */
	rc = find_opaque_objects(funcs, sess, &objs_to_migrate);
	if (rc) {
		exit_code = 9;
		goto close;
	}

	/* XXX Print status: migrating X pub keys, X priv keys, X 3DES keys... */

	/* Use the CCA lib to migrate them to the new master key */
	rv = migrate_objects(objs_to_migrate);
	if (rv != CKR_OK) {
		exit_code = 10;
		goto close;
	}

	/* XXX Print status */

	/* Delete the old PKCS#11 objects (or just attribs if possible) and replace with the
	 * migrated data */
	rc = replace_objects(funcs, sess, objs_to_migrate);
	if (rc) {
		exit_code = 11;
		goto close;
	}

	/* XXX Print status: X objects successfully migrated */

	/* Free the list of PKCS#11 objects */
	for (to_free = objs_to_migrate; to_free; to_free = tmp) {
		tmp = to_free->next;
		free(to_free->opaque_attr);
		free(to_free);
	}

	/* Migrate the keys used to encrypt the data store */
	rc = migrate_master_keys(so_pin, user_pin, data_store);
	if (rc) {
		exit_code = 12;
		goto close;
	}

close:
	funcs->C_CloseSession(sess);
finalize:
	p11_fini(funcs);
	return exit_code;
}

char *
p11strerror(CK_RV rc)
{
	switch (rc) {
		case CKR_OK:
			return "CKR_OK";
		case CKR_CANCEL:
			return "CKR_CANCEL";
		case CKR_HOST_MEMORY:
			return "CKR_HOST_MEMORY";
		case CKR_SLOT_ID_INVALID:
			return "CKR_SLOT_ID_INVALID";
		case CKR_GENERAL_ERROR:
			return "CKR_GENERAL_ERROR";
		case CKR_FUNCTION_FAILED:
			return "CKR_FUNCTION_FAILED";
		case CKR_ARGUMENTS_BAD:
			return "CKR_ARGUMENTS_BAD";
		case CKR_NO_EVENT:
			return "CKR_NO_EVENT";
		case CKR_NEED_TO_CREATE_THREADS:
			return "CKR_NEED_TO_CREATE_THREADS";
		case CKR_CANT_LOCK:
			return "CKR_CANT_LOCK";
		case CKR_ATTRIBUTE_READ_ONLY:
			return "CKR_ATTRIBUTE_READ_ONLY";
		case CKR_ATTRIBUTE_SENSITIVE:
			return "CKR_ATTRIBUTE_SENSITIVE";
		case CKR_ATTRIBUTE_TYPE_INVALID:
			return "CKR_ATTRIBUTE_TYPE_INVALID";
		case CKR_ATTRIBUTE_VALUE_INVALID:
			return "CKR_ATTRIBUTE_VALUE_INVALID";
		case CKR_DATA_INVALID:
			return "CKR_DATA_INVALID";
		case CKR_DATA_LEN_RANGE:
			return "CKR_DATA_LEN_RANGE";
		case CKR_DEVICE_ERROR:
			return "CKR_DEVICE_ERROR";
		case CKR_DEVICE_MEMORY:
			return "CKR_DEVICE_MEMORY";
		case CKR_DEVICE_REMOVED:
			return "CKR_DEVICE_REMOVED";
		case CKR_ENCRYPTED_DATA_INVALID:
			return "CKR_ENCRYPTED_DATA_INVALID";
		case CKR_ENCRYPTED_DATA_LEN_RANGE:
			return "CKR_ENCRYPTED_DATA_LEN_RANGE";
		case CKR_FUNCTION_CANCELED:
			return "CKR_FUNCTION_CANCELED";
		case CKR_FUNCTION_NOT_PARALLEL:
			return "CKR_FUNCTION_NOT_PARALLEL";
		case CKR_FUNCTION_NOT_SUPPORTED:
			return "CKR_FUNCTION_NOT_SUPPORTED";
		case CKR_KEY_HANDLE_INVALID:
			return "CKR_KEY_HANDLE_INVALID";
		case CKR_KEY_SIZE_RANGE:
			return "CKR_KEY_SIZE_RANGE";
		case CKR_KEY_TYPE_INCONSISTENT:
			return "CKR_KEY_TYPE_INCONSISTENT";
		case CKR_KEY_NOT_NEEDED:
			return "CKR_KEY_NOT_NEEDED";
		case CKR_KEY_CHANGED:
			return "CKR_KEY_CHANGED";
		case CKR_KEY_NEEDED:
			return "CKR_KEY_NEEDED";
		case CKR_KEY_INDIGESTIBLE:
			return "CKR_KEY_INDIGESTIBLE";
		case CKR_KEY_FUNCTION_NOT_PERMITTED:
			return "CKR_KEY_FUNCTION_NOT_PERMITTED";
		case CKR_KEY_NOT_WRAPPABLE:
			return "CKR_KEY_NOT_WRAPPABLE";
		case CKR_KEY_UNEXTRACTABLE:
			return "CKR_KEY_UNEXTRACTABLE";
		case CKR_MECHANISM_INVALID:
			return "CKR_MECHANISM_INVALID";
		case CKR_MECHANISM_PARAM_INVALID:
			return "CKR_MECHANISM_PARAM_INVALID";
		case CKR_OBJECT_HANDLE_INVALID:
			return "CKR_OBJECT_HANDLE_INVALID";
		case CKR_OPERATION_ACTIVE:
			return "CKR_OPERATION_ACTIVE";
		case CKR_OPERATION_NOT_INITIALIZED:
			return "CKR_OPERATION_NOT_INITIALIZED";
		case CKR_PIN_INCORRECT:
			return "CKR_PIN_INCORRECT";
		case CKR_PIN_INVALID:
			return "CKR_PIN_INVALID";
		case CKR_PIN_LEN_RANGE:
			return "CKR_PIN_LEN_RANGE";
		case CKR_PIN_EXPIRED:
			return "CKR_PIN_EXPIRED";
		case CKR_PIN_LOCKED:
			return "CKR_PIN_LOCKED";
		case CKR_SESSION_CLOSED:
			return "CKR_SESSION_CLOSED";
		case CKR_SESSION_COUNT:
			return "CKR_SESSION_COUNT";
		case CKR_SESSION_HANDLE_INVALID:
			return "CKR_SESSION_HANDLE_INVALID";
		case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
			return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
		case CKR_SESSION_READ_ONLY:
			return "CKR_SESSION_READ_ONLY";
		case CKR_SESSION_EXISTS:
			return "CKR_SESSION_EXISTS";
		case CKR_SESSION_READ_ONLY_EXISTS:
			return "CKR_SESSION_READ_ONLY_EXISTS";
		case CKR_SESSION_READ_WRITE_SO_EXISTS:
			return "CKR_SESSION_READ_WRITE_SO_EXISTS";
		case CKR_SIGNATURE_INVALID:
			return "CKR_SIGNATURE_INVALID";
		case CKR_SIGNATURE_LEN_RANGE:
			return "CKR_SIGNATURE_LEN_RANGE";
		case CKR_TEMPLATE_INCOMPLETE:
			return "CKR_TEMPLATE_INCOMPLETE";
		case CKR_TEMPLATE_INCONSISTENT:
			return "CKR_TEMPLATE_INCONSISTENT";
		case CKR_TOKEN_NOT_PRESENT:
			return "CKR_TOKEN_NOT_PRESENT";
		case CKR_TOKEN_NOT_RECOGNIZED:
			return "CKR_TOKEN_NOT_RECOGNIZED";
		case CKR_TOKEN_WRITE_PROTECTED:
			return "CKR_TOKEN_WRITE_PROTECTED";
		case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
			return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
		case CKR_UNWRAPPING_KEY_SIZE_RANGE:
			return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
		case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
			return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
		case CKR_USER_ALREADY_LOGGED_IN:
			return "CKR_USER_ALREADY_LOGGED_IN";
		case CKR_USER_NOT_LOGGED_IN:
			return "CKR_USER_NOT_LOGGED_IN";
		case CKR_USER_PIN_NOT_INITIALIZED:
			return "CKR_USER_PIN_NOT_INITIALIZED";
		case CKR_USER_TYPE_INVALID:
			return "CKR_USER_TYPE_INVALID";
		case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
			return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
		case CKR_USER_TOO_MANY_TYPES:
			return "CKR_USER_TOO_MANY_TYPES";
		case CKR_WRAPPED_KEY_INVALID:
			return "CKR_WRAPPED_KEY_INVALID";
		case CKR_WRAPPED_KEY_LEN_RANGE:
			return "CKR_WRAPPED_KEY_LEN_RANGE";
		case CKR_WRAPPING_KEY_HANDLE_INVALID:
			return "CKR_WRAPPING_KEY_HANDLE_INVALID";
		case CKR_WRAPPING_KEY_SIZE_RANGE:
			return "CKR_WRAPPING_KEY_SIZE_RANGE";
		case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
			return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
		case CKR_RANDOM_SEED_NOT_SUPPORTED:
			return "CKR_RANDOM_SEED_NOT_SUPPORTED";
		case CKR_RANDOM_NO_RNG:
			return "CKR_RANDOM_NO_RNG";
		case CKR_BUFFER_TOO_SMALL:
			return "CKR_BUFFER_TOO_SMALL";
		case CKR_SAVED_STATE_INVALID:
			return "CKR_SAVED_STATE_INVALID";
		case CKR_INFORMATION_SENSITIVE:
			return "CKR_INFORMATION_SENSITIVE";
		case CKR_STATE_UNSAVEABLE:
			return "CKR_STATE_UNSAVEABLE";
		case CKR_CRYPTOKI_NOT_INITIALIZED:
			return "CKR_CRYPTOKI_NOT_INITIALIZED";
		case CKR_CRYPTOKI_ALREADY_INITIALIZED:
			return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
		case CKR_MUTEX_BAD:
			return "CKR_MUTEX_BAD";
		case CKR_MUTEX_NOT_LOCKED:
			return "CKR_MUTEX_NOT_LOCKED";
		default:
			return "UNKNOWN";
	}

	return "UNKNOWN";
}

