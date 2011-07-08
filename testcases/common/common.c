#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "pkcs11types.h"
#include "regress.h"

CK_ULONG t_total = 0;		// total test assertions
CK_ULONG t_ran = 0;		// number of assertions ran
CK_ULONG t_passed = 0;		// number of assertions passed
CK_ULONG t_failed = 0;		// number of assertions failed
CK_ULONG t_skipped = 0;		// number of assertions skipped
CK_ULONG t_errors = 0;		// number of errors

#define MAX_MODEL 4

#define DES_KEY_SIZE 8
#define DES3_KEY_SIZE 24

struct	modelinfo {
	const char *name;
	int seckey;
};

struct modelinfo modellist[] = {
	{ .name="TPM", .seckey = 1, },
	{ .name="CCA", .seckey = 1, },
	{ .name="ICA", .seckey = 0, },
	{ .name="SoftTok", .seckey = 0, }
};

int get_key_type(void)
{
	int 		i;
	CK_RV		rc;
	CK_TOKEN_INFO	tokinfo;

	rc = funcs->C_GetTokenInfo(SLOT_ID, &tokinfo);
	if (rc != CKR_OK)
		return -1;

	for (i=0; i < MAX_MODEL; i++) {
		if (strstr((const char *)tokinfo.model, modellist[i].name))
			return(modellist[i].seckey);
	}

	return -1;
}

int mech_supported(CK_SLOT_ID slot_id, CK_ULONG mechanism) {
        CK_MECHANISM_INFO mech_info;
        int rc;
        rc = funcs->C_GetMechanismInfo(slot_id, mechanism, &mech_info);
        return (rc == CKR_OK);
}

int create_AESKey(CK_SESSION_HANDLE session,
                char key[],
                unsigned char key_len,
                CK_OBJECT_HANDLE *h_key)
{
        CK_RV           rc;
        CK_BBOOL        true = TRUE;
        CK_BBOOL        false = FALSE;
        CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
        CK_KEY_TYPE     keyType = CKK_AES;
        CK_ATTRIBUTE    keyTemplate[] =
        {
                        {CKA_CLASS,     &keyClass,      sizeof(keyClass)},
                        {CKA_KEY_TYPE,  &keyType,       sizeof(keyType)},
                        {CKA_ENCRYPT,   &true,          sizeof(true)},
                        {CKA_TOKEN,     &false,         sizeof(false)},
                        {CKA_VALUE,     key,            key_len}
        };

        rc = funcs->C_CreateObject(session, keyTemplate, 5, h_key);
        return rc;
}

int generate_AESKey(CK_SESSION_HANDLE session,
                CK_ULONG key_len,
                CK_MECHANISM *mechkey,
                CK_OBJECT_HANDLE *h_key)
{
        CK_ATTRIBUTE    key_gen_tmpl[] =
                {{CKA_VALUE_LEN, &key_len, sizeof(CK_ULONG)}};

        CK_RV rc = funcs->C_GenerateKey(session,
                                        mechkey,
                                        key_gen_tmpl,
                                        1,
                                        h_key);
        return rc;
}

int create_DESKey(CK_SESSION_HANDLE session,
                char key[],
                unsigned char klen,
                CK_OBJECT_HANDLE *h_key)
{
        CK_RV           rc;
        CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
        CK_KEY_TYPE     keyType = CKK_DES;
        CK_BYTE         value[DES_KEY_SIZE];
        CK_BBOOL        true = TRUE;
        CK_BBOOL        false = FALSE;

        CK_ATTRIBUTE keyTemplate[] =
        {
                {CKA_CLASS,     &keyClass,      sizeof(keyClass)},
                {CKA_KEY_TYPE,  &keyType,       sizeof(keyType)},
                {CKA_ENCRYPT,   &true,          sizeof(true)},
                {CKA_TOKEN,     &false,         sizeof(false)},
                {CKA_VALUE,     value,          klen}
        };

        memset(value, 0, sizeof(value));
        memcpy(value, key, klen);
        rc = funcs->C_CreateObject(session, keyTemplate, 5, h_key);
        if (rc != CKR_OK) {
                testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
        }
        return rc;
}

int create_DES3Key(CK_SESSION_HANDLE session,
                char key[],
                unsigned char klen,
                CK_OBJECT_HANDLE *h_key)
{
        CK_RV           rc;
        CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
        CK_KEY_TYPE     keyType = CKK_DES3;
        CK_BYTE         value[DES3_KEY_SIZE];
        CK_BBOOL        true = TRUE;
        CK_BBOOL        false = FALSE;
        CK_ATTRIBUTE    keyTemplate[] =
        {
                {CKA_CLASS,     &keyClass,      sizeof(keyClass)},
                {CKA_KEY_TYPE,  &keyType,       sizeof(keyType)},
                {CKA_ENCRYPT,   &true,          sizeof(true)},
                {CKA_TOKEN,     &false,         sizeof(false)},
                {CKA_VALUE,     value,          klen}
        };

        memset(value, 0, sizeof(value));
        memcpy(value, key, klen);
        rc = funcs->C_CreateObject(session, keyTemplate, 5, h_key);
        if (rc != CKR_OK) {
                testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
        }
        return rc;
}

int create_GenericSecretKey(CK_SESSION_HANDLE session,
                        CK_BYTE key[],
                        CK_ULONG key_len,
                        CK_OBJECT_HANDLE *h_key)
{
        CK_OBJECT_CLASS key_class  = CKO_SECRET_KEY;
        CK_KEY_TYPE     key_type   = CKK_GENERIC_SECRET;
        CK_BBOOL        false      = FALSE;
        CK_RV           rc;
        CK_ATTRIBUTE    key_attribs[] =
        {
                {CKA_CLASS,       &key_class,   sizeof(key_class)       },
                {CKA_KEY_TYPE,    &key_type,    sizeof(key_type)        },
                {CKA_TOKEN,       &false,       sizeof(false)           },
                {CKA_VALUE,       key,          key_len                 }
        };

        rc = funcs->C_CreateObject(session, key_attribs, 4, h_key);
        if (rc != CKR_OK) {
                testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
        }
        return rc;
}

int get_so_pin(CK_BYTE *dest)
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

int get_user_pin(CK_BYTE *dest)
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
void print_hex( CK_BYTE *buf, CK_ULONG len )
{
   CK_ULONG i, j;

   i = 0;

   while (i < len) {
      for (j=0; (j < 16) && (i < len); j++, i++)
         fprintf(stderr, "%02x ", buf[i] );
      fprintf(stderr, "\n");
   }
   fprintf(stderr, "\n");
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
      testcase_error("C_GetFunctionList rc=%s", p11_get_ckr(rc));
      return FALSE;
   }

   return TRUE;

}
