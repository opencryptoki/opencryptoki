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


int mech_supported(CK_SLOT_ID slot_id, CK_ULONG mechanism) {
        CK_MECHANISM_INFO mech_info;
        int rc;
        rc = funcs->C_GetMechanismInfo(slot_id, mechanism, &mech_info);
        return (rc == CKR_OK);
}

int check_supp_keysize(CK_SLOT_ID slot_id, CK_ULONG mechanism, CK_ULONG keylen) {
        CK_MECHANISM_INFO mech_info;
        int rc;
        rc = funcs->C_GetMechanismInfo(slot_id, mechanism, &mech_info);
	if (rc != CKR_OK)
		return FALSE;
	else return ( (mech_info.ulMinKeySize <= keylen) && (keylen <= mech_info.ulMaxKeySize));
}

/** Returns true if and only if slot supports
    key wrapping with specified mechanism **/
int wrap_supported(CK_SLOT_ID slot_id,
                CK_MECHANISM mech)
{
        CK_MECHANISM_INFO mech_info;
        CK_RV rc;
        // get mech info
        rc = funcs->C_GetMechanismInfo(slot_id,
                                mech.mechanism,
                                &mech_info);
        if (rc != CKR_OK) {
                testcase_error("C_GetMechanismInfo(), rc=%s.",
                        p11_get_ckr(rc));
                return -1;
        }
        rc = mech_info.flags & CKF_WRAP;
        return rc;
}

/** Returns true if and only if slot supports
    key unwrapping with specified mechanism **/
int unwrap_supported(CK_SLOT_ID slot_id,
                CK_MECHANISM mech)
{
        CK_MECHANISM_INFO mech_info;
        CK_RV rc;
        // get mech info
        rc = funcs->C_GetMechanismInfo(slot_id,
                                mech.mechanism,
                                &mech_info);
        if (rc != CKR_OK) {
                testcase_error("C_GetMechanismInfo(), rc=%s.",
                        p11_get_ckr(rc));
                return -1;
        }
        rc = mech_info.flags & CKF_UNWRAP;
        return rc;
}

/** Create an AES key handle with given value **/
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

/** Generate an AES key handle **/
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

/** Create a DES key handle with given value **/
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

/** Create DES3 key handle with given value **/
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

/** Create Generic Secret key handle with given value **/
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

/** Create an RSA private key using ctr
    (chinese remainder theorem) values **/
CK_RV create_RSAPrivateKey(CK_SESSION_HANDLE session,
                        CK_BYTE modulus[],
                        CK_BYTE publicExponent[],
                        CK_BYTE privateExponent[],
                        CK_BYTE prime1[],
                        CK_BYTE prime2[],
                        CK_BYTE exponent1[],
                        CK_BYTE exponent2[],
                        CK_BYTE coefficient[],
                        CK_ULONG modulus_len,
                        CK_ULONG publicExponent_len,
                        CK_ULONG privateExponent_len,
                        CK_ULONG prime1_len,
                        CK_ULONG prime2_len,
                        CK_ULONG exponent1_len,
                        CK_ULONG exponent2_len,
                        CK_ULONG coefficient_len,
                        CK_OBJECT_HANDLE *priv_key)
{

        CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
        CK_KEY_TYPE keyType = CKK_RSA;
        CK_UTF8CHAR label[] = "An RSA private key object";
        CK_BYTE subject[] = {};
        CK_BYTE id[] = {123};
        CK_RV rc;

        CK_BBOOL true = TRUE;
        CK_ATTRIBUTE template[] = {
                {CKA_CLASS, &class, sizeof(class)},
                {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
                {CKA_TOKEN, &true, sizeof(true)},
                {CKA_LABEL, label, sizeof(label)-1},
                {CKA_SUBJECT, subject, sizeof(subject)},
                {CKA_ID, id, sizeof(id)},
                {CKA_SENSITIVE, &true, sizeof(true)},
                {CKA_DECRYPT, &true, sizeof(true)},
                {CKA_SIGN, &true, sizeof(true)},
                {CKA_MODULUS, modulus, modulus_len},
                {CKA_PUBLIC_EXPONENT, publicExponent, publicExponent_len},
                {CKA_PRIVATE_EXPONENT, privateExponent, privateExponent_len},
                {CKA_PRIME_1, prime1, prime1_len},
                {CKA_PRIME_2, prime2, prime2_len},
                {CKA_EXPONENT_1, exponent1, exponent1_len},
                {CKA_EXPONENT_2, exponent2, exponent2_len},
                {CKA_COEFFICIENT, coefficient, coefficient_len}
        };

        // create key
        rc = funcs->C_CreateObject(session, template, 17, priv_key);
        if (rc != CKR_OK) {
                testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
        }
        return rc;
}

/** Create an RSA public key **/
CK_RV create_RSAPublicKey(CK_SESSION_HANDLE session,
                        CK_BYTE modulus[],
                        CK_BYTE publicExponent[],
                        CK_ULONG modulus_len,
                        CK_ULONG publicExponent_len,
                        CK_OBJECT_HANDLE *publ_key)
{

        CK_RV           rc;
        CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
        CK_KEY_TYPE     keyType = CKK_RSA;
        CK_UTF8CHAR     label[] = "An RSA public key object";
        CK_BBOOL        true = TRUE;
        CK_ATTRIBUTE    template[] = {
                {CKA_CLASS, &class, sizeof(class)},
                {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
                {CKA_TOKEN, &true, sizeof(true)},
                {CKA_LABEL, label, sizeof(label)-1},
                {CKA_WRAP, &true, sizeof(true)},
                {CKA_ENCRYPT, &true, sizeof(true)},
                {CKA_MODULUS, modulus, modulus_len},
                {CKA_PUBLIC_EXPONENT, publicExponent, publicExponent_len}
        };

        // create key
        rc = funcs->C_CreateObject(session, template, 8, publ_key);
        if (rc != CKR_OK) {
                testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
        }
        return rc;
}

/** Generate an RSA (PKCS) key pair **/
CK_RV generate_RSA_PKCS_KeyPair(CK_SESSION_HANDLE session,
                CK_ULONG modulusBits,
                CK_BYTE publicExponent[],
                CK_ULONG publicExponent_len,
                CK_OBJECT_HANDLE *publ_key,
                CK_OBJECT_HANDLE *priv_key)
{
        CK_RV           rc;
        CK_MECHANISM    mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};
        CK_BYTE         subject[] = {};
        CK_BYTE         id[] = {123};
        CK_BBOOL        true = TRUE;
        CK_ATTRIBUTE    publicKeyTemplate[] = {
                {CKA_ENCRYPT, &true, sizeof(true)},
                {CKA_VERIFY, &true, sizeof(true)},
                {CKA_WRAP, &true, sizeof(true)},
                {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
                {CKA_PUBLIC_EXPONENT, publicExponent, publicExponent_len}
        };
        CK_ATTRIBUTE    privateKeyTemplate[] = {
                {CKA_TOKEN, &true, sizeof(true)},
                {CKA_PRIVATE, &true, sizeof(true)},
                {CKA_SUBJECT, subject, sizeof(subject)},
                {CKA_ID, id, sizeof(id)},
                {CKA_SENSITIVE, &true, sizeof(true)},
                {CKA_DECRYPT, &true, sizeof(true)},
                {CKA_SIGN, &true, sizeof(true)},
                {CKA_UNWRAP, &true, sizeof(true)},
        };

        // generate keys
        rc = funcs->C_GenerateKeyPair(session,
                        &mech,
                        publicKeyTemplate,
                        5,
                        privateKeyTemplate,
                        8,
                        publ_key,
                        priv_key);
        return rc;
        // no error checking due to
        // ICA Token + public exponent values + CKR_TEMPLATE_INCONSISTENT
        // work around
        // see rsa_func.c
}

/* Generate a secret key */
CK_RV generate_SecretKey(CK_SESSION_HANDLE session,
                        CK_ULONG keylen,
                        CK_MECHANISM *mech,
                        CK_OBJECT_HANDLE *secret_key)
{
        CK_RV           rc;
        CK_OBJECT_CLASS class = CKO_SECRET_KEY;
        CK_ATTRIBUTE    secret_tmpl[] = {
                                {CKA_CLASS, &class, sizeof(class)},
                                {CKA_VALUE_LEN, &keylen, sizeof(keylen)}
                        };
        rc = funcs->C_GenerateKey(session, mech, secret_tmpl, 2, secret_key);
        if (rc != CKR_OK) {
                testcase_fail("C_GenerateKey, rc=%s", p11_get_ckr(rc));
        }
        return rc;
}

int keysize_supported(CK_SLOT_ID slot_id, CK_ULONG mechanism, CK_ULONG size)
{
	CK_MECHANISM_INFO mech_info;
	CK_RV rc;

	rc = funcs->C_GetMechanismInfo(slot_id, mechanism, &mech_info);
	if (size < mech_info.ulMinKeySize || size > mech_info.ulMaxKeySize)
		return 0;

	return (rc == CKR_OK);
}

/** Returns true if pubexp is valid for EP11 Tokens **/
int is_valid_ep11_pubexp(CK_BYTE pubexp[], CK_ULONG pubexp_len)
{
	/* everything > 0x10 valid */
	int i;
	if (pubexp[0] > 0x10)
		return 1;
	else {
		for (i = 1; i < pubexp_len + 1; i++) {
			if (pubexp[i] != 0)
				return 1;
		}
	}
	return 0;
}

/** Returns true if slot_id is an ICA Token **/
int is_ep11_token(CK_SLOT_ID slot_id)
{
	CK_RV	rc;
	CK_TOKEN_INFO   tokinfo;

	rc = funcs->C_GetTokenInfo(slot_id, &tokinfo);
	if (rc != CKR_OK)
		return -1;

	return strstr((const char *)tokinfo.model, "EP11") != NULL;
}

/** Returns true if pubexp is valid for CCA Tokens **/
int is_valid_cca_pubexp(CK_BYTE pubexp[], CK_ULONG pubexp_len)
{
        CK_BYTE exp3[] = {0x03}; // 3
        CK_BYTE exp65537[] = {0x01,0x00,0x01}; // 65537

        return (pubexp_len == 1 && (! memcmp(pubexp, exp3, 1) ))
                || (pubexp_len == 3 && (! memcmp(pubexp, exp65537, 3) ));
}

/** Returns true if slot_id is an ICSF token
 ** ICSF token info is not necessarily hard-coded like the other tokens
 ** so there is no single identifying attribute. So, instead just
 ** use logical deduction....
 **/
int is_icsf_token(CK_SLOT_ID slot_id)
{
        CK_RV           rc;
        CK_TOKEN_INFO   tokinfo;

        rc = funcs->C_GetTokenInfo(slot_id, &tokinfo);
        if (rc != CKR_OK) {
                return -1;
        }

	if ((strstr((const char *)tokinfo.model, "ICA") == NULL) &&
	    (strstr((const char *)tokinfo.model, "EP11") == NULL) &&
	    (strstr((const char *)tokinfo.model, "CCA") == NULL) &&
	    (strstr((const char *)tokinfo.model, "SoftTok") == NULL))
		return TRUE;
	else
		return FALSE;
}

/** Returns true if pubexp is valid for ICSF token **/
int is_valid_icsf_pubexp(CK_BYTE pubexp[], CK_ULONG pubexp_len)
{
        CK_BYTE exp65537[] = {0x01,0x00,0x01}; // 65537

        return (pubexp_len == 3 && (! memcmp(pubexp, exp65537, 3) ));
}

/** Returns true if slot_id is an ICA Token **/
int is_ica_token(CK_SLOT_ID slot_id)
{
        CK_RV           rc;
        CK_TOKEN_INFO   tokinfo;

        rc = funcs->C_GetTokenInfo(slot_id, &tokinfo);
        if (rc != CKR_OK) {
                return -1;
        }

        return strstr((const char *)tokinfo.model, "ICA") != NULL;

}

/** Returns true if slot_id is a CCA Token **/
int is_cca_token(CK_SLOT_ID slot_id)
{
        CK_RV           rc;
        CK_TOKEN_INFO   tokinfo;

        rc = funcs->C_GetTokenInfo(slot_id, &tokinfo);
        if (rc != CKR_OK) {
                return -1;
        }

        return strstr((const char *)tokinfo.model, "CCA") != NULL;
}

/** Returns true if slot_id is a SoftTok Token **/
int is_soft_token(CK_SLOT_ID slot_id)
{
        CK_RV           rc;
        CK_TOKEN_INFO   tokinfo;

        rc = funcs->C_GetTokenInfo(slot_id, &tokinfo);
        if (rc != CKR_OK) {
                return -1;
        }

        return strstr((const char *)tokinfo.model, "SoftTok") != NULL;
}

/** Returns true if slot_id is a TPM Token **/
int is_tpm_token(CK_SLOT_ID slot_id)
{
        CK_RV           rc;
        CK_TOKEN_INFO   tokinfo;

        rc = funcs->C_GetTokenInfo(slot_id, &tokinfo);
        if (rc != CKR_OK) {
                return -1;
        }

        return strstr((const char *)tokinfo.model, "TPM") != NULL;
}

/** Returns true if pubexp is valid for CCA Tokens **/
int is_valid_tpm_pubexp(CK_BYTE pubexp[], CK_ULONG pubexp_len)
{
        CK_BYTE exp65537[] = {0x01,0x00,0x01}; // 65537

        return (pubexp_len == 3 && (! memcmp(pubexp, exp65537, 3) ));
}

int is_valid_tpm_modbits(CK_ULONG modbits)
{
	switch(modbits) {
	case 512:
	case 1024:
	case 2048:
		return 1;
	default:
		return 0;
	}
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
	printf("usage:  %s [-securekey] [-noskip] [-noinit] [-h] -slot <num>\n\n", fct );

	return;
}


int do_ParseArgs(int argc, char **argv)
{
	int i;

	skip_token_obj = TRUE;
	no_stop = FALSE;
	no_init = FALSE;
	securekey = FALSE;
	SLOT_ID = 1000;


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
		else if (strcmp (argv[i], "-securekey") == 0)
			securekey = TRUE;

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

	// error if slot has not been identified.
	if (SLOT_ID == 1000) {
		printf("Please specify the slot to be tested.\n");
		usage (argv[0]);
		return -1;
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
