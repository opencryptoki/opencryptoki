/*
 * COPYRIGHT (c) International Business Machines Corp. 2006-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "pkcs11types.h"
#include "regress.h"
#include "platform.h"

#define UNUSED(var)            ((void)(var))

CK_FUNCTION_LIST *funcs;
CK_FUNCTION_LIST_3_0 *funcs3;
CK_INTERFACE *ifs;
CK_SLOT_ID SLOT_ID;

CK_BBOOL skip_token_obj;
CK_BBOOL no_stop;
CK_BBOOL no_init;
CK_BBOOL securekey;

/*
 * The pkey flag controls whether tests shall exploit the protected key
 * option. To allow easy integration into the CI, this is not provided as
 * a cmdline option, but affected tests are run twice, with and without
 * pkey option.
 */
CK_BBOOL pkey = CK_FALSE;
CK_BBOOL combined_extract = CK_FALSE;

CK_ULONG t_total = 0;           // total test assertions
CK_ULONG t_ran = 0;             // number of assertions ran
CK_ULONG t_passed = 0;          // number of assertions passed
CK_ULONG t_failed = 0;          // number of assertions failed
CK_ULONG t_skipped = 0;         // number of assertions skipped
CK_ULONG t_errors = 0;          // number of errors

#define MAX_MODEL 4

#define DES_KEY_SIZE 8
#define DES3_KEY_SIZE 24

static void *pkcs11lib = NULL;

static void unload_pkcslib(void)
{
    if (pkcs11lib != NULL) {
         dlclose(pkcs11lib);
    }
}

static void free_ifs(void)
{
    free(ifs);
    ifs = NULL;
}

int mech_supported(CK_SLOT_ID slot_id, CK_ULONG mechanism)
{
    CK_MECHANISM_INFO mech_info;
    int rc;
    rc = funcs->C_GetMechanismInfo(slot_id, mechanism, &mech_info);

    return (rc == CKR_OK);
}

int mech_supported_flags(CK_SLOT_ID slot_id, CK_ULONG mechanism, CK_FLAGS flags)
{
    CK_MECHANISM_INFO mech_info;
    int rc;

    rc = funcs->C_GetMechanismInfo(slot_id, mechanism, &mech_info);
    if (rc != CKR_OK)
        return FALSE;

    if (mech_info.flags & flags)
        return TRUE;

    return FALSE;
}

/*
 * Check if the specified key size is in the supported range of the mechanism.
 *
 * ATTENTION: It is mechanism dependent if the key size is in bits or bytes.
 * The caller of this function must take care that the keylen parameter is
 * specified in the appropriate unit.
 */
int check_supp_keysize(CK_SLOT_ID slot_id, CK_ULONG mechanism, CK_ULONG keylen)
{
    CK_MECHANISM_INFO mech_info;
    int rc;
    rc = funcs->C_GetMechanismInfo(slot_id, mechanism, &mech_info);
    if (rc != CKR_OK)
        return FALSE;

    /* min and max being zero indicate no key size limitation */
    if (mech_info.ulMinKeySize == 0 && mech_info.ulMaxKeySize == 0)
        return TRUE;

    return ((mech_info.ulMinKeySize <= keylen)
            && (keylen <= mech_info.ulMaxKeySize));
}

/** Returns true if and only if slot supports
    key wrapping with specified mechanism **/
int wrap_supported(CK_SLOT_ID slot_id, CK_MECHANISM mech)
{
    CK_MECHANISM_INFO mech_info;
    CK_RV rc;
    // get mech info
    rc = funcs->C_GetMechanismInfo(slot_id, mech.mechanism, &mech_info);
    if (rc != CKR_OK) {
        testcase_error("C_GetMechanismInfo(), rc=%s.", p11_get_ckr(rc));
        return -1;
    }
    rc = mech_info.flags & CKF_WRAP;

    return rc;
}

/** Returns true if and only if slot supports
    key unwrapping with specified mechanism **/
int unwrap_supported(CK_SLOT_ID slot_id, CK_MECHANISM mech)
{
    CK_MECHANISM_INFO mech_info;
    CK_RV rc;
    // get mech info
    rc = funcs->C_GetMechanismInfo(slot_id, mech.mechanism, &mech_info);
    if (rc != CKR_OK) {
        testcase_error("C_GetMechanismInfo(), rc=%s.", p11_get_ckr(rc));
        return -1;
    }
    rc = mech_info.flags & CKF_UNWRAP;

    return rc;
}

/**
 * Check if the last CKR_FUNCTION__FAILED error was due to policy restrictions
 */
int is_rejected_by_policy(CK_RV ret_code, CK_SESSION_HANDLE session)
{
    CK_SESSION_INFO info;
    CK_RV rc;

    if (ret_code != CKR_FUNCTION_FAILED)
        return 0;

    rc = funcs->C_GetSessionInfo(session, &info);
    if (rc != CKR_OK) {
        testcase_error("C_GetSessionInfo(), rc=%s.", p11_get_ckr(rc));
        return 0;
    }

    return (info.ulDeviceError == CKR_POLICY_VIOLATION);
}

/** Create an AES key handle with given value **/
CK_RV create_AESKey(CK_SESSION_HANDLE session, CK_BBOOL extractable,
                    unsigned char key[], unsigned char key_len,
                    CK_KEY_TYPE keyType, CK_OBJECT_HANDLE * h_key)
{
    CK_RV rc;
    CK_BBOOL true = TRUE;
    CK_BBOOL false = FALSE;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_BBOOL pkeyextractable = !extractable;
    CK_ATTRIBUTE keyTemplate[] = {
        {CKA_EXTRACTABLE, &extractable, sizeof(CK_BBOOL)},
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_TOKEN, &false, sizeof(false)},
        {CKA_VALUE, key, key_len},
        {CKA_IBM_PROTKEY_EXTRACTABLE, &pkeyextractable, sizeof(CK_BBOOL)},
    };
    CK_ULONG keyTemplate_len = sizeof(keyTemplate) / sizeof(CK_ATTRIBUTE);

    if (combined_extract)
        pkeyextractable = CK_TRUE;

    rc = funcs->C_CreateObject(session, keyTemplate, keyTemplate_len, h_key);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, session))
            rc = CKR_POLICY_VIOLATION;
        else
            testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

/** Generate an AES key handle **/
CK_RV generate_AESKey(CK_SESSION_HANDLE session,
                      CK_ULONG key_len, CK_BBOOL extractable,
                      CK_MECHANISM * mechkey, CK_OBJECT_HANDLE * h_key)
{
    CK_BBOOL pkeyextractable = !extractable;
    CK_ATTRIBUTE key_gen_tmpl[] = {
        {CKA_EXTRACTABLE, &extractable, sizeof(CK_BBOOL)},
        {CKA_VALUE_LEN, &key_len, sizeof(CK_ULONG)},
        {CKA_IBM_PROTKEY_EXTRACTABLE, &pkeyextractable, sizeof(CK_BBOOL)},
    };
    CK_ULONG key_gen_tmpl_len = sizeof(key_gen_tmpl) / sizeof(CK_ATTRIBUTE);

    if (combined_extract)
        pkeyextractable = CK_TRUE;

    CK_RV rc = funcs->C_GenerateKey(session, mechkey,
                                    key_gen_tmpl, key_gen_tmpl_len,
                                    h_key);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, session))
            rc = CKR_POLICY_VIOLATION;
        else
            testcase_error("C_GenerateKey rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

/** Create a DES key handle with given value **/
CK_RV create_DESKey(CK_SESSION_HANDLE session,
                    unsigned char key[], unsigned char klen,
                    CK_OBJECT_HANDLE * h_key)
{
    CK_RV rc;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_DES;
    CK_BYTE value[DES_KEY_SIZE];
    CK_BBOOL true = TRUE;
    CK_BBOOL false = FALSE;

    CK_ATTRIBUTE keyTemplate[] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_TOKEN, &false, sizeof(false)},
        {CKA_VALUE, value, klen}
    };

    memset(value, 0, sizeof(value));
    memcpy(value, key, klen);
    rc = funcs->C_CreateObject(session, keyTemplate, 5, h_key);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, session))
            rc = CKR_POLICY_VIOLATION;
        else
            testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

/** Create DES2 key handle with given value **/
CK_RV create_DES2Key(CK_SESSION_HANDLE session,
                     unsigned char key[], unsigned char klen,
                     CK_OBJECT_HANDLE * h_key)
{
    CK_RV rc;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_DES2;
    CK_BYTE value[2 * DES_KEY_SIZE];
    CK_BBOOL true = TRUE;
    CK_BBOOL false = FALSE;
    CK_ATTRIBUTE keyTemplate[] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_TOKEN, &false, sizeof(false)},
        {CKA_VALUE, value, klen}
    };

    memset(value, 0, sizeof(value));
    memcpy(value, key, klen);
    rc = funcs->C_CreateObject(session, keyTemplate, 5, h_key);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, session))
            rc = CKR_POLICY_VIOLATION;
        else
            testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

/** Create DES3 key handle with given value **/
CK_RV create_DES3Key(CK_SESSION_HANDLE session,
                     unsigned char key[], unsigned char klen,
                     CK_OBJECT_HANDLE * h_key)
{
    CK_RV rc;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_DES3;
    CK_BYTE value[DES3_KEY_SIZE];
    CK_BBOOL true = TRUE;
    CK_BBOOL false = FALSE;
    CK_ATTRIBUTE keyTemplate[] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_TOKEN, &false, sizeof(false)},
        {CKA_VALUE, value, klen}
    };

    memset(value, 0, sizeof(value));
    memcpy(value, key, klen);
    rc = funcs->C_CreateObject(session, keyTemplate, 5, h_key);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, session))
            rc = CKR_POLICY_VIOLATION;
        else
            testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

/** Create Generic Secret key handle with given value **/
CK_RV create_GenericSecretKey(CK_SESSION_HANDLE session,
                            CK_BYTE key[],
                            CK_ULONG key_len, CK_OBJECT_HANDLE * h_key)
{
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
    CK_BBOOL false = FALSE;
    CK_RV rc;
    CK_ATTRIBUTE key_attribs[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_TOKEN, &false, sizeof(false)},
        {CKA_VALUE, key, key_len}
    };

    rc = funcs->C_CreateObject(session, key_attribs, 4, h_key);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, session))
            rc = CKR_POLICY_VIOLATION;
        else
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
                           CK_OBJECT_HANDLE * priv_key)
{

    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_UTF8CHAR label[] = "An RSA private key object";
    CK_BYTE subject[] = {0};
    CK_BYTE id[] = { 123 };
    CK_RV rc;

    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, label, sizeof(label) - 1},
        {CKA_SUBJECT, subject, 0},
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
        if (is_rejected_by_policy(rc, session))
            rc = CKR_POLICY_VIOLATION;
        else
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
                          CK_OBJECT_HANDLE * publ_key)
{

    CK_RV rc;
    CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_UTF8CHAR label[] = "An RSA public key object";
    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, label, sizeof(label) - 1},
        {CKA_WRAP, &true, sizeof(true)},
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_MODULUS, modulus, modulus_len},
        {CKA_PUBLIC_EXPONENT, publicExponent, publicExponent_len}
    };

    // create key
    rc = funcs->C_CreateObject(session, template, 8, publ_key);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, session))
            rc = CKR_POLICY_VIOLATION;
        else
            testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

/** Generate an RSA (PKCS) key pair **/
CK_RV generate_RSA_PKCS_KeyPair(CK_SESSION_HANDLE session,
                                CK_ULONG modulusBits,
                                CK_BYTE publicExponent[],
                                CK_ULONG publicExponent_len,
                                CK_OBJECT_HANDLE * publ_key,
                                CK_OBJECT_HANDLE * priv_key)
{
    CK_RV rc;
    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_BYTE subject[] = {0};
    CK_BYTE id[] = { 123 };
    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE publicKeyTemplate[] = {
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_WRAP, &true, sizeof(true)},
        {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
        {CKA_PUBLIC_EXPONENT, publicExponent, publicExponent_len}
    };
    CK_ATTRIBUTE privateKeyTemplate[] = {
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_SUBJECT, subject, 0},
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
                                  5, privateKeyTemplate, 8, publ_key, priv_key);

    if (is_rejected_by_policy(rc, session))
        rc = CKR_POLICY_VIOLATION;

    return rc;
    // no error checking due to
    // ICA Token + public exponent values + CKR_TEMPLATE_INCONSISTENT
    // work around
    // see rsa_func.c
}

struct rsa_key_cache_entry {
    CK_SESSION_HANDLE session;
    CK_ULONG modulusBits;
    CK_BYTE *publicExponent;
    CK_ULONG publicExponent_len;
    CK_OBJECT_HANDLE publ_key;
    CK_OBJECT_HANDLE priv_key;
};

struct rsa_key_cache_entry *rsa_key_cache = NULL;
CK_ULONG rsa_key_cache_size = 0;

CK_RV generate_RSA_PKCS_KeyPair_cached(CK_SESSION_HANDLE session,
                                       CK_ULONG modulusBits,
                                       CK_BYTE publicExponent[],
                                       CK_ULONG publicExponent_len,
                                       CK_OBJECT_HANDLE *publ_key,
                                       CK_OBJECT_HANDLE *priv_key)
{
    struct rsa_key_cache_entry *tmp, *free = NULL;
    CK_ULONG i;
    CK_RV rc;

    for (i = 0; i < rsa_key_cache_size; i++) {
        if (rsa_key_cache[i].session == session &&
            rsa_key_cache[i].modulusBits == modulusBits &&
            rsa_key_cache[i].publicExponent_len == publicExponent_len &&
            memcmp(rsa_key_cache[i].publicExponent, publicExponent,
                   publicExponent_len) == 0) {
            *publ_key = rsa_key_cache[i].publ_key;
            *priv_key = rsa_key_cache[i].priv_key;

            return CKR_OK;
        }

        if (rsa_key_cache[i].session == CK_INVALID_HANDLE && free == NULL)
            free = &rsa_key_cache[i];
    }

    rc = generate_RSA_PKCS_KeyPair(session, modulusBits, publicExponent,
                                   publicExponent_len, publ_key, priv_key);
    if (rc != CKR_OK)
        return rc;

    if (free == NULL) {
        tmp = realloc(rsa_key_cache, (rsa_key_cache_size + 1) *
                                            sizeof(struct rsa_key_cache_entry));
        if (tmp == NULL) {
            testcase_error("realloc failed to enlarge the RSA key cache");
            return CKR_HOST_MEMORY;
        }

        free = &tmp[rsa_key_cache_size];
        memset(free, 0, sizeof(*free));

        rsa_key_cache = tmp;
        rsa_key_cache_size++;
    }

    free->session = session;
    free->modulusBits = modulusBits;
    free->publicExponent_len = publicExponent_len;
    free->publicExponent = malloc(publicExponent_len);
    if (free->publicExponent == NULL) {
        testcase_error("failed to allocate the public exponent cache entry");
        return CKR_HOST_MEMORY;
    }
    memcpy(free->publicExponent, publicExponent, publicExponent_len);
    free->publ_key = *publ_key;
    free->priv_key = *priv_key;

    return CKR_OK;
}

void free_rsa_key_cache(CK_SESSION_HANDLE session)
{
    CK_ULONG i;

    for (i = 0; i < rsa_key_cache_size; i++) {
        if (rsa_key_cache[i].session == CK_INVALID_HANDLE)
            continue;
        if (session != CK_INVALID_HANDLE && rsa_key_cache[i].session != session)
            continue;

        funcs->C_DestroyObject(rsa_key_cache[i].session,
                               rsa_key_cache[i].publ_key);
        funcs->C_DestroyObject(rsa_key_cache[i].session,
                               rsa_key_cache[i].priv_key);
        free(rsa_key_cache[i].publicExponent);

        /* mark as free */
        memset(&rsa_key_cache[i], 0, sizeof(rsa_key_cache[i]));
    }

    if (session == CK_INVALID_HANDLE) {
        free(rsa_key_cache);
        rsa_key_cache = NULL;
        rsa_key_cache_size = 0;
    }
}

/** Generate an EC key pair **/
CK_RV generate_EC_KeyPair(CK_SESSION_HANDLE session,
                          CK_BYTE* ec_params, CK_ULONG ec_params_len,
                          CK_OBJECT_HANDLE * publ_key,
                          CK_OBJECT_HANDLE * priv_key,
                          CK_BBOOL extractable)
{
    CK_RV rc;
    CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_BBOOL pkeyextractable = !extractable;
    CK_BYTE subject[] = {0};
    CK_BYTE id[] = { 123 };
    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE publicKeyTemplate[] = {
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_EC_PARAMS, ec_params, ec_params_len},
    };
    CK_ATTRIBUTE privateKeyTemplate[] = {
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_SUBJECT, subject, 0},
        {CKA_ID, id, sizeof(id)},
        {CKA_SENSITIVE, &true, sizeof(true)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_DERIVE, &true, sizeof(true)},
        {CKA_EXTRACTABLE, &extractable, sizeof(CK_BBOOL)},
        {CKA_IBM_PROTKEY_EXTRACTABLE, &pkeyextractable, sizeof(CK_BBOOL)},
    };
    CK_ULONG num_publ_attrs = sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE);
    CK_ULONG num_priv_attrs = sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE);

    if (combined_extract)
        pkeyextractable = CK_TRUE;

    // generate keys
    rc = funcs->C_GenerateKeyPair(session,
                                  &mech,
                                  publicKeyTemplate, num_publ_attrs,
                                  privateKeyTemplate, num_priv_attrs,
                                  publ_key, priv_key);

    if (is_rejected_by_policy(rc, session))
        rc = CKR_POLICY_VIOLATION;

    return rc;
}

/** Create an EC private key using private value 'd'
    and ec parameter values (alg id of curve) **/
CK_RV create_ECPrivateKey(CK_SESSION_HANDLE session,
                          CK_BYTE params[],
                          CK_ULONG params_len,
                          CK_BYTE privatekey[],
                          CK_ULONG privatekey_len,
                          CK_OBJECT_HANDLE * priv_key,
                          CK_BBOOL extractable)
{

    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
    CK_BBOOL pkeyextractable = !extractable;
    CK_KEY_TYPE keyType = CKK_EC;
    CK_UTF8CHAR label[] = "An EC private key object";
    CK_BYTE subject[] = {0};
    CK_BYTE id[] = { 123 };
    CK_RV rc;

    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_LABEL, label, sizeof(label)},
        {CKA_SUBJECT, subject, 0},
        {CKA_ID, id, sizeof(id)},
        {CKA_SENSITIVE, &true, sizeof(true)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_DERIVE, &true, sizeof(true)},
        {CKA_EC_PARAMS, params, params_len},
        {CKA_VALUE, privatekey, privatekey_len},
        {CKA_EXTRACTABLE, &extractable, sizeof(CK_BBOOL)},
        {CKA_IBM_PROTKEY_EXTRACTABLE, &pkeyextractable, sizeof(CK_BBOOL)},
    };

    if (combined_extract)
        pkeyextractable = CK_TRUE;

    // create key
    rc = funcs->C_CreateObject(session, template,
                               sizeof(template) / sizeof(CK_ATTRIBUTE),
                               priv_key);

    if (is_rejected_by_policy(rc, session))
        rc = CKR_POLICY_VIOLATION;

    return rc;
}

/** Create an EC public key using  ec params and point 'Q' **/
CK_RV create_ECPublicKey(CK_SESSION_HANDLE session,
                         CK_BYTE params[],
                         CK_ULONG params_len,
                         CK_BYTE pointq[],
                         CK_ULONG pointq_len, CK_OBJECT_HANDLE * publ_key)
{
    CK_RV rc;
    CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_EC;
    CK_UTF8CHAR label[] = "An EC public key object";
    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, label, sizeof(label)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_DERIVE, &true, sizeof(true)},
        {CKA_EC_PARAMS, params, params_len},
        {CKA_EC_POINT, pointq, pointq_len}
    };

    // create key
    rc = funcs->C_CreateObject(session, template,
                               sizeof(template) / sizeof(CK_ATTRIBUTE),
                               publ_key);

    if (is_rejected_by_policy(rc, session))
        rc = CKR_POLICY_VIOLATION;

    return rc;
}

/** Create an IBM Dilithium private key using private values **/
CK_RV create_DilithiumPrivateKey(CK_SESSION_HANDLE session,
                                 CK_BYTE pkcs8[], CK_ULONG pkcs8_len,
                                 CK_ULONG keyform,
                                 CK_BYTE rho[], CK_ULONG rho_len,
                                 CK_BYTE seed[], CK_ULONG seed_len,
                                 CK_BYTE tr[], CK_ULONG tr_len,
                                 CK_BYTE s1[], CK_ULONG s1_len,
                                 CK_BYTE s2[], CK_ULONG s2_len,
                                 CK_BYTE t0[], CK_ULONG t0_len,
                                 CK_BYTE t1[], CK_ULONG t1_len,
                                 CK_OBJECT_HANDLE * priv_key)
{
    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_IBM_PQC_DILITHIUM;
    CK_UTF8CHAR label[] = "A Dilithium private key object";
    CK_BYTE subject[] = {0};
    CK_BYTE id[] = { 123 };
    CK_RV rc;

    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_LABEL, label, sizeof(label)},
        {CKA_SUBJECT, subject, 0},
        {CKA_ID, id, sizeof(id)},
        {CKA_SENSITIVE, &true, sizeof(true)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_IBM_DILITHIUM_RHO, rho, rho_len},
        {CKA_IBM_DILITHIUM_SEED, seed, seed_len},
        {CKA_IBM_DILITHIUM_TR, tr, tr_len},
        {CKA_IBM_DILITHIUM_S1, s1, s1_len},
        {CKA_IBM_DILITHIUM_S2, s2, s2_len},
        {CKA_IBM_DILITHIUM_T0, t0, t0_len},
        {CKA_IBM_DILITHIUM_T1, t1, t1_len},
        {CKA_IBM_DILITHIUM_KEYFORM, &keyform, sizeof(keyform)},
    };
    CK_ATTRIBUTE template_pkcs8[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_LABEL, label, sizeof(label)},
        {CKA_SUBJECT, subject, 0},
        {CKA_ID, id, sizeof(id)},
        {CKA_SENSITIVE, &true, sizeof(true)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_VALUE, pkcs8, pkcs8_len},
    };

    // create key
    if (pkcs8_len > 0)
        rc = funcs->C_CreateObject(session, template_pkcs8,
                                   sizeof(template_pkcs8) / sizeof(CK_ATTRIBUTE),
                                   priv_key);
    else
        rc = funcs->C_CreateObject(session, template,
                                   sizeof(template) / sizeof(CK_ATTRIBUTE),
                                   priv_key);
    if (rc != CKR_OK) {
        if (rc == CKR_KEY_SIZE_RANGE)
            testcase_notice("C_CreateObject rc=%s", p11_get_ckr(rc));
        else if (is_rejected_by_policy(rc, session))
            rc = CKR_POLICY_VIOLATION;
        else
            testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

/** Create an IBM Dilithium public key using  (rho, t1) **/
CK_RV create_DilithiumPublicKey(CK_SESSION_HANDLE session,
                                CK_BYTE spki[], CK_ULONG spki_len,
                                CK_ULONG keyform,
                                CK_BYTE rho[], CK_ULONG rho_len,
                                CK_BYTE t1[], CK_ULONG t1_len,
                                CK_OBJECT_HANDLE * publ_key)
{
    CK_RV rc;
    CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_IBM_PQC_DILITHIUM;
    CK_UTF8CHAR label[] = "A Dilithium public key object";
    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, label, sizeof(label)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_IBM_DILITHIUM_RHO, rho, rho_len},
        {CKA_IBM_DILITHIUM_T1, t1, t1_len},
        {CKA_IBM_DILITHIUM_KEYFORM, &keyform, sizeof(keyform)},
    };
    CK_ATTRIBUTE template_spki[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, label, sizeof(label)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_VALUE, spki, spki_len},
    };

    // create key
    if (spki_len > 0)
        rc = funcs->C_CreateObject(session, template_spki,
                               sizeof(template_spki) / sizeof(CK_ATTRIBUTE),
                               publ_key);
    else
        rc = funcs->C_CreateObject(session, template,
                               sizeof(template) / sizeof(CK_ATTRIBUTE),
                               publ_key);
    if (rc != CKR_OK) {
        if (rc == CKR_KEY_SIZE_RANGE)
            testcase_notice("C_CreateObject rc=%s", p11_get_ckr(rc));
        else if (is_rejected_by_policy(rc, session))
            rc = CKR_POLICY_VIOLATION;
        else
            testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

/** Create an IBM Kyber private key using private values **/
CK_RV create_KyberPrivateKey(CK_SESSION_HANDLE session,
                             CK_BYTE pkcs8[], CK_ULONG pkcs8_len,
                             CK_ULONG keyform,
                             CK_BYTE sk[], CK_ULONG sk_len,
                             CK_BYTE pk[], CK_ULONG pk_len,
                             CK_OBJECT_HANDLE * priv_key)
{
    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_IBM_PQC_KYBER;
    CK_UTF8CHAR label[] = "A Kyber private key object";
    CK_BYTE subject[] = {0};
    CK_BYTE id[] = { 123 };
    CK_RV rc;

    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_LABEL, label, sizeof(label)},
        {CKA_SUBJECT, subject, 0},
        {CKA_ID, id, sizeof(id)},
        {CKA_SENSITIVE, &true, sizeof(true)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_DERIVE, &true, sizeof(true)},
        {CKA_IBM_KYBER_SK, sk, sk_len},
        {CKA_IBM_KYBER_PK, pk, pk_len},
        {CKA_IBM_KYBER_KEYFORM, &keyform, sizeof(keyform)},
    };
    CK_ATTRIBUTE template_pkcs8[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_LABEL, label, sizeof(label)},
        {CKA_SUBJECT, subject, 0},
        {CKA_ID, id, sizeof(id)},
        {CKA_SENSITIVE, &true, sizeof(true)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_DERIVE, &true, sizeof(true)},
        {CKA_VALUE, pkcs8, pkcs8_len},
    };

    // create key
    if (pkcs8_len > 0)
        rc = funcs->C_CreateObject(session, template_pkcs8,
                                   sizeof(template_pkcs8) / sizeof(CK_ATTRIBUTE),
                                   priv_key);
    else
        rc = funcs->C_CreateObject(session, template,
                                   sizeof(template) / sizeof(CK_ATTRIBUTE),
                                   priv_key);
    if (rc != CKR_OK) {
        if (rc == CKR_KEY_SIZE_RANGE)
            testcase_notice("C_CreateObject rc=%s", p11_get_ckr(rc));
        else if (is_rejected_by_policy(rc, session))
            rc = CKR_POLICY_VIOLATION;
        else
            testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

/** Create an IBM Kyber public key using public values **/
CK_RV create_KyberPublicKey(CK_SESSION_HANDLE session,
                            CK_BYTE spki[], CK_ULONG spki_len,
                            CK_ULONG keyform,
                            CK_BYTE pk[], CK_ULONG pk_len,
                            CK_OBJECT_HANDLE * publ_key)
{
    CK_RV rc;
    CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_IBM_PQC_KYBER;
    CK_UTF8CHAR label[] = "A Kyber public key object";
    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, label, sizeof(label)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_DERIVE, &true, sizeof(true)},
        {CKA_IBM_KYBER_PK, pk, pk_len},
        {CKA_IBM_KYBER_KEYFORM, &keyform, sizeof(keyform)},
    };
    CK_ATTRIBUTE template_spki[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, label, sizeof(label)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_DERIVE, &true, sizeof(true)},
        {CKA_VALUE, spki, spki_len},
    };

    // create key
    if (spki_len > 0)
        rc = funcs->C_CreateObject(session, template_spki,
                               sizeof(template_spki) / sizeof(CK_ATTRIBUTE),
                               publ_key);
    else
        rc = funcs->C_CreateObject(session, template,
                               sizeof(template) / sizeof(CK_ATTRIBUTE),
                               publ_key);
    if (rc != CKR_OK) {
        if (rc == CKR_KEY_SIZE_RANGE)
            testcase_notice("C_CreateObject rc=%s", p11_get_ckr(rc));
        else if (is_rejected_by_policy(rc, session))
            rc = CKR_POLICY_VIOLATION;
        else
            testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

/** Create an DSA public key using the prime 'p', subprime 'q', base 'g' and private value 'y' **/
CK_RV create_DSAPrivateKey(CK_SESSION_HANDLE session,
                           CK_BYTE prime[],
                           CK_ULONG prime_len,
                           CK_BYTE subprime[],
                           CK_ULONG subprime_len,
                           CK_BYTE base[],
                           CK_ULONG base_len,
                           CK_BYTE privatekey[],
                           CK_ULONG privatekey_len, CK_OBJECT_HANDLE * priv_key)
{

    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_DSA;
    CK_UTF8CHAR label[] = "An DSA private key object";
    CK_BYTE subject[] = {0};
    CK_BYTE id[] = { 123 };
    CK_RV rc;

    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, label, sizeof(label)},
        {CKA_SUBJECT, subject, 0},
        {CKA_ID, id, sizeof(id)},
        {CKA_SENSITIVE, &true, sizeof(true)},
        {CKA_DECRYPT, &true, sizeof(true)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_PRIME, prime, prime_len},
        {CKA_SUBPRIME, subprime, subprime_len},
        {CKA_BASE, base, base_len},
        {CKA_VALUE, privatekey, privatekey_len}
    };

    // create key
    rc = funcs->C_CreateObject(session, template,
                               sizeof(template) / sizeof(CK_ATTRIBUTE),
                               priv_key);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, session))
            rc = CKR_POLICY_VIOLATION;
        else
            testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

/** Create an DSA public key using the prime 'p', subprime 'q', base 'g' and public value 'x' **/
CK_RV create_DSAPublicKey(CK_SESSION_HANDLE session,
                          CK_BYTE prime[],
                          CK_ULONG prime_len,
                          CK_BYTE subprime[],
                          CK_ULONG subprime_len,
                          CK_BYTE base[],
                          CK_ULONG base_len,
                          CK_BYTE publickey[],
                          CK_ULONG publickey_len, CK_OBJECT_HANDLE * publ_key)
{
    CK_RV rc;
    CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_DSA;
    CK_UTF8CHAR label[] = "An DSA public key object";
    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, label, sizeof(label)},
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_PRIME, prime, prime_len},
        {CKA_SUBPRIME, subprime, subprime_len},
        {CKA_BASE, base, base_len},
        {CKA_VALUE, publickey, publickey_len}
    };

    // create key
    rc = funcs->C_CreateObject(session, template,
                               sizeof(template) / sizeof(CK_ATTRIBUTE),
                               publ_key);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, session))
            rc = CKR_POLICY_VIOLATION;
        else
            testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

/** Create an DH public key using the prime 'p', base 'g' and private value 'y' **/
CK_RV create_DHPrivateKey(CK_SESSION_HANDLE session,
                          CK_BYTE prime[],
                          CK_ULONG prime_len,
                          CK_BYTE base[],
                          CK_ULONG base_len,
                          CK_BYTE privatekey[],
                          CK_ULONG privatekey_len, CK_OBJECT_HANDLE * priv_key)
{

    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_DH;
    CK_UTF8CHAR label[] = "An DH private key object";
    CK_BYTE subject[] = {0};
    CK_BYTE id[] = { 123 };
    CK_RV rc;

    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, label, sizeof(label)},
        {CKA_SUBJECT, subject, 0},
        {CKA_ID, id, sizeof(id)},
        {CKA_SENSITIVE, &true, sizeof(true)},
        {CKA_DECRYPT, &true, sizeof(true)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_DERIVE, &true, sizeof(true)},
        {CKA_PRIME, prime, prime_len},
        {CKA_BASE, base, base_len},
        {CKA_VALUE, privatekey, privatekey_len}
    };

    // create key
    rc = funcs->C_CreateObject(session, template,
                               sizeof(template) / sizeof(CK_ATTRIBUTE),
                               priv_key);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, session))
            rc = CKR_POLICY_VIOLATION;
        else
            testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

/* Create an DH public key using the prime 'p', base 'g' and public value 'x' */
CK_RV create_DHPublicKey(CK_SESSION_HANDLE session,
                         CK_BYTE prime[],
                         CK_ULONG prime_len,
                         CK_BYTE base[],
                         CK_ULONG base_len,
                         CK_BYTE publickey[],
                         CK_ULONG publickey_len, CK_OBJECT_HANDLE * publ_key)
{
    CK_RV rc;
    CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_DH;
    CK_UTF8CHAR label[] = "An DH public key object";
    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, label, sizeof(label)},
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_PRIME, prime, prime_len},
        {CKA_BASE, base, base_len},
        {CKA_VALUE, publickey, publickey_len}
    };

    // create key
    rc = funcs->C_CreateObject(session, template,
                               sizeof(template) / sizeof(CK_ATTRIBUTE),
                               publ_key);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, session))
            rc = CKR_POLICY_VIOLATION;
        else
            testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

/* Generate a secret key */
CK_RV generate_SecretKey(CK_SESSION_HANDLE session,
                         CK_ULONG keylen,
                         CK_MECHANISM * mech, CK_OBJECT_HANDLE * secret_key)
{
    CK_RV rc;
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_ATTRIBUTE secret_tmpl[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_VALUE_LEN, &keylen, sizeof(keylen)}
    };

    rc = funcs->C_GenerateKey(session, mech, secret_tmpl, 2, secret_key);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, session))
            rc = CKR_POLICY_VIOLATION;
        else
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
    CK_ULONG i;

    /* everything > 0x10 valid */
    if (pubexp[0] > 0x10) {
        return 1;
    } else {
        for (i = 1; i < pubexp_len + 1; i++) {
            if (pubexp[i] != 0)
                return 1;
        }
    }

    return 0;
}

/** Returns true if slot_id is an EP11 Token **/
int is_ep11_token(CK_SLOT_ID slot_id)
{
    CK_RV rc;
    CK_TOKEN_INFO tokinfo;

    rc = funcs->C_GetTokenInfo(slot_id, &tokinfo);
    if (rc != CKR_OK)
        return FALSE;

    return strstr((const char *) tokinfo.model, "EP11") != NULL;
}

/** Returns true if pubexp is valid for CCA Tokens **/
int is_valid_cca_pubexp(CK_BYTE pubexp[], CK_ULONG pubexp_len)
{
    CK_BYTE exp3[] = { 0x03 };  // 3
    CK_BYTE exp65537[] = { 0x01, 0x00, 0x01 };  // 65537

    return (pubexp_len == 1 && (!memcmp(pubexp, exp3, 1)))
        || (pubexp_len == 3 && (!memcmp(pubexp, exp65537, 3)));
}

/** Returns true if pubexp is valid for Soft Tokens **/
int is_valid_soft_pubexp(CK_BYTE pubexp[], CK_ULONG pubexp_len)
{
    UNUSED(pubexp);
    UNUSED(pubexp_len);

    return TRUE;
}

/** Returns true if slot_id is an ICSF token
 ** ICSF token info is not necessarily hard-coded like the other tokens
 ** so there is no single identifying attribute. So, instead just
 ** use logical deduction....
 **/
int is_icsf_token(CK_SLOT_ID slot_id)
{
    CK_RV rc;
    CK_TOKEN_INFO tokinfo;

    rc = funcs->C_GetTokenInfo(slot_id, &tokinfo);
    if (rc != CKR_OK)
        return FALSE;

    if ((strstr((const char *) tokinfo.model, "ICA") == NULL) &&
        (strstr((const char *) tokinfo.model, "EP11") == NULL) &&
        (strstr((const char *) tokinfo.model, "CCA") == NULL) &&
        (strstr((const char *) tokinfo.model, "Soft") == NULL) &&
        (strstr((const char *) tokinfo.model, "TPM") == NULL))
        return TRUE;

    return FALSE;
}

/** Returns true if pubexp is valid for ICSF token **/
int is_valid_icsf_pubexp(CK_BYTE pubexp[], CK_ULONG pubexp_len)
{
    CK_BYTE exp65537[] = { 0x01, 0x00, 0x01 };  // 65537

    return (pubexp_len == 3 && (!memcmp(pubexp, exp65537, 3)));
}

/** Returns true if slot_id is an ICA Token **/
int is_ica_token(CK_SLOT_ID slot_id)
{
    CK_RV rc;
    CK_TOKEN_INFO tokinfo;

    rc = funcs->C_GetTokenInfo(slot_id, &tokinfo);
    if (rc != CKR_OK)
        return FALSE;

    return strstr((const char *) tokinfo.model, "ICA") != NULL;
}

/** Returns true if slot_id is a CCA Token **/
int is_cca_token(CK_SLOT_ID slot_id)
{
    CK_RV rc;
    CK_TOKEN_INFO tokinfo;

    rc = funcs->C_GetTokenInfo(slot_id, &tokinfo);
    if (rc != CKR_OK)
        return FALSE;

    return strstr((const char *) tokinfo.model, "CCA") != NULL;
}

/** Returns true if slot_id is a Soft Token **/
int is_soft_token(CK_SLOT_ID slot_id)
{
    CK_RV rc;
    CK_TOKEN_INFO tokinfo;

    rc = funcs->C_GetTokenInfo(slot_id, &tokinfo);
    if (rc != CKR_OK)
        return FALSE;

    return strstr((const char *) tokinfo.model, "Soft") != NULL;
}

/** Returns true if slot_id is a TPM Token **/
int is_tpm_token(CK_SLOT_ID slot_id)
{
    CK_RV rc;
    CK_TOKEN_INFO tokinfo;

    rc = funcs->C_GetTokenInfo(slot_id, &tokinfo);
    if (rc != CKR_OK)
        return FALSE;

    return strstr((const char *) tokinfo.model, "TPM") != NULL;
}

/** Returns true if pubexp is valid for CCA Tokens **/
int is_valid_tpm_pubexp(CK_BYTE pubexp[], CK_ULONG pubexp_len)
{
    CK_BYTE exp65537[] = { 0x01, 0x00, 0x01 };  // 65537

    return (pubexp_len == 3 && (!memcmp(pubexp, exp65537, 3)));
}

int is_valid_tpm_modbits(CK_ULONG modbits)
{
    switch (modbits) {
    case 512:
    case 1024:
    case 2048:
        return 1;
    default:
        return 0;
    }
}

int get_so_pin(CK_BYTE * dest)
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
                PKCS11_SO_PIN_ENV_VAR, (int) PKCS11_MAX_PIN_LEN);
        return -1;
    }

    memcpy(dest, val, strlen(val) + 1);

    return 0;
}

int get_user_pin(CK_BYTE * dest)
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
                PKCS11_SO_PIN_ENV_VAR, (int) PKCS11_MAX_PIN_LEN);
        return -1;
    }

    memcpy(dest, val, strlen(val) + 1);

    return 0;
}



void process_time(SYSTEMTIME t1, SYSTEMTIME t2)
{
    long ms = (t2.tv_usec - t1.tv_usec) / 1000;
    long s = t2.tv_sec - t1.tv_sec;

    while (ms < 0) {
        ms += 1000;
        s--;
    }

    ms += (s * 1000);

    printf("Time:  %u msec\n", (unsigned int) ms);
}



//
//
void print_hex(CK_BYTE * buf, CK_ULONG len)
{
    CK_ULONG i, j;

    i = 0;

    while (i < len) {
        for (j = 0; (j < 16) && (i < len); j++, i++)
            fprintf(stderr, "%02x ", buf[i]);
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
}

void usage(char *fct)
{
    printf("usage:  %s [-securekey] [-noskip] [-noinit] [-h] -slot <num>\n\n",
           fct);

    return;
}


int do_ParseArgs(int argc, char **argv)
{
    int i;
    char *endp;

    skip_token_obj = TRUE;
    no_stop = FALSE;
    no_init = FALSE;
    securekey = FALSE;
    SLOT_ID = 1000;


    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-noskip") == 0) {
            skip_token_obj = FALSE;
        } else if (strcmp(argv[i], "-slot") == 0) {
            if (argc <= i + 1) {
                printf("No slot number specified\n");
                usage(argv[0]);
                return -1;
            }
            SLOT_ID = strtol(argv[i + 1], &endp, 10);
            if (*endp != '\0') {
                printf("Invalid slot number specified: %s\n", argv[i + 1]);
                usage(argv[0]);
                return -1;
            }
            i++;
        } else if (strcmp(argv[i], "-securekey") == 0) {
            securekey = TRUE;
        } else if (strcmp(argv[i], "-noinit") == 0) {
            no_init = TRUE;
        } else if (strcmp(argv[i], "-nostop") == 0) {
            no_stop = TRUE;
        } else if (strcmp(argv[i], "-combined-extract") == 0) {
            combined_extract = TRUE;
        } else {
            printf("Invalid argument passed as option: %s\n", argv[i]);
            usage(argv[0]);
            return -1;
        }
    }

    // error if slot has not been identified.
    if (SLOT_ID == 1000) {
        printf("Please specify the slot to be tested.\n");
        usage(argv[0]);
        return -1;
    }

    return 1;
}

//
//
CK_BBOOL do_GetFunctionList(void)
{
    CK_INTERFACE *interface;
    CK_VERSION version;
    CK_FLAGS flags;
    CK_BBOOL rv;
    CK_RV rc;
    CK_RV(*getfunclist)(CK_FUNCTION_LIST **funcs);
    CK_RV(*getinterfacelist)(CK_INTERFACE_PTR interfaces, CK_ULONG *count);
    CK_RV(*getinterface)(CK_UTF8CHAR_PTR name, CK_VERSION_PTR version,
                         CK_INTERFACE_PTR_PTR interface, CK_FLAGS flags);
    char *e;
    char *f = OCK_API_LIBNAME;
    CK_ULONG nmemb = 0;

    rv = FALSE;

    e = getenv("PKCSLIB");
    if (e == NULL)
        e = f;

    pkcs11lib = dlopen(e, DYNLIB_LDFLAGS);
    if (pkcs11lib == NULL)
        goto ret;

    *(void **)(&getfunclist) = dlsym(pkcs11lib, "C_GetFunctionList");
    if (getfunclist == NULL)
        goto ret;

    rc = getfunclist(&funcs);
    if (rc != CKR_OK) {
        testcase_error("C_GetFunctionList rc=%s", p11_get_ckr(rc));
        goto ret;
    }

    *(void **)(&getinterfacelist) = dlsym(pkcs11lib, "C_GetInterfaceList");
    if (getinterfacelist == NULL) {
        goto ret;
    }
    rc = getinterfacelist(NULL, &nmemb);
    if (rc != CKR_OK) {
        testcase_error("C_GetInterfaceList rc=%s", p11_get_ckr(rc));
        goto ret;
    }
    ifs = calloc(nmemb, sizeof(*ifs));
    if (ifs == NULL) {
        goto ret;
    }
    rc = getinterfacelist(ifs, &nmemb);
    if (rc != CKR_OK) {
        testcase_error("C_GetInterfaceList rc=%s", p11_get_ckr(rc));
        goto ret;
    }

    *(void **)(&getinterface) = dlsym(pkcs11lib, "C_GetInterface");
    if (getinterface == NULL) {
        goto ret;
    }
    version.major = 0x03;
    version.minor = 0x00;
    flags = CKF_INTERFACE_FORK_SAFE;
    rc = getinterface((CK_UTF8CHAR *)"PKCS 11", &version, &interface, flags);
    if (rc != CKR_OK) {
        testcase_error("C_GetInterface rc=%s", p11_get_ckr(rc));
        goto ret;
    }
    funcs3 = interface->pFunctionList;

    rv = TRUE;
ret:
    if (rv == TRUE) {
        atexit(free_ifs);
        atexit(unload_pkcslib);
    } else {
        free(ifs);
        ifs = NULL;

        if (pkcs11lib != NULL) {
            dlclose(pkcs11lib);
            pkcs11lib = NULL;
	}
    }
    return rv;
}
