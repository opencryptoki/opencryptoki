#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif
#include <limits.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>

#include "pkcs11types.h"
#include "ec_curves.h"

#define ARRAY_SIZE(A) (sizeof(A) / sizeof((A)[0]))

#define PKCS11_MAX_PIN_LEN 128
#define PKCS11_SO_PIN_ENV_VAR   "PKCS11_SO_PIN"
#define PKCS11_USER_PIN_ENV_VAR "PKCS11_USER_PIN"

#define POLICY_TEST_RSA_SIZE 4096
#define POLICY_TEST_EC_SIZE  384
#define POLICY_TEST_AES_SIZE 256

/* Tests implemented (Bit indices) */
#define TEST_RSA     1u
#define TEST_EC      2u
#define TEST_AESWRAP 3u
#define TEST_DIGEST  4u
#define TEST_DH      5u

static CK_FUNCTION_LIST *funcs;
static void *pkcs11lib;
static CK_SESSION_HANDLE session;

static const char rsamessage[POLICY_TEST_RSA_SIZE / 8 - 11] = {0};
static const char ecmessage[POLICY_TEST_EC_SIZE / 8] = {0};

static const CK_UTF8CHAR poltestlabel[] = "policytest key";
static const CK_UTF8CHAR poltestdhlabelA[] = "policytest key A";
static const CK_UTF8CHAR poltestdhlabelB[] = "policytest key B";

static CK_BBOOL tokenkeys = CK_FALSE;

static struct {
    CK_OBJECT_HANDLE rsapub;
    CK_OBJECT_HANDLE rsapriv;
    CK_OBJECT_HANDLE ecpub;
    CK_OBJECT_HANDLE ecpriv;
    CK_OBJECT_HANDLE aes;
    CK_OBJECT_HANDLE dhpubA;
    CK_OBJECT_HANDLE dhprivA;
    CK_OBJECT_HANDLE dhpubB;
    CK_OBJECT_HANDLE dhprivB;
} keys;

/* copied from testcases/crypto/dh_func.c */
CK_BYTE DH_PUBL_PRIME[128] = {
    0xd5, 0xb1, 0xaa, 0x6a, 0x3b, 0x85, 0x50, 0xf0, 0xe2,
    0xea, 0x6b, 0xec, 0x26, 0x3b, 0xe0, 0xbf, 0x7a, 0x82,
    0x45, 0x1b, 0xa8, 0x0a, 0x54, 0x2e, 0x14, 0x2c, 0xc2,
    0x58, 0xb1, 0xf5, 0x59, 0xec, 0x7d, 0x16, 0x9e, 0x00,
    0x62, 0xb3, 0xa7, 0xdc, 0x38, 0x6f, 0x64, 0x40, 0xfc,
    0x0d, 0x3e, 0x0b, 0x66, 0x13, 0x5e, 0xa5, 0x84, 0x90,
    0x26, 0x62, 0xcf, 0x5a, 0x14, 0x72, 0x2d, 0x1b, 0x37,
    0x7e, 0x8a, 0x4b, 0xc0, 0xb7, 0xf2, 0x63, 0xd1, 0xaa,
    0x51, 0x92, 0x96, 0x18, 0xae, 0xb9, 0xfd, 0x5f, 0x9d,
    0x5d, 0xdf, 0x75, 0xa9, 0x80, 0x3d, 0xaa, 0xc2, 0x54,
    0x00, 0xcc, 0xc1, 0x9e, 0x31, 0x4d, 0x22, 0x31, 0x44,
    0xe9, 0x69, 0x34, 0xae, 0xcf, 0xcd, 0x6d, 0xf6, 0xe9,
    0x37, 0x20, 0xa4, 0xd3, 0x85, 0x24, 0xff, 0x9f, 0x39,
    0xeb, 0x78, 0xf2, 0xd1, 0xc3, 0xf9, 0x66, 0xab, 0xbd,
    0x2d, 0xd3
};


CK_BYTE DH_PUBL_BASE[128] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x02
};


static void unloadLib(void)
{
    if (pkcs11lib)
        dlclose(pkcs11lib);
}

static void finalizeLib(void)
{
    funcs->C_Finalize(NULL);
}

static void closeSession(void)
{
    funcs->C_CloseSession(session);
}

static void logoutUser(void)
{
    funcs->C_Logout(session);
}

static int doLoadLib(void)
{
    const char *lib = "libopencryptoki.so";
    const char *envlib;
    CK_RV (*pGetFuncList)(CK_FUNCTION_LIST **);
    CK_RV rc;

    if ((envlib = getenv("PKCSLIB")) != NULL)
        lib = envlib;
    pkcs11lib = dlopen(lib, RTLD_NOW);
    if (pkcs11lib == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", lib, dlerror());
        return -1;
    }
    atexit(unloadLib);
    *(void**)(&pGetFuncList) = dlsym(pkcs11lib, "C_GetFunctionList");
    if (pGetFuncList == NULL) {
        fprintf(stderr, "Failed to find C_GetFunctionList symbol in %s\n", lib);
        return -1;
    }
    rc = pGetFuncList(&funcs);
    if (rc != CKR_OK) {
        fprintf(stderr, "C_GetFunctionList failed with 0x%lx\n", rc);
        return -1;
    }
    return 0;
}

static int doInitLib(void)
{
    CK_C_INITIALIZE_ARGS cinit_args;
    CK_RV rc;

    memset(&cinit_args, 0x0, sizeof(cinit_args));
    cinit_args.flags = CKF_OS_LOCKING_OK;
    rc = funcs->C_Initialize(&cinit_args);
    if (rc != CKR_OK) {
        fprintf(stderr, "C_Initialize failed with 0x%lx\n", rc);
        return -1;
    }
    atexit(finalizeLib);
    return 0;
}

static int doOpenSession(CK_SLOT_ID slot)
{
    CK_RV rc;
    CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    rc = funcs->C_OpenSession(slot, flags, NULL, NULL, &session);
    if (rc != CKR_OK) {
        fprintf(stderr, "Failed to open r/w session (rc = 0x%lx)\n", rc);
        return -1;
    }
    atexit(closeSession);
    return 0;
}

static int doLoginUser(unsigned char *pin)
{
    CK_RV rc;

    rc = funcs->C_Login(session, CKU_USER, pin, strlen((char *)pin));
    if (rc != CKR_OK) {
        fprintf(stderr, "Failed to log in to token (rc = 0x%lx)\n", rc);
        return -1;
    }
    atexit(logoutUser);
    return 0;
}

static int is_cca_token(CK_SLOT_ID slot_id)
{
    CK_RV rc;
    CK_TOKEN_INFO tokinfo;

    rc = funcs->C_GetTokenInfo(slot_id, &tokinfo);
    if (rc != CKR_OK)
        return FALSE;

    return strstr((const char *) tokinfo.model, "CCA") != NULL;
}

static CK_RV generateRSAKey(void)
{
    CK_OBJECT_HANDLE pubkey, privkey;
    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_BYTE subject[] = {0};
    CK_BYTE id[] = {123};
    CK_BBOOL cktrue = TRUE;
    CK_ULONG modulusBits = POLICY_TEST_RSA_SIZE;
    CK_BYTE publicExponent[] = {0x01, 0x00, 0x01};
    CK_ATTRIBUTE pubkeyTemplate[] = {
        {CKA_ENCRYPT,         &cktrue,              sizeof(cktrue)},
        {CKA_VERIFY,          &cktrue,              sizeof(cktrue)},
        {CKA_WRAP,            &cktrue,              sizeof(cktrue)},
        {CKA_MODULUS_BITS,    &modulusBits,         sizeof(modulusBits)},
        {CKA_PUBLIC_EXPONENT, publicExponent,       sizeof(publicExponent)},
        {CKA_TOKEN,           &tokenkeys,           sizeof(tokenkeys)},
        {CKA_LABEL,           (void *)poltestlabel, sizeof(poltestlabel)}
    };
    CK_ATTRIBUTE privkeyTemplate[] = {
        {CKA_TOKEN,           &cktrue,              sizeof(cktrue)},
        {CKA_PRIVATE,         &cktrue,              sizeof(cktrue)},
        {CKA_SUBJECT,         subject,              0},
        {CKA_ID,              id,                   sizeof(id)},
        {CKA_DECRYPT,         &cktrue,              sizeof(cktrue)},
        {CKA_SIGN,            &cktrue,              sizeof(cktrue)},
        {CKA_UNWRAP,          &cktrue,              sizeof(cktrue)},
        {CKA_TOKEN,           &tokenkeys,           sizeof(tokenkeys)},
        {CKA_LABEL,           (void *)poltestlabel, sizeof(poltestlabel)}
    };

    return funcs->C_GenerateKeyPair(session, &mech,
                                    pubkeyTemplate, ARRAY_SIZE(pubkeyTemplate),
                                    privkeyTemplate, ARRAY_SIZE(privkeyTemplate),
                                    &pubkey, &privkey);
}

static CK_RV generateECKey(void)
{
    CK_OBJECT_HANDLE pubkey, privkey;
    CK_BYTE secp384r1[] = OCK_SECP384R1;
    CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_BYTE subject[] = {0};
    CK_BYTE id[] = { 123 };
    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE publicKeyTemplate[] = {
        {CKA_VERIFY,        &true,                sizeof(true)},
        {CKA_EC_PARAMS,     &secp384r1,           sizeof(secp384r1)},
        {CKA_TOKEN,         &tokenkeys,           sizeof(tokenkeys)},
        {CKA_LABEL,         (void *)poltestlabel, sizeof(poltestlabel)}
    };
    CK_ATTRIBUTE privateKeyTemplate[] = {
        {CKA_PRIVATE,       &true,                sizeof(true)},
        {CKA_SUBJECT,       subject,              0},
        {CKA_ID,            id,                   sizeof(id)},
        {CKA_SIGN,          &true,                sizeof(true)},
        {CKA_DERIVE,        &true,                sizeof(true)},
        {CKA_TOKEN,         &tokenkeys,           sizeof(tokenkeys)},
        {CKA_LABEL,         (void *)poltestlabel, sizeof(poltestlabel)}
    };

    return funcs->C_GenerateKeyPair(session, &mech,
                                    publicKeyTemplate, ARRAY_SIZE(publicKeyTemplate),
                                    privateKeyTemplate, ARRAY_SIZE(privateKeyTemplate),
                                    &pubkey, &privkey);
}

static CK_RV generateAESKey(void)
{
    CK_OBJECT_HANDLE key;
    CK_ULONG keylen = POLICY_TEST_AES_SIZE / 8;
    CK_ATTRIBUTE key_gen_tmpl[] = {
        {CKA_VALUE_LEN, &keylen,              sizeof(CK_ULONG)},
        {CKA_TOKEN,     &tokenkeys,           sizeof(tokenkeys)},
        {CKA_LABEL,     (void *)poltestlabel, sizeof(poltestlabel)}
    };
    CK_MECHANISM mech = {
        .mechanism = CKM_AES_KEY_GEN,
        .ulParameterLen = 0,
        .pParameter = NULL,
    };

    return funcs->C_GenerateKey(session, &mech, key_gen_tmpl,
                                ARRAY_SIZE(key_gen_tmpl), &key);
}

static CK_RV generateDHKeys(void)
{
    CK_OBJECT_HANDLE pubkeyA, privkeyA, pubkeyB, privkeyB;
    CK_OBJECT_CLASS pub_key_class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE key_type = CKK_DH;
    CK_OBJECT_CLASS priv_key_class = CKO_PRIVATE_KEY;
    CK_BBOOL ltrue = CK_TRUE;
    CK_ATTRIBUTE publA_tmpl[] = {
        {CKA_CLASS,    &pub_key_class,          sizeof(pub_key_class)},
        {CKA_KEY_TYPE, &key_type,               sizeof(key_type)},
        {CKA_PRIME,    DH_PUBL_PRIME,           sizeof(DH_PUBL_PRIME)},
        {CKA_BASE,     DH_PUBL_BASE,            sizeof(DH_PUBL_BASE)},
        {CKA_TOKEN,    &tokenkeys,              sizeof(tokenkeys)},
        {CKA_LABEL,    (void *)poltestdhlabelA, sizeof(poltestdhlabelA)}
    };
    CK_ATTRIBUTE privA_tmpl[] = {
        {CKA_CLASS,    &priv_key_class,         sizeof(priv_key_class)},
        {CKA_KEY_TYPE, &key_type,               sizeof(key_type)},
        {CKA_DERIVE,   &ltrue,                  sizeof(ltrue)},
        {CKA_TOKEN,    &tokenkeys,              sizeof(tokenkeys)},
        {CKA_LABEL,    (void *)poltestdhlabelA, sizeof(poltestdhlabelA)}
    };
    CK_ATTRIBUTE publB_tmpl[] = {
        {CKA_CLASS,    &pub_key_class,          sizeof(pub_key_class)},
        {CKA_KEY_TYPE, &key_type,               sizeof(key_type)},
        {CKA_PRIME,    DH_PUBL_PRIME,           sizeof(DH_PUBL_PRIME)},
        {CKA_BASE,     DH_PUBL_BASE,            sizeof(DH_PUBL_BASE)},
        {CKA_TOKEN,    &tokenkeys,              sizeof(tokenkeys)},
        {CKA_LABEL,    (void *)poltestdhlabelB, sizeof(poltestdhlabelB)}
    };
    CK_ATTRIBUTE privB_tmpl[] = {
        {CKA_CLASS,    &priv_key_class,         sizeof(priv_key_class)},
        {CKA_KEY_TYPE, &key_type,               sizeof(key_type)},
        {CKA_DERIVE,   &ltrue,                  sizeof(ltrue)},
        {CKA_TOKEN,    &tokenkeys,              sizeof(tokenkeys)},
        {CKA_LABEL,    (void *)poltestdhlabelB, sizeof(poltestdhlabelB)}
    };
    CK_MECHANISM mech = { CKM_DH_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_RV rc;

    rc = funcs->C_GenerateKeyPair(session, &mech,
                                  publA_tmpl, ARRAY_SIZE(publA_tmpl),
                                  privA_tmpl, ARRAY_SIZE(privA_tmpl),
                                  &pubkeyA, &privkeyA);
    if (rc != CKR_OK)
        return rc;
    rc = funcs->C_GenerateKeyPair(session, &mech,
                                  publB_tmpl, ARRAY_SIZE(publB_tmpl),
                                  privB_tmpl, ARRAY_SIZE(privB_tmpl),
                                  &pubkeyB, &privkeyB);
    if (rc != CKR_OK) {
        funcs->C_DestroyObject(session, pubkeyA);
        funcs->C_DestroyObject(session, privkeyA);
    }
    return rc;
}

static CK_RV encryptRSA(CK_OBJECT_HANDLE key, CK_BYTE *res, CK_ULONG *reslen)
{
    CK_MECHANISM mech = { .mechanism = CKM_RSA_PKCS,
                          .pParameter = NULL,
                          .ulParameterLen = 0 };
    CK_RV rc;

    rc = funcs->C_EncryptInit(session, &mech, key);
    if (rc != CKR_OK)
        return rc;
    rc = funcs->C_Encrypt(session, (CK_BYTE *)rsamessage, sizeof(rsamessage),
                          res, reslen);
    return rc;
}

static CK_RV decryptRSA(CK_OBJECT_HANDLE key, CK_BYTE *enc, CK_ULONG len)
{
    CK_MECHANISM mech = { .mechanism = CKM_RSA_PKCS,
                          .pParameter = NULL,
                          .ulParameterLen = 0 };
    CK_BYTE dec[POLICY_TEST_RSA_SIZE / 8];
    CK_ULONG declen = sizeof(dec);
    CK_RV rc;

    rc = funcs->C_DecryptInit(session, &mech, key);
    if (rc != CKR_OK)
        return rc;
    rc = funcs->C_Decrypt(session, enc, len, dec, &declen);
    if (rc != CKR_OK)
        return rc;
    if (memcmp(rsamessage, dec, declen))
        return CKR_GENERAL_ERROR;
    return rc;
}

static int runRSATest(void)
{
    CK_BYTE enc[POLICY_TEST_RSA_SIZE / 8];
    CK_ULONG enclen = sizeof(enc);
    CK_RV rc;

    rc = encryptRSA(keys.rsapub, enc, &enclen);
    if (rc != CKR_OK) {
        fprintf(stderr, "WARN: RSA public key usage failed with 0x%lx\n", rc);
        return -1;
    }
    rc = decryptRSA(keys.rsapriv, enc, enclen);
    if (rc != CKR_OK) {
        fprintf(stderr, "WARN: RSA private key usage failed with 0x%lx\n", rc);
        return -1;
    }
    return 0;
}


static CK_RV signEC(CK_OBJECT_HANDLE key, CK_BYTE *sig, CK_ULONG *siglen)
{
    CK_MECHANISM mech = { CKM_ECDSA, NULL, 0 };
    CK_RV rc;

    rc = funcs->C_SignInit(session, &mech, key);
    if (rc != CKR_OK)
        return rc;
    rc = funcs->C_Sign(session, (CK_BYTE *)ecmessage, sizeof(ecmessage),
                       sig, siglen);
    return rc;
}

static CK_RV verifyEC(CK_OBJECT_HANDLE key, CK_BYTE *sig, CK_ULONG siglen)
{
    CK_MECHANISM mech = { CKM_ECDSA, NULL, 0 };
    CK_RV rc;

    rc = funcs->C_VerifyInit(session, &mech, key);
    if (rc != CKR_OK)
        return rc;
    rc = funcs->C_Verify(session, (CK_BYTE *)ecmessage, sizeof(ecmessage),
                         sig, siglen);
    return rc;
}

static int runECTest(void)
{
    CK_BYTE sig[2 * POLICY_TEST_EC_SIZE / 8];
    CK_ULONG siglen = sizeof(sig);
    CK_RV rc;

    rc = signEC(keys.ecpriv, sig, &siglen);
    if (rc != CKR_OK) {
        fprintf(stderr, "WARN: EC private key usage failed with 0x%lx\n", rc);
        return -1;
    }
    rc = verifyEC(keys.ecpub, sig, siglen);
    if (rc != CKR_OK) {
        fprintf(stderr, "WARN: EC public key usage failed with 0x%lx\n", rc);
        return -1;
    }
    return 0;
}

static CK_RV wrapAESKey(CK_OBJECT_HANDLE key, CK_BYTE **wrapped, CK_ULONG *len)
{
    CK_BYTE iv[16] = {0};
    CK_MECHANISM mech = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    CK_RV rc;
    CK_BYTE *res;

    rc = funcs->C_WrapKey(session, &mech, key, key, NULL, len);
    if (rc != CKR_OK)
        return rc;
    res = calloc(1, *len);
    if (!res)
        return CKR_HOST_MEMORY;
    rc = funcs->C_WrapKey(session, &mech, key, key, res, len);
    if (rc != CKR_OK) {
        free(res);
        return rc;
    }
    *wrapped = res;
    return rc;
}

static CK_RV unwrapAESKey(CK_OBJECT_HANDLE key, CK_BYTE *wrapped, CK_ULONG len,
                          CK_OBJECT_HANDLE_PTR unwrapped, int iscca)
{
    CK_BYTE iv[16] = {0};
    CK_MECHANISM mech = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    CK_RV rc;
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_AES;
    CK_ULONG key_size = POLICY_TEST_AES_SIZE / 8;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_VALUE_LEN, &key_size, sizeof(key_size)} /* For CCA only */
    };
    CK_ULONG templatecount = 2 + iscca;

    rc = funcs->C_UnwrapKey(session, &mech, key, wrapped, len,
                            template, templatecount, unwrapped);
    free(wrapped);
    return rc;
}

static int runAESWrapTest(CK_SLOT_ID slot)
{
    CK_OBJECT_HANDLE unwrapped = CK_INVALID_HANDLE;
    CK_BYTE *wrapped;
    CK_ULONG wrappedlen;
    CK_RV rc;

    rc = wrapAESKey(keys.aes, &wrapped, &wrappedlen);
    if (rc != CKR_OK) {
        fprintf(stderr, "WARN: AES wrapping failed with 0x%lx\n", rc);
        return -1;
    }
    rc = unwrapAESKey(keys.aes, wrapped, wrappedlen, &unwrapped,
                      is_cca_token(slot));
    funcs->C_DestroyObject(session, unwrapped);
    if (rc != CKR_OK) {
        fprintf(stderr, "WARN: AES unwrapping failed with 0x%lx\n", rc);
        return -1;
    }
    return 0;
}

static int runDIGESTTest(void)
{
    CK_BYTE digest[64];
    CK_MECHANISM mech = { CKM_SHA512, NULL, 0 };
    CK_RV rc;
    CK_ULONG len = sizeof(digest);

    rc = funcs->C_DigestInit(session, &mech);
    if (rc != CKR_OK) {
        fprintf(stderr, "WARN: Digest initialization failed with 0x%lx\n", rc);
        return -1;
    }
    rc = funcs->C_Digest(session, (CK_BYTE *)rsamessage, sizeof(rsamessage),
                         digest, &len);
    if (rc != CKR_OK) {
        /* No policy checking done in C_Digest... */
        fprintf(stderr, "WARN: Digest failed with 0x%lx\n", rc);
        return -1;
    }
    return 0;
}


static int runDHTest(void)
{
    CK_BYTE key_value[sizeof(DH_PUBL_PRIME) * 2];
    CK_ATTRIBUTE extr_tmpl = {CKA_VALUE, key_value, sizeof(key_value)};
    CK_ULONG secret_key_size = sizeof(DH_PUBL_PRIME);
    CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE secret_key_type = CKK_GENERIC_SECRET;
    CK_ATTRIBUTE secret_tmpl[] = {
        {CKA_CLASS, &secret_key_class, sizeof(secret_key_class)},
        {CKA_KEY_TYPE, &secret_key_type, sizeof(secret_key_type)},
        {CKA_VALUE_LEN, &secret_key_size, sizeof(secret_key_size)}
    };
    CK_MECHANISM mech = { CKM_DH_PKCS_DERIVE, key_value, 0 };
    CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
    CK_RV rc;

    // Extract the peer's public key
    rc = funcs->C_GetAttributeValue(session, keys.dhpubB, &extr_tmpl, 1);
    if (rc != CKR_OK) {
        fprintf(stderr,
                "WARN: Getting CKA_VALUE for DH peer pub key failed with 0x%lx!\n",
                rc);
        return -1;
    }
    mech.ulParameterLen = extr_tmpl.ulValueLen;
    rc = funcs->C_DeriveKey(session, &mech, keys.dhprivA, secret_tmpl, ARRAY_SIZE(secret_tmpl), &derived);
    funcs->C_DestroyObject(session, derived);
    if (rc != CKR_OK) {
        fprintf(stderr, "WARN: DH key derivation failed with 0x%lx\n", rc);
        return -1;
    }
    return 0;
}

static int generateKeys(void)
{
    int res = 0;

    if (generateRSAKey() != CKR_OK)
        res = -1;
    if (generateECKey() != CKR_OK)
        res = -1;
    if (generateAESKey() != CKR_OK)
        res = -1;
    if (generateDHKeys() != CKR_OK)
        res = -1;
    return res;
}

static int loadKeys(void)
{
    static const CK_KEY_TYPE rsakt = CKK_RSA;
    static const CK_KEY_TYPE eckt = CKK_EC;
    static const CK_KEY_TYPE aeskt = CKK_AES;
    static const CK_KEY_TYPE dhkt = CKK_DH;
    static const CK_OBJECT_CLASS publickey = CKO_PUBLIC_KEY;
    static const CK_OBJECT_CLASS privatekey = CKO_PRIVATE_KEY;
    static const CK_ATTRIBUTE rsapubtmpl[] = {
        {CKA_KEY_TYPE,        (void *)&rsakt,       sizeof(rsakt)},
        {CKA_CLASS,           (void *)&publickey,   sizeof(publickey)},
        {CKA_LABEL,           (void *)poltestlabel, sizeof(poltestlabel)}
    };
    static const CK_ATTRIBUTE rsaprivtmpl[] = {
        {CKA_KEY_TYPE,        (void *)&rsakt,       sizeof(rsakt)},
        {CKA_CLASS,           (void *)&privatekey,  sizeof(privatekey)},
        {CKA_LABEL,           (void *)poltestlabel, sizeof(poltestlabel)}
    };
    static const CK_ATTRIBUTE ecpubtmpl[] = {
        {CKA_KEY_TYPE,        (void *)&eckt,        sizeof(eckt)},
        {CKA_CLASS,           (void *)&publickey,   sizeof(publickey)},
        {CKA_LABEL,           (void *)poltestlabel, sizeof(poltestlabel)}
    };
    static const CK_ATTRIBUTE ecprivtmpl[] = {
        {CKA_KEY_TYPE,        (void *)&eckt,        sizeof(eckt)},
        {CKA_CLASS,           (void *)&privatekey,  sizeof(privatekey)},
        {CKA_LABEL,           (void *)poltestlabel, sizeof(poltestlabel)}
    };
    static const CK_ATTRIBUTE aestmpl[] = {
        {CKA_KEY_TYPE,        (void *)&aeskt,       sizeof(aeskt)},
        {CKA_LABEL,           (void *)poltestlabel, sizeof(poltestlabel)}
    };
    static const CK_ATTRIBUTE dhApubtmpl[] = {
        {CKA_KEY_TYPE,        (void *)&dhkt,           sizeof(dhkt)},
        {CKA_CLASS,           (void *)&publickey,      sizeof(publickey)},
        {CKA_LABEL,           (void *)poltestdhlabelA, sizeof(poltestdhlabelA)}
    };
    static const CK_ATTRIBUTE dhAprivtmpl[] = {
        {CKA_KEY_TYPE,        (void *)&dhkt,           sizeof(dhkt)},
        {CKA_CLASS,           (void *)&privatekey,     sizeof(privatekey)},
        {CKA_LABEL,           (void *)poltestdhlabelA, sizeof(poltestdhlabelA)}
    };
    static const CK_ATTRIBUTE dhBpubtmpl[] = {
        {CKA_KEY_TYPE,        (void *)&dhkt,           sizeof(dhkt)},
        {CKA_CLASS,           (void *)&publickey,      sizeof(publickey)},
        {CKA_LABEL,           (void *)poltestdhlabelB, sizeof(poltestdhlabelB)}
    };
    static const CK_ATTRIBUTE dhBprivtmpl[] = {
        {CKA_KEY_TYPE,        (void *)&dhkt,           sizeof(dhkt)},
        {CKA_CLASS,           (void *)&privatekey,     sizeof(privatekey)},
        {CKA_LABEL,           (void *)poltestdhlabelB, sizeof(poltestdhlabelB)}
    };
    CK_OBJECT_HANDLE handle;
    CK_ULONG count;
    CK_RV rc;
    int res = 0;

    // Find RSA pubkey
    rc = funcs->C_FindObjectsInit(session, (CK_ATTRIBUTE *)rsapubtmpl,
                                  ARRAY_SIZE(rsapubtmpl));
    if (rc != CKR_OK) {
        res = -1;
    } else {
        rc = funcs->C_FindObjects(session, &handle, 1, &count);
        funcs->C_FindObjectsFinal(session);
        if (rc != CKR_OK || count != 1u)
            res = -1;
        else
            keys.rsapub = handle;
    }
    // Find RSA privkey
    rc = funcs->C_FindObjectsInit(session, (CK_ATTRIBUTE *)rsaprivtmpl,
                                  ARRAY_SIZE(rsaprivtmpl));
    if (rc != CKR_OK) {
        res = -1;
    } else {
        rc = funcs->C_FindObjects(session, &handle, 1, &count);
        funcs->C_FindObjectsFinal(session);
        if (rc != CKR_OK || count != 1u)
            res = -1;
        else
            keys.rsapriv = handle;
    }
    // Find EC pubkey
    rc = funcs->C_FindObjectsInit(session, (CK_ATTRIBUTE *)ecpubtmpl,
                                  ARRAY_SIZE(ecpubtmpl));
    if (rc != CKR_OK) {
        res = -1;
    } else {
        rc = funcs->C_FindObjects(session, &handle, 1, &count);
        funcs->C_FindObjectsFinal(session);
        if (rc != CKR_OK || count != 1u)
            res = -1;
        else
            keys.ecpub = handle;
    }
    // Find EC privkey
    rc = funcs->C_FindObjectsInit(session, (CK_ATTRIBUTE *)ecprivtmpl,
                                  ARRAY_SIZE(ecprivtmpl));
    if (rc != CKR_OK) {
        res = -1;
    } else {
        rc = funcs->C_FindObjects(session, &handle, 1, &count);
        funcs->C_FindObjectsFinal(session);
        if (rc != CKR_OK || count != 1u)
            res = -1;
        else
            keys.ecpriv = handle;
    }
    // Find AES pubkey
    rc = funcs->C_FindObjectsInit(session, (CK_ATTRIBUTE *)aestmpl,
                                  ARRAY_SIZE(aestmpl));
    if (rc != CKR_OK) {
        res = -1;
    } else {
        rc = funcs->C_FindObjects(session, &handle, 1, &count);
        funcs->C_FindObjectsFinal(session);
        if (rc != CKR_OK || count != 1u)
            res = -1;
        else
            keys.aes = handle;
    }
    // Find DH pubkey A
    rc = funcs->C_FindObjectsInit(session, (CK_ATTRIBUTE *)dhApubtmpl,
                                  ARRAY_SIZE(dhApubtmpl));
    if (rc != CKR_OK) {
        res = -1;
    } else {
        rc = funcs->C_FindObjects(session, &handle, 1, &count);
        funcs->C_FindObjectsFinal(session);
        if (rc != CKR_OK || count != 1u)
            res = -1;
        else
            keys.dhpubA = handle;
    }
    // Find DH privkey A
    rc = funcs->C_FindObjectsInit(session, (CK_ATTRIBUTE *)dhAprivtmpl,
                                  ARRAY_SIZE(dhAprivtmpl));
    if (rc != CKR_OK) {
        res = -1;
    } else {
        rc = funcs->C_FindObjects(session, &handle, 1, &count);
        funcs->C_FindObjectsFinal(session);
        if (rc != CKR_OK || count != 1u)
            res = -1;
        else
            keys.dhprivA = handle;
    }
    // Find DH pubkey B
    rc = funcs->C_FindObjectsInit(session, (CK_ATTRIBUTE *)dhBpubtmpl,
                                  ARRAY_SIZE(dhBpubtmpl));
    if (rc != CKR_OK) {
        res = -1;
    } else {
        rc = funcs->C_FindObjects(session, &handle, 1, &count);
        funcs->C_FindObjectsFinal(session);
        if (rc != CKR_OK || count != 1u)
            res = -1;
        else
            keys.dhpubB = handle;
    }
    // Find DH privkey B
    rc = funcs->C_FindObjectsInit(session, (CK_ATTRIBUTE *)dhBprivtmpl,
                                  ARRAY_SIZE(dhBprivtmpl));
    if (rc != CKR_OK) {
        res = -1;
    } else {
        rc = funcs->C_FindObjects(session, &handle, 1, &count);
        funcs->C_FindObjectsFinal(session);
        if (rc != CKR_OK || count != 1u)
            res = -1;
        else
            keys.dhprivB = handle;
    }
    return res;
}

static void deleteKeys(void)
{
    funcs->C_DestroyObject(session, keys.rsapub);
    funcs->C_DestroyObject(session, keys.rsapriv);
    funcs->C_DestroyObject(session, keys.ecpub);
    funcs->C_DestroyObject(session, keys.ecpriv);
    funcs->C_DestroyObject(session, keys.aes);
    funcs->C_DestroyObject(session, keys.dhpubA);
    funcs->C_DestroyObject(session, keys.dhprivA);
    funcs->C_DestroyObject(session, keys.dhpubB);
    funcs->C_DestroyObject(session, keys.dhprivB);
}

static void dumpKeyInfo(void)
{
#define KEY_TO_STR(X) ((X) == CK_INVALID_HANDLE ? "UNAVAILABLE" : "ok")
    fprintf(stderr, "RSA public key:   %s\n", KEY_TO_STR(keys.rsapub));
    fprintf(stderr, "RSA private key:  %s\n", KEY_TO_STR(keys.rsapriv));
    fprintf(stderr, "EC public key:    %s\n", KEY_TO_STR(keys.ecpub));
    fprintf(stderr, "EC private key:   %s\n", KEY_TO_STR(keys.ecpriv));
    fprintf(stderr, "AES key:          %s\n", KEY_TO_STR(keys.aes));
    fprintf(stderr, "DH public key A:  %s\n", KEY_TO_STR(keys.dhpubA));
    fprintf(stderr, "DH private key A: %s\n", KEY_TO_STR(keys.dhprivA));
    fprintf(stderr, "DH public key B:  %s\n", KEY_TO_STR(keys.dhpubB));
    fprintf(stderr, "DH private key B: %s\n", KEY_TO_STR(keys.dhprivB));
#undef KEY_TO_STR
}

static inline void initializeKeys(void)
{
    keys.rsapub = keys.rsapriv =
        keys.ecpub = keys.ecpriv =
        keys.aes =
        keys.dhpubA = keys.dhprivA =
        keys.dhpubB = keys.dhprivB = CK_INVALID_HANDLE;
}

static int runTests(CK_SLOT_ID slot, uint32_t tests, uint32_t expfail)
{
    int res = 0, tmpres, shouldfail;

    tmpres = 0;
    if (tests & (1u << TEST_RSA)) {
        shouldfail = expfail & (1u << TEST_RSA);
        if (keys.rsapub == CK_INVALID_HANDLE ||
            keys.rsapriv == CK_INVALID_HANDLE) {
            fprintf(stderr, "WARN: RSA test requested, but RSA keys unavailable!\n");
            tmpres = -1;
        } else {
            tmpres = runRSATest();
        }
        if (tmpres && shouldfail == 0) {
            fprintf(stderr, "ERROR: RSA test failed unexpectedly!\n");
            res = -1;
        } else if (tmpres == 0 && shouldfail) {
            fprintf(stderr, "ERROR: RSA test did not fail as expected!\n");
            res = -1;
        }
    }
    tmpres = 0;
    if (tests & (1u << TEST_EC)) {
        shouldfail = expfail & (1u << TEST_EC);
        if (keys.ecpub == CK_INVALID_HANDLE ||
            keys.ecpriv == CK_INVALID_HANDLE) {
            fprintf(stderr, "WARN: EC test requested, but EC keys unavailable!\n");
            tmpres = -1;
        } else {
            tmpres = runECTest();
        }
        if (tmpres && shouldfail == 0) {
            fprintf(stderr, "ERROR: EC test failed unexpectedly!\n");
            res = -1;
        } else if (tmpres == 0 && shouldfail) {
            fprintf(stderr, "ERROR: EC test did not fail as expected!\n");
            res = -1;
        }
    }
    tmpres = 0;
    if (tests & (1u << TEST_AESWRAP)) {
        shouldfail = expfail & (1u << TEST_AESWRAP);
        if (keys.aes == CK_INVALID_HANDLE) {
            fprintf(stderr, "WARN: AES test requested, but AES key unavailable!\n");
            tmpres = -1;
        } else {
            tmpres = runAESWrapTest(slot);
        }
        if (tmpres && shouldfail == 0) {
            fprintf(stderr, "ERROR: AES Wrap test failed unexpectedly!\n");
            res = -1;
        } else if (tmpres == 0 && shouldfail) {
            fprintf(stderr, "ERROR: AES Wrap test did not fail as expected!\n");
            res = -1;
        }
    }
    if (tests & (1u << TEST_DIGEST)) {
        shouldfail = expfail & (1u << TEST_DIGEST);
        tmpres = runDIGESTTest();
        if (tmpres && shouldfail == 0) {
            fprintf(stderr, "ERROR: Digest test failed unexpectedly!\n");
            res = -1;
        } else if (tmpres == 0 && shouldfail) {
            fprintf(stderr, "ERROR: Digest test did not fail as expected!\n");
            res = -1;
        }
    }
    tmpres = 0;
    if (tests & (1u << TEST_DH)) {
        shouldfail = expfail & (1u << TEST_DH);
        if (keys.dhpubA == CK_INVALID_HANDLE ||
            keys.dhprivA == CK_INVALID_HANDLE ||
            keys.dhpubB == CK_INVALID_HANDLE ||
            keys.dhprivB == CK_INVALID_HANDLE) {
            fprintf(stderr, "WARN: DH test requested, but DH key unavailable!\n");
            tmpres = -1;
        } else {
            tmpres = runDHTest();
        }
        if (tmpres && shouldfail == 0) {
            fprintf(stderr, "ERROR: DH test failed unexpectedly!\n");
            res = -1;
        } else if (tmpres == 0 && shouldfail) {
            fprintf(stderr, "ERROR: DH test did not fail as expected!\n");
            res = -1;
        }
    }
    return res;
}

static void usage(char *prgname)
{
    printf("USAGE: %s -s|--slot <num> [-g|--generate] [-t|--tests] [-d|--delete] [-k|--token] [-r|--restrict <tests>] [-f|--fail <tests>]\n",
        prgname);
    printf("where:\n");
    printf("\t-s or --slot specifies the PKCS #11 slot to use\n");
    printf("\t-g or --generate specifies to generate keys for testing\n");
    printf("\t-t or --tests specifies to run tests\n");
    printf("\t-d or --delete specifies to delete the keys at the end\n");
    printf("\t-k or --token specifies to use token keys (only useful with key generation)\n");
    printf("\t-r or --restrict specifies which tests to run\n");
    printf("\t-f or --fail specifies which tests are expected to fail\n");
    printf("\nvalid tests are:\n");
    printf("RSA     - Encrypt/Decrypt test with 4k RSA key and CKM_RSA_PKCS\n");
    printf("EC      - CKM_ECDSA sign/verify with secp384r1 key\n");
    printf("AESWRAP - CKM_AES_CBC_PAD key wrapping with 256bit key\n");
    printf("DIGEST  - CKM_SHA512\n");
    printf("DH      - CKM_DH_PKCS_DERIVE with 128 byte prime\n");
    printf("<tests> is a CSV of the keys above.\n");
}

static int getslotid(CK_SLOT_ID *slotid, char *arg)
{
    char *endptr;
    unsigned long res;

    errno = 0;
    res = strtoul(arg, &endptr, 0);
    if (*endptr || endptr == arg || (res == ULONG_MAX && errno == ERANGE)) {
        fprintf(stderr, "Failed to parse slot id %s\n", arg);
        return -1;
    }
    *slotid = res;
    return 0;
}


static int get_user_pin(CK_BYTE * dest)
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

static int parsecsv(uint32_t *mask, const char *carg)
{
    char *arg = strdup(carg);
    char *s, *tok;
    int res = 0;

    if (!arg)
        return -1;
    s = arg;
    while ((tok = strtok(s, ",")) != NULL) {
        if (strcmp(tok, "RSA") == 0)
            *mask |= (1u << TEST_RSA);
        else if (strcmp(tok, "EC") == 0)
            *mask |= (1u << TEST_EC);
        else if (strcmp(tok, "AESWRAP") == 0)
            *mask |= (1u << TEST_AESWRAP);
        else if (strcmp(tok, "DIGEST") == 0)
            *mask |= (1u << TEST_DIGEST);
        else if (strcmp(tok, "DH") == 0)
            *mask |= (1u << TEST_DH);
        else
            res = -1;
        s = NULL;
    }
    free(arg);
    return res;
}

static int parseArgs(int argc, char **argv, CK_SLOT_ID *slot,
                     int *keygen, int *test, int *delete,
                     uint32_t *tests, uint32_t *fail)
{
    static struct option long_options[] =
        {
         {"slot",     required_argument, 0, 's'},
         {"generate", no_argument,       0, 'g'},
         {"tests",    no_argument,       0, 't'},
         {"delete",   no_argument,       0, 'd'},
         {"restrict", required_argument, 0, 'r'},
         {"fail",     required_argument, 0, 'f'},
         {"token",    no_argument,       0, 'k'},
         {"help",     no_argument,       0, 'h'},
         {0,          0,                 0, 0  }
        };
    int c, slotunspecified = -1;

    *keygen = *test = *delete = 0;
    *tests = ~0u;
    *fail = 0;
    while (1) {
        c = getopt_long(argc, argv, "s:gtdr:f:kh", long_options, 0);
        if (c == -1)
            break;
        switch (c) {
        case 's':
            if (getslotid(slot, optarg))
                return -1;
            slotunspecified = 0;
            break;
        case 'g':
            *keygen = 1;
            break;
        case 't':
            *test = 1;
            break;
        case 'd':
            *delete = 1;
            break;
        case 'r':
            *tests = 0;
            if (parsecsv(tests, optarg))
                return -1;
            break;
        case 'f':
            if (parsecsv(fail, optarg))
                return -1;
            break;
        case 'k':
            tokenkeys = CK_TRUE;
            break;
        case 'h':
            usage(argv[0]);
            return 1;
        default:
            usage(argv[0]);
            return -1;
        }
    }
    if (slotunspecified)
        usage(argv[0]);
    return slotunspecified;
}

int main(int argc, char **argv)
{

    CK_BYTE userpin[PKCS11_MAX_PIN_LEN];
    int keygen, test, delete;
    uint32_t tests, fail;
    CK_SLOT_ID slot = 0;
    int res = 0;

    initializeKeys();
    if (parseArgs(argc, argv, &slot, &keygen, &test, &delete, &tests, &fail))
        return 1;
    if (get_user_pin(userpin))
        return 2;
    if (doLoadLib())
        return 3;
    if (doInitLib())
        return 4;
    if (doOpenSession(slot))
        return 5;
    if (doLoginUser(userpin))
        return 6;
    if (keygen && generateKeys())
        fprintf(stderr, "WARN: Could not generate all keys\n");
    if (loadKeys()) {
        fprintf(stderr, "WARN: Could not load all keys\n");
        dumpKeyInfo();
    }
    if (test && runTests(slot, tests, fail))
        res = 7;
    if (delete)
        deleteKeys();
    return res;
}
