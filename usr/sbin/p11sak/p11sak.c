/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2020
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pkcs11types.h>
#include <dlfcn.h>
#include "cfgparser.h"
#include "configuration.h"
#include <ctype.h>
#include <linux/limits.h>

#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#include <pin_prompt.h>
#include "uri.h"
#include "p11util.h"
#include "p11sak.h"
#include "mechtable.h"

static const char *default_pkcs11lib = "libopencryptoki.so";

static void *pkcs11lib = NULL;
static CK_FUNCTION_LIST *funcs = NULL;

static struct ConfigBaseNode *cfg = NULL;

static void error_hook(int line, int col, const char *msg)
{
  fprintf(stderr, "PARSE ERROR: %d:%d: %s\n", line, col, msg);
}

void dump_attr(CK_ATTRIBUTE_PTR a)
{
    const char *typestr;
    typestr = p11_get_cka(a->type);
    unsigned char *p = a->pValue;
    unsigned int z;

    switch (a->ulValueLen) {
    case 0:
        printf("          %s: no value\n", typestr);
        break;
    default:
        printf("          %s: len=%lu value:", typestr, a->ulValueLen);
        for (z = 0; z < a->ulValueLen; z++) {
            if (z % 16 == 0) {
                printf("\n            %02X ", p[z]);
            }
            else {
                printf("%02X ", p[z]);
            }
        }
        printf("\n");
        break;
    }
}

static void unload_pkcs11lib(void)
{
    if (pkcs11lib)
        dlclose(pkcs11lib);
}

static void load_pkcs11lib(void)
{
    CK_RV rc;
    CK_RV (*getfunclist)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
    const char *libname;

    /* check for environment variable PKCSLIB */
    libname = secure_getenv("PKCSLIB");
    if (libname == NULL || strlen(libname) < 1)
        libname = default_pkcs11lib;

    /* try to load the pkcs11 lib */
    pkcs11lib = dlopen(libname, RTLD_NOW);
    if (!pkcs11lib) {
        fprintf(stderr, "Error: failed to open pkcs11 lib '%s'\n", libname);
        exit(99);
    }

    /* get function list */
    *(void**) (&getfunclist) = dlsym(pkcs11lib, "C_GetFunctionList");
    if (!getfunclist) {
        dlclose(pkcs11lib);
        fprintf(stderr, "Error: failed to resolve symbol '%s' from pkcs11 lib '%s'\n",
                "C_GetFunctionList", libname);
        exit(99);
    }
    rc = getfunclist(&funcs);
    if (rc != CKR_OK) {
        dlclose(pkcs11lib);
        fprintf(stderr, "Error: C_GetFunctionList() on pkcs11 lib '%s' failed with rc = 0x%lX - %s)\n",
                libname, rc, p11_get_ckr(rc));
        exit(99);
    }

    atexit(unload_pkcs11lib);
}

/**
 * Translates the given key type to its string representation.
 */
static const char* kt2str(p11sak_kt ktype)
{
    switch (ktype) {
    case kt_DES:
        return "DES";
    case kt_3DES:
        return "3DES";
    case kt_AES:
        return "AES";
    case kt_AES_XTS:
        return "AES-XTS";
    case kt_RSAPKCS:
        return "RSA_PKCS";
    case kt_EC:
        return "EC";
    case kt_IBM_DILITHIUM:
        return "IBM DILITHIUM";
    case kt_IBM_KYBER:
        return "IBM KYBER";
    case kt_GENERIC:
        return "GENERIC";
    case kt_SECRET:
        return "SECRET";
    case kt_PUBLIC:
        return "PUBLIC";
    case kt_PRIVATE:
        return "PRIVATE";
    case kt_ALL:
        return "ALL";
    case no_key_type:
        return "NO_KEYTYPE";
    default:
        return "NO_KEYTYPE";
    }
}
/**
 * Translates the given key type to its CK_KEY_TYPE
 */
static CK_RV kt2CKK(p11sak_kt ktype, CK_KEY_TYPE *a_key_type)
{
    switch (ktype) {
    case kt_DES:
        *a_key_type = CKK_DES;
        break;
    case kt_3DES:
        *a_key_type = CKK_DES3;
        break;
    case kt_AES:
        *a_key_type = CKK_AES;
        break;
    case kt_AES_XTS:
        *a_key_type = CKK_AES_XTS;
        break;
    case kt_RSAPKCS:
        *a_key_type = CKK_RSA;
        break;
    case kt_EC:
        *a_key_type = CKK_EC;
        break; 
    case kt_IBM_DILITHIUM:
        *a_key_type = CKK_IBM_PQC_DILITHIUM;
        break; 
    case kt_IBM_KYBER:
        *a_key_type = CKK_IBM_PQC_KYBER;
        break;
    case kt_GENERIC:
        *a_key_type = CKK_GENERIC_SECRET;
        break;
    default:
        return CKR_ARGUMENTS_BAD;
    }
    return CKR_OK;
}
/**
 * Translates the given key type to its CK_OBJECT_CLASS
 */
static CK_RV kt2CKO(p11sak_kt ktype, CK_OBJECT_CLASS *a_cko)
{
    switch (ktype) {
    case kt_SECRET:
        *a_cko = CKO_SECRET_KEY;
        break;
    case kt_PUBLIC:
        *a_cko = CKO_PUBLIC_KEY;
        break;
    case kt_PRIVATE:
        *a_cko = CKO_PRIVATE_KEY;
        break;
    default:
        return CKR_ARGUMENTS_BAD;
    }
    return CKR_OK;
}
/**
 * Translates the given p11sak command to its string representation.
 * no_cmd, gen_key, list_key
 */
static const char* cmd2str(p11sak_cmd cmd)
{
    switch (cmd) {
    case no_cmd:
        return "no_cmd";
    case gen_key:
        return "generate-key";
    case list_key:
        return "list-key";
    case remove_key:
        return "remove-key";
    default:
        return "unknown p11sak cmd";
    }
}
/**
 * Translates the given attribute type to its long name.
 */
static const char* CKA2a(CK_ATTRIBUTE_TYPE attr_type)
{
    switch (attr_type) {
    case CKA_TOKEN:
        return "CKA_TOKEN";
    case CKA_PRIVATE:
        return "CKA_PRIVATE";
    case CKA_MODIFIABLE:
        return "CKA_MODIFIABLE";
    case CKA_DERIVE:
        return "CKA_DERIVE";
    case CKA_LOCAL:
        return "CKA_LOCAL";
    case CKA_SENSITIVE:
        return "CKA_SENSITIVE";
    case CKA_ENCRYPT:
        return "CKA_ENCRYPT";
    case CKA_DECRYPT:
        return "CKA_DECRYPT";
    case CKA_SIGN:
        return "CKA_SIGN";
    case CKA_VERIFY:
        return "CKA_VERIFY";
    case CKA_WRAP:
        return "CKA_WRAP";
    case CKA_UNWRAP:
        return "CKA_UNWRAP";
    case CKA_ALWAYS_SENSITIVE:
        return "CKA_ALWAYS_SENSITIVE";
    case CKA_EXTRACTABLE:
        return "CKA_EXTRACTABLE";
    case CKA_NEVER_EXTRACTABLE:
        return "CKA_NEVER_EXTRACTABLE";
    case CKA_TRUSTED:
        return "CKA_TRUSTED";
    default:
        return "unknown attribute";
    }
}
/**
 * Translates the given key type to its related char string.
 */
static const char* CKK2a(CK_KEY_TYPE t)
{
    // if new cases are added, the buffer = malloc()
    // in tok_key_get_key_type() needs to be updated
    switch (t) {
    case CKK_DES:
        return "DES";
    case CKK_DES3:
        return "3DES";
    case CKK_AES:
        return "AES";
    case CKK_AES_XTS:
        return "AES-XTS";
    case CKK_EC:
        return "EC";
    case CKK_IBM_PQC_DILITHIUM:
        return "IBM DILILTHIUM";
    case CKK_IBM_PQC_KYBER:
        return "IBM KYBER";
    case CKK_RSA:
        return "RSA";
    case CKK_DH:
        return "DH";
    case CKK_DSA:
        return "DSA";
    case CKK_GENERIC_SECRET:
        return "generic";
    default:
        return "unknown key type";
    }
}
/**
 * Translates the given bool to its related char string.
 */
static const char* CK_BBOOL2a(CK_BBOOL b)
{
    switch (b) {
    case 0:
        return "CK_FALSE";
    case 1:
        return "CK_TRUE";
    default:
        return "unknown value";
    }
}
/**
 * Translates the given ULONG value to a byte string.
 */
static CK_BYTE* CK_ULONG2bigint(CK_ULONG ul, CK_BYTE *bytes, CK_ULONG *len)
{
    CK_BYTE *ulp;
    CK_ULONG tul = 1;
    CK_BYTE *tulp;
    int i, j, s;

    s = 0;
    ulp = (CK_BYTE*) &ul;
    tulp = (CK_BYTE*) &tul;

    if (tulp[0] == 1) {
        for (j = sizeof(CK_ULONG) - 1, i = 0; j >= 0; j--, i++) {
            bytes[i] = ulp[j];
            if (s == 0 && bytes[i] != 0)
                s = i;
        }
    } else {
        for (i = 0; i <= (int) sizeof(CK_ULONG) - 1; i++) {
            bytes[i] = ulp[i];
            if (s == 0 && bytes[i] != 0)
                s = i;
        }
    }
    *len = sizeof(CK_ULONG) - s;
    memmove(&bytes[0], &bytes[s], *len);
    return &bytes[0];
}
/**
 * print help functions
 */
static void print_cmd_help(void)
{
    printf("\n Usage: p11sak COMMAND [ARGS] [OPTIONS]\n");
    printf("\n Commands:\n");
    printf("      generate-key       Generate a key\n");
    printf("      list-key           List keys in the repository\n");
    printf("      remove-key         Delete keys in the repository\n");
    printf("\n Options:\n");
    printf("      -h, --help         Show this help\n\n");
}

static void print_listkeys_help(void)
{
    printf("\n Usage: p11sak list-key [ARGS] [OPTIONS]\n");
    printf("\n Args:\n");
    printf("      des\n");
    printf("      3des\n");
    printf("      aes\n");
    printf("      aes-xts\n");
    printf("      rsa\n");
    printf("      ec\n");
    printf("      ibm-dilithium\n");
    printf("      ibm-kyber\n");
    printf("      public\n");
    printf("      private\n");
    printf("      secret\n");
    printf("      all\n");
    printf("\n Options:\n");
    printf("      -l, --long           list output with long format\n");
    printf("          --detailed-uri   enable detailed PKCS#11 URI\n");
    printf("      --label LABEL        filter keys by key label\n");
    printf("      --slot SLOTID        openCryptoki repository token SLOTID.\n");
    printf("      --pin PIN            pkcs11 user PIN\n");
    printf("      --force-pin-prompt   enforce user PIN prompt\n");
    printf("      -h, --help           Show this help\n\n");
}

static void print_gen_help(void)
{
    printf("\n Usage: p11sak generate-key [ARGS] [OPTIONS]\n");
    printf("\n Args:\n");
    printf("      des\n");
    printf("      3des\n");
    printf("      aes [128 | 192 | 256]\n");
    printf("      aes-xts [128 | 256]\n");
    printf("      rsa [1024 | 2048 | 4096]\n");
    printf("      ec [prime256v1 | prime192v1 | secp224r1 | secp384r1 | secp521r1 | secp256k1 | \n");
    printf("          brainpoolP160r1 | brainpoolP160t1 | brainpoolP192r1 | brainpoolP192t1 | \n");
    printf("          brainpoolP224r1 | brainpoolP224t1 | brainpoolP256r1 | brainpoolP256t1 | \n");
    printf("          brainpoolP320r1 | brainpoolP320t1 | brainpoolP384r1 | brainpoolP384t1 | \n");
    printf("          brainpoolP512r1 | brainpoolP512t1 | curve25519 | curve448 | ed25519 | \n");
    printf("          ed448]\n");
    printf("      ibm-dilithium [r2_65 | r2_87 | r3_44 | r3_65 | r3_87]\n");
    printf("      ibm-kyber [r2_768 | r2_1024]\n");
    printf("\n Options:\n");
    printf("      --slot SLOTID                           openCryptoki repository token SLOTID.\n");
    printf("      --pin PIN                               pkcs11 user PIN\n");
    printf("      --force-pin-prompt                      enforce user PIN prompt\n");
    printf("      --label LABEL                           key label LABEL to be listed\n");
    printf("      --label PUB_LABEL:PRIV_LABEL\n");
    printf("              for asymmetric keys: set individual labels for public and private key\n");
    printf("      --exponent EXP                          set RSA exponent EXP\n");
    printf("      --attr [M R L S E D G V W U A X N]      set key attributes\n");
    printf("      --attr [[pub_attrs]:[priv_attrs]] \n");
    printf("             for asymmetric keys: set individual key attributes, values see above\n");
    printf("      -h, --help                              Show this help\n\n");
}

static void print_removekeys_help(void)
{
    printf("\n Usage: p11sak remove-key [ARGS] [OPTIONS]\n");
    printf("\n Args:\n");
    printf("      des\n");
    printf("      3des\n");
    printf("      aes\n");
    printf("      aes-xts\n");
    printf("      rsa\n");
    printf("      ec\n");
    printf("      ibm-dilithium\n");
    printf("      ibm-kyber\n");
    printf("\n Options:\n");
    printf("      --slot SLOTID                           openCryptoki repository token SLOTID.\n");
    printf("      --pin PIN                               pkcs11 user PIN\n");
    printf("      --force-pin-prompt                      enforce user PIN prompt\n");
    printf("      --label LABEL                           Key label LABEL to be removed\n");
    printf("      -f, --force                             Force remove all keys of given cipher type\n");
    printf("      -h, --help                              Show this help\n\n");
}

static void print_gen_des_help(void)
{
    printf("\n Options:\n");
    printf("      --slot SLOTID                           openCryptoki repository token SLOTID.\n");
    printf("      --pin PIN                               pkcs11 user PIN\n");
    printf("      --force-pin-prompt                      enforce user PIN prompt\n");
    printf("      --label LABEL                           key label LABEL to be listed\n");
    printf("      --attr [M R L S E D G V W U A X N]      set key attributes\n");
    printf("      -h, --help                              Show this help\n\n");
}

static void print_gen_aes_help(void)
{
    printf("\n Usage: p11sak generate-key aes [ARGS] [OPTIONS]\n");
    printf("\n Args:\n");
    printf("      128\n");
    printf("      192\n");
    printf("      256\n");
    printf("\n Options:\n");
    printf("      --slot SLOTID                           openCryptoki repository token SLOTID.\n");
    printf("      --pin PIN                               pkcs11 user PIN\n");
    printf("      --force-pin-prompt                      enforce user PIN prompt\n");
    printf("      --label LABEL                           key label LABEL to be listed\n");
    printf("      --attr [M R L S E D G V W U A X N]      set key attributes\n");
    printf("      -h, --help                              Show this help\n\n");
}

static void print_gen_aes_xts_help(void)
{
    printf("\n Usage: p11sak generate-key aes-xts [ARGS] [OPTIONS]\n");
    printf("\n Args:\n");
    printf("      128\n");
    printf("      256\n");
    printf("\n Options:\n");
    printf("      --slot SLOTID                           openCryptoki repository token SLOTID.\n");
    printf("      --pin PIN                               pkcs11 user PIN\n");
    printf("      --force-pin-prompt                      enforce user PIN prompt\n");
    printf("      --label LABEL                           key label LABEL to be listed\n");
    printf("      --attr [M R L S E D G V W U A X N]      set key attributes\n");
    printf("      -h, --help                              Show this help\n\n");
}

static void print_gen_rsa_help(void)
{
    printf("\n Usage: p11sak generate-key rsa [ARGS] [OPTIONS] [ARGS]\n");
    printf("\n Args:\n");
    printf("      1024\n");
    printf("      2048\n");
    printf("      4096\n");
    printf("\n Options:\n");
    printf("      --slot SLOTID                           openCryptoki repository token SLOTID.\n");
    printf("      --pin PIN                               pkcs11 user PIN\n");
    printf("      --force-pin-prompt                      enforce user PIN prompt\n");
    printf("      --label LABEL                           key label LABEL to be listed\n");
    printf("      --label PUB_LABEL:PRIV_LABEL\n");
    printf("              for asymmetric keys: set individual labels for public and private key\n");
    printf("      --exponent EXP                          set RSA exponent EXP\n");
    printf("      --attr [S D G U X]                      set key attributes\n");
    printf("      --attr [[pub_attrs]:[priv_attrs]] \n");
    printf("             for asymmetric keys: set individual key attributes, values see above\n");
    printf("      -h, --help                              Show this help\n\n");
}

static void print_gen_ec_help(void)
{
    printf("\n Usage: p11sak generate-key ec [ARGS] [OPTIONS]\n");
    printf("\n Args:\n");
    printf("      prime256v1\n");
    printf("      prime192v1\n");
    printf("      secp224r1\n");
    printf("      secp384r1\n");
    printf("      secp521r1\n");
    printf("      secp265k1\n");
    printf("      brainpoolP160r1\n");
    printf("      brainpoolP160t1\n");
    printf("      brainpoolP192r1\n");
    printf("      brainpoolP192t1\n");
    printf("      brainpoolP224r1\n");
    printf("      brainpoolP224t1\n");
    printf("      brainpoolP256r1\n");
    printf("      brainpoolP256t1\n");
    printf("      brainpoolP320r1\n");
    printf("      brainpoolP320t1\n");
    printf("      brainpoolP384r1\n");
    printf("      brainpoolP384t1\n");
    printf("      brainpoolP512r1\n");
    printf("      brainpoolP512t1\n");
    printf("      curve25519\n");
    printf("      curve448\n");
    printf("      ed25519\n");
    printf("      ed448\n");
    printf("\n Options:\n");
    printf("      --slot SLOTID                           openCryptoki repository token SLOTID.\n");
    printf("      --pin PIN                               pkcs11 user PIN\n");
    printf("      --force-pin-prompt                      enforce user PIN prompt\n");
    printf("      --label LABEL                           key label LABEL to be listed\n");
    printf("      --label PUB_LABEL:PRIV_LABEL\n");
    printf("              for asymmetric keys: set individual labels for public and private key\n");
    printf("      --attr [S D G U X]                      set key attributes\n");
    printf("      --attr [[pub_attrs]:[priv_attrs]] \n");
    printf("             for asymmetric keys: set individual key attributes, values see above\n");
    printf("      -h, --help                              Show this help\n\n");
}

static void print_gen_ibm_dilithium_help(void)
{
    printf("\n Usage: p11sak generate-key ibm-dilithium [ARGS] [OPTIONS]\n");
    printf("\n Args:\n");
    printf("      r2_65\n");
    printf("      r2_87\n");
    printf("      r3_44\n");
    printf("      r3_65\n");
    printf("      r3_87\n");
    printf("\n Options:\n");
    printf("      --slot SLOTID                           openCryptoki repository token SLOTID.\n");
    printf("      --pin PIN                               pkcs11 user PIN\n");
    printf("      --force-pin-prompt                      enforce user PIN prompt\n");
    printf("      --label LABEL                           key label LABEL to be listed\n");
    printf("      --label PUB_LABEL:PRIV_LABEL\n");
    printf("              for asymmetric keys: set individual labels for public and private key\n");
    printf("      --attr [M R L S E D G V W U A X N]      set key attributes\n");
    printf("      --attr [[pub_attrs]:[priv_attrs]] \n");
    printf("             for asymmetric keys: set individual key attributes, values see above\n");
    printf("      -h, --help                              Show this help\n\n");
}

static void print_gen_ibm_kyber_help(void)
{
    printf("\n Usage: p11sak generate-key ibm-kyber [ARGS] [OPTIONS]\n");
    printf("\n Args:\n");
    printf("      r2_768\n");
    printf("      r2_1024\n");
    printf("\n Options:\n");
    printf("      --slot SLOTID                           openCryptoki repository token SLOTID.\n");
    printf("      --pin PIN                               pkcs11 user PIN\n");
    printf("      --force-pin-prompt                      enforce user PIN prompt\n");
    printf("      --label LABEL                           key label LABEL to be listed\n");
    printf("      --label PUB_LABEL:PRIV_LABEL\n");
    printf("              for asymmetric keys: set individual labels for public and private key\n");
    printf("      --attr [M R L S E D G V W U A X N]      set key attributes\n");
    printf("      --attr [[pub_attrs]:[priv_attrs]] \n");
    printf("             for asymmetric keys: set individual key attributes, values see above\n");
    printf("      -h, --help                              Show this help\n\n");
}

/**
 * Print help for generate-key command
 */
static CK_RV print_gen_keys_help(p11sak_kt *kt)
{

    switch (*kt) {
    case kt_DES:
        printf("\n Usage: p11sak generate-key des [ARGS] [OPTIONS]\n");
        print_gen_des_help();
        break;
    case kt_3DES:
        printf("\n Usage: p11sak generate-key 3des [ARGS] [OPTIONS]\n");
        print_gen_des_help();
        break;
    case kt_AES:
        print_gen_aes_help();
        break;
    case kt_AES_XTS:
        print_gen_aes_xts_help();
        break;
    case kt_RSAPKCS:
        print_gen_rsa_help();
        break;
    case kt_EC:
        print_gen_ec_help();
        break;
    case kt_IBM_DILITHIUM:
        print_gen_ibm_dilithium_help();
        break;
    case kt_IBM_KYBER:
        print_gen_ibm_kyber_help();
        break;
    case no_key_type:
        print_gen_help();
        break;
    default:
        print_gen_help();
    }

    return CKR_OK;
}
/**
 * Print help for attributes
 */
static void print_gen_attr_help(void)
{
    printf("\n");
    printf("      Setting CK_ATTRIBUTE\n");
    printf("\n");
    printf("           'P': CKA_PRIVATE\n");
    printf("           'M': CKA_MODIFIABLE\n");
    printf("           'R': CKA_DERIVE\n");
    printf("           'L': CKA_LOCAL\n");
    printf("           'S': CKA_SENSITIVE\n");
    printf("           'E': CKA_ENCRYPT\n");
    printf("           'D': CKA_DECRYPT\n");
    printf("           'G': CKA_SIGN\n");
    printf("           'V': CKA_VERIFY\n");
    printf("           'W': CKA_WRAP\n");
    printf("           'U': CKA_UNWRAP\n");
    printf("           'A': CKA_ALWAYS_SENSITIVE\n");
    printf("           'X': CKA_EXTRACTABLE\n");
    printf("           'N': CKA_NEVER_EXTRACTABLE\n");
    printf("\n");
    printf("           CKA_TOKEN is set by default.\n");
    printf("           If an attribute is not set explicitly, the default values are used.\n");
    printf("           For multiple attributes add char without white space, e. g. 'MLD')\n");
    printf("\n");

    printf("\n");
}
/**
 * Builds an attribute from the given modulus bits and exponent.
 * pubattr >= x elements, prvattr >= y elements
 */
static CK_RV read_rsa_args(CK_ULONG modulusbits, CK_ULONG exponent,
                           CK_ATTRIBUTE *pubattr, CK_ULONG *pubcount)
{
    CK_ULONG *mod_bits;
    CK_ULONG ulpubexp;
    CK_BYTE *pubexp;
    CK_BYTE *spubexp;
    CK_ULONG spubexplen;

    if (!(mod_bits = malloc(sizeof(CK_ULONG)))) {
        fprintf(stderr, "Error: failed to allocate memory for mod_bits.\n");
        return CKR_HOST_MEMORY;
    }
    *mod_bits = modulusbits;

    pubattr[*pubcount].type = CKA_MODULUS_BITS;
    pubattr[*pubcount].pValue = mod_bits;
    pubattr[*pubcount].ulValueLen = sizeof(CK_ULONG);
    (*pubcount)++;

    if (exponent > 0)
        ulpubexp = exponent;
    else
        ulpubexp = 65537; /* default for RSA_PKCS */

    if (!(pubexp = malloc(sizeof(CK_ULONG)))) {
        fprintf(stderr, "Error: failed to allocate memory for public exponent.\n");
        free(mod_bits);
        return CKR_HOST_MEMORY;
    }

    spubexp = CK_ULONG2bigint(ulpubexp, pubexp, &spubexplen);
    pubattr[*pubcount].type = CKA_PUBLIC_EXPONENT;
    pubattr[*pubcount].pValue = spubexp;
    pubattr[*pubcount].ulValueLen = spubexplen;
    (*pubcount)++;

    return CKR_OK;
}
/**
 * Builds the CKA_EC_PARAMS attribute from the given ECcurve.
 */
static CK_RV read_ec_args(const char *ECcurve, CK_ATTRIBUTE *pubattr,
                          CK_ULONG *pubcount, CK_ULONG *keybits)
{
    pubattr[*pubcount].type = CKA_EC_PARAMS;
    if (strcmp(ECcurve, "prime256v1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) prime256v1;
        pubattr[*pubcount].ulValueLen = sizeof(prime256v1);
        *keybits = 256;
    } else if (strcmp(ECcurve, "prime192v1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) prime192v1;
        pubattr[*pubcount].ulValueLen = sizeof(prime192v1);
        *keybits = 192;
    } else if (strcmp(ECcurve, "secp224r1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) secp224r1;
        pubattr[*pubcount].ulValueLen = sizeof(secp224r1);
        *keybits = 224;
    } else if (strcmp(ECcurve, "secp384r1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) secp384r1;
        pubattr[*pubcount].ulValueLen = sizeof(secp384r1);
        *keybits = 384;
    } else if (strcmp(ECcurve, "secp521r1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) secp521r1;
        pubattr[*pubcount].ulValueLen = sizeof(secp521r1);
        *keybits = 521;
    } else if (strcmp(ECcurve, "secp265k1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) secp256k1;
        pubattr[*pubcount].ulValueLen = sizeof(secp256k1);
        *keybits = 256;
    } else if (strcmp(ECcurve, "brainpoolP160r1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP160r1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP160r1);
        *keybits = 160;
    } else if (strcmp(ECcurve, "brainpoolP160t1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP160t1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP160t1);
        *keybits = 160;
    } else if (strcmp(ECcurve, "brainpoolP192r1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP192r1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP192r1);
        *keybits = 192;
    } else if (strcmp(ECcurve, "brainpoolP192t1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP192t1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP192t1);
        *keybits = 192;
    } else if (strcmp(ECcurve, "brainpoolP224r1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP224r1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP224r1);
        *keybits = 224;
    } else if (strcmp(ECcurve, "brainpoolP224t1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP224t1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP224t1);
        *keybits = 224;
    } else if (strcmp(ECcurve, "brainpoolP256r1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP256r1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP256r1);
        *keybits = 256;
    } else if (strcmp(ECcurve, "brainpoolP256t1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP256t1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP256t1);
        *keybits = 256;
    } else if (strcmp(ECcurve, "brainpoolP320r1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP320r1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP320r1);
        *keybits = 320;
    } else if (strcmp(ECcurve, "brainpoolP320t1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP320t1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP320t1);
        *keybits = 320;
    } else if (strcmp(ECcurve, "brainpoolP384r1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP384r1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP384r1);
        *keybits = 384;
    } else if (strcmp(ECcurve, "brainpoolP384t1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP384t1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP384t1);
        *keybits = 384;
    } else if (strcmp(ECcurve, "brainpoolP512r1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP512r1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP512r1);
        *keybits = 512;
    } else if (strcmp(ECcurve, "brainpoolP512t1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP512t1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP512t1);
        *keybits = 512;
    } else if (strcmp(ECcurve, "curve25519") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) curve25519;
        pubattr[*pubcount].ulValueLen = sizeof(curve25519);
        *keybits = 256;
    } else if (strcmp(ECcurve, "curve448") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) curve448;
        pubattr[*pubcount].ulValueLen = sizeof(curve448);
        *keybits = 456;
    } else if (strcmp(ECcurve, "ed25519") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) ed25519;
        pubattr[*pubcount].ulValueLen = sizeof(ed25519);
        *keybits = 256;
    } else if (strcmp(ECcurve, "ed448") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) ed448;
        pubattr[*pubcount].ulValueLen = sizeof(ed448);
        *keybits = 448;
    } else {
        fprintf(stderr, "Unexpected case while parsing EC curves.\n");
        fprintf(stderr, "Note: not all tokens support all curves.\n");
        return CKR_ARGUMENTS_BAD;
    }
    (*pubcount)++;

    return CKR_OK;
}
/**
 * Builds the CKA_IBM_DILITHIUM_KEYFORM attribute from the given version.
 */
static CK_RV read_dilithium_args(const char *dilithium_ver, CK_ULONG *keyform,
                                 CK_ATTRIBUTE *pubattr, CK_ULONG *pubcount)
{
    if (strcasecmp(dilithium_ver, "r2_65") == 0) {
        *keyform = CK_IBM_DILITHIUM_KEYFORM_ROUND2_65;
    } else if (strcasecmp(dilithium_ver, "r2_87") == 0) {
        *keyform = CK_IBM_DILITHIUM_KEYFORM_ROUND2_87;
    } else if (strcasecmp(dilithium_ver, "r3_44") == 0) {
        *keyform =  CK_IBM_DILITHIUM_KEYFORM_ROUND3_44;
    } else if (strcasecmp(dilithium_ver, "r3_65") == 0) {
        *keyform = CK_IBM_DILITHIUM_KEYFORM_ROUND3_65;
    } else if (strcasecmp(dilithium_ver, "r3_87") == 0) {
        *keyform = CK_IBM_DILITHIUM_KEYFORM_ROUND3_87;
    } else {
        fprintf(stderr, "Unexpected case while parsing dilithium version.\n");
        fprintf(stderr, "Note: not all tokens support all versions.\n");
        return CKR_ARGUMENTS_BAD;
    }

    pubattr[*pubcount].type = CKA_IBM_DILITHIUM_KEYFORM;
    pubattr[*pubcount].ulValueLen = sizeof(CK_ULONG);
    pubattr[*pubcount].pValue = keyform;
    (*pubcount)++;

    return CKR_OK;
}
/**
 * Builds the CKA_IBM_KYBER_KEYFORM attribute from the given version.
 */
static CK_RV read_kyber_args(const char *kyber_ver, CK_ULONG *keyform,
                             CK_ATTRIBUTE *pubattr, CK_ULONG *pubcount)
{
    if (strcasecmp(kyber_ver, "r2_768") == 0) {
        *keyform = CK_IBM_KYBER_KEYFORM_ROUND2_768;
    } else if (strcasecmp(kyber_ver, "r2_1024") == 0) {
        *keyform = CK_IBM_KYBER_KEYFORM_ROUND2_1024;
    } else {
        fprintf(stderr, "Unexpected case while parsing kyber version.\n");
        fprintf(stderr, "Note: not all tokens support all versions.\n");
        return CKR_ARGUMENTS_BAD;
    }

    pubattr[*pubcount].type = CKA_IBM_KYBER_KEYFORM;
    pubattr[*pubcount].ulValueLen = sizeof(CK_ULONG);
    pubattr[*pubcount].pValue = keyform;
    (*pubcount)++;

    return CKR_OK;
}
/**
 * Builds two CKA_LABEL attributes from given label.
 * By default the specified label is extended with ":pub" and ":prv" for the
 * public and private key objects.
 * To set 2 different labels for public and private keys, separate them by
 * colon: "pub-label:prv-label".
 * To set the exact same label for public and private key, use "pub-label:="
 * To specify a colon or a equal character within a label, it must be escaped
 * by a back slash:  * "abc\:xyz" results in "abc:xyz".
 */
static CK_RV set_labelpair_attr(const char *label, CK_ATTRIBUTE *pubattr,
                                CK_ULONG *pubcount, CK_ATTRIBUTE *prvattr,
                                CK_ULONG *prvcount)
{
    char *publabel = NULL;
    char *prvlabel = NULL;
    unsigned int i;

    for (i = 0; i < strlen(label); i++) {
        if (label[i] == '\\') {
            i++; /* skip escaped character */
            continue;
        }

        if (label[i] == ':') {
            if (!(publabel = strndup(label, i))) {
                fprintf(stderr, "Error allocating space for publabel\n");
                return CKR_HOST_MEMORY;
            }
            if (!(prvlabel = strdup(&label[i + 1]))) {
                fprintf(stderr, "Error allocating space for prvlabel\n");
                free(publabel);
                return CKR_HOST_MEMORY;
            }
            break;
        }
    }

    if (publabel != NULL && prvlabel != NULL) {
        if (strcmp(prvlabel, "=") == 0) {
            free(prvlabel);
            if (!(prvlabel = strdup(publabel))) {
                fprintf(stderr, "Error allocating space for prvlabel\n");
                free(publabel);
                return CKR_HOST_MEMORY;
            }
        }
    } else {
        if (!(publabel = malloc(strlen(label) + 5))) {
            fprintf(stderr, "Error allocating space for publabel\n");
            return CKR_HOST_MEMORY;
        }
        publabel = strcpy(publabel, label);
        publabel = strcat(publabel, ":pub");

        if (!(prvlabel = malloc(strlen(label) + 5))) {
            fprintf(stderr, "Error allocating space for prvlabel\n");
            free(publabel);
            return CKR_HOST_MEMORY;
        }
        prvlabel = strcpy(prvlabel, label);
        prvlabel = strcat(prvlabel, ":prv");
    }

    for (i = 0; i < strlen(publabel); i++) {
        if (publabel[i] == '\\')
            memmove(&publabel[i], &publabel[i + 1],
                    strlen(&publabel[i + 1]) + 1);
    }

    for (i = 0; i < strlen(prvlabel); i++) {
        if (prvlabel[i] == '\\')
            memmove(&prvlabel[i], &prvlabel[i + 1],
                    strlen(&prvlabel[i + 1]) + 1);
    }

    pubattr[*pubcount].type = CKA_LABEL;
    pubattr[*pubcount].pValue = publabel;
    pubattr[*pubcount].ulValueLen = strlen(publabel);
    (*pubcount)++;

    prvattr[*prvcount].type = CKA_LABEL;
    prvattr[*prvcount].pValue = prvlabel;
    prvattr[*prvcount].ulValueLen = strlen(prvlabel);
    (*prvcount)++;

    return CKR_OK;
}
/**
 * Set mechanism according to given key type.
 */
static CK_RV key_pair_gen_mech(p11sak_kt kt, CK_MECHANISM *pmech)
{
    pmech->pParameter = NULL_PTR;
    pmech->ulParameterLen = 0;
    switch (kt) {
    case kt_DES:
        pmech->mechanism = CKM_DES_KEY_GEN;
        break;
    case kt_3DES:
        pmech->mechanism = CKM_DES3_KEY_GEN;
        break;
    case kt_AES:
        pmech->mechanism = CKM_AES_KEY_GEN;
        break;
    case kt_AES_XTS:
        pmech->mechanism = CKM_AES_XTS_KEY_GEN;
        break;
    case kt_RSAPKCS:
        pmech->mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
        break;
    case kt_EC:
        pmech->mechanism = CKM_EC_KEY_PAIR_GEN;
        break;
    case kt_IBM_DILITHIUM:
        pmech->mechanism = CKM_IBM_DILITHIUM;
        break;
    case kt_IBM_KYBER:
        pmech->mechanism = CKM_IBM_KYBER;
        break;
    default:
        return CKR_MECHANISM_INVALID;
        break;
    }

    return CKR_OK;
}

/**
 * returns 1 if the given attribute is not applicable for the
 * given key type, 0 otherwise.
 */
static CK_BBOOL attr_na(const CK_ULONG attr_type, p11sak_kt ktype)
{
    switch (ktype) {
    case kt_DES:
    case kt_3DES:
    case kt_AES:
    case kt_AES_XTS:
    case kt_SECRET:
        switch (attr_type) {
        case CKA_TRUSTED:
            return 1;
        default:
            return 0;
        }
        break;
    case kt_PUBLIC:
        switch (attr_type) {
        case CKA_SENSITIVE:
        case CKA_DECRYPT:
        case CKA_SIGN:
        case CKA_UNWRAP:
        case CKA_EXTRACTABLE:
        case CKA_ALWAYS_SENSITIVE:
        case CKA_NEVER_EXTRACTABLE:
            return 1;
        default:
            return 0;
        }
        break;
    case kt_PRIVATE:
        switch (attr_type) {
        case CKA_ENCRYPT:
        case CKA_VERIFY:
        case CKA_WRAP:
            return 1;
        default:
            return 0;
        }
        break;
    default:
        /* key type not handled here */
        return 0;
    }
}

static CK_ULONG char2attrtype(char c)
{
    switch (c) {
    case 'T':
        return CKA_TOKEN;
    case 'P':
        return CKA_PRIVATE;
    case 'M':
        return CKA_MODIFIABLE;
    case 'R':
        return CKA_DERIVE;
    case 'L':
        return CKA_LOCAL;
    case 'S':
        return CKA_SENSITIVE;
    case 'E':
        return CKA_ENCRYPT;
    case 'D':
        return CKA_DECRYPT;
    case 'G':
        return CKA_SIGN;
    case 'V':
        return CKA_VERIFY;
    case 'W':
        return CKA_WRAP;
    case 'U':
        return CKA_UNWRAP;
    case 'X':
        return CKA_EXTRACTABLE;
    case 'A':
        return CKA_ALWAYS_SENSITIVE;
    case 'N':
        return CKA_NEVER_EXTRACTABLE;
    default:
        return 0;
    }
}

static void set_bool_attr_from_string(CK_ATTRIBUTE *attr, char attr_char)
{
    if (!attr_char) 
        return;
    
    attr->type = char2attrtype(toupper(attr_char));
    attr->ulValueLen = sizeof(CK_BBOOL);
    if (isupper(attr_char) == 0) {
        attr->pValue = &ckb_false;
    } else {
        attr->pValue = &ckb_true;
    }
}

/**
 * Set default asymmetric key attributes.
 */
static CK_RV set_battr(const char *attr_string, CK_ATTRIBUTE *attr, 
                        CK_ULONG *count, int prv)
{
    int i = 0;

    attr[*count].type = CKA_TOKEN;
    attr[*count].pValue = &ckb_true;
    attr[*count].ulValueLen = sizeof(CK_BBOOL);
    (*count)++;

    if (attr_string) {
        for (i = 0; i < (int) strlen(attr_string); i++) {
            // attr_string length is checked in parse_gen_key_args to avoid memory problems
            if (prv == 1 && attr_na(char2attrtype(toupper(attr_string[i])), kt_PRIVATE) == 0) {
                set_bool_attr_from_string(&attr[*count], attr_string[i]);
                (*count)++;
            } 
            if (prv == 0 && attr_na(char2attrtype(toupper(attr_string[i])), kt_PUBLIC) == 0) {
                set_bool_attr_from_string(&attr[*count], attr_string[i]);
                (*count)++;
            }
        }
    }
    return CKR_OK;
}

CK_BBOOL is_rejected_by_policy(CK_RV ret_code, CK_SESSION_HANDLE session)
{
    CK_SESSION_INFO info;
    CK_RV rc;

    if (ret_code != CKR_FUNCTION_FAILED)
        return CK_FALSE;

    rc = funcs->C_GetSessionInfo(session, &info);
    if (rc != CKR_OK) {
        fprintf(stderr, "C_GetSessionInfo failed (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        return CK_FALSE;
    }

    return (info.ulDeviceError == CKR_POLICY_VIOLATION) ? CK_TRUE : CK_FALSE;
}

CK_BBOOL is_mech_supported(CK_SLOT_ID slot, CK_MECHANISM *pmech,
                           CK_ULONG keybits)
{
    CK_MECHANISM_INFO mech_info;
    int rc;

    rc = funcs->C_GetMechanismInfo(slot, pmech->mechanism, &mech_info);
    if (rc != CKR_OK)
        return CK_FALSE;

    if ((mech_info.flags & (CKF_GENERATE | CKF_GENERATE_KEY_PAIR)) == 0)
        return CK_FALSE;

    if (keybits > 0) {
        switch (pmech->mechanism) {
        case CKM_DES_KEY_GEN:
        case CKM_DES3_KEY_GEN:
        case CKM_AES_KEY_GEN:
        case CKM_AES_XTS_KEY_GEN:
            keybits /= 8; /* mechinfo reports key size in bytes */
            break;
        }

        if (mech_info.ulMinKeySize == 0 && mech_info.ulMaxKeySize == 0)
            return CK_TRUE;
        if (mech_info.ulMinKeySize > keybits)
            return CK_FALSE;
        if (mech_info.ulMaxKeySize < keybits)
            return CK_FALSE;
    }

    return CK_TRUE;
}

/**
 * Generation of the symmetric key
 */
static CK_RV tok_key_gen(CK_SESSION_HANDLE session, CK_SLOT_ID slot,
                         CK_ULONG keylength, CK_MECHANISM *pmech,
                         char *attr_string, CK_OBJECT_HANDLE *phkey,
                         char *label)
{
    CK_RV rc;
    int i = 0;

    /* Boolean attributes (cannot be specified by user) */
    CK_BBOOL a_token = ckb_true; // always true

    /* Non-boolean attributes */
    CK_ULONG a_value_len = keylength / 8;

    /* Standard template */
    CK_ATTRIBUTE key_attr[3 + KEY_MAX_BOOL_ATTR_COUNT] = {
        { CKA_TOKEN, &a_token, sizeof(CK_BBOOL) }, 
        { CKA_VALUE_LEN, &a_value_len, sizeof(CK_ULONG) }, 
        { CKA_LABEL, label, strlen(label) } 
    };
    CK_ULONG num_attrs = 3;
    
    /* set boolean attributes, set template from string 
    attr_string length is checked in parse_gen_key_args to avoid memory problems */
    if (attr_string) {
        for (i = 0; i < (int) strlen(attr_string); i++) {
            set_bool_attr_from_string(&key_attr[i+num_attrs], attr_string[i]);
        }
        num_attrs += strlen(attr_string);
    }
    
    if (!is_mech_supported(slot, pmech, keylength)) {
        fprintf(stderr, "Key generation mechanism %s with key length %lu is not supported by slot %lu\n",
                p11_get_ckm(&mechtable_funcs, pmech->mechanism), a_value_len,
                slot);
        return CKR_MECHANISM_INVALID;
    }

    /* generate key */
    rc = funcs->C_GenerateKey(session, pmech, key_attr, num_attrs, phkey);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, session)) {
            fprintf(stderr, "Key generation of key of length %lu bytes is rejected by policy\n",
                    a_value_len);
        } else {
            fprintf(stderr, "Key generation of key of length %lu bytes failed\n",
                    a_value_len);
            fprintf(stderr, "in tok_key_gen() (error code 0x%lX: %s)\n", rc,
                    p11_get_ckr(rc));
        }
    }
    return rc;
}
/**
 * Generation of the asymmetric key pair
 */
static CK_RV key_pair_gen(CK_SESSION_HANDLE session, CK_SLOT_ID slot,
                          p11sak_kt kt, CK_MECHANISM_PTR pmech,
                          CK_ATTRIBUTE *pubattr, CK_ULONG pubcount,
                          CK_ATTRIBUTE *prvattr, CK_ULONG prvcount,
                          CK_OBJECT_HANDLE_PTR phpubkey,
                          CK_OBJECT_HANDLE_PTR phprvkey, CK_ULONG keybits)
{
    CK_RV rc;

    printf("Generate asymmetric key: %s\n", kt2str(kt));

    if (!is_mech_supported(slot, pmech, keybits)) {
        fprintf(stderr, "Key generation mechanism %s with key length %lu is not supported by slot %lu\n",
                p11_get_ckm(&mechtable_funcs, pmech->mechanism), keybits, slot);
        return CKR_MECHANISM_INVALID;
    }

    rc = funcs->C_GenerateKeyPair(session, pmech, pubattr, pubcount, prvattr,
            prvcount, phpubkey, phprvkey);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, session))
            fprintf(stderr, "Key pair generation rejected by policy\n");
        else if (kt == kt_IBM_DILITHIUM && rc == CKR_KEY_SIZE_RANGE)
            fprintf(stderr, "IBM Dilithum version is not supported\n");
        else if (kt == kt_IBM_KYBER && rc == CKR_KEY_SIZE_RANGE)
            fprintf(stderr, "IBM Kyber version is not supported\n");
        else
            fprintf(stderr, "Key pair generation failed (error code 0x%lX: %s)\n", rc,
                    p11_get_ckr(rc));
        return rc;
    }

    printf("Asymmetric key pair generation successful!\n");

    return CKR_OK;
}
/**
 * Initialize key object list
 */
static CK_RV tok_key_list_init(CK_SESSION_HANDLE session, p11sak_kt kt,
                               char *label)
{
    CK_RV rc;
    CK_ULONG count = 0;

    /* Boolean Attributes */
    CK_BBOOL a_token;
    CK_ULONG bs = sizeof(CK_BBOOL);

    /* key Type attributes */
    CK_KEY_TYPE a_key_type;
    CK_OBJECT_CLASS a_cko;

    CK_ATTRIBUTE tmplt[3];

    a_token = CK_TRUE;
    tmplt[count].type = CKA_TOKEN;
    tmplt[count].pValue = &a_token;
    tmplt[count].ulValueLen = bs;
    count++;

    if (kt < kt_SECRET) {
        rc = kt2CKK(kt, &a_key_type);
        if (rc != CKR_OK) {
            fprintf(stderr, "Keytype could not be set (error code 0x%lX: %s)\n", rc,
                    p11_get_ckr(rc));
            return rc;
        }
    } else if (kt != kt_ALL) {
        rc = kt2CKO(kt, &a_cko);
        if (rc != CKR_OK) {
            fprintf(stderr, "Keyobject could not be set (error code 0x%lX: %s)\n", rc,
                    p11_get_ckr(rc));
            return rc;
        }
    }

    /* Set template */
    switch (kt) {
    case kt_DES:
    case kt_3DES:
    case kt_AES:
    case kt_AES_XTS:
    case kt_GENERIC:
    case kt_RSAPKCS:
    case kt_EC:
    case kt_IBM_DILITHIUM:
    case kt_IBM_KYBER:
        tmplt[count].type = CKA_KEY_TYPE;
        tmplt[count].pValue = &a_key_type;
        tmplt[count].ulValueLen = sizeof(CK_KEY_TYPE);
        count++;
        break;
    case kt_SECRET:
    case kt_PUBLIC:
    case kt_PRIVATE:
        tmplt[count].type = CKA_CLASS;
        tmplt[count].pValue = &a_cko;
        tmplt[count].ulValueLen = sizeof(CK_OBJECT_CLASS);
        count++;
        break;
    case kt_ALL:
        break;
    default:
        fprintf(stderr, "Unknown key type\n");
        return CKR_ARGUMENTS_BAD;
    }

    if (label != NULL_PTR) {
        tmplt[count].type = CKA_LABEL;
        tmplt[count].pValue = label;
        tmplt[count].ulValueLen = strlen(label);
        count++;
    }

    rc = funcs->C_FindObjectsInit(session, tmplt, count);
    if (rc != CKR_OK) {
        fprintf(stderr, "C_FindObjectInit failed\n");
        fprintf(stderr, "in tok_key_list_init() (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        return rc;
    }

    return CKR_OK;
}

/**
 * Columns: T  P  M  R  L  S  E  D  G  V  W  U  X  A  N  *
 */
static CK_ATTRIBUTE_TYPE col2type(int col)
{
    switch (col) {
    case 0:
        return CKA_TOKEN;
    case 1:
        return CKA_PRIVATE;
    case 2:
        return CKA_MODIFIABLE;
    case 3:
        return CKA_DERIVE;
    case 4:
        return CKA_LOCAL;
    case 5:
        return CKA_SENSITIVE;
    case 6:
        return CKA_ENCRYPT;
    case 7:
        return CKA_DECRYPT;
    case 8:
        return CKA_SIGN;
    case 9:
        return CKA_VERIFY;
    case 10:
        return CKA_WRAP;
    case 11:
        return CKA_UNWRAP;
    case 12:
        return CKA_EXTRACTABLE;
    case 13:
        return CKA_ALWAYS_SENSITIVE;
    case 14:
        return CKA_NEVER_EXTRACTABLE;
    default:
        return 0;
    }
}

/**
 *  Print in p11sak_defined_attrs.conf defined attributes in long format
 */
static CK_RV print_custom_attrs(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE hkey, int long_print) 
{
    CK_RV rc = CKR_OK;
    int f;
    struct ConfigBaseNode *c, *name, *hex_string, *type;
    struct ConfigStructNode *structnode;
    int def_attr = 0;
    
    if (cfg != NULL)
    {
        confignode_foreach(c, cfg, f) {
            if (confignode_hastype(c, CT_STRUCT) && strcmp(c->key, "attribute") == 0) {
                // parse...
                structnode = confignode_to_struct(c);
                name = confignode_find(structnode->value, "name");
                hex_string = confignode_find(structnode->value, "id");
                type = confignode_find(structnode->value, "type");

                // checking syntax of attribute...
                if (name == NULL) {
                    fprintf(stderr, "Missing name in Attribute in line %hu\n", c->line);
                    return CKR_DATA_INVALID;
                } else if (!confignode_hastype(name, CT_BAREVAL)) {
                    fprintf(stderr, "Invalid name in Attribute in line %hu\n", name->line);
                    return CKR_DATA_INVALID;
                } else if (hex_string == NULL) {
                    fprintf(stderr, "Missing value in Attribute in line %hu\n", c->line);
                    return CKR_DATA_INVALID;
                } else if (!confignode_hastype(hex_string, CT_INTVAL)) {
                    fprintf(stderr, "Invalid name in Attribute in line %hu\n", hex_string->line);
                    return CKR_DATA_INVALID;
                } else if (type == NULL) {
                    fprintf(stderr, "Missing type in Attribute in line %hu\n", c->line);
                    return CKR_DATA_INVALID;
                } else if (!confignode_hastype(type, CT_BAREVAL)) {
                    fprintf(stderr, "Invalid name in Attribute in line %hu\n", type->line);
                    return CKR_DATA_INVALID;
                }

                def_attr = 1;
                
                // print attribute by type
                unsigned int hex = confignode_to_intval(hex_string)->value;
                if (strcmp(confignode_to_bareval(type)->value, "CK_BBOOL") == 0) {
                    // build template
                    CK_BBOOL a_bool;
                    CK_ATTRIBUTE temp = {hex, &a_bool, sizeof(a_bool)};

                    // get attribute value
                    rc = funcs->C_GetAttributeValue(session, hkey, &temp, 1);
                    if (rc == CKR_OK) {
                        if (temp.ulValueLen != sizeof(CK_BBOOL)) {
                            fprintf(stderr, " Error in retrieving Attribute %s: %lu\n",
                                    confignode_to_bareval(name)->value, temp.ulValueLen);
                        } else {
                            if (long_print) {
                                printf("          %s: %s\n", confignode_to_bareval(name)->value,
                                        CK_BBOOL2a(*(CK_BBOOL*) temp.pValue));
                            } else if (strcmp(CK_BBOOL2a(*(CK_BBOOL*) temp.pValue), "CK_TRUE") == 0) {
                                printf(" 1 ");
                                return CKR_OK;
                            }
                        }    
                    } else if (rc == CKR_ATTRIBUTE_SENSITIVE && long_print) {
                        printf("          %s: SENSITIVE\n", confignode_to_bareval(name)->value);
                    } else if (rc != CKR_ATTRIBUTE_TYPE_INVALID) {
                        return rc;
                    } 
                } else if (strcmp((confignode_to_bareval(type)->value), "CK_ULONG") == 0) {
                    // build template
                    CK_ULONG a_ulong;
                    CK_ATTRIBUTE temp = {hex, &a_ulong, sizeof(a_ulong)};

                    // get attribute value
                    rc = funcs->C_GetAttributeValue(session, hkey, &temp, 1);
                    if (rc == CKR_OK) {
                        if (temp.ulValueLen != sizeof(CK_ULONG)) {
                            fprintf(stderr, " Error in retrieving Attribute %s: %lu\n",
                                    confignode_to_bareval(name)->value, temp.ulValueLen);
                        } else {
                            if (long_print) {
                                printf("          %s: %lu (0x%lX)\n", confignode_to_bareval(name)->value, 
                                        *(CK_ULONG*) temp.pValue, *(CK_ULONG*) temp.pValue);    
                            } else {
                                printf(" 1 ");
                                return CKR_OK;
                            }
                        }    
                    } else if (rc == CKR_ATTRIBUTE_SENSITIVE && long_print) {
                        printf("          %s: SENSITIVE\n", confignode_to_bareval(name)->value);
                    } else if (rc != CKR_ATTRIBUTE_TYPE_INVALID) {
                        return rc;
                    } 
                } else if (strcmp((confignode_to_bareval(type)->value), "CK_BYTE") == 0) {
                    // get length 
                    CK_ATTRIBUTE temp = {hex, NULL, 0};
                    rc = funcs->C_GetAttributeValue(session, hkey, &temp, 1);
                    if (rc == CKR_ATTRIBUTE_SENSITIVE && long_print) {
                        printf("          %s: SENSITIVE\n", confignode_to_bareval(name)->value);
                    } else if (rc != CKR_ATTRIBUTE_TYPE_INVALID && rc != CKR_OK) {
                        return rc;
                    } else if (rc == CKR_OK && temp.ulValueLen != CK_UNAVAILABLE_INFORMATION) {
                        // build template
                        unsigned long a_byte_array = temp.ulValueLen;
                        temp.pValue = malloc(a_byte_array);
                        if (!temp.pValue) {
                            fprintf(stderr, "Error: cannot malloc storage for attribute value.\n");
                            return CKR_HOST_MEMORY;
                        }

                        // get attribute value
                        rc = funcs->C_GetAttributeValue(session, hkey, &temp, 1);
                        if (rc == CKR_OK) {
                            if (temp.ulValueLen != a_byte_array) {
                                fprintf(stderr, " Error in retrieving Attribute %s: %lu\n",
                                        confignode_to_bareval(name)->value, temp.ulValueLen);
                            } else {
                                if (long_print) {
                                    dump_attr(&temp);
                                } else {
                                    printf(" 1 ");
                                    free(temp.pValue);
                                    return CKR_OK;
                                }
                            }    
                        } 
                        free(temp.pValue);
                    } 
                } else {
                    fprintf(stderr, "Error: Attribute type [%s] invalid.\n", confignode_to_bareval(type)->value);
                }
            } 
        }
    }
    if (!long_print)
        printf(" %s ", def_attr ? "0" : "-");
    
    return CKR_OK;
}

/**
 *  Print standard attributes 
 */
static void short_print(int col, CK_ATTRIBUTE attr[], p11sak_kt ktype)
{
    int j = 0;
    int attr_count = 0;

    switch (ktype) {
    case kt_SECRET:
        attr_count = SEC_KEY_MAX_BOOL_ATTR_COUNT;
        break;
    case kt_PUBLIC:
        attr_count = PUB_KEY_MAX_BOOL_ATTR_COUNT;
        break;
    case kt_PRIVATE:
        attr_count = PRV_KEY_MAX_BOOL_ATTR_COUNT;
        break;
    default:
        attr_count = PUB_KEY_MAX_BOOL_ATTR_COUNT;
    }

    for (j = 0; j < attr_count; j++) {
        if (attr[j].type == col2type(col) && !attr_na(attr[j].type, ktype)) {
            printf(" %d ", *(CK_BBOOL*) attr[j].pValue);
            return;
        }
    }

    printf(" - ");
    return;
}
/**
 * Print attributes of secure keys
 */
static CK_RV sec_key_print_attributes(CK_SESSION_HANDLE session,
                                      CK_OBJECT_HANDLE hkey, int long_print)
{
    CK_RV rc;
    int i;

    /* Boolean Attributes */
    CK_BBOOL a_token;
    CK_BBOOL a_private;
    CK_BBOOL a_modifiable;
    CK_BBOOL a_derive;
    CK_BBOOL a_local;
    CK_BBOOL a_sensitive;
    CK_BBOOL a_encrypt;
    CK_BBOOL a_decrypt;
    CK_BBOOL a_sign;
    CK_BBOOL a_verify;
    CK_BBOOL a_wrap;
    CK_BBOOL a_unwrap;
    CK_BBOOL a_extractable;
    CK_BBOOL a_always_sensitive;
    CK_BBOOL a_never_extractable;

    CK_ATTRIBUTE bool_tmplt[] = { 
        { CKA_TOKEN, &a_token, sizeof(a_token) }, 
        { CKA_PRIVATE, &a_private, sizeof(a_private) }, 
        { CKA_MODIFIABLE, &a_modifiable, sizeof(a_modifiable) }, 
        { CKA_DERIVE, &a_derive, sizeof(a_derive) }, 
        { CKA_LOCAL, &a_local, sizeof(a_local) }, 
        { CKA_SENSITIVE, &a_sensitive, sizeof(a_sensitive) }, 
        { CKA_ENCRYPT, &a_encrypt, sizeof(a_encrypt) }, 
        { CKA_DECRYPT, &a_decrypt, sizeof(a_decrypt) }, 
        { CKA_SIGN, &a_sign, sizeof(a_sign) }, 
        { CKA_VERIFY, &a_verify, sizeof(a_verify) }, 
        { CKA_WRAP, &a_wrap, sizeof(a_wrap) }, 
        { CKA_UNWRAP, &a_unwrap, sizeof(a_unwrap) }, 
        { CKA_EXTRACTABLE, &a_extractable, sizeof(a_extractable) }, 
        { CKA_ALWAYS_SENSITIVE, &a_always_sensitive, sizeof(a_always_sensitive) }, 
        { CKA_NEVER_EXTRACTABLE, &a_never_extractable, sizeof(a_never_extractable) } };
    CK_ULONG count = sizeof(bool_tmplt) / sizeof(CK_ATTRIBUTE);

    rc = funcs->C_GetAttributeValue(session, hkey, bool_tmplt, count);
    if (rc != CKR_OK) {
        fprintf(stderr, "Attribute retrieval failed (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        return rc;
    }

    if (long_print) {
        for (i = 0; i < (int) count; i++) {
            if (bool_tmplt[i].ulValueLen != sizeof(CK_BBOOL)) {
                fprintf(stderr, " Error in retrieving Attribute %s\n",
                        CKA2a(bool_tmplt[i].type));
            } else {
                printf("          %s: %s\n", CKA2a(bool_tmplt[i].type),
                        CK_BBOOL2a(*(CK_BBOOL*) bool_tmplt[i].pValue));
            }
        }
        rc = print_custom_attrs(session, hkey, long_print);
        if (rc != CKR_OK) {
            fprintf(stderr, "Attribute retrieval failed (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
            return rc;
        }
    } else {
        printf(" |");
        for (i = 1; i < KEY_MAX_BOOL_ATTR_COUNT; i++)
            short_print(i, bool_tmplt, kt_SECRET);
        rc = print_custom_attrs(session, hkey, long_print);
        if (rc != CKR_OK) {
            fprintf(stderr, "Attribute retrieval failed (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
            return rc;
        }
        printf("|");
    }

    return CKR_OK;
}
/**
 * Print attributes of private keys
 */
static CK_RV priv_key_print_attributes(CK_SESSION_HANDLE session,
                                       CK_OBJECT_HANDLE hkey, int long_print)
{
    CK_RV rc;
    int i = 0;

    /* Boolean Attributes */
    CK_BBOOL a_token;
    CK_BBOOL a_private;
    CK_BBOOL a_modifiable;
    CK_BBOOL a_derive;
    CK_BBOOL a_local;
    CK_BBOOL a_sensitive;
    CK_BBOOL a_decrypt;
    CK_BBOOL a_sign;
    CK_BBOOL a_unwrap;
    CK_BBOOL a_extractable;
    CK_BBOOL a_always_sensitive;
    CK_BBOOL a_never_extractable;

    CK_ATTRIBUTE bool_tmplt[] = { 
        { CKA_TOKEN, &a_token, sizeof(a_token) }, 
        { CKA_PRIVATE, &a_private, sizeof(a_private) }, 
        { CKA_MODIFIABLE, &a_modifiable, sizeof(a_modifiable) }, 
        { CKA_DERIVE, &a_derive, sizeof(a_derive) }, 
        { CKA_LOCAL, &a_local, sizeof(a_local) }, 
        { CKA_SENSITIVE, &a_sensitive, sizeof(a_sensitive) }, 
        { CKA_DECRYPT, &a_decrypt, sizeof(a_decrypt) }, 
        { CKA_SIGN, &a_sign, sizeof(a_sign) }, 
        { CKA_UNWRAP, &a_unwrap, sizeof(a_unwrap) }, 
        { CKA_EXTRACTABLE, &a_extractable, sizeof(a_extractable) }, 
        { CKA_ALWAYS_SENSITIVE, &a_always_sensitive, sizeof(a_always_sensitive) }, 
        { CKA_NEVER_EXTRACTABLE, &a_never_extractable, sizeof(a_never_extractable) } };
    CK_ULONG count = sizeof(bool_tmplt) / sizeof(CK_ATTRIBUTE);

    rc = funcs->C_GetAttributeValue(session, hkey, bool_tmplt, count);
    if (rc != CKR_OK) {
        fprintf(stderr, "Attribute retrieval failed (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        return rc;
    }

    /* Long print */
    if (long_print) {
        for (i = 0; i < (int) count; i++) {
            if (bool_tmplt[i].ulValueLen != sizeof(CK_BBOOL)) {
                fprintf(stderr, " Error in retrieving Attribute %s\n",
                        CKA2a(bool_tmplt[i].type));
            } else {
                printf("          %s: %s\n", CKA2a(bool_tmplt[i].type),
                        CK_BBOOL2a(*(CK_BBOOL*) bool_tmplt[i].pValue));
            }
        }
        rc = print_custom_attrs(session, hkey, long_print);
        if (rc != CKR_OK) {
            fprintf(stderr, "Attribute retrieval failed (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
            return rc;
        }
    } else {
        /* Short print */
        printf(" |");
        for (i = 1; i < KEY_MAX_BOOL_ATTR_COUNT; i++)
            short_print(i, bool_tmplt, kt_PRIVATE);
        rc = print_custom_attrs(session, hkey, long_print);
        if (rc != CKR_OK) {
            fprintf(stderr, "Attribute retrieval failed (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
            return rc;
        }
        printf("|");
    }

    return CKR_OK;
}
/**
 * Print attributes of public keys
 */
static CK_RV pub_key_print_attributes(CK_SESSION_HANDLE session,
                                      CK_OBJECT_HANDLE hkey, int long_print)
{
    CK_RV rc;
    int i = 0;

    /* Boolean Attributes */
    CK_BBOOL a_token;
    CK_BBOOL a_private;
    CK_BBOOL a_modifiable;
    CK_BBOOL a_derive;
    CK_BBOOL a_local;
    CK_BBOOL a_encrypt;
    CK_BBOOL a_verify;
    CK_BBOOL a_wrap;

    CK_ATTRIBUTE bool_tmplt[] = { 
        { CKA_TOKEN, &a_token, sizeof(a_token) }, 
        { CKA_PRIVATE, &a_private, sizeof(a_private) }, 
        { CKA_MODIFIABLE, &a_modifiable, sizeof(a_modifiable) }, 
        { CKA_DERIVE, &a_derive, sizeof(a_derive) }, 
        { CKA_LOCAL, &a_local, sizeof(a_local) }, 
        { CKA_ENCRYPT, &a_encrypt, sizeof(a_encrypt) }, 
        { CKA_VERIFY, &a_verify, sizeof(a_verify) }, 
        { CKA_WRAP, &a_wrap, sizeof(a_wrap) }, };
    CK_ULONG count = sizeof(bool_tmplt) / sizeof(CK_ATTRIBUTE);

    rc = funcs->C_GetAttributeValue(session, hkey, bool_tmplt, count);
    if (rc != CKR_OK) {
        fprintf(stderr, "Attribute retrieval failed (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        return rc;
    }

    /* Long print */
    if (long_print) {
        for (i = 0; i < (int) count; i++) {
            if (bool_tmplt[i].ulValueLen != sizeof(CK_BBOOL)) {
                fprintf(stderr, " Error in retrieving Attribute %s\n",
                        CKA2a(bool_tmplt[i].type));
            } else {
                printf("          %s: %s\n", CKA2a(bool_tmplt[i].type),
                        CK_BBOOL2a(*(CK_BBOOL*) bool_tmplt[i].pValue));
            }
        }
        rc = print_custom_attrs(session, hkey, long_print);
        if (rc != CKR_OK) {
            fprintf(stderr, "Attribute retrieval failed (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
            return rc;
        }
    } else {
        /* Short print */
        printf(" |");
        for (i = 1; i < KEY_MAX_BOOL_ATTR_COUNT; i++)
            short_print(i, bool_tmplt, kt_PUBLIC);
        rc = print_custom_attrs(session, hkey, long_print);
        if (rc != CKR_OK) {
            fprintf(stderr, "Attribute retrieval failed (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
            return rc;
        }
        printf("|");
    }

    return CKR_OK;
}

/**
 * Alloc attribute
 */
static CK_RV tok_attribute_alloc(CK_SESSION_HANDLE session,
                                 CK_OBJECT_HANDLE hkey,
                                 CK_ATTRIBUTE_PTR attribute)
{
    CK_RV rv;
    void *tmp;

    if (!attribute)
        return CKR_ARGUMENTS_BAD;

    if (attribute->pValue)
        return CKR_CANCEL;

    if (attribute->ulValueLen)
        goto alloc;

    /* lookup size */
    rv = funcs->C_GetAttributeValue(session, hkey, attribute, 1);
    if ((rv == CKR_ATTRIBUTE_SENSITIVE) ||
        (attribute->ulValueLen == 0) ||
        (attribute->ulValueLen == CK_UNAVAILABLE_INFORMATION)) {
        /**
         * REVISIT if the attribute is not available, the first
         * returns with ulValueLen == 0. According to the spec a
         * return value CKR_ATTRIBUTE_SENSITIVE is expected. Check
         * implementation and spec for clarification.
         **/
        attribute->pValue = NULL_PTR;
        attribute->ulValueLen = 0;
        return CKR_ATTRIBUTE_SENSITIVE;
    }
    if (rv != CKR_OK) {
        fprintf(stderr,
                "Object can not lookup attribute length "
                "(error code 0x%lX: %s)\n", rv, p11_get_ckr(rv));
        return rv;
    }

alloc:
    tmp = malloc((size_t) attribute->ulValueLen);
    if (!tmp)
        return CKR_HOST_MEMORY;

    attribute->pValue = tmp;

    return CKR_OK;
}

/**
 * Get label attribute of key
 */
static CK_RV tok_key_get_label_attr(CK_SESSION_HANDLE session,
                                    CK_OBJECT_HANDLE hkey, char **plabel)
{
    CK_RV rc;
    char *label;
    CK_ATTRIBUTE template[1] = { { CKA_LABEL, NULL_PTR, 0 } };
    CK_ULONG label_len;

    rc = funcs->C_GetAttributeValue(session, hkey, template, 1);
    if (rc != CKR_OK) {
        fprintf(stderr, "Key cannot show CKA_LABEL attribute (error code 0x%lX: %s)\n",
                rc, p11_get_ckr(rc));
        return rc;
    }

    if (template[0].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
        /* assume empty label */
        *plabel = strdup("");
        if (!*plabel) {
            fprintf(stderr, "Error: cannot malloc storage for label.\n");
            return CKR_HOST_MEMORY;
        }
        return CKR_OK;
    }

    label_len = template[0].ulValueLen;
    label = malloc(label_len + 1);
    if (!label) {
        fprintf(stderr, "Error: cannot malloc storage for label.\n");
        return CKR_HOST_MEMORY;
    }

    template[0].pValue = label;
    rc = funcs->C_GetAttributeValue(session, hkey, template, 1);
    if (rc != CKR_OK) {
        fprintf(stderr, "Error retrieving CKA_LABEL attribute (error code 0x%lX: %s)\n",
                rc, p11_get_ckr(rc));
        free(label);
        return rc;
    }

    label[label_len] = 0;
    *plabel = label;

    return CKR_OK;
}
/**
 * Get key type
 */
static CK_RV tok_key_get_key_type(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE hkey,
                                  CK_OBJECT_CLASS *keyclass, char **ktype,
                                  CK_ULONG *klength)
{
    CK_RV rc;
    char *buffer;
    CK_OBJECT_CLASS oclass;
    CK_KEY_TYPE kt;
    CK_ULONG vl;

    CK_ATTRIBUTE template[1] =
            { { CKA_CLASS, &oclass, sizeof(CK_OBJECT_CLASS) } };

    rc = funcs->C_GetAttributeValue(session, hkey, template, 1);
    if (rc != CKR_OK) {
        fprintf(stderr, 
                "Object does not have CKA_CLASS attribute (error code 0x%lX: %s)\n",
                rc, p11_get_ckr(rc));
        return rc;
    }

    // the buffer holds the following string
    // "public " + CKK2a(kt) with kt = "unknown key type" being the longest kt string
    // or "private  " + CKK2a(kt) with kt = "unknown key type" being the longest kt string
    // Hence, the size of the string is 25 Bytes including the '\0' character
    // Use 32 Bytes as multiple of 8
    buffer = malloc(32);
    if (!buffer) {
        return CKR_HOST_MEMORY;
    }

    switch (oclass) {
    case CKO_SECRET_KEY:
        buffer[0] = 0;
        break;
    case CKO_PUBLIC_KEY:
        strcpy(buffer, "public ");
        break;
    case CKO_PRIVATE_KEY:
        strcpy(buffer, "private ");
        break;
    default:
        /* its not a key */
        rc = CKR_KEY_TYPE_INCONSISTENT;
        free(buffer);
        return rc;
    }

    template[0].type = CKA_KEY_TYPE;
    template[0].pValue = &kt;
    template[0].ulValueLen = sizeof(CK_KEY_TYPE);
    rc = funcs->C_GetAttributeValue(session, hkey, template, 1);
    if (rc != CKR_OK) {
        fprintf(stderr, "Object does not have CKA_KEY_TYPE attribute (error code 0x%lX: %s)\n",
               rc, p11_get_ckr(rc));
        free(buffer);
        return rc;
    }

    strcat(buffer, CKK2a(kt));

    *klength = 0;
    switch (kt) {
    case CKK_AES:
    case CKK_AES_XTS:
    case CKK_GENERIC_SECRET:
        template[0].type = CKA_VALUE_LEN;
        template[0].pValue = &vl;
        template[0].ulValueLen = sizeof(CK_ULONG);
        rc = funcs->C_GetAttributeValue(session, hkey, template, 1);
        if (rc != CKR_OK) {
            fprintf(stderr, "Object does not have CKA_VALUE_LEN attribute (error code 0x%lX: %s)\n",
                   rc, p11_get_ckr(rc));
            free(buffer);
            return rc;
        }
        *klength = vl * 8;
        if (kt == CKK_AES_XTS)
            *klength /= 2;
        break;
    default:
        // Fall through - template values set above
        break;
    }

    *ktype = buffer;
    *keyclass = oclass;

    return CKR_OK;
}

/**
 * Check args for gen_key command.
 */
static CK_RV check_args_gen_key(p11sak_kt *kt, CK_ULONG keylength,
                                char *ECcurve, char *pqc_ver)
{
    switch (*kt) {
    case kt_DES:
    case kt_3DES:
        break;
    case kt_IBM_DILITHIUM:
        if (pqc_ver == NULL) {
            fprintf(stderr,
                    "Cipher key type [%d] supported but Dilithium version not set in arguments. Try adding argument <r2_65>, <r2_87>, <r3_44>, <r3_65>, or <r3_87>\n",
                    *kt);
            return CKR_ARGUMENTS_BAD;
        }
        if (strcasecmp(pqc_ver, "r2_65") == 0 ||
            strcasecmp(pqc_ver, "r2_87") == 0 ||
            strcasecmp(pqc_ver, "r3_44") == 0 ||
            strcasecmp(pqc_ver, "r3_65") == 0 ||
            strcasecmp(pqc_ver, "r3_87") == 0) {
            break;
        } else {
            fprintf(stderr, "IBM Dilithium version [%s] not supported \n", pqc_ver);
            return CKR_ARGUMENTS_BAD;
        }
        break;
    case kt_IBM_KYBER:
        if (pqc_ver == NULL) {
            fprintf(stderr,
                    "Cipher key type [%d] supported but Kyber version not set in arguments. Try adding argument <r2_1024> or <r2_1024>\n",
                    *kt);
            return CKR_ARGUMENTS_BAD;
        }
        if (strcasecmp(pqc_ver, "r2_768") == 0 ||
            strcasecmp(pqc_ver, "r2_1024") == 0) {
            break;
        } else {
            fprintf(stderr, "IBM Kyber version [%s] not supported \n", pqc_ver);
            return CKR_ARGUMENTS_BAD;
        }
        break;
    case kt_AES:
        if ((keylength == 128) || (keylength == 192) || (keylength == 256)) {
            break;
        } else {
            fprintf(stderr, 
                    "Cipher key type [%d] and key bit length %lu is not supported. Try adding argument <128|192|256>\n",
                    *kt, keylength);
            return CKR_ARGUMENTS_BAD;
        }
        break;
    case kt_AES_XTS:
        if ((keylength == 128) || (keylength == 256)) {
            break;
        } else {
            fprintf(stderr,
                    "Cipher key type [%d] and key bit length %lu is not supported. Try adding argument <128|256>\n",
                    *kt, keylength);
            return CKR_ARGUMENTS_BAD;
        }
        break;
    case kt_RSAPKCS:
        if ((keylength == 1024) || (keylength == 2048) || (keylength == 4096)) {
            break;
        } else {
            fprintf(stderr, 
                    "[%d] RSA modulus bit length %lu NOT supported. Try adding argument <1024|2048|4096>\n",
                    *kt, keylength);
        }
        break;
    case kt_EC:
        if (ECcurve == NULL) {
            fprintf(stderr, 
                    "Cipher key type [%d] supported but EC curve not set in arguments. Try argument <prime256v1|secp384r1|secp521r1> \n",
                    *kt);
            return CKR_ARGUMENTS_BAD;
        }
        break;
    case kt_GENERIC:
    case kt_SECRET:
    case kt_PUBLIC:
    case kt_PRIVATE:
        break;
    default:
        fprintf(stderr, "Cipher key type [%d] is not set or not supported\n", *kt);
        print_gen_help();
        return CKR_ARGUMENTS_BAD;
    }

    return CKR_OK;
}
/**
 * Check args for list_key command.
 */
static CK_RV check_args_list_key(p11sak_kt *kt)
{
    switch (*kt) {
    case kt_AES:
    case kt_AES_XTS:
    case kt_RSAPKCS:
    case kt_DES:
    case kt_3DES:
    case kt_EC:
    case kt_IBM_DILITHIUM:
    case kt_IBM_KYBER:
    case kt_GENERIC:
    case kt_SECRET:
    case kt_PUBLIC:
    case kt_PRIVATE:
    case kt_ALL:
        break;
    default:
        fprintf(stderr, "Cipher key type [%d] is not set or not supported\n", *kt);
        print_listkeys_help();
        return CKR_ARGUMENTS_BAD;
    }

    return CKR_OK;
}
/**
 * Check args for remove-key command.
 */
static CK_RV check_args_remove_key(p11sak_kt *kt)
{
    switch (*kt) {
    case kt_DES:
    case kt_3DES:
    case kt_AES:
    case kt_AES_XTS:
    case kt_RSAPKCS:
    case kt_EC:
    case kt_IBM_DILITHIUM:
    case kt_IBM_KYBER:
    case kt_GENERIC:
    case kt_SECRET:
    case kt_PUBLIC:
    case kt_PRIVATE:
        break;
    default:
        fprintf(stderr, "Cipher key type [%d] is not set or not supported\n", *kt);
        print_gen_help();
        return CKR_ARGUMENTS_BAD;
    }

    return CKR_OK;
}
/**
 * Parse p11sak command from argv.
 */
static p11sak_cmd parse_cmd(const char *arg)
{
    p11sak_cmd cmd = no_cmd;

    if ((strcmp(arg, "generate-key") == 0) || (strcmp(arg, "gen-key") == 0)
            || (strcmp(arg, "gen") == 0)) {
        cmd = gen_key;
    } else if ((strcmp(arg, "list-key") == 0) || (strcmp(arg, "ls-key") == 0)
            || (strcmp(arg, "ls") == 0)) {
        cmd = list_key;
    } else if ((strcmp(arg, "remove-key") == 0) || (strcmp(arg, "rm-key") == 0)
            || (strcmp(arg, "rm") == 0)) {
        cmd = remove_key;
    } else {
        fprintf(stderr, "Unknown command %s\n", cmd2str(cmd));
        cmd = no_cmd;
    }
    return cmd;
}

static CK_BBOOL last_parm_is_help(char *argv[], int argc)
{
    if (strcmp(argv[argc - 1], "-h") == 0
            || strcmp(argv[argc - 1], "--help") == 0) {
        return 1;
    }

    return 0;
}

static CK_ULONG get_ulong_arg(int pos, char *argv[], int argc)
{
    if (pos < argc)
        return atol(argv[pos]);
    else
        return 0;
}

static char* get_string_arg(int pos, char *argv[], int argc)
{
    if (pos < argc)
        return argv[pos];
    else
        return NULL;
}
/**
 * Parse the list-key args.
 */
static CK_RV parse_list_key_args(char *argv[], int argc, p11sak_kt *kt,
                                 CK_ULONG *keylength, CK_SLOT_ID *slot,
                                 const char **pin, int *long_print, char **label,
                                 int *full_uri, int *force_pin_prompt)
{
    CK_RV rc;
    CK_BBOOL slotIDset = CK_FALSE;
    int i;

    int base = 0;
    char *endptr, *str;

    if (last_parm_is_help(argv, argc)) {
        print_listkeys_help();
        return CKR_ARGUMENTS_BAD;
    }

    for (i = 2; i < argc; i++) {
        /* Get arguments */
        if (strcasecmp(argv[i], "des") == 0) {
            *kt = kt_DES;
            *keylength = 64;
        } else if (strcasecmp(argv[i], "3des") == 0) {
            *kt = kt_3DES;
        } else if (strcasecmp(argv[i], "aes") == 0) {
            *kt = kt_AES;
        } else if (strcasecmp(argv[i], "aes-xts") == 0) {
            *kt = kt_AES_XTS;
        } else if (strcasecmp(argv[i], "rsa") == 0) {
            *kt = kt_RSAPKCS;
        } else if (strcasecmp(argv[i], "ec") == 0) {
            *kt = kt_EC;
        } else if (strcasecmp(argv[i], "ibm-dilithium") == 0) {
            *kt = kt_IBM_DILITHIUM;
        } else if (strcasecmp(argv[i], "ibm-kyber") == 0) {
            *kt = kt_IBM_KYBER;
        } else if (strcasecmp(argv[i], "generic") == 0) {
            *kt = kt_GENERIC;
        } else if (strcasecmp(argv[i], "secret") == 0) {
            *kt = kt_SECRET;
        } else if (strcasecmp(argv[i], "public") == 0) {
            *kt = kt_PUBLIC;
        } else if (strcasecmp(argv[i], "private") == 0) {
            *kt = kt_PRIVATE;
        } else if (strcasecmp(argv[i], "all") == 0) {
            *kt = kt_ALL;
            /* Get options */
        } else if (strcmp(argv[i], "--slot") == 0) {
            if (i + 1 < argc) {
                str = argv[i + 1];
                errno = 0;
                *slot = strtol(str, &endptr, base);

                if (errno != 0) {
                    perror("strtol");
                    fprintf(stderr, "--slot <SLOT> argument must be specified correctly.\n");
                    return CKR_ARGUMENTS_BAD;
                }

                if (endptr == str) {
                    fprintf(stderr, "--slot <SLOT> argument must be specified correctly.\n");
                    return CKR_ARGUMENTS_BAD;
                }

                if (*endptr != '\0') {
                    fprintf(stderr, "--slot <SLOT> argument must be specified correctly.\n");
                    return CKR_ARGUMENTS_BAD;
                }

                slotIDset = CK_TRUE;
            } else {
                fprintf(stderr, "--slot <SLOT> argument is missing.\n");
                return CKR_ARGUMENTS_BAD;
            }
            i++;
        } else if (strcmp(argv[i], "--pin") == 0) {
            if (i + 1 < argc) {
                *pin = argv[i + 1];
            } else {
                fprintf(stderr, "--pin <PIN> argument is missing.\n");
                return CKR_ARGUMENTS_BAD;
            }
            i++;
        } else if ((strcmp(argv[i], "-l") == 0)
                || (strcmp(argv[i], "--long") == 0)) {
            *long_print = 1;
        } else if (strcmp(argv[i], "--label") == 0) {
            if (i + 1 < argc) {
                *label = argv[i + 1];
            } else {
                fprintf(stderr, "--label <LABEL> argument is missing.\n");
                return CKR_ARGUMENTS_BAD;
            }
            i++;
        } else if (strcmp(argv[i], "--detailed-uri") == 0) {
            *full_uri = 1;
        } else if (strcmp(argv[i], "--force-pin-prompt") == 0) {
            *force_pin_prompt = 1;
        } else if ((strcmp(argv[i], "-h") == 0)
                || (strcmp(argv[i], "--help") == 0)) {
            print_listkeys_help();
            return CKR_ARGUMENTS_BAD;
        } else {
            fprintf(stderr, "Unknown argument or option %s for command list-key\n",
                    argv[i]);
            return CKR_ARGUMENTS_BAD;
        }
    }

    rc = check_args_list_key(kt);

    if (!slotIDset) {
        fprintf(stderr, "--slot <SLOT> must be specified.\n");
        rc = CKR_ARGUMENTS_BAD;
    }

    return rc;
}
/**
 * Parse the generate-key args.
 */
static CK_RV parse_gen_key_args(char *argv[], int argc, p11sak_kt *kt,
                                CK_ULONG *keylength, char **ECcurve,
                                CK_SLOT_ID *slot, const char **pin,
                                CK_ULONG *exponent, char **label,
                                char **attr_string, char **pqc_ver,
                                int *force_pin_prompt)
{
    CK_RV rc;
    CK_BBOOL slotIDset = CK_FALSE;
    int i;

    int base = 0;
    char *endptr, *str;

    for (i = 2; i < argc; i++) {
        /* Get arguments */
        if (strcasecmp(argv[i], "des") == 0) {
            *kt = kt_DES;
            *keylength = 64;
        } else if (strcasecmp(argv[i], "3des") == 0) {
            *kt = kt_3DES;
            *keylength = 192;
        } else if (strcasecmp(argv[i], "aes") == 0) {
            *kt = kt_AES;
            *keylength = get_ulong_arg(i + 1, argv, argc);
            i++;
        } else if (strcasecmp(argv[i], "aes-xts") == 0) {
            *kt = kt_AES_XTS;
            *keylength = get_ulong_arg(i + 1, argv, argc);
            i++;
        } else if (strcasecmp(argv[i], "rsa") == 0) {
            *kt = kt_RSAPKCS;
            *keylength = get_ulong_arg(i + 1, argv, argc);
            i++;
        } else if (strcasecmp(argv[i], "ec") == 0) {
            *kt = kt_EC;
            *ECcurve = get_string_arg(i + 1, argv, argc);
            i++;
        } else if (strcasecmp(argv[i], "ibm-dilithium") == 0) {
            *kt = kt_IBM_DILITHIUM;
            *pqc_ver = get_string_arg(i + 1, argv, argc);
            i++;
        } else if (strcasecmp(argv[i], "ibm-kyber") == 0) {
            *kt = kt_IBM_KYBER;
            *pqc_ver = get_string_arg(i + 1, argv, argc);
            i++;
            /* Get options */
        } else if (strcmp(argv[i], "--slot") == 0) {
            if (i + 1 < argc) {
                str = argv[i + 1];
                errno = 0;
                *slot = strtol(str, &endptr, base);

                if (errno != 0) {
                    perror("strtol");
                    fprintf(stderr, "--slot <SLOT> argument must be specified correctly.\n");
                    return CKR_ARGUMENTS_BAD;
                }

                if (endptr == str) {
                    fprintf(stderr, "--slot <SLOT> argument must be specified correctly.\n");
                    return CKR_ARGUMENTS_BAD;
                }

                if (*endptr != '\0') {
                    fprintf(stderr, "--slot <SLOT> argument must be specified correctly.\n");
                    return CKR_ARGUMENTS_BAD;
                }

                slotIDset = CK_TRUE;
            } else {
                fprintf(stderr, "--slot <SLOT> argument is missing.\n");
                return CKR_ARGUMENTS_BAD;
            }
            i++;
        } else if (strcmp(argv[i], "--pin") == 0) {
            if (i + 1 < argc) {
                *pin = argv[i + 1];
            } else {
                fprintf(stderr, "--pin <PIN> argument is missing.\n");
                return CKR_ARGUMENTS_BAD;
            }
            i++;
        } else if (strcmp(argv[i], "--label") == 0) {
            if (i + 1 < argc) {
                *label = argv[i + 1];
            } else {
                fprintf(stderr, "--label <LABEL> argument is missing.\n");
                return CKR_ARGUMENTS_BAD;
            }
            i++;
        } else if (strcmp(argv[i], "--exponent") == 0) {
            if (i + 1 < argc) {
                *exponent = atol(argv[i + 1]);
            } else {
                fprintf(stderr, "--exponent <EXPONENT> argument is missing.\n");
                return CKR_ARGUMENTS_BAD;
            }
            i++;
        } else if ((strcmp(argv[i], "--attr") == 0)) {
            if (i + 1 < argc) {
                *attr_string = argv[i + 1];
                if (strlen(argv[i + 1]) > KEY_MAX_BOOL_ATTR_COUNT) {
                    fprintf(stderr, "--attr <ATTRIBUTES> argument is too long.\n");
                    return CKR_ARGUMENTS_BAD;
                }
            } else {
                fprintf(stderr, "--attr <ATTRIBUTES> argument is missing.\n");
                return CKR_ARGUMENTS_BAD;
            }
            i++;
        } else if (strcmp(argv[i], "--force-pin-prompt") == 0) {
            *force_pin_prompt = 1;
        } else if ((strcmp(argv[i], "-h") == 0)
                || (strcmp(argv[i], "--help") == 0)) {
            print_gen_keys_help(kt);
            return CKR_ARGUMENTS_BAD;
        } else {
            fprintf(stderr, "Unknown argument or option %s for command generate-key\n",
                    argv[i]);
            return CKR_ARGUMENTS_BAD;
        }
    }

    if (last_parm_is_help(argv, argc)) {
        print_gen_keys_help(kt);
        for (i = 2; i < argc; i++) {
            if ((strcmp(argv[i], "--attr") == 0)) {
                print_gen_attr_help();
            }
        }
        return CKR_ARGUMENTS_BAD;
    }

    /* Check args */
    rc = check_args_gen_key(kt, *keylength, *ECcurve, *pqc_ver);

    /* Check required options */
    if (*label == NULL) {
        fprintf(stderr, "Key label must be specified.\n");
        rc = CKR_ARGUMENTS_BAD;
    }

    if (!slotIDset) {
        fprintf(stderr, "--slot <SLOT> must be specified.\n");
        rc = CKR_ARGUMENTS_BAD;
    }

    return rc;
}
/**
 * Parse the remove-key args.
 */
static CK_RV parse_remove_key_args(char *argv[], int argc, p11sak_kt *kt,
                                   CK_SLOT_ID *slot, const char **pin,
                                   char **label, CK_ULONG *keylength,
                                   CK_BBOOL *forceAll, int *force_pin_prompt)
{
    CK_RV rc;
    CK_BBOOL slotIDset = CK_FALSE;
    int i;

    int base = 0;
    char *endptr, *str;

    if (last_parm_is_help(argv, argc)) {
        print_removekeys_help();
        return CKR_ARGUMENTS_BAD;
    }

    for (i = 2; i < argc; i++) {
        /* Get arguments */
        if (strcasecmp(argv[i], "des") == 0) {
            *kt = kt_DES;
            *keylength = 64;
        } else if (strcasecmp(argv[i], "3des") == 0) {
            *kt = kt_3DES;
        } else if (strcasecmp(argv[i], "aes") == 0) {
            *kt = kt_AES;
        } else if (strcasecmp(argv[i], "aes-xts") == 0) {
            *kt = kt_AES_XTS;
        } else if (strcasecmp(argv[i], "rsa") == 0) {
            *kt = kt_RSAPKCS;
        } else if (strcasecmp(argv[i], "ec") == 0) {
            *kt = kt_EC;
        } else if (strcasecmp(argv[i], "ibm-dilithium") == 0) {
            *kt = kt_IBM_DILITHIUM;
        } else if (strcasecmp(argv[i], "ibm-kyber") == 0) {
            *kt = kt_IBM_KYBER;
            /* Get options */
        } else if (strcmp(argv[i], "--slot") == 0) {
            if (i + 1 < argc) {
                str = argv[i + 1];
                errno = 0;
                *slot = strtol(str, &endptr, base);

                if (errno != 0) {
                    perror("strtol");
                    fprintf(stderr, "--slot <SLOT> argument must be specified correctly.\n");
                    return CKR_ARGUMENTS_BAD;
                }

                if (endptr == str) {
                    fprintf(stderr, "--slot <SLOT> argument must be specified correctly.\n");
                    return CKR_ARGUMENTS_BAD;
                }

                if (*endptr != '\0') {
                    fprintf(stderr, "--slot <SLOT> argument must be specified correctly.\n");
                    return CKR_ARGUMENTS_BAD;
                }

                slotIDset = CK_TRUE;
            } else {
                fprintf(stderr, "--slot <SLOT> argument is missing.\n");
                return CKR_ARGUMENTS_BAD;
            }
            i++;
        } else if (strcmp(argv[i], "--pin") == 0) {
            if (i + 1 < argc) {
                *pin = argv[i + 1];
            } else {
                fprintf(stderr, "--pin <PIN> argument is missing.\n");
                return CKR_ARGUMENTS_BAD;
            }
            i++;
        } else if (strcmp(argv[i], "--label") == 0) {
            if (i + 1 < argc) {
                *label = argv[i + 1];
            } else {
                fprintf(stderr, "--label <LABEL> argument is missing.\n");
                return CKR_ARGUMENTS_BAD;
            }
            i++;
        } else if (strcmp(argv[i], "--force-pin-prompt") == 0) {
            *force_pin_prompt = 1;
        } else if ((strcmp(argv[i], "-f") == 0)
                || (strcmp(argv[i], "--force") == 0)) {
            *forceAll = ckb_true;
        } else if ((strcmp(argv[i], "-h") == 0)
                || (strcmp(argv[i], "--help") == 0)) {

            print_removekeys_help();
            return CKR_ARGUMENTS_BAD;
        } else {
            fprintf(stderr, "Unknown argument or option %s for command remove-key\n",
                    argv[i]);
            return CKR_ARGUMENTS_BAD;
        }
    }

    rc = check_args_remove_key(kt);

    /* Check required options */
    if (*label == NULL) {
        *label = "";
    }

    if (!slotIDset) {
        fprintf(stderr, "--slot <SLOT> must be specified.\n");
        rc = CKR_ARGUMENTS_BAD;
    }

    return rc;
}
/**
 * Parse the p11sak command args.
 */
static CK_RV parse_cmd_args(p11sak_cmd cmd, char *argv[], int argc,
                            p11sak_kt *kt, CK_ULONG *keylength, char **ECcurve,
                            CK_SLOT_ID *slot, const char **pin,
                            CK_ULONG *exponent, char **label,
                            char **attr_string, int *long_print, int *full_uri,
                            CK_BBOOL *forceAll, char **pqc_ver,
                            int *force_pin_prompt)
{
    CK_RV rc;

    switch (cmd) {
    case gen_key:
        rc = parse_gen_key_args(argv, argc, kt, keylength, ECcurve, slot, pin,
                exponent, label, attr_string, pqc_ver, force_pin_prompt);
        break;
    case list_key:
        rc = parse_list_key_args(argv, argc, kt, keylength, slot, pin,
                long_print, label, full_uri, force_pin_prompt);
        break;
    case remove_key:
        rc = parse_remove_key_args(argv, argc, kt, slot, pin, label, keylength,
                forceAll, force_pin_prompt);
        break;
    default:
        fprintf(stderr, "Error: unknown command %d specified.\n", cmd);
        rc = CKR_ARGUMENTS_BAD;
    }

    return rc;
}
/**
 * Generate a symmetric key.
 */
static CK_RV generate_symmetric_key(CK_SESSION_HANDLE session, CK_SLOT_ID slot,
                                    p11sak_kt kt, CK_ULONG keylength,
                                    char *label, char *attr_string)
{
    CK_OBJECT_HANDLE hkey;
    CK_MECHANISM mech;
    CK_RV rc;

    printf("Generate symmetric key %s with keylen=%lu and label=\"%s\"\n",
            kt2str(kt), keylength, label);

    rc = key_pair_gen_mech(kt, &mech);
    if (rc != CKR_OK) {
        fprintf(stderr, "Error setting the mechanism (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        goto done;
    }

    if (kt == kt_AES_XTS)
        keylength *= 2;

    rc = tok_key_gen(session, slot, keylength, &mech, attr_string, &hkey,
                     label);
    if (rc != CKR_OK) {
        fprintf(stderr, "Key generation failed (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        goto done;
    }

    printf("Symmetric key generation successful!\n");

done:

    return rc;
}
/**
 * Generate an asymmetric key.
 */
static CK_RV generate_asymmetric_key(CK_SESSION_HANDLE session, CK_SLOT_ID slot,
                                     p11sak_kt kt, CK_ULONG keylength,
                                     CK_ULONG exponent, char *ECcurve,
                                     char *label, char *attr_string, char *pqc_ver)
{
    CK_OBJECT_HANDLE pub_keyh, prv_keyh;
    CK_ATTRIBUTE pub_attr[KEY_MAX_BOOL_ATTR_COUNT + 2];
    CK_ULONG pub_acount = 0;
    CK_ATTRIBUTE prv_attr[KEY_MAX_BOOL_ATTR_COUNT + 2];
    CK_ULONG prv_acount = 0;
    CK_MECHANISM mech;
    CK_ULONG i, keyform;
    CK_RV rc;
    const char separator = ':';

    memset(pub_attr, 0, sizeof(pub_attr));
    memset(prv_attr, 0, sizeof(prv_attr));

    switch (kt)
    {
    case kt_RSAPKCS:
        rc = read_rsa_args((CK_ULONG) keylength, exponent, pub_attr,
                &pub_acount);
        if (rc) {
            fprintf(stderr, "Error setting RSA parameters!\n");
            goto done;
        }
        break;
    case kt_EC:
        rc = read_ec_args(ECcurve, pub_attr, &pub_acount, &keylength);
        if (rc) {
            fprintf(stderr, "Error parsing EC parameters!\n");
            goto done;
        }
        break;
    case kt_IBM_DILITHIUM:
        rc = read_dilithium_args(pqc_ver, &keyform,
                                 pub_attr, &pub_acount);
        if (rc) {
            fprintf(stderr, "Error parsing Dilithium parameters!\n");
            goto done;
        }
        printf("Generating Dilithium keypair with %s\n", pqc_ver);
        break;
    case kt_IBM_KYBER:
        rc = read_kyber_args(pqc_ver, &keyform, pub_attr, &pub_acount);
        if (rc) {
            fprintf(stderr, "Error parsing Kyber parameters!\n");
            goto done;
        }
        printf("Generating Kyber keypair with %s\n", pqc_ver);
        break;
    default:
        fprintf(stderr, "The key type %d is not yet supported.\n", kt);
        rc = CKR_KEY_TYPE_INCONSISTENT;
        goto done;
        break;
    }

    rc = set_labelpair_attr(label, pub_attr, &pub_acount, prv_attr,
            &prv_acount);
    if (rc != CKR_OK) {
        fprintf(stderr, "Error setting the label attributes (error code 0x%lX: %s)\n",
                rc, p11_get_ckr(rc));
        goto done;
    }

    rc = key_pair_gen_mech(kt, &mech);
    if (rc != CKR_OK) {
        fprintf(stderr, "Error setting the mechanism (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        goto done;
    }

    /**
     * if the separator sign is not in the string the custom attributes apply for 
     * public and private key
     * else the attributes in front of the separator sign are set for the public 
     * key and the ones behind are set for the private key
     */
    char *ret = NULL;
    if (attr_string)
        ret = strchr(attr_string, separator);

    if (attr_string && ret != NULL) {
        // setting the attributes after the separator for the private key
        rc = set_battr(ret + 1, prv_attr, &prv_acount, 1);
        if (rc != CKR_OK) {
            fprintf(stderr, "Error setting binary attributes for private key (error code 0x%lX: %s)\n", rc,
                    p11_get_ckr(rc));
            goto done;
        }
        // setting the attributes in front of the separator for the public key
        *ret = '\0';
        rc = set_battr(attr_string, pub_attr, &pub_acount, 0);
        *ret = separator;
        if (rc != CKR_OK) {
            fprintf(stderr, "Error setting binary attributes for public key (error code 0x%lX: %s)\n", rc,
                    p11_get_ckr(rc));
            goto done;
        }
    } else {
        rc = set_battr(attr_string, pub_attr, &pub_acount, 0);
        if (rc != CKR_OK) {
            fprintf(stderr, "Error setting binary attributes for public key (error code 0x%lX: %s)\n", rc,
                    p11_get_ckr(rc));
            goto done;
        }
        rc = set_battr(attr_string, prv_attr, &prv_acount, 1);
        if (rc != CKR_OK) {
            fprintf(stderr, "Error setting binary attributes for private key (error code 0x%lX: %s)\n", rc,
                    p11_get_ckr(rc));
            goto done;
        }
    }

    rc = key_pair_gen(session, slot, kt, &mech, pub_attr, pub_acount, prv_attr,
            prv_acount, &pub_keyh, &prv_keyh, keylength);
    if (rc != CKR_OK) {
        fprintf(stderr, 
                "Generating a key pair in the token in slot %lu failed (error code 0x%lX: %s)\n",
                slot, rc, p11_get_ckr(rc));
        goto done;
    }

done:
    for (i = 0; i < pub_acount; i++) {
        switch (pub_attr[i].type) {
        case CKA_MODULUS_BITS:
        case CKA_PUBLIC_EXPONENT:
        case CKA_LABEL:
            free(pub_attr[i].pValue);
            break;
        default:
            break;
        }
    }

    for (i = 0; i < prv_acount; i++) {
        switch (prv_attr[i].type) {
        case CKA_LABEL:
            free(prv_attr[i].pValue);
            break;
        default:
            break;
        }
    }

    return rc;
}
/**
 * Generate a new key.
 */
static CK_RV generate_ckey(CK_SESSION_HANDLE session, CK_SLOT_ID slot,
                           p11sak_kt kt, CK_ULONG keylength, char *ECcurve,
                           CK_ULONG exponent, char *label, char *attr_string,
                           char *pqc_ver)
{
    switch (kt) {
    case kt_DES:
    case kt_3DES:
    case kt_AES:
    case kt_AES_XTS:
        return generate_symmetric_key(session, slot, kt, keylength, label,
                attr_string);
    case kt_RSAPKCS:
    case kt_EC:
    case kt_IBM_DILITHIUM:
    case kt_IBM_KYBER:
        return generate_asymmetric_key(session, slot, kt, keylength, exponent,
                ECcurve, label, attr_string, pqc_ver);
    default:
        fprintf(stderr, "Error: cannot create a key of type %i (%s)\n", kt, kt2str(kt));
        return CKR_ARGUMENTS_BAD;
    }
}
/**
 * List the given key.
 */
static CK_RV list_ckey(CK_SESSION_HANDLE session, CK_SLOT_ID slot,
                       p11sak_kt kt, int long_print, char *label, 
                       int full_uri)
{
    CK_ULONG keylength, count;
    CK_OBJECT_CLASS keyclass;
    CK_OBJECT_HANDLE hkey;
    char *keytype = NULL;
    CK_RV rc;
    int CELL_SIZE = 11;
    CK_INFO info;
    CK_SLOT_INFO slot_info;
    CK_TOKEN_INFO token_info;
    struct p11_uri *uri = NULL;

    rc = tok_key_list_init(session, kt, label);
    if (rc != CKR_OK) {
        fprintf(stderr, "Init token key list failed (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        return rc;
    }

    if (long_print == 0) {
        printf("\n");
        printf(
                " | P  M  R  L  S  E  D  G  V  W  U  X  A  N  * |    KEY TYPE | LABEL\n");
        printf(
                " |---------------------------------------------+-------------+-------------\n");
    }

    rc = funcs->C_GetInfo(&info);
    if (rc != CKR_OK) {
        fprintf(stderr, "C_GetInfo failed (error code 0x%lX: %s)\n", rc,
            p11_get_ckr(rc));
        goto done;
    }

    rc = funcs->C_GetSlotInfo(slot, &slot_info);
    if (rc != CKR_OK) {
        fprintf(stderr, "C_GetSlotInfo failed (error code 0x%lX: %s)\n", rc,
            p11_get_ckr(rc));
        goto done;
    }

    rc = funcs->C_GetTokenInfo(slot, &token_info);
    if (rc != CKR_OK) {
        fprintf(stderr, "C_GetTokenInfo failed (error code 0x%lX: %s)\n", rc,
            p11_get_ckr(rc));
        goto done;
    }

    label = NULL;
    while (1) {
        rc = funcs->C_FindObjects(session, &hkey, 1, &count);
        if (rc != CKR_OK) {
            fprintf(stderr, "C_FindObjects failed (error code 0x%lX: %s)\n", rc,
                    p11_get_ckr(rc));
            goto done;
        }
        if (count == 0)
            break;

        rc = tok_key_get_key_type(session, hkey, &keyclass, &keytype,
                &keylength);
        if (rc != CKR_OK) {
            if (rc != CKR_KEY_TYPE_INCONSISTENT)
                fprintf(stderr,
                        "Retrieval of key type failed (error code 0x%lX: %s)\n",
                        rc, p11_get_ckr(rc));
            goto cont;
        }

        rc = tok_key_get_label_attr(session, hkey, &label);
        if (rc != CKR_OK) {
            fprintf(stderr, "Retrieval of label failed (error code 0x%lX: %s)\n", rc,
                    p11_get_ckr(rc));
        } else if (long_print) {
            printf("Label: \"%s\"\t\t", label);
        }

        uri = p11_uri_new();
        if (!uri) {
            rc = CKR_HOST_MEMORY;
            goto done;
        }

        if (full_uri) {
            /* include library and slot information only in detailed URIs */
            uri->info = &info;
            uri->slot_id = slot;
            uri->slot_info = &slot_info;
        }
        uri->token_info = &token_info;

        if (tok_attribute_alloc(session, hkey, &uri->obj_class[0]) == CKR_OK) {
            rc = funcs->C_GetAttributeValue(session, hkey, &uri->obj_class[0], 1);
            if (rc != CKR_OK) {
                fprintf(stderr, "Object does not have CKA_CLASS attribute (error code 0x%lX: %s)\n",
                        rc, p11_get_ckr(rc));
                goto cont;
            }
        }

        if (tok_attribute_alloc(session, hkey, &uri->obj_id[0]) == CKR_OK) {
            rc = funcs->C_GetAttributeValue(session, hkey, &uri->obj_id[0], 1);
            if (rc != CKR_OK) {
                fprintf(stderr, "Object does not have CKA_ID attribute (error code 0x%lX: %s)\n",
                        rc, p11_get_ckr(rc));
                goto cont;
            }
        }

        if (tok_attribute_alloc(session, hkey, &uri->obj_label[0]) == CKR_OK) {
            rc = funcs->C_GetAttributeValue(session, hkey, &uri->obj_label[0], 1);
            if (rc != CKR_OK) {
                fprintf(stderr, "Object does not have CKA_LABEL attribute (error code 0x%lX: %s)\n",
                        rc, p11_get_ckr(rc));
                goto cont;
            }
        }

        if (long_print) {
            printf("\n      URI: %s", p11_uri_format(uri));
            printf("\n      Key: ");
            if (keylength > 0)
                printf("%s %lu\t\t", keytype, keylength);
            else
                printf("%s\t\t", keytype);

            printf("\n      Attributes:\n");
        }

        switch (keyclass) {
        case CKO_SECRET_KEY:
            rc = sec_key_print_attributes(session, hkey, long_print);
            if (rc != CKR_OK) {
                fprintf(stderr, 
                        "Secret key attribute printing failed (error code 0x%lX: %s)\n",
                        rc, p11_get_ckr(rc));
                goto done;
            }
            break;
        case CKO_PRIVATE_KEY:
            rc = priv_key_print_attributes(session, hkey, long_print);
            if (rc != CKR_OK) {
                fprintf(stderr, 
                        "Private key attribute printing failed (error code 0x%lX: %s)\n",
                        rc, p11_get_ckr(rc));
                goto done;
            }
            break;
        case CKO_PUBLIC_KEY:
            rc = pub_key_print_attributes(session, hkey, long_print);
            if (rc != CKR_OK) {
                fprintf(stderr, 
                        "Public key attribute printing failed (error code 0x%lX: %s)\n",
                        rc, p11_get_ckr(rc));
                goto done;
            }
            break;
        default:
            fprintf(stderr, "Unhandled keyclass in list_ckey!\n");
            break;
        }

        if (long_print == 0) {
            if (keylength > 0) {
                char tmp[50];
                snprintf(tmp, sizeof(tmp), "%s %lu", keytype, keylength);
                printf(" %*s | ", CELL_SIZE, tmp);
            } else
                printf(" %*s | ", CELL_SIZE, keytype);
            printf("\"%s\"\n", label);
        }

cont:
        p11_uri_attributes_free(uri);
        p11_uri_free(uri);
        uri = NULL;
        free(label);
        label = NULL;
        free(keytype);
        keytype = NULL;
    }

    rc = funcs->C_FindObjectsFinal(session);
    if (rc != CKR_OK) {
        fprintf(stderr, "C_FindObjectsFinal failed (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        goto done;
    }

    rc = CKR_OK;

done:
    if (rc != CKR_OK) {
        p11_uri_attributes_free(uri);
        p11_uri_free(uri);
        free(label);
        free(keytype);
    }
    return rc;
}

static CK_BBOOL user_input_ok(char *input)
{
    if (strlen(input) != 2)
        return CK_FALSE;

    if ((strncmp(input, "y", 1) == 0) ||
        (strncmp(input, "n", 1) == 0))
        return CK_TRUE;
    else
        return CK_FALSE;
}

static CK_RV confirm_destroy(char **user_input, const char* label,
                             const char *keytype)
{
    int nread;
    size_t buflen = 0;
    CK_RV rc = CKR_OK;

    *user_input = NULL;
    printf("Are you sure you want to destroy %s key object \"%s\" [y/n]? ",
           keytype, label);
    while (1) {
        nread = getline(user_input, &buflen, stdin);
        if (nread == -1) {
            printf("User input: EOF\n");
            return CKR_CANCEL;
        }

        if (user_input_ok(*user_input)) {
            break;
        } else {
            free(*user_input);
            *user_input = NULL;
            fprintf(stderr, "Please just enter 'y' or 'n': ");
        }
    }

    return rc;
}

static CK_RV finalize_destroy_object(const char *label, const char *keytype,
                                     CK_SESSION_HANDLE *session,
                                     CK_OBJECT_HANDLE *hkey,
                                     CK_BBOOL *boolDestroyFlag)
{
    char *user_input = NULL;
    CK_RV rc = CKR_OK;

    rc = confirm_destroy(&user_input, label, keytype);
    if (rc != CKR_OK) {
        fprintf(stderr, "Skip deleting Key. User input %s\n", p11_get_ckr(rc));
        rc = CKR_CANCEL;
        goto done;
    }

    if (strncmp(user_input, "y", 1) == 0) {
        printf("Destroy Object with Label: \"%s\"\n", label);
        rc = funcs->C_DestroyObject(*session, *hkey);
        if (rc != CKR_OK) {
            fprintf(stderr, "Key with label \"%s\" could not be destroyed (error code 0x%lX: %s)\n",
                   label, rc, p11_get_ckr(rc));
            goto done;
        }
        *boolDestroyFlag = CK_TRUE;
    } else if (strncmp(user_input, "n", 1) == 0) {
        printf("Skip deleting Key\n");
        *boolDestroyFlag = CK_FALSE;
    } else {
        fprintf(stderr, "Please just enter (y) for yes or (n) for no.\n");
    }

done:
    free(user_input);
    return rc;
}
/**
 * Delete objects
 */
static CK_RV delete_key(CK_SESSION_HANDLE session, p11sak_kt kt, char *rm_label,
                       CK_BBOOL *forceAll)
{
    CK_ULONG keylength, count;
    CK_OBJECT_CLASS keyclass;
    CK_OBJECT_HANDLE hkey;
    char *keytype = NULL;
    char *label = NULL;
    CK_BBOOL boolDestroyFlag = CK_FALSE;
    CK_BBOOL boolSkipFlag = CK_FALSE;
    CK_RV rc = CKR_OK;

    rc = tok_key_list_init(session, kt, label);
    if (rc != CKR_OK) {
        fprintf(stderr, "Init token key list failed (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        return rc;
    }

    while (1) {
        rc = funcs->C_FindObjects(session, &hkey, 1, &count);
        if (rc != CKR_OK) {
            fprintf(stderr, "C_FindObjects failed (error code 0x%lX: %s)\n", rc,
                    p11_get_ckr(rc));
            goto done;
        }
        if (count == 0)
            break;

        rc = tok_key_get_key_type(session, hkey, &keyclass, &keytype,
                &keylength);
        if (rc != CKR_OK) {
            if (rc != CKR_KEY_TYPE_INCONSISTENT)
                fprintf(stderr,
                        "Retrieval of key type failed (error code 0x%lX: %s)\n",
                        rc, p11_get_ckr(rc));
            continue;
        }

        rc = tok_key_get_label_attr(session, hkey, &label);
        if (rc != CKR_OK) {
            fprintf(stderr, "Retrieval of label failed (error code 0x%lX: %s)\n", rc,
                    p11_get_ckr(rc));
            free(keytype);
            keytype = NULL;
            continue;
        }

        if (*forceAll) {
            if ((strcmp(rm_label, "") == 0) || (strcmp(rm_label, label) == 0)) {
                printf("Destroy Object with Label: \"%s\"\n", label);

                rc = funcs->C_DestroyObject(session, hkey);
                if (rc != CKR_OK) {
                    fprintf(stderr, 
                            "Key with label \"%s\" could not be destroyed (error code 0x%lX: %s)\n",
                            label, rc, p11_get_ckr(rc));
                    goto done;
                }
                boolDestroyFlag = CK_TRUE;
            }
        } else {
            if ((strcmp(rm_label, "") == 0) || (strcmp(rm_label, label) == 0)) {
                rc = finalize_destroy_object(label, keytype, &session, &hkey,
                                             &boolDestroyFlag);
                if (rc != CKR_OK) {
                    goto done;
                }

                if (!boolDestroyFlag) {
                    boolSkipFlag = CK_TRUE;
                }
            }
        }
        free(label);
        label = NULL;
        free(keytype);
        keytype = NULL;
    }

    rc = funcs->C_FindObjectsFinal(session);
    if (rc != CKR_OK) {
        fprintf(stderr, "C_FindObjectsFinal failed (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        goto done;
    }

done:

    if (strlen(rm_label) > 0) {
        if (boolDestroyFlag) {
            printf("Object with Label \"%s\" found and destroyed \n", rm_label);
        } else if (boolSkipFlag) {
            fprintf(stderr, "Object with Label \"%s\" not deleted\n", rm_label);
        } else if (rc == CKR_OK) {
            fprintf(stderr, "Object with Label \"%s\" not found\n", rm_label);
        }
    }

    if (rc != CKR_OK) {
        free(label);
        free(keytype);
    }
    return rc;
}

static CK_RV execute_cmd(CK_SESSION_HANDLE session, CK_SLOT_ID slot,
                         p11sak_cmd cmd, p11sak_kt kt, CK_ULONG keylength,
                         CK_ULONG exponent, char *ECcurve, char *label,
                         char *attr_string, int long_print, int full_uri,
                         CK_BBOOL *forceAll, char *pqc_ver)
{
    CK_RV rc;
    switch (cmd) {
    case gen_key:
        rc = generate_ckey(session, slot, kt, keylength, ECcurve, exponent,
                label, attr_string, pqc_ver);
        break;
    case list_key:
        rc = list_ckey(session, slot, kt, long_print, label, full_uri);
        break;
    case remove_key:
        rc = delete_key(session, kt, label, forceAll);
        break;
    default:
        fprintf(stderr, "   Unknown COMMAND %c\n", cmd);
        print_cmd_help();
        rc = CKR_ARGUMENTS_BAD;
        break;
    }

    return rc;
}

static CK_RV start_session(CK_SESSION_HANDLE *session, CK_SLOT_ID slot,
                           CK_CHAR_PTR pin, CK_ULONG pinlen)
{
    CK_SESSION_HANDLE tmp_sess;
    CK_TOKEN_INFO tokeninfo;
    CK_SLOT_INFO slotinfo;
    CK_RV rc;

    rc = funcs->C_Initialize(NULL_PTR);
    if (rc != CKR_OK) {
        fprintf(stderr, "Error in C_Initialize (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        goto done;
    }

    rc = funcs->C_GetSlotInfo(slot, &slotinfo);
    if (rc != CKR_OK) {
        fprintf(stderr, "Slot %lu not available (error code 0x%lX: %s)\n", slot, rc,
                p11_get_ckr(rc));
        goto done;
    }

    rc = funcs->C_GetTokenInfo(slot, &tokeninfo);
    if (rc != CKR_OK) {
        fprintf(stderr, "Token at slot %lu not available (error code 0x%lX: %s)\n", slot,
                rc, p11_get_ckr(rc));
        goto done;
    }

    rc = funcs->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
            NULL_PTR,
            NULL_PTR, &tmp_sess);
    if (rc != CKR_OK) {
        fprintf(stderr, "Opening a session failed (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        goto done;
    }

    rc = funcs->C_Login(tmp_sess, CKU_USER, pin, pinlen);
    if (rc != CKR_OK) {
        fprintf(stderr, "Login failed (error code 0x%lX: %s)\n", rc, p11_get_ckr(rc));
        goto done;
    }

    *session = tmp_sess;
    rc = CKR_OK;

done:

    return rc;
}

static CK_RV close_session(CK_SESSION_HANDLE session)
{
    CK_RV rc;

    rc = funcs->C_Logout(session);
    if (rc != CKR_OK) {
        fprintf(stderr, "Logout failed (error code 0x%lX: %s)\n", rc, p11_get_ckr(rc));
        return rc;
    }

    rc = funcs->C_Finalize(NULL_PTR);
    if (rc != CKR_OK) {
        fprintf(stderr, "Error in C_Finalize: (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
    }

    return rc;
}

static CK_RV parse_file(void) {
    FILE *fp = NULL;
    char *file_loc = getenv("P11SAK_DEFAULT_CONF_FILE");
    char pathname[PATH_MAX];
    struct passwd *pw;

    // open and parse file
    if (file_loc != NULL) {
        if ((fp = fopen(file_loc, "r")) == NULL) {
            fprintf(stderr, "Cannot load config file from env variable P11SAK_DEFAULT_CONF_FILE(%s): %s\n",
                    file_loc, strerror(errno));
            fprintf(stderr, "Printing of custom attributes not available.\n");
            return CKR_ARGUMENTS_BAD;
        }
    } else {
        pw = getpwuid(geteuid());
        if (pw != NULL) {
            snprintf(pathname, sizeof(pathname), "%s/.p11sak_defined_attrs.conf", pw->pw_dir);
            fp = fopen(pathname, "r");
        }
        if (!fp) {
            file_loc = P11SAK_DEFAULT_CONF_FILE;
            if ((fp = fopen(file_loc, "r")) == NULL) {
                fprintf(stderr, "Cannot load config file from default location %s: %s\n",
                        file_loc, strerror(errno));
                fprintf(stderr, "Printing of custom attributes not available.\n");
                return CKR_ARGUMENTS_BAD;
            }
        } 
    }
    if (parse_configlib_file(fp, &cfg, error_hook, 0)) {
        fprintf(stderr, "Failed to parse %s\n", file_loc ? file_loc : "~/.p11sak_defined_attrs.conf");
        fclose(fp);
        return CKR_DATA_INVALID;
    }
    fclose(fp);

    return CKR_OK;
}

int main(int argc, char *argv[])
{
    int long_print = 0;
    int full_uri = 0;
    p11sak_kt kt = no_key_type;
    p11sak_cmd cmd = no_cmd;
    CK_ULONG exponent = 0;
    CK_SLOT_ID slot = 0;
    char *label = NULL;
    char *ECcurve = NULL;
    char *attr_string = NULL;
    CK_ULONG keylength = 0;
    char *pqc_ver = NULL;
    CK_RV rc = CKR_OK;
    CK_SESSION_HANDLE session;
    const char *pin = NULL;
    char *buf_user = NULL;
    CK_BBOOL forceAll = ckb_false;
    int force_pin_prompt = 0;

    /* Check if just help requested */
    if (argc < 3) {
        print_cmd_help();
        rc = CKR_OK;
        goto done;
    }

    /* Parse command */
    cmd = parse_cmd(argv[1]);
    if (cmd == no_cmd) {
        rc = CKR_ARGUMENTS_BAD;
        print_cmd_help();
        goto done;
    }

    /* Parse command args */
    rc = parse_cmd_args(cmd, argv, argc, &kt, &keylength, &ECcurve, &slot, &pin,
            &exponent, &label, &attr_string, &long_print, &full_uri, &forceAll,
            &pqc_ver, &force_pin_prompt);
    if (rc != CKR_OK) {
        goto done;
    }

    /* now try to load the pkcs11 lib (will exit(99) on failure) */
    load_pkcs11lib();

    /* try pin env */
    if (!pin)
        pin = getenv("PKCS11_USER_PIN");

    /* try pin prompt */
    if (force_pin_prompt || !pin)
        pin = pin_prompt(&buf_user, "Please enter user PIN: ");

    /* no pin */
    if (!pin) {
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Open PKCS#11 session */
    rc = start_session(&session, slot, (CK_CHAR_PTR) pin, strlen(pin));
    if (rc != CKR_OK) {
        fprintf(stderr, "Failed to open session (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        goto done;
    }

    /* Parse p11sak_defined_attrs.conf */
    rc = parse_file();
    if (rc == CKR_DATA_INVALID)
        goto done;

    /* Execute command */
    rc = execute_cmd(session, slot, cmd, kt, keylength, exponent, ECcurve,
            label, attr_string, long_print, full_uri, &forceAll, pqc_ver);
    if (rc == CKR_CANCEL) {
        fprintf(stderr, "Cancel execution: p11sak %s command (error code 0x%lX: %s)\n", cmd2str(cmd), rc,
                p11_get_ckr(rc));
    } else if (rc != CKR_OK) {
        fprintf(stderr, "Failed to execute p11sak %s command (error code 0x%lX: %s)\n", cmd2str(cmd), rc,
                p11_get_ckr(rc));
        goto done;
    }

    /* Close PKCS#11 session */
    rc = close_session(session);
    if (rc != CKR_OK) {
        fprintf(stderr, "Failed to close session (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        goto done;
    }

    rc = CKR_OK;

done:
    /* free */
    confignode_deepfree(cfg);
    pin_free(&buf_user);

    return rc;
}
