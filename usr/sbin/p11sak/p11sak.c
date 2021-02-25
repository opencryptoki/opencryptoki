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

#include <termios.h>
#include "p11util.h"
#include "p11sak.h"

static const char *default_pkcs11lib = "libopencryptoki.so";

static void *pkcs11lib = NULL;
static CK_FUNCTION_LIST *funcs = NULL;

static void unload_pkcs11lib(void)
{
    if (pkcs11lib)
        dlclose(pkcs11lib);
}

static void load_pkcs11lib(void)
{
    CK_RV rc;
    CK_RV (*pfoo)();
    const char *libname;

    /* check for environment variable PKCSLIB */
    libname = secure_getenv("PKCSLIB");
    if (libname == NULL || strlen(libname) < 1)
        libname = default_pkcs11lib;

    /* try to load the pkcs11 lib */
    pkcs11lib = dlopen(libname, RTLD_NOW);
    if (!pkcs11lib) {
        printf("Error: failed to open pkcs11 lib '%s'\n", libname);
        exit(99);
    }

    /* get function list */
    *(void**) (&pfoo) = dlsym(pkcs11lib, "C_GetFunctionList");
    if (!pfoo) {
        dlclose(pkcs11lib);
        printf("Error: failed to resolve symbol '%s' from pkcs11 lib '%s'\n",
                "C_GetFunctionList", libname);
        exit(99);
    }
    rc = pfoo(&funcs);
    if (rc != CKR_OK) {
        dlclose(pkcs11lib);
        printf(
                "Error: C_GetFunctionList() on pkcs11 lib '%s' failed with rc = 0x%lX - %s)\n",
                libname, rc, p11_get_ckr(rc));
        exit(99);
    }

    atexit(unload_pkcs11lib);
}

static CK_RV get_pin(char **pin, size_t *pinlen)
{
    struct termios old, new;
    int nread;
    char *user_input = NULL;
    size_t buflen;
    CK_RV rc = 0;

    /* turn echoing off */
    if (tcgetattr(fileno(stdin), &old) != 0)
        return -1;

    new = old;
    new.c_lflag &= ~ECHO;
    if (tcsetattr(fileno(stdin), TCSAFLUSH, &new) != 0)
        return -1;

    /* read the pin
     * Note: getline will allocate memory for user_input. free it when done.
     */
    nread = getline(&user_input, &buflen, stdin);
    if (nread == -1) {
        rc = -1;
        goto done;
    }

    /* Restore terminal */
    (void) tcsetattr(fileno(stdin), TCSAFLUSH, &old);

    /* start a newline */
    printf("\n");
    fflush(stdout);

    /* Allocate  PIN.
     * Note: nread includes carriage return.
     * Replace with terminating NULL.
     */
    *pin = (char*) malloc(nread);
    if (*pin == NULL) {
        rc = -ENOMEM;
        goto done;
    }

    /* strip the carriage return since not part of pin. */
    user_input[nread - 1] = '\0';
    memcpy(*pin, user_input, nread);
    /* don't include the terminating null in the pinlen */
    *pinlen = nread - 1;

    done: if (user_input)
        free(user_input);

    return rc;
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
    case kt_RSAPKCS:
        return "RSA_PKCS";
    case kt_EC:
        return "EC";
    case kt_GENERIC:
        return "GENERIC";
    case kt_SECRET:
        return "SECRET";
    case kt_PUBLIC:
        return "PUBLIC";
    case kt_PRIVATE:
        return "PRIVATE";
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
    case kt_RSAPKCS:
        *a_key_type = CKK_RSA;
        break;
    case kt_EC:
        *a_key_type = CKK_EC;
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
    case CKK_EC:
        return "EC";
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

    return &bytes[s];
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
    printf("      rsa\n");
    printf("      ec\n");
    printf("      public\n");
    printf("      private\n");
    printf("      secret\n");
    printf("\n Options:\n");
    printf("      -l, --long           list output with long format\n");
    printf(
            "      --slot SLOTID        openCryptoki repository token SLOTID.\n");
    printf("      --pin PIN            pkcs11 user PIN\n");
    printf("      -h, --help           Show this help\n\n");
}

static void print_gen_help(void)
{
    printf("\n Usage: p11sak generate-key [ARGS] [OPTIONS]\n");
    printf("\n Args:\n");
    printf("      des\n");
    printf("      3des\n");
    printf("      aes [128 | 192 | 256]\n");
    printf("      rsa [1024 | 2048 | 4096]\n");
    printf("      ec [prime256v1 | secp384r1 | secp521r1]\n");
    printf("\n Options:\n");
    printf(
            "      --slot SLOTID                           openCryptoki repository token SLOTID.\n");
    printf("      --pin PIN                               pkcs11 user PIN\n");
    printf(
            "      --label LABEL                           key label LABEL to be listed\n");
    printf(
            "      --exponent EXP                          set RSA exponent EXP\n");
    printf(
            "      --attr [M R L S E D G V W U A X N T]    set key attributes\n");
    printf("      -h, --help                              Show this help\n\n");
}

static void print_removekeys_help(void)
{
    printf("\n Usage: p11sak remove-key [ARGS] [OPTIONS]\n");
    printf("\n Args:\n");
    printf("      des\n");
    printf("      3des\n");
    printf("      aes\n");
    printf("      rsa\n");
    printf("      ec\n");
    printf("\n Options:\n");
    printf(
            "      --slot SLOTID                           openCryptoki repository token SLOTID.\n");
    printf("      --pin PIN                               pkcs11 user PIN\n");
    printf(
            "      --label LABEL                           Key label LABEL to be removed\n");
    printf(
            "      -f, --force                             Force remove all keys of given cipher type\n");
    printf("      -h, --help                              Show this help\n\n");
}

static void print_gen_des_help(void)
{
    printf("\n Options:\n");
    printf(
            "      --slot SLOTID                           openCryptoki repository token SLOTID.\n");
    printf("      --pin PIN                               pkcs11 user PIN\n");
    printf(
            "      --label LABEL                           key label LABEL to be listed\n");
    printf(
            "      --attr [M R L S E D G V W U A X N T]    set key attributes\n");
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
    printf(
            "      --slot SLOTID                           openCryptoki repository token SLOTID.\n");
    printf("      --pin PIN                               pkcs11 user PIN\n");
    printf(
            "      --label LABEL                           key label LABEL to be listed\n");
    printf(
            "      --attr [M R L S E D G V W U A X N T]    set key attributes\n");
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
    printf(
            "      --slot SLOTID                           openCryptoki repository token SLOTID.\n");
    printf("      --pin PIN                               pkcs11 user PIN\n");
    printf(
            "      --label LABEL                           key label LABEL to be listed\n");
    printf(
            "      --exponent EXP                          set RSA exponent EXP\n");
    printf(
            "      --attr [M R L S E D G V W U A X N T]    set key attributes\n");
    printf("      -h, --help                              Show this help\n\n");
}

static void print_gen_ec_help(void)
{
    printf("\n Usage: p11sak generate-key ec [ARGS] [OPTIONS]\n");
    printf("\n Args:\n");
    printf("      prime256v1\n");
    printf("      secp384r1\n");
    printf("      secp521r1\n");
    printf("\n Options:\n");
    printf(
            "      --slot SLOTID                           openCryptoki repository token SLOTID.\n");
    printf("      --pin PIN                               pkcs11 user PIN\n");
    printf(
            "      --label LABEL                           key label LABEL to be listed\n");
    printf(
            "      --attr [M R L S E D G V W U A X N T]    set key attributes\n");
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
    case kt_RSAPKCS:
        print_gen_rsa_help();
        break;
    case kt_EC:
        print_gen_ec_help();
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
    printf("           CKA_TOKEN and CKA_PRIVATE are set by default.\n");
    printf(
            "           If an attribute is not set explicitly, the default values are used.\n");
    printf(
            "           For multiple attributes add char without white space, e. g. 'MLD')\n");
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
        printf("Error: failed to allocate memory for mod_bits.\n");
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
        printf("Error: failed to allocate memory for public exponent.\n");
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
                          CK_ULONG *pubcount)
{
    pubattr[*pubcount].type = CKA_EC_PARAMS;
    if (strcmp(ECcurve, "prime256v1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) prime256v1;
        pubattr[*pubcount].ulValueLen = sizeof(prime256v1);
    } else if (strcmp(ECcurve, "prime192") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) prime192;
        pubattr[*pubcount].ulValueLen = sizeof(prime192);
    } else if (strcmp(ECcurve, "secp224") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) secp224;
        pubattr[*pubcount].ulValueLen = sizeof(secp224);
    } else if (strcmp(ECcurve, "secp384r1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) secp384r1;
        pubattr[*pubcount].ulValueLen = sizeof(secp384r1);
    } else if (strcmp(ECcurve, "secp521r1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) secp521r1;
        pubattr[*pubcount].ulValueLen = sizeof(secp521r1);
    } else if (strcmp(ECcurve, "secp265k1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) secp256k1;
        pubattr[*pubcount].ulValueLen = sizeof(secp256k1);
    } else if (strcmp(ECcurve, "brainpoolP160r1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP160r1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP160r1);
    } else if (strcmp(ECcurve, "brainpoolP160t1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP160t1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP160t1);
    } else if (strcmp(ECcurve, "brainpoolP192r1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP192r1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP192r1);
    } else if (strcmp(ECcurve, "brainpoolP192t1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP192t1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP192t1);
    } else if (strcmp(ECcurve, "brainpoolP224r1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP224r1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP224r1);
    } else if (strcmp(ECcurve, "brainpoolP224t1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP224t1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP224t1);
    } else if (strcmp(ECcurve, "brainpoolP256r1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP256r1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP256r1);
    } else if (strcmp(ECcurve, "brainpoolP256t1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP256t1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP256t1);
    } else if (strcmp(ECcurve, "brainpoolP320r1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP320r1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP320r1);
    } else if (strcmp(ECcurve, "brainpoolP320t1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP320t1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP320t1);
    } else if (strcmp(ECcurve, "brainpoolP384r1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP384r1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP384r1);
    } else if (strcmp(ECcurve, "brainpoolP384t1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP384t1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP384t1);
    } else if (strcmp(ECcurve, "brainpoolP512r1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP512r1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP512r1);
    } else if (strcmp(ECcurve, "brainpoolP512t1") == 0) {
        pubattr[*pubcount].pValue = (CK_BYTE*) brainpoolP512t1;
        pubattr[*pubcount].ulValueLen = sizeof(brainpoolP512t1);
    } else {
        printf("Unexpected case while parsing EC curves.\n");
        printf("Note: not all tokens support all curves.\n");
        return CKR_ARGUMENTS_BAD;
    }
    (*pubcount)++;

    return CKR_OK;
}
/**
 * Builds two CKA_LABEL attributes from given label.
 */
static CK_RV set_labelpair_attr(const char *label, CK_ATTRIBUTE *pubattr,
                                CK_ULONG *pubcount, CK_ATTRIBUTE *prvattr,
                                CK_ULONG *prvcount)
{
    char *publabel;
    char *prvlabel;

    if (!(publabel = malloc(strlen(label) + 5))) {
        printf("Error allocating space for publabel\n");
        return CKR_HOST_MEMORY;
    }
    publabel = strcpy(publabel, label);
    publabel = strcat(publabel, ":pub");

    if (!(prvlabel = malloc(strlen(label) + 5))) {
        printf("Error allocating space for prvlabel\n");
        return CKR_HOST_MEMORY;
    }
    prvlabel = strcpy(prvlabel, label);
    prvlabel = strcat(prvlabel, ":prv");

    pubattr[*pubcount].type = CKA_LABEL;
    pubattr[*pubcount].pValue = publabel;
    pubattr[*pubcount].ulValueLen = strlen(publabel) + 1;
    (*pubcount)++;

    prvattr[*prvcount].type = CKA_LABEL;
    prvattr[*prvcount].pValue = prvlabel;
    prvattr[*prvcount].ulValueLen = strlen(prvlabel) + 1;
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
    case kt_RSAPKCS:
        pmech->mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
        break;
    case kt_EC:
        pmech->mechanism = CKM_EC_KEY_PAIR_GEN;
        break;
    default:
        return CKR_MECHANISM_INVALID;
        break;
    }

    return CKR_OK;
}
/**
 * Set default asymmetric key attributes.
 */
static CK_RV set_battr(const char *attr_string, CK_ATTRIBUTE *pubattr,
                       CK_ULONG *pubcount, CK_ATTRIBUTE *prvattr,
                       CK_ULONG *prvcount)
{
    int i = 0;

    pubattr[*pubcount].type = CKA_TOKEN;
    pubattr[*pubcount].pValue = &ckb_true;
    pubattr[*pubcount].ulValueLen = sizeof(CK_BBOOL);
    (*pubcount)++;
    pubattr[*pubcount].type = CKA_PRIVATE;
    pubattr[*pubcount].pValue = &ckb_true;
    pubattr[*pubcount].ulValueLen = sizeof(CK_BBOOL);
    (*pubcount)++;

    prvattr[*prvcount].type = CKA_TOKEN;
    prvattr[*prvcount].pValue = &ckb_true;
    prvattr[*prvcount].ulValueLen = sizeof(CK_BBOOL);
    (*prvcount)++;
    prvattr[*prvcount].type = CKA_PRIVATE;
    prvattr[*prvcount].pValue = &ckb_true;
    prvattr[*prvcount].ulValueLen = sizeof(CK_BBOOL);
    (*prvcount)++;

    if (attr_string) {
        for (i = 0; i < (int) strlen(attr_string); i++) {

            switch (attr_string[i]) {
            case 'S': /* private sensitive */
                prvattr[*prvcount].type = CKA_SENSITIVE;
                prvattr[*prvcount].pValue = &ckb_true;
                prvattr[*prvcount].ulValueLen = sizeof(CK_BBOOL);
                (*prvcount)++;
                break;
            case 'D': /* private decrypt RSA only*/
                prvattr[*prvcount].type = CKA_DECRYPT;
                prvattr[*prvcount].pValue = &ckb_true;
                prvattr[*prvcount].ulValueLen = sizeof(CK_BBOOL);
                (*prvcount)++;
                pubattr[*pubcount].type = CKA_ENCRYPT;
                pubattr[*pubcount].pValue = &ckb_true;
                pubattr[*pubcount].ulValueLen = sizeof(CK_BBOOL);
                (*pubcount)++;
                break;
            case 'G': /* private sign */
                prvattr[*prvcount].type = CKA_SIGN;
                prvattr[*prvcount].pValue = &ckb_true;
                prvattr[*prvcount].ulValueLen = sizeof(CK_BBOOL);
                (*prvcount)++;
                pubattr[*pubcount].type = CKA_VERIFY;
                pubattr[*pubcount].pValue = &ckb_true;
                pubattr[*pubcount].ulValueLen = sizeof(CK_BBOOL);
                (*pubcount)++;
                break;
            case 'U': /* private unwrap RSA only */
                prvattr[*prvcount].type = CKA_UNWRAP;
                prvattr[*prvcount].pValue = &ckb_true;
                prvattr[*prvcount].ulValueLen = sizeof(CK_BBOOL);
                (*prvcount)++;
                pubattr[*pubcount].type = CKA_WRAP;
                pubattr[*pubcount].pValue = &ckb_true;
                pubattr[*pubcount].ulValueLen = sizeof(CK_BBOOL);
                (*pubcount)++;
                break;
            case 'X': /* private extractable */
                prvattr[*prvcount].type = CKA_EXTRACTABLE;
                prvattr[*prvcount].pValue = &ckb_true;
                prvattr[*prvcount].ulValueLen = sizeof(CK_BBOOL);
                (*prvcount)++;
                break;
            default:
                printf("Unknown argument '%c'\n", attr_string[i]);
            }
        }
    }
    return CKR_OK;
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

static void set_bool_attr_from_string(CK_ATTRIBUTE *attr, char *attr_string)
{
    int i;

    if (!attr_string)
        return;

    for (i = 0; i < (int) strlen(attr_string); i++) {
        if (char2attrtype(attr_string[i]) == attr->type) {
            attr->pValue = &ckb_true;
        }
    }
}
/**
 * Generation of the symmetric key
 */
static CK_RV tok_key_gen(CK_SESSION_HANDLE session, CK_ULONG keylength,
                         CK_MECHANISM *pmech, char *attr_string,
                         CK_OBJECT_HANDLE *phkey, char *label)
{
    CK_RV rc;
    int i = 0;

    /* Boolean attributes (cannot be specified by user) */
    CK_BBOOL a_token = ckb_true; // always true
    CK_BBOOL a_private = ckb_true; // always true

    /* Boolean attributes from user input */
    CK_BBOOL a_modifiable = ckb_false;
    CK_BBOOL a_derive = ckb_false;
    CK_BBOOL a_sensitive = ckb_false;
    CK_BBOOL a_encrypt = ckb_false;
    CK_BBOOL a_decrypt = ckb_false;
    CK_BBOOL a_sign = ckb_false;
    CK_BBOOL a_verify = ckb_false;
    CK_BBOOL a_wrap = ckb_false;
    CK_BBOOL a_unwrap = ckb_false;
    CK_BBOOL a_extractable = ckb_false;
    CK_ULONG bs = sizeof(CK_BBOOL);

    /* Non-boolean attributes */
    CK_ULONG a_value_len = keylength / 8;

    CK_ATTRIBUTE tmplt[] = {
            // boolean attrs
            { CKA_TOKEN, &a_token, bs }, { CKA_PRIVATE, &a_private, bs }, {
            CKA_MODIFIABLE, &a_modifiable, bs }, { CKA_DERIVE, &a_derive, bs },
            { CKA_SENSITIVE, &a_sensitive, bs }, {
            CKA_ENCRYPT, &a_encrypt, bs }, { CKA_DECRYPT, &a_decrypt, bs }, {
                    CKA_SIGN, &a_sign, bs }, {
            CKA_VERIFY, &a_verify, bs }, { CKA_WRAP, &a_wrap, bs }, {
            CKA_UNWRAP, &a_unwrap, bs },
            { CKA_EXTRACTABLE, &a_extractable, bs },
            // non-boolean attrs
            { CKA_VALUE_LEN, &a_value_len, sizeof(CK_ULONG) }, { CKA_LABEL,
                    label, strlen(label) } };
    CK_ULONG num_attrs = sizeof(tmplt) / sizeof(CK_ATTRIBUTE);
    CK_ULONG num_bools = num_attrs - 2;

    /* set boolean attributes */
    for (i = 0; i < (int) num_bools; i++) {
        set_bool_attr_from_string(&tmplt[i], attr_string);
    }

    /* generate key */
    rc = funcs->C_GenerateKey(session, pmech, tmplt, num_attrs, phkey);
    if (rc != CKR_OK) {
        printf("Key generation of key of length %ld bytes failed\n",
                a_value_len);
        printf("in tok_key_gen() (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
    }
    return rc;
}
/**
 * Generation of the asymmetric key pair
 */
static CK_RV key_pair_gen(CK_SESSION_HANDLE session, p11sak_kt kt,
                          CK_MECHANISM_PTR pmech, CK_ATTRIBUTE *pubattr,
                          CK_ULONG pubcount, CK_ATTRIBUTE *prvattr,
                          CK_ULONG prvcount, CK_OBJECT_HANDLE_PTR phpubkey,
                          CK_OBJECT_HANDLE_PTR phprvkey)
{

    CK_RV rc;

    printf("Generate asymmetric key: %s\n", kt2str(kt));

    rc = funcs->C_GenerateKeyPair(session, pmech, pubattr, pubcount, prvattr,
            prvcount, phpubkey, phprvkey);
    if (rc != CKR_OK) {
        printf("Key pair generation failed (error code 0x%lX: %s)\n", rc,
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
    CK_ULONG count;

    /* Boolean Attributes */
    CK_BBOOL a_token;
    CK_BBOOL a_private;
    CK_ULONG bs = sizeof(CK_BBOOL);

    /* key Type attributes */
    CK_KEY_TYPE a_key_type;
    CK_OBJECT_CLASS a_cko;

    CK_ATTRIBUTE tmplt[4];

    a_token = CK_TRUE;
    tmplt[0].type = CKA_TOKEN;
    tmplt[0].pValue = &a_token;
    tmplt[0].ulValueLen = bs;
    a_private = CK_TRUE;
    tmplt[1].type = CKA_PRIVATE;
    tmplt[1].pValue = &a_private;
    tmplt[1].ulValueLen = bs;

    if (kt < kt_SECRET) {
        rc = kt2CKK(kt, &a_key_type);
        if (rc != CKR_OK) {
            printf("Keytype could not be set (error code 0x%lX: %s)\n", rc,
                    p11_get_ckr(rc));
            return rc;
        }
    } else {
        rc = kt2CKO(kt, &a_cko);
        if (rc != CKR_OK) {
            printf("Keyobject could not be set (error code 0x%lX: %s)\n", rc,
                    p11_get_ckr(rc));
            return rc;
        }
    }

    /* Set template */
    switch (kt) {
    case kt_DES:
    case kt_3DES:
    case kt_AES:
    case kt_GENERIC:
    case kt_RSAPKCS:
    case kt_EC:
        tmplt[2].type = CKA_KEY_TYPE;
        tmplt[2].pValue = &a_key_type;
        tmplt[2].ulValueLen = sizeof(CK_KEY_TYPE);
        break;
    case kt_SECRET:
    case kt_PUBLIC:
    case kt_PRIVATE:
        tmplt[2].type = CKA_CLASS;
        tmplt[2].pValue = &a_cko;
        tmplt[2].ulValueLen = sizeof(CK_OBJECT_CLASS);
        break;
    default:
        printf("Unknown key type\n");
        return CKR_ARGUMENTS_BAD;
    }

    if (label != NULL_PTR) {
        tmplt[3].type = CKA_LABEL;
        tmplt[3].pValue = label;
        tmplt[3].ulValueLen = strlen(label) + 1;
        count = 4;
    } else
        count = 3;

    rc = funcs->C_FindObjectsInit(session, tmplt, count);
    if (rc != CKR_OK) {
        printf("C_FindObjectInit failed\n");
        printf("in tok_key_list_init() (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        return rc;
    }

    return CKR_OK;
}
/**
 * returns 1 if the given attribute is not applicable for the
 * given key type, 0 otherwise.
 */
static CK_BBOOL attr_na(const CK_ATTRIBUTE attr, p11sak_kt ktype)
{
    switch (ktype) {
    case kt_DES:
    case kt_3DES:
    case kt_AES:
    case kt_SECRET:
        switch (attr.type) {
        case CKA_TRUSTED:
            return 1;
        default:
            return 0;
        }
        break;
    case kt_PUBLIC:
        switch (attr.type) {
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
        switch (attr.type) {
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
/**
 * Columns: T  P  M  R  L  S  E  D  G  V  W  U  X  A  N
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
        if (attr[j].type == col2type(col) && !attr_na(attr[j], ktype)) {
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
    CK_ULONG bs = sizeof(CK_BBOOL);

    CK_ATTRIBUTE bool_tmplt[] = { { CKA_TOKEN, &a_token, bs }, { CKA_PRIVATE,
            &a_private, bs }, { CKA_MODIFIABLE, &a_modifiable, bs }, {
    CKA_DERIVE, &a_derive, bs }, { CKA_LOCAL, &a_local, bs }, {
    CKA_SENSITIVE, &a_sensitive, bs }, { CKA_ENCRYPT, &a_encrypt, bs }, {
            CKA_DECRYPT, &a_decrypt, bs }, { CKA_SIGN, &a_sign, bs }, {
    CKA_VERIFY, &a_verify, bs }, { CKA_WRAP, &a_wrap, bs }, {
    CKA_UNWRAP, &a_unwrap, bs }, { CKA_EXTRACTABLE, &a_extractable, bs }, {
            CKA_ALWAYS_SENSITIVE, &a_always_sensitive, bs }, {
            CKA_NEVER_EXTRACTABLE, &a_never_extractable, bs }, };
    CK_ULONG count = sizeof(bool_tmplt) / sizeof(CK_ATTRIBUTE);

    rc = funcs->C_GetAttributeValue(session, hkey, bool_tmplt, count);
    if (rc != CKR_OK) {
        printf("Attribute retrieval failed (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        return rc;
    }

    if (long_print) {
        for (i = 0; i < (int) count; i++) {
            if (bool_tmplt[i].ulValueLen != sizeof(CK_BBOOL)) {
                printf(" Error in retrieving Attribute %s\n",
                        CKA2a(bool_tmplt[i].type));
            } else {
                printf("          %s: %s\n", CKA2a(bool_tmplt[i].type),
                        CK_BBOOL2a(*(CK_BBOOL*) bool_tmplt[i].pValue));
            }
        }
        printf("|\n");
    } else {
        printf(" |");
        for (i = 2; i < KEY_MAX_BOOL_ATTR_COUNT; i++)
            short_print(i, bool_tmplt, kt_SECRET);
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
    CK_ULONG bs = sizeof(CK_BBOOL);

    CK_ATTRIBUTE bool_tmplt[] = { { CKA_TOKEN, &a_token, bs }, { CKA_PRIVATE,
            &a_private, bs }, { CKA_MODIFIABLE, &a_modifiable, bs }, {
    CKA_DERIVE, &a_derive, bs }, { CKA_LOCAL, &a_local, bs }, {
    CKA_SENSITIVE, &a_sensitive, bs }, { CKA_DECRYPT, &a_decrypt, bs }, {
            CKA_SIGN, &a_sign, bs }, { CKA_UNWRAP, &a_unwrap, bs }, {
    CKA_EXTRACTABLE, &a_extractable, bs }, {
    CKA_ALWAYS_SENSITIVE, &a_always_sensitive, bs }, {
    CKA_NEVER_EXTRACTABLE, &a_never_extractable, bs } };
    CK_ULONG count = sizeof(bool_tmplt) / sizeof(CK_ATTRIBUTE);

    rc = funcs->C_GetAttributeValue(session, hkey, bool_tmplt, count);
    if (rc != CKR_OK) {
        printf("Attribute retrieval failed (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        return rc;
    }

    /* Long print */
    if (long_print) {
        for (i = 0; i < (int) count; i++) {
            if (bool_tmplt[i].ulValueLen != sizeof(CK_BBOOL)) {
                printf(" Error in retrieving Attribute %s\n",
                        CKA2a(bool_tmplt[i].type));
            } else {
                printf("          %s: %s\n", CKA2a(bool_tmplt[i].type),
                        CK_BBOOL2a(*(CK_BBOOL*) bool_tmplt[i].pValue));
            }
        }
        printf("|\n");
    } else {
        /* Short print */
        printf(" |");
        for (i = 2; i < KEY_MAX_BOOL_ATTR_COUNT; i++)
            short_print(i, bool_tmplt, kt_PRIVATE);
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
    CK_ULONG bs = sizeof(CK_BBOOL);

    CK_ATTRIBUTE bool_tmplt[] = { { CKA_TOKEN, &a_token, bs }, { CKA_PRIVATE,
            &a_private, bs }, { CKA_MODIFIABLE, &a_modifiable, bs }, {
    CKA_DERIVE, &a_derive, bs }, { CKA_LOCAL, &a_local, bs }, {
    CKA_ENCRYPT, &a_encrypt, bs }, { CKA_VERIFY, &a_verify, bs }, {
    CKA_WRAP, &a_wrap, bs } };
    CK_ULONG count = sizeof(bool_tmplt) / sizeof(CK_ATTRIBUTE);

    rc = funcs->C_GetAttributeValue(session, hkey, bool_tmplt, count);
    if (rc != CKR_OK) {
        printf("Attribute retrieval failed (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        return rc;
    }

    /* Long print */
    if (long_print) {
        for (i = 0; i < (int) count; i++) {
            if (bool_tmplt[i].ulValueLen != sizeof(CK_BBOOL)) {
                printf(" Error in retrieving Attribute %s\n",
                        CKA2a(bool_tmplt[i].type));
            } else {
                printf("          %s: %s\n", CKA2a(bool_tmplt[i].type),
                        CK_BBOOL2a(*(CK_BBOOL*) bool_tmplt[i].pValue));
            }
        }
        printf("|\n");
    } else {
        /* Short print */
        printf(" |");
        for (i = 2; i < KEY_MAX_BOOL_ATTR_COUNT; i++)
            short_print(i, bool_tmplt, kt_PUBLIC);
        printf("|");
    }

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

    rc = funcs->C_GetAttributeValue(session, hkey, template, 1);
    if (rc != CKR_OK) {
        printf("Key cannot show CKA_LABEL attribute (error code 0x%lX: %s)\n",
                rc, p11_get_ckr(rc));
        return rc;
    }

    label = malloc(template[0].ulValueLen + 1);
    if (!label) {
        printf("Error: cannot malloc storage for label.\n");
        return CKR_HOST_MEMORY;
    }

    template[0].pValue = label;
    rc = funcs->C_GetAttributeValue(session, hkey, template, 1);
    if (rc != CKR_OK) {
        printf("Error retrieving CKA_LABEL attribute (error code 0x%lX: %s)\n",
                rc, p11_get_ckr(rc));
        return rc;
    }

    label[template[0].ulValueLen] = 0;
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
        printf(
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
        // FIXIT - return code to represent object class invalid
        rc = CKR_KEY_HANDLE_INVALID;
        printf("Object handle invalid (error code 0x%lX: %s)\n",
               rc, p11_get_ckr(rc));
        free(buffer);
        return rc;
    }

    template[0].type = CKA_KEY_TYPE;
    template[0].pValue = &kt;
    template[0].ulValueLen = sizeof(CK_KEY_TYPE);
    rc = funcs->C_GetAttributeValue(session, hkey, template, 1);
    if (rc != CKR_OK) {
        printf("Object does not have CKA_KEY_TYPE attribute (error code 0x%lX: %s)\n",
               rc, p11_get_ckr(rc));
        free(buffer);
        return rc;
    }

    strcat(buffer, CKK2a(kt));

    *klength = 0;
    switch (kt) {
    case CKK_AES:
    case CKK_GENERIC_SECRET:
        template[0].type = CKA_VALUE_LEN;
        template[0].pValue = &vl;
        template[0].ulValueLen = sizeof(CK_ULONG);
        rc = funcs->C_GetAttributeValue(session, hkey, template, 1);
        if (rc != CKR_OK) {
            printf("Object does not have CKA_VALUE_LEN attribute (error code 0x%lX: %s)\n",
                   rc, p11_get_ckr(rc));
            free(buffer);
            return rc;
        }
        *klength = vl * 8;
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
                                char *ECcurve)
{
    switch (*kt) {
    case kt_DES:
    case kt_3DES:
        break;
    case kt_AES:
        if ((keylength == 128) || (keylength == 192) || (keylength == 256)) {
            break;
        } else {
            printf(
                    "Cipher key type [%d] and key bit length %ld is not supported. Try adding argument -bits <128|192|256>\n",
                    *kt, keylength);
            return CKR_ARGUMENTS_BAD;
        }
        break;
    case kt_RSAPKCS:
        if ((keylength == 1024) || (keylength == 2048) || (keylength == 4096)) {
            break;
        } else {
            printf(
                    "[%d] RSA modulus bit length %ld NOT supported. Try adding argument -bits <1024|2048|4096>\n",
                    *kt, keylength);
        }
        break;
    case kt_EC:
        if (ECcurve == NULL) {
            printf(
                    "Cipher key type [%d] supported but EC curve not set in arguments. Try argument -curve <prime256v1|secp384r1|secp521r1> \n",
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
        printf("Cipher key type [%d] is not set or not supported\n", *kt);
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
    case kt_RSAPKCS:
    case kt_DES:
    case kt_3DES:
    case kt_EC:
    case kt_GENERIC:
    case kt_SECRET:
    case kt_PUBLIC:
    case kt_PRIVATE:
        break;
    default:
        printf("Cipher key type [%d] is not set or not supported\n", *kt);
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
    case kt_RSAPKCS:
    case kt_EC:
    case kt_GENERIC:
    case kt_SECRET:
    case kt_PUBLIC:
    case kt_PRIVATE:
        break;
    default:
        printf("Cipher key type [%d] is not set or not supported\n", *kt);
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
        printf("Unknown command %s\n", cmd2str(cmd));
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
                                 char **pin, int *long_print)
{
    CK_RV rc;
    int i;

    if (last_parm_is_help(argv, argc)) {
        print_listkeys_help();
        return CKR_ARGUMENTS_BAD;
    }

    for (i = 2; i < argc; i++) {
        /* Get arguments */
        if (strcmp(argv[i], "DES") == 0 || strcmp(argv[i], "des") == 0) {
            *kt = kt_DES;
            *keylength = 64;
        } else if (strcmp(argv[i], "3DES") == 0
                || strcmp(argv[i], "3des") == 0) {
            *kt = kt_3DES;
        } else if (strcmp(argv[i], "AES") == 0 || strcmp(argv[i], "aes") == 0) {
            *kt = kt_AES;
        } else if (strcmp(argv[i], "RSA") == 0 || strcmp(argv[i], "rsa") == 0) {
            *kt = kt_RSAPKCS;
        } else if (strcmp(argv[i], "EC") == 0 || strcmp(argv[i], "ec") == 0) {
            *kt = kt_EC;
        } else if (strcmp(argv[i], "GENERIC") == 0
                || strcmp(argv[i], "generic") == 0) {
            *kt = kt_GENERIC;
        } else if (strcmp(argv[i], "SECRET") == 0
                || strcmp(argv[i], "secret") == 0) {
            *kt = kt_SECRET;
        } else if (strcmp(argv[i], "PUBLIC") == 0
                || strcmp(argv[i], "public") == 0) {
            *kt = kt_PUBLIC;
        } else if (strcmp(argv[i], "PRIVATE") == 0
                || strcmp(argv[i], "private") == 0) {
            *kt = kt_PRIVATE;
            /* Get options */
        } else if (strcmp(argv[i], "--slot") == 0) {
            if (i + 1 < argc) {
                *slot = (CK_ULONG) atol(argv[i + 1]);
            } else {
                printf("--slot <SLOT> argument is missing.\n");
                return CKR_ARGUMENTS_BAD;
            }
            i++;
        } else if (strcmp(argv[i], "--pin") == 0) {
            if (i + 1 < argc) {
                *pin = argv[i + 1];
            } else {
                printf("--pin <PIN> argument is missing.\n");
                return CKR_ARGUMENTS_BAD;
            }
            i++;
        } else if ((strcmp(argv[i], "-l") == 0)
                || (strcmp(argv[i], "--long") == 0)) {
            *long_print = 1;
        } else if ((strcmp(argv[i], "-h") == 0)
                || (strcmp(argv[i], "--help") == 0)) {
            print_listkeys_help();
            return CKR_ARGUMENTS_BAD;
        } else {
            printf("Unknown argument or option %s for command list-key\n",
                    argv[i]);
            return CKR_ARGUMENTS_BAD;
        }
    }

    rc = check_args_list_key(kt);

    if (*slot == 0) {
        printf("Slot number must be specified.\n");
        rc = CKR_ARGUMENTS_BAD;
    }

    return rc;
}
/**
 * Parse the generate-key args.
 */
static CK_RV parse_gen_key_args(char *argv[], int argc, p11sak_kt *kt,
                                CK_ULONG *keylength, char **ECcurve,
                                CK_SLOT_ID *slot, char **pin, CK_ULONG *exponent,
                                char **label, char **attr_string)
{
    CK_RV rc;
    int i;

    for (i = 2; i < argc; i++) {
        /* Get arguments */
        if (strcmp(argv[i], "DES") == 0 || strcmp(argv[i], "des") == 0) {
            *kt = kt_DES;
            *keylength = 64;
        } else if (strcmp(argv[i], "3DES") == 0
                || strcmp(argv[i], "3des") == 0) {
            *kt = kt_3DES;
            *keylength = 192;
        } else if (strcmp(argv[i], "AES") == 0 || strcmp(argv[i], "aes") == 0) {
            *kt = kt_AES;
            *keylength = get_ulong_arg(i + 1, argv, argc);
            i++;
        } else if (strcmp(argv[i], "RSA") == 0 || strcmp(argv[i], "rsa") == 0) {
            *kt = kt_RSAPKCS;
            *keylength = get_ulong_arg(i + 1, argv, argc);
            i++;
        } else if (strcmp(argv[i], "EC") == 0 || strcmp(argv[i], "ec") == 0) {
            *kt = kt_EC;
            *ECcurve = get_string_arg(i + 1, argv, argc);
            i++;
            /* Get options */
        } else if (strcmp(argv[i], "--slot") == 0) {
            if (i + 1 < argc) {
                *slot = (CK_ULONG) atol(argv[i + 1]);
            } else {
                printf("--slot <SLOT> argument is missing.\n");
                return CKR_ARGUMENTS_BAD;
            }
            i++;
        } else if (strcmp(argv[i], "--pin") == 0) {
            if (i + 1 < argc) {
                *pin = argv[i + 1];
            } else {
                printf("--pin <PIN> argument is missing.\n");
                return CKR_ARGUMENTS_BAD;
            }
            i++;
        } else if (strcmp(argv[i], "--label") == 0) {
            if (i + 1 < argc) {
                *label = argv[i + 1];
            } else {
                printf("--label <LABEL> argument is missing.\n");
                return CKR_ARGUMENTS_BAD;
            }
            i++;
        } else if (strcmp(argv[i], "--exponent") == 0) {
            if (i + 1 < argc) {
                *exponent = atol(argv[i + 1]);
            } else {
                printf("--exponent <EXPONENT> argument is missing.\n");
                return CKR_ARGUMENTS_BAD;
            }
            i++;
        } else if ((strcmp(argv[i], "--attr") == 0)) {
            if (i + 1 < argc) {
                *attr_string = argv[i + 1];
            } else {
                printf("--attr <ATTRIBUTES> argument is missing.\n");
                return CKR_ARGUMENTS_BAD;
            }
            i++;
        } else if ((strcmp(argv[i], "-h") == 0)
                || (strcmp(argv[i], "--help") == 0)) {
            print_gen_keys_help(kt);
            return CKR_ARGUMENTS_BAD;
        } else {
            printf("Unknown argument or option %s for command generate-key\n",
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
    rc = check_args_gen_key(kt, *keylength, *ECcurve);

    /* Check required options */
    if (*label == NULL) {
        printf("Key label must be specified.\n");
        rc = CKR_ARGUMENTS_BAD;
    }

    if (*slot == 0) {
        printf("Slot number must be specified.\n");
        rc = CKR_ARGUMENTS_BAD;
    }

    return rc;
}
/**
 * Parse the remove-key args.
 */
static CK_RV parse_remove_key_args(char *argv[], int argc, p11sak_kt *kt,
                                   CK_SLOT_ID *slot, char **pin, char **label,
                                   CK_ULONG *keylength, CK_BBOOL *forceAll)
{
    CK_RV rc;
    int i;

    if (last_parm_is_help(argv, argc)) {
        print_removekeys_help();
        return CKR_ARGUMENTS_BAD;
    }

    for (i = 2; i < argc; i++) {
        /* Get arguments */
        if (strcmp(argv[i], "DES") == 0 || strcmp(argv[i], "des") == 0) {
            *kt = kt_DES;
            *keylength = 64;
        } else if (strcmp(argv[i], "3DES") == 0
                || strcmp(argv[i], "3des") == 0) {
            *kt = kt_3DES;
        } else if (strcmp(argv[i], "AES") == 0 || strcmp(argv[i], "aes") == 0) {
            *kt = kt_AES;
        } else if (strcmp(argv[i], "RSA") == 0 || strcmp(argv[i], "rsa") == 0) {
            *kt = kt_RSAPKCS;
        } else if (strcmp(argv[i], "EC") == 0 || strcmp(argv[i], "ec") == 0) {
            *kt = kt_EC;
            /* Get options */
        } else if (strcmp(argv[i], "--slot") == 0) {
            if (i + 1 < argc) {
                *slot = (CK_ULONG) atol(argv[i + 1]);
            } else {
                printf("--slot <SLOT> argument is missing.\n");
                return CKR_ARGUMENTS_BAD;
            }
            i++;
        } else if (strcmp(argv[i], "--pin") == 0) {
            if (i + 1 < argc) {
                *pin = argv[i + 1];
            } else {
                printf("--pin <PIN> argument is missing.\n");
                return CKR_ARGUMENTS_BAD;
            }
            i++;
        } else if (strcmp(argv[i], "--label") == 0) {
            if (i + 1 < argc) {
                *label = argv[i + 1];
            } else {
                printf("--label <LABEL> argument is missing.\n");
                return CKR_ARGUMENTS_BAD;
            }
            i++;
        } else if ((strcmp(argv[i], "-f") == 0)
                || (strcmp(argv[i], "--force") == 0)) {
            *forceAll = ckb_true;
        } else if ((strcmp(argv[i], "-h") == 0)
                || (strcmp(argv[i], "--help") == 0)) {

            print_removekeys_help();
            return CKR_ARGUMENTS_BAD;
        } else {
            printf("Unknown argument or option %s for command remove-key\n",
                    argv[i]);
            return CKR_ARGUMENTS_BAD;
        }
    }

    rc = check_args_remove_key(kt);

    /* Check required options */
    if (*label == NULL) {
        *label = "";
    }

    if (*slot == 0) {
        printf("Slot number must be specified.\n");
        rc = CKR_ARGUMENTS_BAD;
    }

    return rc;
}
/**
 * Parse the p11sak command args.
 */
static CK_RV parse_cmd_args(p11sak_cmd cmd, char *argv[], int argc,
                            p11sak_kt *kt, CK_ULONG *keylength, char **ECcurve,
                            CK_SLOT_ID *slot, char **pin, CK_ULONG *exponent,
                            char **label, char **attr_string, int *long_print,
                            CK_BBOOL *forceAll)
{
    CK_RV rc;

    switch (cmd) {
    case gen_key:
        rc = parse_gen_key_args(argv, argc, kt, keylength, ECcurve, slot, pin,
                exponent, label, attr_string);
        break;
    case list_key:
        rc = parse_list_key_args(argv, argc, kt, keylength, slot, pin,
                long_print);
        break;
    case remove_key:
        rc = parse_remove_key_args(argv, argc, kt, slot, pin, label, keylength,
                forceAll);
        break;
    default:
        printf("Error: unknown command %d specified.\n", cmd);
        rc = CKR_ARGUMENTS_BAD;
    }

    return rc;
}
/**
 * Generate a symmetric key.
 */
static CK_RV generate_symmetric_key(CK_SESSION_HANDLE session, p11sak_kt kt,
                                    CK_ULONG keylength, char *label,
                                    char *attr_string)
{
    CK_OBJECT_HANDLE hkey;
    CK_MECHANISM mech;
    CK_RV rc;

    printf("Generate symmetric key %s with keylen=%ld and label=[%s]\n",
            kt2str(kt), keylength, label);

    rc = key_pair_gen_mech(kt, &mech);
    if (rc != CKR_OK) {
        printf("Error setting the mechanism (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        goto done;
    }

    rc = tok_key_gen(session, keylength, &mech, attr_string, &hkey, label);
    if (rc != CKR_OK) {
        printf("Key generation failed (error code 0x%lX: %s)\n", rc,
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
                                     char *label, char *attr_string)
{
    CK_OBJECT_HANDLE pub_keyh, prv_keyh;
    CK_ATTRIBUTE pub_attr[KEY_MAX_BOOL_ATTR_COUNT + 2];
    CK_ULONG pub_acount = 0;
    CK_ATTRIBUTE prv_attr[KEY_MAX_BOOL_ATTR_COUNT + 2];
    CK_ULONG prv_acount = 0;
    CK_MECHANISM mech;
    CK_RV rc;

    if (kt == kt_RSAPKCS) {
        rc = read_rsa_args((CK_ULONG) keylength, exponent, pub_attr,
                &pub_acount);
        if (rc) {
            printf("Error setting RSA parameters!\n");
            goto done;
        }
    } else if (kt == kt_EC) {
        rc = read_ec_args(ECcurve, pub_attr, &pub_acount);
        if (rc) {
            printf("Error parsing EC parameters!\n");
            goto done;
        }
    } else {
        printf("The key type %d is not yet supported.\n", kt);
        rc = CKR_KEY_TYPE_INCONSISTENT;
        goto done;
    }

    rc = set_labelpair_attr(label, pub_attr, &pub_acount, prv_attr,
            &prv_acount);
    if (rc != CKR_OK) {
        printf("Error setting the label attributes (error code 0x%lX: %s)\n",
                rc, p11_get_ckr(rc));
        goto done;
    }

    rc = key_pair_gen_mech(kt, &mech);
    if (rc != CKR_OK) {
        printf("Error setting the mechanism (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        goto done;
    }

    rc = set_battr(attr_string, pub_attr, &pub_acount, prv_attr, &prv_acount);
    if (rc != CKR_OK) {
        printf("Error setting binary attributes (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        goto done;
    }

    rc = key_pair_gen(session, kt, &mech, pub_attr, pub_acount, prv_attr,
            prv_acount, &pub_keyh, &prv_keyh);
    if (rc != CKR_OK) {
        printf(
                "Generating a key pair in the token in slot %ld failed (error code 0x%lX: %s)\n",
                slot, rc, p11_get_ckr(rc));
        goto done;
    }

done:

    return rc;
}
/**
 * Generate a new key.
 */
static CK_RV generate_ckey(CK_SESSION_HANDLE session, CK_SLOT_ID slot,
                           p11sak_kt kt, CK_ULONG keylength, char *ECcurve,
                           CK_ULONG exponent, char *label, char *attr_string)
{
    switch (kt) {
    case kt_DES:
    case kt_3DES:
    case kt_AES:
        return generate_symmetric_key(session, kt, keylength, label,
                attr_string);
    case kt_RSAPKCS:
    case kt_EC:
        return generate_asymmetric_key(session, slot, kt, keylength, exponent,
                ECcurve, label, attr_string);
    default:
        printf("Error: cannot create a key of type %i (%s)\n", kt, kt2str(kt));
        return CKR_ARGUMENTS_BAD;
    }
}
/**
 * List the given key.
 */
static CK_RV list_ckey(CK_SESSION_HANDLE session, p11sak_kt kt, int long_print)
{
    CK_ULONG keylength, count;
    CK_OBJECT_CLASS keyclass;
    CK_OBJECT_HANDLE hkey;
    char *keytype = NULL;
    char *label = NULL;
    CK_RV rc;
    int CELL_SIZE = 11;

    rc = tok_key_list_init(session, kt, label);
    if (rc != CKR_OK) {
        printf("Init token key list failed (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        return rc;
    }

    if (long_print == 0) {
        printf("\n");
        printf(
                " | M  R  L  S  E  D  G  V  W  U  X  A  N |    KEY TYPE | LABEL\n");
        printf(
                " |---------------------------------------+-------------+-------------\n");
    }

    while (1) {
        rc = funcs->C_FindObjects(session, &hkey, 1, &count);
        if (rc != CKR_OK) {
            printf("C_FindObjects failed (error code 0x%lX: %s)\n", rc,
                    p11_get_ckr(rc));
            return rc;
        }
        if (count == 0)
            break;

        rc = tok_key_get_key_type(session, hkey, &keyclass, &keytype,
                &keylength);
        if (rc != CKR_OK) {
            printf("Invalid key type (error code 0x%lX: %s)\n", rc,
                    p11_get_ckr(rc));
            continue;
        }

        rc = tok_key_get_label_attr(session, hkey, &label);
        if (rc != CKR_OK) {
            printf("Retrieval of label failed (error code 0x%lX: %s)\n", rc,
                    p11_get_ckr(rc));
        } else if (long_print) {
            printf("Label: %s\t\t", label);
        }

        if (long_print) {
            printf("\n      Key: ");
            if (keylength > 0)
                printf("%s %ld\t\t", keytype, keylength);
            else
                printf("%s\t\t", keytype);

            printf("\n      Attributes:\n");
        }

        switch (keyclass) {
        case CKO_SECRET_KEY:
            rc = sec_key_print_attributes(session, hkey, long_print);
            if (rc != CKR_OK) {
                printf(
                        "Secret key attribute printing failed (error code 0x%lX: %s)\n",
                        rc, p11_get_ckr(rc));
                goto done;
            }
            break;
        case CKO_PRIVATE_KEY:
            rc = priv_key_print_attributes(session, hkey, long_print);
            if (rc != CKR_OK) {
                printf(
                        "Private key attribute printing failed (error code 0x%lX: %s)\n",
                        rc, p11_get_ckr(rc));
                goto done;
            }
            break;
        case CKO_PUBLIC_KEY:
            rc = pub_key_print_attributes(session, hkey, long_print);
            if (rc != CKR_OK) {
                printf(
                        "Public key attribute printing failed (error code 0x%lX: %s)\n",
                        rc, p11_get_ckr(rc));
                goto done;
            }
            break;
        default:
            printf("Unhandled keyclass in list_ckey!\n");
            break;
        }

        if (long_print == 0) {
            if (keylength > 0) {
                char tmp[16];
                snprintf(tmp, sizeof(tmp), "%s %ld", keytype, keylength);
                printf(" %*s | ", CELL_SIZE, tmp);
            } else
                printf(" %*s | ", CELL_SIZE, keytype);
            printf("%s\n", label);
        }
        free(label);
        free(keytype);
    }

    rc = funcs->C_FindObjectsFinal(session);
    if (rc != CKR_OK) {
        printf("C_FindObjectsFinal failed (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        goto done;
    }

    rc = CKR_OK;

done:

    if (rc != CKR_OK) {
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

static CK_RV confirm_destroy(char **user_input, char* label)
{
    int nread;
    size_t buflen;
    CK_RV rc = CKR_OK;

    printf("Are you sure you want to destroy object %s [y/n]? ", label);
    while (1){
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
            printf("Please just enter 'y' or 'n': ");
        }
    }

    return rc;
}

static CK_RV finalize_destroy_object(char *label, CK_SESSION_HANDLE *session,
                                   CK_OBJECT_HANDLE *hkey, CK_BBOOL *boolDestroyFlag)
{
    char *user_input = NULL;
    CK_RV rc = CKR_OK;

    rc = confirm_destroy(&user_input, label);
    if (rc != CKR_OK) {
        printf("Skip deleting Key. User input %s\n", p11_get_ckr(rc));
        rc = CKR_CANCEL;
        goto done;
    }

    if (strncmp(user_input, "y", 1) == 0) {
        printf("Destroy Object with Label: %s\n", label);
        rc = funcs->C_DestroyObject(*session, *hkey);
        if (rc != CKR_OK) {
            printf("Key with label %s could not be destroyed (error code 0x%lX: %s)\n",
                   label, rc, p11_get_ckr(rc));
            goto done;
        }
        *boolDestroyFlag = CK_TRUE;
    } else if (strncmp(user_input, "n", 1) == 0) {
        printf("Skip deleting Key\n");
        *boolDestroyFlag = CK_FALSE;
    } else {
        printf("Please just enter (y) for yes or (n) for no.\n");
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
        printf("Init token key list failed (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        return rc;
    }

    while (1) {
        rc = funcs->C_FindObjects(session, &hkey, 1, &count);
        if (rc != CKR_OK) {
            printf("C_FindObjects failed (error code 0x%lX: %s)\n", rc,
                    p11_get_ckr(rc));
            goto done;
        }
        if (count == 0)
            break;

        rc = tok_key_get_key_type(session, hkey, &keyclass, &keytype,
                &keylength);
        if (rc != CKR_OK) {
            printf("Invalid key type (error code 0x%lX: %s)\n", rc,
                    p11_get_ckr(rc));
            continue;
        }

        rc = tok_key_get_label_attr(session, hkey, &label);
        if (rc != CKR_OK) {
            printf("Retrieval of label failed (error code 0x%lX: %s)\n", rc,
                    p11_get_ckr(rc));
        }

        if (*forceAll) {
            if ((strcmp(rm_label, "") == 0) || (strcmp(rm_label, label) == 0)) {
                printf("Destroy Object with Label: %s\n", label);

                rc = funcs->C_DestroyObject(session, hkey);
                if (rc != CKR_OK) {
                    printf(
                            "Key with label %s could not be destroyed (error code 0x%lX: %s)\n",
                            label, rc, p11_get_ckr(rc));
                    goto done;
                }
                boolDestroyFlag = CK_TRUE;
            }
        } else {
            if ((strcmp(rm_label, "") == 0) || (strcmp(rm_label, label) == 0)) {
                rc = finalize_destroy_object(label, &session, &hkey, &boolDestroyFlag);
                if (rc != CKR_OK) {
                    goto done;
                }

                if (!boolDestroyFlag) {
                    boolSkipFlag = CK_TRUE;
                }
            }
        }

        free(label);
        free(keytype);
    }

    rc = funcs->C_FindObjectsFinal(session);
    if (rc != CKR_OK) {
        printf("C_FindObjectsFinal failed (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        goto done;
    }

done:

    if (strlen(rm_label) > 0) {
        if (boolDestroyFlag) {
            printf("Object with Label: %s found and destroyed \n", rm_label);
        } else if (boolSkipFlag) {
            printf("Object with Label: %s not deleted\n", rm_label);
        } else if (rc == CKR_OK) {
            printf("Object with Label: %s not found\n", rm_label);
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
                         char *attr_string, int long_print, CK_BBOOL *forceAll)
{
    CK_RV rc;
    switch (cmd) {
    case gen_key:
        rc = generate_ckey(session, slot, kt, keylength, ECcurve, exponent,
                label, attr_string);
        break;
    case list_key:
        rc = list_ckey(session, kt, long_print);
        break;
    case remove_key:
        rc = delete_key(session, kt, label, forceAll);
        break;
    default:
        printf("   Unknown COMMAND %c\n", cmd);
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
        printf("Error in C_Initialize (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        goto done;
    }

    rc = funcs->C_GetSlotInfo(slot, &slotinfo);
    if (rc != CKR_OK) {
        printf("Slot %ld not available (error code 0x%lX: %s)\n", slot, rc,
                p11_get_ckr(rc));
        goto done;
    }

    rc = funcs->C_GetTokenInfo(slot, &tokeninfo);
    if (rc != CKR_OK) {
        printf("Token at slot %ld not available (error code 0x%lX: %s)\n", slot,
                rc, p11_get_ckr(rc));
        goto done;
    }

    rc = funcs->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
            NULL_PTR,
            NULL_PTR, &tmp_sess);
    if (rc != CKR_OK) {
        printf("Opening a session failed (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        goto done;
    }

    rc = funcs->C_Login(tmp_sess, CKU_USER, pin, pinlen);
    if (rc != CKR_OK) {
        printf("Login failed (error code 0x%lX: %s)\n", rc, p11_get_ckr(rc));
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
        printf("Logout failed (error code 0x%lX: %s)\n", rc, p11_get_ckr(rc));
        return rc;
    }

    rc = funcs->C_Finalize(NULL_PTR);
    if (rc != CKR_OK) {
        printf("Error in C_Finalize: (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
    }

    return rc;
}

int main(int argc, char *argv[])
{
    int long_print = 0;
    p11sak_kt kt = no_key_type;
    p11sak_cmd cmd = no_cmd;
    CK_ULONG exponent = 0;
    CK_SLOT_ID slot = 0;
    char *label = NULL;
    char *ECcurve = NULL;
    char *attr_string = NULL;
    CK_ULONG keylength = 0;
    CK_RV rc = CKR_OK;
    CK_SESSION_HANDLE session;
    char *pin = NULL;
    size_t pinlen;
    CK_BBOOL forceAll = ckb_false;

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
            &exponent, &label, &attr_string, &long_print, &forceAll);
    if (rc != CKR_OK) {
        goto done;
    }

    /* now try to load the pkcs11 lib (will exit(99) on failure) */
    load_pkcs11lib();

    /* Prompt for PIN if not already set via option */
    if (!pin) {
        printf("Please enter user PIN:");
        rc = get_pin(&pin, &pinlen);

        if (strlen(pin) == 0) {
            char *s = getenv("PKCS11_USER_PIN");
            if (s) {
                strcpy((char*) pin, s);
            } else {
                goto done;
            }
        }
    }

    /* Open PKCS#11 session */
    rc = start_session(&session, slot, (CK_CHAR_PTR) pin, strlen(pin));
    if (rc != CKR_OK) {
        printf("Failed to open session (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        goto done;
    }

    /* Execute command */
    rc = execute_cmd(session, slot, cmd, kt, keylength, exponent, ECcurve,
            label, attr_string, long_print, &forceAll);
    if (rc == CKR_CANCEL) {
        printf("Cancel execution: p11sak %s command (error code 0x%lX: %s)\n", cmd2str(cmd), rc,
                p11_get_ckr(rc));
    } else if (rc != CKR_OK) {
        printf("Failed to execute p11sak %s command (error code 0x%lX: %s)\n", cmd2str(cmd), rc,
                p11_get_ckr(rc));
        goto done;
    }

    /* Close PKCS#11 session */
    rc = close_session(session);
    if (rc != CKR_OK) {
        printf("Failed to close session (error code 0x%lX: %s)\n", rc,
                p11_get_ckr(rc));
        goto done;
    }

    rc = CKR_OK;

    done:

    return rc;
}
