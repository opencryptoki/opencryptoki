/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "pkcs11types.h"
#include "mechtable.h"

#define _sym2str(X)     case X: return #X

//
// p11_get_ckr - return textual interpretation of a CKR_ error code
// @rc is the CKR_.. error
//
const char *p11_get_ckr(CK_RV rc)
{
    switch (rc) {
        _sym2str(CKR_OK);
        _sym2str(CKR_CANCEL);
        _sym2str(CKR_HOST_MEMORY);
        _sym2str(CKR_SLOT_ID_INVALID);
        _sym2str(CKR_GENERAL_ERROR);
        _sym2str(CKR_FUNCTION_FAILED);
        _sym2str(CKR_ARGUMENTS_BAD);
        _sym2str(CKR_NO_EVENT);
        _sym2str(CKR_NEED_TO_CREATE_THREADS);
        _sym2str(CKR_CANT_LOCK);
        _sym2str(CKR_ATTRIBUTE_READ_ONLY);
        _sym2str(CKR_ATTRIBUTE_SENSITIVE);
        _sym2str(CKR_ATTRIBUTE_TYPE_INVALID);
        _sym2str(CKR_ATTRIBUTE_VALUE_INVALID);
        _sym2str(CKR_DATA_INVALID);
        _sym2str(CKR_DATA_LEN_RANGE);
        _sym2str(CKR_DEVICE_ERROR);
        _sym2str(CKR_DEVICE_MEMORY);
        _sym2str(CKR_DEVICE_REMOVED);
        _sym2str(CKR_ENCRYPTED_DATA_INVALID);
        _sym2str(CKR_ENCRYPTED_DATA_LEN_RANGE);
        _sym2str(CKR_FUNCTION_CANCELED);
        _sym2str(CKR_FUNCTION_NOT_PARALLEL);
        _sym2str(CKR_FUNCTION_NOT_SUPPORTED);
        _sym2str(CKR_KEY_HANDLE_INVALID);
        _sym2str(CKR_KEY_SIZE_RANGE);
        _sym2str(CKR_KEY_TYPE_INCONSISTENT);
        _sym2str(CKR_KEY_NOT_NEEDED);
        _sym2str(CKR_KEY_CHANGED);
        _sym2str(CKR_KEY_NEEDED);
        _sym2str(CKR_KEY_INDIGESTIBLE);
        _sym2str(CKR_KEY_FUNCTION_NOT_PERMITTED);
        _sym2str(CKR_KEY_NOT_WRAPPABLE);
        _sym2str(CKR_KEY_UNEXTRACTABLE);
        _sym2str(CKR_MECHANISM_INVALID);
        _sym2str(CKR_MECHANISM_PARAM_INVALID);
        _sym2str(CKR_OBJECT_HANDLE_INVALID);
        _sym2str(CKR_OPERATION_ACTIVE);
        _sym2str(CKR_OPERATION_NOT_INITIALIZED);
        _sym2str(CKR_PIN_INCORRECT);
        _sym2str(CKR_PIN_INVALID);
        _sym2str(CKR_PIN_LEN_RANGE);
        _sym2str(CKR_PIN_EXPIRED);
        _sym2str(CKR_PIN_LOCKED);
        _sym2str(CKR_SESSION_CLOSED);
        _sym2str(CKR_SESSION_COUNT);
        _sym2str(CKR_SESSION_HANDLE_INVALID);
        _sym2str(CKR_SESSION_PARALLEL_NOT_SUPPORTED);
        _sym2str(CKR_SESSION_READ_ONLY);
        _sym2str(CKR_SESSION_EXISTS);
        _sym2str(CKR_SESSION_READ_ONLY_EXISTS);
        _sym2str(CKR_SESSION_READ_WRITE_SO_EXISTS);
        _sym2str(CKR_SIGNATURE_INVALID);
        _sym2str(CKR_SIGNATURE_LEN_RANGE);
        _sym2str(CKR_TEMPLATE_INCOMPLETE);
        _sym2str(CKR_TEMPLATE_INCONSISTENT);
        _sym2str(CKR_TOKEN_NOT_PRESENT);
        _sym2str(CKR_TOKEN_NOT_RECOGNIZED);
        _sym2str(CKR_TOKEN_WRITE_PROTECTED);
        _sym2str(CKR_UNWRAPPING_KEY_HANDLE_INVALID);
        _sym2str(CKR_UNWRAPPING_KEY_SIZE_RANGE);
        _sym2str(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT);
        _sym2str(CKR_USER_ALREADY_LOGGED_IN);
        _sym2str(CKR_USER_NOT_LOGGED_IN);
        _sym2str(CKR_USER_PIN_NOT_INITIALIZED);
        _sym2str(CKR_USER_TYPE_INVALID);
        _sym2str(CKR_USER_ANOTHER_ALREADY_LOGGED_IN);
        _sym2str(CKR_USER_TOO_MANY_TYPES);
        _sym2str(CKR_WRAPPED_KEY_INVALID);
        _sym2str(CKR_WRAPPED_KEY_LEN_RANGE);
        _sym2str(CKR_WRAPPING_KEY_HANDLE_INVALID);
        _sym2str(CKR_WRAPPING_KEY_SIZE_RANGE);
        _sym2str(CKR_WRAPPING_KEY_TYPE_INCONSISTENT);
        _sym2str(CKR_RANDOM_SEED_NOT_SUPPORTED);
        _sym2str(CKR_RANDOM_NO_RNG);
        _sym2str(CKR_DOMAIN_PARAMS_INVALID);
        _sym2str(CKR_CURVE_NOT_SUPPORTED);
        _sym2str(CKR_BUFFER_TOO_SMALL);
        _sym2str(CKR_SAVED_STATE_INVALID);
        _sym2str(CKR_INFORMATION_SENSITIVE);
        _sym2str(CKR_STATE_UNSAVEABLE);
        _sym2str(CKR_CRYPTOKI_NOT_INITIALIZED);
        _sym2str(CKR_CRYPTOKI_ALREADY_INITIALIZED);
        _sym2str(CKR_MUTEX_BAD);
        _sym2str(CKR_MUTEX_NOT_LOCKED);
        _sym2str(CKR_FUNCTION_REJECTED);
        _sym2str(CKR_ACTION_PROHIBITED);
        _sym2str(CKR_AEAD_DECRYPT_FAILED);
        _sym2str(CKR_NEW_PIN_MODE);
        _sym2str(CKR_NEXT_OTP);
        _sym2str(CKR_EXCEEDED_MAX_ITERATIONS);
        _sym2str(CKR_FIPS_SELF_TEST_FAILED);
        _sym2str(CKR_LIBRARY_LOAD_FAILED);
        _sym2str(CKR_PIN_TOO_WEAK);
        _sym2str(CKR_PUBLIC_KEY_INVALID);
    default:
        return "UNKNOWN";
    }
}

#ifndef CKA_IBM_PQC_PARAMS
#define CKA_IBM_PQC_PARAMS (CKA_VENDOR_DEFINED +0x1000e)
#endif

//
// p11_get_cka - return textual interpretation of an attribute type
// only simple types - no arrays. For unknown a ptr to a static
// buffer is returned. So be carefull this is not thread safe then.
//
const char *p11_get_cka(CK_ATTRIBUTE_TYPE atype)
{
    static char buf[50];

    switch (atype) {
        _sym2str(CKA_CLASS);
        _sym2str(CKA_TOKEN);
        _sym2str(CKA_PRIVATE);
        _sym2str(CKA_LABEL);
        _sym2str(CKA_UNIQUE_ID);
        _sym2str(CKA_VALUE);
        _sym2str(CKA_OBJECT_ID);
        _sym2str(CKA_CERTIFICATE_TYPE);
        _sym2str(CKA_ISSUER);
        _sym2str(CKA_SERIAL_NUMBER);
        _sym2str(CKA_ATTR_TYPES);
        _sym2str(CKA_TRUSTED);
        _sym2str(CKA_KEY_TYPE);
        _sym2str(CKA_SUBJECT);
        _sym2str(CKA_CERTIFICATE_CATEGORY);
        _sym2str(CKA_JAVA_MIDP_SECURITY_DOMAIN);
        _sym2str(CKA_URL);
        _sym2str(CKA_HASH_OF_SUBJECT_PUBLIC_KEY);
        _sym2str(CKA_HASH_OF_ISSUER_PUBLIC_KEY);
        _sym2str(CKA_NAME_HASH_ALGORITHM);
        _sym2str(CKA_CHECK_VALUE);
        _sym2str(CKA_ID);
        _sym2str(CKA_SENSITIVE);
        _sym2str(CKA_ENCRYPT);
        _sym2str(CKA_DECRYPT);
        _sym2str(CKA_WRAP);
        _sym2str(CKA_UNWRAP);
        _sym2str(CKA_SIGN);
        _sym2str(CKA_SIGN_RECOVER);
        _sym2str(CKA_VERIFY);
        _sym2str(CKA_VERIFY_RECOVER);
        _sym2str(CKA_DERIVE);
        _sym2str(CKA_START_DATE);
        _sym2str(CKA_END_DATE);
        _sym2str(CKA_MODULUS);
        _sym2str(CKA_MODULUS_BITS);
        _sym2str(CKA_PUBLIC_EXPONENT);
        _sym2str(CKA_PRIVATE_EXPONENT);
        _sym2str(CKA_PRIME_1);
        _sym2str(CKA_PRIME_2);
        _sym2str(CKA_EXPONENT_1);
        _sym2str(CKA_EXPONENT_2);
        _sym2str(CKA_COEFFICIENT);
        _sym2str(CKA_PUBLIC_KEY_INFO);
        _sym2str(CKA_PRIME);
        _sym2str(CKA_SUBPRIME);
        _sym2str(CKA_BASE);
        _sym2str(CKA_PRIME_BITS);
        _sym2str(CKA_SUBPRIME_BITS);
        _sym2str(CKA_VALUE_BITS);
        _sym2str(CKA_VALUE_LEN);
        _sym2str(CKA_EXTRACTABLE);
        _sym2str(CKA_LOCAL);
        _sym2str(CKA_NEVER_EXTRACTABLE);
        _sym2str(CKA_ALWAYS_SENSITIVE);
        _sym2str(CKA_KEY_GEN_MECHANISM);
        _sym2str(CKA_MODIFIABLE);
        _sym2str(CKA_COPYABLE);
        _sym2str(CKA_DESTROYABLE);
        _sym2str(CKA_EC_PARAMS);
        _sym2str(CKA_EC_POINT);
        _sym2str(CKA_SECONDARY_AUTH);
        _sym2str(CKA_AUTH_PIN_FLAGS);
        _sym2str(CKA_ALWAYS_AUTHENTICATE);
        _sym2str(CKA_WRAP_WITH_TRUSTED);
        _sym2str(CKA_HW_FEATURE_TYPE);
        _sym2str(CKA_RESET_ON_INIT);
        _sym2str(CKA_HAS_RESET);
        _sym2str(CKA_WRAP_TEMPLATE);
        _sym2str(CKA_UNWRAP_TEMPLATE);
        _sym2str(CKA_DERIVE_TEMPLATE);
        _sym2str(CKA_ALLOWED_MECHANISMS);
        _sym2str(CKA_PROFILE_ID);
        _sym2str(CKA_IBM_OPAQUE);
        _sym2str(CKA_IBM_OPAQUE_REENC);
        _sym2str(CKA_IBM_OPAQUE_OLD);
        _sym2str(CKA_IBM_RESTRICTABLE);
        _sym2str(CKA_IBM_NEVER_MODIFIABLE);
        _sym2str(CKA_IBM_RETAINKEY);
        _sym2str(CKA_IBM_ATTRBOUND);
        _sym2str(CKA_IBM_KEYTYPE);
        _sym2str(CKA_IBM_CV);
        _sym2str(CKA_IBM_MACKEY);
        _sym2str(CKA_IBM_USE_AS_DATA);
        _sym2str(CKA_IBM_STRUCT_PARAMS);
        _sym2str(CKA_IBM_STD_COMPLIANCE1);
        _sym2str(CKA_IBM_PROTKEY_EXTRACTABLE);
        _sym2str(CKA_IBM_PROTKEY_NEVER_EXTRACTABLE);
        _sym2str(CKA_IBM_OPAQUE_PKEY);
        _sym2str(CKA_IBM_DILITHIUM_KEYFORM);
        _sym2str(CKA_IBM_DILITHIUM_MODE);
        _sym2str(CKA_IBM_ML_DSA_RHO);
        _sym2str(CKA_IBM_ML_DSA_SEED);
        _sym2str(CKA_IBM_ML_DSA_TR);
        _sym2str(CKA_IBM_ML_DSA_S1);
        _sym2str(CKA_IBM_ML_DSA_S2);
        _sym2str(CKA_IBM_ML_DSA_T0);
        _sym2str(CKA_IBM_ML_DSA_T1);
        _sym2str(CKA_IBM_ML_DSA_PRIVATE_SEED);
        _sym2str(CKA_IBM_PQC_PARAMS);
        _sym2str(CKA_IBM_KYBER_KEYFORM);
        _sym2str(CKA_IBM_KYBER_MODE);
        _sym2str(CKA_IBM_ML_KEM_PK);
        _sym2str(CKA_IBM_ML_KEM_SK);
        _sym2str(CKA_IBM_ML_KEM_PRIVATE_SEED);
        _sym2str(CKA_IBM_CCA_AES_KEY_MODE);
        _sym2str(CKA_IBM_PARAMETER_SET);
    default:
        sprintf(buf, "unknown attribute type 0x%08lx", atype);
        return buf;
    }
}

// is_attribute_defined()
//
// determine whether the specified attribute is defined by Cryptoki
//
CK_BBOOL is_attribute_defined(CK_ATTRIBUTE_TYPE type)
{
    if (type >= CKA_VENDOR_DEFINED)
        return TRUE;

    switch (type) {
    case CKA_CLASS:
    case CKA_TOKEN:
    case CKA_PRIVATE:
    case CKA_LABEL:
    case CKA_APPLICATION:
    case CKA_VALUE:
    case CKA_CERTIFICATE_TYPE:
    case CKA_ISSUER:
    case CKA_SERIAL_NUMBER:
    case CKA_KEY_TYPE:
    case CKA_SUBJECT:
    case CKA_ID:
    case CKA_SENSITIVE:
    case CKA_ENCRYPT:
    case CKA_DECRYPT:
    case CKA_WRAP:
    case CKA_UNWRAP:
    case CKA_SIGN:
    case CKA_SIGN_RECOVER:
    case CKA_VERIFY:
    case CKA_VERIFY_RECOVER:
    case CKA_DERIVE:
    case CKA_START_DATE:
    case CKA_END_DATE:
    case CKA_MODULUS:
    case CKA_MODULUS_BITS:
    case CKA_PUBLIC_EXPONENT:
    case CKA_PRIVATE_EXPONENT:
    case CKA_PRIME_1:
    case CKA_PRIME_2:
    case CKA_EXPONENT_1:
    case CKA_EXPONENT_2:
    case CKA_COEFFICIENT:
    case CKA_PRIME:
    case CKA_SUBPRIME:
    case CKA_BASE:
    case CKA_VALUE_BITS:
    case CKA_VALUE_LEN:
    case CKA_EXTRACTABLE:
    case CKA_LOCAL:
    case CKA_NEVER_EXTRACTABLE:
    case CKA_ALWAYS_SENSITIVE:
    case CKA_ALWAYS_AUTHENTICATE:
    case CKA_MODIFIABLE:
    case CKA_UNIQUE_ID:
    case CKA_PROFILE_ID:
    case CKA_ECDSA_PARAMS:
    case CKA_EC_POINT:
    case CKA_HW_FEATURE_TYPE:
    case CKA_HAS_RESET:
    case CKA_RESET_ON_INIT:
    case CKA_KEY_GEN_MECHANISM:
    case CKA_PRIME_BITS:
    case CKA_SUBPRIME_BITS:
    case CKA_OBJECT_ID:
    case CKA_AC_ISSUER:
    case CKA_OWNER:
    case CKA_ATTR_TYPES:
    case CKA_TRUSTED:
    case CKA_WRAP_WITH_TRUSTED:
    case CKA_WRAP_TEMPLATE:
    case CKA_UNWRAP_TEMPLATE:
    case CKA_CERTIFICATE_CATEGORY:
    case CKA_JAVA_MIDP_SECURITY_DOMAIN:
    case CKA_URL:
    case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
    case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
    case CKA_NAME_HASH_ALGORITHM:
    case CKA_CHECK_VALUE:
    case CKA_PUBLIC_KEY_INFO:
    case CKA_COPYABLE:
    case CKA_DESTROYABLE:
    case CKA_ALLOWED_MECHANISMS:
    case CKA_DERIVE_TEMPLATE:
        return TRUE;
    }

    return FALSE;
}

/*
 * Returns true if the attribute is an attribute array type.
 */
CK_BBOOL is_attribute_attr_array(CK_ATTRIBUTE_TYPE type)
{
    if (!is_attribute_defined(type))
        return FALSE;

    switch (type) {
    case CKA_WRAP_TEMPLATE:
    case CKA_UNWRAP_TEMPLATE:
    case CKA_DERIVE_TEMPLATE:
         return TRUE;
    }

    return FALSE;
}


const char *p11_get_ckm(const struct mechtable_funcs *f, CK_ULONG mechanism)
{
    const struct mechrow *row = f->p_row_from_num(mechanism);

    if (row)
        return row->string;
    return "UNKNOWN";
}

// Allocates memory on *dst and puts hex dump from ptr
// with len bytes.
// *dst must be freed by the caller
char *p11_ahex_dump(char **dst, CK_BYTE_PTR ptr, CK_ULONG len)
{
    CK_ULONG i;

    if (dst == NULL) {
        return NULL;
    }

    *dst = (char *) malloc(2 * len + 1);
    if (*dst == NULL) {
        return NULL;
    }

    for (i = 0; i < len; i++) {
        sprintf(*dst + 2 * i, "%02hhX", ptr[i]);
    }
    *(*dst + 2 * len) = '\0';   // null-terminate

    return *dst;
}


/* p11_bigint_trim() - trim a big integer. Returns pointer that is
 *        contained within 'in' + '*size' that represents
 *        the same number, but without leading zeros.
 *  @in   points to a sequence of bytes forming a big integer,
 *        unsigned, right-aligned and big-endian
 *  @size points to the size of @in on input, and the minimum
 *        size that can represent it on output
 */
CK_BYTE_PTR p11_bigint_trim(CK_BYTE_PTR in, CK_ULONG_PTR size)
{
    CK_ULONG i;

    for (i = 0; (i < *size) && in[i] == 0x00; i++);
    *size -= i;

    return in + i;
}

/* p11_attribute_trim() - trim a PKCS#11 CK_ATTRIBUTE in place,
 *      using memmove() to move the data and adjusting
 *      ulValueLen. The resulting "pValue" pointer stays the
 *      same so that the caller can free() it normally
 * @attr is the pointer to the CK_ATTRIBUTE to be trimmed
 */
void p11_attribute_trim(CK_ATTRIBUTE *attr)
{

    CK_BYTE_PTR ptr;
    CK_ULONG size;

    if (attr != NULL && attr->ulValueLen > 0 && attr->pValue != NULL) {
        size = attr->ulValueLen;
        ptr = p11_bigint_trim(attr->pValue, &size);

        if (ptr != attr->pValue) {
            attr->ulValueLen = size;
            memmove(attr->pValue, ptr, size);
        }
    }
}

/* p11_strlen() - calculate the length of CK_CHAR field, which
 *          are not '\0' terminated but padded with spaces.
 * @s       is a pointer to a CK_CHAR string.
 * @max_len is its maximum length.
 */
size_t p11_strlen(const CK_CHAR *s, size_t max_len)
{
    size_t len = max_len;

    while (len > 0 && s[len - 1] == ' ')
        --len;
    return len;
}
