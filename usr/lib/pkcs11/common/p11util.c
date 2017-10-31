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

#define _sym2str(X)     case X: return #X

//
// p11_get_ckr - return textual interpretation of a CKR_ error code
// @rc is the CKR_.. error
//
char *p11_get_ckr( CK_RV rc )
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
      _sym2str(CKR_BUFFER_TOO_SMALL);
      _sym2str(CKR_SAVED_STATE_INVALID);
      _sym2str(CKR_INFORMATION_SENSITIVE);
      _sym2str(CKR_STATE_UNSAVEABLE);
      _sym2str(CKR_CRYPTOKI_NOT_INITIALIZED);
      _sym2str(CKR_CRYPTOKI_ALREADY_INITIALIZED);
      _sym2str(CKR_MUTEX_BAD);
      _sym2str(CKR_MUTEX_NOT_LOCKED);
      default:					return "UNKNOWN";
   }
}

// is_attribute_defined()
//
// determine whether the specified attribute is defined by Cryptoki
//
CK_BBOOL
is_attribute_defined( CK_ATTRIBUTE_TYPE type )
{
   if (type >= CKA_VENDOR_DEFINED)
      return TRUE;

   switch (type)
   {
      case  CKA_CLASS:
      case  CKA_TOKEN:
      case  CKA_PRIVATE:
      case  CKA_LABEL:
      case  CKA_APPLICATION:
      case  CKA_VALUE:
      case  CKA_CERTIFICATE_TYPE:
      case  CKA_ISSUER:
      case  CKA_SERIAL_NUMBER:
      case  CKA_KEY_TYPE:
      case  CKA_SUBJECT:
      case  CKA_ID:
      case  CKA_SENSITIVE:
      case  CKA_ENCRYPT:
      case  CKA_DECRYPT:
      case  CKA_WRAP:
      case  CKA_UNWRAP:
      case  CKA_SIGN:
      case  CKA_SIGN_RECOVER:
      case  CKA_VERIFY:
      case  CKA_VERIFY_RECOVER:
      case  CKA_DERIVE:
      case  CKA_START_DATE:
      case  CKA_END_DATE:
      case  CKA_MODULUS:
      case  CKA_MODULUS_BITS:
      case  CKA_PUBLIC_EXPONENT:
      case  CKA_PRIVATE_EXPONENT:
      case  CKA_PRIME_1:
      case  CKA_PRIME_2:
      case  CKA_EXPONENT_1:
      case  CKA_EXPONENT_2:
      case  CKA_COEFFICIENT:
      case  CKA_PRIME:
      case  CKA_SUBPRIME:
      case  CKA_BASE:
      case  CKA_VALUE_BITS:
      case  CKA_VALUE_LEN:
      case  CKA_EXTRACTABLE:
      case  CKA_LOCAL:
      case  CKA_NEVER_EXTRACTABLE:
      case  CKA_ALWAYS_SENSITIVE:
      case  CKA_ALWAYS_AUTHENTICATE:
      case  CKA_MODIFIABLE:
      case  CKA_ECDSA_PARAMS:
      case  CKA_EC_POINT:
      case  CKA_HW_FEATURE_TYPE:
      case  CKA_HAS_RESET:
      case  CKA_RESET_ON_INIT:
      case  CKA_KEY_GEN_MECHANISM:
      case  CKA_PRIME_BITS:
      case  CKA_SUBPRIME_BITS:
      case  CKA_OBJECT_ID:
      case  CKA_AC_ISSUER:
      case  CKA_OWNER:
      case  CKA_ATTR_TYPES:
      case  CKA_TRUSTED:
         return TRUE;
   }

   return FALSE;
}


char *
p11_get_ckm(CK_ULONG mechanism)
{
	switch (mechanism) {
	_sym2str(CKM_RSA_PKCS_KEY_PAIR_GEN);
	_sym2str(CKM_RSA_PKCS);
	_sym2str(CKM_RSA_9796);
	_sym2str(CKM_RSA_X_509);
	_sym2str(CKM_MD2_RSA_PKCS);
	_sym2str(CKM_MD5_RSA_PKCS);
	_sym2str(CKM_SHA1_RSA_PKCS);
	_sym2str(CKM_RIPEMD128_RSA_PKCS);
	_sym2str(CKM_RIPEMD160_RSA_PKCS);
	_sym2str(CKM_RSA_PKCS_OAEP);
	_sym2str(CKM_RSA_X9_31_KEY_PAIR_GEN);
	_sym2str(CKM_RSA_X9_31);
	_sym2str(CKM_SHA1_RSA_X9_31);
	_sym2str(CKM_RSA_PKCS_PSS);
	_sym2str(CKM_SHA1_RSA_PKCS_PSS);
	_sym2str(CKM_DSA_KEY_PAIR_GEN);
	_sym2str(CKM_DSA);
	_sym2str(CKM_DSA_SHA1);
	_sym2str(CKM_DH_PKCS_KEY_PAIR_GEN);
	_sym2str(CKM_DH_PKCS_DERIVE);
	_sym2str(CKM_X9_42_DH_KEY_PAIR_GEN);
	_sym2str(CKM_X9_42_DH_DERIVE);
	_sym2str(CKM_X9_42_DH_HYBRID_DERIVE);
	_sym2str(CKM_X9_42_MQV_DERIVE);
	_sym2str(CKM_SHA256_RSA_PKCS);
	_sym2str(CKM_SHA384_RSA_PKCS);
	_sym2str(CKM_SHA512_RSA_PKCS);
	_sym2str(CKM_RC2_KEY_GEN);
	_sym2str(CKM_RC2_ECB);
	_sym2str(CKM_RC2_CBC);
	_sym2str(CKM_RC2_MAC);
	_sym2str(CKM_RC2_MAC_GENERAL);
	_sym2str(CKM_RC2_CBC_PAD);
	_sym2str(CKM_RC4_KEY_GEN);
	_sym2str(CKM_RC4);
	_sym2str(CKM_DES_KEY_GEN);
	_sym2str(CKM_DES_ECB);
	_sym2str(CKM_DES_CBC);
	_sym2str(CKM_DES_MAC);
	_sym2str(CKM_DES_MAC_GENERAL);
	_sym2str(CKM_DES_CBC_PAD);
	_sym2str(CKM_DES2_KEY_GEN);
	_sym2str(CKM_DES3_KEY_GEN);
	_sym2str(CKM_DES3_ECB);
	_sym2str(CKM_DES3_CBC);
	_sym2str(CKM_DES3_MAC);
	_sym2str(CKM_DES3_MAC_GENERAL);
	_sym2str(CKM_DES3_CBC_PAD);
	_sym2str(CKM_CDMF_KEY_GEN);
	_sym2str(CKM_CDMF_ECB);
	_sym2str(CKM_CDMF_CBC);
	_sym2str(CKM_CDMF_MAC);
	_sym2str(CKM_CDMF_MAC_GENERAL);
	_sym2str(CKM_CDMF_CBC_PAD);
	_sym2str(CKM_MD2);
	_sym2str(CKM_MD2_HMAC);
	_sym2str(CKM_MD2_HMAC_GENERAL);
	_sym2str(CKM_MD5);
	_sym2str(CKM_MD5_HMAC);
	_sym2str(CKM_MD5_HMAC_GENERAL);
	_sym2str(CKM_SHA_1);
	_sym2str(CKM_SHA_1_HMAC);
	_sym2str(CKM_SHA_1_HMAC_GENERAL);
	_sym2str(CKM_RIPEMD128);
	_sym2str(CKM_RIPEMD128_HMAC);
	_sym2str(CKM_RIPEMD128_HMAC_GENERAL);
	_sym2str(CKM_RIPEMD160);
	_sym2str(CKM_RIPEMD160_HMAC);
	_sym2str(CKM_RIPEMD160_HMAC_GENERAL);
	_sym2str(CKM_SHA256);
	_sym2str(CKM_SHA256_HMAC);
	_sym2str(CKM_SHA256_HMAC_GENERAL);
	_sym2str(CKM_SHA384);
	_sym2str(CKM_SHA384_HMAC);
	_sym2str(CKM_SHA384_HMAC_GENERAL);
	_sym2str(CKM_SHA512);
	_sym2str(CKM_SHA512_HMAC);
	_sym2str(CKM_SHA512_HMAC_GENERAL);
	_sym2str(CKM_CAST_KEY_GEN);
	_sym2str(CKM_CAST_ECB);
	_sym2str(CKM_CAST_CBC);
	_sym2str(CKM_CAST_MAC);
	_sym2str(CKM_CAST_MAC_GENERAL);
	_sym2str(CKM_CAST_CBC_PAD);
	_sym2str(CKM_CAST3_KEY_GEN);
	_sym2str(CKM_CAST3_ECB);
	_sym2str(CKM_CAST3_CBC);
	_sym2str(CKM_CAST3_MAC);
	_sym2str(CKM_CAST3_MAC_GENERAL);
	_sym2str(CKM_CAST3_CBC_PAD);
	_sym2str(CKM_CAST5_KEY_GEN);
	_sym2str(CKM_CAST5_ECB);
	_sym2str(CKM_CAST5_CBC);
	_sym2str(CKM_CAST5_MAC);
	_sym2str(CKM_CAST5_MAC_GENERAL);
	_sym2str(CKM_CAST5_CBC_PAD);
	_sym2str(CKM_RC5_KEY_GEN);
	_sym2str(CKM_RC5_ECB);
	_sym2str(CKM_RC5_CBC);
	_sym2str(CKM_RC5_MAC);
	_sym2str(CKM_RC5_MAC_GENERAL);
	_sym2str(CKM_RC5_CBC_PAD);
	_sym2str(CKM_IDEA_KEY_GEN);
	_sym2str(CKM_IDEA_ECB);
	_sym2str(CKM_IDEA_CBC);
	_sym2str(CKM_IDEA_MAC);
	_sym2str(CKM_IDEA_MAC_GENERAL);
	_sym2str(CKM_IDEA_CBC_PAD);
	_sym2str(CKM_GENERIC_SECRET_KEY_GEN);
	_sym2str(CKM_CONCATENATE_BASE_AND_KEY);
	_sym2str(CKM_CONCATENATE_BASE_AND_DATA);
	_sym2str(CKM_CONCATENATE_DATA_AND_BASE);
	_sym2str(CKM_XOR_BASE_AND_DATA);
	_sym2str(CKM_EXTRACT_KEY_FROM_KEY);
	_sym2str(CKM_SSL3_PRE_MASTER_KEY_GEN);
	_sym2str(CKM_SSL3_MASTER_KEY_DERIVE);
	_sym2str(CKM_SSL3_KEY_AND_MAC_DERIVE);
	_sym2str(CKM_SSL3_MASTER_KEY_DERIVE_DH);
	_sym2str(CKM_TLS_PRE_MASTER_KEY_GEN);
	_sym2str(CKM_TLS_MASTER_KEY_DERIVE);
	_sym2str(CKM_TLS_KEY_AND_MAC_DERIVE);
	_sym2str(CKM_TLS_MASTER_KEY_DERIVE_DH);
	_sym2str(CKM_SSL3_MD5_MAC);
	_sym2str(CKM_SSL3_SHA1_MAC);
	_sym2str(CKM_MD5_KEY_DERIVATION);
	_sym2str(CKM_MD2_KEY_DERIVATION);
	_sym2str(CKM_SHA1_KEY_DERIVATION);
	_sym2str(CKM_SHA256_KEY_DERIVATION);
	_sym2str(CKM_PBE_MD2_DES_CBC);
	_sym2str(CKM_PBE_MD5_DES_CBC);
	_sym2str(CKM_PBE_MD5_CAST_CBC);
	_sym2str(CKM_PBE_MD5_CAST3_CBC);
	_sym2str(CKM_PBE_MD5_CAST5_CBC);
	_sym2str(CKM_PBE_SHA1_CAST5_CBC);
	_sym2str(CKM_PBE_SHA1_RC4_128);
	_sym2str(CKM_PBE_SHA1_RC4_40);
	_sym2str(CKM_PBE_SHA1_DES3_EDE_CBC);
	_sym2str(CKM_PBE_SHA1_DES2_EDE_CBC);
	_sym2str(CKM_PBE_SHA1_RC2_128_CBC);
	_sym2str(CKM_PBE_SHA1_RC2_40_CBC);
	_sym2str(CKM_PKCS5_PBKD2);
	_sym2str(CKM_PBA_SHA1_WITH_SHA1_HMAC);
	_sym2str(CKM_KEY_WRAP_LYNKS);
	_sym2str(CKM_KEY_WRAP_SET_OAEP);
	_sym2str(CKM_SKIPJACK_KEY_GEN);
	_sym2str(CKM_SKIPJACK_ECB64);
	_sym2str(CKM_SKIPJACK_CBC64);
	_sym2str(CKM_SKIPJACK_OFB64);
	_sym2str(CKM_SKIPJACK_CFB64);
	_sym2str(CKM_SKIPJACK_CFB32);
	_sym2str(CKM_SKIPJACK_CFB16);
	_sym2str(CKM_SKIPJACK_CFB8);
	_sym2str(CKM_SKIPJACK_WRAP);
	_sym2str(CKM_SKIPJACK_PRIVATE_WRAP);
	_sym2str(CKM_SKIPJACK_RELAYX);
	_sym2str(CKM_KEA_KEY_PAIR_GEN);
	_sym2str(CKM_KEA_KEY_DERIVE);
	_sym2str(CKM_FORTEZZA_TIMESTAMP);
	_sym2str(CKM_BATON_KEY_GEN);
	_sym2str(CKM_BATON_ECB128);
	_sym2str(CKM_BATON_ECB96);
	_sym2str(CKM_BATON_CBC128);
	_sym2str(CKM_BATON_COUNTER);
	_sym2str(CKM_BATON_SHUFFLE);
	_sym2str(CKM_BATON_WRAP);
	_sym2str(CKM_EC_KEY_PAIR_GEN);
	_sym2str(CKM_ECDSA);
	_sym2str(CKM_ECDSA_SHA1);
	_sym2str(CKM_ECDSA_SHA256);
	_sym2str(CKM_ECDSA_SHA384);
	_sym2str(CKM_ECDSA_SHA512);
	_sym2str(CKM_ECDH1_DERIVE);
	_sym2str(CKM_ECDH1_COFACTOR_DERIVE);
	_sym2str(CKM_ECMQV_DERIVE);
	_sym2str(CKM_JUNIPER_KEY_GEN);
	_sym2str(CKM_JUNIPER_ECB128);
	_sym2str(CKM_JUNIPER_CBC128);
	_sym2str(CKM_JUNIPER_COUNTER);
	_sym2str(CKM_JUNIPER_SHUFFLE);
	_sym2str(CKM_JUNIPER_WRAP);
	_sym2str(CKM_FASTHASH);
	_sym2str(CKM_AES_KEY_GEN);
	_sym2str(CKM_AES_ECB);
	_sym2str(CKM_AES_CBC);
	_sym2str(CKM_AES_MAC);
	_sym2str(CKM_AES_MAC_GENERAL);
	_sym2str(CKM_AES_CBC_PAD);
	_sym2str(CKM_AES_CTR);
	_sym2str(CKM_DSA_PARAMETER_GEN);
	_sym2str(CKM_DH_PKCS_PARAMETER_GEN);
	_sym2str(CKM_X9_42_DH_PARAMETER_GEN);
	_sym2str(CKM_VENDOR_DEFINED);
	default:				return "UNKNOWN";
	}
}

// Allocates memory on *dst and puts hex dump from ptr
// with len bytes.
// *dst must be freed by the caller
char *
p11_ahex_dump(char **dst, CK_BYTE_PTR ptr, CK_ULONG len)
{
    CK_ULONG i;

    if (dst == NULL) {
        return NULL;
    }

    *dst = (char *) calloc(2*len + 1 , sizeof(char));
    if (*dst == NULL) {
        return NULL;
    }

    for (i = 0; i < len; i++) {
            sprintf(*dst + 2*i, "%02hhX", ptr[i]);
    }
    *(*dst + 2*len) = '\0';      // null-terminate

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
CK_BYTE_PTR
p11_bigint_trim(CK_BYTE_PTR in, CK_ULONG_PTR size) {
   CK_ULONG i;

   for (i = 0;
        (i < *size) && in[i] == 0x00;
        i++);
   *size -= i;
   return in + i;
}

/* p11_attribute_trim() - trim a PKCS#11 CK_ATTRIBUTE in place,
 *      using memmove() to move the data and adjusting
 *      ulValueLen. The resulting "pValue" pointer stays the
 *      same so that the caller can free() it normally
 * @attr is the pointer to the CK_ATTRIBUTE to be trimmed
 */
void
p11_attribute_trim(CK_ATTRIBUTE *attr) {

   CK_BYTE_PTR ptr;
   CK_ULONG    size;

   if (attr != NULL) {
      size = attr->ulValueLen;
      ptr = p11_bigint_trim(attr->pValue, &size);

      if (ptr != attr->pValue) {
         attr->ulValueLen = size;
         memmove(attr->pValue, ptr, size);
      }
   }
}
