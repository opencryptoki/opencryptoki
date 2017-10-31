/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef _P11UTIL_H_
#define _P11UTIL_H__


#include "pkcs11types.h"

//
// p11_get_ckr - return textual interpretation of a CKR_ error code
// @rc is the CKR_.. error
//
char *p11_get_ckr( CK_RV rc );
//
// p11_get_ckm - return textual interpretation of a CKM_ mechanism code
// @rc is the CKM_.. as a string
//
char *p11_get_ckm(CK_ULONG);

// is_attribute_defined()
//
// determine whether the specified attribute is defined by Cryptoki
//
CK_BBOOL is_attribute_defined( CK_ATTRIBUTE_TYPE type );

// Allocates memory on *dst and puts hex dump from ptr
// with len bytes.
// *dst must be freed by the caller
char * p11_ahex_dump(char **dst, CK_BYTE_PTR ptr, CK_ULONG len);

/* p11_bigint_trim() - trim a big integer. Returns pointer that is
 *        contained within 'in' + '*size' that represents
 *        the same number, but without leading zeros.
 *  @in   points to a sequence of bytes forming a big integer,
 *        unsigned, right-aligned and big-endian
 *  @size points to the size of @in on input, and the minimum
 *        size that can represent it on output
 */
CK_BYTE_PTR p11_bigint_trim(CK_BYTE_PTR in, CK_ULONG_PTR size);

/* p11_attribute_trim() - trim a PKCS#11 CK_ATTRIBUTE in place,
 *      using memmove() to move the data and adjusting
 *      ulValueLen. The resulting "pValue" pointer stays the
 *      same so that the caller can free() it normally
 * @attr is the pointer to the CK_ATTRIBUTE to be trimmed
 */
void p11_attribute_trim(CK_ATTRIBUTE *attr);

#endif  // #ifndef _P11UTIL_H_
