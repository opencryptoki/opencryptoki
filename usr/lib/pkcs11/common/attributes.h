/*
 * Licensed materials, Property of IBM Corp.
 *
 * OpenCryptoki ICSF token - LDAP functions
 *
 * (C) COPYRIGHT International Business Machines Corp. 2012
 *
 * Author: Marcelo Cerri (mhcerri@br.ibm.com)
 *
 */
#ifndef _ATTRIBUTES_H_
#define _ATTRIBUTES_H_

#include "pkcs11types.h"

void
free_attribute_array(CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len);

CK_RV
dup_attribute_array(CK_ATTRIBUTE_PTR orig, CK_ULONG orig_len,
		    CK_ATTRIBUTE_PTR *p_dest, CK_ULONG *p_dest_len);

CK_ATTRIBUTE_PTR
get_attribute_by_type(CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len,
		      CK_ULONG type);

CK_RV
add_to_attribute_array(CK_ATTRIBUTE_PTR *p_attrs, CK_ULONG_PTR p_attrs_len,
		       CK_ULONG type, CK_BYTE_PTR value, CK_ULONG value_len);
#endif
