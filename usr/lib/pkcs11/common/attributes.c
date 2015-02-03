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
#include <stdlib.h>
#include <string.h>
#include "attributes.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "trace.h"

/*
 * Free an array of attributes allocated with dup_attribute_array().
 */
void
free_attribute_array(CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len)
{
	CK_ULONG i;

	if (!attrs)
		return;

	for (i = 0; i < attrs_len; i++)
		if (attrs[i].pValue)
			free(attrs[i].pValue);
	free(attrs);
}

/*
 * Duplicate an array of attributes and all its values.
 *
 * The returned array must be freed with free_attribute_array().
 */
CK_RV
dup_attribute_array(CK_ATTRIBUTE_PTR orig, CK_ULONG orig_len,
		    CK_ATTRIBUTE_PTR *p_dest, CK_ULONG *p_dest_len)
{
	CK_RV rc = CKR_OK;
	CK_ATTRIBUTE_PTR dest;
	CK_ULONG dest_len;
	CK_ATTRIBUTE_PTR it;

	/* Allocate the new array */
	dest_len = orig_len;
	dest = malloc(dest_len * sizeof(*dest));
	if (dest == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return CKR_HOST_MEMORY;
	}
	memset(dest, 0, dest_len);

	/* Copy each element */
	for (it = dest; it != (dest + orig_len); it++, orig++) {
		it->type = orig->type;
		it->ulValueLen = orig->ulValueLen;
		it->pValue = malloc(it->ulValueLen);
		if (it->pValue == NULL) {
			TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
			rc = CKR_HOST_MEMORY;
			goto done;
		}
		memcpy(it->pValue, orig->pValue, orig->ulValueLen);
	}

done:
	if (rc == CKR_OK) {
		*p_dest = dest;
		*p_dest_len = dest_len;
	} else {
		free_attribute_array(dest, dest_len);
	}
	return rc;
}

/*
 * Return the attribute structure for a given type.
 */
CK_ATTRIBUTE_PTR
get_attribute_by_type(CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len, CK_ULONG type)
{
	CK_ATTRIBUTE_PTR it;

	for (it = attrs; it != attrs + attrs_len; it++)
		if (it->type == type)
			return it;
	return NULL;
}

/*
 * Reallocate the attribute array and add the new element.
 */
CK_RV
add_to_attribute_array(CK_ATTRIBUTE_PTR *p_attrs, CK_ULONG_PTR p_attrs_len,
		       CK_ULONG type, CK_BYTE_PTR value, CK_ULONG value_len)
{
	CK_ATTRIBUTE_PTR attrs;
	CK_BYTE_PTR copied_value;

	copied_value = malloc(value_len);
	if (copied_value == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return CKR_HOST_MEMORY;
	}
	memcpy(copied_value, value, value_len);

	attrs = realloc(*p_attrs, sizeof(**p_attrs) * (*p_attrs_len + 1));
	if (attrs == NULL) {
		free(copied_value);
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return CKR_HOST_MEMORY;
	}

	attrs[*p_attrs_len].type = type;
	attrs[*p_attrs_len].pValue = copied_value;
	attrs[*p_attrs_len].ulValueLen= value_len;
	*p_attrs = attrs;
	*p_attrs_len += 1;
	return CKR_OK;
}
