/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/* File:  template.c
 *
 * Attribute template management routines
 *
 * Functions contained in this file:
 *
 *    template_add_attributes
 *    template_add_default_attributes
 *    template_attribute_find
 *    template_check_required_attributes
 *    template_check_required_base_attributes
 *    template_free
 *    template_set_default_common_attributes
 *    template_update_attribute
 *    template_validate_attribute
 *    template_validate_attributes
 *    template_validate_base_attribute
 */

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "pkcs32.h"
#include "p11util.h"
#include "trace.h"

/* template_add_attributes()
 *
 * blindly add the given attributes to the template. do no sanity checking
 * at this point. sanity checking will occur later.
 */
CK_RV template_add_attributes(TEMPLATE *tmpl, CK_ATTRIBUTE *pTemplate,
			      CK_ULONG ulCount)
{
	CK_ATTRIBUTE *attr = NULL;
	CK_RV rc;
	unsigned int i;

	for (i = 0; i < ulCount; i++) {
		if (!is_attribute_defined(pTemplate[i].type)) {
			TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_TYPE_INVALID));
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
		attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) +
					      pTemplate[i].ulValueLen);
		if (!attr) {
			TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
			return CKR_HOST_MEMORY;
		}
		attr->type = pTemplate[i].type;
		attr->ulValueLen = pTemplate[i].ulValueLen;

		if (attr->ulValueLen != 0) {
			attr->pValue = (CK_BYTE *)attr + sizeof(CK_ATTRIBUTE);
			memcpy(attr->pValue, pTemplate[i].pValue,
				attr->ulValueLen);
		} else
			attr->pValue = NULL;

		rc = template_update_attribute(tmpl, attr);
		if (rc != CKR_OK) {
			free(attr);
			TRACE_DEVEL("template_update_attribute failed.\n");
			return rc;
		}
	}

	return CKR_OK;
}


/* template_add_default_attributes()
 * Add default attributes to '*tmpl'.
 * '*basetmpl' may be used to derive values to the default attributes
 */
CK_RV template_add_default_attributes(TEMPLATE *tmpl, TEMPLATE *basetmpl,
				      CK_ULONG class, CK_ULONG subclass,
				      CK_ULONG mode)
{
	CK_RV rc;

	/* first add the default common attributes */
	rc = template_set_default_common_attributes(tmpl);
	if (rc != CKR_OK) {
		TRACE_DEVEL("template_set_default_common_attributes failed.\n");
		return rc;
	}

	/* set the template class-specific default attributes */
	switch (class) {
	case CKO_DATA:
		return data_object_set_default_attributes(tmpl, mode);

	case CKO_CERTIFICATE:
		if (subclass == CKC_X_509)
			return cert_x509_set_default_attributes(tmpl, mode);
		else
			return CKR_OK;

	case CKO_PUBLIC_KEY:
		switch (subclass) {
		case CKK_RSA:
			return rsa_publ_set_default_attributes(tmpl, basetmpl,
								mode);
		case CKK_DSA:
			return dsa_publ_set_default_attributes(tmpl, mode);

		case CKK_ECDSA:
			return ecdsa_publ_set_default_attributes(tmpl, mode);

		case CKK_DH:
			return dh_publ_set_default_attributes(tmpl, mode);

		case CKK_KEA:
			return kea_publ_set_default_attributes(tmpl, mode);

		default:
			TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
			return CKR_ATTRIBUTE_VALUE_INVALID; // unknown key type
		}

	case CKO_PRIVATE_KEY:
		switch (subclass) {
		case CKK_RSA:
			return rsa_priv_set_default_attributes(tmpl, mode);

		case CKK_DSA:
			return dsa_priv_set_default_attributes(tmpl, mode);

		case CKK_ECDSA:
			return ecdsa_priv_set_default_attributes(tmpl, mode);

		case CKK_DH:
			return dh_priv_set_default_attributes(tmpl, mode);

		case CKK_KEA:
			return kea_priv_set_default_attributes(tmpl, mode);

		default:
			TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
			return CKR_ATTRIBUTE_VALUE_INVALID; // unknown key type
		}

	case CKO_SECRET_KEY:
		switch (subclass) {
		case CKK_GENERIC_SECRET:
			return generic_secret_set_default_attributes(tmpl, mode);
		case CKK_RC2:
			return rc2_set_default_attributes(tmpl, mode);

		case CKK_RC4:
			return rc4_set_default_attributes(tmpl, mode);

		case CKK_RC5:
			return rc5_set_default_attributes(tmpl, mode);

		case CKK_DES:
			return des_set_default_attributes(tmpl, mode);

		case CKK_DES2:
			return des2_set_default_attributes(tmpl, mode);

		case CKK_DES3:
			return des3_set_default_attributes(tmpl, mode);

		case CKK_CAST:
			return cast_set_default_attributes(tmpl, mode);

		case CKK_CAST3:
			return cast3_set_default_attributes(tmpl, mode);

		case CKK_CAST5:
			return cast5_set_default_attributes(tmpl, mode);

		case CKK_IDEA:
			return idea_set_default_attributes(tmpl, mode);

#if !(NOCDMF)
		case CKK_CDMF:
			return cdmf_set_default_attributes(tmpl, mode);
#endif

		case CKK_SKIPJACK:
			return skipjack_set_default_attributes(tmpl, mode);

		case CKK_BATON:
			return baton_set_default_attributes(tmpl, mode);

		case CKK_JUNIPER:
			return juniper_set_default_attributes(tmpl, mode);

		case CKK_AES:
			return aes_set_default_attributes(tmpl, mode);

		default:
			TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
			return CKR_ATTRIBUTE_VALUE_INVALID; // unknown key type
		}

	case CKO_HW_FEATURE:
		switch (subclass) {
		case CKH_CLOCK:
			return clock_set_default_attributes(tmpl, mode);

		case CKH_MONOTONIC_COUNTER:
			return counter_set_default_attributes(tmpl, mode);

		default:
			TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
		return CKR_ATTRIBUTE_VALUE_INVALID;
		}

	case CKO_DOMAIN_PARAMETERS:
		switch (subclass) {
		case CKK_DSA:
			return dp_dsa_set_default_attributes(tmpl, mode);

		case CKK_DH:
			return dp_dh_set_default_attributes(tmpl, mode);

		case CKK_X9_42_DH:
			return dp_x9dh_set_default_attributes(tmpl, mode);

		default:
			TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}

	default:
		TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}
}


/* template_attribute_find()
 *
 * find the attribute in the list and return its value
 */
CK_BBOOL template_attribute_find(TEMPLATE *tmpl, CK_ATTRIBUTE_TYPE type,
				 CK_ATTRIBUTE **attr)
{
	DL_NODE *node = NULL;
	CK_ATTRIBUTE *a = NULL;

	if (!tmpl || !attr)
		return FALSE;

	node = tmpl->attribute_list;

	while (node != NULL) {
		a = (CK_ATTRIBUTE *)node->data;

		if (type == a->type) {
			*attr = a;
			return TRUE;
		}

		node = node->next;
	}

	*attr = NULL;
	return FALSE;
}

/* template_attribute_find_multiple()
 *
 * find the attributes in the list and return their values
 */
void template_attribute_find_multiple(TEMPLATE *tmpl,
				      ATTRIBUTE_PARSE_LIST *parselist,
				      CK_ULONG plcount)
{
	CK_ATTRIBUTE *attr = NULL;
	CK_ULONG i;

	for (i = 0; i < plcount; i++) {
		parselist[i].found = template_attribute_find(tmpl,
						parselist[i].type, &attr);

		if (parselist[i].found && parselist[i].ptr != NULL)
			memcpy(parselist[i].ptr, attr->pValue,
				parselist[i].len);
	}
}


/* template_check_required_attributes() */
CK_RV template_check_required_attributes(TEMPLATE *tmpl, CK_ULONG class,
					 CK_ULONG subclass, CK_ULONG mode)
{
	if (class == CKO_DATA)
		return data_object_check_required_attributes(tmpl, mode);
	else if (class == CKO_CERTIFICATE) {
		if (subclass == CKC_X_509)
			return cert_x509_check_required_attributes(tmpl, mode);
		else
			return cert_vendor_check_required_attributes(tmpl, mode);
	} else if (class == CKO_PUBLIC_KEY) {
		switch (subclass) {
		case CKK_RSA:
			return rsa_publ_check_required_attributes(tmpl, mode);

		case CKK_DSA:
			return dsa_publ_check_required_attributes(tmpl, mode);

		case CKK_ECDSA:
			return ecdsa_publ_check_required_attributes(tmpl, mode);

		case CKK_DH:
			return dh_publ_check_required_attributes(tmpl, mode);

		case CKK_KEA:
			return kea_publ_check_required_attributes(tmpl, mode);

		default:
			TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
			return CKR_ATTRIBUTE_VALUE_INVALID;  // unknown keytype
		}
	} else if (class == CKO_PRIVATE_KEY) {
		switch (subclass) {
		case CKK_RSA:
			return rsa_priv_check_required_attributes(tmpl, mode);

		case CKK_DSA:
			return dsa_priv_check_required_attributes(tmpl, mode);

		case CKK_ECDSA:
			return ecdsa_priv_check_required_attributes(tmpl, mode);

		case CKK_DH:
			return dh_priv_check_required_attributes(tmpl, mode);

		case CKK_KEA:
			return kea_priv_check_required_attributes(tmpl, mode);

		default:
			TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
			return CKR_ATTRIBUTE_VALUE_INVALID; // unknown key type
		}
	} else if (class == CKO_SECRET_KEY) {
		switch (subclass) {
		case CKK_GENERIC_SECRET:
			return generic_secret_check_required_attributes(tmpl,
									mode );
		case CKK_RC2:
			return rc2_check_required_attributes(tmpl, mode);

		case CKK_RC4:
			return rc4_check_required_attributes(tmpl, mode);

		case CKK_RC5:
			return rc5_check_required_attributes(tmpl, mode);

		case CKK_DES:
			return des_check_required_attributes(tmpl, mode);

		case CKK_DES2:
			return des2_check_required_attributes(tmpl, mode);

		case CKK_DES3:
			return des3_check_required_attributes(tmpl, mode);

		case CKK_CAST:
			return cast_check_required_attributes(tmpl, mode);

		case CKK_CAST3:
			return cast3_check_required_attributes(tmpl, mode);

		case CKK_CAST5:
			return cast5_check_required_attributes(tmpl, mode);

		case CKK_IDEA:
			return idea_check_required_attributes(tmpl, mode);

#if !(NOCDMF)
		case CKK_CDMF:
			return cdmf_check_required_attributes(tmpl, mode);
#endif

		case CKK_SKIPJACK:
			return skipjack_check_required_attributes(tmpl, mode);

		case CKK_BATON:
			return baton_check_required_attributes(tmpl, mode);

		case CKK_JUNIPER:
			return juniper_check_required_attributes(tmpl, mode);

		case CKK_AES:
			return aes_check_required_attributes(tmpl, mode);

		default:
			TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
			return CKR_ATTRIBUTE_VALUE_INVALID;  // unknown key type
		}
	} else if (class == CKO_HW_FEATURE) {
		switch (subclass) {
		case CKH_CLOCK:
			return clock_check_required_attributes(tmpl, mode);

		case CKH_MONOTONIC_COUNTER:
			return counter_check_required_attributes(tmpl, mode);

		default:
			TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
	} else if (class == CKO_DOMAIN_PARAMETERS) {
		switch (subclass) {
		case CKK_DSA:
			return dp_dsa_check_required_attributes(tmpl, mode);

		case CKK_DH:
			return dp_dh_check_required_attributes(tmpl, mode);

		case CKK_X9_42_DH:
			return dp_x9dh_check_required_attributes(tmpl, mode);

		default:
			TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
	}

	TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
	return CKR_ATTRIBUTE_VALUE_INVALID;   // default fallthru
}


/* template_check_required_base_attributes()
 *
 * check to make sure that attributes required by Cryptoki are
 * present.  does not check to see if the attribute makes sense
 * for the particular object (that is done in the 'validate' routines)
 */
CK_RV template_check_required_base_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
	CK_ATTRIBUTE *attr;
	CK_BBOOL found;

	found = template_attribute_find(tmpl, CKA_CLASS, &attr);
	if (mode == MODE_CREATE && found == FALSE)
		return CKR_TEMPLATE_INCOMPLETE;

	return CKR_OK;
}

/* template_compare() */
CK_BBOOL template_compare(CK_ATTRIBUTE *t1, CK_ULONG ulCount, TEMPLATE *t2)
{
	CK_ATTRIBUTE *attr1 = NULL;
	CK_ATTRIBUTE *attr2 = NULL;
	CK_ULONG i;
	CK_RV rc;

	if (!t1 || !t2)
		return FALSE;

	attr1 = t1;

	for (i = 0; i < ulCount; i++) {
		rc = template_attribute_find(t2, attr1->type, &attr2);
		if (rc == FALSE)
			return FALSE;

		if (attr1->ulValueLen != attr2->ulValueLen)
			return FALSE;

		if (memcmp(attr1->pValue, attr2->pValue, attr1->ulValueLen) != 0)
		return FALSE;

		attr1++;
	}

	return TRUE;
}


/* template_copy()
 *
 * This doesn't copy the template items verbatim.  The new template is in
 * the reverse order of the old one.  This should not have any effect.
 *
 * This is very similar to template_merge().  template_merge() can also
 * be used to copy a list (of unique attributes) but is slower because for
 * each attribute, it must search through the list.
 */
CK_RV template_copy(TEMPLATE *dest, TEMPLATE *src)
{
	DL_NODE *node;

	if (!dest || !src) {
		TRACE_ERROR("Invalid function arguments.\n");
		return CKR_FUNCTION_FAILED;
	}
	node = src->attribute_list;

	while (node) {
		CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *)node->data;
		CK_ATTRIBUTE *new_attr = NULL;
		CK_ULONG len;

		len = sizeof(CK_ATTRIBUTE) + attr->ulValueLen;

		new_attr = (CK_ATTRIBUTE *)malloc(len);
		if (!new_attr) {
			TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
			return CKR_HOST_MEMORY;
		}
		memcpy(new_attr, attr, len);

		new_attr->pValue = (CK_BYTE *)new_attr + sizeof(CK_ATTRIBUTE);

		dest->attribute_list = dlist_add_as_first(dest->attribute_list,
							  new_attr);
		node = node->next;
	}

	return CKR_OK;
}


/* template_flatten()
 * this still gets used when saving token objects to disk
 */
CK_RV template_flatten(TEMPLATE *tmpl, CK_BYTE *dest)
{
	DL_NODE *node = NULL;
	CK_BYTE *ptr = NULL;
	CK_ULONG_32 long_len;
	CK_ATTRIBUTE_32 *attr_32 = NULL;
	CK_ULONG Val;
	CK_ULONG_32 Val_32;
	CK_ULONG *pVal;

	long_len = sizeof(CK_ULONG);

	if (!tmpl || !dest) {
		TRACE_ERROR("Invalid function arguments.\n");
		return CKR_FUNCTION_FAILED;
	}
	ptr = dest;
	node = tmpl->attribute_list;
	while (node) {
		CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *)node->data;

		if (long_len == 4) {
			memcpy(ptr, attr,
			       sizeof(CK_ATTRIBUTE) + attr->ulValueLen);
			ptr += sizeof(CK_ATTRIBUTE) + attr->ulValueLen;
		} else {
			attr_32 = malloc(sizeof(CK_ATTRIBUTE_32));
			if (!attr_32) {
				TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
				return CKR_HOST_MEMORY;
			}
			attr_32->type = attr->type;
			attr_32->pValue = 0x00;
			if ((attr->type == CKA_CLASS ||
			     attr->type == CKA_KEY_TYPE ||
			     attr->type == CKA_MODULUS_BITS ||
			     attr->type == CKA_VALUE_BITS ||
			     attr->type == CKA_CERTIFICATE_TYPE ||
			     attr->type == CKA_VALUE_LEN ) &&
			     attr->ulValueLen != 0) {

				attr_32->ulValueLen = sizeof(CK_ULONG_32);

				memcpy(ptr, attr_32, sizeof(CK_ATTRIBUTE_32));
				ptr += sizeof(CK_ATTRIBUTE_32);

				pVal = (CK_ULONG *)attr->pValue;
				Val = *pVal;
				Val_32 = (CK_ULONG_32)Val;
				memcpy( ptr, &Val_32, sizeof(CK_ULONG_32));
				ptr += sizeof(CK_ULONG_32);
			} else {
				attr_32->ulValueLen = attr->ulValueLen;
				memcpy(ptr, attr_32, sizeof(CK_ATTRIBUTE_32));
				ptr += sizeof(CK_ATTRIBUTE_32);
				if (attr->ulValueLen != 0) {
					memcpy(ptr, attr->pValue,
					       attr->ulValueLen);
					ptr += attr->ulValueLen;
				}
			}
		}

		node = node->next;
	}

	if (attr_32)
		free(attr_32);

	return CKR_OK;
}

CK_RV template_unflatten(TEMPLATE **new_tmpl, CK_BYTE *buf, CK_ULONG count)
{
	return template_unflatten_withSize(new_tmpl, buf, count, -1);
}

/* Modified version of template_unflatten that checks
 * that buf isn't overread.  buf_size=-1 turns off checking
 * (for backwards compatability)
 */
CK_RV template_unflatten_withSize(TEMPLATE **new_tmpl, CK_BYTE *buf,
				  CK_ULONG count, int buf_size)
{
	TEMPLATE *tmpl = NULL;
	CK_ATTRIBUTE *a2 = NULL;
	CK_BYTE *ptr = NULL;
	CK_ULONG i, len;
	CK_RV rc;
	CK_ULONG_32 long_len = sizeof(CK_ULONG);
	CK_ULONG_32 attr_ulong_32;
	CK_ULONG attr_ulong;
	CK_ATTRIBUTE *a1_64 = NULL;
	CK_ATTRIBUTE_32 *a1 = NULL;


	if (!new_tmpl || !buf) {
		TRACE_ERROR("Invalid function arguments.\n");
		return CKR_FUNCTION_FAILED;
	}
	tmpl = (TEMPLATE *)malloc(sizeof(TEMPLATE));
	if (!tmpl) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return CKR_HOST_MEMORY;
	}
	memset(tmpl, 0x0, sizeof(TEMPLATE));

	ptr = buf;
	for (i=0; i < count; i++) {
		if (buf_size >= 0 &&
		    ((ptr + sizeof(CK_ATTRIBUTE)) > (buf + buf_size))) {
			template_free( tmpl );
			return CKR_FUNCTION_FAILED;
		}

		if (long_len == 4) {
			a1_64 = (CK_ATTRIBUTE *)ptr;

			len = sizeof(CK_ATTRIBUTE) + a1_64->ulValueLen;
			a2 = (CK_ATTRIBUTE *)malloc(len);
			if (!a2) {
				template_free(tmpl);
				TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
				return CKR_HOST_MEMORY;
			}

			/* if a buffer size is given, make sure it
			 * doesn't get overrun
			 */
			if (buf_size >= 0 &&
			    (((void*)a1_64 + len) > ((void*)buf + buf_size))) {
				free(a2);
				template_free(tmpl);
				return CKR_FUNCTION_FAILED;
			}
			memcpy(a2, a1_64, len);
		} else {
			a1 = (CK_ATTRIBUTE_32 *)ptr;

			if ((a1->type == CKA_CLASS || a1->type == CKA_KEY_TYPE
			    || a1->type == CKA_MODULUS_BITS
			    || a1->type == CKA_VALUE_BITS
			    || a1->type == CKA_CERTIFICATE_TYPE
			    || a1->type == CKA_VALUE_LEN)
			    && a1->ulValueLen != 0) {
				len = sizeof(CK_ATTRIBUTE) + sizeof(CK_ULONG);
			} else {
				len = sizeof(CK_ATTRIBUTE) + a1->ulValueLen;
			}

			a2 = (CK_ATTRIBUTE *)malloc(len);
			if (!a2) {
				template_free(tmpl);
				TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
				return CKR_HOST_MEMORY;
			}
			a2->type = a1->type;

			if ((a1->type == CKA_CLASS || a1->type == CKA_KEY_TYPE
			    || a1->type == CKA_MODULUS_BITS
			    || a1->type == CKA_VALUE_BITS
			    || a1->type == CKA_CERTIFICATE_TYPE
			    || a1->type == CKA_VALUE_LEN)
			    && a1->ulValueLen != 0) {

				a2->ulValueLen = sizeof(CK_ULONG);

				{
					CK_ULONG_32 *p32;
					CK_BYTE *pb2;

					pb2 = (CK_BYTE *)a1;
					pb2 += sizeof (CK_ATTRIBUTE_32);
					p32 = (CK_ULONG_32 *)pb2;
					attr_ulong_32 = *p32;
				}

				attr_ulong = attr_ulong_32;

				{
					CK_BYTE *pb2;
					pb2 = (CK_BYTE *)a2;
					pb2 += sizeof(CK_ATTRIBUTE);
					memcpy(pb2, (CK_BYTE *)&attr_ulong,
					       sizeof(CK_ULONG));
				}
			} else {
				CK_BYTE *pb2,*pb;

				a2->ulValueLen = a1->ulValueLen;
				pb2 = (CK_BYTE *)a2;
				pb2 += sizeof(CK_ATTRIBUTE);
				pb = (CK_BYTE *)a1;
				pb += sizeof(CK_ATTRIBUTE_32);
				/* if a buffer size is given, make sure it
				 * doesn't get overrun
				 */
				if (buf_size >= 0 &&
				    (pb + a1->ulValueLen) > (buf + buf_size)) {
					free(a2);
					template_free(tmpl);
					return CKR_FUNCTION_FAILED;
				}
				memcpy(pb2, pb, a1->ulValueLen);
			}
		}

		if (a2->ulValueLen != 0)
			a2->pValue = (CK_BYTE *)a2 + sizeof(CK_ATTRIBUTE);
		else
			a2->pValue = NULL;

		rc = template_update_attribute(tmpl, a2);
		if (rc != CKR_OK) {
			free(a2);
			template_free(tmpl);
			return rc;
		}
		if (long_len == 4)
			ptr += len;
		else
			ptr += sizeof(CK_ATTRIBUTE_32) + a1->ulValueLen;
	}

	*new_tmpl = tmpl;
	return CKR_OK;
}


/* template_free() */
CK_RV template_free(TEMPLATE *tmpl)
{
	if (!tmpl)
		return CKR_OK;

	while (tmpl->attribute_list) {
		CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *)tmpl->attribute_list->data;

		if (attr)
			free(attr);

		tmpl->attribute_list = dlist_remove_node(tmpl->attribute_list,
							 tmpl->attribute_list);
	}

	free(tmpl);
	return CKR_OK;
}

/* template_get_class */
CK_BBOOL template_get_class(TEMPLATE *tmpl, CK_ULONG *class, CK_ULONG *subclass)
{
	DL_NODE *node;
	CK_BBOOL found = FALSE;

	if (!tmpl || !class || !subclass)
		return FALSE;

	node = tmpl->attribute_list;

	/* have to iterate through all attributes. no early exits */
	while (node) {
		CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *)node->data;

		if (attr->type == CKA_CLASS) {
			*class = *(CK_OBJECT_CLASS *)attr->pValue;
			found = TRUE;
		}

		/* underneath, these guys are both CK_ULONG so we
		 * could combine this
		 */
		if (attr->type == CKA_CERTIFICATE_TYPE)
			*subclass = *(CK_CERTIFICATE_TYPE *)attr->pValue;

		if (attr->type == CKA_KEY_TYPE)
			*subclass = *(CK_KEY_TYPE *)attr->pValue;

		node = node->next;
	}

	return found;
}

CK_ULONG template_get_count(TEMPLATE *tmpl)
{
	if (tmpl == NULL)
		return 0;

	return dlist_length(tmpl->attribute_list);
}

CK_ULONG template_get_size(TEMPLATE *tmpl)
{
	DL_NODE *node;
	CK_ULONG size = 0;

	if (tmpl == NULL)
		return 0;

	node = tmpl->attribute_list;
	while (node) {
		CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *)node->data;

		size += sizeof(CK_ATTRIBUTE) + attr->ulValueLen;

		node = node->next;
	}

	return size;
}

CK_ULONG template_get_compressed_size(TEMPLATE *tmpl)
{
	DL_NODE *node;
	CK_ULONG size = 0;

	if (tmpl == NULL)
		return 0;
	node = tmpl->attribute_list;
	while (node) {
		CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *)node->data;

		size += sizeof(CK_ATTRIBUTE_32);
		if ((attr->type == CKA_CLASS || attr->type == CKA_KEY_TYPE
		    || attr->type == CKA_MODULUS_BITS
		    || attr->type == CKA_VALUE_BITS
		    || attr->type == CKA_CERTIFICATE_TYPE
		    || attr->type == CKA_VALUE_LEN)
		    && attr->ulValueLen != 0 ) {
			size += sizeof(CK_ULONG_32);
		} else {
			size += attr->ulValueLen;
		}

		node = node->next;
	}

	return size;
}

/* template_is_okay_to_reveal_attribute()
 *
 * determines whether the specified CK_ATTRIBUTE_TYPE is allowed to
 * be leave the card in the clear.  note: the specified template doesn't need
 * to actually posess an attribute of type 'type'.  The template is
 * provided mainly to determine the object class and subclass
 *
 * this routine is called by C_GetAttributeValue which exports the attributes
 * in the clear.  this routine is NOT called when wrapping a key.
 */
CK_BBOOL template_check_exportability(TEMPLATE *tmpl, CK_ATTRIBUTE_TYPE type)
{
	CK_ATTRIBUTE *sensitive = NULL;
	CK_ATTRIBUTE *extractable = NULL;
	CK_ULONG class;
	CK_ULONG subclass;
	CK_BBOOL sensitive_val;
	CK_BBOOL extractable_val;

	if (!tmpl)
		return FALSE;

	/* since 'tmpl' belongs to a validated object, it's safe
	 * to assume that the following routine works
	 */
	template_get_class(tmpl, &class, &subclass);

	/* Early exits:
	 * 1) CKA_SENSITIVE and CKA_EXTRACTABLE only apply to private key
	 * and secret key objects.  If object type is any other, then
	 * by default the attribute is exportable.
	 *
	 * 2) If CKA_SENSITIVE = FALSE  and CKA_EXTRACTABLE = TRUE then
	 * all attributes are exportable
	 */
	if (class != CKO_PRIVATE_KEY && class != CKO_SECRET_KEY)
		return TRUE;

	sensitive_val = template_attribute_find(tmpl, CKA_SENSITIVE,
						&sensitive);
	extractable_val = template_attribute_find(tmpl, CKA_EXTRACTABLE,
						  &extractable);
	if (sensitive_val && extractable_val) {
		sensitive_val = *(CK_BBOOL *)sensitive->pValue;
		extractable_val = *(CK_BBOOL *)extractable->pValue;
		if (sensitive_val == FALSE && extractable_val == TRUE)
			return TRUE;
	} else {
		/* technically, we should throw an error here... */
		return FALSE;
	}

	/* at this point, we know the object must have CKA_SENSITIVE = TRUE
	 * or CKA_EXTRACTABLE = FALSE (or both).
	 * need to determine whether the particular attribute in question is
	 * a "sensitive" attribute.
	 */

	if (class == CKO_PRIVATE_KEY) {
		switch (subclass) {
		case CKK_RSA:
			return rsa_priv_check_exportability(type);

		case CKK_DSA:
			return dsa_priv_check_exportability(type);

		case CKK_ECDSA:
			return ecdsa_priv_check_exportability(type);

		case CKK_X9_42_DH:
		case CKK_DH:
			return dh_priv_check_exportability(type);

		case CKK_KEA:
			return kea_priv_check_exportability(type);

		default:
			TRACE_ERROR("%s\n",
				    ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
			return TRUE;
		}
	} else if (class == CKO_SECRET_KEY) {
		return secret_key_check_exportability(type);
	}

	TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
	return TRUE;
}

/*  template_merge()
 *
 * Merge two templates together:  dest = dest U src
 *
 * src is destroyed in the process
 */
CK_RV template_merge(TEMPLATE *dest, TEMPLATE **src)
{
	DL_NODE *node;
	CK_RV rc;

	if (!dest || !src) {
		TRACE_ERROR("Invalid function arguments.\n");
		return CKR_FUNCTION_FAILED;
	}
	node = (*src)->attribute_list;

	while (node) {
		CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *)node->data;

		rc = template_update_attribute(dest, attr);
		if (rc != CKR_OK) {
			TRACE_DEVEL("template_update_attribute failed.\n");
			return rc;
		}
		/* we've assigned the node's data to a node in 'dest' */
		node->data = NULL;
		node = node->next;
	}

	template_free(*src);
	*src = NULL;

	return CKR_OK;
}

/* template_set_default_common_attributes()
 *
 * Set the default attributes common to all objects:
 *
 *	CKA_TOKEN:	FALSE
 *	CKA_PRIVATE:	TRUE -- Cryptoki leaves this up to the token to decide
 *	CKA_MODIFIABLE:	TRUE
 *	CKA_LABEL:	empty string
 */
CK_RV template_set_default_common_attributes(TEMPLATE *tmpl)
{
	CK_ATTRIBUTE *token_attr;
	CK_ATTRIBUTE *priv_attr;
	CK_ATTRIBUTE *mod_attr;
	CK_ATTRIBUTE *label_attr;

	/* add the default common attributes */
	token_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE)
					    + sizeof(CK_BBOOL));
	priv_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE)
					   + sizeof(CK_BBOOL));
	mod_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE)
					  + sizeof(CK_BBOOL));
	label_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + 0);

	if (!token_attr || !priv_attr || !mod_attr || !label_attr) {
		if (token_attr) free(token_attr);
		if (priv_attr) free(priv_attr);
		if (mod_attr) free(mod_attr);
		if (label_attr) free(label_attr);

		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return CKR_HOST_MEMORY;
	}

	token_attr->type = CKA_TOKEN;
	token_attr->ulValueLen = sizeof(CK_BBOOL);
	token_attr->pValue = (CK_BYTE *)token_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)token_attr->pValue = FALSE;

	priv_attr->type = CKA_PRIVATE;
	priv_attr->ulValueLen = sizeof(CK_BBOOL);
	priv_attr->pValue = (CK_BYTE *)priv_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)priv_attr->pValue = FALSE;

	mod_attr->type = CKA_MODIFIABLE;
	mod_attr->ulValueLen = sizeof(CK_BBOOL);
	mod_attr->pValue = (CK_BYTE *)mod_attr + sizeof(CK_ATTRIBUTE);
	*(CK_BBOOL *)mod_attr->pValue = TRUE;

	label_attr->type = CKA_LABEL;
	label_attr->ulValueLen = 0;	// empty string
	label_attr->pValue = NULL;

	template_update_attribute(tmpl, token_attr);
	template_update_attribute(tmpl, priv_attr);
	template_update_attribute(tmpl, mod_attr);
	template_update_attribute(tmpl, label_attr);

	/* the TEMPLATE 'owns' the attributes now.
	 * it is responsible for freeing them upon deletion...
	 */
	return CKR_OK;
}


/* template_update_attribute()
 *
 * modifies an existing attribute or adds a new attribute to the template
 *
 * Returns:  TRUE on success, FALSE on failure
 */
CK_RV template_update_attribute(TEMPLATE *tmpl, CK_ATTRIBUTE *new_attr)
{
	DL_NODE *node = NULL;
	CK_ATTRIBUTE *attr = NULL;

	if (!tmpl || !new_attr) {
		TRACE_ERROR("Invalid function arguments.\n");
		return CKR_FUNCTION_FAILED;
	}
	node = tmpl->attribute_list;

	/* if the attribute already exists in the list, remove it.
	 * this algorithm will limit an attribute to appearing at most
	 * once in the list
	 */
	while (node != NULL) {
		attr = (CK_ATTRIBUTE *)node->data;

		if (new_attr->type == attr->type) {
			free(attr);
			tmpl->attribute_list = dlist_remove_node(tmpl->attribute_list, node);
			break;
		}

		node = node->next;
	}

	/* add the new attribute */
	tmpl->attribute_list = dlist_add_as_first(tmpl->attribute_list,
						  new_attr);

	return CKR_OK;
}


/* template_validate_attribute()
 *
 * essentially a group of if-then-else-switch clauses.  separated from
 * template_validate_attributes() to make that routine more readable
 */
CK_RV template_validate_attribute(TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
				  CK_ULONG class, CK_ULONG subclass,
				  CK_ULONG mode)
{
	if (class == CKO_DATA)
		return data_object_validate_attribute(tmpl, attr, mode);
	else if (class == CKO_CERTIFICATE) {
		if (subclass == CKC_X_509)
			return cert_x509_validate_attribute(tmpl, attr, mode);
		else
			return cert_vendor_validate_attribute(tmpl, attr, mode);
	} else if (class == CKO_PUBLIC_KEY) {
		switch (subclass) {
		case CKK_RSA:
			return rsa_publ_validate_attribute(tmpl, attr, mode);

		case CKK_DSA:
			return dsa_publ_validate_attribute(tmpl, attr, mode);

		case CKK_ECDSA:
			return ecdsa_publ_validate_attribute(tmpl, attr, mode);

		case CKK_DH:
			return dh_publ_validate_attribute(tmpl, attr, mode);

		case CKK_KEA:
			return kea_publ_validate_attribute(tmpl, attr, mode);

		default:
			TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
			return CKR_ATTRIBUTE_VALUE_INVALID; // unknown key type
		}
	} else if (class == CKO_PRIVATE_KEY) {
		switch (subclass) {
		case CKK_RSA:
			return rsa_priv_validate_attribute(tmpl, attr, mode);

		case CKK_DSA:
			return dsa_priv_validate_attribute(tmpl, attr, mode);

		case CKK_ECDSA:
			return ecdsa_priv_validate_attribute(tmpl, attr, mode);

		case CKK_DH:
			return dh_priv_validate_attribute(tmpl, attr, mode);

		case CKK_KEA:
			return kea_priv_validate_attribute(tmpl, attr, mode);

		default:
			TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
			return CKR_ATTRIBUTE_VALUE_INVALID; // unknown key type
		}
	} else if (class == CKO_SECRET_KEY) {
		switch (subclass) {
		case CKK_GENERIC_SECRET:
			return generic_secret_validate_attribute(tmpl, attr,
								 mode);
		case CKK_RC2:
			return rc2_validate_attribute(tmpl, attr, mode);

		case CKK_RC4:
			return rc4_validate_attribute(tmpl, attr, mode);

		case CKK_RC5:
			return rc5_validate_attribute(tmpl, attr, mode);

		case CKK_DES:
			return des_validate_attribute(tmpl, attr, mode);

		case CKK_DES2:
			return des2_validate_attribute(tmpl, attr, mode);

		case CKK_DES3:
			return des3_validate_attribute(tmpl, attr, mode);

		case CKK_CAST:
			return cast_validate_attribute(tmpl, attr, mode);

		case CKK_CAST3:
			return cast3_validate_attribute(tmpl, attr, mode);

		case CKK_CAST5:
			return cast5_validate_attribute(tmpl, attr, mode);

		case CKK_IDEA:
			return idea_validate_attribute(tmpl, attr, mode);

#if !(NOCDMF)
		case CKK_CDMF:
			return cdmf_validate_attribute(tmpl, attr, mode);
#endif

		case CKK_SKIPJACK:
			return skipjack_validate_attribute(tmpl, attr, mode);

		case CKK_BATON:
			return baton_validate_attribute(tmpl, attr, mode);

		case CKK_JUNIPER:
			return juniper_validate_attribute(tmpl, attr, mode);

		case CKK_AES:
			return aes_validate_attribute(tmpl, attr, mode);

		default:
			TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
			return CKR_ATTRIBUTE_VALUE_INVALID; // unknown key type
		}
	} else if (class == CKO_HW_FEATURE) {
		switch (subclass) {
		case CKH_CLOCK:
			return clock_validate_attribute(tmpl, attr, mode);

		case CKH_MONOTONIC_COUNTER:
			return counter_validate_attribute(tmpl, attr, mode);

		default:
			TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
	} else if (class == CKO_DOMAIN_PARAMETERS) {
		switch (subclass) {
		case CKK_DSA:
			return dp_dsa_validate_attribute(tmpl, attr, mode);

		case CKK_DH:
			return dp_dh_validate_attribute(tmpl, attr, mode);

		case CKK_X9_42_DH:
			return dp_x9dh_validate_attribute(tmpl, attr, mode);

		default:
			TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
	}

	TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
	return CKR_ATTRIBUTE_VALUE_INVALID;   // default fallthru
}


/* template_validate_attributes()
 *
 * walk through the list of attributes in the template validating each one
 */
CK_RV template_validate_attributes(TEMPLATE *tmpl, CK_ULONG class,
				   CK_ULONG subclass, CK_ULONG mode)
{
	DL_NODE *node;
	CK_RV rc = CKR_OK;

	node = tmpl->attribute_list;

	while (node) {
		CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *)node->data;

		rc = template_validate_attribute(tmpl, attr, class,
						 subclass, mode);
		if (rc != CKR_OK) {
			TRACE_DEVEL("template_validate_attribute failed.\n");
			return rc;
		}
		node = node->next;
	}

	return CKR_OK;
}


/* template_validate_base_attribute() */
CK_RV template_validate_base_attribute(TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
				       CK_ULONG mode)
{
	if (!tmpl || !attr) {
		TRACE_ERROR("Invalid function arguments.\n");
		return CKR_FUNCTION_FAILED;
	}
	switch (attr->type) {
	case CKA_CLASS:
		if ((mode & (MODE_CREATE|MODE_DERIVE|MODE_KEYGEN|MODE_UNWRAP)) != 0)
			return CKR_OK;
		break;

	case CKA_TOKEN:
		if ((mode & (MODE_CREATE|MODE_COPY|MODE_DERIVE|MODE_KEYGEN|
			     MODE_UNWRAP)) != 0)
			return CKR_OK;
		break;

	case CKA_PRIVATE:
		if ((mode & (MODE_CREATE|MODE_COPY|MODE_DERIVE|MODE_KEYGEN|
			     MODE_UNWRAP)) != 0)
			return CKR_OK;
		break;

	case CKA_LABEL:
		return CKR_OK;

	case CKA_IBM_OPAQUE:
		/* Allow this attribute to be modified in order to support
		 * migratable keys on secure key tokens.
		 */
		if ((mode & (MODE_COPY|MODE_MODIFY)) != 0)
			return CKR_OK;
		break;

	case CKA_MODIFIABLE:
		if ((mode & (MODE_CREATE|MODE_COPY|MODE_DERIVE|MODE_KEYGEN|
			     MODE_UNWRAP)) != 0)
			return CKR_OK;
		break;

	default:
		TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
		return CKR_TEMPLATE_INCONSISTENT;
	}

	TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
	return CKR_ATTRIBUTE_READ_ONLY;
}
