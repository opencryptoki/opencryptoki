/*
 * COPYRIGHT (c) International Business Machines Corp. 2005-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/**
 * This is an example of how you might convert your library's internal
 * mechanism descriptors into PKCS#11-compatible descriptors while
 * generating a mechanism list for openCryptoki.
 */

#include "mech_types.h"

#ifndef NULL
#define NULL 0
#endif

/**
 * Bogus internal data descriptors for various mechanisms.
 */
#define CUSTOM_MECH_TDES 1
#define CUSTOM_MECH_BLOWFISH 2
#define CUSTOM_MECH_RIPEMD160 3
#define CUSTOM_MECH_DSA 4

/**
 * An example of a library's way of representing a mechanism.
 */
struct custom_mech_descriptor {
	int mech_type;
	int min_key_size;
	int max_key_size;
	int is_hw_accelerated;
	int support_encrypt;
	int support_decrypt;
	int support_digest;
	int support_wrap;
	int support_unwrap;
	int support_sign;
	int support_verify;
};

/**
 * Something like this should actually be filled in by querying the
 * driver for what is available; if the library supports software
 * fallback, then the CKF_HW flag should not be set so openCryptoki is
 * aware of what really is hardware accelerated and what is not.
 */
struct custom_mech_descriptor library_specific_mechs[] = {
	{CUSTOM_MECH_TDES, 24, 24, 1, 1, 1, 0, 1, 1, 0, 0},
	{CUSTOM_MECH_BLOWFISH, 16, 16, 1, 1, 1, 0, 1, 1, 0, 0},
	{CUSTOM_MECH_RIPEMD160, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0},
	{CUSTOM_MECH_DSA, 512, 4096, 1, 0, 0, 0, 0, 0, 1, 1}
};
#define CUSTOM_MECH_ARRAY_SIZE 4

/**
 * Here is an example of how you might map your driver's type
 * descriptors to the PKCS#11 type descriptors
 */
struct mech_type_mapping {
	int internal_mech_type;
	CK_MECHANISM_TYPE pkcs11_mech_type;
};

/**
 * The mapping from the internal driver type to the PKCS#11 type.
 */
struct mech_type_mapping mech_type_map[] = {
	{CUSTOM_MECH_TDES, CKM_DES3_CBC},
	{CUSTOM_MECH_BLOWFISH, CKM_VENDOR_DEFINED},
	{CUSTOM_MECH_RIPEMD160, CKM_RIPEMD160},
	{CUSTOM_MECH_DSA, CKM_DSA}
};
#define MECH_TYPE_MAP_SIZE 4

static CK_MECHANISM_TYPE pkcs11_mech_type_for_internal_type(int internal_type)
{
	int i = 0;
	CK_MECHANISM_TYPE pkcs11_type = CKM_VENDOR_DEFINED;
	while (i < MECH_TYPE_MAP_SIZE) {
		if (mech_type_map[i].internal_mech_type == internal_type) {
			pkcs11_type = mech_type_map[i].pkcs11_mech_type;
			break;
		}
		i++;
	}
	return pkcs11_type;
}

/**
 * Example method that converts a library's internal mechanism
 * descriptor into a PKCS#11 mechanism descriptor. Yours may look very
 * different from this one...
 */
static void convert_internal_element_to_pkcs11_method_element(
	MECH_LIST_ELEMENT *element,
	struct custom_mech_descriptor *internal_mech)
{
	element->mech_type =
		pkcs11_mech_type_for_internal_type(internal_mech->mech_type);
	element->mech_info.ulMinKeySize = internal_mech->min_key_size;
	element->mech_info.ulMaxKeySize = internal_mech->max_key_size;
	element->mech_info.flags = 0;
	/* Partial example list of flags that could be set */
	if (internal_mech->is_hw_accelerated) {
		element->mech_info.flags |= CKF_HW;
	}
	if (internal_mech->support_encrypt) {
		element->mech_info.flags |= CKF_ENCRYPT;
	}
	if (internal_mech->support_decrypt) {
		element->mech_info.flags |= CKF_DECRYPT;
	}
	if (internal_mech->support_digest) {
		element->mech_info.flags |= CKF_DIGEST;
	}
	if (internal_mech->support_wrap) {
		element->mech_info.flags |= CKF_WRAP;
	}
	if (internal_mech->support_unwrap) {
		element->mech_info.flags |= CKF_UNWRAP;
	}
	if (internal_mech->support_sign) {
		element->mech_info.flags |= CKF_SIGN;
	}
	if (internal_mech->support_verify) {
		element->mech_info.flags |= CKF_VERIFY;
	}
	/* ... */
}

/**
 * Generates a list of supported mechanisms. This is the function that
 * openCryptoki will be calling directly with a pointer to a
 * placeholder mech_list struct.
 *
 * @param head Pointer to placeholder mech_list struct; this function
 *             fills in the list by tagging on newly malloc'd
 *             mech_list structs off of this struct.
 */
void generate_pkcs11_mech_list(struct mech_list *head)
{
	struct mech_list *item;
	int i = 0;
	item = head;
	while (i < CUSTOM_MECH_ARRAY_SIZE) {
		item->next = malloc(sizeof(struct mech_list));
		item = item->next;
		convert_internal_element_to_pkcs11_method_element(
			&item->element, &library_specific_mechs[i]);
		i++;
	}
	item->next = NULL;
	return;
}
