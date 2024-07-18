/*
 * COPYRIGHT (c) International Business Machines Corp. 2021-2024
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#define _DEFAULT_SOURCE

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "kmip.h"
#include "names.h"

/**
 * Constructs a Key Block node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Block                               Structure     v1.0
 *     Key Format Type             Yes       Enumeration   v1.0
 *     Key Compression Type        No        Enumeration   v1.0
 *     Key Value                   Yes       various       v1.0
 *     Cryptographic Algorithm     Yes       Enumeration   v1.0
 *     Cryptographic Length        Yes       Integer       v1.0
 *     Key Wrapping Data           No        Structure     v1.0
 *
 * @param format_type       the key format type
 * @param format_type       the key compression type (if 0 it is ignored)
 * @param key_value         the key value node
 * @param algorithm         the key algorithm (if 0 it is ignored)
 * @param length            the cryptographic length (if <= 0 it is ignored)
 * @param wrappig_data      the key wrapping data (can be NULL)
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_key_block(enum kmip_key_format_type format_type,
				     enum kmip_key_compression_type compr_type,
				     struct kmip_node *key_value,
				     enum kmip_crypto_algo algorithm,
				     int32_t length,
				     struct kmip_node *wrappig_data)
{
	struct kmip_node *ret = NULL, *fmt, *cmp = NULL, *algo = NULL;
	struct kmip_node *len = NULL;

	if (format_type == 0 || key_value == NULL)
		return NULL;

	fmt = kmip_node_new_enumeration(KMIP_TAG_KEY_FORMAT_TYPE, NULL,
					format_type);
	if (fmt == NULL)
		goto out;

	if (compr_type != 0) {
		cmp = kmip_node_new_enumeration(KMIP_TAG_KEY_COMPRESSION_TYPE,
						NULL, compr_type);
		if (cmp == NULL)
			goto out;
	}

	if (algorithm != 0) {
		algo = kmip_node_new_enumeration(
					KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM,
					NULL, algorithm);
		if (algo == NULL)
			goto out;
	}

	if (length > 0) {
		len = kmip_node_new_integer(KMIP_TAG_CRYPTOGRAPHIC_LENGTH, NULL,
					    length);
		if (len == NULL)
			goto out;
	}

	ret = kmip_node_new_structure_va(KMIP_TAG_KEY_BLOCK, NULL, 6, fmt, cmp,
					 key_value, algo, len, wrappig_data);

out:
	kmip_node_free(fmt);
	kmip_node_free(cmp);
	kmip_node_free(algo);
	kmip_node_free(len);

	return ret;
}

/**
 * Gets information from a Key Block node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Block                               Structure     v1.0
 *     Key Format Type             Yes       Enumeration   v1.0
 *     Key Compression Type        No        Enumeration   v1.0
 *     Key Value                   Yes       various       v1.0
 *     Cryptographic Algorithm     Yes       Enumeration   v1.0
 *     Cryptographic Length        Yes       Integer       v1.0
 *     Key Wrapping Data           No        Structure     v1.0
 *
 * @param node              the KMIP node
 * @param format_type       On return: the key format type
 * @param format_type       On return: the key compression type (0 if not avail,
 *                          can be NULL)
 * @param key_value         On return: the key value node (can be NULL)
 * @param algorithm         On return: the key algorithm (0 if not avail, can
 *                          be NULL)
 * @param length            On return: the cryptographic length (0 if not avail,
 *                          can be NULL)
 * @param wrappig_data      On return: the key wrapping data (can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_key_block(const struct kmip_node *node,
		       enum kmip_key_format_type *format_type,
		       enum kmip_key_compression_type *compr_type,
		       struct kmip_node **key_value,
		       enum kmip_crypto_algo *algorithm,
		       int32_t *length,
		       struct kmip_node **wrappig_data)
{
	struct kmip_node *n;

	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_KEY_BLOCK)
		return -EBADMSG;

	if (format_type != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_KEY_FORMAT_TYPE, 0);
		if (n == NULL)
			return -EBADMSG;
		*format_type = kmip_node_get_enumeration(n);
		kmip_node_free(n);
	}

	if (compr_type != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_KEY_COMPRESSION_TYPE, 0);
		if (n != NULL)
			*compr_type = kmip_node_get_enumeration(n);
		else
			*compr_type = 0;
		kmip_node_free(n);
	}

	if (algorithm != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, 0);
		if (n != NULL)
			*algorithm = kmip_node_get_enumeration(n);
		else
			*algorithm = 0;
		kmip_node_free(n);
	}

	if (length != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_CRYPTOGRAPHIC_LENGTH, 0);
		if (n != NULL)
			*length = kmip_node_get_integer(n);
		else
			*length = -1;
		kmip_node_free(n);
	}

	if (key_value != NULL) {
		*key_value = kmip_node_get_structure_element_by_tag(node,
							KMIP_TAG_KEY_VALUE, 0);
		if (*key_value == NULL)
			return -EBADMSG;
	}

	if (wrappig_data != NULL)
		*wrappig_data = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_KEY_WRAPPING_DATA, 0);

	return 0;
}

/**
 * Constructs a Key Value node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Value                               Structure     v1.0
 *     Key Material                Yes       various       v1.0
 *     Attribute                   No        Structure     v1.x only
 *     ... may be repeated
 *     Attributes                  No        Structure     v2.x only
 *
 * @param version           the protocol version. If null, the current default
 *                          protocol version is used.
 * @param key_material      the key material node
 * @param attrs_count       the number of attributes following (can be 0)
 * @param v2_attrs          the array of attributes (as KMIP v2.x attribute)
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_key_value(const struct kmip_version *version,
				     struct kmip_node *key_material,
				     unsigned int attrs_count,
				     struct kmip_node **v2_attrs)
{
	struct kmip_node *ret = NULL, *v2_attr, *v1_attr, *attrs = NULL;
	unsigned int i;
	int rc;

	if (key_material == NULL)
		return NULL;
	if (attrs_count > 0 && v2_attrs == NULL)
		return NULL;

	if (version == NULL)
		version = kmip_get_default_protocol_version();

	if (version->major == 1) {
		/* KMIP v1.x */
		ret = kmip_node_new_structure_va(KMIP_TAG_KEY_VALUE, NULL, 1,
						 key_material);
		if (ret == NULL)
			return NULL;

		for (i = 0; i < attrs_count; i++) {
			v2_attr = v2_attrs[i];
			if (v2_attr == NULL)
				continue;

			rc = kmip_v1_attr_from_v2_attr(v2_attr, &v1_attr);
			if (rc != 0)
				goto error;

			rc = kmip_node_add_structure_element(ret, v1_attr);
			kmip_node_free(v1_attr);
			if (rc != 0)
				goto error;
		}
	} else {
		/* KMIP >= v2.0 */
		if (attrs_count > 0) {
			attrs = kmip_new_attributes(version,
						    KMIP_TAG_ATTRIBUTES,
						    attrs_count, v2_attrs);
			if (attrs == NULL)
				return NULL;
		}

		ret = kmip_node_new_structure_va(KMIP_TAG_KEY_VALUE, NULL, 2,
						 key_material, attrs);
		kmip_node_free(attrs);
	}

	return ret;

error:
	kmip_node_free(ret);
	return NULL;
}

/**
 * Constructs a Key Value node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Value                               Structure     v1.0
 *     Key Material                Yes       various       v1.0
 *     Attribute                   No        Structure     v1.x only
 *     ... may be repeated
 *     Attributes                  No        Structure     v2.x only
 *
 * @param version           the protocol version. If null, the current default
 *                          protocol version is used.
 * @param key_material      the key material node
 * @param attrs_count       the number of attributes following (can be 0)
 * @param <attributes>      the attributes (as KMIP v2.x attribute)
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_key_value_va(const struct kmip_version *version,
					struct kmip_node *key_material,
					unsigned int attrs_count, ...)
{
	struct kmip_node *ret, **attrs = NULL;
	unsigned int i, k;
	va_list ap;

	if (attrs_count > 0) {
		attrs = calloc(attrs_count, sizeof(struct kmip_node *));
		if (attrs == NULL)
			return NULL;
	}

	va_start(ap, attrs_count);
	for (i = 0, k = 0; i < attrs_count; i++) {
		attrs[k] = va_arg(ap, struct kmip_node *);
		if (attrs[k] != NULL)
			k++;
	}
	va_end(ap);

	ret = kmip_new_key_value(version, key_material, k, attrs);
	if (attrs != NULL)
		free(attrs);

	return ret;
}

/**
 *Gets information from a Key Value node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Value (wrapped key value)           Byte String   v1.0
 *   Key Value (plaintext key value)         Structure     v1.0
 *     Key Material                Yes       various       v1.0
 *     Attribute                   No        Structure     v1.x only
 *     ... may be repeated
 *     Attributes                  No        Structure     v2.x only
 *
 * @param node              the KMIP node
 * @param key_material      On return: the key material node (can be NULL)
 * @param num_attrs         On return: the number of attributes (can be NULL).
 * @param index             the index of the attribute to get
 * @param v2_attr           On return: the attribute (as v2.x attribute) at the
 *                          specified index. Function returns -ENOENT if no
 *                          attribute is available at the index.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_key_value(const struct kmip_node *node,
		       struct kmip_node **key_material,
		       unsigned int *num_attrs, unsigned int index,
		       struct kmip_node **v2_attr)
{
	struct kmip_node *attr;
	int rc;

	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_KEY_VALUE)
		return -EBADMSG;

	if (key_material != NULL) {
		switch (kmip_node_get_type(node)) {
		case KMIP_TYPE_BYTE_STRING:
			/* Wrapped key value */
			*key_material = (struct kmip_node *)node;
			kmip_node_upref(*key_material);
			break;

		case KMIP_TYPE_STRUCTURE:
			/* plaintext key value */
			*key_material =
				kmip_node_get_structure_element_by_index(node,
									 0);
			if (*key_material == NULL)
				return -EBADMSG;

			switch (kmip_node_get_type(*key_material)) {
			case KMIP_TYPE_BYTE_STRING:
				/* Raw, Opaque, PKCS1, PKCS8, ECPrivateKey */
				break;
			case KMIP_TYPE_STRUCTURE:
				/* Transparent key formats */
				switch (kmip_node_get_tag(*key_material)) {
				/* Transparent key formats: TAG_KEY_MATERIAL */
				case KMIP_TAG_KEY_MATERIAL:
					break;
				default:
					rc = -EBADMSG;
					goto error;
				}
				break;
			default:
				rc = -EBADMSG;
				goto error;
			}
			break;

		default:
			return -EBADMSG;
		}
	}

	if (v2_attr == NULL || kmip_node_get_type(node) != KMIP_TYPE_STRUCTURE)
		return 0;

	attr = kmip_node_get_structure_element_by_index(node, 1);
	if (attr == NULL) {
		rc = -ENOENT;
		goto error;
	}

	if (kmip_node_get_tag(attr) == KMIP_TAG_ATTRIBUTES) {
		/* Its already a KMIP v2.x attributes structure */
		rc = kmip_get_attributes(attr, num_attrs, index, v2_attr);
		kmip_node_free(attr);
		if (rc != 0)
			goto error;
		return 0;
	}

	/* Must be a KMIP v1.x attribute then */
	kmip_node_free(attr);

	if (num_attrs != NULL)
		*num_attrs = kmip_node_get_structure_element_count(node) - 1;

	if (v2_attr == NULL)
		return 0;

	attr = kmip_node_get_structure_element_by_index(node, index + 1);
	if (attr == NULL) {
		rc = -ENOENT;
		goto error;
	}

	rc = kmip_v2_attr_from_v1_attr(attr, v2_attr);
	kmip_node_free(attr);
	if (rc != 0)
		goto error;

	return 0;

error:
	if (key_material != NULL) {
		kmip_node_free(*key_material);
		*key_material = NULL;
	}

	return rc;
}

/**
 * Constructs a Key Wrapping Data node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Wrapping Data                       Structure     v1.0
 *     Wrapping Method             Yes       Enumeration   v1.0
 *     Encryption Key Information  No        Structure     v1.0
 *     MAC/Signature Key Info.     No        Structure     v1.0
 *     MAC/Signature               No        Byte String   v1.0
 *     IV/Counter/Nonce            No        Byte String   v1.0
 *     Encoding Option             No        Enumeration   v1.2
 *
 * @param version           the protocol version. If null, the current default
 *                          protocol version is used.
 * @param wrap_method       the key wrapping method
 * @param encr_key_info     the encryption key info node (can be NULL)
 * @param mac_sign_key_info the MAC/Sign key info node (can be NULL)
 * @param mac_signature     MAC/signature (can be NULL)
 * @param mac_signature_len the length of the MAC/Signature
 * @param iv_counter_nonce  IV/Counter/Nonce (can be NULL)
 * @param iv_counter_nonce_len the length of theIV/Counter/Nonce
 * @param encoding          the encoding option (can be 0, defaults to TTLV)
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_key_wrapping_data(
					const struct kmip_version *version,
					enum kmip_wrapping_method wrap_method,
					struct kmip_node *encr_key_info,
					struct kmip_node *mac_sign_key_info,
					const unsigned char *mac_signature,
					uint32_t mac_signature_len,
					const unsigned char *iv_counter_nonce,
					uint32_t iv_counter_nonce_len,
					enum kmip_encoding_option encoding)
{
	struct kmip_node *ret = NULL, *wmeth, *mac = NULL, *iv = NULL;
	struct kmip_node *enc = NULL;

	if (wrap_method == 0)
		return NULL;

	if (version == NULL)
		version = kmip_get_default_protocol_version();

	wmeth = kmip_node_new_enumeration(KMIP_TAG_WRAPPING_METHOD, NULL,
					  wrap_method);
	if (wmeth == NULL)
		goto out;

	if (mac_signature != NULL && mac_signature_len > 0) {
		mac = kmip_node_new_byte_string(KMIP_TAG_MAC_SIGNATURE,
						NULL, mac_signature,
						mac_signature_len);
		if (mac == NULL)
			goto out;
	}

	if (iv_counter_nonce != NULL && iv_counter_nonce_len > 0) {
		iv = kmip_node_new_byte_string(KMIP_TAG_IV_COUNTER_NONCE,
					       NULL, iv_counter_nonce,
					       iv_counter_nonce_len);
		if (iv == NULL)
			goto out;
	}

	if (encoding != 0 && (version->major > 1 ||
			      (version->major == 1 && version->minor > 1))) {
		enc = kmip_node_new_enumeration(KMIP_TAG_ENCODING_OPTION, NULL,
						encoding);
		if (enc == NULL)
			goto out;
	}

	ret = kmip_node_new_structure_va(KMIP_TAG_KEY_WRAPPING_DATA, NULL, 6,
					 wmeth, encr_key_info,
					 mac_sign_key_info, mac, iv, enc);

out:
	kmip_node_free(wmeth);
	kmip_node_free(mac);
	kmip_node_free(iv);
	kmip_node_free(enc);

	return ret;
}

/**
 *Gets information from a Key Wrapping Data node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Wrapping Data                       Structure     v1.0
 *     Wrapping Method             Yes       Enumeration   v1.0
 *     Encryption Key Information  No        Structure     v1.0
 *     MAC/Signature Key Info.     No        Structure     v1.0
 *     MAC/Signature               No        Byte String   v1.0
 *     IV/Counter/Nonce            No        Byte String   v1.0
 *     Encoding Option             No        Enumeration   v1.2
 *
 * @param node              the KMIP node
 * @param wrap_method       On return: the key wrapping method (can be NULL)
 * @param encr_key_info     On return: the encryption key info node
 *                          (can be NULL)
 * @param mac_sign_key_info On return: the MAC/Sign key info node (can be NULL)
 * @param mac_signature     On return: MAC/signature (can be NULL)
 * @param mac_signature_len On return: the length of the MAC/Signature
 *                          (can be NULL)
 * @param iv_counter_nonce  On return: IV/Counter/Nonce (can be NULL)
 * @param iv_counter_nonce_len On return: the length of theIV/Counter/Nonce
 *                          (can be NULL)
 * @param encoding          On return: the encoding option (can be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_key_wrapping_data(const struct kmip_node *node,
			       enum kmip_wrapping_method *wrap_method,
			       struct kmip_node **encr_key_info,
			       struct kmip_node **mac_sign_key_info,
			       const unsigned char **mac_signature,
			       uint32_t *mac_signature_len,
			       const unsigned char **iv_counter_nonce,
			       uint32_t *iv_counter_nonce_len,
			       enum kmip_encoding_option *encoding)
{
	struct kmip_node *n;

	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_KEY_WRAPPING_DATA)
		return -EBADMSG;

	if (wrap_method != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_WRAPPING_METHOD, 0);
		if (n == NULL)
			return -EBADMSG;
		*wrap_method = kmip_node_get_enumeration(n);
		kmip_node_free(n);
	}

	if (mac_signature != NULL && mac_signature_len != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_MAC_SIGNATURE, 0);
		if (n != NULL) {
			*mac_signature = kmip_node_get_byte_string(n,
							mac_signature_len);
		} else {
			*mac_signature = NULL;
			*mac_signature_len = 0;
		}
		kmip_node_free(n);
	}

	if (iv_counter_nonce != NULL && iv_counter_nonce_len != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_IV_COUNTER_NONCE, 0);
		if (n != NULL) {
			*iv_counter_nonce = kmip_node_get_byte_string(n,
							iv_counter_nonce_len);
		} else {
			*iv_counter_nonce = NULL;
			*iv_counter_nonce_len = 0;
		}
		kmip_node_free(n);
	}

	if (encoding != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_ENCODING_OPTION, 0);

		*encoding = (n != NULL ? kmip_node_get_enumeration(n) : 0);
		kmip_node_free(n);
	}

	if (encr_key_info != NULL)
		*encr_key_info = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_ENCRYPTION_KEY_INFORMATION, 0);

	if (mac_sign_key_info != NULL)
		*mac_sign_key_info =
			kmip_node_get_structure_element_by_tag(node,
				KMIP_TAG_MAC_SIGNATURE_KEY_INFORMATION, 0);

	return 0;
}

/**
 * Constructs a Key Wrapping Specification node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Wrapping Specification              Structure     v1.0
 *     Wrapping Method             Yes       Enumeration   v1.0
 *     Encryption Key Information  No        Structure     v1.0
 *     MAC/Signature Key Info.     No        Structure     v1.0
 *     Attribute Name              No        Text String   v1.0
 *     ... may be repeated
 *     Encoding Option             No        Enumeration   v1.2
 *
 * @param version           the protocol version. If null, the current default
 *                          protocol version is used.
 * @param wrap_method       the key wrapping method
 * @param encr_key_info     the encryption key info node (can be NULL)
 * @param mac_sign_key_info the MAC/Sign key info node (can be NULL)
 * @param encoding          the encoding option (can be 0, defaults to TTLV)
 * @param attr_name_count   the number of attribute names following
 * @param attr_names        the array of attributes names (as const char *)
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_key_wrapping_specification(
					const struct kmip_version *version,
					enum kmip_wrapping_method wrap_method,
					struct kmip_node *encr_key_info,
					struct kmip_node *mac_sign_key_info,
					enum kmip_encoding_option encoding,
					unsigned int attr_name_count,
					const char **attr_names)
{
	struct kmip_node *ret = NULL, *wmeth, *enc = NULL, *name;
	unsigned int i;
	int rc;

	if (wrap_method == 0)
		return NULL;

	if (version == NULL)
		version = kmip_get_default_protocol_version();

	wmeth = kmip_node_new_enumeration(KMIP_TAG_WRAPPING_METHOD, NULL,
					  wrap_method);
	if (wmeth == NULL)
		goto out;

	ret = kmip_node_new_structure_va(KMIP_TAG_KEY_WRAPPING_SPECIFICATION,
					 NULL, 3, wmeth, encr_key_info,
					 mac_sign_key_info);


	for (i = 0; i < attr_name_count; i++) {
		if (attr_names[i] == NULL)
			continue;

		name = kmip_node_new_text_string(KMIP_TAG_ATTRIBUTE_NAME, NULL,
						 attr_names[i]);
		if (name == NULL)
			goto error;

		rc = kmip_node_add_structure_element(ret, name);
		kmip_node_free(name);
		if (rc != 0)
			goto error;
	}

	if (encoding != 0 && (version->major > 1 ||
			      (version->major == 1 && version->minor > 1))) {
		enc = kmip_node_new_enumeration(KMIP_TAG_ENCODING_OPTION, NULL,
						encoding);
		if (enc == NULL)
			goto error;

		rc = kmip_node_add_structure_element(ret, enc);
		if (rc != 0)
			goto error;
	}
	goto out;

error:
	kmip_node_free(ret);
	ret = NULL;

out:
	kmip_node_free(wmeth);
	kmip_node_free(enc);

	return ret;
}

/**
 * Constructs a Key Wrapping Specification node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Wrapping Specification              Structure     v1.0
 *     Wrapping Method             Yes       Enumeration   v1.0
 *     Encryption Key Information  No        Structure     v1.0
 *     MAC/Signature Key Info.     No        Structure     v1.0
 *     Attribute Name              No        Text String   v1.0
 *     ... may be repeated
 *     Encoding Option             No        Enumeration   v1.2
 *
 * @param version           the protocol version. If null, the current default
 *                          protocol version is used.
 * @param wrap_method       the key wrapping method
 * @param encr_key_info     the encryption key info node (can be NULL)
 * @param mac_sign_key_info the MAC/Sign key info node (can be NULL)
 * @param encoding          the encoding option (can be 0, defaults to TTLV)
 * @param attr_name_count   the number of atribute names following
 * @param <attr names>      the attributes names (as const char *)
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_key_wrapping_specification_va(
					const struct kmip_version *version,
					enum kmip_wrapping_method wrap_method,
					struct kmip_node *encr_key_info,
					struct kmip_node *mac_sign_key_info,
					enum kmip_encoding_option encoding,
					unsigned int attr_name_count, ...)
{
	const char **names = NULL;
	struct kmip_node *ret;
	unsigned int i;
	va_list ap;

	if (attr_name_count > 0) {
		names = calloc(attr_name_count, sizeof(const char *));
		if (names == NULL)
			return NULL;
	}

	va_start(ap, attr_name_count);
	for (i = 0; i < attr_name_count; i++)
		names[i] = va_arg(ap, const char *);
	va_end(ap);

	ret = kmip_new_key_wrapping_specification(version, wrap_method,
						  encr_key_info,
						  mac_sign_key_info, encoding,
						  attr_name_count, names);
	if (names != NULL)
		free(names);

	return ret;
}


/**
 *Gets information from a Key Wrapping Specification node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Wrapping Specification              Structure     v1.0
 *     Wrapping Method             Yes       Enumeration   v1.0
 *     Encryption Key Information  No        Structure     v1.0
 *     MAC/Signature Key Info.     No        Structure     v1.0
 *     Attribute Name              No        Text String   v1.0
 *     ... may be repeated
 *     Encoding Option             No        Enumeration   v1.2

 *
 * @param node              the KMIP node
 * @param wrap_method       On return: the key wrapping method (can be NULL)
 * @param encr_key_info     On return: the encryption key info node
 *                          (can be NULL)
 * @param mac_sign_key_info On return: the MAC/Sign key info node (can be NULL)
 * @param encoding          On return: the encoding option (can be NULL)
 * @param num_attr_names    On return: the number of attributes (can be NULL).
 * @param attr_name_index   The index of the attribute name to return
 * @param attr_name         On return: the attribute name at the specified index
 *                          (can be NULL). Function returns -ENOENT if no name
 *                          is available at the index.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_key_wrapping_specification(const struct kmip_node *node,
			       enum kmip_wrapping_method *wrap_method,
			       struct kmip_node **encr_key_info,
			       struct kmip_node **mac_sign_key_info,
			       enum kmip_encoding_option *encoding,
			       unsigned int *num_attr_names,
			       unsigned int attr_name_index,
			       const char **attr_name)
{
	struct kmip_node *n;

	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_KEY_WRAPPING_SPECIFICATION)
		return -EBADMSG;

	if (wrap_method != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_WRAPPING_METHOD, 0);
		if (n == NULL)
			return -EBADMSG;
		*wrap_method = kmip_node_get_enumeration(n);
		kmip_node_free(n);
	}

	if (encoding != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
						KMIP_TAG_ENCODING_OPTION, 0);
		*encoding = (n != NULL ? kmip_node_get_enumeration(n) : 0);
		kmip_node_free(n);
	}

	if (num_attr_names != NULL)
		*num_attr_names = kmip_node_get_structure_element_by_tag_count(
						node, KMIP_TAG_ATTRIBUTE_NAME);

	if (attr_name != NULL) {
		n = kmip_node_get_structure_element_by_tag(node,
				KMIP_TAG_ATTRIBUTE_NAME, attr_name_index);
		if (n == NULL)
			return -ENOENT;
		*attr_name = kmip_node_get_text_string(n);
		kmip_node_free(n);
	}

	if (encr_key_info != NULL)
		*encr_key_info = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_ENCRYPTION_KEY_INFORMATION, 0);

	if (mac_sign_key_info != NULL)
		*mac_sign_key_info =
			kmip_node_get_structure_element_by_tag(node,
				KMIP_TAG_MAC_SIGNATURE_KEY_INFORMATION, 0);

	return 0;
}


/**
 * Constructs a Encryption Key Information or MAC/Signature Key Information
 * node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Information                         Structure     v1.0
 *     Unique Identifier           Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *     Cryptographic Parameters    No        Structure     v1.0
 *
 * @param mac_sign          if true a MAC/Signature Key Information node is
 *                          created, otherwise a Encryption Key Information
 *                          node.
 * @param unique_id         the unique ID node
 * @param crypto_params     the cryptographic parameters node (can be NULL)
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_key_info(bool mac_sign, struct kmip_node *unique_id,
				    struct kmip_node *crypto_params)
{
	enum kmip_tag tag;

	if (unique_id == NULL)
		return NULL;

	tag = (mac_sign ? KMIP_TAG_MAC_SIGNATURE_KEY_INFORMATION :
					KMIP_TAG_ENCRYPTION_KEY_INFORMATION);
	return kmip_node_new_structure_va(tag, NULL, 2, unique_id,
					  crypto_params);
}

/**
 * Gets the information from an Encryption Key Information or MAC/Signature Key
 * Information node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Information                         Structure     v1.0
 *     Unique Identifier           Yes       Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *     Cryptographic Parameters    No        Structure     v1.0
 *
 * @param node              the KMIP node
 * @param unique_id         On return: the unique ID node (can be NULL)
 * @param crypto_params     On return: the cryptographic parameters node (can
 *                          be NULL)
 *
 * @returns 0 on success, or a negative errno in case of an error
 * The reference count of the returned nodes is increased. The caller must
 * free the node via kmip_node_free() when no longer needed.
 */
int kmip_get_key_info(const struct kmip_node *node,
		      struct kmip_node **unique_id,
		      struct kmip_node **crypto_params)
{
	if (node == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_ENCRYPTION_KEY_INFORMATION &&
	    kmip_node_get_tag(node) != KMIP_TAG_MAC_SIGNATURE_KEY_INFORMATION)
		return -EBADMSG;

	if (unique_id != NULL) {
		*unique_id = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_UNIQUE_IDENTIFIER, 0);
		if (*unique_id == NULL)
			return -EBADMSG;
	}

	if (crypto_params != NULL)
		*crypto_params = kmip_node_get_structure_element_by_tag(node,
					KMIP_TAG_CRYPTOGRAPHIC_PARAMETERS, 0);

	return 0;
}

/**
 * Constructs a Transparent Symmetric Key node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Material                            Structure     v1.0
 *     Key                         Yes       Byte String   v1.0
 *
 * @param key               the key
 * @param key_length        the key length
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_transparent_symmetric_key(const unsigned char *key,
						     uint32_t key_length)
{
	struct kmip_node *k, *ret;

	if (key == NULL || key_length == 0)
		return NULL;

	k = kmip_node_new_byte_string(KMIP_TAG_KEY, NULL, key, key_length);
	if (k == NULL)
		return NULL;

	ret = kmip_node_new_structure_va(KMIP_TAG_KEY_MATERIAL, NULL, 1, k);
	kmip_node_free(k);

	return ret;
}

/**
 * Gets the information from a Transparent Symmetric Key node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Material                            Structure     v1.0
 *     Key                         Yes       Byte String   v1.0
 *
 * @param node              the KMIP node
 * @param key               On return: the key
 * @param key_length        On return: the key length
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_transparent_symmetric_key(const struct kmip_node *node,
				       const unsigned char **key,
				       uint32_t *key_length)
{
	struct kmip_node *k;

	if (node == NULL || key == NULL || key_length == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_KEY_MATERIAL)
		return -EBADMSG;

	k = kmip_node_get_structure_element_by_tag(node, KMIP_TAG_KEY, 0);
	if (k == NULL)
		return -EBADMSG;

	*key = kmip_node_get_byte_string(k, key_length);
	kmip_node_free(k);

	return 0;
}

/**
 * Constructs a Transparent RSA Public Key node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Material                            Structure     v1.0
 *     Modulus                     Yes       Big Integer   v1.0
 *     Public Exponent             Yes       Big Integer   v1.0
 *
 * @param modulus           the modulus as OpenSSL BIGNUM
 * @param pub_ext           the public exponent as OpenSSL BIGNUM
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_transparent_rsa_public_key(const BIGNUM *modulus,
						      const BIGNUM *pub_exp)
{
	struct kmip_node *mod, *exp, *ret = NULL;

	if (modulus == NULL || pub_exp == NULL)
		return NULL;

	mod = kmip_node_new_bigint(KMIP_TAG_MODULUS, NULL, modulus);
	exp = kmip_node_new_bigint(KMIP_TAG_PUBLIC_EXPONENT, NULL, pub_exp);
	if (mod == NULL || exp == NULL)
		goto out;

	ret = kmip_node_new_structure_va(KMIP_TAG_KEY_MATERIAL, NULL, 2, mod,
					 exp);

out:
	kmip_node_free(mod);
	kmip_node_free(exp);

	return ret;
}

/**
 * Gets the information from a Transparent RSA Public Key node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Material                            Structure     v1.0
 *     Modulus                     Yes       Big Integer   v1.0
 *     Public Exponent             Yes       Big Integer   v1.0
 *
 * @param node              the KMIP node
 * @param modulus           On return: the modulus as OpenSSL BIGNUM
 * @param pub_ext           On return: the public exponent as OpenSSL BIGNUM
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_transparent_rsa_public_key(const struct kmip_node *node,
					const BIGNUM **modulus,
					const BIGNUM **pub_exp)
{
	struct kmip_node *n;

	if (node == NULL || modulus == NULL || pub_exp == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_KEY_MATERIAL)
		return -EBADMSG;

	n = kmip_node_get_structure_element_by_tag(node, KMIP_TAG_MODULUS, 0);
	if (n == NULL)
		return -EBADMSG;
	*modulus = kmip_node_get_bigint(n);
	kmip_node_free(n);

	n = kmip_node_get_structure_element_by_tag(node,
						   KMIP_TAG_PUBLIC_EXPONENT, 0);
	if (n == NULL)
		return -EBADMSG;
	*pub_exp = kmip_node_get_bigint(n);
	kmip_node_free(n);

	return 0;
}

/**
 * Constructs a PKCS#1 Public Key node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Material                            Byte String   v1.0
 *
 * @param pub_key           the public key as OpenSSL PKEY
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_pkcs1_public_key(EVP_PKEY *pub_key)
{
	struct kmip_node *ret = NULL;
	unsigned char *buf = NULL;
	int len;

	if (pub_key == NULL)
		return NULL;

	len = i2d_PublicKey(pub_key, &buf);
	if (len <= 0)
		return NULL;

	ret = kmip_node_new_byte_string(KMIP_TAG_KEY_MATERIAL, NULL, buf, len);

	OPENSSL_free(buf);
	return ret;
}

/**
 * Gets the information from a PKCS#1 Public Key node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Material                            Byte String   v1.0
 *
 * @param node              the KMIP node
 * @param algo              the algorithm of the key
 * @param pub_key           On return: the public key as OpenSSL PKEY. Must be
 *                          freed by the caller using EVP_PKEY_free() when no
 *                          longer needed.
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_pkcs1_public_key(const struct kmip_node *node,
			      enum kmip_crypto_algo algo,
			      EVP_PKEY **pub_key)
{
	const unsigned char *buf;
	uint32_t len = 0;
	int type;

	if (node == NULL || pub_key == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_KEY_MATERIAL)
		return -EBADMSG;

	buf = kmip_node_get_byte_string(node, &len);
	if (buf == NULL || len == 0)
		return -EBADMSG;

	switch (algo) {
	case KMIP_CRYPTO_ALGO_RSA:
		type = EVP_PKEY_RSA;
		break;
	case KMIP_CRYPTO_ALGO_DSA:
		type = EVP_PKEY_DSA;
		break;
	case KMIP_CRYPTO_ALGO_ECDSA:
		type = EVP_PKEY_EC;
		break;
	default:
		return -EINVAL;
	}

	*pub_key = d2i_PublicKey(type, NULL, &buf, len);
	if (*pub_key == NULL)
		return -EIO;

	return 0;
}

/**
 * Constructs a PKCS#8 Public Key node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Material                            Byte String   v1.0
 *
 * @param pub_key           the public key as OpenSSL PKEY
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_pkcs8_public_key(EVP_PKEY *pub_key)
{
	struct kmip_node *ret = NULL;
	unsigned char *buf = NULL;
	int len;

	if (pub_key == NULL)
		return NULL;

	len = i2d_PUBKEY(pub_key, &buf);
	if (len <= 0)
		return NULL;

	ret = kmip_node_new_byte_string(KMIP_TAG_KEY_MATERIAL, NULL, buf, len);

	OPENSSL_free(buf);
	return ret;
}

/**
 * Gets the information from a PKCS#8 Public Key node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Material                            Byte String   v1.0
 *
 * @param node              the KMIP node
 * @param pub_key           On return: the public key as OpenSSL PKEY. Must be
 *                          freed by the caller using EVP_PKEY_free() when no
 *                          longer needed.
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_pkcs8_public_key(const struct kmip_node *node,
			      EVP_PKEY **pub_key)
{
	const unsigned char *buf;
	uint32_t len = 0;

	if (node == NULL || pub_key == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_KEY_MATERIAL)
		return -EBADMSG;

	buf = kmip_node_get_byte_string(node, &len);
	if (buf == NULL || len == 0)
		return -EBADMSG;

	*pub_key = d2i_PUBKEY(NULL, &buf, len);
	if (*pub_key == NULL)
		return -EIO;

	return 0;
}

/**
 * Constructs a Raw Key node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Material                            Byte String   v1.0
 *
 * @param key               the raw key
 * @param key_len           the length of the key
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_raw_key(const unsigned char *key, uint32_t key_len)
{

	if (key == NULL)
		return NULL;

	return kmip_node_new_byte_string(KMIP_TAG_KEY_MATERIAL, NULL, key,
					 key_len);
}

/**
 * Gets the information from a Raw Key node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Key Material                            Byte String   v1.0
 *
 * @param node              the KMIP node
 * @param key               On return: the raw key
 * @param key_len           On return: the length of the key
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_raw_key(const struct kmip_node *node, const unsigned char **key,
		     uint32_t *key_len)
{
	if (node == NULL || key == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_KEY_MATERIAL)
		return -EBADMSG;

	*key = kmip_node_get_byte_string(node, key_len);
	if (*key == NULL)
		return -EBADMSG;

	return 0;
}


/**
 * Constructs a Symmetric Key node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Symmetric Key                           Structure     v1.0
 *     Key Block                   Yes       Structure     v1.0
 *
 * @param keyblock          the key block node
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_symmetric_key(struct kmip_node *keyblock)
{
	if (keyblock == NULL)
		return NULL;

	return kmip_node_new_structure_va(KMIP_TAG_SYMMETRIC_KEY, NULL, 1,
					  keyblock);
}

/**
 * Gets the information from a Symmetric Key node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Symmetric Key                           Structure     v1.0
 *     Key Block                   Yes       Structure     v1.0
 *
 * @param node              the KMIP node
 * @param keyblock          On return: the key block node
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_symmetric_key(const struct kmip_node *node,
			   struct kmip_node **keyblock)
{
	if (node == NULL || keyblock == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_SYMMETRIC_KEY)
		return -EBADMSG;

	*keyblock = kmip_node_get_structure_element_by_tag(node,
							   KMIP_TAG_KEY_BLOCK,
							   0);
	if (*keyblock == NULL)
		return -EBADMSG;

	return 0;
}

/**
 * Constructs a Public Key node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Public Key                              Structure     v1.0
 *     Key Block                   Yes       Structure     v1.0
 *
 * @param keyblock          the key block node
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_public_key(struct kmip_node *keyblock)
{
	if (keyblock == NULL)
		return NULL;

	return kmip_node_new_structure_va(KMIP_TAG_PUBLIC_KEY, NULL, 1,
					  keyblock);
}

/**
 * Gets the information from a Public Key node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Public Key                              Structure     v1.0
 *     Key Block                   Yes       Structure     v1.0
 *
 * @param node              the KMIP node
 * @param keyblock          On return: the key block node
 *
 * @returns 0 on success, or a negative errno in case of an error
 */
int kmip_get_public_key(const struct kmip_node *node,
			struct kmip_node **keyblock)
{
	if (node == NULL || keyblock == NULL)
		return -EINVAL;

	if (kmip_node_get_tag(node) != KMIP_TAG_PUBLIC_KEY)
		return -EBADMSG;

	*keyblock = kmip_node_get_structure_element_by_tag(node,
							   KMIP_TAG_KEY_BLOCK,
							   0);
	if (*keyblock == NULL)
		return -EBADMSG;

	return 0;
}

