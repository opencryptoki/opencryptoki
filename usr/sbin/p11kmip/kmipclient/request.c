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

#include "kmip.h"
#include "names.h"

/**
 * Constructs a Protocol Version node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Protocol Version                        Structure     v1.0
 *     Protocol Version Major      Yes       Integer       v1.0
 *     Protocol Version Minor      Yes       Integer       v1.0
 *
 * @param version           the protocol version
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_protocol_version(const struct kmip_version *version)
{
	struct kmip_node *ret = NULL, *maj, *min;

	if (version == NULL)
		return NULL;

	maj = kmip_node_new_integer(KMIP_TAG_PROTOCOL_VERSION_MAJOR, NULL,
				    version->major);
	min = kmip_node_new_integer(KMIP_TAG_PROTOCOL_VERSION_MINOR, NULL,
				    version->minor);
	if (maj == NULL || min == NULL)
		goto out;

	ret = kmip_node_new_structure_va(KMIP_TAG_PROTOCOL_VERSION, NULL, 2,
					 maj, min);

out:
	kmip_node_free(maj);
	kmip_node_free(min);

	return ret;
}

/**
 * Constructs a Profile Version node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Profile Version                         Structure     v1.0
 *     Profile Version Major       Yes       Integer       v1.0
 *     Profile Version Minor       Yes       Integer       v1.0
 *
 * @param version           the profile version
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_profile_version(const struct kmip_version *version)
{
	struct kmip_node *ret = NULL, *maj, *min;

	if (version == NULL)
		return NULL;

	maj = kmip_node_new_integer(KMIP_TAG_PROFILE_VERSION_MAJOR, NULL,
				    version->major);
	min = kmip_node_new_integer(KMIP_TAG_PROFILE_VERSION_MINOR, NULL,
				    version->minor);
	if (maj == NULL || min == NULL)
		goto out;

	ret = kmip_node_new_structure_va(KMIP_TAG_PROFILE_VERSION, NULL, 2,
					 maj, min);

out:
	kmip_node_free(maj);
	kmip_node_free(min);

	return ret;
}

/**
 * Constructs a Request Header node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Request Header                Yes       Structure     v1.0
 *     Protocol Version            Yes       Structure     v1.0
 *     Maximum Response Size       No        Integer       v1.0
 *     Client Correlation Value    No        Text String   v1.4
 *     Server Correlation Value    No        Text String   v1.4
 *     Asynchronous Indicator      No        Boolean       v1.0
 *     Attestation Capable Indic.  No        Boolean       v1.2
 *     Attestation Type            No        Enumeration   v1.2
 *        ... may be repeated
 *     Authentication              No        Structure     v1.0
 *     Batch Error Cont. Option    No        Enumeration   v1.0
 *     Batch Order Option          No        Boolean       v1.0
 *     Time Stamp                  No        Date Time     v1.0
 *     Batch Count                 Yes       Integer       v1.0
 *
 * @param version           the protocol version. If NULL, the default
 *                          protocol version is used
 * @param max_response_size the maximum response size. Ignored if <= 0.
 * @param client_corr_value the client correlation value. Ignored if NULL.
 * @param server_corr_value the server correlation value. Ignored if NULL.
 * @param asynchronous      if true the request is asynchronous
 * @param authentication    the authentication node (can be NULL)
 * @param batch_err_opt     the batch error continuation option. Ignored if 0,
 *                          or if batch_count is less than 2.
 * @param batch_order_option the batch order option (true = execute in order)
 * @param batch_count       the batch count
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_request_header(const struct kmip_version *version,
					  int32_t max_response_size,
					  const char *client_corr_value,
					  const char *server_corr_value,
					  bool asynchronous,
					  struct kmip_node *authentication,
				enum kmip_batch_error_cont_option batch_err_opt,
					  bool batch_order_option,
					  int32_t batch_count)
{
	struct kmip_node *ret = NULL, *err = NULL, *async = NULL, *tim = NULL;
	struct kmip_node *max = NULL, *cnt = NULL, *ord = NULL, *ver = NULL;
	struct kmip_node *ccorr = NULL, *scorr = NULL;

	if (version == NULL)
		version = kmip_get_default_protocol_version();

	ver = kmip_new_protocol_version(version);
	if (ver == NULL)
		goto out;

	if (max_response_size > 0) {
		max = kmip_node_new_integer(KMIP_TAG_MAXIMUM_RESPONSE_SIZE,
					    NULL, max_response_size);
		if (max == NULL)
			goto out;
	}

	if (version->major == 1 && version->minor <= 3) {
		client_corr_value = NULL;
		server_corr_value = NULL;
	}

	if (client_corr_value) {
		ccorr = kmip_node_new_text_string(
					KMIP_TAG_CLIENT_CORRELATION_VALUE,
					NULL, client_corr_value);
		if (ccorr == NULL)
			goto out;
	}

	if (server_corr_value) {
		scorr = kmip_node_new_text_string(
					KMIP_TAG_SERVER_CORRELATION_VALUE,
					NULL, server_corr_value);
		if (scorr == NULL)
			goto out;
	}

	if (asynchronous) {
		async = kmip_node_new_boolean(KMIP_TAG_ASYNCHRONOUS_INDICATOR,
					      NULL, asynchronous);
		if (async == NULL)
			goto out;
	}

	if (batch_err_opt != 0 && batch_count > 1) {
		err = kmip_node_new_enumeration(
				KMIP_TAG_BATCH_ERROR_CONTINUATION_OPTION, NULL,
				batch_err_opt);
		if (err == NULL)
			goto out;
	}

	ord = kmip_node_new_boolean(KMIP_TAG_BATCH_ORDER_OPTION, NULL,
				    batch_order_option);
	if (ord == NULL)
		goto out;

	tim = kmip_node_new_date_time(KMIP_TAG_TIME_STAMP,  NULL, time(NULL));
	if (tim == NULL)
		goto out;

	cnt = kmip_node_new_integer(KMIP_TAG_BATCH_COUNT, NULL, batch_count);
	if (cnt == NULL)
		goto out;

	ret = kmip_node_new_structure_va(KMIP_TAG_REQUEST_HEADER, NULL, 10,
					 ver, max, ccorr, scorr, authentication,
					 async, err, ord, tim, cnt);
out:
	kmip_node_free(ver);
	kmip_node_free(max);
	kmip_node_free(async);
	kmip_node_free(err);
	kmip_node_free(ord);
	kmip_node_free(tim);
	kmip_node_free(cnt);

	return ret;
}

/**
 * Constructs a Request Batch Item node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Batch Item                    Yes       Structure     v1.0
 *     Operation                   Yes       Enumeration   v1.0
 *     Ephemeral                   No        Boolean       v2.0
 *     Unique Batch Item ID        No        Byte String   v1.0
 *     Request Payload             Yes       Structure     v1.0
 *     Message Extension           No        Structure     v1.0
 *
 * @param operation         the operation
 * @param authentication    A batch_id (can be NULL, req. if batch count > 0)
 * @param batch_id_length   the size of the batch ID
 * @param payload           the payload node
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_request_batch_item(enum kmip_operation operation,
					      unsigned char *batch_id,
					      uint32_t batch_id_length,
					      struct kmip_node *payload)
{
	struct kmip_node *ret = NULL, *op, *bid = NULL;

	if (payload == NULL)
		return NULL;

	op = kmip_node_new_enumeration(KMIP_TAG_OPERATION, NULL, operation);
	if (op == NULL)
		return NULL;

	if (batch_id != NULL && batch_id_length > 0) {
		bid = kmip_node_new_byte_string(KMIP_TAG_UNIQUE_BATCH_ITEM_ID,
					       NULL, batch_id, batch_id_length);
		if (bid == NULL)
			goto out;
	}

	ret = kmip_node_new_structure_va(KMIP_TAG_BATCH_ITEM, NULL, 3, op, bid,
					 payload);

out:
	kmip_node_free(op);
	kmip_node_free(bid);

	return ret;
}

/**
 * Constructs a Request Message node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Request Message               Yes       Structure     v1.0
 *     Request Header              Yes       Structure     v1.0
 *     Batch Item                  Yes       Structure     v1.0
 *     ... may be repeated
 *
 * @param request_header    the request header node
 * @param batch_count       the number of batch items to add
 * @parambatch_items        array of batch items
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_request(struct kmip_node *request_header,
				   int32_t batch_count,
				   struct kmip_node **batch_items)
{
	struct kmip_node *ret;
	int rc = 0;

	if (request_header == NULL)
		return NULL;

	ret = kmip_node_new_structure_va(KMIP_TAG_REQUEST_MESSAGE, NULL, 1,
					 request_header);
	if (ret == NULL)
		return NULL;

	rc = kmip_node_add_structure_elements(ret, batch_count, batch_items);
	if (rc != 0)
		goto error;

	return ret;

error:
	kmip_node_free(ret);
	return NULL;
}

/**
 * Constructs a Request Message node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Request Message               Yes       Structure     v1.0
 *     Request Header              Yes       Structure     v1.0
 *     Batch Item                  Yes       Structure     v1.0
 *     ... may be repeated
 *
 * @param request_header    the request header node
 * @param batch_count       the number of batch items following
 * @param <batch item>      batch items (struct kmip_node *)
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_request_va(struct kmip_node *request_header,
				      int32_t batch_count, ...)
{
	struct kmip_node *ret, **bis = NULL;
	va_list ap;
	int32_t i;

	if (request_header == NULL)
		return NULL;

	if (batch_count > 0) {
		bis = calloc(batch_count, sizeof(struct kmip_node *));
		if (bis == NULL)
			return NULL;
	}

	va_start(ap, batch_count);
	for (i = 0; i < batch_count; i++)
		bis[i] = va_arg(ap, struct kmip_node *);
	va_end(ap);

	ret = kmip_new_request(request_header, batch_count, bis);

	if (bis != NULL)
		free(bis);

	return ret;
}

/**
 * Constructs a Query request payload:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Query Function              Yes       Enumeration   v1.0
 *        ... may be repeated
 *
 * @param query_count       the number of query function items following
 * @param functions         query function items
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_query_request_payload(unsigned int query_count,
				const enum kmip_query_function *functions)
{
	struct kmip_node *rpl, *qf = NULL;
	unsigned int i;
	int rc = 0;

	if (query_count > 0 && functions == NULL)
		return NULL;

	rpl = kmip_node_new_structure_va(KMIP_TAG_REQUEST_PAYLOAD, NULL, 0);
	if (rpl == NULL)
		return NULL;

	for (i = 0; i < query_count; i++) {
		qf = kmip_node_new_enumeration(KMIP_TAG_QUERY_FUNCTION, NULL,
					       functions[i]);
		if (qf == NULL)
			goto error;

		rc = kmip_node_add_structure_element(rpl, qf);
		if (rc != 0)
			break;
		kmip_node_free(qf);
		qf = NULL;
	}

	if (rc != 0)
		goto error;

	return rpl;

error:
	kmip_node_free(rpl);
	kmip_node_free(qf);
	return NULL;
}

/**
 * Constructs a Query request payload:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Query Function              Yes       Enumeration   v1.0
 *        ... may be repeated
 *
 * @param query_count       the number of query function items following
 * @param <query function>  query items (enum kmip_query_function)
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_query_request_payload_va(unsigned int query_count,
						    ...)
{
	enum kmip_query_function *qfs = NULL;
	struct kmip_node *rpl;
	unsigned int i;
	va_list ap;

	if (query_count > 0) {
		qfs = calloc(query_count, sizeof(enum kmip_query_function));
		if (qfs == NULL)
			return NULL;
	}

	va_start(ap, query_count);
	for (i = 0; i < query_count; i++)
		qfs[i] = va_arg(ap, enum kmip_query_function);
	va_end(ap);

	rpl = kmip_new_query_request_payload(query_count, qfs);

	if (qfs != NULL)
		free(qfs);

	return rpl;
}

static const struct kmip_version kmip_versions[] = {
	{ .major = 1, .minor = 0 },
	{ .major = 1, .minor = 1 },
	{ .major = 1, .minor = 2 },
	{ .major = 1, .minor = 3 },
	{ .major = 1, .minor = 4 },
	{ .major = 2, .minor = 0 },
	{ .major = 2, .minor = 1 },
};

/**
 * Constructs a Discover Versions request payload:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Protocol Version            No        Structure     v1.2
 *        ... may be repeated
 *
 * @param version_count     the number of version items following. If -1 then
 *                          all currently supported versions are added.
 * @param versions          array of version items
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_discover_versions_payload(int version_count,
					const struct kmip_version *versions)
{
	struct kmip_node *rpl, *ver = NULL;
	int rc = 0;
	int i;

	if (version_count > 0 && versions == NULL)
		return NULL;

	rpl = kmip_node_new_structure_va(KMIP_TAG_REQUEST_PAYLOAD, NULL, 0);
	if (rpl == NULL)
		return NULL;


	if (version_count < 0) {
		versions = kmip_versions;
		version_count = sizeof(kmip_versions) /
						sizeof(struct kmip_version);
	}

	for (i = 0; i < version_count; i++) {
		ver = kmip_new_protocol_version(&versions[i]);
		if (ver == NULL)
			goto error;

		rc = kmip_node_add_structure_element(rpl, ver);
		if (rc != 0)
			break;
		kmip_node_free(ver);
		ver = NULL;
	}


	if (rc != 0)
		goto error;

	return rpl;

error:
	kmip_node_free(rpl);
	kmip_node_free(ver);
	return NULL;
}

/**
 * Constructs a Discover Versions request payload:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Protocol Version            No        Structure     v1.2
 *        ... may be repeated
 *
 * @param version_count     the number of version items following. If -1 then
 *                          all currently supported versions are added.
 * @param <version>         version items (struct kmip_version)
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_discover_versions_payload_va(int version_count, ...)
{
	struct kmip_version *versions = NULL;
	struct kmip_node *rpl;
	va_list ap;
	int i;

	if (version_count > 0) {
		versions = calloc(version_count, sizeof(struct kmip_version));
		if (versions == NULL)
			return NULL;
	}

	va_start(ap, version_count);
	for (i = 0; i < version_count; i++)
		versions[i] = *va_arg(ap, struct kmip_version *);
	va_end(ap);

	rpl = kmip_new_discover_versions_payload(version_count, versions);

	if (versions != NULL)
		free(versions);

	return rpl;
}

/**
 * Constructs a Protection Storage Masks node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Protection Storage Masks      Yes       Structure     v2.0
 *     Protection Storage Mask     Yes       Integer       v2.0
 *     ... may be repeated
 *
 * @param masks_count       the number of protection storage masks
 * @param masks             array of mask items
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_protection_storage_masks(unsigned int masks_count,
						    int32_t *masks)
{
	struct kmip_node *ret, *psm;
	unsigned int i;
	int rc = 0;

	if (masks_count > 0 && masks == NULL)
		return NULL;

	ret = kmip_node_new_structure_va(KMIP_TAG_PROTECTION_STORAGE_MASKS,
					 NULL, 0);
	if (ret == NULL)
		return NULL;

	for (i = 0; i < masks_count; i++) {
		psm = kmip_node_new_integer(KMIP_TAG_PROTECTION_STORAGE_MASK,
					    NULL, masks[i]);
		if (psm == NULL)
			break;

		rc = kmip_node_add_structure_element(ret, psm);
		if (rc != 0)
			break;
		kmip_node_free(psm);
		psm = NULL;
	}

	if (rc != 0)
		goto error;

	return ret;

error:
	kmip_node_free(ret);
	kmip_node_free(psm);
	return NULL;
}

/**
 * Constructs a Protection Storage Masks node:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Protection Storage Masks      Yes       Structure     v2.0
 *     Protection Storage Mask     Yes       Integer       v2.0
 *     ... may be repeated
 *
 * @param masks_count       the number of protection storage masks following
 * @param <mask item>      mask items (int32_t)
 *
 * @returns the allocated node, or NULL in case of an error.
 */
struct kmip_node *kmip_new_protection_storage_masks_va(unsigned int masks_count,
						       ...)
{
	int32_t *masks = NULL;
	struct kmip_node *ret;
	unsigned int i;
	va_list ap;

	if (masks_count > 0) {
		masks = calloc(masks_count, sizeof(int32_t));
		if (masks == NULL)
			return NULL;
	}

	va_start(ap, masks_count);
	for (i = 0; i < masks_count; i++)
		masks[i] = va_arg(ap, int32_t);
	va_end(ap);

	ret = kmip_new_protection_storage_masks(masks_count, masks);

	if (masks != NULL)
		free(masks);

	return ret;
}

/**
 * Constructs a Create request payload:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Object Type                 Yes       Enumeration   v1.0
 *     Template-Attribute          Yes(v1.x) Structure     v1.x only
 *     Attributes                  Yes(v2.x) Structure     v2.x only
 *     Protection Storage Masks    No        Structure     v2.x
 *
 * @param version           the protocol version. If null, the current default
 *                          protocol version is used.
 * @param obj_type          the object type to create
 * @paran prot_storage_masks the protection storage masks (can be NULL)
 * @param attrs_count       the number of attributes following (can be 0)
 * @param attrs             the array of attributes (as KMIP v2.x attribute)
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_create_request_payload(
					const struct kmip_version *version,
					enum kmip_object_type obj_type,
					struct kmip_node *prot_storage_masks,
					unsigned int attrs_count,
					struct kmip_node **attrs)
{
	struct kmip_node *rpl = NULL, *otyp = NULL, *att;

	if (attrs_count > 0 && attrs == NULL)
		return NULL;

	if (version == NULL)
		version = kmip_get_default_protocol_version();

	otyp = kmip_new_object_type(obj_type);
	if (otyp == NULL)
		return NULL;

	if (version->major < 2)
		prot_storage_masks = NULL;

	att = kmip_new_attributes(version, KMIP_TAG_ATTRIBUTES, attrs_count,
				  attrs);
	if (att == NULL)
		goto out;

	rpl = kmip_node_new_structure_va(KMIP_TAG_REQUEST_PAYLOAD, NULL, 3,
					 otyp, att, prot_storage_masks);

out:
	kmip_node_free(otyp);
	kmip_node_free(att);

	return rpl;
}


/**
 * Constructs a Create request payload:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Object Type                 Yes       Enumeration   v1.0
 *     Template-Attribute          Yes(v1.x) Structure     v1.x only
 *     Attributes                  Yes(v2.x) Structure     v2.x only
 *     Protection Storage Masks    No        Structure     v2.x
 *
 * @param version           the protocol version. If null, the current default
 *                          protocol version is used.
 * @param obj_type          the object type to create
 * @paran prot_storage_masks the protection storage masks (can be NULL)
 * @param attrs_count       the number of attributes following (can be 0)
 * @param <attributes>      the attributes (as KMIP v2.x attribute)
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_create_request_payload_va(
					const struct kmip_version *version,
					enum kmip_object_type obj_type,
					struct kmip_node *prot_storage_masks,
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

	ret = kmip_new_create_request_payload(version, obj_type,
					      prot_storage_masks, k,
					      attrs);
	if (attrs != NULL)
		free(attrs);

	return ret;
}

/**
 * Constructs a Get Attribute List request payload:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           No        Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *
 * @param unique_id         the unique id of the object to address (can be NULL)
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_get_attribute_list_request_payload(
					struct kmip_node *unique_id)
{
	struct kmip_node *rpl;

	rpl = kmip_node_new_structure_va(KMIP_TAG_REQUEST_PAYLOAD, NULL, 1,
					 unique_id);

	return rpl;
}

/**
 * Constructs a Get Attributes request payload:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           No        Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *     Attribute Name              No        Text String   v1.x only
 *     ... may be repeated
 *     Attribute Reference         No        Enumeration   v2.x only
 *                                           Structure     v2.x only
 *     ... may be repeated
 *
 * @param version           the protocol version. If null, the current default
 *                          protocol version is used.
 * @param unique_id         the unique id of the object to address
 * @param num_attrs         number of attribute references following
 * @param attr_refs         array of attribute references (struct kmip_node *)
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_get_attributes_request_payload(
					const struct kmip_version *version,
					struct kmip_node *unique_id,
					unsigned int num_attrs,
					struct kmip_node **attr_refs)
{
	struct kmip_node *rpl, *v2_attr_ref, *v1_attr_name;
	unsigned int i;
	int rc = 0;

	if (num_attrs > 0 && attr_refs == NULL)
		return NULL;

	if (version == NULL)
		version = kmip_get_default_protocol_version();

	rpl = kmip_node_new_structure_va(KMIP_TAG_REQUEST_PAYLOAD, NULL, 1,
					 unique_id);

	for (i = 0; i < num_attrs; i++) {
		v2_attr_ref = attr_refs[i];
		if (v2_attr_ref == NULL)
			continue;

		if  (version->major == 1) {
			/* KMIP v1.x */
			v1_attr_name = kmip_new_attribute_name_v1(v2_attr_ref);
			if (v1_attr_name == NULL) {
				rc = -EBADMSG;
				break;
			}

			rc = kmip_node_add_structure_element(rpl, v1_attr_name);
			kmip_node_free(v1_attr_name);
		} else {
			/* KMIP >= v2.0 */
			rc = kmip_node_add_structure_element(rpl, v2_attr_ref);
		}

		if (rc != 0)
			break;
	}

	if (rc != 0)
		goto error;

	return rpl;

error:
	kmip_node_free(rpl);
	return NULL;
}

/**
 * Constructs a Get Attributes request payload:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           No        Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *     Attribute Name              No        Text String   v1.x only
 *     ... may be repeated
 *     Attribute Reference         No        Enumeration   v2.x only
 *                                           Structure     v2.x only
 *     ... may be repeated
 *
 * @param version           the protocol version. If null, the current default
 *                          protocol version is used.
 * @param unique_id         the unique id of the object to address
 * @param num_attrs         number of attribute references following
 * @param <attr_refs>       attribute references (struct kmip_node *)
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_get_attributes_request_payload_va(
					const struct kmip_version *version,
					struct kmip_node *unique_id,
					unsigned int num_attrs, ...)
{
	struct kmip_node *ret, **attr_refs = NULL;
	unsigned int i, k;
	va_list ap;

	if (num_attrs > 0) {
		attr_refs = calloc(num_attrs, sizeof(struct kmip_node *));
		if (attr_refs == NULL)
			return NULL;
	}

	va_start(ap, num_attrs);
	for (i = 0, k = 0; i < num_attrs; i++) {
		attr_refs[k] = va_arg(ap, struct kmip_node *);
		if (attr_refs[k] != NULL)
			k++;
	}
	va_end(ap);

	ret = kmip_new_get_attributes_request_payload(version, unique_id,
						      k, attr_refs);
	if (attr_refs != NULL)
		free(attr_refs);

	return ret;
}

/**
 * Constructs a Add Attribute request payload:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           No        Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *     Attribute                   Yes       Structure     v1.x only
 *  or
 *     New Attribute               Yes       Structure     v2.x only
 *
 * @param version           the protocol version. If null, the current default
 *                          protocol version is used.
 * @param unique_id         the unique id of the object to address
 * @param v2_attr           the attribute to add (as KMIP v2.x attribute)
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_add_attribute_request_payload(
					const struct kmip_version *version,
					struct kmip_node *unique_id,
					struct kmip_node *v2_attr)
{
	struct kmip_node *rpl, *new_attr, *v1_attr;
	int rc;

	if (v2_attr == NULL)
		return NULL;

	if (version == NULL)
		version = kmip_get_default_protocol_version();

	if (version->major == 1) {
		/* KMIP v1.x */
		rc = kmip_v1_attr_from_v2_attr(v2_attr, &v1_attr);
		if (rc != 0)
			return NULL;

		rpl = kmip_node_new_structure_va(KMIP_TAG_REQUEST_PAYLOAD, NULL,
						 2, unique_id, v1_attr);
		kmip_node_free(v1_attr);
	} else {
		/* KMIP >= v2.0 */
		new_attr = kmip_new_current_new_attribute(true, v2_attr);
		if (new_attr == NULL)
			return NULL;

		rpl = kmip_node_new_structure_va(KMIP_TAG_REQUEST_PAYLOAD, NULL,
						 2, unique_id, new_attr);
		kmip_node_free(new_attr);
	}

	return rpl;
}

/**
 * Constructs a Modify Attribute request payload:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           No        Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *     Attribute                   Yes       Structure     v1.x only
 *  or
 *     Current Attribute           No        Structure     v2.x only
 *     New Attribute               Yes       Structure     v2.x only
 *
 * @param version           the protocol version. If null, the current default
 *                          protocol version is used.
 * @param unique_id         the unique id of the object to address
 * @param v2_current        the current attribute (as KMIP v2.x attribute).
 *                          Can be NULL, ignored for KMIP v1.x.
 * @param v2_attr           the attribute to modify (as KMIP v2.x attribute)
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_modify_attribute_request_payload(
					const struct kmip_version *version,
					struct kmip_node *unique_id,
					struct kmip_node *v2_current,
					struct kmip_node *v2_attr)
{
	struct kmip_node *rpl, *new_attr, *cur_attr = NULL, *v1_attr;
	int rc;

	if (v2_attr == NULL)
		return NULL;

	if (version == NULL)
		version = kmip_get_default_protocol_version();

	if (version->major == 1) {
		/* KMIP v1.x */
		rc = kmip_v1_attr_from_v2_attr(v2_attr, &v1_attr);
		if (rc != 0)
			return NULL;

		rpl = kmip_node_new_structure_va(KMIP_TAG_REQUEST_PAYLOAD, NULL,
						 2, unique_id, v1_attr);
		kmip_node_free(v1_attr);
	} else {
		/* KMIP >= v2.0 */
		new_attr = kmip_new_current_new_attribute(true, v2_attr);
		if (new_attr == NULL)
			return NULL;

		if (v2_current != NULL) {
			cur_attr = kmip_new_current_new_attribute(false,
								  v2_current);
			if (cur_attr == NULL) {
				kmip_node_free(new_attr);
				return NULL;
			}
		}

		rpl = kmip_node_new_structure_va(KMIP_TAG_REQUEST_PAYLOAD, NULL,
						 3, unique_id, cur_attr,
						 new_attr);
		kmip_node_free(new_attr);
		if (cur_attr != NULL)
			kmip_node_free(cur_attr);
	}

	return rpl;
}

/**
 * Constructs a Set Attribute request payload:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           No        Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *     New Attribute               Yes       Structure     v2.x only
 *
 * KMIP v1.x does not have a Set Attribute operation.
 *
 * @param unique_id         the unique id of the object to address
 * @param v2_attr           the attribute to set (as KMIP v2.x attribute)
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_set_attribute_v2_request_payload(
					struct kmip_node *unique_id,
					struct kmip_node *v2_attr)
{
	struct kmip_node *rpl, *new_attr;

	if (v2_attr == NULL)
		return NULL;

	new_attr = kmip_new_current_new_attribute(true, v2_attr);
	if (new_attr == NULL)
		return NULL;

	rpl = kmip_node_new_structure_va(KMIP_TAG_REQUEST_PAYLOAD, NULL, 2,
					 unique_id, new_attr);
	kmip_node_free(new_attr);

	return rpl;
}

/**
 * Constructs a Delete Attribute request payload:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           No        Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *     Attribute Name              Yes       Text String   v1.x only
 *     Attribute Index             No        Integer       v1.x only
 *  or
 *     Current Attribute           No        Structure     v2.x only
 *     Attribute Reference         No        Structure     v2.x only
 *
 * @param version           the protocol version. If null, the current default
 *                          protocol version is used.
 * @param unique_id         the unique id of the object to address
 * @param v2_current        the current attribute (as KMIP v2.x attribute).
 *                          Can be NULL.
 * @param attr_ref          the attribute to modify (as KMIP v2.x attribute
 *                          reference). Either v2_current or attr_ref can be
 *                          specified.
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_delete_attribute_request_payload(
					const struct kmip_version *version,
					struct kmip_node *unique_id,
					struct kmip_node *v2_current,
					struct kmip_node *attr_ref)
{
	struct kmip_node *rpl, *cur_attr = NULL, *nam = NULL;
	const char *vendor_id, *attr_name, *name;
	char *custom_name = NULL;
	int rc;

	if (v2_current != NULL && attr_ref != NULL)
		return NULL;
	if (v2_current == NULL && attr_ref == NULL)
		return NULL;

	if (version == NULL)
		version = kmip_get_default_protocol_version();

	if (version->major == 1) {
		/* KMIP v1.x */
		if (v2_current != NULL) {
			if (kmip_node_get_tag(v2_current) ==
							KMIP_TAG_ATTRIBUTE) {
				/* Special handling for v2.x Vendor Attribute */
				rc = kmip_get_vendor_attribute(v2_current,
							       &vendor_id,
							       &attr_name,
							       NULL);
				if (rc != 0)
					return NULL;

				custom_name = kmip_build_v1_custom_attr_name(
							vendor_id, attr_name);
				if (custom_name == NULL)
					return NULL;

				name = custom_name;
			} else {
				name = kmip_v1_attr_name_by_tag(
						kmip_node_get_tag(v2_current));
			}

			nam = kmip_node_new_text_string(KMIP_TAG_ATTRIBUTE_NAME,
							NULL, name);
			if (custom_name != NULL)
				free(custom_name);
		} else if (attr_ref != NULL) {
			nam = kmip_new_attribute_name_v1(attr_ref);
		}
		if (nam == NULL)
			return NULL;

		rpl = kmip_node_new_structure_va(KMIP_TAG_REQUEST_PAYLOAD, NULL,
						 2, unique_id, nam);
		kmip_node_free(nam);
	} else {
		/* KMIP >= v2.0 */
		if (v2_current != NULL) {
			cur_attr = kmip_new_current_new_attribute(false,
								  v2_current);
			if (cur_attr == NULL)
				return NULL;
		}

		rpl = kmip_node_new_structure_va(KMIP_TAG_REQUEST_PAYLOAD, NULL,
						 3, unique_id, cur_attr,
						 attr_ref);
		if (cur_attr != NULL)
			kmip_node_free(cur_attr);
	}

	return rpl;
}

/**
 * Constructs an Activate request payload:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           No        Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *
 * @param unique_id         the unique id of the object to address
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_activate_request_payload(struct kmip_node *unique_id)
{

	return kmip_node_new_structure_va(KMIP_TAG_REQUEST_PAYLOAD, NULL, 1,
					  unique_id);
}

/**
 * Constructs an Destroy request payload:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           No        Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *
 * @param unique_id         the unique id of the object to address
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_destroy_request_payload(struct kmip_node *unique_id)
{

	return kmip_node_new_structure_va(KMIP_TAG_REQUEST_PAYLOAD, NULL, 1,
					  unique_id);
}

/**
 * Constructs an Archive request payload:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           No        Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *
 * @param unique_id         the unique id of the object to address
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_archive_request_payload(struct kmip_node *unique_id)
{

	return kmip_node_new_structure_va(KMIP_TAG_REQUEST_PAYLOAD, NULL, 1,
					  unique_id);
}

/**
 * Constructs an Recover request payload:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           No        Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *
 * @param unique_id         the unique id of the object to address
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_recover_request_payload(struct kmip_node *unique_id)
{

	return kmip_node_new_structure_va(KMIP_TAG_REQUEST_PAYLOAD, NULL, 1,
					  unique_id);
}

/**
 * Constructs an Revoke request payload:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           No        Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *     Revocation Reason           Yes       Structure     v1.0
 *       Revocation Reason Code    Yes       Enumeration   v1.0
 *       Revocation Message        No        Text String   v1.0
 *     Compromise Occurrence Date  No        Date Time     v1.0
 *
 * @param unique_id         the unique id of the object to address
 * @param rsn               the revocation reason
 * @param message           the revocation message (can be NULL)
 * @param compromise_date   the date when he compromise happened (can be 0)
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_revoke_request_payload(struct kmip_node *unique_id,
						  enum kmip_revoke_reason rsn,
						  const char *message,
						  uint64_t compromise_date)
{
	struct kmip_node  *rsn_code, *reason = NULL, *rsn_msg = NULL;
	struct kmip_node *rpl = NULL, *date = NULL;

	rsn_code = kmip_node_new_enumeration(KMIP_TAG_REVOCATION_REASON_CODE,
					     NULL, rsn);
	if (rsn_code == NULL)
		return NULL;

	if (message != NULL) {
		rsn_msg = kmip_node_new_text_string(KMIP_TAG_REVOCATION_MESSAGE,
						    NULL, message);
		if (rsn_msg == NULL)
			goto out;

	}

	reason = kmip_node_new_structure_va(KMIP_TAG_REVOCATION_REASON, NULL, 2,
					    rsn_code, rsn_msg);
	if (reason == NULL)
		goto out;

	switch (rsn) {
	case KMIP_REVOK_RSN_KEY_COMPROMISE:
	case KMIP_REVOK_RSN_CA_COMPROMISE:
		if (compromise_date != 0) {
			date = kmip_node_new_date_time(
					KMIP_TAG_COMPROMISE_OCCURRENCE_DATE,
					NULL, compromise_date);
			if (date == NULL)
				goto out;
		}
		break;
	default:
		/*Compromise date is ignored on other reasons */
		break;
	}

	rpl = kmip_node_new_structure_va(KMIP_TAG_REQUEST_PAYLOAD, NULL, 3,
					 unique_id, reason, date);

out:
	kmip_node_free(rsn_code);
	kmip_node_free(rsn_msg);
	kmip_node_free(reason);
	kmip_node_free(date);

	return rpl;
}

/**
 * Constructs an Locate request payload:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Maximum Items               No        Integer       v1.0
 *     Offset Items                No        Integer       v1.3
 *     Storage Status Mask         No        Integer       v1.0
 *     Object Group Member         No        Enumeration   v1.2
 *     Attribute                   No        Structure     v1.x only
 *     ... may be repeated
 *     Attributes                  Yes       Structure     v2.x only
 *
 * @param version           the protocol version. If null, the current default
 *                          protocol version is used.
 * @param max_items         the maximum numbers of items to return. If <= 0
 *                          then no limit is assumed.
 * @param offset_items      the number of items to skip If <= 0 then no offset
 *                          is assumed. Ignored for KMIP <= v1.2.
 * @param storage_status    the storage status filter. If 0, then no filter is
 *                          used and only on-line objects are returned.
 * @param obj_group         the object group filter. If 0 then no object group
 *                          filter is used. Ignored for KMIP <= v1.1.
 * @param attrs_count       the number of attributes following (can be 0)
 * @param attrs             the array of attributes (as KMIP v2.x attribute)
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_locate_request_payload(
				const struct kmip_version *version,
				int32_t max_items, int32_t offset_items,
				enum kmip_storage_status_mask storage_status,
				enum kmip_object_group_member obj_group,
				unsigned int attrs_count,
				struct kmip_node **attrs)
{
	struct kmip_node *max = NULL, *ofs = NULL, *stm = NULL, *grp = NULL;
	struct kmip_node *rpl = NULL, *att, *v2_attr, *v1_attr;
	unsigned int i;
	int rc;

	if (attrs_count > 0 && attrs == NULL)
		return NULL;

	if (version == NULL)
		version = kmip_get_default_protocol_version();

	if (max_items > 0) {
		max = kmip_node_new_integer(KMIP_TAG_MAXIMUM_ITEMS, NULL,
					    max_items);
		if (max == NULL)
			return NULL;
	}

	if (offset_items > 0 && (version->major > 1 ||
				(version->major == 1 && version->minor > 2))) {
		ofs = kmip_node_new_integer(KMIP_TAG_OFFSET_ITEMS, NULL,
					    offset_items);
		if (ofs == NULL)
			goto out;
	}

	if (storage_status != 0) {
		stm = kmip_node_new_integer(KMIP_TAG_STORAGE_STATUS_MASK, NULL,
					    storage_status);
		if (stm == NULL)
			goto out;
	}

	if (obj_group > 0 && (version->major > 1 || version->minor > 1)) {
		grp = kmip_node_new_enumeration(KMIP_TAG_OBJECT_GROUP_MEMBER,
						NULL, obj_group);
		if (grp == NULL)
			goto out;
	}

	if (version->major == 1) {
		/* KMIP v1.x */
		rpl = kmip_node_new_structure_va(KMIP_TAG_REQUEST_PAYLOAD, NULL,
						 4, max, ofs, stm, grp);
		if (rpl == NULL)
			goto out;

		for (i = 0; i < attrs_count; i++) {
			v2_attr = attrs[i];
			if (v2_attr == NULL)
				continue;

			rc = kmip_v1_attr_from_v2_attr(v2_attr, &v1_attr);
			if (rc != 0)
				goto error;

			rc = kmip_node_add_structure_element(rpl, v1_attr);
			kmip_node_free(v1_attr);
			if (rc != 0)
				goto error;
		}
	} else {
		/* KMIP >= v2.0 */
		att = kmip_new_attributes(version, KMIP_TAG_ATTRIBUTES,
					  attrs_count, attrs);
		if (att == NULL)
			goto out;

		rpl = kmip_node_new_structure_va(KMIP_TAG_REQUEST_PAYLOAD, NULL,
						 5, max, ofs, stm, grp, att);
		kmip_node_free(att);
	}

	goto out;

error:
	kmip_node_free(rpl);
	rpl = NULL;

out:
	kmip_node_free(max);
	kmip_node_free(ofs);
	kmip_node_free(stm);
	kmip_node_free(grp);

	return rpl;
}

/**
 * Constructs an Locate request payload:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Maximum Items               No        Integer       v1.0
 *     Offset Items                No        Integer       v1.3
 *     Storage Status Mask         No        Integer       v1.0
 *     Object Group Member         No        Enumeration   v1.2
 *     Attribute                   No        Structure     v1.x only
 *     ... may be repeated
 *     Attributes                  Yes       Structure     v2.x only
 *
 * @param version           the protocol version. If null, the current default
 *                          protocol version is used.
 * @param max_items         the maximum numbers of items to return. If <= 0
 *                          then no limit is assumed.
 * @param offset_items      the number of items to skip If <= 0 then no offset
 *                          is assumed. Ignored for KMIP <= v1.2.
 * @param storage_status    the storage status filter. If 0, then no filter is
 *                          used and only on-line objects are returned.
 * @param obj_group         the object group filter. If 0 then no object group
 *                          filter is used. Ignored for KMIP <= v1.1.
 * @param attrs_count       the number of attributes following (can be 0)
 * @param <attributes>      the attributes (as KMIP v2.x attribute)
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_locate_request_payload_va(
				const struct kmip_version *version,
				int32_t max_items, int32_t offset_items,
				enum kmip_storage_status_mask storage_status,
				enum kmip_object_group_member obj_group,
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

	ret = kmip_new_locate_request_payload(version, max_items, offset_items,
					      storage_status, obj_group,
					      k, attrs);
	if (attrs != NULL)
		free(attrs);

	return ret;
}

/**
 * Constructs an Register request payload:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Object Type                 Yes       Enumeration   v1.0
 *     Template-Attribute          Yes(v1.x) Structure     v1.x only
 *     Attributes                  Yes(v2.x) Structure     v2.x only
 *     <any object>                Yes       Structure     v1.0
 *     Protection Storage Masks    No        Structure     v2.x
 *
 * @param version           the protocol version. If null, the current default
 *                          protocol version is used.
 * @param obj_type          the object type to register
 * @param object            the object to register
 * @paran prot_storage_masks the protection storage masks (can be NULL)
 * @param attrs_count       the number of attributes following (can be 0)
 * @param attrs             the array of attributes (as KMIP v2.x attribute)
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_register_request_payload(
					const struct kmip_version *version,
					enum kmip_object_type obj_type,
					struct kmip_node *object,
					struct kmip_node *prot_storage_masks,
					unsigned int attrs_count,
					struct kmip_node **attrs)
{
	struct kmip_node *rpl = NULL, *otyp = NULL, *att;

	if (object == NULL)
		return NULL;
	if (attrs_count > 0 && attrs == NULL)
		return NULL;

	if (version == NULL)
		version = kmip_get_default_protocol_version();

	otyp = kmip_new_object_type(obj_type);
	if (otyp == NULL)
		return NULL;

	if (version->major < 2)
		prot_storage_masks = NULL;

	att = kmip_new_attributes(version, KMIP_TAG_ATTRIBUTES, attrs_count,
				  attrs);

	if (att == NULL)
		goto out;

	rpl = kmip_node_new_structure_va(KMIP_TAG_REQUEST_PAYLOAD, NULL, 4,
					 otyp, att, object,
					 prot_storage_masks);

out:
	kmip_node_free(otyp);
	kmip_node_free(att);

	return rpl;
}

/**
 * Constructs an Register request payload:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Object Type                 Yes       Enumeration   v1.0
 *     Template-Attribute          Yes(v1.x) Structure     v1.x only
 *     Attributes                  Yes(v2.x) Structure     v2.x only
 *     <any object>                Yes       Structure     v1.0
 *     Protection Storage Masks    No        Structure     v2.x
 *
 * @param version           the protocol version. If null, the current default
 *                          protocol version is used.
 * @param obj_type          the object type to register
 * @param object            the object to register
 * @paran prot_storage_masks the protection storage masks (can be NULL)
 * @param attrs_count       the number of attributes following (can be 0)
 * @param <attributes>      the attributes (as KMIP v2.x attribute)
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_register_request_payload_va(
					const struct kmip_version *version,
					enum kmip_object_type obj_type,
					struct kmip_node *object,
					struct kmip_node *prot_storage_masks,
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

	ret = kmip_new_register_request_payload(version, obj_type, object,
						prot_storage_masks,
						k, attrs);
	if (attrs != NULL)
		free(attrs);

	return ret;
}

/**
 * Constructs an Get request payload:
 *
 * Object                          Required  Encoding      KMIP version
 * ---------------------------------------------------------------------
 *   Payload                       Yes       Structure     v1.0
 *     Unique Identifier           No        Text String   v1.0
 *                                           Enumeration   v2.0
 *                                           Integer       v2.0
 *     Key Format Type             No        Enumeration   v1.0
 *     Key Wrap Type               No        Enumeration   v1.4
 *     Key Compression Type        No        Enumeration   v1.0
 *     Key Wrapping Specification  No        Structure     v1.0
 *
 * @param version           the protocol version. If null, the current default
 *                          protocol version is used.
 * @param unique_id         the unique id of the object to get
 * @param format_type       the format type of the key (ignored if 0)
 * @paran wrap_type         the wrap type (ignored if 0)
 * @param compr_type        the compression type (ignored if 0)
 * @param wrap_specification the key wrapping specification node (can be NULL)
 *
 * @returns the allocated node, or NULL in case of an error.
 * The reference counts of the nodes specified as parameters which are added to
 * the newly allocated node are increased. The caller must free its reference
 * via kmip_node_free() if no longer needed.
 */
struct kmip_node *kmip_new_get_request_payload(
					const struct kmip_version *version,
					struct kmip_node *unique_id,
					enum kmip_key_format_type format_type,
					enum kmip_key_wrap_type wrap_type,
				enum kmip_key_compression_type compr_type,
					struct kmip_node *wrap_specification)
{
	struct kmip_node *rpl = NULL, *fmt = NULL, *wt = NULL, *cmpt = NULL;

	if (version == NULL)
		version = kmip_get_default_protocol_version();

	if (format_type != 0) {
		fmt = kmip_node_new_enumeration(KMIP_TAG_KEY_FORMAT_TYPE, NULL,
						format_type);
		if (fmt == NULL)
			goto out;
	}

	if (wrap_type != 0 && (version->major > 1 ||
	    (version->major == 1 && version->minor > 3))) {
		wt = kmip_node_new_enumeration(KMIP_TAG_KEY_WRAP_TYPE, NULL,
				wrap_type);
		if (wt == NULL)
			goto out;
	}

	if (compr_type != 0) {
		cmpt = kmip_node_new_enumeration(KMIP_TAG_KEY_COMPRESSION_TYPE,
						 NULL, compr_type);
		if (cmpt == NULL)
			goto out;
	}

	rpl = kmip_node_new_structure_va(KMIP_TAG_REQUEST_PAYLOAD, NULL, 5,
					 unique_id, fmt, wt, cmpt,
					 wrap_specification);

out:
	kmip_node_free(fmt);
	kmip_node_free(wt);
	kmip_node_free(cmpt);

	return rpl;
}

