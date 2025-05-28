/*
 * COPYRIGHT (c) International Business Machines Corp. 2021-2024
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <errno.h>
#include <string.h>

#include "kmip.h"
#include "utils.h"

#define KMIP_TTLV_HEADER_LENGTH		8
#define KMIP_TTLV_BLOCK_LENGTH		8

/**
 * Decode a KMIP node from the data in BIO using the TTLV encoding.
 *
 * @param bio               the OpenSSL bio to read the data from
 * @param size              Optional: If not NULL:
 *                          On entry: The number of bytes available to read
 *                          On return: decremented by the number of bytes read
 *                          If NULL, it is assumed that we can read from bio
 *                          as many bytes as needed.
 * @param node              On return: the decoded node. The newly allocated
 *                          node has a reference count of 1.
 * @param debug             if true, debug messages are printed
 *
 * @returns 0 in case of success, or a negative errno value
 */
int kmip_decode_ttlv(BIO *bio, size_t *size, struct kmip_node **node,
		     bool debug)
{
	unsigned char padding[KMIP_TTLV_BLOCK_LENGTH];
	unsigned char ttlv[KMIP_TTLV_HEADER_LENGTH];
	size_t value_len, pad_len;
	struct kmip_node *n, *e;
	void *value = NULL;
	uint32_t int32;
	uint64_t int64;
	int rc;

	if (bio == NULL || node == NULL)
		return -EINVAL;

	if (size != NULL)
		kmip_debug(debug, "size: %lu", *size);
	else
		kmip_debug(debug, "size: unknown");

	if (size != NULL && *size < sizeof(ttlv)) {
		kmip_debug(debug, "length %u > available size %lu",
			  sizeof(ttlv), *size);
		return -EMSGSIZE;
	}

	if (BIO_read(bio, ttlv, sizeof(ttlv)) != sizeof(ttlv)) {
		kmip_debug(debug, "BIO_read failed");
		return -EIO;
	}
	if (size != NULL)
		*size -= sizeof(ttlv);

	n = calloc(1, sizeof(struct kmip_node));
	if (n == NULL) {
		kmip_debug(debug, "calloc failed");
		return -ENOMEM;
	}
	n->ref_count = 1;

	/* Tag: 3-byte binary unsigned integer, transmitted big endian */
	n->tag |= (uint32_t)(ttlv[0] << 16);
	n->tag |= (uint32_t)(ttlv[1] << 8);
	n->tag |= (uint32_t)(ttlv[2]);

	/* Type: 1 byte containing a coded value that indicates the data type */
	n->type = ttlv[3];

	/* Length: 32-bit binary integer, transmitted big-endian */
	n->length |= (uint32_t)(ttlv[4] << 24);
	n->length |= (uint32_t)(ttlv[5] << 16);
	n->length |= (uint32_t)(ttlv[6] << 8);
	n->length |= (uint32_t)(ttlv[7]);

	kmip_debug(debug, "tag: 0x%x type: 0x%x, length: %u", n->tag, n->type,
		   n->length);

	switch (n->type) {
	case KMIP_TYPE_STRUCTURE:
		value_len = n->length;
		break;

	case KMIP_TYPE_BIG_INTEGER:
	case KMIP_TYPE_TEXT_STRING:
	case KMIP_TYPE_BYTE_STRING:
		value_len = n->length;
		value = calloc(1, value_len + 1);
		if (value == NULL) {
			kmip_debug(debug, "calloc failed");
			rc = -ENOMEM;
			goto out;
		}
		break;

	case KMIP_TYPE_INTEGER:
	case KMIP_TYPE_ENUMERATION:
	case KMIP_TYPE_INTERVAL:
		value_len = sizeof(int32);
		value = &int32;
		break;

	case KMIP_TYPE_LONG_INTEGER:
	case KMIP_TYPE_BOOLEAN:
	case KMIP_TYPE_DATE_TIME:
	case KMIP_TYPE_DATE_TIME_EXTENDED:
		value_len = sizeof(int64);
		value = &int64;
		break;

	default:
		kmip_debug(debug, "unknown type: 0x%x", n->type);
		rc = -EBADMSG;
		goto out;
	}

	if (n->length != value_len) {
		kmip_debug(debug, "length %u not as expected (%lu)", n->length,
			   value_len);
		rc = -EBADMSG;
		goto out;
	}
	if (size != NULL && *size < n->length) {
		kmip_debug(debug, "length %u > available size %lu", n->length,
			   *size);
		rc = -EMSGSIZE;
		goto out;
	}

	if (n->type != KMIP_TYPE_STRUCTURE && value_len > 0) {
		if (BIO_read(bio, value, value_len) != (int)value_len) {
			kmip_debug(debug, "BIO_read failed");
			rc = -EIO;
			goto out;
		}
	}
	if (size != NULL)
		*size -= value_len;

	if ((value_len % KMIP_TTLV_BLOCK_LENGTH) != 0) {
		pad_len = KMIP_TTLV_BLOCK_LENGTH -
					(value_len % KMIP_TTLV_BLOCK_LENGTH);

		kmip_debug(debug, "pad_len: %lu", pad_len);
		if (BIO_read(bio, padding, pad_len) != (int)pad_len) {
			kmip_debug(debug, "BIO_read failed (padding)");
			rc = -EIO;
			goto out;
		}
		if (size != NULL)
			*size -= pad_len;
	}

	switch (n->type) {
	case KMIP_TYPE_STRUCTURE:
		while (value_len > 0) {
			rc = kmip_decode_ttlv(bio, &value_len, &e, debug);
			if (rc != 0) {
				kmip_debug(debug, "kmip_decode_ttlv failed: "
					   "rc: %d", rc);
				goto out;
			}
			rc = kmip_node_add_structure_element(n, e);
			kmip_node_free(e);
			if (rc != 0) {
				kmip_debug(debug,
					"kmip_node_structure_add_element "
					"failed: rc: %d", rc);
				goto out;
			}
		}
		break;

	case KMIP_TYPE_INTEGER:
		n->integer_value = be32toh(int32);
		break;

	case KMIP_TYPE_LONG_INTEGER:
		n->long_value = be64toh(int64);
		break;

	case KMIP_TYPE_BIG_INTEGER:
		rc = kmip_decode_bignum(value, value_len,
					&n->big_integer_value);
		if (rc != 0) {
			kmip_debug(debug, "kmip_decode_bignum failed");
			goto out;
		}
		free(value);
		value = NULL;
		break;

	case KMIP_TYPE_ENUMERATION:
		n->enumeration_value = be32toh(int32);
		break;

	case KMIP_TYPE_BOOLEAN:
		n->boolean_value = int64 != 0;
		break;

	case KMIP_TYPE_TEXT_STRING:
		n->text_value = value;
		break;

	case KMIP_TYPE_BYTE_STRING:
		n->bytes_value = value;
		break;

	case KMIP_TYPE_DATE_TIME:
		n->date_time_value = be64toh(int64);
		break;

	case KMIP_TYPE_INTERVAL:
		n->interval_value = be32toh(int32);
		break;

	case KMIP_TYPE_DATE_TIME_EXTENDED:
		n->date_time_ext_value = be64toh(int64);
		break;

	default:
		kmip_debug(debug, "unknown type: 0x%x", n->type);
		rc = -EBADMSG;
		goto out;
	}

	*node = n;
	rc = 0;

out:
	if (rc != 0) {
		switch (n->type) {
		case KMIP_TYPE_BIG_INTEGER:
		case KMIP_TYPE_TEXT_STRING:
		case KMIP_TYPE_BYTE_STRING:
			free(value);
			break;
		default:
			break;
		}

		kmip_node_free(n);
	}
	return rc;
}

/**
 * Gets the length of the value part of a KMIP node (in TTLV encoding)
 */
static int kmip_node_get_length(struct kmip_node *node, size_t *length)
{
	struct kmip_node *element;
	size_t len;
	int rc;

	if (node == NULL || length == NULL)
		return -EINVAL;

	switch (node->type) {
	case KMIP_TYPE_STRUCTURE:
		*length = 0;
		element = node->structure_value;
		while (element != NULL) {
			rc = kmip_node_get_length(element, &len);
			if (rc != 0)
				return rc;

			*length += KMIP_TTLV_HEADER_LENGTH + len;
			if ((len % KMIP_TTLV_BLOCK_LENGTH) != 0)
				*length += KMIP_TTLV_BLOCK_LENGTH -
						(len % KMIP_TTLV_BLOCK_LENGTH);

			element = element->next;
		}
		break;

	case KMIP_TYPE_INTEGER:
	case KMIP_TYPE_ENUMERATION:
	case KMIP_TYPE_INTERVAL:
		*length = sizeof(int32_t);
		break;

	case KMIP_TYPE_LONG_INTEGER:
	case KMIP_TYPE_BOOLEAN:
	case KMIP_TYPE_DATE_TIME:
	case KMIP_TYPE_DATE_TIME_EXTENDED:
		*length = sizeof(int64_t);
		break;

	case KMIP_TYPE_BIG_INTEGER:
		*length = kmip_encode_bignum_length(node->big_integer_value);
		/* BIG INTEGERS must be a multiple of 8 bytes long */
		if ((*length % KMIP_BIG_INTEGER_BLOCK_LENGTH) != 0)
			*length += KMIP_BIG_INTEGER_BLOCK_LENGTH -
				(*length % KMIP_BIG_INTEGER_BLOCK_LENGTH);
		break;

	case KMIP_TYPE_BYTE_STRING:
		*length = node->length;
		break;

	case KMIP_TYPE_TEXT_STRING:
		if (node->text_value != NULL)
			*length = strlen(node->text_value);
		else
			*length = 0;
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

/**
 * Encode a KMIP node into a BIO using the TTLV encoding.
 *
 * @param node              the node to encode
 * @param bio               the OpenSSL bio to write the data to
 * @param size              On return: the number of bytes written to BIO
 * @param debug             if true, debug messages are printed
 *
 * @returns 0 in case of success, or a negative errno value
 */
int kmip_encode_ttlv(struct kmip_node *node, BIO *bio, size_t *size,
		     bool debug)
{
	const unsigned char padding[KMIP_TTLV_BLOCK_LENGTH] = { 0 };
	unsigned char ttlv[KMIP_TTLV_HEADER_LENGTH];
	size_t len, elem_len, value_len, pad_len;
	struct kmip_node *element;
	void *value = NULL;
	uint32_t int32;
	uint64_t int64;
	int rc;

	if (bio == NULL || node == NULL || size == NULL)
		return -EINVAL;

	kmip_debug(debug, "tag: 0x%x type: 0x%x, length: %u", node->tag,
		   node->type, node->length);

	*size = 0;

	/* Update node's length field to match node's current data */
	rc = kmip_node_get_length(node, &len);
	if (rc != 0) {
		kmip_debug(debug, "kmip_node_get_length failed");
		return rc;
	}
	node->length = len;

	/* Tag: 3-byte binary unsigned integer, transmitted big endian */
	ttlv[0] = (node->tag & 0xff0000) >> 16;
	ttlv[1] = (node->tag & 0xff00) >> 8;
	ttlv[2] = (node->tag & 0xff);

	/* Type: 1 byte containing a coded value that indicates the data type */
	ttlv[3] = node->type;

	/* Length: 32-bit binary integer, transmitted big-endian */
	ttlv[4] = (node->length & 0xff000000) >> 24;
	ttlv[5] = (node->length & 0xff0000) >> 16;
	ttlv[6] = (node->length & 0xff00) >> 8;
	ttlv[7] = (node->length & 0xff);

	if (BIO_write(bio, ttlv, sizeof(ttlv)) != sizeof(ttlv)) {
		kmip_debug(debug, "BIO_write failed");
		return -EIO;
	}
	*size += sizeof(ttlv);

	switch (node->type) {
	case KMIP_TYPE_STRUCTURE:
		value_len = 0;
		element = node->structure_value;
		while (element != NULL) {
			rc = kmip_encode_ttlv(element, bio, &elem_len, debug);
			if (rc != 0) {
				kmip_debug(debug, "kmip_encode_ttlv failed");
				return rc;
			}
			value_len += elem_len;
			element = element->next;
		}
		if (value_len != node->length) {
			kmip_debug(debug, "written length %lu not as expected "
				   "(%u)", len, node->length);
			return -EIO;
		}
		break;

	case KMIP_TYPE_INTEGER:
		int32 = htobe32(node->integer_value);
		value_len = sizeof(int32);
		value = &int32;
		break;

	case KMIP_TYPE_LONG_INTEGER:
		int64 = htobe64(node->long_value);
		value_len = sizeof(int64);
		value = &int64;
		break;

	case KMIP_TYPE_BIG_INTEGER:
		value_len = node->length; /* was already calculated above */
		value = malloc(value_len);
		if (value == NULL) {
			kmip_debug(debug, "malloc failed");
			return -ENOMEM;
		}
		rc = kmip_encode_bignum(node->big_integer_value, value,
					value_len);
		if (rc != 0) {
			kmip_debug(debug, "kmip_encode_bignum failed");
			goto out;
		}
		break;

	case KMIP_TYPE_ENUMERATION:
		int32 = htobe32(node->enumeration_value);
		value_len = sizeof(int32);
		value = &int32;
		break;

	case KMIP_TYPE_BOOLEAN:
		int64 = node->boolean_value ? 1 : 0;
		value_len = sizeof(int64);
		value = &int64;
		break;

	case KMIP_TYPE_TEXT_STRING:
		value_len = node->length;
		value = node->text_value;
		break;

	case KMIP_TYPE_BYTE_STRING:
		value_len = node->length;
		value = node->bytes_value;
		break;

	case KMIP_TYPE_DATE_TIME:
		int64 = htobe64(node->date_time_value);
		value_len = sizeof(int64);
		value = &int64;
		break;

	case KMIP_TYPE_INTERVAL:
		int32 = htobe32(node->interval_value);
		value_len = sizeof(int32);
		value = &int32;
		break;

	case KMIP_TYPE_DATE_TIME_EXTENDED:
		int64 = htobe64(node->date_time_ext_value);
		value_len = sizeof(int64);
		value = &int64;
		break;

	default:
		kmip_debug(debug, "unknown type: 0x%x", node->type);
		return -EINVAL;
	}

	if (value != NULL) {
		if (BIO_write(bio, value, value_len) != (int)value_len) {
			kmip_debug(debug, "BIO_write failed");
			rc = -EIO;
			goto out;
		}

	}
	*size += value_len;

	if ((value_len % KMIP_TTLV_BLOCK_LENGTH) != 0) {
		pad_len = KMIP_TTLV_BLOCK_LENGTH -
					(value_len % KMIP_TTLV_BLOCK_LENGTH);

		kmip_debug(debug, "pad_len: %lu", pad_len);
		if (BIO_write(bio, padding, pad_len) != (int)pad_len) {
			kmip_debug(debug, "BIO_write failed (padding)");
			rc = -EIO;
			goto out;
		}
		*size += pad_len;
	}

	kmip_debug(debug, "size: %lu", *size);

	rc = 0;
out:
	if (node->type == KMIP_TYPE_BIG_INTEGER)
		free(value);

	return rc;
}

