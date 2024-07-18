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
#include <err.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>

#include "utils.h"
#include "names.h"

/**
 * Print a debug message
 */
void kmip_print_debug(const char *func, const char *fmt, ...)
{
	char tmp_fmt[200];
	va_list ap;

	if (snprintf(tmp_fmt, sizeof(tmp_fmt), "DBG: %s: %s", func, fmt) >
							(int)sizeof(tmp_fmt))
		return;

	va_start(ap, fmt);
	vwarnx(tmp_fmt, ap);
	va_end(ap);
}


/**
 * Parse a decimal string into a 64 bit signed value
 */
int kmip_parse_decimal_int(const char *str, int64_t *val)
{
	long long v;
	char *endptr;

	if (str == NULL)
		return -EINVAL;

	errno = 0;
	v = strtoll(str, &endptr, 10);

	if ((errno == ERANGE && (v == LLONG_MAX || v == LLONG_MIN)) ||
	    (errno != 0 && v == 0))
		return -EBADMSG;

	if (endptr == str || *endptr != 0)
		return -EBADMSG;

	*val = v;
	return 0;
}

/**
 * Parse a decimal string into a 64 bit unsigned value
 */
int kmip_parse_decimal_uint(const char *str, uint64_t *val)
{
	unsigned long long v;
	char *endptr;

	if (str == NULL)
		return -EINVAL;

	errno = 0;
	v = strtoull(str, &endptr, 10);

	if ((errno == ERANGE && (v == 0 || v == ULLONG_MAX)) ||
	    (errno != 0 && v == 0))
		return -EBADMSG;

	if (endptr == str || *endptr != 0)
		return -EBADMSG;

	*val = v;
	return 0;
}

/**
 * Parse a hex string into a 64 bit signed value
 */
int kmip_parse_hex_int(const char *str, int64_t *val)
{
	long long v;
	char *endptr;

	if (str == NULL)
		return -EINVAL;

	if (strncmp(str, "0x", 2) != 0)
		return -EBADMSG;

	errno = 0;
	v = strtoll(str, &endptr, 16);

	if ((errno == ERANGE && (v == LLONG_MAX || v == LLONG_MIN)) ||
	    (errno != 0 && v == 0))
		return -EBADMSG;

	if (endptr == str || *endptr != 0)
		return -EBADMSG;

	*val = v;
	return 0;
}

/**
 * Parse a hex string into a variable length signed big integer.
 * On return, val and length is set. The buffer returned in val must be freed
 * by the caller.
 */
int kmip_parse_hex(const char *str, bool has_prefix, unsigned char **val,
		   uint32_t *length)
{
	unsigned char *buf;
	BIGNUM *b = NULL;
	int len;

	if (str == NULL)
		return -EINVAL;

	if (has_prefix && strncmp(str, "0x", 2) != 0)
		return -EBADMSG;

	len = BN_hex2bn(&b, str + (has_prefix ? 2 : 0));
	if (len <= 0)
		return -EBADMSG;
	if (len < (int)strlen(str) - (has_prefix ? 2 : 0))
		return -EBADMSG;

	len = len / 2 + (len % 2 > 0 ? 1 : 0);
	buf = calloc(1, len);
	if (buf == NULL) {
		BN_free(b);
		return -ENOMEM;
	}

	if (BN_bn2binpad(b, buf, len) != len) {
		BN_free(b);
		free(buf);
		return -EIO;
	}

	*val = buf;
	*length = len;

	BN_free(b);

	return 0;
}

/**
 * Format a hex string from the byte array specified in val. The caller must
 * free the returned str.
 */
int kmip_format_hex(const unsigned char *val, uint32_t length, bool prefix,
		    char **str)
{
	uint32_t str_len, i;
	char tmp[4];
	char *ret;

	str_len = length * 2 + (prefix ? 2 : 0) + 1;
	ret = calloc(1, str_len);
	if (ret == NULL)
		return -ENOMEM;

	if (prefix)
		strcat(ret, "0x");

	for (i = 0; i < length; i++) {
		sprintf(tmp, "%02x", val[i]);
		strcat(ret, tmp);
	}

	*str = ret;

	return 0;
}

/**
 * Parse a hex string into a big number.
 * On return, val and length is set. The buffer returned in val must be freed
 * by the caller.
 */
int kmip_parse_bignum(const char *str, bool has_prefix, BIGNUM **bn)
{
	unsigned char *buf;
	uint32_t len;
	int rc;

	if (str == NULL)
		return -EINVAL;

	rc = kmip_parse_hex(str, has_prefix, &buf, &len);
	if (rc != 0)
		return rc;

	rc = kmip_decode_bignum(buf, len, bn);

	free(buf);

	return rc;
}

/**
 * Format a hex string from a big number. The caller must free the returned str.
 */
int kmip_format_bignum(const BIGNUM *bn, bool prefix, char **str)
{
	unsigned char *buf;
	uint32_t len;
	int rc;

	len = kmip_encode_bignum_length(bn);
	/* BIG INTEGERS must be a multiple of 8 bytes long */
	if ((len % KMIP_BIG_INTEGER_BLOCK_LENGTH) != 0)
		len += KMIP_BIG_INTEGER_BLOCK_LENGTH -
				(len % KMIP_BIG_INTEGER_BLOCK_LENGTH);

	buf = malloc(len);
	if (buf == NULL)
		return -ENOMEM;

	rc = kmip_encode_bignum(bn, buf, len);
	if (rc != 0) {
		free(buf);
		return -EIO;
	}

	rc = kmip_format_hex(buf, len, prefix, str);

	free(buf);
	return rc;
}

/**
 * Decode a binary big integer in two's complement form into an OpenSSL BIGNUM.
 */
int kmip_decode_bignum(const unsigned char *data, uint32_t length, BIGNUM **bn)
{
	unsigned char *tmp = (unsigned char *)data;
	int i, neg = 0, rc = 0;

	if (data == NULL || bn == NULL)
		return -EINVAL;

	if (data[0] & 0x80) {
		neg = 1;

		tmp = calloc(1, length);
		if (tmp == NULL)
			return -ENOMEM;

		for (i = 0; i < (int)length; i++)
			tmp[i] = ~data[i];

		for (i = length - 1; i >= 0; i--) {
			tmp[i]++;
			if (tmp[i] != 0x00)
				break;
		}
	}

	*bn = BN_bin2bn(tmp, length, NULL);
	if (*bn == NULL) {
		rc = -EIO;
		goto out;
	}
	BN_set_negative(*bn, neg);

out:
	if (neg)
		free(tmp);

	return rc;
}

/**
 * Returns the length required by a binary big integer in two's complement form
 */
uint32_t kmip_encode_bignum_length(const BIGNUM *bn)
{
	uint32_t length;

	if (bn == NULL)
		return 0;

	length = BN_num_bytes(bn);
	if (BN_is_negative(bn) && BN_is_bit_set(bn, (length * 8) - 1))
		length += 1;

	return length;
}

/**
 * Encode an OpenSSL BIGNUM to a binary big integer in two's complement form,
 * in the desired length.
 */
int kmip_encode_bignum(const BIGNUM *bn, unsigned char *data, uint32_t length)
{
	int i;

	if (bn == NULL || data == NULL)
		return -EINVAL;

	if (BN_bn2binpad(bn, data, length) != (int)length)
		return -EIO;

	if (BN_is_negative(bn)) {
		for (i = 0; i < (int)length; i++)
			data[i] = ~data[i];

		for (i = length - 1; i >= 0; i--) {
			data[i]++;
			if (data[i] != 0x00)
				break;
		}
	}

	return 0;
}

/**
 * Parse a timestamp in ISO8601 format and return it as time_t value
 */
int kmip_parse_timestamp(const char *str, int64_t *val)
{
	struct tm tm = { 0 };
	char *p;
	int rc;

	rc = kmip_parse_hex_int(str, val);
	if (rc == 0)
		return 0;
	if (rc != -EBADMSG)
		return rc;

	p = strptime(str, KMIP_ISO8601_TIMESTAMP_TZ, &tm);
	if (p == NULL)
		p = strptime(str, KMIP_ISO8601_TIMESTAMP, &tm);
	if (p == NULL || *p != 0)
		return -EBADMSG;

	/* Adjust according to the parsed time zone */
	tm.tm_sec -= tm.tm_gmtoff;
	tm.tm_gmtoff = 0;
	tm.tm_isdst = 0;

	*val = (time_t)timegm(&tm);

	return 0;
}

/**
 * Parses a mask specification of the specified tag and separator character
 */
int kmip_parse_mask(enum kmip_tag tag, const char *str, char separator,
		    int64_t *val)
{
	const struct kmip_enum *info;
	char *save_ptr, *s, *tok;
	char delimiter[2];
	uint32_t enum_val;
	int rc = 0;

	info = kmip_enum_info_by_tag(tag);
	if (info == NULL)
		return kmip_parse_hex_int(str, val);

	*val = 0;

	s = strdup(str);
	if (s == NULL)
		return -ENOMEM;

	delimiter[0] = separator;
	delimiter[1] = 0;
	tok = strtok_r(s,  delimiter, &save_ptr);
	while (tok != NULL) {
		rc = kmip_enum_value_by_name_or_hex(info, tok, &enum_val);
		if (rc != 0)
			break;

		*val |= enum_val;

		tok = strtok_r(NULL,  delimiter, &save_ptr);
	}

	free(s);
	return rc;
}

static int kmip_append_string(char **str, int *str_len, char separator,
			      const char *append)
{
	int new_len;
	char *tmp;

	if (str == NULL || str_len == NULL)
		return -EINVAL;

	if (*str == NULL)
		*str_len = 0;

	new_len = *str_len;
	if (*str == NULL)
		new_len++;
	else if (separator != 0)
		new_len++;
	if (append != NULL)
		new_len += strlen(append);

	tmp = realloc(*str, new_len);
	if (tmp == NULL)
		return -ENOMEM;

	if (*str == NULL)
		memset(tmp, 0, new_len);
	else if (separator != 0)
		strncat(tmp, &separator, 1);
	if (append != NULL)
		strcat(tmp, append);

	*str = tmp;
	*str_len = new_len;

	return 0;
}

/**
 * Format a mask specification of the specified tag and separator character
 */
int kmip_format_mask(enum kmip_tag tag, int32_t value, char separator,
		     char **str)
{
	const struct kmip_enum *info;
	int rc = 0, i, s_len = 0;
	char *s = NULL, *tmp;

	info = kmip_enum_info_by_tag(tag);
	if (info == NULL || value == 0)
		return kmip_format_hex((const unsigned char *)&value,
				       sizeof(value), true, str);

	/* Process all known mask bits */
	for (i = 0; value != 0 && info[i].name != NULL; i++) {
		if (value & info[i].val) {
			rc = kmip_append_string(&s, &s_len, separator,
						info[i].name);
			if (rc != 0)
				goto out;

			value &= ~info[i].val;
		}
	}

	/* Any bits left in the value? */
	if (value != 0) {
		rc = kmip_format_hex((const unsigned char *)&value,
				      sizeof(value), true, &tmp);
		if (rc != 0)
			goto out;

		rc = kmip_append_string(&s, &s_len, separator, tmp);
		free(tmp);
		if (rc != 0)
			goto out;

	}

	*str = s;

out:
	if (rc != 0)
		free(s);

	return rc;
}

void kmip_print_dump(const char *func, unsigned char *data, size_t size,
		     unsigned int indent)
{
	char outstr[200], hexstr[4];
	size_t i;

	if (data == NULL)
		return;

	strcpy(outstr, "");
	for (i = 0; i < size; i++) {
		sprintf(hexstr, "%02x ", data[i]);
		strcat(outstr, hexstr);

		if (i % 16 == 15) {
			kmip_print_debug(func, "%*s%s", indent, "",
					 outstr);
			strcpy(outstr, "");
		}
	}
	if (i % 16 != 0)
		kmip_print_debug(func, "%*s%s", indent, "", outstr);
}

static void kmip_print_bignum(const char *func, const BIGNUM *bn,
			      unsigned int indent)
{
	unsigned char *buf;
	uint32_t len;
	int rc;

	if (bn == NULL)
		return;

	len = kmip_encode_bignum_length(bn);
	buf = malloc(len);
	if (buf == NULL)
		return;

	rc = kmip_encode_bignum(bn, buf, len);
	if (rc != 0) {
		free(buf);
		return;
	}

	kmip_print_dump(func, buf, len, indent);

	free(buf);
}

static void kmip_node_dump_int(struct kmip_node *node, unsigned int indent)
{
	enum kmip_tag tag, v1_attr_tag = 0;
	struct kmip_node *element;
	char outstr[200] = { 0 };
	struct tm *tm;
	const char *s;
	char *tmp;
	time_t t;
	int rc;

	if (node == NULL)
		return;

	s = kmip_tag_name_by_tag(node->tag);
	kmip_print_debug("kmip_node_dump", "%*sTag: %s (0x%x)", indent, "",
			 s ? s : "UNKNOWN", node->tag);
	s = kmip_type_name_by_type(node->type);
	kmip_print_debug("kmip_node_dump", "%*s  Type: %s (0x%x)", indent, "",
			 s ? s : "UNKNOWN", node->type);

	if (node->name != NULL)
		kmip_print_debug("kmip_node_dump", "%*s  Name: %s", indent,
				 "", node->name);

	/*
	 * KMIP v1.x attribute values may be Enumerations or Integer Masks.
	 * To correctly print them, we need to know the tag. This is contained
	 * in a Attribute Name node, which is an element of our parent node.
	 */
	if (node->tag == KMIP_TAG_ATTRIBUTE_VALUE)
		v1_attr_tag = kmip_find_v1_attribute_name_tag(node->parent);
	tag = (v1_attr_tag != 0 ? v1_attr_tag : node->tag);

	switch (node->type) {
	case KMIP_TYPE_STRUCTURE:
		kmip_print_debug("kmip_node_dump", "%*s  Elements (%u):",
				 indent, "",
				 kmip_node_get_structure_element_count(node));
		element = node->structure_value;
		while (element != NULL) {
			kmip_node_dump_int(element, indent + 4);
			element = element->next;
		}
		break;
	case KMIP_TYPE_INTEGER:
		if (kmip_is_tag_mask(tag)) {
			rc = kmip_format_mask(tag, node->integer_value,
					      '|', &tmp);
			if (rc == 0) {
				kmip_print_debug("kmip_node_dump", "%*s  "
						 "Value: %s (0x%x)",
						 indent, "", tmp,
						 node->integer_value);
				free(tmp);
				break;
			}
		}
		kmip_print_debug("kmip_node_dump", "%*s  Value: %d (0x%x)",
				 indent, "", node->integer_value,
				 node->integer_value);
		break;
	case KMIP_TYPE_LONG_INTEGER:
		kmip_print_debug("kmip_node_dump", "%*s  Value: %ld (0x%lx)",
				 indent, "", node->long_value,
				 node->long_value);
		break;
	case KMIP_TYPE_BIG_INTEGER:
		kmip_print_debug("kmip_node_dump", "%*s  Value: (%u bytes)",
				 indent, "", kmip_encode_bignum_length(
						node->big_integer_value));
		kmip_print_bignum("kmip_node_dump", node->big_integer_value,
				  indent + 4);
		break;
	case KMIP_TYPE_ENUMERATION:
		s = kmip_enum_name_by_tag_value(tag, node->enumeration_value);
		kmip_print_debug("kmip_node_dump", "%*s  Value: %s (0x%x)",
				 indent, "", s ? s : "UNKNOWN",
				 node->enumeration_value);
		break;
	case KMIP_TYPE_BOOLEAN:
		kmip_print_debug("kmip_node_dump", "%*s  Value: %s", indent, "",
				 node->boolean_value ? "True" : "False");
		break;
	case KMIP_TYPE_TEXT_STRING:
		kmip_print_debug("kmip_node_dump", "%*s  Value: '%s' "
				 "(%u characters)", indent, "",
				 node->text_value, strlen(node->text_value));
		break;
	case KMIP_TYPE_BYTE_STRING:
		kmip_print_debug("kmip_node_dump", "%*s  Value: (%u bytes)",
				 indent, "", node->length);
		kmip_print_dump("kmip_node_dump", node->bytes_value,
				node->length, indent + 4);
		break;
	case KMIP_TYPE_DATE_TIME:
		tm = gmtime((time_t *)&node->date_time_value);
		if (tm != NULL)
			strftime(outstr, sizeof(outstr),
				 KMIP_ISO8601_TIMESTAMP_UTC, tm);
		else
			strcpy(outstr, "INVALID");
		kmip_print_debug("kmip_node_dump", "%*s  Value: %s (0x%lx)",
				 indent, "", outstr, node->date_time_value);
		break;
	case KMIP_TYPE_INTERVAL:
		kmip_print_debug("kmip_node_dump", "%*s  Value: %d (0x%x)",
				 indent, "", node->interval_value,
				 node->interval_value);
		break;
	case KMIP_TYPE_DATE_TIME_EXTENDED:
		t = (time_t)node->date_time_ext_value / 1000000;
		tm = gmtime(&t);
		if (tm != NULL)
			strftime(outstr, sizeof(outstr),
				 KMIP_ISO8601_TIMESTAMP_UTC, tm);
		else
			strcpy(outstr, "INVALID");
		kmip_print_debug("kmip_node_dump", "%*s  Value: %s %lu (0x%lx)",
				 indent, "", outstr,
				 node->date_time_ext_value % 1000000,
				 node->date_time_ext_value);
		break;

	default:
		break;
	}
}


/**
 * Dump a KMIP node
 *
 * @param node              the node to free
 * @param debug             if false, the function is a no-op
 */
void kmip_node_dump(struct kmip_node *node, bool debug)
{
	if (node == NULL || !debug)
		return;

	kmip_node_dump_int(node, 0);
}

/**
 * Find a KMIP v1.x Attribute Name node in the elements of the specified parent
 * node, and return the tag value of the attribute name.
 *
 * @param parent            the parent node of the attribute name and value
 *
 * @returns the tag value of the attribute name, or 0 if not found, or unknown
 * attribute name
 */
enum kmip_tag kmip_find_v1_attribute_name_tag(struct kmip_node *parent)
{
	struct kmip_node *e;

	if (parent == NULL)
		return 0;

	if (parent->tag != KMIP_TAG_ATTRIBUTE)
		return 0;
	if (parent->type != KMIP_TYPE_STRUCTURE)
		return 0;

	e = parent->structure_value;
	while (e != NULL) {
		/*
		 * A KMIP v2.x Vendor Attribute looks similar to a KMIP v1.x
		 * Attribute, but has a Vendor Identification node. If we find
		 * a Vendor Identification node, then it can't be a KMIP v1.x
		 * Attribute.
		 */
		if (e->tag == KMIP_TAG_VENDOR_IDENTIFICATION &&
		    e->type == KMIP_TYPE_TEXT_STRING)
			return 0;

		if (e->tag == KMIP_TAG_ATTRIBUTE_NAME &&
		    e->type == KMIP_TYPE_TEXT_STRING)
			return kmip_attr_tag_by_v1_attr_name(e->text_value);

		e = e->next;
	}

	return 0;
}

