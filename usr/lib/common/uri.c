/*
 * COPYRIGHT (c) International Business Machines Corp. 2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <stdlib.h>
#include <string.h>

#include <pkcs11types.h>
#include <p11util.h>
#include <buffer.h>
#include <uri.h>
#include <uri_enc.h>

#define buffer_get(u) (p11_buffer_t *)(u)->priv

#define P11_URI_SEP_PROT  ':'
#define P11_URI_SEP_ATTR  ';'
#define P11_URI_SEP_QUERY '&'
#define P11_URI_SEP_QUERY_START '?'

#define START_END(c, c_max)                                             \
    (const CK_CHAR *)(c),                                               \
    (const CK_CHAR *)((CK_CHAR *)c + p11_strlen(c, c_max))

#define FORMAT_STRING(sep, txt, s, buf)                                 \
    do {                                                                \
        if (p11_strlen((s), sizeof(s))) {                               \
            p11_buffer_append_len(buf, sep, 1);                         \
            p11_buffer_append(buf, txt);                                \
            p11_url_encode(START_END((s), sizeof(s)),                   \
                           P11_URI_P_UNRES, buf);                       \
            *sep = P11_URI_SEP_ATTR;                                    \
        }                                                               \
    } while(0)

#define FORMAT_QUERY_CSTRING(sep, txt, s, buf)                          \
    do {                                                                \
        if (strlen((s))) {                                              \
            p11_buffer_append_len(buf, sep, 1);                         \
            p11_buffer_append(buf, txt);                                \
            p11_url_encode((unsigned char *)(s),                        \
                           (unsigned char *)(s) + strlen(s),            \
                           P11_URI_Q_UNRES, buf);                       \
            *sep = P11_URI_SEP_QUERY;                                   \
        }                                                               \
    } while(0)

#define FORMAT_ATTRIBUTE_STRING(sep, txt, a, t, buf)                    \
    do {                                                                \
        if (((a)[0].type == (t)) &&                                     \
            ((a)[0].pValue)) {                                          \
            p11_buffer_append_len(buf, sep, 1);                         \
            p11_buffer_append(buf, txt);                                \
            p11_url_encode(START_END((a)[0].pValue, (a)[0].ulValueLen), \
                           P11_URI_P_UNRES, buf);                       \
            *sep = P11_URI_SEP_ATTR;                                    \
        }                                                               \
    } while(0)

#define FORMAT_ATTRIBUTE_ALL(sep, txt, a, t, buf)                       \
    do {                                                                \
        if (((a)[0].type == (t)) &&                                     \
            ((a)[0].pValue)) {                                          \
            p11_buffer_append_len(buf, sep, 1);                         \
            p11_buffer_append(buf, txt);                                \
            p11_encode(START_END((a)[0].pValue,                         \
                                 (a)[0].ulValueLen),                    \
                       buf);                                            \
            *sep = P11_URI_SEP_ATTR;                                    \
        }                                                               \
    } while(0)

#define FORMAT_ATTRIBUTE_CLASS(sep, txt, a, buf)                        \
    do {                                                                \
        if (((a)[0].type == CKA_CLASS) &&                               \
            ((a)[0].pValue) &&                                          \
            (rfc7512_get_cko((a)[0].pValue))) {                         \
            p11_buffer_append_len(buf, sep, 1);                         \
            p11_buffer_append(buf, txt);                                \
            p11_buffer_append(buf, rfc7512_get_cko((a)[0].pValue));     \
            *sep = P11_URI_SEP_ATTR;                                    \
        }                                                               \
    } while(0)

#define FORMAT_VERSION(sep, txt, v, buf)                                \
    do {                                                                \
        if (((v).major != (CK_BYTE)-1) ||                               \
            ((v).minor != (CK_BYTE)-1)) {                               \
            p11_buffer_append_len(buf, sep, 1);                         \
            p11_buffer_append_printf(buf, txt "%d.%d",                  \
                                     (v).major, (v).minor);             \
            *sep = P11_URI_SEP_ATTR;                                    \
        }                                                               \
    } while(0)

#define FORMAT_ULONG(sep, txt, ul, buf)                                 \
    do {                                                                \
        if ((ul) != (CK_ULONG)-1) {                                     \
            p11_buffer_append_len(buf, sep, 1);                         \
            p11_buffer_append_printf(buf, txt "%lu", ul);               \
            *sep = P11_URI_SEP_ATTR;                                    \
        }                                                               \
    } while(0)

static const char HEX_CHARS_LOWER[] = "0123456789abcdef";

static char *rfc7512_get_cko(CK_OBJECT_CLASS *class)
{
    switch (*class) {
    case CKO_CERTIFICATE:
        return "cert";
    case CKO_DATA:
        return "data";
    case CKO_PRIVATE_KEY:
        return "private";
    case CKO_PUBLIC_KEY:
        return "public";
    case CKO_SECRET_KEY:
        return "secret-key";
    default:
        break;
    }
    return NULL;
}

static void p11_encode(const unsigned char *start,
                       const unsigned char *end,
                       p11_buffer_t *buf)
{
    unsigned char hex[3];

    if (end <= start)
        return;

    while (start != end) {
        /* encoding required */
        hex[0] = '%';
        hex[1] = HEX_CHARS_LOWER[(*start) >> 4];
        hex[2] = HEX_CHARS_LOWER[(*start) & 0x0F];

        p11_buffer_append_len(buf, (const char *)hex, 3);

        ++start;
    }
}

static void p11_url_encode(const unsigned char *start,
                           const unsigned char *end,
                           const char *verbatim,
                           p11_buffer_t *buf)
{
    while (start != end) {
        if (*start && strchr(verbatim, *start) != NULL) {
            /* no encoding */
            p11_buffer_append_len(buf, (const char *)start, 1);
        } else {
            p11_encode(start, start + 1, buf);
        }

        ++start;
    }
}

static void p11_uri_init(struct p11_uri *uri)
{
    uri->slot_id = (CK_ULONG) - 1;
    uri->obj_id[0].type = CKA_ID;
    uri->obj_label[0].type = CKA_LABEL;
    uri->obj_class[0].type = CKA_CLASS;
    uri->pin_value = NULL;
    uri->pin_source = NULL;

    p11_buffer_reset(buffer_get(uri));
}

const char *p11_uri_format(struct p11_uri *uri)
{
    p11_buffer_t *buf;
    char sep;

    if (!uri)
        return NULL;
    buf = buffer_get(uri);

    p11_buffer_reset(buf);

    p11_buffer_append(buf, "pkcs11");
    sep = P11_URI_SEP_PROT;

    /* CK_INFO */
    if (uri->info) {
        FORMAT_STRING(&sep, "library-description=",
                      uri->info->libraryDescription, buf);
        FORMAT_STRING(&sep, "library-manufacturer=",
                      uri->info->manufacturerID, buf);
        FORMAT_VERSION(&sep, "library-version=",
                       uri->info->libraryVersion, buf);
    }

    FORMAT_ULONG(&sep, "slot-id=",
                 uri->slot_id, buf);

    /* CK_SLOT_INFO */
    if (uri->slot_info) {
        FORMAT_STRING(&sep, "slot-description=",
                      uri->slot_info->slotDescription, buf);
        FORMAT_STRING(&sep, "slot-manufacturer=",
                      uri->slot_info->manufacturerID, buf);
    }

    /* CK_TOKEN_INFO */
    if (uri->token_info) {
        FORMAT_STRING(&sep, "manufacturer=",
                      uri->token_info->manufacturerID, buf);
        FORMAT_STRING(&sep, "model=",
                      uri->token_info->model, buf);
        FORMAT_STRING(&sep, "serial=",
                      uri->token_info->serialNumber, buf);
        FORMAT_STRING(&sep, "token=",
                      uri->token_info->label, buf);
    }

    /* OBJECT */
    FORMAT_ATTRIBUTE_ALL(&sep, "id=", uri->obj_id, CKA_ID, buf);
    FORMAT_ATTRIBUTE_STRING(&sep, "object=", uri->obj_label, CKA_LABEL, buf);
    FORMAT_ATTRIBUTE_CLASS(&sep, "type=", uri->obj_class, buf);

    if (uri->pin_value) {
        sep = P11_URI_SEP_QUERY_START;
        FORMAT_QUERY_CSTRING(&sep, "pin-value=", uri->pin_value, buf);
    } else if (uri->pin_source) {
        sep = P11_URI_SEP_QUERY_START;
        FORMAT_QUERY_CSTRING(&sep, "pin-source=", uri->pin_source, buf);
    }

    /* append the protocol separator for empty URI */
    if (sep == P11_URI_SEP_PROT)
        p11_buffer_append_len(buf, &sep, 1);

    return p11_buffer_char(buf);
}

struct p11_uri *p11_uri_new(void)
{
    struct p11_uri *uri;

    if (!(uri = calloc(1, sizeof(struct p11_uri))))
        goto out;

    if (!(uri->priv = (void *) p11_buffer_new()))
        goto err;

    p11_uri_init(uri);
out:
    return uri;

err:
    free(uri);
    return NULL_PTR;
}

static void p11_uri_attribute_free(CK_ATTRIBUTE_PTR attr)
{
    if (attr->pValue)
        free(attr->pValue);
    attr->pValue = NULL;
    attr->ulValueLen = 0;
}

void p11_uri_attributes_free(struct p11_uri *uri)
{
    if (!uri)
        return;

    p11_uri_attribute_free(&uri->obj_id[0]);
    p11_uri_attribute_free(&uri->obj_label[0]);
    p11_uri_attribute_free(&uri->obj_class[0]);
}

void p11_uri_free(struct p11_uri *uri)
{
    if (!uri)
        return;

    p11_buffer_free((p11_buffer_t *) uri->priv);
    free(uri);
}
