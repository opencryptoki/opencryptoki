/*
 * COPYRIGHT (c) International Business Machines Corp. 2014-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * pkcscca - A tool for PKCS#11 CCA token.
 * Currently, only migrates CCA private token objects from CCA cipher
 * to using a software cipher.
 *
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <getopt.h>
#include <memory.h>
#include <linux/limits.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>
#include <unistd.h>

#include <pkcs11types.h>

#include "sw_crypt.h"
#include "pkcscca.h"


int v_flag = 0;
void *p11_lib = NULL;
void (*CSNDKTC) ();
void (*CSNBKTC) ();
void (*CSNBKTC2) ();
void (*CSNBDEC) ();
void *lib_csulcca;

static struct algo aes = {(CK_BYTE *)"RTCMK   AES     ", (CK_BYTE *)"AES", 2 };
static struct algo des = {(CK_BYTE *)"RTCMK   ", (CK_BYTE *)"DES", 1 };
static struct algo hmac = {(CK_BYTE *)"RTCMK   HMAC    ", (CK_BYTE *)"HMAC", 2 };
static struct algo ecc = {(CK_BYTE *)"RTCMK   ECC     ", (CK_BYTE *)"ECC", 2 };
static struct algo rsa = {(CK_BYTE *)"RTCMK   ", (CK_BYTE *)"RSA", 1 };

int compute_hash(int hash_type, int buf_size, char *buf, char *digest)
{
    EVP_MD_CTX *md_ctx = NULL;
    unsigned int result_size;
    int rc;

    md_ctx = EVP_MD_CTX_create();

    switch (hash_type) {
    case HASH_SHA1:
        rc = EVP_DigestInit(md_ctx, EVP_sha1());
        break;
    case HASH_MD5:
        rc = EVP_DigestInit(md_ctx, EVP_md5());
        break;
    default:
        EVP_MD_CTX_destroy(md_ctx);
        return -1;
        break;
    }

    if (rc != 1) {
        fprintf(stderr, "EVP_DigestInit() failed: rc = %d\n", rc);
        return -1;
    }

    rc = EVP_DigestUpdate(md_ctx, buf, buf_size);
    if (rc != 1) {
        fprintf(stderr, "EVP_DigestUpdate() failed: rc = %d\n", rc);
        return -1;
    }

    result_size = EVP_MD_CTX_size(md_ctx);
    rc = EVP_DigestFinal(md_ctx, (unsigned char *) digest, &result_size);
    if (rc != 1) {
        fprintf(stderr, "EVP_DigestFinal() failed: rc = %d\n", rc);
        return -1;
    }

    EVP_MD_CTX_destroy(md_ctx);

    return 0;
}

int cca_decrypt(unsigned char *in_data, unsigned long in_data_len,
                unsigned char *out_data, unsigned long *out_data_len,
                unsigned char *init_v, unsigned char *key_value)
{
    long return_code, reason_code, rule_array_count, length;
    unsigned char chaining_vector[18];
    unsigned char rule_array[256];

    length = in_data_len;
    rule_array_count = 1;
    memcpy(rule_array, "CBC     ", 8);

    CSNBDEC(&return_code, &reason_code, NULL, NULL, key_value,
            &length, in_data, init_v, &rule_array_count,
            rule_array, chaining_vector, out_data);

    if (return_code != 0) {
        fprintf(stderr,
                "CSNBDEC (DES3 DECRYPT) failed: "
                "return_code=%ld reason_code=%ld\n",
                return_code, reason_code);
        return -1;
    }

    *out_data_len = length;

    return 0;
}

// Function:  dlist_remove_node()
//
// Attempts to remove the specified node from the list.  The caller is
// responsible for freeing the data associated with the node prior to
// calling this routine
//
DL_NODE *dlist_remove_node(DL_NODE *list, DL_NODE *node)
{
    DL_NODE *temp = list;

    if (!list || !node)
        return NULL;

    // special case:  removing head of the list
    //
    if (list == node) {
        temp = list->next;
        if (temp)
            temp->prev = NULL;

        free(list);
        return temp;
    }
    // we have no guarantee that the node is in the list
    // so search through the list to find it
    //
    while ((temp != NULL) && (temp->next != node))
        temp = temp->next;

    if (temp != NULL) {
        DL_NODE *next = node->next;

        temp->next = next;
        if (next)
            next->prev = temp;

        free(node);
    }

    return list;
}

// Function:  dlist_add_as_first()
//
// Adds the specified node to the start of the list
//
// Returns:  pointer to the start of the list
//
DL_NODE *dlist_add_as_first(DL_NODE *list, void *data)
{
    DL_NODE *node = NULL;

    if (!data)
        return list;

    node = (DL_NODE *) malloc(sizeof(DL_NODE));
    if (!node)
        return NULL;

    node->data = data;
    node->prev = NULL;
    node->next = list;
    if (list)
        list->prev = node;

    return node;
}

CK_ULONG dlist_length(DL_NODE *list)
{
    DL_NODE *temp = list;
    CK_ULONG len = 0;

    while (temp) {
        len++;
        temp = temp->next;
    }

    return len;
}

/* template_free() */
CK_RV template_free(TEMPLATE *tmpl)
{
    if (!tmpl)
        return CKR_OK;

    while (tmpl->attribute_list) {
        CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *) tmpl->attribute_list->data;

        if (attr)
            free(attr);

        tmpl->attribute_list = dlist_remove_node(tmpl->attribute_list,
                                                 tmpl->attribute_list);
    }

    free(tmpl);

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
        fprintf(stderr, "Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    node = tmpl->attribute_list;

    /* if the attribute already exists in the list, remove it.
     * this algorithm will limit an attribute to appearing at most
     * once in the list
     */
    while (node != NULL) {
        attr = (CK_ATTRIBUTE *) node->data;

        if (new_attr->type == attr->type) {
            free(attr);
            tmpl->attribute_list =
                dlist_remove_node(tmpl->attribute_list, node);
            break;
        }

        node = node->next;
    }

    /* add the new attribute */
    tmpl->attribute_list = dlist_add_as_first(tmpl->attribute_list, new_attr);

    return CKR_OK;
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
        fprintf(stderr, "Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    tmpl = (TEMPLATE *) malloc(sizeof(TEMPLATE));
    if (!tmpl) {
        fprintf(stderr, "Failed to allocate template\n");
        return CKR_HOST_MEMORY;
    }
    memset(tmpl, 0x0, sizeof(TEMPLATE));

    ptr = buf;
    for (i = 0; i < count; i++) {
        if (buf_size >= 0 &&
            ((ptr + sizeof(CK_ATTRIBUTE)) > (buf + buf_size))) {
            template_free(tmpl);
            return CKR_FUNCTION_FAILED;
        }

        if (long_len == 4) {
            a1_64 = (CK_ATTRIBUTE *) ptr;

            len = sizeof(CK_ATTRIBUTE) + a1_64->ulValueLen;
            a2 = (CK_ATTRIBUTE *) malloc(len);
            if (!a2) {
                template_free(tmpl);
                fprintf(stderr, "Failed to allocate attribute\n");
                return CKR_HOST_MEMORY;
            }

            /* if a buffer size is given, make sure it
             * doesn't get overrun
             */
            if (buf_size >= 0 &&
                (((unsigned char *) a1_64 + len)
                 > ((unsigned char *) buf + buf_size))) {
                free(a2);
                template_free(tmpl);
                return CKR_FUNCTION_FAILED;
            }
            memcpy(a2, a1_64, len);
        } else {
            a1 = (CK_ATTRIBUTE_32 *) ptr;

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

            a2 = (CK_ATTRIBUTE *) malloc(len);
            if (!a2) {
                template_free(tmpl);
                fprintf(stderr, "Failed to allocate attribute\n");
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

                    pb2 = (CK_BYTE *) a1;
                    pb2 += sizeof(CK_ATTRIBUTE_32);
                    p32 = (CK_ULONG_32 *) pb2;
                    attr_ulong_32 = *p32;
                }

                attr_ulong = attr_ulong_32;

                {
                    CK_BYTE *pb2;
                    pb2 = (CK_BYTE *) a2;
                    pb2 += sizeof(CK_ATTRIBUTE);
                    memcpy(pb2, (CK_BYTE *) & attr_ulong, sizeof(CK_ULONG));
                }
            } else {
                CK_BYTE *pb2, *pb;

                a2->ulValueLen = a1->ulValueLen;
                pb2 = (CK_BYTE *) a2;
                pb2 += sizeof(CK_ATTRIBUTE);
                pb = (CK_BYTE *) a1;
                pb += sizeof(CK_ATTRIBUTE_32);
                /* if a buffer size is given, make sure it
                 * doesn't get overrun
                 */
                if (buf_size >= 0 && (pb + a1->ulValueLen) > (buf + buf_size)) {
                    free(a2);
                    template_free(tmpl);
                    return CKR_FUNCTION_FAILED;
                }
                memcpy(pb2, pb, a1->ulValueLen);
            }
        }

        if (a2->ulValueLen != 0)
            a2->pValue = (CK_BYTE *) a2 + sizeof(CK_ATTRIBUTE);
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
        fprintf(stderr, "Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    ptr = dest;
    node = tmpl->attribute_list;
    while (node) {
        CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *) node->data;

        if (long_len == 4) {
            memcpy(ptr, attr, sizeof(CK_ATTRIBUTE) + attr->ulValueLen);
            ptr += sizeof(CK_ATTRIBUTE) + attr->ulValueLen;
        } else {
            attr_32 = malloc(sizeof(CK_ATTRIBUTE_32));
            if (!attr_32) {
                fprintf(stderr, "Failed to allocate attribute\n");
                return CKR_HOST_MEMORY;
            }
            attr_32->type = attr->type;
            attr_32->pValue = 0x00;
            if ((attr->type == CKA_CLASS ||
                 attr->type == CKA_KEY_TYPE ||
                 attr->type == CKA_MODULUS_BITS ||
                 attr->type == CKA_VALUE_BITS ||
                 attr->type == CKA_CERTIFICATE_TYPE ||
                 attr->type == CKA_VALUE_LEN) && attr->ulValueLen != 0) {

                attr_32->ulValueLen = sizeof(CK_ULONG_32);

                memcpy(ptr, attr_32, sizeof(CK_ATTRIBUTE_32));
                ptr += sizeof(CK_ATTRIBUTE_32);

                pVal = (CK_ULONG *) attr->pValue;
                Val = *pVal;
                Val_32 = (CK_ULONG_32) Val;
                memcpy(ptr, &Val_32, sizeof(CK_ULONG_32));
                ptr += sizeof(CK_ULONG_32);
            } else {
                attr_32->ulValueLen = attr->ulValueLen;
                memcpy(ptr, attr_32, sizeof(CK_ATTRIBUTE_32));
                ptr += sizeof(CK_ATTRIBUTE_32);
                if (attr->ulValueLen != 0) {
                    memcpy(ptr, attr->pValue, attr->ulValueLen);
                    ptr += attr->ulValueLen;
                }
            }
            free(attr_32);
        }

        node = node->next;
    }

    return CKR_OK;
}

CK_ULONG template_get_count(TEMPLATE *tmpl)
{
    if (tmpl == NULL)
        return 0;

    return dlist_length(tmpl->attribute_list);
}

CK_ULONG template_get_compressed_size(TEMPLATE *tmpl)
{
    DL_NODE *node;
    CK_ULONG size = 0;

    if (tmpl == NULL)
        return 0;
    node = tmpl->attribute_list;
    while (node) {
        CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *) node->data;

        size += sizeof(CK_ATTRIBUTE_32);
        if ((attr->type == CKA_CLASS || attr->type == CKA_KEY_TYPE
             || attr->type == CKA_MODULUS_BITS
             || attr->type == CKA_VALUE_BITS
             || attr->type == CKA_CERTIFICATE_TYPE
             || attr->type == CKA_VALUE_LEN)
            && attr->ulValueLen != 0) {
            size += sizeof(CK_ULONG_32);
        } else {
            size += attr->ulValueLen;
        }

        node = node->next;
    }

    return size;
}

/* template_get_class */
CK_BBOOL template_get_class(TEMPLATE *tmpl, CK_ULONG *class,
                            CK_ULONG *subclass)
{
    DL_NODE *node;
    CK_BBOOL found = FALSE;

    if (!tmpl || !class || !subclass)
        return FALSE;

    node = tmpl->attribute_list;

    /* have to iterate through all attributes. no early exits */
    while (node) {
        CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *) node->data;

        if (attr->type == CKA_CLASS) {
            *class = *(CK_OBJECT_CLASS *) attr->pValue;
            found = TRUE;
        }

        /* underneath, these guys are both CK_ULONG so we
         * could combine this
         */
        if (attr->type == CKA_CERTIFICATE_TYPE)
            *subclass = *(CK_CERTIFICATE_TYPE *) attr->pValue;

        if (attr->type == CKA_KEY_TYPE)
            *subclass = *(CK_KEY_TYPE *) attr->pValue;

        node = node->next;
    }

    return found;
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
        a = (CK_ATTRIBUTE *) node->data;

        if (type == a->type) {
            *attr = a;
            return TRUE;
        }

        node = node->next;
    }

    *attr = NULL;

    return FALSE;
}

CK_RV build_attribute(CK_ATTRIBUTE_TYPE type,
                      CK_BYTE *data, CK_ULONG data_len, CK_ATTRIBUTE **attrib)
{
    CK_ATTRIBUTE *attr = NULL;

    attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + data_len);
    if (!attr) {
        fprintf(stderr, "Failed to allocate attribute\n");
        return CKR_HOST_MEMORY;
    }
    attr->type = type;
    attr->ulValueLen = data_len;

    if (data_len > 0) {
        attr->pValue = (CK_BYTE *) attr + sizeof(CK_ATTRIBUTE);
        memcpy(attr->pValue, data, data_len);
    } else {
        attr->pValue = NULL;
    }

    *attrib = attr;

    return CKR_OK;
}

// object_free()
//
// does what it says...
//
void object_free(OBJECT * obj)
{
    /* refactorization here to do actual free - fix from coverity scan */
    if (obj) {
        if (obj->template)
            template_free(obj->template);
        free(obj);
    }
}

//Modified object_restore to prevent buffer overflow
//If data_size=-1, won't do bounds checking
CK_RV object_restore_withSize(CK_BYTE * data, OBJECT ** new_obj,
                              CK_BBOOL replace, int data_size)
{
    TEMPLATE *tmpl = NULL;
    OBJECT *obj = NULL;
    CK_ULONG offset = 0;
    CK_ULONG_32 count = 0;
    CK_RV rc;
    CK_OBJECT_CLASS_32 class32;

    if (!data || !new_obj) {
        fprintf(stderr, "Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    obj = (OBJECT *) malloc(sizeof(OBJECT));
    if (!obj) {
        fprintf(stderr, "Failed to allocate object\n");
        rc = CKR_HOST_MEMORY;
        goto error;
    }


    memset(obj, 0x0, sizeof(OBJECT));

    memcpy( &class32, data + offset, sizeof(CK_OBJECT_CLASS_32) );
    obj->class = class32;
    offset += sizeof(CK_OBJECT_CLASS_32);

    memcpy(&count, data + offset, sizeof(CK_ULONG_32));
    offset += sizeof(CK_ULONG_32);


    memcpy(&obj->name, data + offset, 8);
    offset += 8;

    rc = template_unflatten_withSize(&tmpl, data + offset, count, data_size);
    if (rc != CKR_OK) {
        fprintf(stderr, "template_unflatten_withSize failed rc=%lx.\n", rc);
        goto error;
    }
    obj->template = tmpl;

    if (replace == FALSE) {
        *new_obj = obj;
    } else {
        template_free((*new_obj)->template);
        memcpy(*new_obj, obj, sizeof(OBJECT));

        free(obj);              // don't want to do object_free() here!
    }

    return CKR_OK;

error:
    if (obj)
        object_free(obj);
    if (tmpl)
        template_free(tmpl);

    return rc;
}

// object_flatten() - this is still used when saving token objects
//
CK_RV object_flatten(OBJECT * obj, CK_BYTE ** data, CK_ULONG * len)
{
    CK_BYTE *buf = NULL;
    CK_ULONG tmpl_len, total_len;
    CK_ULONG offset;
    CK_ULONG_32 count;
    CK_OBJECT_CLASS_32 class32;
    long rc;

    if (!obj) {
        fprintf(stderr, "Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    count = template_get_count(obj->template);
    tmpl_len = template_get_compressed_size(obj->template);

    total_len = tmpl_len + sizeof(CK_OBJECT_CLASS_32) + sizeof(CK_ULONG_32) + 8;

    buf = (CK_BYTE *) malloc(total_len);
    if (!buf) {                 // SAB  XXX FIXME  This was DATA
        fprintf(stderr, "Failed to allocate buffer\n");
        return CKR_HOST_MEMORY;
    }

    memset((CK_BYTE *) buf, 0x0, total_len);

    offset = 0;

    class32 = obj->class;
    memcpy( buf + offset, &class32, sizeof(CK_OBJECT_CLASS_32) );
    offset += sizeof(CK_OBJECT_CLASS_32);

    memcpy(buf + offset, &count, sizeof(CK_ULONG_32));
    offset += sizeof(CK_ULONG_32);

    memcpy(buf + offset, &obj->name, sizeof(CK_BYTE) * 8);
    offset += 8;
    rc = template_flatten(obj->template, buf + offset);
    if (rc != CKR_OK) {
        free(buf);
        return rc;
    }

    *data = buf;
    *len = total_len;

    return CKR_OK;
}

CK_RV add_pkcs_padding(CK_BYTE *ptr,
                       CK_ULONG block_size, CK_ULONG data_len,
                       CK_ULONG total_len)
{
    CK_ULONG i, pad_len;
    CK_BYTE pad_value;

    pad_len = block_size - (data_len % block_size);
    pad_value = (CK_BYTE) pad_len;

    if (data_len + pad_len > total_len) {
        fprintf(stderr, "The total length is too small to add padding.\n");
        return CKR_FUNCTION_FAILED;
    }
    for (i = 0; i < pad_len; i++)
        ptr[i] = pad_value;

    return CKR_OK;
}

#define CKR_IBM_NOT_TOUCHED     -1

int adjust_secret_key_attributes(OBJECT *obj, CK_ULONG key_type)
{
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;
    CK_ATTRIBUTE *value_attr = NULL;
    CK_ATTRIBUTE *ibm_opaque_attr = NULL;
    CK_ULONG key_size;
    struct secaeskeytoken *aes_token;
    CK_BYTE *zero = NULL;

    if (key_type != CKK_AES) {
        /* DES/3DES keys are already contained in CKA_IBM_OPAQUE */
        return CKR_IBM_NOT_TOUCHED;
    }

    /* Don't touch if object already has an IBM_OPAQUE attribute */
    if (template_attribute_find(obj->template, CKA_IBM_OPAQUE, &attr))
        return CKR_IBM_NOT_TOUCHED;

    if (!template_attribute_find(obj->template, CKA_VALUE, &value_attr)) {
        fprintf(stderr, "No CKA_VALUE attribute found\n");
        return CKR_TEMPLATE_INCOMPLETE;
    }

    aes_token = (struct secaeskeytoken *)value_attr->pValue;
    if (value_attr->ulValueLen != sizeof(struct secaeskeytoken) ||
        aes_token->type != 0x01 ||
        aes_token->version != 0x04) {
        fprintf(stderr, "CKA_VALUE does not contain a CCA secure key\n");
        return CKR_IBM_NOT_TOUCHED;
    }

    /* Move CKA_VALUE to CKA_IBM_OPAQUE */
    rc = build_attribute(CKA_IBM_OPAQUE, value_attr->pValue,
                         value_attr->ulValueLen, &ibm_opaque_attr);
    if (rc != CKR_OK)
        goto cleanup;

    rc = template_update_attribute(obj->template, ibm_opaque_attr);
    if (rc != CKR_OK)
        goto cleanup;

    /* Provide dummy CKA_VAUE attribute in (clear) key size */
    key_size = aes_token->bitsize / 8;
    zero = (CK_BYTE *)calloc(key_size, 1);
    if (zero == NULL) {
        fprintf(stderr, "Failed to allocate zero value\n");
        rc = CKR_HOST_MEMORY;
        goto cleanup;
    }

    rc = build_attribute(CKA_VALUE, zero, key_size, &value_attr);
    if (rc != CKR_OK)
        goto cleanup;

    rc = template_update_attribute(obj->template, value_attr);
    if (rc != CKR_OK)
        goto cleanup;

    free(zero);

    return CKR_OK;

cleanup:
    if (ibm_opaque_attr)
        free(ibm_opaque_attr);
    if (zero)
        free(zero);
    return rc;
}

/*
 * OCK version 2.x create AES key objects with the CCA secure key stored
 * in CKA_VALUE. OCK 3.x requires the secure in CKA_IBM_OPAQUE instead.
 * Note: Other key types, such as DES/3DES keys as well as symmetric
 * keys (RSA, EC, etc) already store the key in CKA_IBM_OPAQUE in OCK 2.x
 *
 * This function moves the CCA AES key from CKA_VALUE to CKA_IBM_OPAQUE
 * and supplies a dummy (all zero) key in CKA_VALUE.
 */
int adjust_key_object_attributes(unsigned char *data, unsigned long data_len,
                                 unsigned char **new_data,
                                 unsigned long *new_data_len)
{
    int rc;
    OBJECT *obj = NULL;
    CK_ULONG class, subclass = 0;

    *new_data = NULL;
    *new_data_len = 0;

    /* Now unflatten the OBJ */
    rc = object_restore_withSize(data, &obj, CK_FALSE, data_len);
    if (rc)
        goto cleanup;

    if (!template_get_class(obj->template, &class, &subclass)) {
        fprintf(stderr, "No CKA_CLASS attribute found\n");
        rc = CKR_TEMPLATE_INCOMPLETE;
        goto cleanup;
    }

    switch(class) {
    case CKO_SECRET_KEY:
        rc = adjust_secret_key_attributes(obj, subclass);
        if (rc == CKR_IBM_NOT_TOUCHED) {
            rc = CKR_OK;
            goto cleanup;
        }
        break;
    default:
        /* no need to modify the object */
        rc = CKR_OK;
        goto cleanup;
    }
    if (rc != CKR_OK)
        goto cleanup;

    /* flatten the object */
    rc = object_flatten(obj, new_data, new_data_len);
    if (rc)
        goto cleanup;

cleanup:
    if (obj)
        object_free(obj);

    return rc;
}

int reencrypt_private_token_object(unsigned char *data, unsigned long len,
                                   unsigned char *new_cipher,
                                   unsigned long *new_cipher_len,
                                   unsigned char *masterkey)
{
    unsigned char *clear = NULL;
    unsigned char des3_key[64];
    unsigned char sw_des3_key[3 * DES_KEY_SIZE];
    unsigned long clear_len;
    unsigned char *new_obj_data = NULL;
    unsigned long new_obj_data_len;
    CK_ULONG_32 obj_data_len_32;
    CK_ULONG padded_len;
    CK_ULONG block_size = DES_BLOCK_SIZE;
    CK_BYTE *ptr = NULL;
    CK_BYTE hash_sha[SHA1_HASH_SIZE];
    CK_RV rc;
    int ret;

    /* cca wants 8 extra bytes for padding purposes */
    clear_len = len + 8;
    clear = (unsigned char *) malloc(clear_len);
    if (!clear) {
        fprintf(stderr, "malloc() failed: %s.\n", strerror(errno));
        ret = -1;
        goto done;
    }

    /* decrypt using cca des3 */
    memcpy(des3_key, masterkey, MASTER_KEY_SIZE);
    ret = cca_decrypt(data, len, clear, &clear_len, (CK_BYTE *)"10293847",
                      des3_key);
    if (ret)
        goto done;

    /* Validate the hash */
    memcpy(&obj_data_len_32, clear, sizeof(CK_ULONG_32));
    if (obj_data_len_32 >= clear_len) {
        fprintf(stderr, "Decrypted object data is inconsistent. Possibly already migrated?\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    ret = compute_sha1((char *)(clear + sizeof(CK_ULONG_32)),
                       obj_data_len_32, (char *)hash_sha);
    if (ret != CKR_OK) {
        goto done;
    }

    if (memcmp(clear + sizeof(CK_ULONG_32) + obj_data_len_32, hash_sha,
               SHA1_HASH_SIZE) != 0) {
        fprintf(stderr, "Stored hash does not match restored data hash.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Adjust the key object attributes */
    ret = adjust_key_object_attributes(clear + sizeof(CK_ULONG_32),
                                       obj_data_len_32,
                                       &new_obj_data, &new_obj_data_len);
    if (ret)
        goto done;

    if (new_obj_data != NULL) {
        free(clear);

        /* build data to be encrypted */
        clear_len = sizeof(CK_ULONG_32) + new_obj_data_len + SHA1_HASH_SIZE;
        padded_len = block_size * (clear_len / block_size + 1);

        clear = malloc(padded_len);
        if (!clear) {
            fprintf(stderr, "Failed to allocate buffer\n");
            goto done;
        }

        ptr = clear;
        obj_data_len_32 = new_obj_data_len;
        memcpy(ptr, &obj_data_len_32, sizeof(CK_ULONG_32));
        ptr += sizeof(CK_ULONG_32);
        memcpy(ptr, new_obj_data, obj_data_len_32);
        ptr += obj_data_len_32;
        compute_sha1((char *)new_obj_data, new_obj_data_len, (char *)hash_sha);
        memcpy(ptr, hash_sha, SHA1_HASH_SIZE);

        add_pkcs_padding(clear + clear_len, block_size, clear_len,
                         padded_len);

        clear_len = padded_len;
    }
    /* now encrypt using software des3 */
    memcpy(sw_des3_key, masterkey, 3 * DES_KEY_SIZE);
    rc = sw_des3_cbc_encrypt(clear, clear_len, new_cipher, new_cipher_len,
                             (CK_BYTE *)"10293847", sw_des3_key);
    if (rc != CKR_OK)
        ret = -1;

done:
    if (clear)
        free(clear);

    return ret;
}

int load_token_objects(unsigned char *data_store,
                       unsigned char *masterkey)
{
    FILE *fp1 = NULL, *fp2 = NULL;
    unsigned char *buf = NULL;
    char tmp[PATH_MAX], fname[PATH_MAX], iname[PATH_MAX];
    CK_BBOOL priv;
    unsigned int size;
    int rc = 0, scount = 0, fcount = 0;
    size_t read_size;
    unsigned char *new_cipher = NULL;
    unsigned long new_cipher_len;

    snprintf(iname, sizeof(iname), "%s/TOK_OBJ/OBJ.IDX", data_store);

    fp1 = fopen((char *) iname, "r");
    if (!fp1)
        return -1;              // no token objects

    while (fgets((char *) tmp, 50, fp1)) {
        tmp[strlen((char *) tmp) - 1] = 0;

        snprintf((char *) fname, sizeof(fname), "%s/TOK_OBJ/", data_store);
        strcat((char *) fname, (char *) tmp);

        fp2 = fopen((char *) fname, "r");
        if (!fp2)
            continue;

        read_size = fread(&size, sizeof(CK_ULONG_32), 1, fp2);
        if (read_size != 1) {
            fprintf(stderr, "Cannot read size\n");
            goto cleanup;
        }
        read_size = fread(&priv, sizeof(CK_BBOOL), 1, fp2);
        if (read_size != 1) {
            fprintf(stderr, "Cannot read boolean\n");
            goto cleanup;
        }

        size = size - sizeof(CK_ULONG_32) - sizeof(CK_BBOOL);
        buf = (unsigned char *) malloc(size);
        if (!buf) {
            fprintf(stderr, "Cannot malloc for object %s "
                    "(ignoring it).\n", tmp);
            goto cleanup;
        }

        read_size = fread((char *) buf, 1, size, fp2);
        if (read_size != size) {
            fprintf(stderr, "Cannot read object %s " "(ignoring it).\n", tmp);
            goto cleanup;
        }

        fclose(fp2);
        fp2 = NULL;

        if (priv != FALSE) {
            /* private token object */
            new_cipher_len = size * 2; /* obj may grow during processing ! */
            new_cipher = malloc(new_cipher_len);
            if (!new_cipher) {
                fprintf(stderr, "Cannot malloc space for new "
                        "cipher (ignoring object %s).\n", tmp);
                goto cleanup;
            }

            /* After reading the private token object,
             * decrypt it using CCA des3 and then re-encrypt it
             * using software des3.
             */
            memset(new_cipher, 0, new_cipher_len);
            rc = reencrypt_private_token_object(buf, size,
                                                new_cipher, &new_cipher_len,
                                                masterkey);
            if (rc)
                goto cleanup;
        } else {
            /* public token object */
            rc = adjust_key_object_attributes(buf, size, &new_cipher,
                                              &new_cipher_len);
            if (rc)
                goto cleanup;

            /* Only save if the object has been changed */
            if (new_cipher == NULL)
                goto cleanup;
        }

        /* now save the newly re-encrypted object back to
         * disk in its original file.
         */
        fp2 = fopen((char *) fname, "w");
        size = sizeof(CK_ULONG_32) + sizeof(CK_BBOOL) + new_cipher_len;
        (void) fwrite(&size, sizeof(CK_ULONG_32), 1, fp2);
        (void) fwrite(&priv, sizeof(CK_BBOOL), 1, fp2);
        (void) fwrite(new_cipher, new_cipher_len, 1, fp2);
        rc = 0;

cleanup:
        if (fp2)
            fclose(fp2);
        if (buf)
            free(buf);
        if (new_cipher)
            free(new_cipher);

        if (rc) {
            if (v_flag)
                printf("Failed to process %s\n", fname);
            fcount++;
        } else {
            if (v_flag)
                printf("Processed %s.\n", fname);
            scount++;
        }
    }
    fclose(fp1);
    printf("Successfully migrated %d object(s).\n", scount);

    if (v_flag && fcount)
        printf("Failed to migrate %d object(s).\n", fcount);

    return 0;
}

int load_masterkey(char *mkfile, char *pin, char *masterkey)
{
    unsigned char des3_key[3 * DES_KEY_SIZE];
    char hash_sha[SHA1_HASH_SIZE];
    char pin_md5_hash[MD5_HASH_SIZE];
    unsigned char *cipher = NULL;
    char *clear = NULL;
    unsigned long cipher_len, clear_len;
    int ret;
    CK_RV rc;
    FILE *fp = NULL;

    clear_len = cipher_len =
        (MASTER_KEY_SIZE + SHA1_HASH_SIZE +
         (DES_BLOCK_SIZE - 1)) & ~(DES_BLOCK_SIZE - 1);

    fp = fopen((char *) mkfile, "r");
    if (!fp) {
        print_error("Could not open %s: %s\n", mkfile, strerror(errno));
        return -1;
    }

    cipher = malloc(cipher_len);
    clear = malloc(clear_len);
    if (cipher == NULL || clear == NULL) {
        ret = -1;
        goto done;
    }

    ret = fread(cipher, cipher_len, 1, fp);
    if (ret != 1) {
        print_error("Could not read %s: %s\n", mkfile, strerror(errno));
        ret = -1;
        goto done;
    }

    /* decrypt the masterkey */

    ret = compute_md5(pin, strlen(pin), pin_md5_hash);
    if (ret) {
        print_error("Error calculating MD5 of PIN!\n");
        goto done;
    }

    memcpy(des3_key, pin_md5_hash, MD5_HASH_SIZE);
    memcpy(des3_key + MD5_HASH_SIZE, pin_md5_hash, DES_KEY_SIZE);

    rc = sw_des3_cbc_decrypt(cipher, cipher_len, (unsigned char *)clear,
                             &clear_len, (unsigned char *) "12345678",
                             des3_key);
    if (rc != CKR_OK) {
        print_error("Error decrypting master key file after read");
        ret = -1;
        goto done;
    }

    /*
     * technically should strip PKCS padding here but since I already know
     * what the length should be, I don't bother.
     *
     * compare the hashes to verify integrity
     */

    ret = compute_sha1(clear, MASTER_KEY_SIZE, hash_sha);
    if (ret) {
        print_error("Failed to compute sha for masterkey.\n");
        goto done;
    }

    if (memcmp(hash_sha, clear + MASTER_KEY_SIZE, SHA1_HASH_SIZE) != 0) {
        print_error("%s appears to have been tampered!\n", mkfile);
        print_error("Cannot migrate.\n");
        ret = -1;
        goto done;
    }

    memcpy(masterkey, clear, MASTER_KEY_SIZE);
    ret = 0;

done:
    if (fp)
        fclose(fp);
    if (clear)
        free(clear);
    if (cipher)
        free(cipher);

    return ret;
}

int get_pin(char **pin, size_t *pinlen)
{
    struct termios old, new;
    int nread;
    char *buff = NULL;
    size_t buflen;
    int rc = 0;

    /* turn echoing off */
    if (tcgetattr(fileno(stdin), &old) != 0)
        return -1;

    new = old;
    new.c_lflag &= ~ECHO;
    if (tcsetattr(fileno(stdin), TCSAFLUSH, &new) != 0)
        return -1;

    /* read the pin
     * Note: getline will allocate memory for buff. free it when done.
     */
    nread = getline(&buff, &buflen, stdin);
    if (nread == -1) {
        rc = -1;
        goto done;
    }

    /* Restore terminal */
    (void) tcsetattr(fileno(stdin), TCSAFLUSH, &old);

    /* start a newline */
    printf("\n");
    fflush(stdout);

    /* Allocate  PIN.
     * Note: nread includes carriage return.
     * Replace with terminating NULL.
     */
    *pin = (char *) malloc(nread);
    if (*pin == NULL) {
        rc = -ENOMEM;
        goto done;
    }

    /* strip the carriage return since not part of pin. */
    buff[nread - 1] = '\0';
    memcpy(*pin, buff, nread);
    /* don't include the terminating null in the pinlen */
    *pinlen = nread - 1;

done:
    if (buff)
        free(buff);

    return rc;
}

int verify_pins(char *data_store, char *sopin, unsigned long sopinlen,
                char *userpin, unsigned long userpinlen)
{
    TOKEN_DATA td;
    char fname[PATH_MAX];
    char pin_sha[SHA1_HASH_SIZE];
    FILE *fp = NULL;
    int ret;

    /* read the NVTOK.DAT */
    snprintf(fname, PATH_MAX, "%s/NVTOK.DAT", data_store);
    fp = fopen((char *) fname, "r");
    if (!fp) {
        print_error("Could not open %s: %s\n", fname, strerror(errno));
        return -1;
    }

    ret = fread(&td, sizeof(TOKEN_DATA), 1, fp);
    if (ret != 1) {
        print_error("Could not read %s: %s\n", fname, strerror(errno));
        ret = -1;
        goto done;
    }

    /* Now compute the SHAs for the SO and USER pins entered.
     * Compare with the SHAs for SO and USER PINs saved in
     * NVTOK.DAT to verify.
     */

    if (sopin != NULL) {
        ret = compute_sha1(sopin, sopinlen, pin_sha);
        if (ret) {
            print_error("Failed to compute sha for SO.\n");
            goto done;
        }

        if (memcmp(td.so_pin_sha, pin_sha, SHA1_HASH_SIZE) != 0) {
            print_error("SO PIN is incorrect.\n");
            ret = -1;
            goto done;
        }
    }

    if (userpin != NULL) {
        ret = compute_sha1(userpin, userpinlen, pin_sha);
        if (ret) {
            print_error("Failed to compute sha for USER.\n");
            goto done;
        }

        if (memcmp(td.user_pin_sha, pin_sha, SHA1_HASH_SIZE) != 0) {
            print_error("USER PIN is incorrect.\n");
            ret = -1;
            goto done;
        }
    }
    ret = 0;

done:
    /* clear out the hash */
    memset(pin_sha, 0, SHA1_HASH_SIZE);
    if (fp)
        fclose(fp);

    return ret;
}


CK_FUNCTION_LIST *p11_init(void)
{
    CK_RV rv;
    CK_RV (*pfoo) ();
    char *loc1_lib = "/usr/lib/pkcs11/PKCS11_API.so64";
    char *loc2_lib = "libopencryptoki.so";
    CK_FUNCTION_LIST *funcs = NULL;


    p11_lib = dlopen(loc1_lib, RTLD_NOW);
    if (p11_lib != NULL)
        goto get_list;

    p11_lib = dlopen(loc2_lib, RTLD_NOW);
    if (p11_lib == NULL) {
        print_error("Couldn't get a handle to the PKCS#11 library.");
        return NULL;
    }

get_list:
    *(void **)(&pfoo) = dlsym(p11_lib, "C_GetFunctionList");
    if (pfoo == NULL) {
        print_error("Couldn't get the address of the C_GetFunctionList "
                    "routine.");
        dlclose(p11_lib);
        return NULL;
    }

    rv = pfoo(&funcs);
    if (rv != CKR_OK) {
        p11_error("C_GetFunctionList", rv);
        dlclose(p11_lib);
        return NULL;
    }

    rv = funcs->C_Initialize(NULL_PTR);
    if (rv != CKR_OK) {
        p11_error("C_Initialize", rv);
        dlclose(p11_lib);
        return NULL;
    }

    if (v_flag)
        printf("PKCS#11 library initialized\n");

    return funcs;
}

void p11_fini(CK_FUNCTION_LIST *funcs)
{
    funcs->C_Finalize(NULL_PTR);

    if (p11_lib)
        dlclose(p11_lib);
}

/* Expect attribute array to have 3 entries,
 * 0 CKA_IBM_OPAQUE
 * 1 CKA_KEY_TYPE
 * 2 CKA_LABEL
 */
int add_key(CK_OBJECT_HANDLE handle, CK_ATTRIBUTE *attrs, struct key **keys)
{
    struct key *new_key;
    CK_ULONG key_type = *(CK_ULONG *) attrs[1].pValue;

    new_key = malloc(sizeof(struct key));
    if (!new_key) {
        print_error("Malloc of %zd bytes failed!", sizeof(struct key));
        return 1;
    }

    switch (key_type) {
    case CKK_AES:
    case CKK_DES:
    case CKK_DES2:
    case CKK_DES3:
    case CKK_EC:
    case CKK_GENERIC_SECRET:
    case CKK_RSA:
        break;
    default:
        free(new_key);
        return 0;
    }

    new_key->type = key_type;
    new_key->opaque_attr = malloc(attrs[0].ulValueLen);
    if (!new_key->opaque_attr) {
        print_error("Malloc of %lu bytes failed!", attrs[0].ulValueLen);
        return 2;
    }
    new_key->handle = handle;
    new_key->attr_len = attrs[0].ulValueLen;
    memcpy(new_key->opaque_attr, attrs[0].pValue, attrs[0].ulValueLen);
    new_key->label = malloc(attrs[2].ulValueLen + 1);
    if (!new_key->label) {
        print_error("Malloc of %lu bytes failed!", attrs[2].ulValueLen + 1);
        return 2;
    }

    memset(new_key->label, 0, attrs[2].ulValueLen + 1);
    memcpy(new_key->label, attrs[2].pValue, attrs[2].ulValueLen);

    new_key->next = *keys;
    *keys = new_key;

    if (v_flag) {
        char *type_name;
        switch (new_key->type) {
        case CKK_AES:
            type_name = AES_NAME;
            break;
        case CKK_DES:
            type_name = DES_NAME;
            break;
        case CKK_DES2:
            type_name = DES2_NAME;
            break;
        case CKK_DES3:
            type_name = DES3_NAME;
            break;
        case CKK_EC:
            type_name = ECC_NAME;
            break;
        case CKK_GENERIC_SECRET:
            type_name = HMAC_NAME;
            break;
        case CKK_RSA:
            type_name = RSA_NAME;
            break;
        default:
            type_name = BAD_NAME;
        }

        printf("Migratable key found: type=%s, label=%s, handle=%lu\n",
               type_name, new_key->label, handle);
    }

    return 0;
}

int find_wrapped_keys(CK_FUNCTION_LIST *funcs, CK_SESSION_HANDLE sess,
                      CK_KEY_TYPE *key_type, struct key **keys)
{
    CK_RV rv;
    CK_OBJECT_HANDLE *handles = NULL, tmp;
    CK_ULONG ulObjectCount = 0, ulTotalCount = 0;
    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE key_tmpl[] = {
        {CKA_KEY_TYPE, key_type, sizeof(*key_type)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_EXTRACTABLE, &true, sizeof(true)}
    };

    CK_ATTRIBUTE attrs[] = {
        {CKA_IBM_OPAQUE, NULL, 0},
        {CKA_KEY_TYPE, NULL, 0},
        {CKA_LABEL, NULL, 0}
    };
    int i, rc, num_attrs = 3;


    /* Find all objects in the store */
    rv = funcs->C_FindObjectsInit(sess, key_tmpl, 3);
    if (rv != CKR_OK) {
        p11_error("C_FindObjectsInit", rv);
        print_error("Error finding CCA key objects");
        return 1;
    }

    while (1) {
        rv = funcs->C_FindObjects(sess, &tmp, 1, &ulObjectCount);
        if (rv != CKR_OK) {
            p11_error("C_FindObjects", rv);
            print_error("Error finding CCA key objects");
            free(handles);
            return 1;
        }

        if (ulObjectCount == 0)
            break;

        handles = realloc(handles, sizeof(CK_OBJECT_HANDLE) * (++ulTotalCount));
        if (!handles) {
            print_error("Malloc of %lu bytes failed!", ulTotalCount);
            break;
        }

        handles[ulTotalCount - 1] = tmp;
    }
    if (v_flag)
        printf("Found %lu keys to examine\n", ulTotalCount);

    /* Don't care if this fails */
    funcs->C_FindObjectsFinal(sess);

    /* At this point we have an array with handles to every object in the
     * store. We only care about those with a CKA_IBM_OPAQUE attribute,
     * so whittle down the list accordingly */
    for (tmp = 0; tmp < ulTotalCount; tmp++) {
        rv = funcs->C_GetAttributeValue(sess, handles[tmp], attrs, num_attrs);
        if (rv != CKR_OK) {
            p11_error("C_GetAttributeValue", rv);
            print_error("Error finding CCA key objects");
            free(handles);
            return 1;
        }

        /* If the opaque attr DNE, move to the next key */
        if (attrs[0].ulValueLen == ((CK_ULONG) - 1)) {
            continue;
        }

        /* Allocate space in the template for the actual data */
        for (i = 0; i < num_attrs; i++) {
            attrs[i].pValue = malloc(attrs[i].ulValueLen);
            if (!attrs[i].pValue) {
                print_error("Malloc of %lu bytes failed!", attrs[i].ulValueLen);
                free(handles);
                return 1;
            }
        }

        /* Pull in the actual data */
        rv = funcs->C_GetAttributeValue(sess, handles[tmp], attrs, num_attrs);
        if (rv != CKR_OK) {
            p11_error("C_GetAttributeValue", rv);
            print_error("Error getting object attributes");
            free(handles);
            return 1;
        }

        rc = add_key(handles[tmp], attrs, keys);
        if (rc) {
            free(handles);
            return 1;
        }

        for (i = 0; i < num_attrs; i++) {
            free(attrs[i].pValue);
            attrs[i].pValue = NULL_PTR;
            attrs[i].ulValueLen = 0;
        }
    }

    free(handles);

    return 0;
}

int replace_keys(CK_FUNCTION_LIST *funcs, CK_SESSION_HANDLE sess,
                 struct key *keys)
{
    CK_RV rv;
    CK_ATTRIBUTE new_attr[] = { {CKA_IBM_OPAQUE, NULL, 0} };
    struct key *key;

    for (key = keys; key; key = key->next) {
        new_attr->pValue = key->opaque_attr;
        new_attr->ulValueLen = key->attr_len;

        rv = funcs->C_SetAttributeValue(sess, key->handle, new_attr, 1);
        if (rv != CKR_OK) {
            p11_error("C_SetAttributeValue", rv);
            print_error("Error replacing old key with " "migrated key.");
            return 1;
        }
    }

    return 0;
}

int cca_migrate_asymmetric(struct key *key, char **out, struct algo algo)
{
    long return_code, reason_code, exit_data_length, key_identifier_length;
    unsigned char *key_identifier;

    exit_data_length = 0;
    key_identifier_length = key->attr_len;

    key_identifier = calloc(1, key->attr_len);
    if (!key_identifier) {
        print_error("Malloc of %lu bytes failed!", key->attr_len);
        return 1;
    }
    memcpy(key_identifier, (char *) key->opaque_attr, key->attr_len);

    CSNDKTC(&return_code,
            &reason_code,
            &exit_data_length,
            NULL,
            &(algo.rule_array_count),
            algo.rule_array, &key_identifier_length, key_identifier);

    if (return_code != CCA_SUCCESS) {
        cca_error("CSNDKTC (Key Token Change)", return_code, reason_code);
        print_error("Migrating %s key failed. label=%s, handle=%lu",
                    algo.name, key->label, key->handle);
        return 1;
    } else if (v_flag) {
        printf("Successfully migrated %s key. label=%s, handle=%lu\n",
               algo.name, key->label, key->handle);
    }

    *out = (char *) key_identifier;

    if (!memcmp((CK_BYTE *) key->opaque_attr,
                (CK_BYTE *) key_identifier, key_identifier_length)) {
        printf("Skipping, %s token is  wrapped with current master key. "
               "label=%s, handle=%lu\n",
               algo.name, key->label, key->handle);
    }

    return 0;
}

int cca_migrate_symmetric(struct key *key, char **out, struct algo algo)
{
    long return_code, reason_code, exit_data_length;
    unsigned char *key_identifier;

    exit_data_length = 0;

    key_identifier = calloc(1, key->attr_len);
    if (!key_identifier) {
        print_error("Malloc of %lu bytes failed!", key->attr_len);
        return 1;
    }
    memcpy(key_identifier, (char *) key->opaque_attr, key->attr_len);

    CSNBKTC(&return_code,
            &reason_code,
            &exit_data_length,
            NULL, &(algo.rule_array_count), algo.rule_array, key_identifier);

    if (return_code != CCA_SUCCESS) {
        cca_error("CSNBKTC (Key Token Change)", return_code, reason_code);
        print_error("Migrating %s key failed. label=%s, handle=%lu",
                    algo.name, key->label, key->handle);
        return 1;
    } else if (v_flag) {
        printf("Successfully migrated %s key. label=%s, handle=%lu\n",
               algo.name, key->label, key->handle);
    }

    *out = (char *) key_identifier;

    if (!memcmp((CK_BYTE *) key->opaque_attr,
                (CK_BYTE *) key_identifier, key->attr_len)) {
        printf("Skipping, %s token is  wrapped with current master key. "
                "label=%s, handle=%lu\n",
                algo.name, key->label, key->handle);
    }
    return 0;
}

int cca_migrate_hmac(struct key *key, char **out, struct algo algo)
{
    long return_code, reason_code, exit_data_length, key_identifier_length;
    unsigned char *key_identifier;

    exit_data_length = 0;
    key_identifier_length = key->attr_len;

    key_identifier = calloc(1, key->attr_len);
    if (!key_identifier) {
        print_error("Malloc of %lu bytes failed!", key->attr_len);
        return 1;
    }
    memcpy(key_identifier, (char *) key->opaque_attr, key->attr_len);

    CSNBKTC2(&return_code,
             &reason_code,
             &exit_data_length,
             NULL,
             &(algo.rule_array_count),
             algo.rule_array, &key_identifier_length, key_identifier);

    if (return_code != CCA_SUCCESS) {
        cca_error("CSNBKTC2 (Key Token Change)", return_code, reason_code);
        print_error("Migrating %s key failed. label=%s, handle=%lu",
                    algo.name, key->label, key->handle);
        return 1;
    } else if (v_flag) {
        printf("Successfully migrated %s key. label=%s, handle=%lu\n",
               algo.name, key->label, key->handle);
    }

    *out = (char *) key_identifier;

    if (!memcmp((CK_BYTE *) key->opaque_attr,
                (CK_BYTE *) key_identifier, key_identifier_length)) {
        printf("Skipping, %s token is  wrapped with current master key. "
                "label=%s, handle=%lu\n",
                algo.name, key->label, key->handle);
    }

    return 0;
}

/* @keys: A linked list of data to migrate and the PKCS#11 handle for the
 * object in the data store.
 * @count: counter for number of keys migrated
 * @count_failed: counter for number of keys that failed to migrate
 */
int cca_migrate(struct key *keys, struct key_count *count,
                struct key_count *count_failed)
{
    struct key *key;
    char *migrated_data;
    int rc;

    for (key = keys; key; key = key->next) {
        migrated_data = NULL;

        switch (key->type) {
        case CKK_AES:
            rc = cca_migrate_symmetric(key, &migrated_data, aes);
            if (rc)
                count_failed->aes++;
            else
                count->aes++;
            break;
        case CKK_DES:
        case CKK_DES2:
        case CKK_DES3:
            rc = cca_migrate_symmetric(key, &migrated_data, des);
            if (rc)
                count_failed->des++;
            else
                count->des++;
            break;
        case CKK_EC:
            rc = cca_migrate_asymmetric(key, &migrated_data, ecc);
            if (rc)
                count_failed->ecc++;
            else
                count->ecc++;
            break;
        case CKK_GENERIC_SECRET:
            rc = cca_migrate_hmac(key, &migrated_data, hmac);
            if (rc)
                count_failed->hmac++;
            else
                count->hmac++;
            break;
        case CKK_RSA:
            rc = cca_migrate_asymmetric(key, &migrated_data, rsa);
            if (rc)
                count_failed->rsa++;
            else
                count->rsa++;
            break;
        }

        /* replace the original key with the migrated key */
        if (!rc && migrated_data) {
            free(key->opaque_attr);
            key->opaque_attr = (CK_BYTE *) migrated_data;
        }
    }

    return 0;
}

int migrate_keytype(CK_FUNCTION_LIST *funcs, CK_SESSION_HANDLE sess,
                    CK_KEY_TYPE *k_type, struct key_count *count,
                    struct key_count *count_failed)
{
    struct key *keys = NULL, *tmp, *to_free;
    int rc;

    rc = find_wrapped_keys(funcs, sess, k_type, &keys);
    if (rc) {
        goto done;
    }

    rc = cca_migrate(keys, count, count_failed);
    if (rc) {
        goto done;
    }

    rc = replace_keys(funcs, sess, keys);
    if (rc) {
        goto done;
    }

done:
    for (to_free = keys; to_free; to_free = tmp) {
        tmp = to_free->next;
        free(to_free->opaque_attr);
        free(to_free);
    }

    return rc;
}

void key_migration_results(struct key_count migrated, struct key_count failed)
{
    if (migrated.aes || migrated.des || migrated.des2 || migrated.des3 ||
        migrated.ecc || migrated.hmac || migrated.rsa)
        printf("Successfully migrated: ");
    if (migrated.aes)
        printf("AES: %d. ", migrated.aes);
    if (migrated.des)
        printf("DES: %d. ", migrated.des);
    if (migrated.des2)
        printf("DES2: %d. ", migrated.des2);
    if (migrated.des3)
        printf("DES3: %d. ", migrated.des3);
    if (migrated.ecc)
        printf("ECC: %d. ", migrated.ecc);
    if (migrated.hmac)
        printf("HMAC: %d. ", migrated.hmac);
    if (migrated.rsa)
        printf("RSA: %d. ", migrated.rsa);

    if (failed.aes || failed.des || failed.des2 || failed.des3 ||
        failed.ecc || failed.hmac || failed.rsa)
        printf("\nFailed to migrate: ");
    if (failed.aes)
        printf("AES: %d. ", failed.aes);
    if (failed.des)
        printf("DES: %d. ", failed.des);
    if (failed.des2)
        printf("DES2: %d. ", failed.des2);
    if (failed.des3)
        printf("DES3: %d. ", failed.des3);
    if (failed.ecc)
        printf("ECC: %d. ", failed.ecc);
    if (failed.hmac)
        printf("HMAC: %d. ", failed.hmac);
    if (failed.rsa)
        printf("RSA: %d. ", failed.rsa);

    printf("\n");
}

int migrate_wrapped_keys(CK_SLOT_ID slot_id, char *userpin, int masterkey)
{
    CK_FUNCTION_LIST *funcs;
    CK_KEY_TYPE key_type = 0;
    CK_ULONG slot_count;
    CK_SESSION_HANDLE sess;
    CK_RV rv;
    struct key_count count = { 0, 0, 0, 0, 0, 0, 0 };
    struct key_count count_failed = { 0, 0, 0, 0, 0, 0, 0 };
    int exit_code = 0, rc;

    funcs = p11_init();
    if (!funcs) {
        return 2;
    }

    rv = funcs->C_GetSlotList(TRUE, NULL_PTR, &slot_count);
    if (rv != CKR_OK) {
        p11_error("C_GetSlotList", rv);
        exit_code = 3;
        goto finalize;
    }

    if (slot_id >= slot_count) {
        print_error("%lu is not a valid slot ID.", slot_id);
        exit_code = 4;
        goto finalize;
    }

    rv = funcs->C_OpenSession(slot_id, CKF_RW_SESSION |
                              CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sess);
    if (rv != CKR_OK) {
        p11_error("C_OpenSession", rv);
        exit_code = 5;
        goto finalize;
    }

    rv = funcs->C_Login(sess, CKU_USER, (CK_BYTE *) userpin, strlen(userpin));
    if (rv != CKR_OK) {
        p11_error("C_Login (USER)", rv);
        exit_code = 8;
        goto finalize;
    }

    switch (masterkey) {
    case MK_AES:
        if (v_flag)
            printf("Search for AES keys\n");
        key_type = CKK_AES;
        rc = migrate_keytype(funcs, sess, &key_type, &count, &count_failed);
        if (rc) {
            goto done;
        }
        if (v_flag)
            printf("Search for HMAC keys\n");
        key_type = CKK_GENERIC_SECRET;
        rc = migrate_keytype(funcs, sess, &key_type, &count, &count_failed);
        if (rc) {
            goto done;
        }
        break;
    case MK_APKA:
        if (v_flag)
            printf("Search for ECC keys\n");
        key_type = CKK_EC;
        rc = migrate_keytype(funcs, sess, &key_type, &count, &count_failed);
        if (rc) {
            goto done;
        }
        break;
    case MK_ASYM:
        if (v_flag)
            printf("Search for RSA keys\n");
        key_type = CKK_RSA;
        rc = migrate_keytype(funcs, sess, &key_type, &count, &count_failed);
        if (rc) {
            goto done;
        }
        break;
    case MK_SYM:
        if (v_flag)
            printf("Search for DES keys\n");
        key_type = CKK_DES;
        rc = migrate_keytype(funcs, sess, &key_type, &count, &count_failed);
        if (rc) {
            goto done;
        }
        if (v_flag)
            printf("Search for DES2 keys\n");
        key_type = CKK_DES2;
        rc = migrate_keytype(funcs, sess, &key_type, &count, &count_failed);
        if (rc) {
            goto done;
        }
        if (v_flag)
            printf("Search for DES3 keys\n");
        key_type = CKK_DES3;
        rc = migrate_keytype(funcs, sess, &key_type, &count, &count_failed);
        if (rc) {
            goto done;
        }
        break;
    default:
        print_error("unknown key type (%lu)\n", key_type);
        return -1;
    }

    key_migration_results(count, count_failed);

done:
    funcs->C_CloseSession(sess);
finalize:
    p11_fini(funcs);
    return exit_code;
}

int migrate_version(char *sopin, char *userpin, unsigned char *data_store)
{
    char masterkey[MASTER_KEY_SIZE];
    char fname[PATH_MAX];
    struct stat statbuf;
    int ret = 0;

    /* Verify that the data store is valid by looking for
     * MK_SO, MK_USER, and TOK_OBJ/OBJ.IDX.
     */
    memset(fname, 0, PATH_MAX);
    snprintf(fname, PATH_MAX, "%s/MK_SO", data_store);
    if (stat(fname, &statbuf) != 0) {
        fprintf(stderr, "Cannot find %s.\n", fname);
        ret = -1;
        goto done;
    }

    memset(fname, 0, PATH_MAX);
    snprintf(fname, PATH_MAX, "%s/MK_USER", data_store);
    if (stat(fname, &statbuf) != 0) {
        fprintf(stderr, "Cannot find %s.\n", fname);
        ret = -1;
        goto done;
    }

    memset(fname, 0, PATH_MAX);
    snprintf(fname, PATH_MAX, "%s/TOK_OBJ/OBJ.IDX", data_store);
    if (stat(fname, &statbuf) != 0) {
        fprintf(stderr, "Cannot find %s.\n", fname);
        ret = -1;
        goto done;
    }

    /* If the OBJ.IDX is empty, then no objects to migrate. */
    if (statbuf.st_size == 0) {
        printf("OBJ.IDX file is empty. Thus no objects to migrate.\n");
        goto done;
    }

    if (v_flag)
        printf("%s has an MK_SO, MK_USER and TOK/OBJ.IDX\n", data_store);
    /* Get the masterkey from MK_SO.
     * This also helps verify that correct SO pin was entered.
     */
    memset(masterkey, 0, MASTER_KEY_SIZE);
    memset(fname, 0, PATH_MAX);
    snprintf(fname, PATH_MAX, "%s/MK_SO", data_store);
    ret = load_masterkey(fname, sopin, masterkey);
    if (ret) {
        fprintf(stderr, "Could not load masterkey from MK_SO.\n");
        goto done;
    }

    if (v_flag)
        printf("Successfully verified SO Pin.\n");

    /* Get the masterkey from MK_USER.
     * This also helps verift that correct USER pin was entered.
     */
    memset(masterkey, 0, MASTER_KEY_SIZE);
    memset(fname, 0, PATH_MAX);
    snprintf(fname, PATH_MAX, "%s/MK_USER", data_store);
    ret = load_masterkey(fname, userpin, masterkey);
    if (ret) {
        fprintf(stderr, "Could not load masterkey from MK_USER.\n");
        goto done;
    }

    if (v_flag)
        printf("Successfully verified USER Pin.\n");

    /* Load all the private token objects and re-encrypt them
     * using software des3, instead of CSNBENC.
     * For private and public token objects, migrate the key object's
     * attributes to IBM_OPAQUE.
     */
    (void)load_token_objects(data_store, (CK_BYTE *)masterkey);

done:
    return ret;
}

void usage(char *progname)
{
    printf(" Help:\t\t\t\t%s -h\n", progname);
    printf(" -h\t\t\t\tShow this help\n\n");
    printf(" Migrate Object Version:\t%s -m v2objectsv3 [OPTIONS] \n",
           progname);
    printf(" -m v2objectsv3.\t\tMigrates CCA private token objects from");
    printf(" CCA\n\t\t\t\tencryption (used in v2) to software encryption");
    printf(" \n\t\t\t\t(used in v3). \n");
    printf(" Migrate Wrapped Keys:\t\t%s -m keys -s SLOTID -k KEYTYPE "
           "[OPTIONS] \n", progname);
    printf(" -m keys.\t\t\tUnwraps private keys with the");
    printf(" old CCA master\n\t\t\t\tkey and wraps them with the");
    printf(" new CCA master key\n");
    printf(" -s, --slotid SLOTID\t\tPKCS slot number\n");
    printf(" -k aes|apka|asym|sym\t\tMigrate selected keytype\n\n");
    printf(" Options:\n");
    printf(" -d, --datastore DATASTORE\tCCA token datastore location\n");
    printf(" -v, --verbose\t\t\tProvide more detailed output\n");
    printf(" \n\t\t\t\tthe migrated data\n\n");
    return;
}

int main(int argc, char **argv)
{
    int ret = 0, opt = 0, c_flag = 0, masterkey = 0;
    int data_store_len = 0;
    CK_SLOT_ID slot_id = 0;
    char *sopin = NULL, *userpin = NULL;
    size_t sopinlen, userpinlen;
    char *data_store = NULL;
    char *m_type = NULL;
    char *mk_type = NULL;
    void *lib_csulcca;

    int m_version = 0;
    int m_keys = 0;

    struct option long_opts[] = {
        {"datastore", required_argument, NULL, 'd'},
        {"slotid", required_argument, NULL, 's'},
        {"verbose", no_argument, NULL, 'v'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "m:d:s:k:hv", long_opts, NULL))
           != -1) {
        switch (opt) {
        case 'd':
            data_store = strdup(optarg);
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        case 'k':
            mk_type = strdup(optarg);
            if (!memcmp(mk_type, "aes", 3)) {
                masterkey = MK_AES;
            } else if (!memcmp(mk_type, "apka", 4)) {
                masterkey = MK_APKA;
            } else if (!memcmp(mk_type, "asym", 4)) {
                masterkey = MK_ASYM;
            } else if (!memcmp(mk_type, "sym", 3)) {
                masterkey = MK_SYM;
            } else {
                print_error("unknown key type (%s)\n", mk_type);
                usage(argv[0]);
                return -1;
            }
            break;
        case 'm':
            m_type = strdup(optarg);
            if (!memcmp(m_type, "v2objectsv3", 11)) {
                m_version = 1;
            } else if (!memcmp(m_type, "keys", 4)) {
                m_keys = 1;
            } else {
                print_error("unknown migration type (%s)\n", m_type);
                usage(argv[0]);
                return -1;
            }
            break;
        case 's':
            c_flag++;
            slot_id = atoi(optarg);
            break;
        case 'v':
            v_flag++;
            break;
        default:
            usage(argv[0]);
            return -1;
        }
    }

    /* check for missing parameters */
    if (!m_version && !m_keys) {
        print_error("missing migration type\n");
        usage(argv[0]);
        return -1;
    }

    /* use default data_store if one is not given */
    if (data_store == NULL) {
        data_store_len = strlen(TOK_DATASTORE);
        data_store = malloc(data_store_len + 1);
        if (data_store == NULL) {
            fprintf(stderr, "malloc failed: %s\n", strerror(errno));
            return -1;
        }
        memset(data_store, 0, data_store_len + 1);
        memcpy(data_store, TOK_DATASTORE, data_store_len);
    }

    /* get the SO pin to authorize migration */
    printf("Enter the SO PIN: ");
    fflush(stdout);
    ret = get_pin(&sopin, &sopinlen);
    if (ret != 0) {
        print_error("Could not get SO PIN.\n");
        goto done;
    }

    /* get the USER pin to authorize migration */
    printf("Enter the USER PIN: ");
    fflush(stdout);
    ret = get_pin(&userpin, &userpinlen);
    if (ret != 0) {
        print_error("Could not get USER PIN.\n");
        goto done;
    }

    /* verify the SO and USER PINs entered. */
    ret = verify_pins(data_store, sopin, sopinlen, userpin, userpinlen);
    if (ret)
        goto done;

    lib_csulcca = dlopen(CCA_LIBRARY, (RTLD_GLOBAL | RTLD_NOW));
    if (lib_csulcca == NULL) {
        fprintf(stderr, "dlopen(%s) failed: %s\n", CCA_LIBRARY,
                strerror(errno));
        return -1;
    }

    if (m_version) {
        *(void **)(&CSNBDEC) = dlsym(lib_csulcca, "CSNBDEC");
        ret = migrate_version(sopin, userpin, (CK_BYTE *)data_store);
    } else if (m_keys) {
        if (!slot_id) {
            print_error("missing slot number\n");
            usage(argv[0]);
            return -1;
        }

        if (!masterkey) {
            print_error("missing key type\n");
            usage(argv[0]);
            return -1;
        }

        *(void **)(&CSNDKTC) = dlsym(lib_csulcca, "CSNDKTC");
        *(void **)(&CSNBKTC) = dlsym(lib_csulcca, "CSNBKTC");
        *(void **)(&CSNBKTC2) = dlsym(lib_csulcca, "CSNBKTC2");
        ret = migrate_wrapped_keys(slot_id, userpin, masterkey);
    }

done:
    if (sopin)
        free(sopin);
    if (userpin)
        free(userpin);
    if (data_store)
        free(data_store);

    return ret;
}

char *p11strerror(CK_RV rc)
{
    switch (rc) {
    case CKR_OK:
        return "CKR_OK";
    case CKR_CANCEL:
        return "CKR_CANCEL";
    case CKR_HOST_MEMORY:
        return "CKR_HOST_MEMORY";
    case CKR_SLOT_ID_INVALID:
        return "CKR_SLOT_ID_INVALID";
    case CKR_GENERAL_ERROR:
        return "CKR_GENERAL_ERROR";
    case CKR_FUNCTION_FAILED:
        return "CKR_FUNCTION_FAILED";
    case CKR_ARGUMENTS_BAD:
        return "CKR_ARGUMENTS_BAD";
    case CKR_NO_EVENT:
        return "CKR_NO_EVENT";
    case CKR_NEED_TO_CREATE_THREADS:
        return "CKR_NEED_TO_CREATE_THREADS";
    case CKR_CANT_LOCK:
        return "CKR_CANT_LOCK";
    case CKR_ATTRIBUTE_READ_ONLY:
        return "CKR_ATTRIBUTE_READ_ONLY";
    case CKR_ATTRIBUTE_SENSITIVE:
        return "CKR_ATTRIBUTE_SENSITIVE";
    case CKR_ATTRIBUTE_TYPE_INVALID:
        return "CKR_ATTRIBUTE_TYPE_INVALID";
    case CKR_ATTRIBUTE_VALUE_INVALID:
        return "CKR_ATTRIBUTE_VALUE_INVALID";
    case CKR_DATA_INVALID:
        return "CKR_DATA_INVALID";
    case CKR_DATA_LEN_RANGE:
        return "CKR_DATA_LEN_RANGE";
    case CKR_DEVICE_ERROR:
        return "CKR_DEVICE_ERROR";
    case CKR_DEVICE_MEMORY:
        return "CKR_DEVICE_MEMORY";
    case CKR_DEVICE_REMOVED:
        return "CKR_DEVICE_REMOVED";
    case CKR_ENCRYPTED_DATA_INVALID:
        return "CKR_ENCRYPTED_DATA_INVALID";
    case CKR_ENCRYPTED_DATA_LEN_RANGE:
        return "CKR_ENCRYPTED_DATA_LEN_RANGE";
    case CKR_FUNCTION_CANCELED:
        return "CKR_FUNCTION_CANCELED";
    case CKR_FUNCTION_NOT_PARALLEL:
        return "CKR_FUNCTION_NOT_PARALLEL";
    case CKR_FUNCTION_NOT_SUPPORTED:
        return "CKR_FUNCTION_NOT_SUPPORTED";
    case CKR_KEY_HANDLE_INVALID:
        return "CKR_KEY_HANDLE_INVALID";
    case CKR_KEY_SIZE_RANGE:
        return "CKR_KEY_SIZE_RANGE";
    case CKR_KEY_TYPE_INCONSISTENT:
        return "CKR_KEY_TYPE_INCONSISTENT";
    case CKR_KEY_NOT_NEEDED:
        return "CKR_KEY_NOT_NEEDED";
    case CKR_KEY_CHANGED:
        return "CKR_KEY_CHANGED";
    case CKR_KEY_NEEDED:
        return "CKR_KEY_NEEDED";
    case CKR_KEY_INDIGESTIBLE:
        return "CKR_KEY_INDIGESTIBLE";
    case CKR_KEY_FUNCTION_NOT_PERMITTED:
        return "CKR_KEY_FUNCTION_NOT_PERMITTED";
    case CKR_KEY_NOT_WRAPPABLE:
        return "CKR_KEY_NOT_WRAPPABLE";
    case CKR_KEY_UNEXTRACTABLE:
        return "CKR_KEY_UNEXTRACTABLE";
    case CKR_MECHANISM_INVALID:
        return "CKR_MECHANISM_INVALID";
    case CKR_MECHANISM_PARAM_INVALID:
        return "CKR_MECHANISM_PARAM_INVALID";
    case CKR_OBJECT_HANDLE_INVALID:
        return "CKR_OBJECT_HANDLE_INVALID";
    case CKR_OPERATION_ACTIVE:
        return "CKR_OPERATION_ACTIVE";
    case CKR_OPERATION_NOT_INITIALIZED:
        return "CKR_OPERATION_NOT_INITIALIZED";
    case CKR_PIN_INCORRECT:
        return "CKR_PIN_INCORRECT";
    case CKR_PIN_INVALID:
        return "CKR_PIN_INVALID";
    case CKR_PIN_LEN_RANGE:
        return "CKR_PIN_LEN_RANGE";
    case CKR_PIN_EXPIRED:
        return "CKR_PIN_EXPIRED";
    case CKR_PIN_LOCKED:
        return "CKR_PIN_LOCKED";
    case CKR_SESSION_CLOSED:
        return "CKR_SESSION_CLOSED";
    case CKR_SESSION_COUNT:
        return "CKR_SESSION_COUNT";
    case CKR_SESSION_HANDLE_INVALID:
        return "CKR_SESSION_HANDLE_INVALID";
    case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
        return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
    case CKR_SESSION_READ_ONLY:
        return "CKR_SESSION_READ_ONLY";
    case CKR_SESSION_EXISTS:
        return "CKR_SESSION_EXISTS";
    case CKR_SESSION_READ_ONLY_EXISTS:
        return "CKR_SESSION_READ_ONLY_EXISTS";
    case CKR_SESSION_READ_WRITE_SO_EXISTS:
        return "CKR_SESSION_READ_WRITE_SO_EXISTS";
    case CKR_SIGNATURE_INVALID:
        return "CKR_SIGNATURE_INVALID";
    case CKR_SIGNATURE_LEN_RANGE:
        return "CKR_SIGNATURE_LEN_RANGE";
    case CKR_TEMPLATE_INCOMPLETE:
        return "CKR_TEMPLATE_INCOMPLETE";
    case CKR_TEMPLATE_INCONSISTENT:
        return "CKR_TEMPLATE_INCONSISTENT";
    case CKR_TOKEN_NOT_PRESENT:
        return "CKR_TOKEN_NOT_PRESENT";
    case CKR_TOKEN_NOT_RECOGNIZED:
        return "CKR_TOKEN_NOT_RECOGNIZED";
    case CKR_TOKEN_WRITE_PROTECTED:
        return "CKR_TOKEN_WRITE_PROTECTED";
    case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
        return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
    case CKR_UNWRAPPING_KEY_SIZE_RANGE:
        return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
    case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
        return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
    case CKR_USER_ALREADY_LOGGED_IN:
        return "CKR_USER_ALREADY_LOGGED_IN";
    case CKR_USER_NOT_LOGGED_IN:
        return "CKR_USER_NOT_LOGGED_IN";
    case CKR_USER_PIN_NOT_INITIALIZED:
        return "CKR_USER_PIN_NOT_INITIALIZED";
    case CKR_USER_TYPE_INVALID:
        return "CKR_USER_TYPE_INVALID";
    case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
        return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
    case CKR_USER_TOO_MANY_TYPES:
        return "CKR_USER_TOO_MANY_TYPES";
    case CKR_WRAPPED_KEY_INVALID:
        return "CKR_WRAPPED_KEY_INVALID";
    case CKR_WRAPPED_KEY_LEN_RANGE:
        return "CKR_WRAPPED_KEY_LEN_RANGE";
    case CKR_WRAPPING_KEY_HANDLE_INVALID:
        return "CKR_WRAPPING_KEY_HANDLE_INVALID";
    case CKR_WRAPPING_KEY_SIZE_RANGE:
        return "CKR_WRAPPING_KEY_SIZE_RANGE";
    case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
        return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
    case CKR_RANDOM_SEED_NOT_SUPPORTED:
        return "CKR_RANDOM_SEED_NOT_SUPPORTED";
    case CKR_RANDOM_NO_RNG:
        return "CKR_RANDOM_NO_RNG";
    case CKR_BUFFER_TOO_SMALL:
        return "CKR_BUFFER_TOO_SMALL";
    case CKR_SAVED_STATE_INVALID:
        return "CKR_SAVED_STATE_INVALID";
    case CKR_INFORMATION_SENSITIVE:
        return "CKR_INFORMATION_SENSITIVE";
    case CKR_STATE_UNSAVEABLE:
        return "CKR_STATE_UNSAVEABLE";
    case CKR_CRYPTOKI_NOT_INITIALIZED:
        return "CKR_CRYPTOKI_NOT_INITIALIZED";
    case CKR_CRYPTOKI_ALREADY_INITIALIZED:
        return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
    case CKR_MUTEX_BAD:
        return "CKR_MUTEX_BAD";
    case CKR_MUTEX_NOT_LOCKED:
        return "CKR_MUTEX_NOT_LOCKED";
    default:
        return "UNKNOWN";
    }

    return "UNKNOWN";
}
