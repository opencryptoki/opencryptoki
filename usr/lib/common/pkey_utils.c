/*
 * COPYRIGHT (c) International Business Machines Corp. 2020
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * Some protected key related routines that are shared between the
 * CCA and EP11 tokens.
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <pkcs11types.h>
#include <sys/ioctl.h>
#include <asm/pkey.h>

#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "attributes.h"
#include "trace.h"
#include "pkey_utils.h"

/**
 * s390_km:
 * @func: the function code passed to KM; see s390_km_func
 * @param: address of parameter block; see POP for details on each func
 * @dest: address of destination memory area
 * @src: address of source memory area
 * @src_len: length of src operand in bytes
 *
 * Executes the KM (CIPHER MESSAGE) operation of the CPU.
 *
 * Returns -1 for failure, 0 for the query func, number of processed
 * bytes for encryption/decryption funcs
 */
static int s390_km(unsigned long func, void *param, unsigned char *dest,
           const unsigned char *src, long src_len)
{
    register long __func __asm__("0") = func;
    register void *__param __asm__("1") = param;
    register const unsigned char *__src __asm__("2") = src;
    register long __src_len __asm__("3") = src_len;
    register unsigned char *__dest __asm__("4") = dest;

    __asm__ volatile (
        "0: .insn   rre,0xb92e0000,%2,%0 \n"    /* KM opcode */
        "   brc 1,0b \n"    /* handle partial completion */
        : "+a"(__src), "+d"(__src_len), "+a"(__dest)
        : "d"(__func), "a"(__param)
        : "cc", "memory");

    return func ? src_len - __src_len : __src_len;
}

/**
 * s390_kmc:
 * @func: the function code passed to KM; see s390_kmc_func
 * @param: address of parameter block; see POP for details on each func
 * @dest: address of destination memory area
 * @src: address of source memory area
 * @src_len: length of src operand in bytes
 *
 * Executes the KMC (CIPHER MESSAGE WITH CHAINING) operation of the CPU.
 *
 * Returns -1 for failure, 0 for the query func, number of processed
 * bytes for encryption/decryption funcs
 */
static int s390_kmc(unsigned long func, void *param, unsigned char *dest,
            const unsigned char *src, long src_len)
{
    register long __func __asm__("0") = func;
    register void *__param __asm__("1") = param;
    register const unsigned char *__src __asm__("2") = src;
    register long __src_len __asm__("3") = src_len;
    register unsigned char *__dest __asm__("4") = dest;

    __asm__ volatile (
        "0: .insn   rre, 0xb92f0000,%2,%0 \n"   /* KMC opcode */
        "   brc 1, 0b \n"   /* handle partial completion */
        : "+a"(__src), "+d"(__src_len), "+a"(__dest)
        : "d"(__func), "a"(__param)
        : "cc", "memory");

    return func ? src_len - __src_len : __src_len;
}

/**
 * s390_kmac:
 * @func: the function code passed to KMAC; see s390_kmac_func
 * @param: address of parameter block; see POP for details on each func
 * @src: address of source memory area
 * @src_len: length of src operand in bytes
 *
 * Executes the KMAC (COMPUTE MESSAGE AUTHENTICATION CODE) operation of the CPU.
 *
 * Returns -1 for failure, 0 for the query func, number of processed
 * bytes for encryption/decryption funcs
 */
static int s390_kmac(unsigned long func, void *param,
            const unsigned char *src, long src_len)
{
    register long __func __asm__("0") = func;
    register void *__param __asm__("1") = param;
    register const unsigned char *__src __asm__("2") = src;
    register long __src_len __asm__("3") = src_len;

    __asm__ volatile (
        "0:     .insn   rre, 0xb91e0000,%0,%0 \n"
        "       brc     1, 0b \n"
        : "+a"(__src), "+d"(__src_len)
        : "d"(__func), "a"(__param)
        : "cc", "memory");
    return func ? src_len - __src_len : __src_len;
}

/**
 * s390_pcc:
 * @func: the function code passed to KM; see s390_pcc_functions
 * @param: address of parameter block; see POP for details on each func
 *
 * Executes the PCC operation of the CPU.
 *
 * Returns -1 for failure, 0 for the query func, number of processed
 * bytes for encryption/decryption funcs
 */
static int s390_pcc(unsigned long func, void *param)
{
    register unsigned long r0 __asm__("0") = (unsigned long)func;
    register unsigned long r1 __asm__("1") = (unsigned long)param;

    __asm__ volatile (
        "0: .long   %[opc] << 16\n"
        "   brc 1,0b\n"
        :
        : [fc] "d" (r0), [param] "a" (r1), [opc] "i" (0xb92c)
        : "cc", "memory");

    return 0;
}

/**
 * Update the specified attribute of the given key object. The object gets
 * locked for write and is saved, if it's a token object.
 *
 * Note: When calling this function, the XProcLock MUST NOT be held,
 *       because it tries to obtain a write lock on the key object.
 */
CK_RV pkey_update_and_save(STDLL_TokData_t *tokdata, OBJECT *key_obj,
                           CK_ATTRIBUTE *pkey_attr)
{
    CK_RV ret1, ret2;

    /* Unlock obj to remove READ_LOCK */
    ret1 = object_unlock(key_obj);
    if (ret1 != CKR_OK) {
        TRACE_ERROR("object_unlock failed with rc=0x%lx\n", ret1);
        return ret1;
    }

    /* Obtain write lock on key object */
    ret1 = object_lock(key_obj, WRITE_LOCK);
    if (ret1 != CKR_OK) {
        TRACE_ERROR("object_lock for WRITE failed with rc=0x%lx\n", ret1);
        /* Try to restore read lock without rc checking */
        object_lock(key_obj, READ_LOCK);
        return ret1;
    }

    /* Update attribute */
    ret1 = template_update_attribute(key_obj->template, pkey_attr);
    if (ret1 != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed with rc=0x%lx\n", ret1);
        goto done;
    }

    /* Save to repository if it's a token object */
    if (object_is_token_object(key_obj)) {
        ret1 = object_mgr_save_token_object(tokdata, key_obj);
        if (ret1 != CKR_OK) {
            TRACE_ERROR("Could not save token obj to repository, rc=0x%lx.\n", ret1);
        }
    }

done:

    /* Restore object's READ_LOCK */
    ret2 = object_unlock(key_obj);
    if (ret2 != CKR_OK) {
        TRACE_ERROR("object_unlock failed with rc=0x%lx\n", ret2);
        return ret1 == CKR_OK ? ret2 : ret1;
    }

    ret2 = object_lock(key_obj, READ_LOCK);
    if (ret2 != CKR_OK) {
        TRACE_ERROR("object_lock for READ failed with rc=0x%lx\n", ret2);
        return ret1 == CKR_OK ? ret2 : ret1;
    }

    return ret1;
}

/**
 * Returns true if the protected key operation implied by the given mechanism
 * is supported by CPACF, false otherwise.
 */
CK_BBOOL pkey_op_supported_by_cpacf(CK_MECHANISM *mech)
{
    if (!mech)
        return CK_FALSE;

    switch (mech->mechanism) {
    case CKM_AES_ECB:
    case CKM_AES_CBC:
    case CKM_AES_CBC_PAD:
    case CKM_AES_CMAC_GENERAL:
    case CKM_AES_CMAC:
        return CK_TRUE;
    default:
        return CK_FALSE;
    }
}

/**
 * Return the KM/KMC/KMAC function code for the given key length and
 * encrypt/decrypt op.
 */
unsigned long get_function_code(CK_ULONG clear_keylen, CK_BYTE encrypt)
{
    unsigned long fc;

    switch (clear_keylen) {
    case 16:
        fc = ENCRYPTED_AES_128;
        break;
    case 24:
        fc = ENCRYPTED_AES_192;
        break;
    case 32:
        fc = ENCRYPTED_AES_256;
        break;
    default:
        return 0;
    }

    if (!encrypt)
        fc |= CPACF_DECRYPT;

    return fc;
}

/**
 * Performs an aes-ecb operation on the given data, using a protected key
 * via the KM-encrypted-AES instruction. The protected key must be
 * available in the key template as CKA_IBM_OPAQUE_PKEY.
 */
CK_RV pkey_aes_ecb(OBJECT *key_obj, CK_BYTE *in_data,
                   CK_ULONG in_data_len, CK_BYTE *out_data,
                   CK_ULONG_PTR p_output_data_len, CK_BYTE encrypt)
{
    CK_RV ret;
    unsigned long fc;
    CK_ATTRIBUTE *pkey_attr = NULL;
    CK_ULONG clear_keylen;
    struct __attribute__((packed)){
        uint8_t key[MAXPROTKEYSIZE];
    } param;
    int bytes_processed = 0;

    /* Check parms */
    if (in_data_len == 0) {
        ret = CKR_OK;
        goto done;
    }

    /* Handle implicit length_only parm (not passed down) */
    if (!out_data) {
        *p_output_data_len = in_data_len;
        ret = CKR_OK;
        goto done;
    }

    /* Get protected key from key object */
    if (template_attribute_get_non_empty(key_obj->template, CKA_IBM_OPAQUE_PKEY,
                                         &pkey_attr) != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE_PKEY in key's template.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Determine clear key length */
    if (template_attribute_get_ulong(key_obj->template, CKA_VALUE_LEN,
                                     &clear_keylen) != CKR_OK) {
        TRACE_ERROR("There is no CKA_VALUE_LEN, cannot determine clear keylen.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Set function code */
    fc = get_function_code(clear_keylen, encrypt);
    if (fc == 0) {
        TRACE_ERROR("Could not determine CPACF fc for given keylen %ld\n",
                    clear_keylen);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Call CPACF */
    memcpy(param.key, pkey_attr->pValue, pkey_attr->ulValueLen);
    bytes_processed = s390_km(fc, &param, out_data, in_data, in_data_len);
    if (bytes_processed <= 0) {
        TRACE_ERROR("CPACF error: s390_km returned %i\n", bytes_processed);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    *p_output_data_len = bytes_processed;
    ret = CKR_OK;

done:

    return ret;
}

/**
 * Performs an AES-CBC operation via CPACF using a protected key.
 */
CK_RV pkey_aes_cbc(OBJECT *key_obj, CK_BYTE *iv,
                   CK_BYTE *in_data, CK_ULONG in_data_len, CK_BYTE *out_data,
                   CK_ULONG_PTR p_output_data_len, CK_BYTE encrypt)
{
    CK_RV ret;
    unsigned long fc;
    CK_ATTRIBUTE *pkey_attr = NULL;
    CK_ULONG clear_keylen;
    struct __attribute__((packed)){
        uint8_t iv[16];
        uint8_t key[MAXPROTKEYSIZE];
    } param;
    int bytes_processed = 0;

    /* Check parms */
    if (in_data_len == 0) {
        ret = CKR_OK;
        goto done;
    }

    /* Handle implicit length_only parm (not passed down) */
    if (!out_data) {
        *p_output_data_len = in_data_len;
        ret = CKR_OK;
        goto done;
    }

    /* Get protected key from key object */
    if (template_attribute_get_non_empty(key_obj->template, CKA_IBM_OPAQUE_PKEY,
                                         &pkey_attr) != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE_PKEY in key's template.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Determine clear key length */
    if (template_attribute_get_ulong(key_obj->template, CKA_VALUE_LEN,
                                     &clear_keylen) != CKR_OK) {
        TRACE_ERROR("Cannot determine clear key len.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Set function code */
    fc = get_function_code(clear_keylen, encrypt);
    if (fc == 0) {
        TRACE_ERROR("Could not determine CPACF fc for given keylen %ld\n",
                    clear_keylen);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Call CPACF */
    memcpy(param.iv, iv, 16);
    memcpy(param.key, pkey_attr->pValue, pkey_attr->ulValueLen);
    bytes_processed = s390_kmc(fc, &param, out_data, in_data, in_data_len);
    if (bytes_processed <= 0) {
        TRACE_ERROR("CPACF error: s390_kmc returned %i\n", bytes_processed);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    *p_output_data_len = bytes_processed;
    memcpy(iv, param.iv, AES_BLOCK_SIZE);
    ret = CKR_OK;

done:

    return ret;
}

#define PARM_BLOCK_SIZE 8192

typedef unsigned char parm_block_t[PARM_BLOCK_SIZE];

struct parm_block_lookup {
    unsigned int block_size;
    unsigned char *base;
    uint8_t       *ml;
    unsigned char *message;
    unsigned char *iv;
    unsigned char *keys;
};

static inline void parm_block_lookup_init(struct parm_block_lookup *lookup,
                                          parm_block_t base,
                                          unsigned int block_size)
{
    lookup->block_size = block_size;
    lookup->base       = base;
    lookup->ml         = (uint8_t *)base;
    lookup->message    = (unsigned char *)(base + 8);
    lookup->iv         = (unsigned char *)(lookup->message + block_size);
    lookup->keys       = (unsigned char *)(lookup->iv + block_size);
}

/**
 * Calculates an AES-CMAC via CPACF using a protected key.
 */
CK_RV pkey_aes_cmac(OBJECT *key_obj, CK_BYTE *message,
                    CK_ULONG message_len, CK_BYTE *cmac, CK_BYTE *iv)
{
    CK_RV ret;
    parm_block_t parm_block;
    unsigned long fc;
    struct parm_block_lookup pb_lookup;
    unsigned int length_tail;
    unsigned long length_head;
    CK_ULONG clear_keylen;
    CK_ATTRIBUTE *pkey_attr = NULL;
    int rc;

    /* Determine clear key length */
    if (template_attribute_get_ulong(key_obj->template, CKA_VALUE_LEN,
                                     &clear_keylen) != CKR_OK) {
        TRACE_ERROR("No CKA_VALUE_LEN given, cannot determine clear key length\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Set function code */
    fc = get_function_code(clear_keylen, CPACF_DECRYPT);
    if (fc == 0) {
        TRACE_ERROR("Could not determine CPACF fc for given keylen %ld\n",
                    clear_keylen);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Get protected key from key object */
    if (template_attribute_get_non_empty(key_obj->template, CKA_IBM_OPAQUE_PKEY,
                                         &pkey_attr) != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE_PKEY in key's template.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Setup parm block */
    memset(parm_block, 0, sizeof(parm_block));
    parm_block_lookup_init(&pb_lookup, parm_block, AES_BLOCK_SIZE);
    memcpy(pb_lookup.keys, pkey_attr->pValue, pkey_attr->ulValueLen);

    /* copy iv into param block, if available (intermediate) */
    if (iv != NULL)
        memcpy(pb_lookup.iv, iv, pb_lookup.block_size);

    if (cmac == NULL) {
        /* intermediate */
        rc = s390_kmac(fc, pb_lookup.iv, message, message_len);
        memset(pb_lookup.keys, 0, pkey_attr->ulValueLen);
        if (rc < 0) {
            ret = CKR_FUNCTION_FAILED;
            goto done;
        }

        /* rescue iv for chained calls (intermediate) */
        memcpy(iv, pb_lookup.iv, pb_lookup.block_size);
    } else {
        if (message_len) {
            length_tail = message_len % pb_lookup.block_size;
            if (length_tail)
                length_head = message_len - length_tail;
            else {
                length_head = message_len - pb_lookup.block_size;
                length_tail = pb_lookup.block_size;
            }

            if (length_head) {
                rc = s390_kmac(fc, pb_lookup.iv,
                           message, length_head);
                if (rc < 0) {
                    memset(pb_lookup.keys, 0, pkey_attr->ulValueLen);
                    ret = CKR_FUNCTION_FAILED;
                    goto done;
                }
            }

            *pb_lookup.ml = length_tail * 8; /* message length in bits */
            memcpy(pb_lookup.message, message + length_head, length_tail);
        }
        /* calculate final block (last/full) */
        rc = s390_pcc(fc, pb_lookup.base);
        memset(pb_lookup.keys, 0, pkey_attr->ulValueLen);
        if (rc < 0) {
            ret = CKR_FUNCTION_FAILED;
            goto done;
        }
        if (cmac)
            memcpy(cmac, pb_lookup.iv, AES_BLOCK_SIZE);
    }

    ret = CKR_OK;

done:

    return ret;
}
