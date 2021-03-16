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


static const CK_BYTE p256[] = OCK_PRIME256V1;
static const CK_BYTE p384[] = OCK_SECP384R1;
static const CK_BYTE p521[] = OCK_SECP521R1;
static const CK_BYTE ed25519[] = OCK_ED25519;
static const CK_BYTE ed448[] = OCK_ED448;

#if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
# if __GLIBC_PREREQ(2, 16)
#  include <sys/auxv.h>
#  if defined(HWCAP_S390_STFLE) && defined(HWCAP_S390_VX)
#   define IMPLEMENT_GETAUXVAL
#  endif
# endif
#endif

/**
 * s390_stfle:
 *
 * Executes the STFLE operation of the CPU.
 *
 * Returns the no. of double words needed to store the facility bits.
 */
static inline int s390_stfle(unsigned long long *list, int doublewords)
{
    register unsigned long __nr __asm__("0") = doublewords - 1;

    __asm__ volatile(".insn s,0xb2b00000,0(%1)" /* stfle */
             : "+d" (__nr) : "a" (list) : "memory", "cc");

    return __nr + 1;
}

/**
 * Determine the machine's MSA level.
 */
int get_msa_level(void)
{
#ifdef IMPLEMENT_GETAUXVAL
    unsigned long long facility_bits[3];
    int msa = 0;
    int num = 0;
    const unsigned long hwcap = getauxval(AT_HWCAP);

    if (hwcap & HWCAP_S390_STFLE) {
        memset(facility_bits, 0, sizeof(facility_bits));
        num = s390_stfle(facility_bits, 3);

        /* s390_stfle always returns the no. of double words needed to store the
         * facility bits. This quantity is machine dependent. With MSA8, we
         * need the first three double words. */
        if (num >= 2) {
            if(facility_bits[0] & (1ULL << (63 - 17)))
                msa = 1;
            if(facility_bits[1] & (1ULL << (127 - 76)))
                msa = 3;
            if(facility_bits[1] & (1ULL << (127 - 77)))
                msa = 4;
            if(facility_bits[0] & (1ULL << (63 - 57)))
                msa = 5;
            if (facility_bits[2] & (1ULL << (191 - 146)))
                msa = 8;
            if (facility_bits[2] & (1ULL << (191 - 155)))
                msa = 9;
        }
    }

    return msa;
#endif
    return 0;
}

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
 * s390_kdsa:
 * @func: the function code passed to KDSA; see s390_kdsa_functions
 * @param: address of parameter block; see POP for details on each func
 * @src: address of source memory area
 * @srclen: length of src operand in bytes
 *
 * Executes the KDSA (COMPUTE DIGITAL SIGNATURE AUTHENTICATION) operation of
 * the CPU.
 *
 * Returns 0 on success. Fails in case of sign if the random number was not
 * invertible. Fails in case of verify if the signature is invalid or the
 * public key is not on the curve.
 */
static int s390_kdsa(unsigned long func, void *param,
                    const unsigned char *src, unsigned long srclen)
{
    register unsigned long r0 __asm__("0") = (unsigned long)func;
    register unsigned long r1 __asm__("1") = (unsigned long)param;
    register unsigned long r2 __asm__("2") = (unsigned long)src;
    register unsigned long r3 __asm__("3") = (unsigned long)srclen;
    unsigned long rc = 1;

    __asm__ volatile(
        "0: .insn   rre,%[__opc] << 16,0,%[__src]\n"
        "   brc 1,0b\n" /* handle partial completion */
        "   brc 7,1f\n"
        "   lghi    %[__rc],0\n"
        "1:\n"
        : [__src] "+a" (r2), [__srclen] "+d" (r3), [__rc] "+d" (rc)
        : [__fc] "d" (r0), [__param] "a" (r1), [__opc] "i" (0xb93a)
        : "cc", "memory");

    return (int)rc;
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

static inline void s390_flip_endian_32(void *dest, const void *src)
{
    __asm__ volatile(
        "   lrvg    %%r0,0(%[__src])\n"
        "   lrvg    %%r1,8(%[__src])\n"
        "   lrvg    %%r4,16(%[__src])\n"
        "   lrvg    %%r5,24(%[__src])\n"
        "   stg %%r0,24(%[__dest])\n"
        "   stg %%r1,16(%[__dest])\n"
        "   stg %%r4,8(%[__dest])\n"
        "   stg %%r5,0(%[__dest])\n"
        :
        : [__dest] "a" (dest), [__src] "a" (src)
        : "memory", "%r0", "%r1", "%r4", "%r5");
}

static inline void s390_flip_endian_64(void *dest, const void *src)
{
    __asm__ volatile(
        "   lrvg    %%r0,0(%[__src])\n"
        "   lrvg    %%r1,8(%[__src])\n"
        "   lrvg    %%r4,16(%[__src])\n"
        "   lrvg    %%r5,24(%[__src])\n"
        "   lrvg    %%r6,32(%[__src])\n"
        "   lrvg    %%r7,40(%[__src])\n"
        "   lrvg    %%r8,48(%[__src])\n"
        "   lrvg    %%r9,56(%[__src])\n"
        "   stg %%r0,56(%[__dest])\n"
        "   stg %%r1,48(%[__dest])\n"
        "   stg %%r4,40(%[__dest])\n"
        "   stg %%r5,32(%[__dest])\n"
        "   stg %%r6,24(%[__dest])\n"
        "   stg %%r7,16(%[__dest])\n"
        "   stg %%r8,8(%[__dest])\n"
        "   stg %%r9,0(%[__dest])\n"
        :
        : [__dest] "a" (dest), [__src] "a" (src)
        : "memory", "%r0", "%r1", "%r4", "%r5",
                "%r6", "%r7", "%r8", "%r9");
}

/**
 * Return true if the given template indicates an EC public key,
 * false otherwise.
 */
CK_BBOOL pkey_is_ec_public_key(TEMPLATE *tmpl)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_ULONG class;

    if (template_attribute_get_ulong(tmpl, CKA_CLASS, &class) != CKR_OK)
        return CK_FALSE;

    if (class == CKO_PUBLIC_KEY) {
        if (template_attribute_get_non_empty(tmpl, CKA_ECDSA_PARAMS, &attr) == CKR_OK)
            return CK_TRUE;
        else
            return CK_FALSE;
    }

    return CK_FALSE;
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
 * Returns true if the elliptic curve implied by the given key_obj
 * is supported by CPACF, false otherwise.
 */
CK_BBOOL pkey_op_ec_curve_supported_by_cpacf(TEMPLATE *tmpl)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE *ec_params;

    if (template_attribute_get_non_empty(tmpl, CKA_ECDSA_PARAMS, &attr) != CKR_OK) {
        TRACE_ERROR("%s: No CKA_ECDSA_PARAMS found in template, cannot determine curve\n",
                    __func__);
        return CK_FALSE;
    }

    ec_params = (CK_BYTE *) attr->pValue;

    if (memcmp(ec_params, p256, sizeof(p256)) == 0 ||
        memcmp(ec_params, p384, sizeof(p384)) == 0 ||
        memcmp(ec_params, p521, sizeof(p521)) == 0 ||
        memcmp(ec_params, ed25519, sizeof(ed25519)) == 0 ||
        memcmp(ec_params, ed448, sizeof(ed448)) == 0) {
        return CK_TRUE;
    }

    return CK_FALSE;
}

/**
 * Returns true if the protected key operation implied by the given mechanism
 * is supported by CPACF, false otherwise.
 */
CK_BBOOL pkey_op_supported_by_cpacf(int msa_level, CK_MECHANISM_TYPE type,
                                    TEMPLATE *tmpl)
{
    switch (type) {
    case CKM_AES_ECB:
    case CKM_AES_CBC:
    case CKM_AES_CBC_PAD:
    case CKM_AES_CMAC_GENERAL:
    case CKM_AES_CMAC:
        if (msa_level > 1)
            return CK_TRUE;
        break;
    case CKM_ECDSA:
    case CKM_ECDSA_SHA1:
    case CKM_ECDSA_SHA224:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
    case CKM_ECDSA_SHA512:
    case CKM_IBM_ED25519_SHA512:
    case CKM_IBM_ED448_SHA3:
        if (msa_level > 8)
            return pkey_op_ec_curve_supported_by_cpacf(tmpl);
        break;
    default:
        break;
    }

    return CK_FALSE;
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

/**
 * Determine the CPACF curve type from given template.
 */
cpacf_curve_type_t get_cpacf_curve_type(TEMPLATE *tmpl)
{
    CK_BYTE *ec_params;
    CK_ATTRIBUTE *attr = NULL;
    cpacf_curve_type_t curve_type;

    /* Determine CKA_EC_PARAMS */
    if (template_attribute_get_non_empty(tmpl, CKA_EC_PARAMS, &attr) != CKR_OK) {
        TRACE_ERROR("%s: This template does not have CKA_EC_PARAMS, cannot determine curve type.\n",
                    __func__);
        curve_type = curve_invalid;
        goto done;
    }
    ec_params = (CK_BYTE *) attr->pValue;

    if (memcmp(ec_params, p256, sizeof(p256)) == 0)
        curve_type = curve_p256;
    else if (memcmp(ec_params, p384, sizeof(p384)) == 0)
        curve_type = curve_p384;
    else if (memcmp(ec_params, p521, sizeof(p521)) == 0)
        curve_type = curve_p521;
    else if (memcmp(ec_params, ed25519, sizeof(ed25519)) == 0)
        curve_type = curve_ed25519;
    else if (memcmp(ec_params, ed448, sizeof(ed448)) == 0)
        curve_type = curve_ed448;
    else
        curve_type = curve_invalid;

done:

    return curve_type;
}

/**
 * Sign the given hash via CPACF using the given protected private key.
 */
CK_RV pkey_ec_sign(OBJECT *privkey, CK_BYTE *hash, CK_ULONG hash_len,
                   CK_BYTE *sig, CK_ULONG *sig_len,
                   void (*rng_cb)(unsigned char *, size_t))
{
#define DEF_PARAM(curve, size)        \
    struct {                          \
        unsigned char sig_r[size];    \
        unsigned char sig_s[size];    \
        unsigned char hash[size];     \
        unsigned char priv[size];     \
        unsigned char rand[size];     \
        unsigned char vp[32];         \
        short c;                      \
        short res;                    \
    } curve

    union {
        long long buff[512]; /* 4k buffer: params + reserved area */
        DEF_PARAM(P256, 32);
        DEF_PARAM(P384, 48);
        DEF_PARAM(P521, 80);
    } param;
#undef DEF_PARAM

    CK_RV ret;
    unsigned long fc;
    CK_ATTRIBUTE *pkey_attr = NULL;
    int rc, off;
    cpacf_curve_type_t curve_type;

    /* Get protected key from key object */
    if (template_attribute_get_non_empty(privkey->template, CKA_IBM_OPAQUE_PKEY,
                                         &pkey_attr) != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE_PKEY in key's template.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Setup CPACF parmblock */
    memset(&param, 0, sizeof(param));
    curve_type = get_cpacf_curve_type(privkey->template);
    switch (curve_type) {
    case curve_p256:
        if (hash_len > 32)
            hash_len = 32;
        off = 32 - hash_len;
        memcpy(param.P256.hash + off, hash, hash_len);
        memcpy(param.P256.priv, pkey_attr->pValue, 32);
        memcpy(param.P256.vp, (char *)pkey_attr->pValue + 32, 32);
        *sig_len = 2 * 32;
        break;
    case curve_p384:
        if (hash_len > 48)
            hash_len = 48;
        off = 48 - hash_len;
        memcpy(param.P384.hash + off, hash, hash_len);
        memcpy(param.P384.priv, pkey_attr->pValue, 48);
        memcpy(param.P384.vp, (char *)pkey_attr->pValue + 48, 32);
        *sig_len = 2 * 48;
        break;
    case curve_p521:
        if (hash_len > 66)
            hash_len = 66;
        /* Note that the pkey for p521 has 80 + 32 bytes. */
        off = 80 - hash_len;
        memcpy(param.P521.hash + off, hash, hash_len);
        memcpy(param.P521.priv, pkey_attr->pValue, pkey_attr->ulValueLen - 32);
        memcpy(param.P521.vp, (char *)pkey_attr->pValue + pkey_attr->ulValueLen - 32, 32);
        *sig_len = 2 * 66;
        break;
    default:
        TRACE_ERROR("Could not determine the curve type.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (sig == NULL) {
        /* length_only requested, just return with *sig_len */
        ret = CKR_OK;
        goto done;
    }

    /* Set random number and function code */
    switch (curve_type) {
    case curve_p256:
        fc = KDSA_ENCRYPTED_ECDSA_SIGN_P256 | 0x80;
        if (rng_cb != NULL) {
            rng_cb(param.P256.rand, sizeof(param.P256.rand));
            fc = KDSA_ENCRYPTED_ECDSA_SIGN_P256;
        }
        break;
    case curve_p384:
        fc = KDSA_ENCRYPTED_ECDSA_SIGN_P384 | 0x80;
        if (rng_cb != NULL) {
            rng_cb(param.P384.rand, sizeof(param.P384.rand));
            fc = KDSA_ENCRYPTED_ECDSA_SIGN_P384;
        }
        break;
    case curve_p521:
        fc = KDSA_ENCRYPTED_ECDSA_SIGN_P521 | 0x80;
        if (rng_cb != NULL) {
            rng_cb(param.P521.rand, sizeof(param.P521.rand));
            fc = KDSA_ENCRYPTED_ECDSA_SIGN_P521;
        }
        break;
    default:
        TRACE_ERROR("Could not determine the curve type.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Call CPACF */
    rc = s390_kdsa(fc, param.buff, NULL, 0);
    switch (rc) {
    case 0:
        ret = CKR_OK;
        break;
    case 1:
        switch (curve_type) {
        case curve_p256:
            TRACE_ERROR("%s rc from KDSA = 1 and C = %02X.\n",
                        __func__, param.P256.c);
            break;
        case curve_p384:
            TRACE_ERROR("%s rc from KDSA = 1 and C = %02X.\n",
                        __func__, param.P384.c);
            break;
        case curve_p521:
            TRACE_ERROR("%s rc from KDSA = 1 and C = %02X.\n",
                        __func__, param.P521.c);
            break;
        default:
            break;
        }
        ret = CKR_FUNCTION_FAILED;
        goto done;
        break;
    default: /* rc = 2 */
        TRACE_ERROR("%s rc from KDSA = 2\n", __func__);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Provide signature to caller */
    switch (curve_type) {
    case curve_p256:
    case curve_p384:
        /* r and s are consecutive in the param block */
        memcpy(sig, param.buff, *sig_len);
        break;
    case curve_p521:
        /* r and s are both righ-aligned in the param block */
        memcpy(sig, param.P521.sig_r + 14, 66);
        memcpy(sig + 66, param.P521.sig_s + 14, 66);
        break;
    default:
        TRACE_ERROR("Could not determine the curve type.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }
    OPENSSL_cleanse(&param, sizeof(param));

    ret = CKR_OK;

done:

    return ret;
}

/**
 * Sign the given input message via CPACF using the given protected private key.
 * This routine only supports the two IBM specific Edwards curves ED25519 and
 * ED448.
 * Note: The original input message is passed to CPACF without being
 * pre-hashed. Hashing is done internally in CPACF.
 */
CK_RV pkey_ibm_ed_sign(OBJECT *privkey, CK_BYTE *msg, CK_ULONG msg_len,
                       CK_BYTE *sig, CK_ULONG *sig_len)
{
#define DEF_EDPARAM(curve, size)      \
    struct {                          \
        unsigned char sig_r[size];    \
        unsigned char sig_s[size];    \
        unsigned char priv[size];     \
        unsigned char vp[32];         \
        unsigned char res1[16];       \
        short c;                      \
        short res2;                   \
    } curve

    union {
        long long buff[512]; /* 4k buffer: params + reserved area */
        DEF_EDPARAM(ED25519, 32);
        DEF_EDPARAM(ED448, 64);
    } edparam;
#undef DEF_EDPARAM

    CK_RV ret;
    unsigned long fc;
    CK_ATTRIBUTE *pkey_attr = NULL;
    int rc;
    cpacf_curve_type_t curve_type;

    /* Get protected key from key object */
    if (template_attribute_get_non_empty(privkey->template, CKA_IBM_OPAQUE_PKEY,
                                         &pkey_attr) != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_OPAQUE_PKEY in key's template.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Setup CPACF parmblock */
    memset(&edparam, 0, sizeof(edparam));
    curve_type = get_cpacf_curve_type(privkey->template);
    switch (curve_type) {
    case curve_ed25519:
        fc = KDSA_ENCRYPTED_EDDSA_SIGN_ED25519;
        memcpy(edparam.ED25519.priv, pkey_attr->pValue, 32);
        memcpy(edparam.ED25519.vp, (char *)pkey_attr->pValue + 32, 32);
        *sig_len = 2 * 32;
        break;
    case curve_ed448:
        fc = KDSA_ENCRYPTED_EDDSA_SIGN_ED448;
        memcpy(edparam.ED448.priv, pkey_attr->pValue, 64);
        memcpy(edparam.ED448.vp, (char *)pkey_attr->pValue + 64, 32);
        *sig_len = 2 * 57;
        break;
    default:
        TRACE_ERROR("Could not determine the curve type.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (sig == NULL) {
        /* length_only requested, just return with *sig_len */
        ret = CKR_OK;
        goto done;
    }

    /* Call CPACF */
    rc = s390_kdsa(fc, edparam.buff, msg, msg_len);
    switch (rc) {
    case 0:
        ret = CKR_OK;
        break;
    case 1:
        switch (curve_type) {
        case curve_ed25519:
            TRACE_ERROR("%s rc from KDSA = 1 and C = %02X.\n",
                        __func__, edparam.ED25519.c);
            break;
        case curve_ed448:
            TRACE_ERROR("%s rc from KDSA = 1 and C = %02X.\n",
                        __func__, edparam.ED448.c);
            break;
        default:
            break;
        }
        ret = CKR_FUNCTION_FAILED;
        goto done;
        break;
    default: /* rc = 2 */
        TRACE_ERROR("%s rc from KDSA = 2\n", __func__);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Provide signature to caller */
    switch (curve_type) {
    case curve_ed25519:
        /* r and s are consecutive in the param block */
        s390_flip_endian_32(sig, edparam.ED25519.sig_r);
        s390_flip_endian_32(sig + 32, edparam.ED25519.sig_s);
        break;
    case curve_ed448:
        /* r and s are right aligned in the param block */
        s390_flip_endian_64(edparam.ED448.sig_r, edparam.ED448.sig_r);
        s390_flip_endian_64(edparam.ED448.sig_s, edparam.ED448.sig_s);
        memcpy(sig, edparam.ED448.sig_r, 57);
        memcpy(sig + 57, edparam.ED448.sig_s, 57);
        break;
    default:
        TRACE_ERROR("Could not determine the curve type.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }
    OPENSSL_cleanse(&edparam, sizeof(edparam));

    ret = CKR_OK;

done:

    return ret;
}

/**
 * Verify the given signature via CPACF using the given public key.
 */
CK_RV pkey_ec_verify(OBJECT *pubkey, CK_BYTE *hash, CK_ULONG hash_len,
                     CK_BYTE *sig, CK_ULONG sig_len)
{
#define DEF_PARAM(curve, size)    \
struct {                          \
    unsigned char sig_r[size];    \
    unsigned char sig_s[size];    \
    unsigned char hash[size];     \
    unsigned char pub_x[size];    \
    unsigned char pub_y[size];    \
} curve

    union {
        long long buff[512]; /* 4k buffer: params + reserved area */
        DEF_PARAM(P256, 32);
        DEF_PARAM(P384, 48);
        DEF_PARAM(P521, 80);
    } param;
#undef DEF_PARAM

    CK_RV ret;
    unsigned long fc;
    CK_ATTRIBUTE *pub_attr = NULL;
    int rc, hash_off, key_off;
    CK_BYTE *ecpoint;
    CK_ULONG ecpoint_len, field_len;
    cpacf_curve_type_t curve_type;

    /* Get public key from template */
    if (template_attribute_get_non_empty(pubkey->template, CKA_EC_POINT,
                                         &pub_attr) != CKR_OK) {
        TRACE_ERROR("%s: This public key does not have a CKA_EC_POINT.\n",
                    __func__);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* CKA_EC_POINT is an BER encoded OCTET STRING. Extract it. */
    rc = ber_decode_OCTET_STRING(pub_attr->pValue, &ecpoint,
                                 &ecpoint_len, &field_len);
    if (rc != CKR_OK || pub_attr->ulValueLen != field_len) {
        TRACE_ERROR("%s: ber_decode_OCTET_STRING failed\n", __func__);
        ret = CKR_ATTRIBUTE_VALUE_INVALID;
        goto done;
    }

    /* Uncompressed EC keys have both (x,y) values and begin with 0x04 */
    if (ecpoint[0] != 0x04) {
        TRACE_ERROR("%s: EC_POINT is compressed, not supported here.\n",
                    __func__);
        ret = CKR_ATTRIBUTE_VALUE_INVALID;
        goto done;
    }
    ecpoint++;
    ecpoint_len--;

    /* Setup parmblock and function code */
    memset(&param, 0, sizeof(param));
    curve_type = get_cpacf_curve_type(pubkey->template);
    switch (curve_type) {
    case curve_p256:
        if (hash_len > sig_len / 2)
            hash_len = sig_len / 2;
        fc = KDSA_ECDSA_VERIFY_P256;
        hash_off = 32 - hash_len;
        memcpy(param.P256.sig_r, sig, sig_len);
        memcpy(param.P256.hash + hash_off, hash, hash_len);
        memcpy(param.P256.pub_x, ecpoint, ecpoint_len);
        break;
    case curve_p384:
        if (hash_len > sig_len / 2)
            hash_len = sig_len / 2;
        fc = KDSA_ECDSA_VERIFY_P384;
        hash_off = 48 - hash_len;
        memcpy(param.P384.sig_r, sig, sig_len);
        memcpy(param.P384.hash + hash_off, hash, hash_len);
        memcpy(param.P384.pub_x, ecpoint, ecpoint_len);
        break;
    case curve_p521:
        if (hash_len > sig_len / 2)
            hash_len = sig_len / 2;
        fc = KDSA_ECDSA_VERIFY_P521;
        /* Note that the pkey for p521 has 80 + 32 bytes. */
        hash_off = 80 - hash_len;
        key_off = 80 - (sig_len / 2);
        memcpy(param.P521.sig_r + key_off, sig, sig_len / 2);
        memcpy(param.P521.sig_s + key_off, sig + (sig_len / 2), sig_len / 2);
        memcpy(param.P521.hash + hash_off, hash, hash_len);
        memcpy(param.P521.pub_x + key_off, ecpoint, sig_len / 2);
        memcpy(param.P521.pub_y + key_off, ecpoint + (sig_len / 2), sig_len / 2);
        break;
    default:
        TRACE_ERROR("Could not determine the curve type.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Call CPACF */
    rc = s390_kdsa(fc, param.buff, NULL, 0);
    switch (rc) {
    case 0:
        /* signature verified successfully */
        ret = CKR_OK;
        break;
    default:
        ret = CKR_SIGNATURE_INVALID;
        break;
    }

done:

    return ret;
}

/**
 * Verify the given signature via CPACF using the given public key.
 * This routine only supports the two IBM specific Edwards curves ED25519 and
 * ED448.
 * Note: The original input message is passed to CPACF without being
 * pre-hashed. Hashing is done internally in CPACF.
 */
CK_RV pkey_ibm_ed_verify(OBJECT *pubkey, CK_BYTE *msg, CK_ULONG msg_len,
                         CK_BYTE *sig, CK_ULONG sig_len)
{
#define DEF_EDPARAM(curve, size)    \
struct {                            \
    unsigned char sig_r[size];      \
    unsigned char sig_s[size];      \
    unsigned char pub[size];        \
} curve

    union {
        long long buff[512]; /* 4k buffer: params + reserved area */
        DEF_EDPARAM(ED25519, 32);
        DEF_EDPARAM(ED448, 64);
    } edparam;
#undef DEF_EDPARAM

    CK_RV ret;
    unsigned long fc;
    CK_ATTRIBUTE *pub_attr = NULL;
    int rc;
    CK_BYTE *ecpoint;
    CK_ULONG ecpoint_len, field_len;
    cpacf_curve_type_t curve_type;

    /* Get public key from template */
    if (template_attribute_get_non_empty(pubkey->template, CKA_EC_POINT, 
                                         &pub_attr) != CKR_OK) {
        TRACE_ERROR("%s: This public key does not have a CKA_EC_POINT.\n",
                    __func__);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* CKA_EC_POINT is an BER encoded OCTET STRING. Extract it. */
    rc = ber_decode_OCTET_STRING(pub_attr->pValue, &ecpoint,
                                 &ecpoint_len, &field_len);
    if (rc != CKR_OK || pub_attr->ulValueLen != field_len) {
        TRACE_ERROR("%s: ber_decode_OCTET_STRING failed\n", __func__);
        ret = CKR_ATTRIBUTE_VALUE_INVALID;
        goto done;
    }

    /* Setup parmblock and function code */
    memset(&edparam, 0, sizeof(edparam));
    curve_type = get_cpacf_curve_type(pubkey->template);
    switch (curve_type) {
    case curve_ed25519:
        fc = KDSA_EDDSA_VERIFY_ED25519;
        s390_flip_endian_32(edparam.ED25519.sig_r, sig);
        s390_flip_endian_32(edparam.ED25519.sig_s, sig + (sig_len / 2));
        s390_flip_endian_32(edparam.ED25519.pub, ecpoint);
        break;
    case curve_ed448:
        fc = KDSA_EDDSA_VERIFY_ED448;
        memcpy(edparam.ED448.sig_r, sig, sig_len / 2);
        memcpy(edparam.ED448.sig_s, sig + (sig_len / 2), sig_len / 2);
        memcpy(edparam.ED448.pub, ecpoint, ecpoint_len);
        s390_flip_endian_64(edparam.ED448.sig_r, edparam.ED448.sig_r);
        s390_flip_endian_64(edparam.ED448.sig_s, edparam.ED448.sig_s);
        s390_flip_endian_64(edparam.ED448.pub, edparam.ED448.pub);
        break;
    default:
        TRACE_ERROR("Could not determine the curve type.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Call CPACF */
    switch (curve_type) {
    case curve_ed25519:
        rc = s390_kdsa(fc, edparam.buff, msg, msg_len);
        break;
    case curve_ed448:
        rc = s390_kdsa(fc, edparam.buff, msg, msg_len);
        if (sig[113] != 0) {
            /* KDSA doesn't check last byte */
            rc = 1;
        }
        break;
    default:
        TRACE_ERROR("Could not determine the curve type.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    switch (rc) {
    case 0:
        /* signature verified successfully */
        ret = CKR_OK;
        break;
    default:
        ret = CKR_SIGNATURE_INVALID;
        break;
    }

done:

    return ret;
}
