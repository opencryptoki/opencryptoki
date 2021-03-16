/*
 * COPYRIGHT (c) International Business Machines Corp. 2020
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef PKEY_UTILS_H
#define PKEY_UTILS_H

#include "pkcs11types.h"
#include "ec_curves.h"

/**
 * the pkey kernel module
 */
#define PKEYDEVICE "/dev/pkey"

/**
 * Modifier bit for CPACF instructions.
 */
#define CPACF_ENCRYPT         0x00
#define CPACF_DECRYPT         0x80

/**
 * function codes for the KM/KMC/KMAC instruction.
 */
#define ENCRYPTED_AES_128     0x1a
#define ENCRYPTED_AES_192     0x1b
#define ENCRYPTED_AES_256     0x1c

/**
 * function codes for the KDSA instruction.
 */
#define KDSA_ECDSA_VERIFY_P256                0x01
#define KDSA_ECDSA_VERIFY_P384                0x02
#define KDSA_ECDSA_VERIFY_P521                0x03

#define KDSA_ENCRYPTED_ECDSA_SIGN_P256        0x11
#define KDSA_ENCRYPTED_ECDSA_SIGN_P384        0x12
#define KDSA_ENCRYPTED_ECDSA_SIGN_P521        0x13

/**
 * EP11 blob header as defined in linux/drivers/s390/crypto/zcrypt_ep11misc.h
 */
#define TOKTYPE_NON_CCA      0x00
#define TOKVER_EP11_AES      0x03
typedef struct {
    uint8_t  type;      /* 0x00 (TOKTYPE_NON_CCA) */
    uint8_t  res0;      /* unused */
    uint16_t len;       /* total length in bytes of this blob */
    uint8_t  version;   /* 0x06 (TOKVER_EP11_AES) */
    uint8_t  res1;      /* unused */
    uint16_t keybitlen; /* clear key bit len, 0 for unknown */
}  __attribute__ ((packed)) ep11_blob_header;

typedef enum {
    encmode_ecb,
    encmode_cbc
} encmode_t;

typedef enum {
    curve_invalid,
    curve_p256,
    curve_p384,
    curve_p521,
} cpacf_curve_type_t;

int get_msa_level(void);

CK_BBOOL pkey_is_ec_public_key(TEMPLATE *tmpl);

CK_RV pkey_update_and_save(STDLL_TokData_t *tokdata, OBJECT *key_obj,
                           CK_ATTRIBUTE *attr);

CK_BBOOL pkey_op_supported_by_cpacf(int msa_level, CK_MECHANISM_TYPE type,
                                    TEMPLATE *tmpl);

CK_RV pkey_aes_ecb(OBJECT *key, CK_BYTE * in_data,
                   CK_ULONG in_data_len, CK_BYTE * out_data,
                   CK_ULONG_PTR p_output_data_len, CK_BYTE encrypt);

CK_RV pkey_aes_cbc(OBJECT *key, CK_BYTE *iv,
                   CK_BYTE *in_data, CK_ULONG in_data_len,
                   CK_BYTE *out_data, CK_ULONG_PTR p_output_data_len,
                   CK_BYTE encrypt);

CK_RV pkey_aes_cmac(OBJECT *key_obj, CK_BYTE *message,
                    CK_ULONG message_len, CK_BYTE *cmac, CK_BYTE *iv);

CK_RV pkey_ec_sign(OBJECT *privkey, CK_BYTE *hash, CK_ULONG hashlen,
                   CK_BYTE *sig, CK_ULONG *sig_len,
                   void (*rng_cb)(unsigned char *, size_t));

CK_RV pkey_ec_verify(OBJECT *pubkey, CK_BYTE *hash, CK_ULONG hashlen,
                     CK_BYTE *sig, CK_ULONG sig_len);

#endif
