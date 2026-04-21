/*
 * COPYRIGHT (c) International Business Machines Corp. 2026
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * Stub implementations for asn1.c dependencies that are not needed
 * for testing basic BER encoding/decoding functions.
 */

#include <stdlib.h>
#include <string.h>
#include "pkcs11types.h"
#include "defs.h"
#include "pqc_defs.h"

/* Helper function to create a CK_ATTRIBUTE with data */
CK_ATTRIBUTE *create_attribute(CK_ATTRIBUTE_TYPE type, CK_BYTE *data, CK_ULONG data_len)
{
    CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + data_len);
    if (!attr)
        return NULL;

    attr->type = type;
    attr->ulValueLen = data_len;

    if (data_len > 0) {
        attr->pValue = (CK_BYTE *)attr + sizeof(CK_ATTRIBUTE);
        memcpy(attr->pValue, data, data_len);
    } else {
        attr->pValue = NULL;
    }

    return attr;
}

/* Real implementation of build_attribute - needed for RSA key encoding/decoding */
CK_RV build_attribute(CK_ATTRIBUTE_TYPE type, CK_BYTE *data,
                      CK_ULONG data_len, CK_ATTRIBUTE **attr)
{
    CK_ATTRIBUTE *a = NULL;

    a = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + data_len);
    if (!a)
        return CKR_HOST_MEMORY;

    a->type = type;
    a->ulValueLen = data_len;

    if (data_len > 0) {
        a->pValue = (CK_BYTE *)a + sizeof(CK_ATTRIBUTE);
        memcpy(a->pValue, data, data_len);
    } else {
        a->pValue = NULL;
    }

    *attr = a;
    return CKR_OK;
}

/* Real RSA OID constants - needed for RSA key encoding/decoding */
/* AlgorithmIdentifier for RSA: SEQUENCE { OID, NULL } */
const CK_BYTE ber_AlgIdRSAEncryption[] = {
    0x30, 0x0D,  /* SEQUENCE, length 13 */
    0x06, 0x09,  /* OID, length 9 */
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,  /* rsaEncryption OID */
    0x05, 0x00   /* NULL */
};
const CK_ULONG ber_AlgIdRSAEncryptionLen = sizeof(ber_AlgIdRSAEncryption);

/* Just the OID part for comparison */
const CK_BYTE ber_rsaEncryption[] = {
    0x06, 0x09,  /* OID, length 9 */
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01  /* rsaEncryption OID */
};
const CK_ULONG ber_rsaEncryptionLen = sizeof(ber_rsaEncryption);

/* Real DSA OID constant - needed for DSA key encoding/decoding */
const CK_BYTE ber_idDSA[] = {
    0x06, 0x07,  /* OID, length 7 */
    0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01  /* id-dsa OID: 1.2.840.10040.4.1 */
};
const CK_ULONG ber_idDSALen = sizeof(ber_idDSA);

/* Real DH OID constant - needed for DH key encoding/decoding */
const CK_BYTE ber_idDH[] = {
    0x06, 0x07,  /* OID, length 7 */
    0x2A, 0x86, 0x48, 0xCE, 0x3E, 0x02, 0x01  /* dhKeyAgreement OID: 1.2.840.10046.2.1 */
};
const CK_ULONG ber_idDHLen = sizeof(ber_idDH);

/* Real EC OID constants - needed for EC key encoding/decoding */
/* This is the base AlgorithmIdentifier for EC keys WITHOUT the curve parameter */
const CK_BYTE der_AlgIdECBase[] = {
    0x30, 0x09,  /* SEQUENCE, length 9 (will be adjusted by encode function to add curve OID length) */
    0x06, 0x07,  /* OID, length 7 */
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01  /* id-ecPublicKey OID: 1.2.840.10045.2.1 */
    /* Curve OID parameter will be appended by the encode function */
};
const CK_ULONG der_AlgIdECBaseLen = 11;

/* Just the EC algorithm OID for comparison */
const CK_BYTE ber_idEC[] = {
    0x06, 0x07,  /* OID, length 7 */
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01  /* id-ecPublicKey OID: 1.2.840.10045.2.1 */
};
const CK_ULONG ber_idECLen = sizeof(ber_idEC);

const CK_BYTE ber_NULL[] = {0x00};
const CK_ULONG ber_NULLLen = 0;

/* ML-DSA OID constants for testing */
/* ML-DSA-44: 2.16.840.1.101.3.4.3.17 */
const CK_BYTE ber_idML_DSA_44[] = {
    0x06, 0x09,  /* OID, length 9 */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11
};
const CK_ULONG ber_idML_DSA_44Len = sizeof(ber_idML_DSA_44);

/* ML-DSA-65: 2.16.840.1.101.3.4.3.18 */
const CK_BYTE ber_idML_DSA_65[] = {
    0x06, 0x09,  /* OID, length 9 */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12
};
const CK_ULONG ber_idML_DSA_65Len = sizeof(ber_idML_DSA_65);

/* ML-DSA-87: 2.16.840.1.101.3.4.3.19 */
const CK_BYTE ber_idML_DSA_87[] = {
    0x06, 0x09,  /* OID, length 9 */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13
};
const CK_ULONG ber_idML_DSA_87Len = sizeof(ber_idML_DSA_87);

/* ML-KEM OID constants for testing */
/* ML-KEM-512: 2.16.840.1.101.3.4.4.1 */
const CK_BYTE ber_idML_KEM_512[] = {
    0x06, 0x09,  /* OID, length 9 */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01
};
const CK_ULONG ber_idML_KEM_512Len = sizeof(ber_idML_KEM_512);

/* ML-KEM-768: 2.16.840.1.101.3.4.4.2 */
const CK_BYTE ber_idML_KEM_768[] = {
    0x06, 0x09,  /* OID, length 9 */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02
};
const CK_ULONG ber_idML_KEM_768Len = sizeof(ber_idML_KEM_768);

/* ML-KEM-1024: 2.16.840.1.101.3.4.4.3 */
const CK_BYTE ber_idML_KEM_1024[] = {
    0x06, 0x09,  /* OID, length 9 */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03
};
const CK_ULONG ber_idML_KEM_1024Len = sizeof(ber_idML_KEM_1024);

/* PQC OID arrays for ML-DSA and ML-KEM */
const struct pqc_oid ml_dsa_oids[] = {
    {
        .oid = (const CK_BYTE[]){0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11},
        .oid_len = 11,
        .keyform = 44,
        .len_info.ml_dsa = {
            .rho_len = 32,
            .seed_len = 32,
            .tr_len = 64,
            .s1_len = 384,
            .s2_len = 384,
            .t0_len = 1664,
            .t1_len = 1280,
            .priv_seed_len = 32
        }
    },
    {
        .oid = (const CK_BYTE[]){0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12},
        .oid_len = 11,
        .keyform = 65,
        .len_info.ml_dsa = {
            .rho_len = 32,
            .seed_len = 32,
            .tr_len = 64,
            .s1_len = 640,
            .s2_len = 768,
            .t0_len = 2496,
            .t1_len = 1920,
            .priv_seed_len = 32
        }
    },
    {
        .oid = (const CK_BYTE[]){0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13},
        .oid_len = 11,
        .keyform = 87,
        .len_info.ml_dsa = {
            .rho_len = 32,
            .seed_len = 32,
            .tr_len = 64,
            .s1_len = 672,
            .s2_len = 768,
            .t0_len = 3328,
            .t1_len = 2560,
            .priv_seed_len = 32
        }
    },
    { .oid = NULL }
};

const struct pqc_oid ml_kem_oids[] = {
    {
        .oid = (const CK_BYTE[]){0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01},
        .oid_len = 11,
        .keyform = 512,
        .len_info.ml_kem = {
            .sk_len = 1632,
            .pk_len = 800,
            .fs_len = 64,
            .priv_seed_len = 64,
            .pubseed_len = 32
        }
    },
    {
        .oid = (const CK_BYTE[]){0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02},
        .oid_len = 11,
        .keyform = 768,
        .len_info.ml_kem = {
            .sk_len = 2400,
            .pk_len = 1184,
            .fs_len = 64,
            .priv_seed_len = 64,
            .pubseed_len = 32
        }
    },
    {
        .oid = (const CK_BYTE[]){0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03},
        .oid_len = 11,
        .keyform = 1024,
        .len_info.ml_kem = {
            .sk_len = 3168,
            .pk_len = 1568,
            .fs_len = 64,
            .priv_seed_len = 64,
            .pubseed_len = 32
        }
    },
    { .oid = NULL }
};

/* IBM Dilithium OID constants for testing */
const CK_BYTE ber_idDilithium_r2_65[] = {0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x02, 0x82, 0x0B, 0x01, 0x06, 0x05};
const CK_ULONG ber_idDilithium_r2_65Len = sizeof(ber_idDilithium_r2_65);

const struct pqc_oid dilithium_oids[] = {
    {
        .oid = ber_idDilithium_r2_65,
        .oid_len = sizeof(ber_idDilithium_r2_65),
        .keyform = CK_IBM_DILITHIUM_KEYFORM_ROUND2_65,
        .policy_size = 256,
        .policy_siglen = 3366,
        .len_info.ml_dsa = {
            .rho_len = 32,
            .seed_len = 32,
            .tr_len = 48,
            .s1_len = 480,
            .s2_len = 576,
            .t0_len = 2688,
            .t1_len = 1728
        }
    },
    { .oid = NULL }
};

/* IBM Kyber OID constants for testing */
const CK_BYTE ber_idKyber_r2_1024[] = {0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x02, 0x82, 0x0B, 0x05, 0x04, 0x04};
const CK_ULONG ber_idKyber_r2_1024Len = sizeof(ber_idKyber_r2_1024);

const struct pqc_oid kyber_oids[] = {
    {
        .oid = ber_idKyber_r2_1024,
        .oid_len = sizeof(ber_idKyber_r2_1024),
        .keyform = CK_IBM_KYBER_KEYFORM_ROUND2_1024,
        .policy_size = 256,
        .policy_siglen = 0,
        .len_info.ml_kem = {
            .sk_len = 3168,
            .pk_len = 1568,
            .fs_len = 64,
            .pubseed_len = 32
        }
    },
    { .oid = NULL }
};

/* Implementation of find_pqc_by_oid for ML-DSA and ML-KEM tests */
const struct pqc_oid *find_pqc_by_oid(const struct pqc_oid *oids,
                                      const CK_BYTE *oid, CK_ULONG oid_len)
{
    const struct pqc_oid *p;

    if (oids == NULL || oid == NULL || oid_len == 0)
        return NULL;

    for (p = oids; p->oid != NULL; p++) {
        if (p->oid_len == oid_len && memcmp(p->oid, oid, oid_len) == 0)
            return p;
    }

    return NULL;
}
