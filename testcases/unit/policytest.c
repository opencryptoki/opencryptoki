/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
#include "policy.h"
#include "ec_defs.h"
#include "unittest.h"
#include <stdio.h>
#include <stdlib.h>
#include <openssl/obj_mac.h>

#define UNUSED(var)            ((void)(var))

/* Inlined strength definitions */
static const char niststrength[] =
    "version strength-0\n"
    "strength 112 {\n"
    "  MOD_EXP = 2048\n"
    "  ECC = 224\n"
    "  SYMMETRIC = 112\n"
    "  digest = 224\n"
    "  signature = 112\n"
    "}\n"
    "strength 128 {\n"
    "  MOD_EXP = 3072\n"
    "  ECC = 256\n"
    "  SYMMETRIC = 128\n"
    "  digest = 256\n"
    "  signature = 128\n"
    "}\n"
    "strength 192 {\n"
    "  MOD_EXP = 7680\n"
    "  ECC = 384\n"
    "  SYMMETRIC = 192\n"
    "  digest = 384\n"
    "  signature = 192\n"
    "}\n"
    "strength 256 {\n"
    "  MOD_EXP = 15360\n"
    "  ECC = 512\n"
    "  SYMMETRIC = 256\n"
    "  digest = 512\n"
    "  signature = 256\n"
    "}\n";

static const char quantum112[] =
    "version strength-0\n"
    "strength 112 {\n"
    "  SYMMETRIC = 224\n"
    "  digest = 448\n"
    "  signature = 224\n"
    "}\n";

static const char emptystrength[] =
    "version strength-0\n";

/* Inlined policies */
static const char policysecponly[] =
    "version policy-0\n"
    "strength = 0\n"
    "allowedcurves ( SECP224R1, SECP384R1, SECP521R1, SECP256K1 )\n";

static const char policynocurves[] =
    "version policy-0\n"
    "strength = 0\n"
    "allowedcurves ( )\n";

static const char policystrength256[] =
    "version policy-0\n"
    "strength = 256\n";

static const char policystrength192[] =
    "version policy-0\n"
    "strength = 192\n";

static const char policystrength128[] =
    "version policy-0\n"
    "strength = 128\n";

static const char policystrength112[] =
    "version policy-0\n"
    "strength = 112\n";

static const char policyempty[] =
    "version policy-0\n"
    "strength = 0\n";

static const char policynomechs[] =
    "version policy-0\n"
    "strength = 0\n"
    "allowedmechs ()\n";

static const char policyfixedmechs[] =
    "version policy-0\n"
    "strength = 0\n"
    "allowedmechs ( CKM_RSA_PKCS, CKM_ECDSA )\n";

static const char policymgfstandard[] =
    "version policy-0\n"
    "strength = 0\n"
    "allowedmgfs ( CKG_MGF1_SHA1, CKG_MGF1_SHA224, CKG_MGF1_SHA256,\n"
    "CKG_MGF1_SHA384, CKG_MGF1_SHA512 )\n";

static const char policymgfibm[] =
    "version policy-0\n"
    "strength = 0\n"
    "allowedmgfs ( CKG_IBM_MGF1_SHA3_224, CKG_IBM_MGF1_SHA3_256,\n"
    "CKG_IBM_MGF1_SHA3_384, CKG_IBM_MGF1_SHA3_512 )\n";

static const char policymgfoneeach[] =
    "version policy-0\n"
    "strength = 0\n"
    "allowedmgfs ( CKG_MGF1_SHA512, CKG_IBM_MGF1_SHA3_224 )\n";

static const char policymgfnone[] =
    "version policy-0\n"
    "strength = 0\n"
    "allowedmgfs ()\n";

static const char policykdfnosha1[] =
    "version policy-0\n"
    "strength = 0\n"
    "allowedkdfs ( CKD_SHA224_KDF, CKD_SHA256_KDF, CKD_SHA384_KDF,\n"
    "CKD_SHA512_KDF )\n";

static const char policykdfnone[] =
    "version policy-0\n"
    "strength = 0\n"
    "allowedkdfs ()\n";

/* Loading functions (in usr/lib/api/policy.c) */
struct policy_private;
extern void policy_init_policy(struct policy *p);
extern CK_RV policy_load_strength_cfg(struct policy_private *pp,
                                      FILE *fp);
extern CK_RV policy_load_policy_cfg(struct policy_private *pp,
                                    FILE *fp, CK_BBOOL *restricting);
extern struct policy_private *policy_private_alloc(void);
extern struct policy_private *policy_private_free(struct policy_private *pp);
extern void policy_private_deactivate(struct policy_private *pp);

struct keytest {
    CK_ULONG keytype;
    union {
        CK_ULONG value;
        int      nid;
    } strengthattr;
    CK_ULONG sigattr;
    CK_ULONG expstrength;/* Index: 0=256; 1=192; 2=128; 3=112; 4=0 */
    CK_ULONG expsiglen;
    CK_BBOOL expallowed;
    CK_RV    exprc;
};

#define STRENGTH_256 0
#define STRENGTH_192 1
#define STRENGTH_128 2
#define STRENGTH_112 3
#define STRENGTH_0   4

#define NUM_KEYTESTS_STRENGTHDET 4

static const struct strengthdettest {
    const char *definition;
    size_t definitionsize;
    struct keytest tests[NUM_KEYTESTS_STRENGTHDET];
} strengthdettests[] =
    {
     /* 0: NIST strength definition */
     {
      niststrength,
      sizeof(niststrength),
      {
       { CKK_RSA, { .value = 7680 }, 0, STRENGTH_192, 7680, CK_TRUE, CKR_OK },
       { CKK_DSA, { .value = 1024 }, 512, STRENGTH_0, 512 * 2, CK_TRUE, CKR_OK },
       { CKK_EC,  { .nid = NID_secp224r1 }, 0, STRENGTH_112, 224 * 2, CK_TRUE, CKR_OK },
       { CKK_AES, { .value = 156 / 8 }, 0, STRENGTH_128, 128, CK_TRUE, CKR_OK },
      }
     },
     /* 1: PQ strength definition */
     {
      quantum112,
      sizeof(quantum112),
      {
       { CKK_RSA, { .value = 7680 }, 0, STRENGTH_0, 7680, CK_TRUE, CKR_OK },
       { CKK_DSA, { .value = 1024 }, 512, STRENGTH_0, 512 * 2, CK_TRUE, CKR_OK },
       /* allowed is CK_TRUE since no policy is active */
       { CKK_EC,  { .nid = NID_secp224r1 }, 0, STRENGTH_0, 224 * 2, CK_TRUE, CKR_OK },
       { CKK_AES, { .value = 256 / 8  }, 0, STRENGTH_112, 128, CK_TRUE, CKR_OK },
      }
     },
     /* 2: empty */
     {
      emptystrength,
      sizeof(emptystrength),
      {
       { CKK_RSA, { .value = 7680 }, 0, STRENGTH_0, 7680, CK_TRUE, CKR_OK },
       { CKK_DSA, { .value = 1024 }, 512, STRENGTH_0, 512 * 2, CK_TRUE, CKR_OK },
       { CKK_EC,  { .nid = NID_secp224r1 }, 0, STRENGTH_0, 224 * 2, CK_TRUE, CKR_OK },
       { CKK_AES, { .value = 156 / 8 }, 0, STRENGTH_0, 128, CK_TRUE, CKR_OK },
      }
     }
    };

#define NUM_KEYTESTS_STRENGTHENFORCE 4

static const struct strengthenforcetest {
    const char *strength;
    size_t strengthsize;
    const char *policy;
    size_t policysize;
    struct keytest tests[NUM_KEYTESTS_STRENGTHENFORCE];
} strengthenforcetests[] =
    {
     /* 0: NIST strength, require 0 and only secp curves */
     {
      niststrength,
      sizeof(niststrength),
      policysecponly,
      sizeof(policysecponly),
      {
       /* MOD_EXP */
       { CKK_RSA, { .value = 3072 }, 0, STRENGTH_128, 3072, CK_TRUE, CKR_OK },
       /* ECC (Test 0) */
       { CKK_EC,  { .nid = NID_secp224r1 }, 0, STRENGTH_112, 448, CK_TRUE, CKR_OK },
       /* ECC (Test 1) */
       { CKK_EC,  { .nid = NID_brainpoolP512t1 }, 0, STRENGTH_256, 1024, CK_FALSE, CKR_FUNCTION_FAILED },
       /* SYMMETRIC */
       { CKK_AES, { .value = 200 / 8 }, 0, STRENGTH_192, 128, CK_TRUE, CKR_OK }  
      }
     },
     /* 1: NIST strength, require 0 and no curves */
     {
      niststrength,
      sizeof(niststrength),
      policynocurves,
      sizeof(policynocurves),
      {
       /* MOD_EXP */
       { CKK_RSA, { .value = 3072 }, 0, STRENGTH_128, 3072, CK_TRUE, CKR_OK },
       /* ECC (Test 0) */
       { CKK_EC,  { .nid = NID_secp224r1 }, 0, STRENGTH_112, 448, CK_FALSE, CKR_FUNCTION_FAILED },
       /* ECC (Test 1) */
       { CKK_EC,  { .nid = NID_brainpoolP512t1 }, 0, STRENGTH_256, 1024, CK_FALSE, CKR_FUNCTION_FAILED },
       /* SYMMETRIC */
       { CKK_AES, { .value = 200 / 8 }, 0, STRENGTH_192, 128, CK_TRUE, CKR_OK }  
      }
     },
     /* 2: NIST strength, require 256 */
     {
      niststrength,
      sizeof(niststrength),
      policystrength256,
      sizeof(policystrength256),
      {
       /* MOD_EXP */
       { CKK_RSA, { .value = 3072 }, 0, STRENGTH_128, 3072, CK_TRUE, CKR_FUNCTION_FAILED },
       /* ECC (Test 0) */
       { CKK_EC,  { .nid = NID_secp224r1 }, 0, STRENGTH_112, 448, CK_TRUE, CKR_FUNCTION_FAILED },
       /* ECC (Test 1) */
       { CKK_EC,  { .nid = NID_brainpoolP512t1 }, 0, STRENGTH_256, 1024, CK_TRUE, CKR_OK },
       /* SYMMETRIC */
       { CKK_AES, { .value = 200 / 8 }, 0, STRENGTH_192, 128, CK_TRUE, CKR_FUNCTION_FAILED }  
      }
     },
     /* 3: NIST strength, require 192 */
     {
      niststrength,
      sizeof(niststrength),
      policystrength192,
      sizeof(policystrength192),
      {
       /* MOD_EXP */
       { CKK_RSA, { .value = 3072 }, 0, STRENGTH_128, 3072, CK_TRUE, CKR_FUNCTION_FAILED },
       /* ECC (Test 0) */
       { CKK_EC,  { .nid = NID_secp224r1 }, 0, STRENGTH_112, 448, CK_TRUE, CKR_FUNCTION_FAILED },
       /* ECC (Test 1) */
       { CKK_EC,  { .nid = NID_brainpoolP512t1 }, 0, STRENGTH_256, 1024, CK_TRUE, CKR_OK },
       /* SYMMETRIC */
       { CKK_AES, { .value = 200 / 8 }, 0, STRENGTH_192, 128, CK_TRUE, CKR_OK }  
      }
     },
     /* 4: NIST strength, require 128 */
     {
      niststrength,
      sizeof(niststrength),
      policystrength128,
      sizeof(policystrength128),
      {
       /* MOD_EXP */
       { CKK_RSA, { .value = 3072 }, 0, STRENGTH_128, 3072, CK_TRUE, CKR_OK },
       /* ECC (Test 0) */
       { CKK_EC,  { .nid = NID_secp224r1 }, 0, STRENGTH_112, 448, CK_TRUE, CKR_FUNCTION_FAILED },
       /* ECC (Test 1) */
       { CKK_EC,  { .nid = NID_brainpoolP512t1 }, 0, STRENGTH_256, 1024, CK_TRUE, CKR_OK },
       /* SYMMETRIC */
       { CKK_AES, { .value = 200 / 8 }, 0, STRENGTH_192, 128, CK_TRUE, CKR_OK }  
      }
     },
     /* 5: NIST strength, require 112 */
     {
      niststrength,
      sizeof(niststrength),
      policystrength112,
      sizeof(policystrength112),
      {
       /* MOD_EXP */
       { CKK_RSA, { .value = 3072 }, 0, STRENGTH_128, 3072, CK_TRUE, CKR_OK },
       /* ECC (Test 0) */
       { CKK_EC,  { .nid = NID_secp224r1 }, 0, STRENGTH_112, 448, CK_TRUE, CKR_OK },
       /* ECC (Test 1) */
       { CKK_EC,  { .nid = NID_brainpoolP512t1 }, 0, STRENGTH_256, 1024, CK_TRUE, CKR_OK },
       /* SYMMETRIC */
       { CKK_AES, { .value = 200 / 8 }, 0, STRENGTH_192, 128, CK_TRUE, CKR_OK }  
      }
     },
     /* 6: NIST strength, require 0 */
     {
      niststrength,
      sizeof(niststrength),
      policyempty,
      sizeof(policyempty),
      {
       /* MOD_EXP */
       { CKK_RSA, { .value = 3072 }, 0, STRENGTH_128, 3072, CK_TRUE, CKR_OK },
       /* ECC (Test 0) */
       { CKK_EC,  { .nid = NID_secp224r1 }, 0, STRENGTH_112, 448, CK_TRUE, CKR_OK },
       /* ECC (Test 1) */
       { CKK_EC,  { .nid = NID_brainpoolP512t1 }, 0, STRENGTH_256, 1024, CK_TRUE, CKR_OK },
       /* SYMMETRIC */
       { CKK_AES, { .value = 200 / 8 }, 0, STRENGTH_192, 128, CK_TRUE, CKR_OK }  
      }
     }
    };

/* These tests run with niststrength and policystrength128 */
static const struct policyenforcetest {
    CK_ULONG strength;
    CK_ULONG siglen;
    CK_ULONG mech;
    int check;
    CK_RV exprc;
} policyenforcetests[] =
    {
     { STRENGTH_0, 0, CKM_SHA_1, POLICY_CHECK_DIGEST, CKR_FUNCTION_FAILED },
     { STRENGTH_0, 0, CKM_SHA256, POLICY_CHECK_DIGEST, CKR_OK },
     { STRENGTH_112, 0, CKM_RSA_PKCS, POLICY_CHECK_ENCRYPT, CKR_FUNCTION_FAILED },
     { STRENGTH_128, 0, CKM_RSA_PKCS, POLICY_CHECK_ENCRYPT, CKR_OK },
     { STRENGTH_128, 112, CKM_RSA_PKCS, POLICY_CHECK_SIGNATURE, CKR_FUNCTION_FAILED },
     { STRENGTH_128, 128, CKM_RSA_PKCS, POLICY_CHECK_SIGNATURE, CKR_OK },
    };

static const CK_ULONG testhashmechs[] =
    { CKM_RSA_PKCS, CKM_SHA1_RSA_PKCS, CKM_ECDSA, CKM_ECDSA_SHA1 };

static const CK_RV testhashempty[] = { CKR_OK, CKR_OK, CKR_OK, CKR_OK };
static const CK_RV testhashnomechs[] =
    { CKR_FUNCTION_FAILED, CKR_FUNCTION_FAILED, CKR_FUNCTION_FAILED,
      CKR_FUNCTION_FAILED };
static const CK_RV testhashfixed[] =
    { CKR_OK, CKR_FUNCTION_FAILED, CKR_OK, CKR_FUNCTION_FAILED };

static const struct policyhashtest {
    const char     *policy;
    size_t          policysize;
    const CK_ULONG *mechs;
    const CK_RV    *exprcs;
    size_t          nummechs;
} policyhashtests[] =
    {
     {
      policyempty,
      sizeof(policyempty),
      testhashmechs,
      testhashempty,
      ARRAYSIZE(testhashmechs)
     },
     {
      policynomechs,
      sizeof(policynomechs),
      testhashmechs,
      testhashnomechs,
      ARRAYSIZE(testhashmechs)
     },
     {
      policyfixedmechs,
      sizeof(policyfixedmechs),
      testhashmechs,
      testhashfixed,
      ARRAYSIZE(testhashmechs)
     }
    };

/* Helper functions for strength determination */
static CK_RV build_ulong_attr(CK_ATTRIBUTE_TYPE type, CK_ULONG value,
                              CK_ATTRIBUTE **attr)
{
    CK_ATTRIBUTE *a;

    a = malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_ULONG));
    if (a == NULL)
        return CKR_HOST_MEMORY;
    a->type = type;
    a->pValue = ((char *)a) + sizeof(CK_ATTRIBUTE);
    a->ulValueLen = sizeof(CK_ULONG);
    *(CK_ULONG *)a->pValue = value;
    *attr = a;
    return CKR_OK;
}

static CK_RV build_bigint_attr(CK_ATTRIBUTE_TYPE type, CK_ULONG numbits,
                               CK_ATTRIBUTE **attr)
{
    CK_ATTRIBUTE *a;
    CK_ULONG numbytes = numbits / 8u;

    a = malloc(sizeof(CK_ATTRIBUTE) + numbytes);
    if (a == NULL)
        return CKR_HOST_MEMORY;
    a->type = type;
    a->pValue = ((char *)a) + sizeof(CK_ATTRIBUTE);
    a->ulValueLen = numbytes;
    *attr = a;
    return CKR_OK;
}

static CK_RV build_oid_attr(CK_ATTRIBUTE_TYPE type, const CK_BYTE *data,
                            CK_ULONG datasize, CK_ATTRIBUTE **attr)
{
    CK_ATTRIBUTE *a;

    a = malloc(sizeof(CK_ATTRIBUTE));
    if (a == NULL)
        return CKR_HOST_MEMORY;
    a->type = type;
    a->pValue = (void *)data;
    a->ulValueLen = datasize;
    *attr = a;
    return CKR_OK;
}

static int attrcalls;

static CK_RV getdetattr(void *d, CK_ATTRIBUTE_TYPE type, CK_ATTRIBUTE **attr)
{
    struct keytest *t = d;
    int i;

    ++attrcalls;
    switch (type) {
    case CKA_KEY_TYPE:
        return build_ulong_attr(type, t->keytype, attr);
    case CKA_VALUE_LEN:
        return build_ulong_attr(type, t->strengthattr.value, attr);
    case CKA_MODULUS:
    case CKA_PRIME:
        return build_bigint_attr(type, t->strengthattr.value, attr);
    case CKA_SUBPRIME:
        return build_bigint_attr(type, t->sigattr, attr);
    case CKA_EC_PARAMS:
        for (i = 0; i < NUMEC; ++i) {
            if (der_ec_supported[i].nid == t->strengthattr.nid)
                return build_oid_attr(type, der_ec_supported[i].data,
                                      der_ec_supported[i].data_size, attr);

        }
        // Fallthrough
    default:
        return CKR_FUNCTION_FAILED;
    }
}

static void freedetattr(void *d, CK_ATTRIBUTE *a)
{
    UNUSED(d);

    --attrcalls;
    free(a);
}

static int test_load_strength_cfg(struct policy_private *pp,
                                  void *cfg, size_t size)
{
    FILE *fp;
    CK_RV rc;

    fp = fmemopen(cfg, size, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to memopen strength configuration\n");
        return -1;
    }
    rc = policy_load_strength_cfg(pp, fp);
    fclose(fp);
    if (rc != CKR_OK) {
        fprintf(stderr, "Strength configuration could not be loaded\n");
        return -1;
    }
    return 0;
}

static int test_load_policy_cfg(struct policy_private *pp,
                                void *cfg, size_t size)
{
    FILE *fp;
    CK_RV rc;
    CK_BBOOL ignored;

    fp = fmemopen(cfg, size, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to memopen policy\n");
        return -1;
    }
    rc = policy_load_policy_cfg(pp, fp, &ignored);
    fclose(fp);
    if (rc != CKR_OK) {
        fprintf(stderr, "Policy configuration could not be loaded\n");
        return -1;
    }
    return 0;
}

static int runstrengthdettests(void)
{
    struct objstrength strength;
    struct policy_private *pp;
    const struct keytest *t;
    struct policy p;
    unsigned int o;
    CK_RV rc;
    int res;
    int i;

    fprintf(stderr, "Running strengthdettests\n");
    res = 0;
    policy_init_policy(&p);
    for (o = 0; o < ARRAYSIZE(strengthdettests); ++o) {
        pp = policy_private_alloc();
        if (pp == NULL) {
            fprintf(stderr, "Failed to allocate policy_private\n");
            return -1;
        }
        policy_private_deactivate(pp);
        p.priv = pp;
        if (test_load_strength_cfg(pp, (void *)strengthdettests[o].definition,
                                    strengthdettests[o].definitionsize)) {
            fprintf(stderr, "Test %u: Failed to load strength configuration\n", o);
            return -1;
        }
        for (i = 0; i < NUM_KEYTESTS_STRENGTHDET; ++i) {
            attrcalls = 0;
            t = &(strengthdettests[o].tests[i]);
            rc = p.store_object_strength(&p, &strength, getdetattr, (void *)t,
                                         freedetattr, NULL);
            if (rc != CKR_OK) {
                res = -1;
                fprintf(stderr, "Test %u, case %i: Could not store object strength\n",
                        o, i);
                break;
            }
            if (strength.strength != t->expstrength) {
                res = -1;
                fprintf(stderr, "Test %u, case %i: Unexpected strength:\nexpected: %lu\nis: %lu\n",
                        o, i, t->expstrength, strength.strength);
                break;
            }
            if (strength.siglen != t->expsiglen) {
                res = -1;
                fprintf(stderr, "Test %u, case %i: Unexpected siglen:\nexpected: %lu\nis: %lu\n",
                        o, i, t->expsiglen, strength.siglen);
                break;
            }
            if (t->keytype == CKK_EC && strength.allowed != t->expallowed) {
                res = -1;
                fprintf(stderr, "Test %u, case %i: Unexpected EC allowed flag\n",
                        o, i);
                break;
            }
            if (attrcalls != 0) {
                res = -1;
                fprintf(stderr, "Unbalanced attribute calls.  Count shows %i!\n",
                        attrcalls);
                break;
            }
        }
        p.priv = policy_private_free(pp);
        if (res != 0)
            break;
    }
    return res;
}

static int runstrengthenforcetests(void)
{
    struct objstrength strength;
    struct policy_private *pp;
    const struct keytest *t;
    struct policy p;
    unsigned int o;
    CK_RV rc;
    int res;
    int i;

    fprintf(stderr, "Running strengthenforcetests\n");
    res = 0;
    policy_init_policy(&p);
    for (o = 0; o < ARRAYSIZE(strengthenforcetests); ++o) {
        pp = policy_private_alloc();
        if (pp == NULL) {
            fprintf(stderr, "Test %u: Failed to allocate policy_private\n", o);
            return -1;
        }
        p.priv = pp;
        if (test_load_strength_cfg(pp,(void *)strengthenforcetests[o].strength,
                                   strengthenforcetests[o].strengthsize)) {
            policy_private_free(pp);
            fprintf(stderr, "Test %u: Failed to load strength configuration\n",
                    o);
            return -1;
        }
        if (test_load_policy_cfg(pp, (void *)strengthenforcetests[o].policy,
                                 strengthenforcetests[o].policysize)) {
            policy_private_free(pp);
            fprintf(stderr, "Test %u: Failed to load policy configuration\n",
                    o);
            return -1;
        }
        for (i = 0; i < NUM_KEYTESTS_STRENGTHENFORCE; ++i) {
            attrcalls = 0;
            t = &(strengthenforcetests[o].tests[i]);
            rc = p.store_object_strength(&p, &strength, getdetattr, (void *)t,
                                         freedetattr, NULL);
            if (rc != t->exprc) {
                res = -1;
                fprintf(stderr, "Test %u, case %i: Wrong result on strength determination: expected %lu, got %lu\n",
                        o, i, t->exprc, rc);
                break;
            }
            /* Even if we get CKR_FUNCTION_FAILED, the policy should
               have stored the correct strength information. */
            if (strength.strength != t->expstrength) {
                res = -1;
                fprintf(stderr, "Test %u, case %i: Unexpected strength:\nexpected: %lu\nis: %lu\n",
                        o, i, t->expstrength, strength.strength);
                break;
            }
            if (strength.siglen != t->expsiglen) {
                res = -1;
                fprintf(stderr, "Test %u, case %i: Unexpected siglen:\nexpected: %lu\nis: %lu\n",
                        o, i, t->expsiglen, strength.siglen);
                break;
            }
            if (t->keytype == CKK_EC && strength.allowed != t->expallowed) {
                res = -1;
                fprintf(stderr, "Test %u, case %i: Unexpected EC allowed flag\n",
                        o, i);
                break;
            }
            if (attrcalls != 0) {
                res = -1;
                fprintf(stderr, "Unbalanced attribute calls.  Count shows %i!\n",
                        attrcalls);
                break;
            }
        }
        p.priv = policy_private_free(pp);
        if (res != 0)
            break;
    }
    return res;
}

static int runpolicyenforcetests(void)
{
    struct objstrength strength, *s;
    struct policy_private *pp;
    CK_MECHANISM mech;
    struct policy p;
    unsigned int i;
    CK_RV rc;
    int res;

    fprintf(stderr, "Running policyenforcetests\n");
    res = 0;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;
    strength.allowed = CK_TRUE;
    policy_init_policy(&p);
    pp = policy_private_alloc();
    if (pp == NULL) {
        fprintf(stderr, "Failed to allocate policy_private\n");
        return -1;
    }
    p.priv = pp;
    if (test_load_strength_cfg(pp, (void *)niststrength, sizeof(niststrength))) {
        policy_private_free(pp);
        fprintf(stderr, "Failed to load NIST strength configuration\n");
        return -1;
    }
    if (test_load_policy_cfg(pp, (void *)policystrength128,
                             sizeof(policystrength128))) {
        policy_private_free(pp);
        fprintf(stderr, "Failed to load policy with strength 128\n");
        return -1;
    }
    for (i = 0; i < ARRAYSIZE(policyenforcetests); ++i) {
        strength.strength = policyenforcetests[i].strength;
        strength.siglen = policyenforcetests[i].siglen;
        s = policyenforcetests[i].check == POLICY_CHECK_DIGEST ?
            NULL : &strength;
        mech.mechanism = policyenforcetests[i].mech;
        rc = p.is_mech_allowed(&p, &mech, s, policyenforcetests[i].check, NULL);
        if (rc != policyenforcetests[i].exprc) {
            fprintf(stderr,
                    "Test %u: Unexpected result: 0x%lx (expected 0x%lx)\n",
                    i, rc, policyenforcetests[i].exprc);
            res = -1;
        }
    }
    policy_private_free(pp);
    return res;
}

static int runpolicyhashtests(void)
{
    struct objstrength strength;
    struct policy_private *pp;
    CK_MECHANISM mech;
    struct policy p;
    unsigned int o, i;
    CK_RV rc;
    int res;

    fprintf(stderr, "Running policyhashtests\n");
    res = 0;
    policy_init_policy(&p);
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;
    strength.strength = 0;
    strength.siglen = 0;
    strength.allowed = CK_TRUE;
    for (o = 0; o < ARRAYSIZE(policyhashtests); ++o) {
        pp = policy_private_alloc();
        if (pp == NULL) {
            fprintf(stderr, "Test %u: Failed to allocate policy_private\n", o);
            return -1;
        }
        p.priv = pp;
        if (test_load_strength_cfg(pp,(void *)niststrength,
                                   sizeof(niststrength))) {
            policy_private_free(pp);
            fprintf(stderr, "Test %u: Failed to load strength configuration\n",
                    o);
            return -1;
        }
        if (test_load_policy_cfg(pp, (void *)policyhashtests[o].policy,
                                 policyhashtests[o].policysize)) {
            policy_private_free(pp);
            fprintf(stderr, "Test %u: Failed to load policy configuration\n",
                    o);
            return -1;
        }
        for (i = 0; i < policyhashtests[o].nummechs; ++i) {
            mech.mechanism = policyhashtests[o].mechs[i];
            /* check is wrong for most, but is chosen to not perform
               any additional size checking. */
            rc = p.is_mech_allowed(&p, &mech, &strength, POLICY_CHECK_ENCRYPT,
                                   NULL);
            if (rc != policyhashtests[o].exprcs[i]) {
                fprintf(stderr, "Test %u case %u: Wrong result: 0x%lx (expected 0x%lx)\n",
                        o, i, rc, policyhashtests[o].exprcs[i]);
                res = -1;
            }
        }
        policy_private_free(pp);
    }
    return res;
}

#define POLICYDEEPCHECKMGFNUM 4

static int runpolicydeepcheckmgftests(void)
{
    static const CK_ULONG mgfs[POLICYDEEPCHECKMGFNUM] =
        { CKG_MGF1_SHA1, CKG_MGF1_SHA512,
          CKG_IBM_MGF1_SHA3_224, CKG_IBM_MGF1_SHA3_384 };
    static const struct {
        const char *policy;
        size_t policylen;
        CK_RV exprc[POLICYDEEPCHECKMGFNUM];
    } policies[] =
          {
           { policyempty, sizeof(policyempty),
             {CKR_OK, CKR_OK, CKR_OK, CKR_OK} },
           { policymgfstandard, sizeof(policymgfstandard),
             {CKR_OK, CKR_OK, CKR_FUNCTION_FAILED, CKR_FUNCTION_FAILED} },
           { policymgfibm, sizeof(policymgfibm),
             { CKR_FUNCTION_FAILED, CKR_FUNCTION_FAILED, CKR_OK, CKR_OK} },
           { policymgfoneeach, sizeof(policymgfoneeach),
             { CKR_FUNCTION_FAILED, CKR_OK, CKR_OK, CKR_FUNCTION_FAILED} },
           { policymgfnone, sizeof(policymgfnone),
             { CKR_FUNCTION_FAILED, CKR_FUNCTION_FAILED,
               CKR_FUNCTION_FAILED, CKR_FUNCTION_FAILED } }
          };
    struct objstrength strength;
    struct policy_private *pp;
    CK_MECHANISM oaepmech, pssmech;
    struct policy p;
    unsigned int i, o;
    CK_RV rc;
    int res;
    CK_RSA_PKCS_OAEP_PARAMS oaepparams;
    CK_RSA_PKCS_PSS_PARAMS pssparams;

    fprintf(stderr, "Running policydeepcheckmgftests\n");
    res = 0;
    policy_init_policy(&p);
    oaepparams.hashAlg = CKM_SHA_1;
    oaepparams.source = CKZ_DATA_SPECIFIED;
    oaepparams.pSourceData = NULL;
    oaepparams.ulSourceDataLen = 0;
    pssparams.hashAlg = CKM_SHA_1;
    pssparams.sLen = 0;
    strength.strength = 0;
    strength.siglen = 0;
    strength.allowed = CK_TRUE;
    oaepmech.mechanism = CKM_RSA_PKCS_OAEP;
    oaepmech.pParameter = &oaepparams;
    oaepmech.ulParameterLen = sizeof(oaepparams);
    pssmech.mechanism = CKM_RSA_PKCS_PSS;
    pssmech.pParameter = &pssparams;
    pssmech.ulParameterLen = sizeof(pssparams);

    for (o = 0; o < ARRAYSIZE(policies); ++o) {
        pp = policy_private_alloc();
        if (pp == NULL) {
            fprintf(stderr, "Test %u: Failed to allocate policy_private\n", o);
            return -1;
        }
        p.priv = pp;
        if (test_load_strength_cfg(pp,(void *)niststrength,
                                   sizeof(niststrength))) {
            policy_private_free(pp);
            fprintf(stderr, "Test %u: Failed to load strength configuration\n",
                    o);
            return -1;
        }
        if (test_load_policy_cfg(pp, (void *)policies[o].policy,
                                 policies[o].policylen)) {
            policy_private_free(pp);
            fprintf(stderr, "Test %u: Failed to load policy configuration\n",
                    o);
            return -1;
        }
        for (i = 0; i < ARRAYSIZE(mgfs); ++i) {
            oaepparams.mgf = pssparams.mgf = mgfs[i];
            /* Checking encrypt prevents output size checking here
               which is not the goal of this test. */
            rc = p.is_mech_allowed(&p, &oaepmech, &strength,
                                   POLICY_CHECK_ENCRYPT,
                                   NULL);
            if (rc != policies[o].exprc[i]) {
                fprintf(stderr,
                        "Test %u, case %u, OAEP: unexpected result 0x%lx (expected 0x%lx)\n",
                        o, i, rc, policies[o].exprc[i]);
                res = -1;
            }
            rc = p.is_mech_allowed(&p, &pssmech, &strength,
                                   POLICY_CHECK_ENCRYPT,
                                   NULL);
            if (rc != policies[o].exprc[i]) {
                fprintf(stderr,
                        "Test %u, case %u, PSS: unexpected result 0x%lx (expected 0x%lx)\n",
                        o, i, rc, policies[o].exprc[i]);
                res = -1;
            }
        }
        p.priv = pp = policy_private_free(pp);
    }
    return res;
}

#define POLICYDEEPCHECKKDFNUM 4

static int runpolicydeepcheckkdftests(void)
{
    static const CK_ULONG kdfs[POLICYDEEPCHECKKDFNUM] =
        { CKD_NULL, CKD_SHA1_KDF_ASN1, CKD_SHA256_KDF, CKD_SHA512_KDF };
    static const struct {
        const char *policy;
        size_t policylen;
        CK_RV exprc[POLICYDEEPCHECKKDFNUM];
    } policies[] =
          {
           {
            policyempty, sizeof(policyempty),
            { CKR_OK, CKR_OK, CKR_OK, CKR_OK }
           },
           {
            policykdfnosha1, sizeof(policykdfnosha1),
            { CKR_FUNCTION_FAILED, CKR_FUNCTION_FAILED, CKR_OK, CKR_OK }
           },
           {
            policykdfnone, sizeof(policykdfnone),
            { CKR_FUNCTION_FAILED, CKR_FUNCTION_FAILED,
              CKR_FUNCTION_FAILED, CKR_FUNCTION_FAILED }
           }
          };
    CK_ECDH1_DERIVE_PARAMS ecdhparams;
    struct objstrength strength;
    struct policy_private *pp;
    CK_MECHANISM mech;
    struct policy p;
    unsigned int i, o;
    CK_RV rc;
    int res;

    fprintf(stderr, "Running policydeepcheckkdftests\n");
    res = 0;
    policy_init_policy(&p);
    strength.strength = 0;
    strength.siglen = 0;
    strength.allowed = CK_TRUE;
    ecdhparams.ulSharedDataLen = 0;
    ecdhparams.pSharedData = NULL;
    ecdhparams.ulPublicDataLen = 0;
    ecdhparams.pPublicData = NULL;
    mech.mechanism = CKM_ECDH1_DERIVE;
    mech.pParameter = &ecdhparams;
    mech.ulParameterLen = sizeof(ecdhparams);
    for (o = 0; o < ARRAYSIZE(policies); ++o) {
        fprintf(stderr, "Test %u\n", o);
        pp = policy_private_alloc();
        if (pp == NULL) {
            fprintf(stderr, "Test %u: Failed to allocate policy_private\n", o);
            return -1;
        }
        p.priv = pp;
        if (test_load_strength_cfg(pp,(void *)niststrength,
                                   sizeof(niststrength))) {
            policy_private_free(pp);
            fprintf(stderr, "Test %u: Failed to load strength configuration\n",
                    o);
            return -1;
        }
        if (test_load_policy_cfg(pp, (void *)policies[o].policy,
                                 policies[o].policylen)) {
            policy_private_free(pp);
            fprintf(stderr, "Test %u: Failed to load policy configuration\n",
                    o);
            return -1;
        }
        for (i = 0; i < ARRAYSIZE(kdfs); ++i) {
            fprintf(stderr, "Case %u\n", i);
            ecdhparams.kdf = kdfs[i];
            rc = p.is_mech_allowed(&p, &mech, &strength, POLICY_CHECK_DERIVE,
                                   NULL);
            if (rc != policies[o].exprc[i]) {
                fprintf(stderr,
                        "Test %u, case %u: unexpected result 0x%lx (expected 0x%lx)\n",
                        o, i, rc, policies[o].exprc[i]);
                res = -1;
            }
        }
        p.priv = pp = policy_private_free(pp);
    }
    return res;
}

static int runpolicydeepchecktests(void)
{
    return runpolicydeepcheckmgftests() | runpolicydeepcheckkdftests();
}

static int runstrengthtests(void)
{
    return runstrengthdettests() | runstrengthenforcetests();
}

static int runpolicytests(void)
{
    return runpolicyenforcetests() | runpolicyhashtests() |
        runpolicydeepchecktests();
}

int main(void)
{
    if (runstrengthtests())
        return TEST_FAIL;
    if (runpolicytests())
        return TEST_FAIL;
    return TEST_PASS;
}
