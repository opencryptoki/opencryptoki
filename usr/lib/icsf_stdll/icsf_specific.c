/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * openCryptoki ICSF token
 *
 * Author: Marcelo Cerri (mhcerri@br.ibm.com)
 *
 * Based on CCC token.
 *
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "pbkdf.h"
#include "h_extern.h"
#include "tok_specific.h"
#include "tok_struct.h"
#include "icsf_config.h"
#include "icsf_specific.h"
#include "pbkdf.h"
#include "list.h"
#include "attributes.h"
#include "../api/apiproto.h"
#include "trace.h"
#include "shared_memory.h"
#include "slotmgr.h"
#include "../api/policy.h"
#include "cfgparser.h"
#include "configuration.h"

/* Default token attributes */
const char manuf[] = "IBM";
const char model[] = "ICSF";
const char descr[] = "IBM ICSF token";
const char label[] = "icsftok";

/* mechanisms provided by this token */
static const MECH_LIST_ELEMENT icsf_mech_list[] = {
    {CKM_DES_KEY_GEN, {8, 8, CKF_HW | CKF_GENERATE}},
    {CKM_DES_ECB, {0, 0, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT}},
    {CKM_DES_CBC, {0, 0, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT}},
    {CKM_DES_CBC_PAD,
     {0, 0, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES3_ECB, {0, 0, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT}},
    {CKM_DES3_CBC, {0, 0, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT}},
    {CKM_DES3_CBC_PAD,
     {0, 0, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES3_KEY_GEN, {24, 24, CKF_HW | CKF_GENERATE}},
    {CKM_DES2_KEY_GEN, {24, 24, CKF_HW | CKF_GENERATE}},
    {CKM_RSA_PKCS_KEY_PAIR_GEN, {512, 4096, CKF_HW | CKF_GENERATE_KEY_PAIR}},
    {CKM_RSA_PKCS,
     {512, 4096, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP |
      CKF_SIGN | CKF_VERIFY }},
    {CKM_RSA_X_509,
     {512, 4096, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY }},
    {CKM_MD5_RSA_PKCS, {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA1_RSA_PKCS, {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA224_RSA_PKCS, {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA256_RSA_PKCS, {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA384_RSA_PKCS, {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA512_RSA_PKCS, {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA_1, {0, 0, CKF_HW | CKF_DIGEST}},
    {CKM_SHA_1_HMAC, {0, 0, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA224_HMAC, {0, 0, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA256_HMAC, {0, 0, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA384_HMAC, {0, 0, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA512_HMAC, {0, 0, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_MD5, {0, 0, CKF_DIGEST}},
    {CKM_MD5_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
    {CKM_AES_KEY_GEN, {16, 32, CKF_HW | CKF_GENERATE}},
    {CKM_AES_ECB, {16, 32, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT}},
    {CKM_AES_CBC, {16, 32, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT}},
    {CKM_AES_CBC_PAD,
     {16, 32, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DH_PKCS_KEY_PAIR_GEN, {512, 2048, CKF_GENERATE_KEY_PAIR}},
    {CKM_DH_PKCS_DERIVE, {512, 2048, CKF_DERIVE}},
    {CKM_DSA_KEY_PAIR_GEN, {512, 2048, CKF_HW | CKF_GENERATE_KEY_PAIR}},
    {CKM_DSA_SHA1, {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_DSA, {512, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_ECDSA_SHA1,
      {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P |
      CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS}},
    {CKM_ECDSA_SHA224,
      {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P |
      CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS}},
    {CKM_ECDSA_SHA256,
      {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P |
      CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS}},
    {CKM_ECDSA_SHA384,
      {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P |
      CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS}},
    {CKM_ECDSA_SHA512,
      {512, 4096, CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P |
      CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS}},
    {CKM_ECDSA,
     {160, 521, CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P |
      CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS}},
    {CKM_EC_KEY_PAIR_GEN,
     {160, 521, CKF_HW | CKF_GENERATE_KEY_PAIR | CKF_EC_F_P |
      CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS}},
    {CKM_ECDH1_DERIVE,
       {160, 521, CKF_HW | CKF_DERIVE | CKF_EC_NAMEDCURVE |
        CKF_EC_F_P | CKF_EC_UNCOMPRESS}},
    {CKM_SSL3_PRE_MASTER_KEY_GEN, {48, 48, CKF_HW | CKF_GENERATE}},
    {CKM_SSL3_MD5_MAC, {384, 384, CKF_SIGN | CKF_VERIFY}},
    {CKM_SSL3_SHA1_MAC, {384, 384, CKF_SIGN | CKF_VERIFY}},
    {CKM_SSL3_MASTER_KEY_DERIVE, {48, 48, CKF_DERIVE}},
    {CKM_SSL3_KEY_AND_MAC_DERIVE, {48, 48, CKF_DERIVE}},
    {CKM_TLS_PRE_MASTER_KEY_GEN, {48, 48, CKF_HW | CKF_GENERATE}},
    {CKM_TLS_KEY_AND_MAC_DERIVE, {48, 48, CKF_DERIVE}},
    {CKM_GENERIC_SECRET_KEY_GEN, {80, 2048, CKF_HW | CKF_GENERATE}},
};

static const CK_ULONG icsf_mech_list_len =
                (sizeof(icsf_mech_list) / sizeof(MECH_LIST_ELEMENT));

/* Each element of the list sessions should have this type: */
struct session_state {
    CK_SESSION_HANDLE session_id;
    LDAP *ld;

    /* List element */
    list_entry_t sessions;
};


/* Each element of the btree objects should have this type: */
struct icsf_object_mapping {
    struct bt_ref_hdr hdr;
    CK_SESSION_HANDLE session_id;
    struct icsf_object_record icsf_object;
    struct objstrength strength;
};

/*
 * Structure used to keep track of data used in multi-part operations.
 */
struct icsf_multi_part_context {
    int initiated;
    char chain_data[ICSF_CHAINING_DATA_LEN];
    char *data;
    size_t data_len;
    size_t used_data_len;
};

struct icsf_policy_attr {
    LDAP *ld;
    struct icsf_object_record *icsf_object;
};

int icsf_to_ock_err(int icsf_return_code, int icsf_reason_code);

static CK_RV icsf_policy_get_attr(void *data,
                                  CK_ATTRIBUTE_TYPE type,
                                  CK_ATTRIBUTE **attr)
{
    CK_RV rc;
    int reason;
    struct icsf_policy_attr *d = data;
    CK_ATTRIBUTE *a;
    CK_ATTRIBUTE s = { .type = type, .ulValueLen = 0, .pValue = NULL };
    
    rc = icsf_get_attribute(d->ld, &reason, d->icsf_object, &s, 1);
    if (rc != CKR_OK) {
        TRACE_DEVEL("icsf_get_attribute failed\n");
        return icsf_to_ock_err(rc, reason);
    }
    if (s.ulValueLen == CK_UNAVAILABLE_INFORMATION) {
        TRACE_DEVEL("Size information for attribute 0x%lx not available\n",
                    type);
        return CKR_FUNCTION_FAILED;
    }
    a = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + s.ulValueLen);
    if (!a) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }
    a->type = type;
    a->ulValueLen = s.ulValueLen;
    a->pValue = (CK_BYTE *) a + sizeof(CK_ATTRIBUTE);
    rc = icsf_get_attribute(d->ld, &reason, d->icsf_object, a, 1);
    if (rc != CKR_OK) {
        TRACE_DEVEL("icsf_get_attribute failed\n");
        free(a);
        return icsf_to_ock_err(rc, reason);
    }
    *attr = a;
    return rc;
}

static void icsf_policy_free_attr(CK_ATTRIBUTE *attr)
{
    free(attr);
}

/*
 * Get the session specific structure.
 */
static struct session_state *get_session_state(STDLL_TokData_t * tokdata,
                                               CK_SESSION_HANDLE session_id)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    struct session_state *found = NULL;
    struct session_state *s;

    /* Lock sessions list */
    if (pthread_mutex_lock(&icsf_data->sess_list_mutex)) {
        TRACE_ERROR("Failed to lock mutex.\n");
        return NULL;
    }

    for_each_list_entry(&icsf_data->sessions, struct session_state, s, sessions) {
        if (s->session_id == session_id) {
            found = s;
            goto done;
        }
    }

done:
    /* Unlock */
    if (pthread_mutex_unlock(&icsf_data->sess_list_mutex)) {
        TRACE_ERROR("Mutex Unlock failed.\n");
        return NULL;
    }

    return found;
}

static void purge_object_mapping_cb(STDLL_TokData_t * tokdata, void *value,
                                    unsigned long node_num, void *p3)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;

    UNUSED(value);
    UNUSED(p3);

    /* Remove the object */
    bt_node_free(&icsf_data->objects, node_num, TRUE);
}

/*
 * Remove all mapped objects.
 */
static CK_RV purge_object_mapping(STDLL_TokData_t * tokdata)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;

    bt_for_each_node(tokdata, &icsf_data->objects, purge_object_mapping_cb,
                     NULL);

    return CKR_OK;
}

/* Store ICSF specific data for each slot*/
struct slot_data {
    int initialized;
    char conf_name[PATH_MAX + 1];
    char uri[PATH_MAX + 1];
    char dn[NAME_MAX + 1];
    char ca_file[PATH_MAX + 1];
    char cert_file[PATH_MAX + 1];
    char key_file[PATH_MAX + 1];
    int mech;
};
struct slot_data *slot_data[NUMBER_SLOTS_MANAGED];

/*
 * Converts an ICSF reason code to an ock error code
 */
int icsf_to_ock_err(int icsf_return_code, int icsf_reason_code)
{
    switch (icsf_return_code) {
    case 0:
        return CKR_OK;
    case 4:
        switch (icsf_reason_code) {
        case 8000:
        case 11000:
            return CKR_SIGNATURE_INVALID;
        }
        break;
    case 8:
        switch (icsf_reason_code) {
        case 2154:
            return CKR_KEY_TYPE_INCONSISTENT;
        case 2028:
            return CKR_WRAPPED_KEY_INVALID;
        case 3003:
            return CKR_BUFFER_TOO_SMALL;
        case 3009:
            return CKR_TEMPLATE_INCONSISTENT;
        case 3019:
            return CKR_SESSION_HANDLE_INVALID;
        case 3027:
            return CKR_SESSION_HANDLE_INVALID;
        case 3029:
            return CKR_ATTRIBUTE_TYPE_INVALID;
        case 3030:
            return CKR_ATTRIBUTE_VALUE_INVALID;
        case 3033:
            return CKR_TEMPLATE_INCOMPLETE;
        case 3034:
        case 3035:
            return CKR_ATTRIBUTE_READ_ONLY;
        case 3038:
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        case 3039:
            return CKR_KEY_TYPE_INCONSISTENT;
        case 3041:
            return CKR_KEY_NOT_WRAPPABLE;
        case 3043:
            return CKR_KEY_HANDLE_INVALID;
        case 3045:
            return CKR_KEY_UNEXTRACTABLE;
        case 72:
        case 11000:
            return CKR_DATA_LEN_RANGE;
        case 11028:
            return CKR_SIGNATURE_INVALID;
        }
        break;
    }
    return CKR_FUNCTION_FAILED;
}

/*
 * Called during C_Initialize.
 */
CK_RV icsftok_init(STDLL_TokData_t * tokdata, CK_SLOT_ID slot_id,
                   char *conf_name)
{
    CK_RV rc;
    struct slot_data *data;
    icsf_private_data_t *icsf_data;

    TRACE_INFO("icsf %s slot=%lu running\n", __func__, slot_id);

    /* Check Slot ID */
    if (slot_id >= NUMBER_SLOTS_MANAGED) {
        TRACE_ERROR("Invalid slot ID: %lu\n", slot_id);
        return CKR_FUNCTION_FAILED;
    }

    rc = ock_generic_filter_mechanism_list(tokdata,
                                           icsf_mech_list,
                                           icsf_mech_list_len,
                                           &(tokdata->mech_list),
                                           &(tokdata->mech_list_len));
    if (rc != CKR_OK) {
        TRACE_ERROR("Mechanism filtering failed!  rc = 0x%lx\n", rc);
        return rc;
    }

    icsf_data = calloc(1, sizeof(icsf_private_data_t));
    if (icsf_data == NULL)
        return CKR_HOST_MEMORY;
    list_init(&icsf_data->sessions);
    if (pthread_mutex_init(&icsf_data->sess_list_mutex, NULL) != 0) {
        TRACE_ERROR("Initializing session list lock failed.\n");
        free(icsf_data);
        return CKR_CANT_LOCK;
    }
    if (bt_init(&icsf_data->objects, free) != CKR_OK) {
        TRACE_ERROR("BTree init failed.\n");
        pthread_mutex_destroy(&icsf_data->sess_list_mutex);
        free(icsf_data);
        return CKR_FUNCTION_FAILED;
    }
    tokdata->private_data = icsf_data;

    rc = XProcLock(tokdata);
    if (rc != CKR_OK)
        return CKR_FUNCTION_FAILED;

    if (slot_data[slot_id] == NULL) {
        TRACE_ERROR("ICSF slot data not initialized.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    data = slot_data[slot_id];
    data->initialized = 0;
    strncpy(data->conf_name, conf_name, sizeof(data->conf_name) - 1);
    data->conf_name[sizeof(data->conf_name) - 1] = '\0';

done:
    if (rc == CKR_OK)
        rc = XProcUnLock(tokdata);
    else
        XProcUnLock(tokdata);

    return rc;
}

static void config_parse_error(int line, int col, const char *msg)
{
    TRACE_ERROR("Error parsing config file: line %d column %d: %s\n", line, col,
                msg);
}

static struct icsf_config out_config;
static char out_str_mech[64] = "";

struct ref {
    char *key;
    char *addr;
    size_t len;
    int required;
};

static struct ref refs[] = {
    { "token_name",        out_config.name,    sizeof(out_config.name),    1 },
    { "token_manufacture", out_config.manuf,   sizeof(out_config.manuf),   1 },
    { "token_model",       out_config.model,   sizeof(out_config.model),   1 },
    { "token_serial",      out_config.serial,  sizeof(out_config.serial),  1 },
    { "mech",              out_str_mech,       sizeof(out_str_mech),       1 },
    { "uri",               out_config.uri,     sizeof(out_config.uri),     0 },
    { "binddn",            out_config.dn,      sizeof(out_config.dn),      0 },
    { "cacert",            out_config.ca_file, sizeof(out_config.ca_file), 0 },
    { "cert",              out_config.cert_file, sizeof(out_config.cert_file), 0 },
    { "key",               out_config.key_file, sizeof(out_config.key_file), 0 },
};
static const size_t refs_len = sizeof(refs)/sizeof(*refs);

static int check_keys(const char *conf_name)
{
    size_t i;

    for (i = 0; i < refs_len; i++) {
        if (refs[i].required && *refs[i].addr == '\0') {
            TRACE_ERROR("Missing required key \"%s\" in \"%s\".\n",
                        refs[i].key, conf_name);
            return -1;
        }
    }

    return 0;
}

static CK_RV config_parse_slot(const char *config_file,
                               struct ConfigIdxStructNode *slot)
{
    struct ConfigBaseNode *c;
    int i;
    size_t k;
    char *str;

    TRACE_DEVEL("Slot: %lu\n", slot->idx);

    confignode_foreach(c, slot->value, i) {
        TRACE_DEVEL("Config node: '%s' type: %u line: %u\n",
                    c->key, c->type, c->line);

        str = confignode_getstr(c);
        if (str != NULL) {
            for (k = 0; k < refs_len; k++) {
                if (!strcasecmp(refs[k].key, c->key)) {
                    strncpy(refs[k].addr, str, refs[k].len);
                    refs[k].addr[refs[k].len - 1] = '\0';
                    goto found;
                }
            }

            TRACE_ERROR("Error parsing config file '%s': unexpected token '%s' "
                        "at line %d: \n", config_file, c->key, c->line);
            return CKR_FUNCTION_FAILED;

found:
            continue;
        }

        TRACE_ERROR("Error parsing config file '%s': unexpected token '%s' "
                    "at line %d: \n", config_file, c->key, c->line);
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

static CK_RV parse_config_file(const char *conf_name, CK_SLOT_ID slot_id,
                               struct icsf_config *data)
{
    FILE *file;
    struct ConfigBaseNode *c, *config = NULL;
    struct ConfigIdxStructNode *slot;
    CK_RV ret = CKR_OK;
    int i;

    file = fopen(conf_name, "r");
    if (file == NULL) {
        TRACE_ERROR("Error opening config file '%s': %s\n", conf_name,
                    strerror(errno));
       return CKR_FUNCTION_FAILED;
    }

    ret = parse_configlib_file(file, &config, config_parse_error, 0);
    fclose(file);
    if (ret != 0) {
        TRACE_ERROR("Error parsing config file '%s'\n", conf_name);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    confignode_foreach(c, config, i) {
        TRACE_DEVEL("Config node: '%s' type: %u line: %u\n",
                    c->key, c->type, c->line);

        if (confignode_hastype(c, CT_IDX_STRUCT)) {
            slot = confignode_to_idxstruct(c);
            if (strcmp(slot->base.key, "slot") == 0 &&
                slot->idx == slot_id) {
                ret = config_parse_slot(conf_name, slot);
                if (ret != 0)
                    break;
                continue;
            }

            TRACE_ERROR("Error parsing config file '%s': unexpected token '%s' "
                        "at line %d: \n", conf_name, c->key, c->line);
            ret = -1;
            break;
        }

        TRACE_ERROR("Error parsing config file '%s': unexpected token '%s' "
                    "at line %d: \n", conf_name, c->key, c->line);
        ret = CKR_FUNCTION_FAILED;
        break;
    }

    if (ret != CKR_OK)
        goto done;

    if (check_keys(conf_name)) {
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Parse mechanism type */
    if (!strcmp(out_str_mech, "SIMPLE")) {
        out_config.mech = ICSF_CFG_MECH_SIMPLE;
    } else if (!strcmp(out_str_mech, "SASL")) {
        out_config.mech = ICSF_CFG_MECH_SASL;
    } else {
        TRACE_ERROR("Unknown mechanism type found: %s\n", out_str_mech);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Copy output data. */
    memcpy(data, &out_config, sizeof(*data));

    #if DEBUG
    {
        size_t i;
        TRACE_DEVEL("ICSF configs for slot %lu.\n", slot_id);
        for (i = 0; i < refs_len; i++) {
            TRACE_DEVEL(" %s = \"%s\"\n", refs[i].key,
                        refs[i].addr);
        }
    }
    #endif

done:
    confignode_deepfree(config);
    return ret;
}

CK_RV token_specific_init_token_data(STDLL_TokData_t * tokdata,
                                     CK_SLOT_ID slot_id)
{
    CK_RV rc = CKR_OK;
    const char *conf_name = NULL;
    struct icsf_config config;

    /* Check Slot ID */
    if (slot_id >= NUMBER_SLOTS_MANAGED) {
        TRACE_ERROR("Invalid slot ID: %lu\n", slot_id);
        return CKR_FUNCTION_FAILED;
    }

    rc = XProcLock(tokdata);
    if (rc != CKR_OK)
        return CKR_FUNCTION_FAILED;

    if (slot_data[slot_id] == NULL) {
        TRACE_ERROR("ICSF slot data not initialized.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Check if data needs to be retrieved for this slot */
    if (slot_data[slot_id]->initialized) {
        TRACE_DEVEL("Slot data already initialized for slot %lu. "
                    "Skipping it\n", slot_id);
        goto done;
    }

    /* Check config file */
    conf_name = slot_data[slot_id]->conf_name;
    if (!conf_name || !conf_name[0]) {
        TRACE_ERROR("Missing config for slot %lu.\n", slot_id);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    TRACE_DEVEL("DEBUG: conf_name=\"%s\".\n", conf_name);
    if (parse_config_file(conf_name, slot_id, &config)) {
        TRACE_ERROR("Failed to parse file \"%s\" for slot %lu.\n",
                    conf_name, slot_id);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Copy general info */
    memcpy(tokdata->nv_token_data->token_info.label, config.name,
           strlen(config.name));
    memcpy(tokdata->nv_token_data->token_info.manufacturerID, config.manuf,
           strlen(config.manuf));
    memcpy(tokdata->nv_token_data->token_info.model, config.model,
           strlen(config.model));
    memcpy(tokdata->nv_token_data->token_info.serialNumber, config.serial,
           strlen(config.serial));

    /* Copy ICSF specific info */
    strcpy(slot_data[slot_id]->uri, config.uri);
    strcpy(slot_data[slot_id]->dn, config.dn);
    strcpy(slot_data[slot_id]->ca_file, config.ca_file);
    strcpy(slot_data[slot_id]->cert_file, config.cert_file);
    strcpy(slot_data[slot_id]->key_file, config.key_file);
    slot_data[slot_id]->initialized = 1;
    slot_data[slot_id]->mech = config.mech;

done:
    if (rc == CKR_OK)
        rc = XProcUnLock(tokdata);
    else
        XProcUnLock(tokdata);

    return rc;
}

CK_RV token_specific_load_token_data(STDLL_TokData_t * tokdata,
                                     CK_SLOT_ID slot_id, FILE * fh)
{
    CK_RV rc;
    struct slot_data data;

    /* Check Slot ID */
    if (slot_id >= NUMBER_SLOTS_MANAGED) {
        TRACE_ERROR("Invalid slot ID: %lu\n", slot_id);
        return CKR_FUNCTION_FAILED;
    }

    if (fread(&data, sizeof(data), 1, fh) != 1) {
        TRACE_ERROR("Failed to read ICSF slot data.\n");
        return CKR_FUNCTION_FAILED;
    }

    rc = XProcLock(tokdata);
    if (rc != CKR_OK)
        return CKR_FUNCTION_FAILED;

    if (slot_data[slot_id] == NULL) {
        TRACE_ERROR("ICSF slot data not initialized.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    memcpy(slot_data[slot_id], &data, sizeof(data));

done:
    if (rc == CKR_OK)
        rc = XProcUnLock(tokdata);
    else
        XProcUnLock(tokdata);

    return rc;
}

CK_RV token_specific_save_token_data(STDLL_TokData_t * tokdata,
                                     CK_SLOT_ID slot_id, FILE * fh)
{
    CK_RV rc;

    /* Check Slot ID */
    if (slot_id >= NUMBER_SLOTS_MANAGED) {
        TRACE_ERROR("Invalid slot ID: %lu\n", slot_id);
        return CKR_FUNCTION_FAILED;
    }

    rc = XProcLock(tokdata);
    if (rc != CKR_OK)
        return CKR_FUNCTION_FAILED;

    if (slot_data[slot_id] == NULL) {
        TRACE_ERROR("ICSF slot data not initialized.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (!fwrite(slot_data[slot_id], sizeof(**slot_data), 1, fh)) {
        TRACE_ERROR("Failed to write ICSF slot data.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

done:
    if (rc == CKR_OK)
        rc = XProcUnLock(tokdata);
    else
        XProcUnLock(tokdata);

    return rc;
}

/*
 * Initialize the shared memory region. ICSF has to use a custom method for
 * this because it uses additional data in the shared memory and in the future
 * multiple slots should be supported for ICSF.
 */
CK_RV token_specific_attach_shm(STDLL_TokData_t * tokdata, CK_SLOT_ID slot_id)
{
    CK_RV rc;
    int ret;
    void *ptr;
    LW_SHM_TYPE **shm = &tokdata->global_shm;
    size_t len = sizeof(**shm) + sizeof(**slot_data);
    char *shm_id = NULL;

    if (slot_id >= NUMBER_SLOTS_MANAGED) {
        TRACE_ERROR("Invalid slot ID: %lu\n", slot_id);
        return CKR_FUNCTION_FAILED;
    }

    if (asprintf(&shm_id, "/icsf-%lu", slot_id) < 0 || shm_id == NULL) {
        TRACE_ERROR("Failed to allocate shared memory id "
                    "for slot %lu.\n", slot_id);
        return CKR_HOST_MEMORY;
    }
    TRACE_DEVEL("Attaching to shared memory \"%s\".\n", shm_id);

    rc = XProcLock(tokdata);
    if (rc != CKR_OK) {
        free(shm_id);
        return CKR_FUNCTION_FAILED;
    }

    /*
     * Attach to an existing shared memory region or create it if it doesn't
     * exists. When the it's created (ret=0) the region is initialized with
     * zeroes.
     */
    ret = sm_open(shm_id, 0660, (void **) &ptr, len, 1);
    if (ret < 0) {
        TRACE_ERROR("Failed to open shared memory \"%s\".\n", shm_id);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    *shm = ptr;
    slot_data[slot_id] = (struct slot_data *)((unsigned char *)ptr
                                              + sizeof(**shm));

done:
    if (rc == CKR_OK)
        rc = XProcUnLock(tokdata);
    else
        XProcUnLock(tokdata);

    if (shm_id)
        free(shm_id);

    return rc;
}

CK_RV login(STDLL_TokData_t * tokdata, LDAP ** ld, CK_SLOT_ID slot_id,
            CK_BYTE * pin, CK_ULONG pin_len, const char *pass_file_type)
{
    CK_RV rc;
    struct slot_data data;
    LDAP *ldapd = NULL;
    int ret;

    UNUSED(pass_file_type);

    /* Check Slot ID */
    if (slot_id >= NUMBER_SLOTS_MANAGED) {
        TRACE_ERROR("Invalid slot ID: %lu\n", slot_id);
        return CKR_FUNCTION_FAILED;
    }

    rc = XProcLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to get process lock.\n");
        return rc;
    }

    /* Check slot data */
    if (slot_data[slot_id] == NULL || !slot_data[slot_id]->initialized) {
        TRACE_ERROR("ICSF slot data not initialized.\n");
        rc = CKR_FUNCTION_FAILED;
        XProcUnLock(tokdata);
        return rc;
    }
    memcpy(&data, slot_data[slot_id], sizeof(data));

    rc = XProcUnLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to release process lock.\n");
        return rc;
    }

    if (data.mech == ICSF_CFG_MECH_SIMPLE) {
        CK_BYTE mk[MAX_KEY_SIZE];
        CK_BYTE racf_pass[PIN_SIZE];
        int mk_len = sizeof(mk);
        int racf_pass_len = sizeof(racf_pass);
        char fname[PATH_MAX];

        /* Load master key */
        if (get_pk_dir(tokdata, fname, PATH_MAX) == NULL) {
            TRACE_ERROR("pk_dir buffer overflow\n");
            return CKR_FUNCTION_FAILED;
        }
        
        if (PATH_MAX - strlen(fname) > strlen("/MK_SO")) {
            strcat(fname, "/MK_SO");
        } else {
            TRACE_ERROR("MK_SO buffer overflow\n");
            return CKR_FUNCTION_FAILED;
        }
        if (get_masterkey(tokdata, pin, pin_len, fname, mk, &mk_len)) {
            TRACE_DEVEL("Failed to get masterkey \"%s\".\n", fname);
            return CKR_FUNCTION_FAILED;
        }

        /* Load RACF password */
        if (get_racf(tokdata, mk, mk_len, racf_pass, &racf_pass_len)) {
            TRACE_DEVEL("Failed to get RACF password.\n");
            return CKR_FUNCTION_FAILED;
        }

        /* Simple bind */
        ret = icsf_login(&ldapd, data.uri, data.dn, (char *)racf_pass);
    } else {
        /* SASL bind */
        ret = icsf_sasl_login(&ldapd, data.uri, data.cert_file,
                              data.key_file, data.ca_file, NULL);
    }

    if (ret) {
        TRACE_DEVEL("Failed to bind to %s\n", data.uri);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (icsf_check_pkcs_extension(ldapd)) {
        TRACE_ERROR("ICSF LDAP externsion not supported.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

done:
    if (rc == CKR_OK && ld)
        *ld = ldapd;

    return rc;
}

CK_RV reset_token_data(STDLL_TokData_t * tokdata, CK_SLOT_ID slot_id,
                       CK_CHAR_PTR pin, CK_ULONG pin_len)
{
    CK_BYTE mk[MAX_KEY_SIZE];
    CK_BYTE racf_pass[PIN_SIZE];
    int mk_len = sizeof(mk);
    int racf_pass_len = sizeof(racf_pass);
    char pk_dir_buf[PATH_MAX];
    char fname[PATH_MAX];

    /* Remove user's masterkey */
    if (slot_data[slot_id]->mech == ICSF_CFG_MECH_SIMPLE) {
        if (get_pk_dir(tokdata, pk_dir_buf, PATH_MAX) == NULL) {
            TRACE_ERROR("pk_dir_buf overflow\n");
            return CKR_FUNCTION_FAILED;
        }
        if (ock_snprintf(fname, PATH_MAX, "%s/MK_USER", pk_dir_buf) != 0) {
            TRACE_ERROR("MK_USER filename buffer overflow\n");
            return CKR_FUNCTION_FAILED;
        }
        if (unlink(fname) && errno == ENOENT)
            TRACE_WARNING("Failed to remove \"%s\".\n", fname);

        /* Load master key */
        if (ock_snprintf(fname, PATH_MAX, "%s/MK_SO", pk_dir_buf) != 0) {
            TRACE_ERROR("MK_SO filename buffer overflow\n");
            return CKR_FUNCTION_FAILED;
        }
        if (get_masterkey(tokdata, pin, pin_len, fname, mk, &mk_len)) {
            TRACE_DEVEL("Failed to load masterkey \"%s\".\n", fname);
            return CKR_FUNCTION_FAILED;
        }

        /* Load RACF password */
        if (get_racf(tokdata, mk, mk_len, racf_pass, &racf_pass_len)) {
            TRACE_DEVEL("Failed to get RACF password.\n");
            return CKR_FUNCTION_FAILED;
        }

        /* Generate new key */
        if (get_randombytes(mk, mk_len)) {
            TRACE_DEVEL("Failed to generate new master key.\n");
            return CKR_FUNCTION_FAILED;
        }

        if ((tokdata->statistics->flags & STATISTICS_FLAG_COUNT_INTERNAL) != 0)
            tokdata->statistics->increment_func(tokdata->statistics,
                                                tokdata->slot_id,
                                                &tokdata->store_strength.mk_keygen,
                                                tokdata->store_strength.mk_strength);

        /* Save racf password using the new master key */
        if (secure_racf(tokdata, racf_pass, racf_pass_len, mk, mk_len)) {
            TRACE_DEVEL("Failed to save racf password.\n");
            return CKR_FUNCTION_FAILED;
        }
    }

    /* Reset token data and keep token name */
    slot_data[slot_id]->initialized = 0;
    load_token_data(tokdata, slot_id);
    init_slotInfo(&tokdata->slot_info);
    tokdata->nv_token_data->token_info.flags |= CKF_TOKEN_INITIALIZED;
    tokdata->nv_token_data->token_info.flags &= ~(CKF_USER_PIN_INITIALIZED |
            CKF_USER_PIN_LOCKED | CKF_USER_PIN_FINAL_TRY |
            CKF_USER_PIN_COUNT_LOW);

    if (slot_data[slot_id]->mech == ICSF_CFG_MECH_SIMPLE) {
        /* Save master key */
        if (secure_masterkey(tokdata, mk, mk_len, pin, pin_len, fname)) {
            TRACE_DEVEL("Failed to save the new master key.\n");
            return CKR_FUNCTION_FAILED;
        }
    }

    if (save_token_data(tokdata, slot_id)) {
        TRACE_DEVEL("Failed to save token data.\n");
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

CK_RV destroy_objects(STDLL_TokData_t * tokdata, CK_SLOT_ID slot_id,
                      CK_CHAR_PTR token_name, CK_CHAR_PTR pin, CK_ULONG pin_len)
{
    CK_RV rv = CKR_OK;
    LDAP *ld = NULL;
    struct icsf_object_record records[16];
    struct icsf_object_record *previous = NULL;
    size_t i, records_len;
    int reason = 0;
    int rc;

    if (login(tokdata, &ld, slot_id, pin, pin_len, RACFFILE))
        return CKR_FUNCTION_FAILED;

    TRACE_DEVEL("Destroying objects in slot %lu.\n", slot_id);
    do {
        records_len = sizeof(records) / sizeof(records[0]);

        rc = icsf_list_objects(ld, NULL, (char *)token_name, 0, NULL,
                               previous, records, &records_len, 0);
        if (ICSF_RC_IS_ERROR(rc)) {
            TRACE_DEVEL("Failed to list objects for slot %lu.\n", slot_id);
            rv = CKR_FUNCTION_FAILED;
            goto done;
        }

        for (i = 0; i < records_len; i++) {
            if ((rc = icsf_destroy_object(ld, &reason, &records[i]))) {
                TRACE_DEVEL("Failed to destroy object "
                            "%s/%lu/%c in slot %lu.\n",
                            records[i].token_name,
                            records[i].sequence, records[i].id, slot_id);
                rv = icsf_to_ock_err(rc, reason);
                goto done;
            }
        }

        if (records_len)
            previous = &records[records_len - 1];
    } while (records_len);

done:
    if (icsf_logout(ld) && rv == CKR_OK)
        rv = CKR_FUNCTION_FAILED;

    return rv;
}

/*
 * Initialize token.
 */
CK_RV icsftok_init_token(STDLL_TokData_t * tokdata, CK_SLOT_ID slot_id,
                         CK_CHAR_PTR pin, CK_ULONG pin_len, CK_CHAR_PTR label)
{
    CK_RV rc = CKR_OK;
    CK_BYTE hash_sha[SHA1_HASH_SIZE];
    CK_CHAR token_name[sizeof(tokdata->nv_token_data->token_info.label) + 1];

    UNUSED(label);

    /* Check pin */
    rc = compute_sha1(tokdata, pin, pin_len, hash_sha);
    if (rc != CKR_OK)
        goto done;
    if (memcmp(tokdata->nv_token_data->so_pin_sha, hash_sha,
               SHA1_HASH_SIZE) != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_PIN_INCORRECT));
        rc = CKR_PIN_INCORRECT;
        goto done;
    }

    if ((rc = reset_token_data(tokdata, slot_id, pin, pin_len)))
        goto done;

    strunpad((char *)token_name,
             (const char *)tokdata->nv_token_data->token_info.label,
             sizeof(tokdata->nv_token_data->token_info.label), ' ');

    if ((rc = destroy_objects(tokdata, slot_id, token_name, pin, pin_len)))
        goto done;

    /* purge the object btree */
    if (purge_object_mapping(tokdata)) {
        TRACE_DEVEL("Failed to purge objects.\n");
        rc = CKR_FUNCTION_FAILED;
    }

done:
    return rc;
}

CK_RV icsftok_init_pin(STDLL_TokData_t * tokdata, SESSION * sess,
                       CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    CK_RV rc = CKR_OK;
    CK_BYTE hash_sha[SHA1_HASH_SIZE];
    CK_SLOT_ID sid;
    char fname[PATH_MAX];
    char pk_dir_buf[PATH_MAX];

    /* get slot id */
    sid = sess->session_info.slotID;

    /* compute the SHA of the user pin */
    rc = compute_sha1(tokdata, pPin, ulPinLen, hash_sha);
    if (rc != CKR_OK) {
        TRACE_ERROR("Hash Computation Failed.\n");
        return rc;
    }

    /* encrypt the masterkey and store in MK_USER if using SIMPLE AUTH
     * to authenticate to ldao server. The masterkey protects the
     * racf passwd.
     */
    if (slot_data[sid]->mech == ICSF_CFG_MECH_SIMPLE) {
        if (get_pk_dir(tokdata, pk_dir_buf, PATH_MAX) == NULL) {
            TRACE_ERROR("pk_dir_buf overflow\n");
            return CKR_FUNCTION_FAILED;
        }
        if (ock_snprintf(fname, PATH_MAX, "%s/MK_USER", pk_dir_buf) != 0) {
            TRACE_ERROR("MK_USER filename buffer overflow\n");
            return CKR_FUNCTION_FAILED;
        }

        rc = secure_masterkey(tokdata, tokdata->master_key,
                              AES_KEY_SIZE_256, pPin, ulPinLen, fname);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Could not create MK_USER.\n");
            return rc;
        }
    }

    rc = XProcLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to get process lock.\n");
        return rc;
    }

    memcpy(tokdata->nv_token_data->user_pin_sha, hash_sha, SHA1_HASH_SIZE);
    tokdata->nv_token_data->token_info.flags |= CKF_USER_PIN_INITIALIZED;
    tokdata->nv_token_data->token_info.flags &= ~(CKF_USER_PIN_TO_BE_CHANGED);
    tokdata->nv_token_data->token_info.flags &= ~(CKF_USER_PIN_LOCKED);

    rc = XProcUnLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Process Lock Failed.\n");
        return rc;
    }

    return rc;
}

CK_RV icsftok_set_pin(STDLL_TokData_t * tokdata, SESSION * sess,
                      CK_CHAR_PTR pOldPin, CK_ULONG ulOldLen,
                      CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
    CK_RV rc = CKR_OK;
    CK_BYTE new_hash_sha[SHA1_HASH_SIZE];
    CK_BYTE old_hash_sha[SHA1_HASH_SIZE];
    CK_SLOT_ID sid;
    char fname[PATH_MAX];

    /* get slot id */
    sid = sess->session_info.slotID;

    rc = compute_sha1(tokdata, pNewPin, ulNewLen, new_hash_sha);
    rc |= compute_sha1(tokdata, pOldPin, ulOldLen, old_hash_sha);
    if (rc != CKR_OK) {
        TRACE_ERROR("Hash Computation Failed.\n");
        return rc;
    }

    /* check that the old pin  and new pin are not the same. */
    if (memcmp(old_hash_sha, new_hash_sha, SHA1_HASH_SIZE) == 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_PIN_INVALID));
        return CKR_PIN_INVALID;
    }

    /* check the length requirements */
    if ((ulNewLen < MIN_PIN_LEN) || (ulNewLen > MAX_PIN_LEN)) {
        TRACE_ERROR("%s\n", ock_err(ERR_PIN_LEN_RANGE));
        return CKR_PIN_LEN_RANGE;
    }

    if ((sess->session_info.state == CKS_RW_USER_FUNCTIONS) ||
        (sess->session_info.state == CKS_RW_PUBLIC_SESSION)) {
        /* check that old pin matches what is in NVTOK.DAT */
        if (memcmp
            (tokdata->nv_token_data->user_pin_sha, old_hash_sha,
             SHA1_HASH_SIZE) != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_PIN_INCORRECT));
            return CKR_PIN_INCORRECT;
        }
        /* if using simple auth, encrypt masterkey with new pin */
        if (slot_data[sid]->mech == ICSF_CFG_MECH_SIMPLE) {
            if (get_pk_dir(tokdata, fname, PATH_MAX) == NULL) {
                TRACE_ERROR("pk_dir buffer overflow\n");
                return CKR_FUNCTION_FAILED;
            }
            if (PATH_MAX - strlen(fname) > strlen("/MK_USER")) {
                strcat(fname, "/MK_USER");
            } else {
                TRACE_ERROR("MK_USER buffer overflow\n");
                return CKR_FUNCTION_FAILED;
            }
            rc = secure_masterkey(tokdata, tokdata->master_key,
                                  AES_KEY_SIZE_256, pNewPin, ulNewLen, fname);
            if (rc != CKR_OK) {
                TRACE_ERROR("Save Master Key Failed.\n");
                return rc;
            }
        }

        /* grab lock and change shared memory */
        rc = XProcLock(tokdata);
        if (rc != CKR_OK) {
            TRACE_ERROR("Process Lock Failed.\n");
            return rc;
        }

        memcpy(tokdata->nv_token_data->user_pin_sha, new_hash_sha,
               SHA1_HASH_SIZE);
        tokdata->nv_token_data->token_info.flags &=
            ~(CKF_USER_PIN_TO_BE_CHANGED);

        rc = XProcUnLock(tokdata);
        if (rc != CKR_OK) {
            TRACE_ERROR("Process Lock Failed.\n");
            return rc;
        }

    } else if (sess->session_info.state == CKS_RW_SO_FUNCTIONS) {

        /* check that old pin matches what is in NVTOK.DAT */
        if (memcmp
            (tokdata->nv_token_data->so_pin_sha, old_hash_sha,
             SHA1_HASH_SIZE) != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_PIN_INCORRECT));
            return CKR_PIN_INCORRECT;
        }

        /* check that new pin is not the default */
        if (memcmp(new_hash_sha, default_so_pin_sha, SHA1_HASH_SIZE) == 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_PIN_INVALID));
            return CKR_PIN_INVALID;
        }

        if (slot_data[sid]->mech == ICSF_CFG_MECH_SIMPLE) {
            /*
             * if using simle auth, encrypt masterkey with new pin
             */
            if (get_pk_dir(tokdata, fname, PATH_MAX) == NULL) {
                TRACE_ERROR("pk_dir buffer overflow\n");
                return CKR_FUNCTION_FAILED;
            }
            if (PATH_MAX - strlen(fname) > strlen("/MK_SO")) {
                strcat(fname, "/MK_SO");
            } else {
                TRACE_ERROR("MK_SO buffer overflow\n");
                return CKR_FUNCTION_FAILED;
            }

            rc = secure_masterkey(tokdata, tokdata->master_key,
                                  AES_KEY_SIZE_256, pNewPin, ulNewLen, fname);
            if (rc != CKR_OK) {
                TRACE_ERROR("Save Master Key Failed.\n");
                return rc;
            }
        }

        /* grab lock and change shared memory */
        rc = XProcLock(tokdata);
        if (rc != CKR_OK) {
            TRACE_ERROR("Process Lock Failed.\n");
            return rc;
        }

        memcpy(tokdata->nv_token_data->so_pin_sha, new_hash_sha,
               SHA1_HASH_SIZE);
        tokdata->nv_token_data->token_info.flags &= ~(CKF_SO_PIN_TO_BE_CHANGED);

        rc = XProcUnLock(tokdata);
        if (rc != CKR_OK) {
            TRACE_ERROR("Process Lock Failed.\n");
            return rc;
        }
    } else {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_READ_ONLY));
        return CKR_SESSION_READ_ONLY;
    }

    rc = save_token_data(tokdata, sid);
    if (rc != CKR_OK) {
        TRACE_ERROR("Save Token Failed.\n");
        return rc;
    }

    return rc;
}

LDAP *getLDAPhandle(STDLL_TokData_t * tokdata, CK_SLOT_ID slot_id)
{
    CK_BYTE racfpwd[PIN_SIZE];
    int racflen;
    char *ca_dir = NULL;
    LDAP *new_ld = NULL;
    CK_RV rc = CKR_OK;

    if (slot_data[slot_id] == NULL) {
        TRACE_ERROR("ICSF slot data not initialized.\n");
        return NULL;
    }
    /* Check if using sasl or simple auth */
    if (slot_data[slot_id]->mech == ICSF_CFG_MECH_SIMPLE) {
        TRACE_INFO("Using SIMPLE auth with slot ID: %lu\n", slot_id);
        /* get racf passwd */
        rc = get_racf(tokdata, tokdata->master_key, AES_KEY_SIZE_256,
                      racfpwd, &racflen);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Failed to get racf passwd.\n");
            return NULL;
        }

        /* ok got the passwd, perform simple ldap bind call */
        rc = icsf_login(&new_ld, slot_data[slot_id]->uri,
                        slot_data[slot_id]->dn, (char *)racfpwd);
        if (rc != 0) {
            TRACE_DEVEL("Failed to bind to ldap server.\n");
            return NULL;
        }
    } else {
        TRACE_INFO("Using SASL auth with slot ID: %lu\n", slot_id);
        rc = icsf_sasl_login(&new_ld, slot_data[slot_id]->uri,
                             slot_data[slot_id]->cert_file,
                             slot_data[slot_id]->key_file,
                             slot_data[slot_id]->ca_file, ca_dir);
        if (rc != 0) {
            TRACE_DEVEL("Failed to bind to ldap server.\n");
            return NULL;
        }
    }

    return new_ld;
}

CK_RV icsf_get_handles(STDLL_TokData_t * tokdata, CK_SLOT_ID slot_id)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    struct session_state *s;

    /* Any prior sessions without an ldap descriptor, can now get one. */
    /* Lock sessions list */
    if (pthread_mutex_lock(&icsf_data->sess_list_mutex)) {
        TRACE_ERROR("Failed to lock mutex.\n");
        return CKR_FUNCTION_FAILED;
    }

    for_each_list_entry(&icsf_data->sessions, struct session_state, s,
                        sessions) {
        if (s->ld == NULL)
            s->ld = getLDAPhandle(tokdata, slot_id);
    }

    if (pthread_mutex_unlock(&icsf_data->sess_list_mutex)) {
        TRACE_ERROR("Mutex Unlock failed.\n");
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

CK_RV icsftok_open_session(STDLL_TokData_t * tokdata, SESSION * sess)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    CK_RV rc = CKR_OK;
    LDAP *ld;
    struct session_state *session_state;

    /* Sanity */
    if (sess == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
        return CKR_FUNCTION_FAILED;
    }

    /* Add session to list */
    session_state = malloc(sizeof(struct session_state));
    if (!session_state) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_FUNCTION_FAILED;
    }
    session_state->session_id = sess->handle;
    session_state->ld = NULL;

    if (pthread_mutex_lock(&icsf_data->sess_list_mutex)) {
        TRACE_ERROR("Failed to lock mutex.\n");
        free(session_state);
        return CKR_FUNCTION_FAILED;
    }
    /* see if user has logged in to acquire ldap handle for session.
     * pkcs#11v2.2 states that all sessions within a process have
     * same login state.
     */
    if (session_mgr_user_session_exists(tokdata)) {
        ld = getLDAPhandle(tokdata, sess->session_info.slotID);
        if (ld == NULL) {
            TRACE_DEVEL("Failed to get LDAP handle for session.\n");
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
        /* put the new ldap handle into the session state. */
        session_state->ld = ld;
    }

    /* put new session_state into the list */
    list_insert_head(&icsf_data->sessions, &session_state->sessions);

done:
    /* Unlock */
    if (pthread_mutex_unlock(&icsf_data->sess_list_mutex)) {
        TRACE_ERROR("Mutex Unlock Failed.\n");
        rc = CKR_FUNCTION_FAILED;
    }

    if (rc != CKR_OK)
        free(session_state);

    return rc;
}

/*
 * Close a session.
 *
 * Must be called with sess_list_mutex locked.
 */
static CK_RV close_session(STDLL_TokData_t * tokdata,
                           struct session_state *session_state,
                           CK_BBOOL in_fork_initializer)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    CK_RV rc = CKR_OK;
    unsigned long i;
    int reason = 0;

    /* Remove each session object */
    for (i = 1; i <= icsf_data->objects.size; i++) {
        struct icsf_object_mapping *mapping;

        /* Skip missing ids */
        if (!(mapping = bt_get_node_value(&icsf_data->objects, i)))
            continue;

        /* Skip object from other sessions */
        if (mapping->session_id != session_state->session_id) {
            bt_put_node_value(&icsf_data->objects, mapping);
            mapping = NULL;
            continue;
        }

        /* Skip token objects */
        if (mapping->icsf_object.id != ICSF_SESSION_OBJECT) {
            bt_put_node_value(&icsf_data->objects, mapping);
            mapping = NULL;
            continue;
        }

        if ((rc = icsf_destroy_object(session_state->ld, &reason,
                                      &mapping->icsf_object))) {
            /* Log error */
            TRACE_DEBUG("Failed to remove icsf object: %s/%lu/%c",
                        mapping->icsf_object.token_name,
                        mapping->icsf_object.sequence, mapping->icsf_object.id);
            rc = icsf_to_ock_err(rc, reason);
            bt_put_node_value(&icsf_data->objects, mapping);
            mapping = NULL;
            break;
        }

        bt_put_node_value(&icsf_data->objects, mapping);
        mapping = NULL;

        /* Remove object from object list */
        bt_node_free(&icsf_data->objects, i, TRUE);
    }
    if (rc)
        return rc;

    /* Log off from LDAP server */
    if (session_state->ld) {
        if (!in_fork_initializer && icsf_logout(session_state->ld)) {
            TRACE_DEVEL("Failed to disconnect from LDAP server.\n");
            return CKR_FUNCTION_FAILED;
        }
        session_state->ld = NULL;
    }

    /* Remove session */
    list_remove(&session_state->sessions);
    if (list_is_empty(&icsf_data->sessions)) {
        if (purge_object_mapping(tokdata)) {
            TRACE_DEVEL("Failed to purge objects.\n");
            rc = CKR_FUNCTION_FAILED;
        }
    }
    free(session_state);

    return rc;
}

/*
 * Called during C_CloseSession.
 */
CK_RV icsftok_close_session(STDLL_TokData_t * tokdata, SESSION * session,
                            CK_BBOOL in_fork_initializer)
{
    CK_RV rc;
    struct session_state *session_state;

    /* Get the related session_state */
    if (session == NULL
        || !(session_state = get_session_state(tokdata, session->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        return CKR_SESSION_HANDLE_INVALID;
    }

    if ((rc = close_session(tokdata, session_state, in_fork_initializer)))
        TRACE_ERROR("close_session failed\n");

    return rc;
}

/*
 * Called during C_Finalize and C_CloseAllSessions
 */
CK_RV icsftok_final(STDLL_TokData_t * tokdata, CK_BBOOL finalize,
                    CK_BBOOL in_fork_initializer)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    CK_RV rc = CKR_OK;
    struct session_state *session_state;
    list_entry_t *e;

    /* Lock to add a new session in the list */
    if (pthread_mutex_lock(&icsf_data->sess_list_mutex)) {
        TRACE_ERROR("Failed to lock mutex.\n");
        return CKR_FUNCTION_FAILED;
    }

    for_each_list_entry_safe(&icsf_data->sessions, struct session_state,
                             session_state, sessions, e) {
        if ((rc = close_session(tokdata, session_state, in_fork_initializer)))
            break;
    }

    /* Unlock */
    if (pthread_mutex_unlock(&icsf_data->sess_list_mutex)) {
        TRACE_ERROR("Mutex Unlock Failed.\n");
        return CKR_FUNCTION_FAILED;
    }

    if (finalize) {
        bt_destroy(&icsf_data->objects);
        pthread_mutex_destroy(&icsf_data->sess_list_mutex);
        free(icsf_data);
        tokdata->private_data = NULL;
        free(tokdata->mech_list);
    }

    return rc;
}

CK_RV icsftok_login(STDLL_TokData_t * tokdata, SESSION * sess,
                    CK_USER_TYPE userType, CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    CK_RV rc = CKR_OK;
    char fname[PATH_MAX];
    CK_BYTE hash_sha[SHA1_HASH_SIZE];
    int mklen;
    CK_SLOT_ID slot_id = sess->session_info.slotID;

    /* Check Slot ID */
    if (slot_id >= NUMBER_SLOTS_MANAGED) {
        TRACE_ERROR("Invalid slot ID: %lu\n", slot_id);
        return CKR_FUNCTION_FAILED;
    }

    /* compute the sha of the pin. */
    rc = compute_sha1(tokdata, pPin, ulPinLen, hash_sha);
    if (rc != CKR_OK) {
        TRACE_ERROR("Hash Computation Failed.\n");
        return rc;
    }

    rc = XProcLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Process Lock Failed.\n");
        return rc;
    }

    if (userType == CKU_USER) {
        /* check if pin initialized */
        if (memcmp(tokdata->nv_token_data->user_pin_sha,
                   "00000000000000000000", SHA1_HASH_SIZE) == 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_USER_PIN_NOT_INITIALIZED));
            rc = CKR_USER_PIN_NOT_INITIALIZED;
            goto done;
        }

        /* check that pin is the same as the one in NVTOK.DAT */
        if (memcmp(tokdata->nv_token_data->user_pin_sha, hash_sha,
                   SHA1_HASH_SIZE) != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_PIN_INCORRECT));
            rc = CKR_PIN_INCORRECT;
            goto done;
        }

        /* now load the master key */
        if (slot_data[slot_id]->mech == ICSF_CFG_MECH_SIMPLE) {
            if (get_pk_dir(tokdata, fname, PATH_MAX) == NULL) {
                TRACE_ERROR("pk_dir buffer overflow\n");
                rc = CKR_FUNCTION_FAILED;
                goto done;
            }
            if (PATH_MAX - strlen(fname) > strlen("/MK_USER")) {
                strcat(fname, "/MK_USER");
            } else {
                TRACE_ERROR("MK_USER buffer overflow\n");
                rc = CKR_FUNCTION_FAILED;
                goto done;
            }
            rc = get_masterkey(tokdata, pPin, ulPinLen, fname,
                               tokdata->master_key, &mklen);
            if (rc != CKR_OK) {
                TRACE_DEVEL("Failed to load master key.\n");
                goto done;
            }
        }
    } else {
        /* if SO ... */

        /* check that pin is the same as the one in NVTOK.DAT */
        if (memcmp(tokdata->nv_token_data->so_pin_sha, hash_sha,
                   SHA1_HASH_SIZE) != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_PIN_INCORRECT));
            rc = CKR_PIN_INCORRECT;
            goto done;
        }

        if (slot_data[slot_id]->mech == ICSF_CFG_MECH_SIMPLE) {
            /* now load the master key */
            if (get_pk_dir(tokdata, fname, PATH_MAX) == NULL) {
                TRACE_ERROR("pk_dir buffer overflow\n");
                rc = CKR_FUNCTION_FAILED;
                goto done;
            }
            if (PATH_MAX - strlen(fname) > strlen("/MK_SO")) {
                strcat(fname, "/MK_SO");
            } else {
                TRACE_ERROR("MK_SO buffer overflow\n");
                rc = CKR_FUNCTION_FAILED;
                goto done;
            }
            rc = get_masterkey(tokdata, pPin, ulPinLen, fname,
                               tokdata->master_key, &mklen);
            if (rc != CKR_OK) {
                TRACE_DEVEL("Failed to load master key.\n");
                goto done;
            }
        }
    }
    /* Now that user is authenticated, can get racf passwd and
     * establish ldap handle for session. This will get done
     * when we call icsf_get_handles() in SC_Login().
     */
done:
    if (rc == CKR_OK)
        rc = XProcUnLock(tokdata);
    else
        XProcUnLock(tokdata);

    return rc;
}

static CK_RV check_session_permissions(SESSION * sess, CK_ATTRIBUTE * attrs,
                                       CK_ULONG attrs_len)
{
    CK_RV rc = CKR_OK;
    /* PKCS#11 default value for CKA_TOKEN is FALSE */
    CK_BBOOL is_token_obj = FALSE;
    /* ICSF default value for CKA_PRIVATE is TRUE */
    CK_BBOOL is_priv_obj = TRUE;

    /* Get attributes values */
    find_bbool_attribute(attrs, attrs_len, CKA_TOKEN, &is_token_obj);
    find_bbool_attribute(attrs, attrs_len, CKA_PRIVATE, &is_priv_obj);

    /*
     * Check whether session has permissions to create the object, etc
     *
     * Object                  R/O      R/W      R/O     R/W    R/W
     * Type                   Public   Public    User    User   SO
     * -------------------------------------------------------------
     * Public session          R/W      R/W      R/W     R/W    R/W
     * Private session                           R/W     R/W
     * Public token            R/O      R/W      R/O     R/W    R/W
     * Private token                             R/O     R/W
     */

    if (sess->session_info.state == CKS_RO_PUBLIC_SESSION) {
        if (is_priv_obj) {
            TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
            rc = CKR_USER_NOT_LOGGED_IN;
            goto done;
        }
        if (is_token_obj) {
            TRACE_ERROR("%s\n", ock_err(ERR_SESSION_READ_ONLY));
            rc = CKR_SESSION_READ_ONLY;
            goto done;
        }
    }

    if (sess->session_info.state == CKS_RO_USER_FUNCTIONS) {
        if (is_token_obj) {
            TRACE_ERROR("%s\n", ock_err(ERR_SESSION_READ_ONLY));
            rc = CKR_SESSION_READ_ONLY;
            goto done;
        }
    }

    if (sess->session_info.state == CKS_RW_PUBLIC_SESSION) {
        if (is_priv_obj) {
            TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
            rc = CKR_USER_NOT_LOGGED_IN;
            goto done;
        }
    }

    if (sess->session_info.state == CKS_RW_SO_FUNCTIONS) {
        if (is_priv_obj) {
            TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
            rc = CKR_USER_NOT_LOGGED_IN;
            goto done;
        }
    }

done:
    return rc;
}

/*
 * Copy an existing object.
 */
CK_RV icsftok_copy_object(STDLL_TokData_t * tokdata,
                          SESSION * session, CK_ATTRIBUTE_PTR attrs,
                          CK_ULONG attrs_len, CK_OBJECT_HANDLE src,
                          CK_OBJECT_HANDLE_PTR dst)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    CK_RV rc = CKR_OK;
    struct session_state *session_state;
    struct icsf_object_mapping *mapping_dst = NULL;
    struct icsf_object_mapping *mapping_src = NULL;
    CK_ULONG node_number;
    int reason = 0;

    CK_BBOOL is_priv;
    CK_BBOOL is_token;
    CK_RV rc_permission = CKR_OK;

    CK_ATTRIBUTE priv_attrs[] = {
        {CKA_PRIVATE, &is_priv, sizeof(is_priv)}
        ,
        {CKA_TOKEN, &is_token, sizeof(is_token)}
        ,
    };

    CK_ATTRIBUTE_PTR temp_attrs;

    /* Get session state */
    if (!(session_state = get_session_state(tokdata, session->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        rc = CKR_SESSION_HANDLE_INVALID;
        goto done;
    }

    /* check ldap handle */
    if (session_state->ld == NULL) {
        TRACE_ERROR("No LDAP handle.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Allocate structure for new object */
    if (!(mapping_dst = malloc(sizeof(*mapping_dst)))) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    mapping_src = bt_get_node_value(&icsf_data->objects, src);
    if (!mapping_src) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_OBJECT_HANDLE_INVALID;
        goto done;
    }

    rc = icsf_get_attribute(session_state->ld, &reason,
                            &mapping_src->icsf_object, priv_attrs, 2);
    if (rc != CKR_OK) {
        TRACE_ERROR("icsf_get_attribute failed\n");
        goto done;
    }

    if (attrs_len != 0) {
        /* looking for CKA_PRIVATE */
        temp_attrs = get_attribute_by_type(attrs, attrs_len, CKA_PRIVATE);
        if (temp_attrs != NULL) {
            priv_attrs[0].pValue = temp_attrs->pValue;
            priv_attrs[0].ulValueLen = temp_attrs->ulValueLen;
        }

        /* looking for CKA_TOKEN */
        temp_attrs = get_attribute_by_type(attrs, attrs_len, CKA_TOKEN);
        if (temp_attrs != NULL) {
            priv_attrs[1].pValue = temp_attrs->pValue;
            priv_attrs[1].ulValueLen = attrs->ulValueLen;
        }
    }

    /* Check permissions based on attributes and session */
    rc = check_session_permissions(session, priv_attrs, 2);
    if (rc_permission != CKR_OK) {
        TRACE_DEVEL("check_session_permissions failed\n");
        goto done;
    }

    /* Call ICSF service */
    rc = icsf_copy_object(session_state->ld, &reason, attrs, attrs_len,
                          &mapping_src->icsf_object, &mapping_dst->icsf_object);
    if (rc != 0) {
        TRACE_DEVEL("Failed to Copy object.\n");
        rc = icsf_to_ock_err(rc, reason);
        goto done;
    }

    /* Add info about object into session */
    if (!(node_number = bt_node_add(&icsf_data->objects, mapping_dst))) {
        TRACE_ERROR("Failed to add object to binary tree.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    memcpy(&mapping_dst->strength, &mapping_src->strength,
           sizeof(struct objstrength));

    /* Use node number as handle */
    *dst = node_number;

done:
    if (mapping_src) {
        bt_put_node_value(&icsf_data->objects, mapping_src);
        mapping_src = NULL;
    }

    /* If allocated, object must be freed in case of failure */
    if (rc && mapping_dst)
        free(mapping_dst);

    return rc;
}

/*
 * Create a new object.
 */
CK_RV icsftok_create_object(STDLL_TokData_t * tokdata, SESSION * session,
                            CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len,
                            CK_OBJECT_HANDLE_PTR handle)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    CK_RV rc = CKR_OK;
    struct session_state *session_state;
    struct icsf_object_mapping *mapping;
    CK_ULONG node_number;
    char token_name[sizeof(tokdata->nv_token_data->token_info.label) + 1];
    int reason = 0;
    struct icsf_policy_attr pattr;

    /* Check permissions based on attributes and session */
    rc = check_session_permissions(session, attrs, attrs_len);
    if (rc != CKR_OK)
        return rc;

    /* Copy token name from shared memory */
    rc = XProcLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to get process lock.\n");
        return rc;
    }

    strunpad(token_name, (const char *)tokdata->nv_token_data->token_info.label,
             sizeof(tokdata->nv_token_data->token_info.label), ' ');

    rc = XProcUnLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to release process lock.\n");
        return rc;
    }

    /* Allocate structure to keep ICSF object information */
    if (!(mapping = malloc(sizeof(*mapping)))) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }
    memset(mapping, 0, sizeof(struct icsf_object_mapping));
    mapping->session_id = session->handle;

    /* Get session state */
    if (!(session_state = get_session_state(tokdata, session->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        rc = CKR_SESSION_HANDLE_INVALID;
        goto done;
    }

    /* check ldap handle */
    if (session_state->ld == NULL) {
        TRACE_ERROR("No LDAP handle.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Call ICSF service */
    if ((rc = icsf_create_object(session_state->ld, &reason, token_name,
                                 attrs, attrs_len, &mapping->icsf_object))) {
        TRACE_DEVEL("icsf_create_object failed\n");
        rc = icsf_to_ock_err(rc, reason);
        goto done;
    }
    /* Policy check */
    pattr.ld = session_state->ld;
    pattr.icsf_object = &mapping->icsf_object;
    rc = tokdata->policy->store_object_strength(tokdata->policy,
                                                &mapping->strength,
                                                icsf_policy_get_attr, &pattr,
                                                icsf_policy_free_attr, session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: Object too weak\n");
        goto done;
    }

    /* Add info about object into session */
    if (!(node_number = bt_node_add(&icsf_data->objects, mapping))) {
        TRACE_ERROR("Failed to add object to binary tree.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Use node number as handle */
    *handle = node_number;

done:
    /* If allocated, object must be freed in case of failure */
    if (rc && mapping)
        free(mapping);

    return rc;
}

/*
 * Check if attribute values are valid and add default values for missing ones.
 *
 * It returns a new allocated array that must be freed with
 * free_attribute_array().
 */
static CK_RV check_key_attributes(CK_ULONG class, CK_ULONG key_type,
                                  CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len,
                                  CK_ATTRIBUTE_PTR * p_attrs,
                                  CK_ULONG * p_attrs_len)
{

    CK_RV rc;
    CK_ULONG i;
    CK_ULONG check_types[] = { CKA_CLASS, CKA_KEY_TYPE };
    CK_ULONG *check_values[] = { &class, &key_type };

    if ((rc = dup_attribute_array(attrs, attrs_len, p_attrs, p_attrs_len)))
        return rc;

    for (i = 0; i < sizeof(check_types) / sizeof(*check_types); i++) {
        /* Search for the attribute */
        CK_ATTRIBUTE_PTR attr = get_attribute_by_type(*p_attrs,
                                                      *p_attrs_len,
                                                      check_types[i]);
        if (attr) {
            /* Check the expected value */
            if (*((CK_ULONG *) attr->pValue) != *check_values[i]) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                rc = CKR_ATTRIBUTE_VALUE_INVALID;
                goto cleanup;
            }
        } else {
            /* Add default value */
            rc = add_to_attribute_array(p_attrs, p_attrs_len,
                                        check_types[i],
                                        (CK_BYTE *) check_values[i],
                                        sizeof(*check_values[i]));
            if (rc)
                goto cleanup;
        }
    }

    rc = CKR_OK;

cleanup:
    if (rc) {
        free_attribute_array(*p_attrs, *p_attrs_len);
        *p_attrs = NULL;
        *p_attrs_len = 0;
    }

    return rc;
}

/*
 * Get the type of the key that must be generated based on given mechanism.
 *
 * This functions is used by both symmetric and asymmetric key generation
 * functions.
 */
static CK_ULONG get_generate_key_type(CK_MECHANISM_PTR mech)
{
    switch (mech->mechanism) {
        /* Symmetric keys */
    case CKM_AES_KEY_GEN:
        return CKK_AES;
    case CKM_DES_KEY_GEN:
        return CKK_DES;
    case CKM_DES2_KEY_GEN:
        return CKK_DES2;
    case CKM_DES3_KEY_GEN:
        return CKK_DES3;
    case CKM_SSL3_PRE_MASTER_KEY_GEN:
    case CKM_TLS_PRE_MASTER_KEY_GEN:
        return CKK_GENERIC_SECRET;
        /* Asymmetric keys */
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        return CKK_RSA;
    case CKM_DSA_KEY_PAIR_GEN:
        return CKK_DSA;
    case CKM_DH_PKCS_KEY_PAIR_GEN:
    case CKM_DH_PKCS_DERIVE:
        return CKK_DH;
    case CKM_EC_KEY_PAIR_GEN:
        return CKK_EC;
    case CKM_SSL3_MASTER_KEY_DERIVE:
    case CKM_SSL3_KEY_AND_MAC_DERIVE:
    case CKM_TLS_KEY_AND_MAC_DERIVE:
    case CKM_GENERIC_SECRET_KEY_GEN:
        return CKK_GENERIC_SECRET;
    }

    return -1;
}

/*
 * Generate a key pair.
 */
CK_RV icsftok_generate_key_pair(STDLL_TokData_t * tokdata, SESSION * session,
                                CK_MECHANISM_PTR mech,
                                CK_ATTRIBUTE_PTR pub_attrs,
                                CK_ULONG pub_attrs_len,
                                CK_ATTRIBUTE_PTR priv_attrs,
                                CK_ULONG priv_attrs_len,
                                CK_OBJECT_HANDLE_PTR p_pub_key,
                                CK_OBJECT_HANDLE_PTR p_priv_key)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    CK_RV rc;
    char token_name[sizeof(tokdata->nv_token_data->token_info.label) + 1];
    struct session_state *session_state;
    struct icsf_object_mapping *pub_key_mapping = NULL;
    struct icsf_object_mapping *priv_key_mapping = NULL;
    int reason = 0;
    int pub_node_number, priv_node_number;
    CK_ATTRIBUTE_PTR new_pub_attrs = NULL;
    CK_ULONG new_pub_attrs_len = 0;
    CK_ATTRIBUTE_PTR new_priv_attrs = NULL;
    CK_ULONG new_priv_attrs_len = 0;
    CK_ULONG key_type;
    struct icsf_policy_attr pattr;

    /* Check and set default attributes based on mech */
    if ((key_type = get_generate_key_type(mech)) == (CK_ULONG)-1) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }
    rc = check_key_attributes(CKO_PUBLIC_KEY, key_type, pub_attrs,
                              pub_attrs_len, &new_pub_attrs,
                              &new_pub_attrs_len);
    if (rc != CKR_OK)
        goto done;

    rc = check_key_attributes(CKO_PRIVATE_KEY, key_type, priv_attrs,
                              priv_attrs_len, &new_priv_attrs,
                              &new_priv_attrs_len);
    if (rc != CKR_OK)
        goto done;

    /* Check permissions based on attributes and session */
    rc = check_session_permissions(session, new_pub_attrs, new_pub_attrs_len);
    if (rc != CKR_OK)
        goto done;
    rc = check_session_permissions(session, new_priv_attrs, new_priv_attrs_len);
    if (rc != CKR_OK)
        goto done;

    /* Get session state */
    if (!(session_state = get_session_state(tokdata, session->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        rc = CKR_SESSION_HANDLE_INVALID;
        goto done;
    }

    /* check ldap handle */
    if (session_state->ld == NULL) {
        TRACE_ERROR("No LDAP handle.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Copy token name from shared memory */
    rc = XProcLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to get process lock.\n");
        goto done;
    }

    strunpad(token_name, (const char *)tokdata->nv_token_data->token_info.label,
             sizeof(tokdata->nv_token_data->token_info.label), ' ');

    rc = XProcUnLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to release process lock.\n");
        goto done;
    }

    /* Allocate structure to keep ICSF objects information */
    if (!(pub_key_mapping = malloc(sizeof(*pub_key_mapping))) ||
        !(priv_key_mapping = malloc(sizeof(*priv_key_mapping)))) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    /* Call ICSF service */
    if ((rc = icsf_generate_key_pair(session_state->ld, &reason, token_name,
                                     new_pub_attrs, new_pub_attrs_len,
                                     new_priv_attrs, new_priv_attrs_len,
                                     &pub_key_mapping->icsf_object,
                                     &priv_key_mapping->icsf_object))) {
        TRACE_DEVEL("icsf_generate_key_pair failed\n");
        rc = icsf_to_ock_err(rc, reason);
        goto done;
    }
    pattr.ld = session_state->ld;
    pattr.icsf_object = &pub_key_mapping->icsf_object;
    rc = tokdata->policy->store_object_strength(tokdata->policy,
                                                &pub_key_mapping->strength,
                                                icsf_policy_get_attr, &pattr,
                                                icsf_policy_free_attr, session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: Public key too weak\n");
        goto done;
    }
    pattr.icsf_object = &priv_key_mapping->icsf_object;
    rc = tokdata->policy->store_object_strength(tokdata->policy,
                                                &priv_key_mapping->strength,
                                                icsf_policy_get_attr, &pattr,
                                                icsf_policy_free_attr, session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: Private key too weak\n");
        goto done;
    }

    /* Add info about objects into session */
    if (!(pub_node_number = bt_node_add(&icsf_data->objects, pub_key_mapping)) ||
        !(priv_node_number = bt_node_add(&icsf_data->objects, priv_key_mapping))) {
        TRACE_ERROR("Failed to add object to binary tree.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Use node numbers as handles */
    *p_pub_key = pub_node_number;
    *p_priv_key = priv_node_number;

done:
    if (rc == CKR_OK && tokdata->statistics->increment_func != NULL)
        tokdata->statistics->increment_func(tokdata->statistics,
                                            session->session_info.slotID,
                                            mech,
                                            priv_key_mapping->strength.strength);

    free_attribute_array(new_pub_attrs, new_pub_attrs_len);
    free_attribute_array(new_priv_attrs, new_priv_attrs_len);

    /* Object mappings must be freed in case of failure */
    if (rc && pub_key_mapping)
        free(pub_key_mapping);
    if (rc && priv_key_mapping)
        free(priv_key_mapping);

    return rc;
}

/*
 * Generate a symmetric key.
 */
CK_RV icsftok_generate_key(STDLL_TokData_t * tokdata, SESSION * session,
                           CK_MECHANISM_PTR mech, CK_ATTRIBUTE_PTR attrs,
                           CK_ULONG attrs_len, CK_OBJECT_HANDLE_PTR handle)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    CK_RV rc = CKR_OK;
    struct session_state *session_state;
    struct icsf_object_mapping *mapping = NULL;
    CK_ULONG node_number;
    char token_name[sizeof(tokdata->nv_token_data->token_info.label) + 1];
    CK_ATTRIBUTE_PTR new_attrs = NULL;
    CK_ULONG new_attrs_len = 0;
    CK_ULONG class = CKO_SECRET_KEY;
    CK_ULONG key_type = 0;
    int reason = 0;
    struct icsf_policy_attr pattr;

    /* Check attributes */
    if ((key_type = get_generate_key_type(mech)) == (CK_ULONG)-1) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    rc = check_key_attributes(class, key_type, attrs, attrs_len, &new_attrs,
                              &new_attrs_len);
    if (rc != CKR_OK)
        goto done;

    /* Check permissions based on attributes and session */
    rc = check_session_permissions(session, new_attrs, new_attrs_len);
    if (rc != CKR_OK)
        goto done;

    /* Copy token name from shared memory */
    rc = XProcLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to get process lock.\n");
        goto done;
    }

    strunpad(token_name, (const char *)tokdata->nv_token_data->token_info.label,
             sizeof(tokdata->nv_token_data->token_info.label), ' ');

    rc = XProcUnLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to release process lock.\n");
        goto done;
    }

    /* Allocate structure to keep ICSF object information */
    if (!(mapping = malloc(sizeof(*mapping)))) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        goto done;
    }
    memset(mapping, 0, sizeof(struct icsf_object_mapping));
    mapping->session_id = session->handle;

    /* Get session state */
    if (!(session_state = get_session_state(tokdata, session->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        rc = CKR_SESSION_HANDLE_INVALID;
        goto done;
    }

    /* check ldap handle */
    if (session_state->ld == NULL) {
        TRACE_ERROR("No LDAP handle.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Call ICSF service */
    if ((rc = icsf_generate_secret_key(session_state->ld, &reason, token_name,
                                       mech, new_attrs, new_attrs_len,
                                       &mapping->icsf_object))) {
        TRACE_DEVEL("icsf_generate_secret_key failed\n");
        rc = icsf_to_ock_err(rc, reason);
        goto done;
    }
    pattr.ld = session_state->ld;
    pattr.icsf_object = &mapping->icsf_object;
    rc = tokdata->policy->store_object_strength(tokdata->policy,
                                                &mapping->strength,
                                                icsf_policy_get_attr, &pattr,
                                                icsf_policy_free_attr, session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: Public key too weak\n");
        goto done;
    }

    /* Add info about object into session */
    if (!(node_number = bt_node_add(&icsf_data->objects, mapping))) {
        TRACE_ERROR("Failed to add object to binary tree.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Use node number as handle */
    *handle = node_number;

done:
    if (rc == CKR_OK && tokdata->statistics->increment_func != NULL &&
        mapping != NULL)
        tokdata->statistics->increment_func(tokdata->statistics,
                                            session->session_info.slotID,
                                            mech, mapping->strength.strength);

    if (new_attrs)
        free_attribute_array(new_attrs, new_attrs_len);

    /* If allocated, object must be freed in case of failure */
    if (rc && mapping)
        free(mapping);

    return rc;
}

/*
 * Free all data pointed by an encryption context and set everything to zero.
 */
static void free_encr_ctx(ENCR_DECR_CONTEXT * encr_ctx)
{
    struct icsf_multi_part_context *multi_part_ctx;

    if (!encr_ctx)
        return;

    /* Initialize encryption context */
    multi_part_ctx = (struct icsf_multi_part_context *) encr_ctx->context;
    if (multi_part_ctx) {
        if (multi_part_ctx->data)
            free(multi_part_ctx->data);
        free(multi_part_ctx);
    }
    if (encr_ctx->mech.pParameter)
        free(encr_ctx->mech.pParameter);
    memset(encr_ctx, 0, sizeof(*encr_ctx));
}

/*
 * Return if the algorithm used by a mechanism is asymmetric or symmetric.
 */
static CK_RV get_crypt_type(CK_MECHANISM_PTR mech, int *p_symmetric)
{
    switch (mech->mechanism) {
    case CKM_AES_ECB:
    case CKM_AES_CBC:
    case CKM_AES_CBC_PAD:
    case CKM_DES_ECB:
    case CKM_DES_CBC:
    case CKM_DES_CBC_PAD:
    case CKM_DES3_ECB:
    case CKM_DES3_CBC:
    case CKM_DES3_CBC_PAD:
        *p_symmetric = 1;
        break;
    case CKM_RSA_PKCS:
    case CKM_RSA_X_509:
        *p_symmetric = 0;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    return CKR_OK;
}

/**
 * Validate mechanism parameter length here for the applicable
 * encryption/decryption mechanisms supported by icsf token
 */
static CK_RV validate_mech_parameters(CK_MECHANISM_PTR mech)
{
    CK_RV rc = CKR_OK;
    size_t expected_block_size = 0;

    /* Verify the mechanisms that has a parameter length
     * specification per pkcs11#v2.2 spec
     * */
    switch (mech->mechanism) {
    case CKM_DES_CBC:
    case CKM_DES_CBC_PAD:
    case CKM_DES3_CBC:
    case CKM_DES3_CBC_PAD:
    case CKM_AES_CBC:
    case CKM_AES_CBC_PAD:
        /* Get the expected block size. This check needs to be here as
         * CKM_RSA_X_509 and CKM_RSA_PKCS does not have a block size */
        if ((rc = icsf_block_size(mech->mechanism, &expected_block_size)))
            return rc;

        if (mech->ulParameterLen != expected_block_size) {
            TRACE_ERROR("Invalid mechanism parameter length: %lu "
                        "(expected %lu)\n",
                        (unsigned long) mech->ulParameterLen,
                        (unsigned long) expected_block_size);
            return CKR_MECHANISM_PARAM_INVALID;
        }
        break;
    case CKM_DES_ECB:
    case CKM_DES3_ECB:
    case CKM_RSA_X_509:
    case CKM_RSA_PKCS:
    case CKM_AES_ECB:
        if (mech->ulParameterLen != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            return CKR_MECHANISM_PARAM_INVALID;
        }
        break;
    default:
        /** Encryption/decryption mechanism not supported by icsf token */
        TRACE_ERROR("icsf invalid mechanism %lu\n", mech->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    return rc;
}


/*
 * Initialize an encryption operation.
 */
CK_RV icsftok_encrypt_init(STDLL_TokData_t * tokdata,
                           SESSION * session, CK_MECHANISM_PTR mech,
                           CK_OBJECT_HANDLE key)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    CK_RV rc = CKR_OK;
    ENCR_DECR_CONTEXT *encr_ctx = &session->encr_ctx;
    struct icsf_multi_part_context *multi_part_ctx = NULL;
    size_t block_size = 0;
    int symmetric = 0;
    struct icsf_object_mapping *mapping = NULL;

    /* Check session */
    if (!get_session_state(tokdata, session->handle)) {
        rc = CKR_SESSION_HANDLE_INVALID;
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        goto done;
    }

    /* Get algorithm type */
    if ((rc = get_crypt_type(mech, &symmetric)))
        goto done;

    /* Check if key exists */
    if (!(mapping = bt_get_node_value(&icsf_data->objects, key))) {
        rc = CKR_KEY_HANDLE_INVALID;
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
        goto done;
    }
    rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech,
                                          &mapping->strength,
                                          POLICY_CHECK_ENCRYPT,
                                          session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: encrypt init\n");
        goto done;
    }

        /** validate the mechanism parameter length here */
    if ((rc = validate_mech_parameters(mech)))
        goto done;

    /* Initialize encryption context */
    free_encr_ctx(encr_ctx);
    encr_ctx->key = key;
    encr_ctx->active = TRUE;
    encr_ctx->multi = FALSE;

    /* Copy mechanism */
    if (mech->pParameter == NULL || mech->ulParameterLen == 0) {
        encr_ctx->mech.ulParameterLen = 0;
        encr_ctx->mech.pParameter = NULL;
    } else {
        encr_ctx->mech.pParameter = malloc(mech->ulParameterLen);
        if (!encr_ctx->mech.pParameter) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rc = CKR_HOST_MEMORY;
            goto done;
        }
        encr_ctx->mech.ulParameterLen = mech->ulParameterLen;
        memcpy(encr_ctx->mech.pParameter, mech->pParameter,
               mech->ulParameterLen);
    }
    encr_ctx->mech.mechanism = mech->mechanism;

    /*
     * Asymmetric algorithms don't support multi-part and then there's no
     * need to allocate context.
     */
    if (!symmetric)
        goto done;

    /* Allocate context for multi-part operations */
    if (!(multi_part_ctx = malloc(sizeof(*multi_part_ctx)))) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    encr_ctx->context = (void *) multi_part_ctx;

    /* Chained data has always a fixed length */
    memset(multi_part_ctx, 0, sizeof(*multi_part_ctx));

    /* Check mechanism and get block size */
    rc = icsf_block_size(mech->mechanism, &block_size);
    if (rc != CKR_OK)
        goto done;

    /*
     * data is used to retain data until at least the block size is reached.
     */
    multi_part_ctx->data_len = block_size;
    multi_part_ctx->data = malloc(multi_part_ctx->data_len);
    if (!multi_part_ctx->data) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

done:
    if (rc == CKR_OK && tokdata->statistics->increment_func != NULL)
        tokdata->statistics->increment_func(tokdata->statistics,
                                            session->session_info.slotID,
                                            mech, mapping->strength.strength);

    if (rc != CKR_OK)
        free_encr_ctx(encr_ctx);
    bt_put_node_value(&icsf_data->objects, mapping);
    mapping = NULL;

    return rc;
}

/*
 * Encrypt data and finalize an encryption operation.
 */
CK_RV icsftok_encrypt(STDLL_TokData_t * tokdata,
                      SESSION * session, CK_BYTE_PTR input_data,
                      CK_ULONG input_data_len, CK_BYTE_PTR output_data,
                      CK_ULONG_PTR p_output_data_len)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    CK_RV rc = CKR_OK;
    CK_BBOOL is_length_only = (output_data == NULL);
    ENCR_DECR_CONTEXT *encr_ctx = &session->encr_ctx;
    struct session_state *session_state;
    struct icsf_object_mapping *mapping = NULL;
    char chain_data[ICSF_CHAINING_DATA_LEN] = { 0, };
    size_t chain_data_len = sizeof(chain_data);
    int reason = 0;
    int symmetric = 0;

    /* Get algorithm type */
    if ((rc = get_crypt_type(&encr_ctx->mech, &symmetric)))
        goto done;

    /* Check if there's a multi-part encryption in progress */
    if (encr_ctx->multi) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
        rc = CKR_OPERATION_ACTIVE;
        goto done;
    }

    /* Check session */
    if (!(session_state = get_session_state(tokdata, session->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        rc = CKR_SESSION_HANDLE_INVALID;
        goto done;
    }

    /* check ldap handle */
    if (session_state->ld == NULL) {
        TRACE_ERROR("No LDAP handle.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Check if key exists */
    if (!(mapping = bt_get_node_value(&icsf_data->objects, encr_ctx->key))) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
        rc = CKR_KEY_HANDLE_INVALID;
        goto done;
    }

    /* Encrypt data using remote token. */
    if (symmetric) {
        rc = icsf_secret_key_encrypt(session_state->ld, &reason,
                                     &mapping->icsf_object,
                                     &encr_ctx->mech,
                                     ICSF_CHAINING_ONLY, (char *)input_data,
                                     input_data_len, (char *)output_data,
                                     p_output_data_len, chain_data,
                                     &chain_data_len);
    } else {
        rc = icsf_public_key_verify(session_state->ld, &reason, TRUE,
                                    &mapping->icsf_object,
                                    &encr_ctx->mech, (char *)input_data,
                                    input_data_len, (char *)output_data,
                                    p_output_data_len);
    }
    if (rc) {
        if (reason == ICSF_REASON_OUTPUT_PARAMETER_TOO_SHORT) {
            if (is_length_only) {
                /*
                 * Parameter too short is not a problem when
                 * querying the expect output size.
                 */
                rc = CKR_OK;
            } else {
                TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
                rc = CKR_BUFFER_TOO_SMALL;
            }
        } else {
            TRACE_ERROR("Failed to encrypt data. reason = %d\n", reason);
            rc = icsf_to_ock_err(rc, reason);
        }
        goto done;
    }

done:
    if (mapping) {
        bt_put_node_value(&icsf_data->objects, mapping);
        mapping = NULL;
    }

    if (rc != CKR_BUFFER_TOO_SMALL && !(rc == CKR_OK && is_length_only))
        free_encr_ctx(encr_ctx);

    return rc;
}

/*
 * Multi-part encryption.
 */
CK_RV icsftok_encrypt_update(STDLL_TokData_t * tokdata,
                             SESSION * session, CK_BYTE_PTR input_part,
                             CK_ULONG input_part_len, CK_BYTE_PTR output_part,
                             CK_ULONG_PTR p_output_part_len)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    CK_RV rc = CKR_OK;
    CK_BBOOL is_length_only = (output_part == NULL);
    ENCR_DECR_CONTEXT *encr_ctx = &session->encr_ctx;
    struct icsf_multi_part_context *multi_part_ctx;
    struct session_state *session_state;
    struct icsf_object_mapping *mapping = NULL;
    char chain_data[ICSF_CHAINING_DATA_LEN] = { 0, };
    size_t chain_data_len = sizeof(chain_data);
    CK_ULONG total, remaining;
    char *buffer = NULL;
    int chaining;
    int reason = 0;
    int symmetric = 0;

    /* Multi-part is not supported for asymmetric algorithms. */
    if ((rc = get_crypt_type(&encr_ctx->mech, &symmetric)))
        goto done;
    if (!symmetric) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    /* Check session */
    if (!(session_state = get_session_state(tokdata, session->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        rc = CKR_SESSION_HANDLE_INVALID;
        goto done;
    }

    /* check ldap handle */
    if (session_state->ld == NULL) {
        TRACE_ERROR("No LDAP handle.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Check if key exists */
    if (!(mapping = bt_get_node_value(&icsf_data->objects, encr_ctx->key))) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
        rc = CKR_KEY_HANDLE_INVALID;
        goto done;
    }

    multi_part_ctx = (struct icsf_multi_part_context *) encr_ctx->context;

    /* Define the type of the call */
    switch (encr_ctx->mech.mechanism) {
    case CKM_DES_ECB:
    case CKM_DES3_ECB:
    case CKM_AES_ECB:
        /* ICSF just support the chaining mode ONLY for ECB. */
        chaining = ICSF_CHAINING_ONLY;
        break;
    default:
        if (multi_part_ctx->initiated) {
            chaining = ICSF_CHAINING_CONTINUE;
            memcpy(chain_data, multi_part_ctx->chain_data, chain_data_len);
        } else {
            chaining = ICSF_CHAINING_INITIAL;
        }
    }

    /*
     * Data needs to be sent to ICSF in chucks with size that is multiple of
     * block size. Any remaining data is kept in the multi-part context and
     * can be sent in a further call of the update function or when the
     * finalize function is called.
     */
    total = multi_part_ctx->used_data_len + input_part_len;
    remaining = total % multi_part_ctx->data_len;

    /*
     * If there's no enough data to make a call, skip it.
     */
    if (total < multi_part_ctx->data_len) {
        *p_output_part_len = 0;
        goto keep_remaining_data;
    }

    /*
     * The data to be encrypted should have length that is multiple of the
     * block size. It is composed by data kept in the multi-part context
     * concatenated with part of the data given.
     */
    if (!(buffer = malloc(total - remaining))) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    memcpy(buffer, multi_part_ctx->data, multi_part_ctx->used_data_len);
    if (input_part_len - remaining > 0)
        memcpy(buffer + multi_part_ctx->used_data_len, input_part,
               input_part_len - remaining);

    /* Encrypt data using remote token. */
    rc = icsf_secret_key_encrypt(session_state->ld, &reason,
                                 &mapping->icsf_object,
                                 &encr_ctx->mech, chaining,
                                 buffer, total - remaining,
                                 (char *)output_part, p_output_part_len,
                                 chain_data, &chain_data_len);
    if (rc) {
        if (reason == ICSF_REASON_OUTPUT_PARAMETER_TOO_SHORT) {
            if (is_length_only) {
                /*
                 * Parameter too short is not a problem when
                 * querying the expect output size.
                 */
                rc = CKR_OK;
            } else {
                TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
                rc = CKR_BUFFER_TOO_SMALL;
            }
        } else {
            TRACE_DEVEL("Failed to encrypt data. reason = %d\n", reason);
            rc = icsf_to_ock_err(rc, reason);
        }
        goto done;
    }

    /** If this is the first block for multi-part operation, also set
     *  the encr_ctx->context_len here. This is needed for
     *  C_GetOperationState to work correctly */
    if (!multi_part_ctx->initiated)
        encr_ctx->context_len = sizeof(*multi_part_ctx);

    /*
     * When blocks are sent it's necessary to keep the chain data returned
     * to be used in a subsequent call.
     */
    if (!is_length_only) {
        /* Copy chain data into context */
        memcpy(multi_part_ctx->chain_data, chain_data, chain_data_len);

        /* Mark multi-part operation as initiated */
        multi_part_ctx->initiated = TRUE;

        /* Mark the multi-part operation in encr_ctx */
        encr_ctx->multi = TRUE;

        /* Data stored in cache was used */
        multi_part_ctx->used_data_len = 0;
    }

keep_remaining_data:
    /* Keep the remaining data to a next call */
    if (!is_length_only) {
        /* Copy remaining part of input_part into context */
        if (total < multi_part_ctx->data_len) {
            if (input_part_len > 0)
                memcpy(multi_part_ctx->data +
                       multi_part_ctx->used_data_len, input_part,
                       input_part_len);
        } else {
            memcpy(multi_part_ctx->data,
                   input_part + input_part_len - remaining, remaining);
        }
        multi_part_ctx->used_data_len = remaining;
    }

done:
    if (mapping) {
        bt_put_node_value(&icsf_data->objects, mapping);
        mapping = NULL;
    }

    /* Free resources */
    if (buffer)
        free(buffer);

    if (rc != CKR_OK && rc != CKR_BUFFER_TOO_SMALL)
        free_encr_ctx(encr_ctx);

    return rc;
}

/*
 * Finalize a multi-part encryption.
 */
CK_RV icsftok_encrypt_final(STDLL_TokData_t * tokdata,
                            SESSION * session, CK_BYTE_PTR output_part,
                            CK_ULONG_PTR p_output_part_len)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    CK_RV rc = CKR_OK;
    CK_BBOOL is_length_only = (output_part == NULL);
    ENCR_DECR_CONTEXT *encr_ctx = &session->encr_ctx;
    struct icsf_multi_part_context *multi_part_ctx;
    struct session_state *session_state;
    struct icsf_object_mapping *mapping = NULL;
    char chain_data[ICSF_CHAINING_DATA_LEN] = { 0, };
    size_t chain_data_len = sizeof(chain_data);
    int chaining;
    int reason = 0;
    int symmetric = 0;

    /* Multi-part is not supported for asymmetric algorithms. */
    if ((rc = get_crypt_type(&encr_ctx->mech, &symmetric)))
        goto done;
    if (!symmetric) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    /* Check session */
    if (!(session_state = get_session_state(tokdata, session->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        rc = CKR_SESSION_HANDLE_INVALID;
        goto done;
    }

    /* check ldap handle */
    if (session_state->ld == NULL) {
        TRACE_ERROR("No LDAP handle.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Check if key exists */
    if (!(mapping = bt_get_node_value(&icsf_data->objects, encr_ctx->key))) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
        rc = CKR_KEY_HANDLE_INVALID;
        goto done;
    }

    /* Define the type of the call */
    multi_part_ctx = (struct icsf_multi_part_context *) encr_ctx->context;
    switch (encr_ctx->mech.mechanism) {
    case CKM_DES_ECB:
    case CKM_DES3_ECB:
    case CKM_AES_ECB:
        /*
         * When not using a chained algorithm and there's no remaining
         * data, don't call ICSF.
         */
        *p_output_part_len = 0;
        if (!multi_part_ctx->used_data_len)
            goto done;

        /* ICSF just support the chaining mode ONLY for ECB. */
        chaining = ICSF_CHAINING_ONLY;
        break;
    default:
        if (multi_part_ctx->initiated) {
            chaining = ICSF_CHAINING_FINAL;
            memcpy(chain_data, multi_part_ctx->chain_data, chain_data_len);
        } else {
            chaining = ICSF_CHAINING_ONLY;
        }
    }

    /*
     * Encrypt data using remote token.
     *
     * All the data in multi-part context should be sent.
     */
    rc = icsf_secret_key_encrypt(session_state->ld, &reason,
                                 &mapping->icsf_object,
                                 &encr_ctx->mech, chaining,
                                 multi_part_ctx->data,
                                 multi_part_ctx->used_data_len,
                                 (char *)output_part, p_output_part_len,
                                 chain_data, &chain_data_len);
    if (rc) {
        if (reason == ICSF_REASON_OUTPUT_PARAMETER_TOO_SHORT) {
            if (is_length_only) {
                /*
                 * Parameter too short is not a problem when
                 * querying the expect output size.
                 */
                rc = CKR_OK;
            } else {
                TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
                rc = CKR_BUFFER_TOO_SMALL;
            }
        } else {
            TRACE_DEVEL("Failed to encrypt data. reason = %d\n", reason);
            rc = icsf_to_ock_err(rc, reason);
        }
        goto done;
    }

done:
    if (mapping) {
        bt_put_node_value(&icsf_data->objects, mapping);
        mapping = NULL;
    }

    if ((is_length_only && rc != CKR_OK) ||
        (!is_length_only && rc != CKR_BUFFER_TOO_SMALL))
        free_encr_ctx(encr_ctx);

    return rc;
}

/*
 * Initialize a decryption operation.
 */
CK_RV icsftok_decrypt_init(STDLL_TokData_t * tokdata,
                           SESSION * session, CK_MECHANISM_PTR mech,
                           CK_OBJECT_HANDLE key)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    CK_RV rc = CKR_OK;
    ENCR_DECR_CONTEXT *decr_ctx = &session->decr_ctx;
    struct icsf_multi_part_context *multi_part_ctx = NULL;
    size_t block_size = 0;
    int symmetric = 0;
    struct icsf_object_mapping *mapping = NULL;

    /* Check session */
    if (!get_session_state(tokdata, session->handle)) {
        rc = CKR_SESSION_HANDLE_INVALID;
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        goto done;
    }

    /* Get algorithm type */
    if ((rc = get_crypt_type(mech, &symmetric)))
        goto done;

    /* Check if key exists */
    if (!(mapping = bt_get_node_value(&icsf_data->objects, key))) {
        rc = CKR_KEY_HANDLE_INVALID;
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
        goto done;
    }
    rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech,
                                          &mapping->strength,
                                          POLICY_CHECK_DECRYPT,
                                          session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: decrypt init\n");
        goto done;
    }

    /** validate the mechanism parameter length here */
    if ((rc = validate_mech_parameters(mech)))
        goto done;

    /* Initialize decryption context */
    free_encr_ctx(decr_ctx);
    decr_ctx->key = key;
    decr_ctx->active = TRUE;
    decr_ctx->multi = FALSE;

    /* Copy mechanism */
    if (mech->pParameter == NULL || mech->ulParameterLen == 0) {
        decr_ctx->mech.ulParameterLen = 0;
        decr_ctx->mech.pParameter = NULL;
    } else {
        decr_ctx->mech.pParameter = malloc(mech->ulParameterLen);
        if (!decr_ctx->mech.pParameter) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rc = CKR_HOST_MEMORY;
            goto done;
        }
        decr_ctx->mech.ulParameterLen = mech->ulParameterLen;
        memcpy(decr_ctx->mech.pParameter, mech->pParameter,
               mech->ulParameterLen);
    }
    decr_ctx->mech.mechanism = mech->mechanism;

    /*
     * Asymmetric algorithms don't support multi-part and then there's no
     * need to allocate context.
     */
    if (!symmetric)
        goto done;

    /* Allocate context for multi-part operations */
    if (!(multi_part_ctx = malloc(sizeof(*multi_part_ctx)))) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    decr_ctx->context = (void *) multi_part_ctx;

    /* Chained data has always a fixed length */
    memset(multi_part_ctx, 0, sizeof(*multi_part_ctx));

    /* Check mechanism and get block size */
    rc = icsf_block_size(mech->mechanism, &block_size);
    if (rc != CKR_OK)
        goto done;

    /*
     * data is used to retain data until at least the block size is reached.
     */
    multi_part_ctx->data_len = block_size;
    multi_part_ctx->data = malloc(multi_part_ctx->data_len);
    if (!multi_part_ctx->data) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

done:
    if (rc == CKR_OK && tokdata->statistics->increment_func != NULL)
        tokdata->statistics->increment_func(tokdata->statistics,
                                            session->session_info.slotID,
                                            mech, mapping->strength.strength);

    if (rc != CKR_OK)
        free_encr_ctx(decr_ctx);
    bt_put_node_value(&icsf_data->objects, mapping);
    mapping = NULL;

    return rc;
}

/*
 * Decrypt data and finalize a decryption operation.
 */
CK_RV icsftok_decrypt(STDLL_TokData_t * tokdata,
                      SESSION * session, CK_BYTE_PTR input_data,
                      CK_ULONG input_data_len, CK_BYTE_PTR output_data,
                      CK_ULONG_PTR p_output_data_len)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    CK_RV rc = CKR_OK;
    CK_BBOOL is_length_only = (output_data == NULL);
    ENCR_DECR_CONTEXT *decr_ctx = &session->decr_ctx;
    struct session_state *session_state;
    struct icsf_object_mapping *mapping = NULL;
    char chain_data[ICSF_CHAINING_DATA_LEN] = { 0, };
    size_t chain_data_len = sizeof(chain_data);
    int reason = 0;
    int symmetric = 0;

    /* Get algorithm type */
    if ((rc = get_crypt_type(&decr_ctx->mech, &symmetric)))
        goto done;

    /* Check if there's a multi-part decryption in progress */
    if (decr_ctx->multi) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
        rc = CKR_OPERATION_ACTIVE;
        goto done;
    }

    /* Check session */
    if (!(session_state = get_session_state(tokdata, session->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        rc = CKR_SESSION_HANDLE_INVALID;
        goto done;
    }

    /* check ldap handle */
    if (session_state->ld == NULL) {
        TRACE_ERROR("No LDAP handle.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Check if key exists */
    if (!(mapping = bt_get_node_value(&icsf_data->objects, decr_ctx->key))) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
        rc = CKR_KEY_HANDLE_INVALID;
        goto done;
    }

    /* Decrypt data using remote token. */
    if (symmetric) {
        rc = icsf_secret_key_decrypt(session_state->ld, &reason,
                                     &mapping->icsf_object,
                                     &decr_ctx->mech,
                                     ICSF_CHAINING_ONLY, (char *)input_data,
                                     input_data_len, (char *)output_data,
                                     p_output_data_len, chain_data,
                                     &chain_data_len);
    } else {
        rc = icsf_private_key_sign(session_state->ld, &reason, TRUE,
                                   &mapping->icsf_object,
                                   &decr_ctx->mech, (char *)input_data,
                                   input_data_len, (char *)output_data,
                                   p_output_data_len);
    }
    if (rc) {
        if (reason == ICSF_REASON_OUTPUT_PARAMETER_TOO_SHORT) {
            if (is_length_only) {
                /*
                 * Parameter too short is not a problem when
                 * querying the expect output size.
                 */
                rc = CKR_OK;
            } else {
                TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
                rc = CKR_BUFFER_TOO_SMALL;
            }
        } else {
            TRACE_DEVEL("Failed to decrypt data. reason = %d\n", reason);
            rc = icsf_to_ock_err(rc, reason);
        }
        goto done;
    }

done:
    if (mapping) {
        bt_put_node_value(&icsf_data->objects, mapping);
        mapping = NULL;
    }

    if (rc != CKR_BUFFER_TOO_SMALL && !(rc == CKR_OK && is_length_only))
        free_encr_ctx(decr_ctx);

    return rc;
}

/*
 * Multi-part decryption.
 */
CK_RV icsftok_decrypt_update(STDLL_TokData_t * tokdata,
                             SESSION * session, CK_BYTE_PTR input_part,
                             CK_ULONG input_part_len, CK_BYTE_PTR output_part,
                             CK_ULONG_PTR p_output_part_len)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    CK_RV rc = CKR_OK;
    CK_BBOOL is_length_only = (output_part == NULL);
    ENCR_DECR_CONTEXT *decr_ctx = &session->decr_ctx;
    struct icsf_multi_part_context *multi_part_ctx;
    struct session_state *session_state;
    struct icsf_object_mapping *mapping = NULL;
    char chain_data[ICSF_CHAINING_DATA_LEN] = { 0, };
    size_t chain_data_len = sizeof(chain_data);
    CK_ULONG total, remaining;
    char *buffer = NULL;
    int chaining;
    int reason = 0;
    int padding = 0;
    int symmetric = 0;

    /* Multi-part is not supported for asymmetric algorithms. */
    if ((rc = get_crypt_type(&decr_ctx->mech, &symmetric)))
        goto done;
    if (!symmetric) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    /* Check session */
    if (!(session_state = get_session_state(tokdata, session->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        rc = CKR_SESSION_HANDLE_INVALID;
        goto done;
    }

    /* check ldap handle */
    if (session_state->ld == NULL) {
        TRACE_ERROR("No LDAP handle.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Check if key exists */
    if (!(mapping = bt_get_node_value(&icsf_data->objects, decr_ctx->key))) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
        rc = CKR_KEY_HANDLE_INVALID;
        goto done;
    }

    multi_part_ctx = (struct icsf_multi_part_context *) decr_ctx->context;

    /* Define the type of the call */
    switch (decr_ctx->mech.mechanism) {
    case CKM_AES_ECB:
    case CKM_DES_ECB:
    case CKM_DES3_ECB:
        /* ICSF just support the chaining mode ONLY for ECB. */
        chaining = ICSF_CHAINING_ONLY;
        break;
    case CKM_AES_CBC_PAD:
    case CKM_DES_CBC_PAD:
    case CKM_DES3_CBC_PAD:
        padding = 1;
        /* fallthrough */
    default:
        if (multi_part_ctx->initiated) {
            chaining = ICSF_CHAINING_CONTINUE;
            memcpy(chain_data, multi_part_ctx->chain_data, chain_data_len);
        } else {
            chaining = ICSF_CHAINING_INITIAL;
        }
    }

    /*
     * Data needs to be sent to ICSF in chucks with size that is multiple of
     * block size. Any remaining data is kept in the multi-part context and
     * can be sent in a further call of the update function or when the
     * finalize function is called.
     *
     * When padding is used, there's no way to know if the current block of
     * data is the one that contains the padding, So a block is kept in
     * multi-part context when the data available is exactly multiple of the
     * block size.
     */
    total = multi_part_ctx->used_data_len + input_part_len;
    if (!padding) {
        remaining = total % multi_part_ctx->data_len;
    } else {
        remaining = MIN(((total - 1) % multi_part_ctx->data_len) + 1, total);
    }

    /*
     * If there's no enough data to make a call, skip it.
     */
    if (total < multi_part_ctx->data_len ||
        (padding && total == multi_part_ctx->data_len)) {
        *p_output_part_len = 0;
        goto keep_remaining_data;
    }


    /*
     * The data to be decrypted should have length that is multiple of the
     * block size. It is composed by data kept in the multi-part context
     * concatenated with part of the data given.
     */
    if (!(buffer = malloc(total - remaining))) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    memcpy(buffer, multi_part_ctx->data, multi_part_ctx->used_data_len);
    if (input_part_len - remaining > 0)
        memcpy(buffer + multi_part_ctx->used_data_len, input_part,
               input_part_len - remaining);

    /* Decrypt data using remote token. */
    rc = icsf_secret_key_decrypt(session_state->ld, &reason,
                                 &mapping->icsf_object,
                                 &decr_ctx->mech, chaining,
                                 buffer, total - remaining,
                                 (char *)output_part, p_output_part_len,
                                 chain_data, &chain_data_len);
    if (rc) {
        if (reason == ICSF_REASON_OUTPUT_PARAMETER_TOO_SHORT) {
            if (is_length_only) {
                /*
                 * Parameter too short is not a problem when
                 * querying the expect output size.
                 */
                rc = CKR_OK;
            } else {
                TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
                rc = CKR_BUFFER_TOO_SMALL;
            }
        } else {
            TRACE_DEVEL("Failed to decrypt data. reason = %d\n", reason);
            rc = icsf_to_ock_err(rc, reason);
        }
        goto done;
    }

    /* If this is the first block sent for multi-part set the context_len */
    if (!multi_part_ctx->initiated)
        decr_ctx->context_len = sizeof(*multi_part_ctx);

    /*
     * When blocks are sent it's necessary to keep the chain data returned
     * to be used in a subsequent call.
     */
    if (!is_length_only) {
        /* Copy chain data into context */
        memcpy(multi_part_ctx->chain_data, chain_data, chain_data_len);

        /* Mark multi-part operation as initiated */
        multi_part_ctx->initiated = TRUE;

        /* Mark multi-part operation in decr_ctx in session */
        decr_ctx->multi = TRUE;

        /* Data stored in cache was used */
        multi_part_ctx->used_data_len = 0;
    }

keep_remaining_data:
    /* Keep the remaining data to a next call */
    if (!is_length_only) {
        /* Copy remaining part of input_part into context */
        if (total < multi_part_ctx->data_len ||
            (padding && total == multi_part_ctx->data_len)) {
            if (input_part_len > 0)
                memcpy(multi_part_ctx->data +
                       multi_part_ctx->used_data_len, input_part,
                       input_part_len);
        } else {
            memcpy(multi_part_ctx->data,
                   input_part + input_part_len - remaining, remaining);
        }
        multi_part_ctx->used_data_len = remaining;
    }

done:
    if (mapping) {
        bt_put_node_value(&icsf_data->objects, mapping);
        mapping = NULL;
    }

    /* Free resources */
    if (buffer)
        free(buffer);

    if (rc != CKR_OK && rc != CKR_BUFFER_TOO_SMALL)
        free_encr_ctx(decr_ctx);

    return rc;
}

/*
 * Finalize a multi-part decryption.
 */
CK_RV icsftok_decrypt_final(STDLL_TokData_t * tokdata,
                            SESSION * session, CK_BYTE_PTR output_part,
                            CK_ULONG_PTR p_output_part_len)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    CK_RV rc = CKR_OK;
    CK_BBOOL is_length_only = (output_part == NULL);
    ENCR_DECR_CONTEXT *decr_ctx = &session->decr_ctx;
    struct icsf_multi_part_context *multi_part_ctx;
    struct session_state *session_state;
    struct icsf_object_mapping *mapping = NULL;
    char chain_data[ICSF_CHAINING_DATA_LEN] = { 0, };
    size_t chain_data_len = sizeof(chain_data);
    int chaining;
    int reason = 0;
    int symmetric = 0;

    /* Multi-part is not supported for asymmetric algorithms. */
    if ((rc = get_crypt_type(&decr_ctx->mech, &symmetric)))
        goto done;
    if (!symmetric) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    /* Check session */
    if (!(session_state = get_session_state(tokdata, session->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        rc = CKR_SESSION_HANDLE_INVALID;
        goto done;
    }

    /* check ldap handle */
    if (session_state->ld == NULL) {
        TRACE_ERROR("No LDAP handle.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Check if key exists */
    if (!(mapping = bt_get_node_value(&icsf_data->objects, decr_ctx->key))) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
        rc = CKR_KEY_HANDLE_INVALID;
        goto done;
    }

    /* Define the type of the call */
    multi_part_ctx = (struct icsf_multi_part_context *) decr_ctx->context;
    switch (decr_ctx->mech.mechanism) {
    case CKM_AES_ECB:
    case CKM_DES_ECB:
    case CKM_DES3_ECB:
        /*
         * When not using a chained algorithm and there's no remaining
         * data, don't call ICSF.
         */
        *p_output_part_len = 0;
        if (!multi_part_ctx->used_data_len)
            goto done;

        /* ICSF just support the chaining mode ONLY for ECB. */
        chaining = ICSF_CHAINING_ONLY;
        break;
    default:
        if (multi_part_ctx->initiated) {
            chaining = ICSF_CHAINING_FINAL;
            memcpy(chain_data, multi_part_ctx->chain_data, chain_data_len);
        } else {
            chaining = ICSF_CHAINING_ONLY;
        }
    }

    /*
     * Decrypt data using remote token.
     *
     * All the data in multi-part context should be sent.
     */
    rc = icsf_secret_key_decrypt(session_state->ld, &reason,
                                 &mapping->icsf_object,
                                 &decr_ctx->mech, chaining,
                                 multi_part_ctx->data,
                                 multi_part_ctx->used_data_len,
                                 (char *)output_part, p_output_part_len,
                                 chain_data, &chain_data_len);
    if (rc) {
        if (reason == ICSF_REASON_OUTPUT_PARAMETER_TOO_SHORT) {
            if (is_length_only) {
                /*
                 * Parameter too short is not a problem when
                 * querying the expect output size.
                 */
                rc = CKR_OK;
            } else {
                TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
                rc = CKR_BUFFER_TOO_SMALL;
            }
        } else {
            TRACE_DEVEL("Failed to decrypt data. reason = %d\n", reason);
            rc = icsf_to_ock_err(rc, reason);
        }
        goto done;
    }

done:
    if (mapping) {
        bt_put_node_value(&icsf_data->objects, mapping);
        mapping = NULL;
    }

    if ((is_length_only && rc != CKR_OK) ||
        (!is_length_only && rc != CKR_BUFFER_TOO_SMALL))
        free_encr_ctx(decr_ctx);

    return rc;
}

/*
 * Get the attribute values for a list of attributes.
 */
CK_RV icsftok_get_attribute_value(STDLL_TokData_t * tokdata,
                                  SESSION * sess, CK_OBJECT_HANDLE handle,
                                  CK_ATTRIBUTE * pTemplate, CK_ULONG ulCount,
                                  CK_ULONG * obj_size)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    CK_RV rc = CKR_OK;
    CK_BBOOL priv_obj;
    struct session_state *session_state;
    struct icsf_object_mapping *mapping = NULL;
    int reason = 0;

    CK_ATTRIBUTE priv_attr[] = {
        {CKA_PRIVATE, &priv_obj, sizeof(priv_obj)}
        ,
    };

    /* Get session state */
    if (!(session_state = get_session_state(tokdata, sess->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        return CKR_SESSION_HANDLE_INVALID;
    }

    /* check ldap handle */
    if (session_state->ld == NULL) {
        TRACE_ERROR("No LDAP handle.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* get the object handle */
    mapping = bt_get_node_value(&icsf_data->objects, handle);

    if (!mapping) {
        TRACE_ERROR("%s\n", ock_err(ERR_OBJECT_HANDLE_INVALID));
        rc = CKR_OBJECT_HANDLE_INVALID;
        goto done;
    }

    /* get the private attribute so we can check the permissions */
    rc = icsf_get_attribute(session_state->ld, &reason,
                            &mapping->icsf_object, priv_attr, 1);
    if (rc != CKR_OK) {
        TRACE_DEVEL("icsf_get_attribute failed\n");
        rc = icsf_to_ock_err(rc, reason);
        goto done;
    }

    if (priv_obj == TRUE) {
        if (sess->session_info.state == CKS_RO_PUBLIC_SESSION ||
            sess->session_info.state == CKS_RW_PUBLIC_SESSION) {
            TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
            rc = CKR_USER_NOT_LOGGED_IN;
            goto done;
        }
    }
    // get requested attributes and values if the obj_size ptr is not set
    if (!obj_size) {
        /* Now call icsf to get the attribute values */
        rc = icsf_get_attribute(session_state->ld, &reason,
                                &mapping->icsf_object, pTemplate, ulCount);

        if (rc != CKR_OK) {
            TRACE_DEVEL("icsf_get_attribute failed\n");
            rc = icsf_to_ock_err(rc, reason);
        }
    } else {
        /* if size is specified get the object size from remote end */
        rc = icsf_get_object_size(session_state->ld, &reason,
                                  &mapping->icsf_object, ulCount, obj_size);

        if (rc != CKR_OK) {
            TRACE_DEVEL("icsf_get_object_size failed\n");
            rc = icsf_to_ock_err(rc, reason);
        }
    }

done:
    if (mapping) {
        bt_put_node_value(&icsf_data->objects, mapping);
        mapping = NULL;
    }

    return rc;
}

/*
 * Set attribute values for a list of attributes.
 */
CK_RV icsftok_set_attribute_value(STDLL_TokData_t * tokdata,
                                  SESSION * sess, CK_OBJECT_HANDLE handle,
                                  CK_ATTRIBUTE * pTemplate, CK_ULONG ulCount)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    struct session_state *session_state;
    struct icsf_object_mapping *mapping = NULL;
    CK_BBOOL is_priv;
    CK_BBOOL is_token;
    CK_RV rc = CKR_OK;
    int reason = 0;

    CK_ATTRIBUTE priv_attrs[] = {
        {CKA_PRIVATE, &is_priv, sizeof(is_priv)}
        ,
        {CKA_TOKEN, &is_token, sizeof(is_token)}
        ,
    };

    /* Get session state */
    if (!(session_state = get_session_state(tokdata, sess->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        return CKR_SESSION_HANDLE_INVALID;
    }

    /* check ldap handle */
    if (session_state->ld == NULL) {
        TRACE_ERROR("No LDAP handle.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* get the object handle */
    mapping = bt_get_node_value(&icsf_data->objects, handle);

    if (!mapping) {
        TRACE_ERROR("%s\n", ock_err(ERR_OBJECT_HANDLE_INVALID));
        rc = CKR_OBJECT_HANDLE_INVALID;
        goto done;
    }

    /* check permissions :
     * first get CKA_PRIVATE since we need to check againse session
     * icsf will check if the attributes are modifiable
     */
    rc = icsf_get_attribute(session_state->ld, &reason,
                            &mapping->icsf_object, priv_attrs, 2);
    if (rc != CKR_OK) {
        TRACE_DEVEL("icsf_get_attribute failed\n");
        rc = icsf_to_ock_err(rc, reason);
        goto done;
    }

    /* Check permissions based on attributes and session */
    rc = check_session_permissions(sess, priv_attrs, 2);
    if (rc != CKR_OK) {
        TRACE_DEVEL("check_session_permissions failed\n");
        goto done;
    }

    /* Now call into icsf to set the attribute values */
    rc = icsf_set_attribute(session_state->ld, &reason,
                            &mapping->icsf_object, pTemplate, ulCount);
    if (rc != CKR_OK) {
        TRACE_ERROR("icsf_set_attribute failed\n");
        rc = icsf_to_ock_err(rc, reason);
        goto done;
    }

done:
    if (mapping) {
        bt_put_node_value(&icsf_data->objects, mapping);
        mapping = NULL;
    }

    return rc;
}

/*
 * Initialize a search for token and session objects that match a template.
 */
CK_RV icsftok_find_objects_init(STDLL_TokData_t * tokdata, SESSION * sess,
                                CK_ATTRIBUTE * pTemplate, CK_ULONG ulCount)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    char token_name[sizeof(tokdata->nv_token_data->token_info.label) + 1];
    struct session_state *session_state;
    struct icsf_object_record records[MAX_RECORDS];
    struct icsf_object_record *previous = NULL;
    size_t records_len;
    unsigned int i, j;
    int node_number, rc;
    int reason = 0;
    CK_RV rv = CKR_OK;
    struct icsf_policy_attr pattr;

    /* Whether we retrieve public or private objects is determined by
     * the caller's SAF authority on the token, something ock doesn't
     * control.
     * Since an app MUST have authenticated to ICSF token to use it,
     * we can always assume it is an authenticated session and anything else
     * is an error.
     */
    if (sess->session_info.state == CKS_RO_PUBLIC_SESSION ||
        sess->session_info.state == CKS_RW_PUBLIC_SESSION ||
        sess->session_info.state == CKS_RW_SO_FUNCTIONS) {
        TRACE_ERROR("You must authenticate to access ICSF token.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* Initialize the found object list. In keeping with other tokens,
     * if the list does not exist, allocate list big enough for MAX_RECORD
     * handles. reallocate later if more needed.
     */
    if (sess->find_list == NULL) {
        sess->find_list =
            (CK_OBJECT_HANDLE *) malloc(10 * sizeof(CK_OBJECT_HANDLE));
        if (!sess->find_list) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            return CKR_HOST_MEMORY;
        }
        sess->find_len = 10;
    }
    memset(sess->find_list, 0x0, sess->find_len * sizeof(CK_OBJECT_HANDLE));
    sess->find_count = 0;
    sess->find_idx = 0;

    /* Prepare to query ICSF for list objects
     * Copy token name from shared memory
     */
    rc = XProcLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to get process lock.\n");
        return rc;
    }

    strunpad(token_name, (const char *)tokdata->nv_token_data->token_info.label,
             sizeof(tokdata->nv_token_data->token_info.label), ' ');

    rc = XProcUnLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to release process lock.\n");
        return rc;
    }

    /* Get session state */
    if (!(session_state = get_session_state(tokdata, sess->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        return CKR_SESSION_HANDLE_INVALID;
    }

    /* check ldap handle */
    if (session_state->ld == NULL) {
        TRACE_ERROR("No LDAP handle.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* clear out records */
    memset(records, 0, MAX_RECORDS * (sizeof(struct icsf_object_record)));

    do {
        records_len = sizeof(records) / sizeof(struct icsf_object_record);
        rc = icsf_list_objects(session_state->ld, &reason, token_name,
                               ulCount, pTemplate, previous, records,
                               &records_len, 0);
        if (ICSF_RC_IS_ERROR(rc)) {
            TRACE_DEVEL("Failed to list objects.\n");
            rv = icsf_to_ock_err(rc, reason);
            goto done;
        }

        /* Now step thru the object btree so we can find the node
         * value for any matching objects we retrieved from ICSF.
         * If we cannot find a matching object in the btree,
         * then add it so we can get a node value.
         * And also because ICSF object database is authoritative.
         */

        for (i = 0; i < records_len; i++) {

            /* mark not found */
            node_number = 0;

            for (j = 1; j <= icsf_data->objects.size; j++) {
                struct icsf_object_mapping *mapping = NULL;

                /* skip missing ids */
                mapping = bt_get_node_value(&icsf_data->objects, j);
                if (mapping) {
                    if (memcmp(&records[i],
                               &mapping->icsf_object,
                               sizeof(struct icsf_object_record)) == 0) {
                        node_number = j;
                        bt_put_node_value(&icsf_data->objects, mapping);
                        mapping = NULL;
                        break;
                    }
                    bt_put_node_value(&icsf_data->objects, mapping);
                    mapping = NULL;
                } else {
                    continue;
                }
            }
            /* if could not find in our object tree, then add it
             * since ICSF object database is authoritative.
             */
            if (!node_number) {
                struct icsf_object_mapping *new_mapping;

                if (!(new_mapping = malloc(sizeof(*new_mapping)))) {
                    TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                    rv = CKR_HOST_MEMORY;
                    goto done;
                }
                new_mapping->session_id = sess->handle;
                new_mapping->icsf_object = records[i];
                /* Policy check */
                pattr.ld = session_state->ld;
                pattr.icsf_object = &new_mapping->icsf_object;
                rc = tokdata->policy->store_object_strength(
                     tokdata->policy, &new_mapping->strength,
                     icsf_policy_get_attr, &pattr, icsf_policy_free_attr, sess);
                if (rc != CKR_OK) {
                    TRACE_ERROR("POLICY VIOLATION: Object too weak\n");
                    goto done;
                }

                if (!(node_number = bt_node_add(&icsf_data->objects,
                                                new_mapping))) {
                    TRACE_ERROR("Failed to add object to " "binary tree.\n");
                    rv = CKR_FUNCTION_FAILED;
                    goto done;
                }
            }

            /* Add to our findobject list */
            if (node_number) {
                sess->find_list[sess->find_count] = node_number;
                sess->find_count++;

                if (sess->find_count >= sess->find_len) {
                    void *find_list;
                    size_t find_len = sess->find_len + MAX_RECORDS;
                    find_list = realloc(sess->find_list,
                                        find_len * sizeof(CK_OBJECT_HANDLE));
                    if (!find_list) {
                        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                        rv = CKR_HOST_MEMORY;
                        goto done;
                    }
                    sess->find_list = find_list;
                    sess->find_len = find_len;
                }
            }
        }

        if (records_len)
            previous = &records[records_len - 1];
    } while (records_len);

    sess->find_active = TRUE;

done:
    return rv;
}

/*
 * Destroy an object.
 */
CK_RV icsftok_destroy_object(STDLL_TokData_t * tokdata, SESSION * sess,
                             CK_OBJECT_HANDLE handle)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    struct session_state *session_state;
    struct icsf_object_mapping *mapping = NULL;
    int reason;
    CK_RV rc = CKR_OK;


    /* Get session state */
    if (!(session_state = get_session_state(tokdata, sess->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        return CKR_SESSION_HANDLE_INVALID;;
    }

    /* check ldap handle */
    if (session_state->ld == NULL) {
        TRACE_ERROR("No LDAP handle.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* get the object handle */
    mapping = bt_get_node_value(&icsf_data->objects, handle);

    if (!mapping) {
        TRACE_ERROR("%s\n", ock_err(ERR_OBJECT_HANDLE_INVALID));
        rc = CKR_OBJECT_HANDLE_INVALID;
        goto done;
    }

    /* Now remove the object from ICSF */
    rc = icsf_destroy_object(session_state->ld, &reason, &mapping->icsf_object);
    if (rc != 0) {
        TRACE_DEVEL("icsf_destroy_object failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    bt_put_node_value(&icsf_data->objects, mapping);
    mapping = NULL;

    /* Now remove the object from the object btree */
    bt_node_free(&icsf_data->objects, handle, TRUE);

done:
    if (mapping) {
        bt_put_node_value(&icsf_data->objects, mapping);
        mapping = NULL;
    }
    return rc;
}

/*
 * Free all data pointed by SIGN_VERIFY_CONTEXT and set everything to zero.
 */
static void free_sv_ctx(SIGN_VERIFY_CONTEXT * ctx)
{
    struct icsf_multi_part_context *multi_part_ctx;

    if (!ctx)
        return;

    /* Initialize encryption context */
    multi_part_ctx = (struct icsf_multi_part_context *) ctx->context;
    if (multi_part_ctx) {
        if (multi_part_ctx->data)
            free(multi_part_ctx->data);
        free(multi_part_ctx);
    }
    if (ctx->mech.pParameter)
        free(ctx->mech.pParameter);

    memset(ctx, 0, sizeof(*ctx));
}

/*
 * get the hash size for hmacs.
 */
int get_signverify_len(CK_MECHANISM mech)
{
    switch (mech.mechanism) {
    case CKM_MD5_HMAC:
    case CKM_SSL3_MD5_MAC:
        return MD5_HASH_SIZE;
    case CKM_SHA_1_HMAC:
    case CKM_SSL3_SHA1_MAC:
        return SHA1_HASH_SIZE;
    case CKM_SHA224_HMAC:
        return SHA224_HASH_SIZE;
    case CKM_SHA256_HMAC:
        return SHA256_HASH_SIZE;
    case CKM_SHA384_HMAC:
        return SHA384_HASH_SIZE;
    case CKM_SHA512_HMAC:
        return SHA512_HASH_SIZE;
    }

    return -1;
}

CK_RV icsftok_sign_init(STDLL_TokData_t * tokdata,
                        SESSION * session, CK_MECHANISM * mech,
                        CK_OBJECT_HANDLE key)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    struct session_state *session_state;
    SIGN_VERIFY_CONTEXT *ctx = &session->sign_ctx;
    struct icsf_multi_part_context *multi_part_ctx = NULL;
    struct icsf_object_mapping *mapping = NULL;
    CK_RV rc = CKR_OK;
    CK_BBOOL multi = FALSE;
    CK_BBOOL datacaching = FALSE;
    CK_MAC_GENERAL_PARAMS *param;

    /* Check session */
    if (!(session_state = get_session_state(tokdata, session->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        return CKR_SESSION_HANDLE_INVALID;
    }

    /* Check if key exists */
    if (!(mapping = bt_get_node_value(&icsf_data->objects, key))) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
        rc = CKR_KEY_HANDLE_INVALID;
        return rc;
    }
    rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech,
                                          &mapping->strength,
                                          POLICY_CHECK_SIGNATURE,
                                          session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: Sign init\n");
        goto done;
    }

    /* Check the mechanism info */
    switch (mech->mechanism) {
    case CKM_RSA_X_509:
    case CKM_RSA_PKCS:
    case CKM_DSA:
    case CKM_ECDSA:
        /* these do not do multipart and do not require
         * a mechanism parameter.
         */
        if (mech->ulParameterLen != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            return CKR_MECHANISM_PARAM_INVALID;
        }
        multi = FALSE;
        break;
    case CKM_MD5_HMAC:
    case CKM_SHA_1_HMAC:
    case CKM_SHA224_HMAC:
    case CKM_SHA256_HMAC:
    case CKM_SHA384_HMAC:
    case CKM_SHA512_HMAC:
        /* hmacs can do mulitpart and do not require a
         *  mechanism parameter.
         */
        if (mech->ulParameterLen != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            return CKR_MECHANISM_PARAM_INVALID;
        }
        multi = TRUE;
        break;
    case CKM_SSL3_MD5_MAC:
    case CKM_SSL3_SHA1_MAC:
        /* can do mulitpart and take a mech parameter */

        param = (CK_MAC_GENERAL_PARAMS *) mech->pParameter;

        if (mech->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS) ||
            mech->pParameter == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            return CKR_MECHANISM_PARAM_INVALID;
        }
        if (((mech->mechanism == CKM_SSL3_MD5_MAC) && (*param != 16)) ||
            ((mech->mechanism == CKM_SSL3_SHA1_MAC) && (*param != 20))) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            return CKR_MECHANISM_PARAM_INVALID;
        }

        multi = TRUE;
        break;
    case CKM_MD5_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA224_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
    case CKM_DSA_SHA1:
    case CKM_ECDSA_SHA1:
    case CKM_ECDSA_SHA224:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
    case CKM_ECDSA_SHA512:
        /* these can do mulitpart and require data caching
         * and do not require a mechanism parameter.
         */
        if (mech->ulParameterLen != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            return CKR_MECHANISM_PARAM_INVALID;
        }
        multi = TRUE;
        datacaching = TRUE;
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    /* Initialize sign context */
    free_sv_ctx(ctx);

    /* Copy mechanism */
    if (mech->pParameter == NULL || mech->ulParameterLen == 0) {
        ctx->mech.ulParameterLen = 0;
        ctx->mech.pParameter = NULL;
    } else {
        ctx->mech.pParameter = malloc(mech->ulParameterLen);
        if (!ctx->mech.pParameter) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rc = CKR_HOST_MEMORY;
            goto done;
        }
        ctx->mech.ulParameterLen = mech->ulParameterLen;
        memcpy(ctx->mech.pParameter, mech->pParameter, mech->ulParameterLen);
    }
    ctx->mech.mechanism = mech->mechanism;

    /* If the mechanism supports multipart, prepare ctx */
    if (multi) {
        /* Allocate context for multi-part operations */
        if (!(multi_part_ctx = malloc(sizeof(*multi_part_ctx)))) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rc = CKR_HOST_MEMORY;
            goto done;
        }
        ctx->context_len = sizeof(*multi_part_ctx);
        ctx->context = (void *) multi_part_ctx;
        memset(multi_part_ctx, 0, sizeof(*multi_part_ctx));

        /* keep a cache to ensure multiple of blocksize
         * is sent to ICSF.
         */

        if (datacaching) {
            size_t blocksize;

            rc = icsf_block_size(mech->mechanism, &blocksize);
            if (rc != CKR_OK)
                goto done;
            multi_part_ctx->data_len = blocksize;
            multi_part_ctx->data = malloc(multi_part_ctx->data_len);
            if (!multi_part_ctx->data) {
                TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                rc = CKR_HOST_MEMORY;
                goto done;
            }
            memset(multi_part_ctx->data, 0, blocksize);
        }
    } else {
        ctx->context_len = 0;
        ctx->context = NULL;
    }

    ctx->key = key;
    ctx->multi = FALSE;
    ctx->active = TRUE;

done:
    if (rc == CKR_OK && tokdata->statistics->increment_func != NULL)
        tokdata->statistics->increment_func(tokdata->statistics,
                                            session->session_info.slotID,
                                            mech, mapping->strength.strength);

    if (mapping) {
        bt_put_node_value(&icsf_data->objects, mapping);
        mapping = NULL;
    }
    if (rc != CKR_OK)
        free_sv_ctx(ctx);

    return rc;
}

CK_RV icsftok_sign(STDLL_TokData_t * tokdata,
                   SESSION * session, CK_BYTE * in_data, CK_ULONG in_data_len,
                   CK_BYTE * signature, CK_ULONG * sig_len)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    struct session_state *session_state;
    SIGN_VERIFY_CONTEXT *ctx = &session->sign_ctx;
    struct icsf_object_mapping *mapping = NULL;
    char chain_data[ICSF_CHAINING_DATA_LEN] = { 0, };
    size_t chain_data_len = sizeof(chain_data);
    CK_RV rc = CKR_OK;
    int hlen, reason;
    CK_BBOOL length_only = (signature == NULL);

    if (ctx->multi == TRUE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
        rc = CKR_OPERATION_ACTIVE;
        goto done;
    }

    /* Check session */
    if (!(session_state = get_session_state(tokdata, session->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        rc = CKR_SESSION_HANDLE_INVALID;
        goto done;
    }

    /* check ldap handle */
    if (session_state->ld == NULL) {
        TRACE_ERROR("No LDAP handle.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Check if key exists */
    if (!(mapping = bt_get_node_value(&icsf_data->objects, ctx->key))) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
        rc = CKR_KEY_HANDLE_INVALID;
        goto done;
    }

    switch (ctx->mech.mechanism) {
    case CKM_MD5_HMAC:
    case CKM_SHA_1_HMAC:
    case CKM_SHA224_HMAC:
    case CKM_SHA256_HMAC:
    case CKM_SHA384_HMAC:
    case CKM_SHA512_HMAC:
    case CKM_SSL3_MD5_MAC:
    case CKM_SSL3_SHA1_MAC:
        if (length_only) {
            hlen = get_signverify_len(ctx->mech);
            if (hlen < 0) {
                TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
                rc = CKR_MECHANISM_INVALID;
                goto done;
            }
            *sig_len = hlen;
            rc = CKR_OK;
            goto done;
        }

        rc = icsf_hmac_sign(session_state->ld, &reason,
                            &mapping->icsf_object, &ctx->mech, "ONLY",
                            (char *)in_data, in_data_len,
                            (char *)signature, sig_len,
                            chain_data, &chain_data_len);
        if (rc != 0)
            rc = icsf_to_ock_err(rc, reason);
        break;
    case CKM_RSA_X_509:
    case CKM_RSA_PKCS:
    case CKM_DSA:
    case CKM_ECDSA:
        rc = icsf_private_key_sign(session_state->ld, &reason, FALSE,
                                   &mapping->icsf_object, &ctx->mech,
                                   (char *)in_data, in_data_len,
                                   (char *)signature, sig_len);
        if (rc != 0) {
            if (reason == ICSF_REASON_OUTPUT_PARAMETER_TOO_SHORT &&
                length_only) {
                rc = CKR_OK;
            } else {
                TRACE_DEVEL("icsf_private_key_sign failed\n");
                rc = icsf_to_ock_err(rc, reason);
            }
        }
        break;
    case CKM_MD5_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA224_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
    case CKM_DSA_SHA1:
    case CKM_ECDSA_SHA1:
    case CKM_ECDSA_SHA224:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
    case CKM_ECDSA_SHA512:
        rc = icsf_hash_signverify(session_state->ld, &reason,
                                  &mapping->icsf_object, &ctx->mech,
                                  "ONLY", (char *)in_data, in_data_len,
                                  (char *)signature, sig_len,
                                  chain_data, &chain_data_len, 0);
        if (rc != 0) {
            if (reason == ICSF_REASON_OUTPUT_PARAMETER_TOO_SHORT &&
                length_only) {
                rc = CKR_OK;
            } else {
                TRACE_DEVEL("icsf_hash_signverify failed\n");
                rc = icsf_to_ock_err(rc, reason);
            }
        }
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
    }

done:
    if (mapping) {
        bt_put_node_value(&icsf_data->objects, mapping);
        mapping = NULL;
    }
    if (rc != CKR_BUFFER_TOO_SMALL && !(rc == CKR_OK && length_only))
        free_sv_ctx(ctx);

    return rc;
}

CK_RV icsftok_sign_update(STDLL_TokData_t * tokdata,
                          SESSION * session, CK_BYTE * in_data,
                          CK_ULONG in_data_len)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    struct session_state *session_state;
    SIGN_VERIFY_CONTEXT *ctx = &session->sign_ctx;
    struct icsf_object_mapping *mapping = NULL;
    struct icsf_multi_part_context *multi_part_ctx = NULL;
    char chain_data[ICSF_CHAINING_DATA_LEN] = { 0, };
    size_t chain_data_len = sizeof(chain_data);
    CK_RV rc = CKR_OK;
    int reason;
    size_t siglen = 0;
    CK_ULONG total, remain, out_len = 0;
    char *buffer = NULL;

    /* Check session */
    if (!(session_state = get_session_state(tokdata, session->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        rc = CKR_SESSION_HANDLE_INVALID;
        goto done;
    }

    /* check ldap handle */
    if (session_state->ld == NULL) {
        TRACE_ERROR("No LDAP handle.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Check if key exists */
    if (!(mapping = bt_get_node_value(&icsf_data->objects, ctx->key))) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
        rc = CKR_KEY_HANDLE_INVALID;
        goto done;
    }

    /* indicate this is multipart operation and get chain info from ctx.
     * if any mechanisms that cannot do multipart sign come here, they
     * will not have had ctx->context allocated and will
     * get an error in switch below.
     */
    ctx->multi = TRUE;
    if (ctx->context) {
        multi_part_ctx = (struct icsf_multi_part_context *) ctx->context;
        if (multi_part_ctx->initiated)
            memcpy(chain_data, multi_part_ctx->chain_data, chain_data_len);
    } else {
        TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

    switch (ctx->mech.mechanism) {
    case CKM_MD5_HMAC:
    case CKM_SHA_1_HMAC:
    case CKM_SHA224_HMAC:
    case CKM_SHA256_HMAC:
    case CKM_SHA384_HMAC:
    case CKM_SHA512_HMAC:
    case CKM_SSL3_MD5_MAC:
    case CKM_SSL3_SHA1_MAC:
        rc = icsf_hmac_sign(session_state->ld, &reason,
                            &mapping->icsf_object, &ctx->mech,
                            (multi_part_ctx->initiated) ? "MIDDLE" : "FIRST",
                            (char *)in_data, in_data_len, NULL, &siglen,
                            chain_data, &chain_data_len);

        if (rc != 0) {
            TRACE_DEVEL("icsf_hmac_sign failed\n");
            rc = icsf_to_ock_err(rc, reason);
        } else {
            multi_part_ctx->initiated = TRUE;
            memcpy(multi_part_ctx->chain_data, chain_data, chain_data_len);
        }
        break;
    case CKM_MD5_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA224_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
    case CKM_DSA_SHA1:
    case CKM_ECDSA_SHA1:
    case CKM_ECDSA_SHA224:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
    case CKM_ECDSA_SHA512:
        /* caching data since ICSF wants in multiple of blocksize */
        if (multi_part_ctx && multi_part_ctx->data) {

            total = multi_part_ctx->used_data_len + in_data_len;
            remain = total % multi_part_ctx->data_len;;

            /* if not enough to meet blocksize, cache and exit. */
            if (total < multi_part_ctx->data_len) {
                if (in_data_len > 0)
                    memcpy(multi_part_ctx->data + multi_part_ctx->used_data_len,
                           (char *)in_data, in_data_len);
                multi_part_ctx->used_data_len += in_data_len;

                rc = CKR_OK;
                goto done;
            } else {
                /* there is at least 1 block */

                out_len = total - remain;

                /* prepare a buffer to send data in */
                if (!(buffer = malloc(out_len))) {
                    TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                    rc = CKR_HOST_MEMORY;
                    goto done;
                }
                memcpy(buffer, multi_part_ctx->data,
                       multi_part_ctx->used_data_len);
                if (out_len - multi_part_ctx->used_data_len > 0)
                    memcpy(buffer + multi_part_ctx->used_data_len,
                           (char *)in_data,
                           out_len - multi_part_ctx->used_data_len);

                /* copy remainder of data to ctx
                 * for next time. caching.
                 */
                if (remain != 0)
                    memcpy(multi_part_ctx->data,
                           in_data + (in_data_len - remain), remain);

                multi_part_ctx->used_data_len = remain;
            }
        }

        rc = icsf_hash_signverify(session_state->ld, &reason,
                                  &mapping->icsf_object, &ctx->mech,
                                  (multi_part_ctx->
                                   initiated) ? "MIDDLE" : "FIRST", buffer,
                                  out_len, NULL, NULL, chain_data,
                                  &chain_data_len, 0);

        if (rc != 0) {
            TRACE_DEVEL("icsf_hash_signverify failed\n");
            rc = icsf_to_ock_err(rc, reason);
        } else {
            multi_part_ctx->initiated = TRUE;
            memcpy(multi_part_ctx->chain_data, chain_data, chain_data_len);
        }

        if (buffer)
            free(buffer);

        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
    }

done:
    if (mapping) {
        bt_put_node_value(&icsf_data->objects, mapping);
        mapping = NULL;
    }
    if (rc != CKR_OK)
        free_sv_ctx(ctx);

    return rc;
}

CK_RV icsftok_sign_final(STDLL_TokData_t * tokdata,
                         SESSION * session, CK_BYTE * signature,
                         CK_ULONG * sig_len)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    struct session_state *session_state;
    SIGN_VERIFY_CONTEXT *ctx = &session->sign_ctx;
    struct icsf_object_mapping *mapping = NULL;
    struct icsf_multi_part_context *multi_part_ctx = NULL;
    char chain_data[ICSF_CHAINING_DATA_LEN] = { 0, };
    size_t chain_data_len = sizeof(chain_data);
    char *buffer = NULL;
    CK_RV rc = CKR_OK;
    int hlen, reason;
    CK_BBOOL length_only = (signature == NULL);

    /* Check session */
    if (!(session_state = get_session_state(tokdata, session->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        rc = CKR_SESSION_HANDLE_INVALID;
        goto done;
    }

    /* check ldap handle */
    if (session_state->ld == NULL) {
        TRACE_ERROR("No LDAP handle.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Check if key exists */
    if (!(mapping = bt_get_node_value(&icsf_data->objects, ctx->key))) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
        rc = CKR_KEY_HANDLE_INVALID;
        goto done;
    }

    /* get the chain data from ctx */
    if (ctx->context) {
        multi_part_ctx = (struct icsf_multi_part_context *) ctx->context;
        memcpy(chain_data, multi_part_ctx->chain_data, chain_data_len);
    } else {
        TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

    switch (ctx->mech.mechanism) {
    case CKM_MD5_HMAC:
    case CKM_SHA_1_HMAC:
    case CKM_SHA224_HMAC:
    case CKM_SHA256_HMAC:
    case CKM_SHA384_HMAC:
    case CKM_SHA512_HMAC:
    case CKM_SSL3_MD5_MAC:
    case CKM_SSL3_SHA1_MAC:
        if (length_only) {
            hlen = get_signverify_len(ctx->mech);
            if (hlen < 0) {
                TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
                return CKR_MECHANISM_INVALID;
            }

            *sig_len = hlen;
            return CKR_OK;
        }

        rc = icsf_hmac_sign(session_state->ld, &reason,
                            &mapping->icsf_object, &ctx->mech,
                            multi_part_ctx->initiated ? "LAST" : "ONLY", "",
                            0, (char *)signature, sig_len,
                            chain_data, &chain_data_len);
        if (rc != 0)
            rc = icsf_to_ock_err(rc, reason);
        break;
    case CKM_MD5_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA224_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
    case CKM_DSA_SHA1:
    case CKM_ECDSA_SHA1:
    case CKM_ECDSA_SHA224:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
    case CKM_ECDSA_SHA512:
        /* see if any data left in the cache */
        if (multi_part_ctx && multi_part_ctx->used_data_len) {
            if (!(buffer = malloc(multi_part_ctx->used_data_len))) {
                TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                rc = CKR_HOST_MEMORY;
                goto done;
            }
            memcpy(buffer, multi_part_ctx->data, multi_part_ctx->used_data_len);
        }

        rc = icsf_hash_signverify(session_state->ld, &reason,
                                  &mapping->icsf_object, &ctx->mech,
                                  multi_part_ctx->initiated ? "LAST" : "ONLY",
                                  (buffer) ? buffer : NULL,
                                  multi_part_ctx->used_data_len,
                                  (char *)signature, sig_len,
                                  chain_data, &chain_data_len, 0);

        if (rc != 0) {
            if (length_only && reason == 3003) {
                rc = CKR_OK;
            } else {
                TRACE_DEVEL("icsf_hash_signverify failed\n");
                rc = icsf_to_ock_err(rc, reason);
            }
        }

        if (buffer)
            free(buffer);
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
    }

done:
    if (mapping) {
        bt_put_node_value(&icsf_data->objects, mapping);
        mapping = NULL;
    }
    if (rc != CKR_BUFFER_TOO_SMALL && !(rc == CKR_OK && length_only))
        free_sv_ctx(ctx);

    return rc;
}

CK_RV icsftok_verify_init(STDLL_TokData_t * tokdata,
                          SESSION * session, CK_MECHANISM * mech,
                          CK_OBJECT_HANDLE key)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    struct session_state *session_state;
    SIGN_VERIFY_CONTEXT *ctx = &session->verify_ctx;
    struct icsf_multi_part_context *multi_part_ctx = NULL;
    struct icsf_object_mapping *mapping = NULL;
    CK_RV rc = CKR_OK;
    CK_BBOOL multi = FALSE;
    CK_BBOOL datacaching = FALSE;
    CK_MAC_GENERAL_PARAMS *param;

    /* Check session */
    if (!(session_state = get_session_state(tokdata, session->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        return CKR_SESSION_HANDLE_INVALID;
    }

    /* Check if key exists */
    if (!(mapping = bt_get_node_value(&icsf_data->objects, key))) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
        rc = CKR_KEY_HANDLE_INVALID;
        return rc;
    }
        rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech,
                                              &mapping->strength,
                                              POLICY_CHECK_VERIFY,
                                              session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: Sign init\n");
        goto done;
    }

    /* Check the mechanism info */
    switch (mech->mechanism) {
    case CKM_RSA_X_509:
    case CKM_RSA_PKCS:
    case CKM_DSA:
    case CKM_ECDSA:
        /* these do not do multipart and do not require
         * a mechanism parameter.
         */
        if (mech->ulParameterLen != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        multi = FALSE;
        break;
    case CKM_MD5_HMAC:
    case CKM_SHA_1_HMAC:
    case CKM_SHA224_HMAC:
    case CKM_SHA256_HMAC:
    case CKM_SHA384_HMAC:
    case CKM_SHA512_HMAC:
        /* hmacs can do mulitpart and do not require a
         *  mechanism parameter.
         */
        if (mech->ulParameterLen != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        multi = TRUE;
        break;
    case CKM_SSL3_MD5_MAC:
    case CKM_SSL3_SHA1_MAC:
        /* can do mulitpart and take a mech parameter */
        param = (CK_MAC_GENERAL_PARAMS *) mech->pParameter;

        if (mech->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS) ||
            mech->pParameter == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        if (((mech->mechanism == CKM_SSL3_MD5_MAC) && (*param != 16)) ||
            ((mech->mechanism == CKM_SSL3_SHA1_MAC) && (*param != 20))) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }

        multi = TRUE;
        break;
    case CKM_MD5_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA224_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
    case CKM_DSA_SHA1:
    case CKM_ECDSA_SHA1:
    case CKM_ECDSA_SHA224:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
    case CKM_ECDSA_SHA512:
        /* these can do mulitpart and require data caching
         * but do not require a mechanism parameter
         */
        if (mech->ulParameterLen != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        multi = TRUE;
        datacaching = TRUE;
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    /* Initialize ctx */
    free_sv_ctx(ctx);

    /* Copy mechanism */
    if (mech->pParameter == NULL || mech->ulParameterLen == 0) {
        ctx->mech.ulParameterLen = 0;
        ctx->mech.pParameter = NULL;
    } else {
        ctx->mech.pParameter = malloc(mech->ulParameterLen);
        if (!ctx->mech.pParameter) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rc = CKR_HOST_MEMORY;
            goto done;
        }
        ctx->mech.ulParameterLen = mech->ulParameterLen;
        memcpy(ctx->mech.pParameter, mech->pParameter, mech->ulParameterLen);
    }
    ctx->mech.mechanism = mech->mechanism;

    /* If the mechanism supports multipart, prepare ctx */
    if (multi) {
        /* Allocate context for multi-part operations */
        if (!(multi_part_ctx = malloc(sizeof(*multi_part_ctx)))) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rc = CKR_HOST_MEMORY;
            goto done;
        }
        ctx->context_len = sizeof(*multi_part_ctx);
        ctx->context = (void *) multi_part_ctx;
        memset(multi_part_ctx, 0, sizeof(*multi_part_ctx));

        /* keep a cache to ensure multiple of blocksize
         * is sent to ICSF.
         */

        if (datacaching) {
            size_t blocksize;

            rc = icsf_block_size(mech->mechanism, &blocksize);
            if (rc != CKR_OK)
                goto done;
            multi_part_ctx->data_len = blocksize;
            multi_part_ctx->data = malloc(multi_part_ctx->data_len);
            if (!multi_part_ctx->data) {
                TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                rc = CKR_HOST_MEMORY;
                goto done;
            }
            memset(multi_part_ctx->data, 0, blocksize);
        }
    } else {
        ctx->context_len = 0;
        ctx->context = NULL;
    }

    ctx->key = key;
    ctx->multi = FALSE;
    ctx->active = TRUE;

done:
    if (rc == CKR_OK && tokdata->statistics->increment_func != NULL)
        tokdata->statistics->increment_func(tokdata->statistics,
                                            session->session_info.slotID,
                                            mech, mapping->strength.strength);

    if (mapping) {
        bt_put_node_value(&icsf_data->objects, mapping);
        mapping = NULL;
    }

    if (rc != CKR_OK)
        free_sv_ctx(ctx);

    return rc;
}

CK_RV icsftok_verify(STDLL_TokData_t * tokdata,
                     SESSION * session, CK_BYTE * in_data, CK_ULONG in_data_len,
                     CK_BYTE * signature, CK_ULONG sig_len)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    struct session_state *session_state;
    SIGN_VERIFY_CONTEXT *ctx = &session->verify_ctx;
    struct icsf_object_mapping *mapping = NULL;
    char chain_data[ICSF_CHAINING_DATA_LEN] = { 0, };
    size_t chain_data_len = sizeof(chain_data);
    CK_RV rc = CKR_OK;
    int reason;

    if (ctx->multi == TRUE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
        rc = CKR_OPERATION_ACTIVE;
        goto done;
    }

    /* Check session */
    if (!(session_state = get_session_state(tokdata, session->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        rc = CKR_SESSION_HANDLE_INVALID;
        goto done;
    }

    /* check ldap handle */
    if (session_state->ld == NULL) {
        TRACE_ERROR("No LDAP handle.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Check if key exists */
    if (!(mapping = bt_get_node_value(&icsf_data->objects, ctx->key))) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
        rc = CKR_KEY_HANDLE_INVALID;
        goto done;
    }

    switch (ctx->mech.mechanism) {
    case CKM_MD5_HMAC:
    case CKM_SHA_1_HMAC:
    case CKM_SHA224_HMAC:
    case CKM_SHA256_HMAC:
    case CKM_SHA384_HMAC:
    case CKM_SHA512_HMAC:
    case CKM_SSL3_MD5_MAC:
    case CKM_SSL3_SHA1_MAC:
        rc = icsf_hmac_verify(session_state->ld, &reason,
                              &mapping->icsf_object, &ctx->mech, "ONLY",
                              (char *)in_data, in_data_len,
                              (char *)signature, sig_len,
                              chain_data, &chain_data_len);
        if (rc != 0)
            rc = icsf_to_ock_err(rc, reason);

        break;
    case CKM_RSA_X_509:
    case CKM_RSA_PKCS:
    case CKM_DSA:
    case CKM_ECDSA:
        rc = icsf_public_key_verify(session_state->ld, &reason, FALSE,
                                    &mapping->icsf_object, &ctx->mech,
                                    (char *)in_data, in_data_len,
                                    (char *)signature, &sig_len);
        if (rc != 0)
            rc = icsf_to_ock_err(rc, reason);
        break;
    case CKM_MD5_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA224_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
    case CKM_DSA_SHA1:
    case CKM_ECDSA_SHA1:
    case CKM_ECDSA_SHA224:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
    case CKM_ECDSA_SHA512:
        rc = icsf_hash_signverify(session_state->ld, &reason,
                                  &mapping->icsf_object, &ctx->mech,
                                  "ONLY", (char *)in_data, in_data_len,
                                  (char *)signature, &sig_len,
                                  chain_data, &chain_data_len, 1);
        if (rc != 0)
            rc = icsf_to_ock_err(rc, reason);

        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
    }

done:
    if (mapping) {
        bt_put_node_value(&icsf_data->objects, mapping);
        mapping = NULL;
    }

    free_sv_ctx(ctx);
    return rc;
}

CK_RV icsftok_verify_update(STDLL_TokData_t * tokdata,
                            SESSION * session, CK_BYTE * in_data,
                            CK_ULONG in_data_len)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    struct session_state *session_state;
    SIGN_VERIFY_CONTEXT *ctx = &session->verify_ctx;
    struct icsf_object_mapping *mapping = NULL;
    struct icsf_multi_part_context *multi_part_ctx = NULL;
    char chain_data[ICSF_CHAINING_DATA_LEN] = { 0, };
    size_t chain_data_len = sizeof(chain_data);
    CK_RV rc = CKR_OK;
    int reason;
    CK_ULONG total, remain, out_len = 0;
    char *buffer = NULL;

    /* Check session */
    if (!(session_state = get_session_state(tokdata, session->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        rc = CKR_SESSION_HANDLE_INVALID;
        goto done;
    }

    /* check ldap handle */
    if (session_state->ld == NULL) {
        TRACE_ERROR("No LDAP handle.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Check if key exists */
    if (!(mapping = bt_get_node_value(&icsf_data->objects, ctx->key))) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
        rc = CKR_KEY_HANDLE_INVALID;
        goto done;
    }

    /* indicate this is multipart operation and get chain info from ctx.
     * if any mechanisms that cannot do multipart verify come here, they
     * will get an error in switch below.
     */
    ctx->multi = TRUE;
    if (ctx->context) {
        multi_part_ctx = (struct icsf_multi_part_context *) ctx->context;
        if (multi_part_ctx->initiated)
            memcpy(chain_data, multi_part_ctx->chain_data, chain_data_len);
    } else {
        TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

    switch (ctx->mech.mechanism) {
    case CKM_MD5_HMAC:
    case CKM_SHA_1_HMAC:
    case CKM_SHA224_HMAC:
    case CKM_SHA256_HMAC:
    case CKM_SHA384_HMAC:
    case CKM_SHA512_HMAC:
    case CKM_SSL3_MD5_MAC:
    case CKM_SSL3_SHA1_MAC:
        rc = icsf_hmac_verify(session_state->ld, &reason,
                              &mapping->icsf_object, &ctx->mech,
                              (multi_part_ctx->initiated) ? "MIDDLE" : "FIRST",
                              (char *)in_data, in_data_len, "", 0,
                              chain_data, &chain_data_len);

        if (rc != 0) {
            TRACE_DEVEL("icsf_hmac_verify failed\n");
            rc = icsf_to_ock_err(rc, reason);
        } else {
            multi_part_ctx->initiated = TRUE;
            memcpy(multi_part_ctx->chain_data, chain_data, chain_data_len);
        }
        break;
    case CKM_MD5_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA224_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
    case CKM_DSA_SHA1:
    case CKM_ECDSA_SHA1:
    case CKM_ECDSA_SHA224:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
    case CKM_ECDSA_SHA512:
        /* caching data since ICSF wants in multiple of blocksize */
        if (multi_part_ctx && multi_part_ctx->data) {

            total = multi_part_ctx->used_data_len + in_data_len;
            remain = total % multi_part_ctx->data_len;;

            /* if not enough to meet blocksize, cache and exit. */
            if (total < multi_part_ctx->data_len) {
                if (in_data_len > 0)
                    memcpy(multi_part_ctx->data + multi_part_ctx->used_data_len,
                           (char *)in_data, in_data_len);
                multi_part_ctx->used_data_len += in_data_len;

                rc = CKR_OK;
                goto done;
            } else {
                /* there is at least 1 block */

                out_len = total - remain;

                /* prepare a buffer to send data in */
                if (!(buffer = malloc(out_len))) {
                    TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                    rc = CKR_HOST_MEMORY;
                    goto done;
                }
                memcpy(buffer, multi_part_ctx->data,
                       multi_part_ctx->used_data_len);
                if (out_len - multi_part_ctx->used_data_len > 0)
                    memcpy(buffer + multi_part_ctx->used_data_len,
                           (char *)in_data,
                           out_len - multi_part_ctx->used_data_len);

                /* copy remainder of data to ctx
                 * for next time. caching.
                 */
                if (remain != 0)
                    memcpy(multi_part_ctx->data,
                           (char *)in_data + (in_data_len - remain), remain);

                multi_part_ctx->used_data_len = remain;
            }
        }

        rc = icsf_hash_signverify(session_state->ld, &reason,
                                  &mapping->icsf_object, &ctx->mech,
                                  (multi_part_ctx->
                                   initiated) ? "MIDDLE" : "FIRST", buffer,
                                  out_len, NULL, NULL, chain_data,
                                  &chain_data_len, 1);

        if (rc != 0) {
            TRACE_DEVEL("icsf_hash_signverify failed\n");
            rc = icsf_to_ock_err(rc, reason);
        } else {
            multi_part_ctx->initiated = TRUE;
            memcpy(multi_part_ctx->chain_data, chain_data, chain_data_len);
        }

        if (buffer)
            free(buffer);

        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
    }

done:
    if (mapping) {
        bt_put_node_value(&icsf_data->objects, mapping);
        mapping = NULL;
    }

    if (rc != CKR_OK)
        free_sv_ctx(ctx);

    return rc;
}

CK_RV icsftok_verify_final(STDLL_TokData_t * tokdata,
                           SESSION * session, CK_BYTE * signature,
                           CK_ULONG sig_len)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    struct session_state *session_state;
    SIGN_VERIFY_CONTEXT *ctx = &session->verify_ctx;
    struct icsf_object_mapping *mapping = NULL;
    struct icsf_multi_part_context *multi_part_ctx = NULL;
    char chain_data[ICSF_CHAINING_DATA_LEN] = { 0, };
    size_t chain_data_len = sizeof(chain_data);
    CK_RV rc = CKR_OK;
    int reason;
    char *buffer = NULL;

    if (!sig_len) {
        TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

    /* Check session */
    if (!(session_state = get_session_state(tokdata, session->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        rc = CKR_SESSION_HANDLE_INVALID;
        goto done;
    }

    /* check ldap handle */
    if (session_state->ld == NULL) {
        TRACE_ERROR("No LDAP handle.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Check if key exists */
    if (!(mapping = bt_get_node_value(&icsf_data->objects, ctx->key))) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
        rc = CKR_KEY_HANDLE_INVALID;
        goto done;
    }

    /* get the chain data from ctx */
    if (ctx->context) {
        multi_part_ctx = (struct icsf_multi_part_context *) ctx->context;
        memcpy(chain_data, multi_part_ctx->chain_data, chain_data_len);
    } else {
        TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

    switch (ctx->mech.mechanism) {
    case CKM_MD5_HMAC:
    case CKM_SHA_1_HMAC:
    case CKM_SHA224_HMAC:
    case CKM_SHA256_HMAC:
    case CKM_SHA384_HMAC:
    case CKM_SHA512_HMAC:
    case CKM_SSL3_MD5_MAC:
    case CKM_SSL3_SHA1_MAC:
        /* get the chain data */
        rc = icsf_hmac_verify(session_state->ld, &reason,
                              &mapping->icsf_object, &ctx->mech,
                              multi_part_ctx->initiated ? "LAST" : "ONLY", "",
                              0, (char *)signature, sig_len,
                              chain_data, &chain_data_len);
        if (rc != 0)
            rc = icsf_to_ock_err(rc, reason);

        break;
    case CKM_MD5_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA224_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
    case CKM_DSA_SHA1:
    case CKM_ECDSA_SHA1:
    case CKM_ECDSA_SHA224:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
    case CKM_ECDSA_SHA512:
        /* see if any data left in the cache */
        if (multi_part_ctx && multi_part_ctx->used_data_len) {
            if (!(buffer = malloc(multi_part_ctx->used_data_len))) {
                TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                rc = CKR_HOST_MEMORY;
                goto done;
            }
            memcpy(buffer, multi_part_ctx->data, multi_part_ctx->used_data_len);
        }

        rc = icsf_hash_signverify(session_state->ld, &reason,
                                  &mapping->icsf_object, &ctx->mech,
                                  multi_part_ctx->initiated ? "LAST" : "ONLY",
                                  (buffer) ? buffer : NULL,
                                  multi_part_ctx->used_data_len,
                                  (char *)signature, &sig_len,
                                  chain_data, &chain_data_len, 1);

        if (rc != 0)
            rc = icsf_to_ock_err(rc, reason);

        if (buffer)
            free(buffer);
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
    }

done:
    if (mapping) {
        bt_put_node_value(&icsf_data->objects, mapping);
        mapping = NULL;
    }

    free_sv_ctx(ctx);

    return rc;
}

/*
 * Wrap a key and return it as binary data.
 */
CK_RV icsftok_wrap_key(STDLL_TokData_t * tokdata,
                       SESSION * session, CK_MECHANISM_PTR mech,
                       CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE key,
                       CK_BYTE_PTR wrapped_key, CK_ULONG_PTR p_wrapped_key_len)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    int rc = CKR_OK;
    int reason = 0;
    struct session_state *session_state;
    struct icsf_object_mapping *wrapping_key_mapping = NULL;
    struct icsf_object_mapping *key_mapping = NULL;
    size_t expected_block_size = 0;

    /* Check session */
    if (!(session_state = get_session_state(tokdata, session->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        return CKR_SESSION_HANDLE_INVALID;
    }

    /* check ldap handle */
    if (session_state->ld == NULL) {
        TRACE_ERROR("No LDAP handle.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* Check if keys exist */
    wrapping_key_mapping = bt_get_node_value(&icsf_data->objects, wrapping_key);
    key_mapping = bt_get_node_value(&icsf_data->objects, key);
    if (!wrapping_key_mapping || !key_mapping) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
        rc = CKR_KEY_HANDLE_INVALID;
        goto done;
    }
    rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech,
                                          &wrapping_key_mapping->strength,
                                          POLICY_CHECK_WRAP, session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: Wrap init\n");
        goto done;
    }
    rc = tokdata->policy->is_key_allowed(tokdata->policy,
                                         &key_mapping->strength,
                                         session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: Wrap init\n");
        goto done;
    }

    /* validate mechanism parameters. Only 4 mechanisms support
     * key wrapping in icsf token */
    switch (mech->mechanism) {
    case CKM_DES_CBC_PAD:
    case CKM_DES3_CBC_PAD:
    case CKM_AES_CBC_PAD:
        if ((rc = icsf_block_size(mech->mechanism, &expected_block_size)))
            goto done;

        if (mech->ulParameterLen != expected_block_size ||
            mech->pParameter == NULL) {
            TRACE_ERROR("Invalid mechanism parameter NULL or length: %lu "
                        "(expected %lu)\n",
                        (unsigned long) mech->ulParameterLen,
                        (unsigned long) expected_block_size);
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        break;
    case CKM_RSA_PKCS:
        if (mech->ulParameterLen != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        break;
    default:
        TRACE_ERROR("icsf invalid %lu mechanism for key wrapping\n",
                    mech->mechanism);
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    /* Call ICSF service */
    rc = icsf_wrap_key(session_state->ld, &reason, mech,
                       &wrapping_key_mapping->icsf_object,
                       &key_mapping->icsf_object, wrapped_key,
                       p_wrapped_key_len);
    if (rc) {
        TRACE_DEVEL("icsf_wrap_key failed\n");
        rc = icsf_to_ock_err(rc, reason);
        goto done;
    }

done:
    if (rc == CKR_OK && tokdata->statistics->increment_func != NULL)
        tokdata->statistics->increment_func(tokdata->statistics,
                                            session->session_info.slotID,
                                            mech,
                                            wrapping_key_mapping->strength.strength);

    if (wrapping_key_mapping) {
        bt_put_node_value(&icsf_data->objects, wrapping_key_mapping);
        wrapping_key_mapping = NULL;
    }
    if (key_mapping) {
        bt_put_node_value(&icsf_data->objects, key_mapping);
        key_mapping = NULL;
    }

    return rc;
}

/*
 * Unwrap a key from binary data and create a new key object.
 */
CK_RV icsftok_unwrap_key(STDLL_TokData_t * tokdata,
                         SESSION * session, CK_MECHANISM_PTR mech,
                         CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len,
                         CK_BYTE_PTR wrapped_key, CK_ULONG wrapped_key_len,
                         CK_OBJECT_HANDLE wrapping_key,
                         CK_OBJECT_HANDLE_PTR p_key)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    int rc;
    int reason = 0;
    struct session_state *session_state;
    struct icsf_object_mapping *wrapping_key_mapping = NULL;
    struct icsf_object_mapping *key_mapping = NULL;
    CK_ULONG node_number;
    size_t expected_block_size = 0;
    struct icsf_policy_attr pattr;

    /* Check session */
    if (!(session_state = get_session_state(tokdata, session->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        return CKR_SESSION_HANDLE_INVALID;
    }

    /* check ldap handle */
    if (session_state->ld == NULL) {
        TRACE_ERROR("No LDAP handle.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* Check if key exists */
    wrapping_key_mapping = bt_get_node_value(&icsf_data->objects, wrapping_key);
    if (!wrapping_key_mapping) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
        return CKR_KEY_HANDLE_INVALID;
    }
    rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech,
                                          &wrapping_key_mapping->strength,
                                          POLICY_CHECK_UNWRAP, session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: Unwrap init\n");
        goto done;
    }


    /* Allocate structure to keep ICSF object information */
    if (!(key_mapping = malloc(sizeof(*key_mapping)))) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    memset(key_mapping, 0, sizeof(*key_mapping));
    key_mapping->session_id = session->handle;

    /* validate mechanism parameters. Only 4 mechanisms support
     * key wrapping in icsf token */
    switch (mech->mechanism) {
    case CKM_DES_CBC_PAD:
    case CKM_DES3_CBC_PAD:
    case CKM_AES_CBC_PAD:
        if ((rc = icsf_block_size(mech->mechanism, &expected_block_size)))
            goto done;

        if (mech->ulParameterLen != expected_block_size ||
            mech->pParameter == NULL) {
            TRACE_ERROR("Invalid mechanism parameter NULL or length: %lu "
                        "(expected %lu)\n",
                        (unsigned long) mech->ulParameterLen,
                        (unsigned long) expected_block_size);
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        break;
    case CKM_RSA_PKCS:
        if (mech->ulParameterLen != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        break;
    default:
        TRACE_ERROR("icsf invalid %lu mechanism for key wrapping\n",
                    mech->mechanism);
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    /* Call ICSF service */
    rc = icsf_unwrap_key(session_state->ld, &reason, mech,
                         &wrapping_key_mapping->icsf_object,
                         wrapped_key, wrapped_key_len,
                         attrs, attrs_len, &key_mapping->icsf_object);
    if (rc) {
        TRACE_DEVEL("icsf_unwrap_key failed\n");
        rc = icsf_to_ock_err(rc, reason);
        goto done;
    }
    pattr.ld = session_state->ld;
    pattr.icsf_object = &key_mapping->icsf_object;
    rc = tokdata->policy->store_object_strength(tokdata->policy,
                                                &key_mapping->strength,
                                                icsf_policy_get_attr, &pattr,
                                                icsf_policy_free_attr, session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: Unwrapped key too weak\n");
        goto done;
    }

    /* Add info about object into session */
    if (!(node_number = bt_node_add(&icsf_data->objects, key_mapping))) {
        TRACE_ERROR("Failed to add object to binary tree.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Use node number as handle */
    *p_key = node_number;

done:
    if (rc == CKR_OK && tokdata->statistics->increment_func != NULL)
        tokdata->statistics->increment_func(tokdata->statistics,
                                            session->session_info.slotID,
                                            mech,
                                            wrapping_key_mapping->strength.strength);

    if (wrapping_key_mapping) {
        bt_put_node_value(&icsf_data->objects, wrapping_key_mapping);
        wrapping_key_mapping = NULL;
    }

    /* If allocated, object must be freed in case of failure */
    if (rc && key_mapping)
        free(key_mapping);

    return rc;
}

/*
 * Derive a key from a base key, creating a new key object.
 */
CK_RV icsftok_derive_key(STDLL_TokData_t * tokdata, SESSION * session,
                         CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE hBaseKey,
                         CK_OBJECT_HANDLE_PTR handle, CK_ATTRIBUTE_PTR attrs,
                         CK_ULONG attrs_len)
{
    icsf_private_data_t *icsf_data = tokdata->private_data;
    CK_RV rc = CKR_OK;
    struct session_state *session_state;
    struct icsf_object_mapping *base_key_mapping = NULL;
    CK_ULONG node_number;
    char token_name[sizeof(tokdata->nv_token_data->token_info.label) + 1];
    CK_SSL3_KEY_MAT_PARAMS *params = { 0 };
    unsigned int i;
    int reason = 0;
    struct icsf_policy_attr pattr;

    /* Variable for multiple keys derivation */
    int multiple = 0;
    struct icsf_object_mapping *mappings[4] = { NULL, };
    CK_OBJECT_HANDLE *keys[4] = { NULL, };

    /* Check type of derivation */
    if (mech->mechanism == CKM_SSL3_KEY_AND_MAC_DERIVE ||
        mech->mechanism == CKM_TLS_KEY_AND_MAC_DERIVE) {
        multiple = 1;
        params = (CK_SSL3_KEY_MAT_PARAMS *) mech->pParameter;
        keys[0] = &params->pReturnedKeyMaterial->hClientMacSecret;
        keys[1] = &params->pReturnedKeyMaterial->hServerMacSecret;
        keys[2] = &params->pReturnedKeyMaterial->hClientKey;
        keys[3] = &params->pReturnedKeyMaterial->hServerKey;
    } else {
        keys[0] = handle;
    }

    /* Check permissions based on attributes and session */
    rc = check_session_permissions(session, attrs, attrs_len);
    if (rc != CKR_OK)
        return rc;

    /* Copy token name from shared memory */
    rc = XProcLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to get process lock.\n");
        return rc;
    }

    strunpad(token_name, (const char *)tokdata->nv_token_data->token_info.label,
             sizeof(tokdata->nv_token_data->token_info.label), ' ');

    rc = XProcUnLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to release process lock.\n");
        return rc;
    }

    /* Allocate structure to keep ICSF object information */
    for (i = 0; i < sizeof(mappings) / sizeof(*mappings); i++) {
        if (!(mappings[i] = malloc(sizeof(*mappings[i])))) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rc = CKR_HOST_MEMORY;
            goto done;
        }
        memset(mappings[i], 0, sizeof(*mappings[i]));
        mappings[i]->session_id = session->handle;

        /* If not deriving multiple keys, just one key is needed */
        if (!multiple)
            break;
    }

    /* Get session state */
    if (!(session_state = get_session_state(tokdata, session->handle))) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        rc = CKR_SESSION_HANDLE_INVALID;
        goto done;
    }

    /* check ldap handle */
    if (session_state->ld == NULL) {
        TRACE_ERROR("No LDAP handle.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Convert the OCK_CK_OBJECT_HANDLE_PTR to ICSF */
    base_key_mapping = bt_get_node_value(&icsf_data->objects, hBaseKey);
    if (!base_key_mapping) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
        rc = CKR_KEY_HANDLE_INVALID;
        goto done;
    }
    rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech,
                                          &base_key_mapping->strength,
                                          POLICY_CHECK_DERIVE, session);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: Derive key\n");
        goto done;
    }

    /* Call ICSF service */
    if (!multiple) {
        rc = icsf_derive_key(session_state->ld, &reason, mech,
                             &base_key_mapping->icsf_object,
                             &mappings[0]->icsf_object, attrs, attrs_len);
        if (rc) {
            rc = icsf_to_ock_err(rc, reason);
            goto done;
        }
        pattr.ld = session_state->ld;
        pattr.icsf_object = &mappings[0]->icsf_object;
        rc = tokdata->policy->store_object_strength(tokdata->policy,
                                                    &mappings[0]->strength,
                                                    icsf_policy_get_attr,
                                                    &pattr,
                                                    icsf_policy_free_attr,
                                                    session);
        if (rc != CKR_OK) {
            TRACE_ERROR("POLICY VIOLATION: Derived key too weak\n");
            goto done;
        }
    } else {
        rc = icsf_derive_multiple_keys(session_state->ld, &reason,
                                       mech, &base_key_mapping->icsf_object,
                                       attrs, attrs_len,
                                       &mappings[0]->icsf_object,
                                       &mappings[1]->icsf_object,
                                       &mappings[2]->icsf_object,
                                       &mappings[3]->icsf_object,
                                       params->pReturnedKeyMaterial->pIVClient,
                                       params->pReturnedKeyMaterial->pIVServer);
        if (rc) {
            rc = icsf_to_ock_err(rc, reason);
            goto done;
        }
        pattr.ld = session_state->ld;
        for (i = 0; i < 4; ++i) {
            pattr.icsf_object = &mappings[i]->icsf_object;
            rc = tokdata->policy->store_object_strength(tokdata->policy,
                                                        &mappings[i]->strength,
                                                        icsf_policy_get_attr,
                                                        &pattr,
                                                        icsf_policy_free_attr,
                                                        session);
            if (rc != CKR_OK) {
                TRACE_ERROR("POLICY VIOLATION: Derived key too weak\n");
                goto done;
            }
        }
    }
    

    for (i = 0; i < sizeof(mappings) / sizeof(*mappings); i++) {
        /* Add info about object into session */
        if (!(node_number = bt_node_add(&icsf_data->objects, mappings[i]))) {
            TRACE_ERROR("Failed to add object to binary tree.\n");
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        /* Use node number as handle */
        *keys[i] = node_number;

        /* If not deriving multiple keys, just one key is returned */
        if (!multiple)
            break;
    }

done:
    if (rc == CKR_OK && tokdata->statistics->increment_func != NULL)
        tokdata->statistics->increment_func(tokdata->statistics,
                                            session->session_info.slotID,
                                            mech,
                                            base_key_mapping->strength.strength);

    if (base_key_mapping) {
        bt_put_node_value(&icsf_data->objects, base_key_mapping);
        base_key_mapping = NULL;
    }

    /* If allocated, object must be freed in case of failure */
    if (rc) {
        for (i = 0; i < sizeof(mappings) / sizeof(*mappings); i++)
            if (mappings[i])
                free(mappings[i]);
    }

    return rc;
}
