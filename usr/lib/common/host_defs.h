/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <sys/mman.h>
#ifndef _HOST_DEFS_H
#define _HOST_DEFS_H

#include <pthread.h>
#include <endian.h>

#include "pkcs32.h"
#include <stdint.h>
#include <pthread.h>

#include "local_types.h"
#include "../api/policy.h"
#include "../api/mechtable.h"
#include "../api/statistics.h"

struct _SESSION;

typedef void (*context_free_func_t)(STDLL_TokData_t *tokdata, struct _SESSION *sess,
                                    CK_BYTE *context, CK_ULONG context_len);

typedef struct _ENCR_DECR_CONTEXT {
    CK_OBJECT_HANDLE key;
    CK_MECHANISM mech;
    CK_BYTE *context;
    CK_ULONG context_len;
    context_free_func_t context_free_func;
    CK_BBOOL multi;
    CK_BBOOL active;
    CK_BBOOL init_pending;      // indicate init request pending
    CK_BBOOL multi_init;        // multi field is initialized
                                // on first call *after* init
    CK_BBOOL pkey_active;
    CK_BBOOL state_unsaveable;
    CK_BBOOL count_statistics;
} ENCR_DECR_CONTEXT;

typedef struct _DIGEST_CONTEXT {
    CK_MECHANISM mech;
    CK_BYTE *context;
    CK_ULONG context_len;
    context_free_func_t context_free_func;
    CK_BBOOL multi;
    CK_BBOOL active;
    CK_BBOOL multi_init;        // multi field is initialized
                                // on first call *after* init
    CK_BBOOL state_unsaveable;
    CK_BBOOL count_statistics;
} DIGEST_CONTEXT;

typedef struct _SIGN_VERIFY_CONTEXT {
    CK_OBJECT_HANDLE key;
    CK_MECHANISM mech;          // current sign mechanism
    CK_BYTE *context;           // temporary work area
    CK_ULONG context_len;
    context_free_func_t context_free_func;
    CK_BBOOL multi;             // is this a multi-part operation?
    CK_BBOOL recover;           // are we in recover mode?
    CK_BBOOL active;
    CK_BBOOL init_pending;      // indicate init request pending
    CK_BBOOL multi_init;        // multi field is initialized
                                // on first call *after* init
    CK_BBOOL pkey_active;
    CK_BBOOL state_unsaveable;
    CK_BBOOL count_statistics;
} SIGN_VERIFY_CONTEXT;


typedef struct _SESSION {
    struct bt_ref_hdr hdr;
    CK_SESSION_HANDLE handle;
    CK_SESSION_INFO session_info;

    CK_OBJECT_HANDLE *find_list;        // array of CK_OBJECT_HANDLE
    CK_ULONG_32 find_count;     // # handles in the list
    CK_ULONG_32 find_len;       // max # of handles in the list
    CK_ULONG_32 find_idx;       // current position
    CK_BBOOL find_active;

    ENCR_DECR_CONTEXT encr_ctx;
    ENCR_DECR_CONTEXT decr_ctx;
    DIGEST_CONTEXT digest_ctx;
    SIGN_VERIFY_CONTEXT sign_ctx;
    SIGN_VERIFY_CONTEXT verify_ctx;

    void *private_data;
} SESSION;

/* TODO:
 * Add compile-time checking that sizeof(void *) == sizeof(CK_SESSION_HANDLE)
 * */


typedef struct _DES_CONTEXT {
    CK_BYTE data[DES_BLOCK_SIZE];
    CK_ULONG len;
    CK_BBOOL cbc_pad;           // is this a CKM_DES_CBC_PAD operation?
} DES_CONTEXT;

typedef struct _DES_DATA_CONTEXT {
    CK_BYTE data[DES_BLOCK_SIZE];
    CK_ULONG len;
    CK_BYTE iv[DES_BLOCK_SIZE];
} DES_DATA_CONTEXT;

typedef struct _AES_CONTEXT {
    CK_BYTE data[AES_BLOCK_SIZE];
    CK_ULONG len;
    CK_BBOOL cbc_pad;
} AES_CONTEXT;

typedef struct _AES_XTS_CONTEXT {
    CK_BYTE iv[AES_INIT_VECTOR_SIZE];
    CK_BYTE data[2 * AES_BLOCK_SIZE];
    CK_ULONG len;
    CK_BBOOL initialized;
} AES_XTS_CONTEXT;

typedef struct _AES_DATA_CONTEXT {
    CK_BYTE data[AES_BLOCK_SIZE];
    CK_ULONG len;
    CK_BYTE iv[AES_BLOCK_SIZE];
} AES_DATA_CONTEXT;

typedef struct _AES_GCM_CONTEXT {
    /* Data buffer for DecryptUpdate needs space
     * for tag data and remaining tail data */
    CK_BYTE data[2 * AES_BLOCK_SIZE];
    CK_ULONG len;
    CK_BYTE icb[AES_BLOCK_SIZE];
    CK_BYTE ucb[AES_BLOCK_SIZE];
    CK_BYTE hash[AES_BLOCK_SIZE];
    CK_BYTE subkey[AES_BLOCK_SIZE];
    CK_ULONG ulAlen;
    CK_ULONG ulClen;
} AES_GCM_CONTEXT;

typedef struct _SHA1_CONTEXT {
    unsigned int buf[16];
    unsigned int hash_value[5];
    unsigned int bits_hi, bits_lo;      // # bits  processed so far

} SHA1_CONTEXT;

typedef SHA1_CONTEXT SHA2_CONTEXT;

#if !(NOMD2)
typedef struct _MD2_CONTEXT {
    CK_BYTE state[16];          // state
    CK_BYTE checksum[16];       // checksum
    CK_ULONG count;             // number of bytes, modulo 16
    CK_BYTE buffer[16];         // input buffer
} MD2_CONTEXT;
#endif

typedef struct _MD5_CONTEXT {
    CK_ULONG i[2];              // number of _bits_ handled mod 2^64
    CK_ULONG buf[4];            // scratch buffer
    CK_BYTE in[64];             // input buffer
    CK_BYTE digest[16];         // actual digest after MD5Final call

} MD5_CONTEXT;

typedef struct _DES_CMAC_CONTEXT {
    CK_BYTE data[DES_BLOCK_SIZE];
    CK_ULONG len;
    CK_BYTE iv[DES_BLOCK_SIZE];
    CK_BBOOL initialized;
    CK_VOID_PTR ctx;
} DES_CMAC_CONTEXT;

typedef struct _AES_CMAC_CONTEXT {
    CK_BYTE data[AES_BLOCK_SIZE];
    CK_ULONG len;
    CK_BYTE iv[AES_BLOCK_SIZE];
    CK_BBOOL initialized;
    CK_VOID_PTR ctx;
} AES_CMAC_CONTEXT;

// linux
typedef pthread_mutex_t MUTEX;

// This is actualy wrong... XPROC will be with spinlocks

typedef struct _TEMPLATE {
    DL_NODE *attribute_list;
} TEMPLATE;


typedef struct _OBJECT {
    struct bt_ref_hdr hdr;
    CK_OBJECT_CLASS class;
    CK_BYTE name[8];            // for token objects

    SESSION *session;           // creator; only for session objects
    TEMPLATE *template;
    pthread_rwlock_t template_rwlock; // Lock for object's template
    CK_ULONG count_hi;          // only significant for token objects
    CK_ULONG count_lo;          // only significant for token objects
    CK_ULONG index;             // SAB  Index into the SHM
    CK_OBJECT_HANDLE map_handle;

    // policy support (set via store_object_strength_f pointer)
    struct objstrength strength;
} OBJECT;


typedef struct _OBJECT_MAP {
    struct bt_ref_hdr hdr;
    CK_OBJECT_HANDLE obj_handle;
    CK_BBOOL is_private;
    CK_BBOOL is_session_obj;
    SESSION *session;
} OBJECT_MAP;

/* FIXME: Compile-time check that sizeof(void *) == sizeof(CK_OBJECT_HANDLE) */


typedef struct _ATTRIBUTE_PARSE_LIST {
    CK_ATTRIBUTE_TYPE type;
    void *ptr;
    CK_ULONG len;
    CK_BBOOL found;
} ATTRIBUTE_PARSE_LIST;


typedef struct _OP_STATE_DATA {
    CK_CHAR library_version[16]; /* zero termination does not matter here */
    CK_CHAR manufacturerID[member_size(CK_TOKEN_INFO_32, manufacturerID)];
    CK_CHAR model[member_size(CK_TOKEN_INFO_32, model)];
    CK_STATE session_state;
    CK_ULONG active_operation;
    CK_ULONG data_len;
    // state data gets appended here
    //

    // mechanism parameter gets appended here
    //
} OP_STATE_DATA;


// this is our internal "tweak" vector (not the FCV) used to tweak various
// aspects of the PKCS #11 implementation.  Some of these tweaks deviate from
// the PKCS #11 specification but are needed to support Netscape.  Others
// are left as token-defined values by PKCS #11.
//
//    - whether or not to allow weak/semi-weak DES keys to be imported
//    - whether to insist imported DES keys have proper parity
//    - whether the CKA_ENCRYPT/DECRYPT/SIGN/VERIFY attributes are modifiable
//      after key creation
//
typedef struct _TWEAK_VEC {
    int allow_weak_des;
    int check_des_parity;
    int allow_key_mods;
    int netscape_mods;
} TWEAK_VEC;

typedef struct _TOKEN_DATA_VERSION {
    uint32_t version; /* major<<16|minor */
    /* --- PBKDF2 --- */
    /* SO login */
    uint64_t so_login_it;
    unsigned char so_login_salt[64];
    unsigned char so_login_key[32];
    /* User login */
    uint64_t user_login_it;
    unsigned char user_login_salt[64];
    unsigned char user_login_key[32];
    /* SO MK wrap */
    uint64_t so_wrap_it;
    unsigned char so_wrap_salt[64];
    /* User MK wrap */
    uint64_t user_wrap_it;
    unsigned char user_wrap_salt[64];
} TOKEN_DATA_VERSION;

typedef struct _TOKEN_DATA {
    CK_TOKEN_INFO_32 token_info;

    CK_BYTE user_pin_sha[3 * DES_BLOCK_SIZE];
    CK_BYTE so_pin_sha[3 * DES_BLOCK_SIZE];
    CK_BYTE unused[8];
    TWEAK_VEC tweak_vector;

    /* new for tokversion >= 3.12 */
    TOKEN_DATA_VERSION dat;
} TOKEN_DATA;

typedef struct _TOKEN_DATA_OLD {
    CK_TOKEN_INFO_32 token_info;

    CK_BYTE user_pin_sha[3 * DES_BLOCK_SIZE];
    CK_BYTE so_pin_sha[3 * DES_BLOCK_SIZE];
    CK_BYTE next_token_object_name[8];
    TWEAK_VEC tweak_vector;
} TOKEN_DATA_OLD;

typedef struct _SSL3_MAC_CONTEXT {
    DIGEST_CONTEXT hash_context;
    CK_BBOOL flag;
} SSL3_MAC_CONTEXT;


typedef struct _RSA_DIGEST_CONTEXT {
    DIGEST_CONTEXT hash_context;
    CK_BBOOL flag;
} RSA_DIGEST_CONTEXT;


typedef struct _MECH_LIST_ELEMENT {
    CK_MECHANISM_TYPE mech_type;
    CK_MECHANISM_INFO mech_info;
} MECH_LIST_ELEMENT;

struct mech_list_item;

struct mech_list_item {
    struct mech_list_item *next;
    MECH_LIST_ELEMENT element;
};

struct mech_list_item *find_mech_list_item_for_type(CK_MECHANISM_TYPE type,
                                                    struct mech_list_item
                                                    *head);

/* mech_list.c */
CK_RV ock_generic_filter_mechanism_list(STDLL_TokData_t *tokdata,
                                        const MECH_LIST_ELEMENT *list,
                                        CK_ULONG listlen,
                                        MECH_LIST_ELEMENT **reslist,
                                        CK_ULONG *reslen);

/* mech_list.c */
CK_RV ock_generic_get_mechanism_list(STDLL_TokData_t * tokdata,
                                     CK_MECHANISM_TYPE_PTR pMechanismList,
                                     CK_ULONG_PTR pulCount);

/* mech_list.c */
CK_RV ock_generic_get_mechanism_info(STDLL_TokData_t * tokdata,
                                     CK_MECHANISM_TYPE type,
                                     CK_MECHANISM_INFO_PTR pInfo);

typedef struct _TOK_OBJ_ENTRY {
    CK_BBOOL deleted;
    char name[8];
    CK_ULONG_32 count_lo;
    CK_ULONG_32 count_hi;
} TOK_OBJ_ENTRY;

struct _LW_SHM_TYPE {
    TOKEN_DATA nv_token_data;
    CK_ULONG_32 num_priv_tok_obj;
    CK_ULONG_32 num_publ_tok_obj;
    CK_BBOOL priv_loaded;
    CK_BBOOL publ_loaded;
    TOK_OBJ_ENTRY publ_tok_objs[MAX_TOK_OBJS];
    TOK_OBJ_ENTRY priv_tok_objs[MAX_TOK_OBJS];
};

struct _STDLL_TokData_t {
    CK_SLOT_INFO slot_info;
    CK_SLOT_ID slot_id;
    pid_t real_pid; /* pid of client process in pkcsslotd namespace */
    uid_t real_uid; /* uid of client process in pkcsslotd namespace */
    gid_t real_gid; /* gid of client process in pkcsslotd namespace */
    int spinxplfd;              // token specific lock
    unsigned int spinxplfd_count; // counter for recursive file lock
    pthread_mutex_t spinxplfd_mutex; // token specific pthread lock
    char *pk_dir;
    char data_store[256];       // path information of the token directory
    CK_BYTE user_pin_md5[MD5_HASH_SIZE];
    CK_BYTE so_pin_md5[MD5_HASH_SIZE];
    CK_BYTE master_key[MAX_KEY_SIZE];
    CK_BBOOL initialized;
    CK_ULONG ro_session_count;
    CK_STATE global_login_state;
    LW_SHM_TYPE *global_shm;
    TOKEN_DATA *nv_token_data;
    void *private_data;
    uint32_t version; /* major<<16|minor */
    unsigned char so_wrap_key[32];
    unsigned char user_wrap_key[32];
    pthread_mutex_t login_mutex;
    struct btree sess_btree;
    pthread_rwlock_t sess_list_rwlock;
    struct btree object_map_btree;
    struct btree sess_obj_btree;
    struct btree publ_token_obj_btree;
    struct btree priv_token_obj_btree;
    MECH_LIST_ELEMENT *mech_list;
    CK_ULONG mech_list_len;
    struct policy *policy;
    const struct mechtable_funcs *mechtable_funcs;
    struct statistics *statistics;
    struct tokstore_strength store_strength;
    CK_BBOOL hsm_mk_change_supported;
    pthread_rwlock_t hsm_mk_change_rwlock;
};

#endif
