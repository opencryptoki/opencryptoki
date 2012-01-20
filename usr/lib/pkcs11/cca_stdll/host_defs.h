/*
 * Licensed materials, Property of IBM Corp.
 *
 * openCryptoki CCA token
 *
 * (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2006
 *
 * Author: Kent E. Yoder <yoder1@us.ibm.com>
 *
 */


#include <sys/mman.h>
#ifndef _HOST_DEFS_H
#define _HOST_DEFS_H

#include <pthread.h>
#include <endian.h>

#include "pkcs32.h"
// Both of the strings below have a length of 32 chars and must be
// padded with spaces, and non-null terminated.
//
#define PKW_CRYPTOKI_VERSION_MAJOR      2
#define PKW_CRYPTOKI_VERSION_MINOR      1
#define PKW_CRYPTOKI_MANUFACTURER       "IBM Corp.                       "
#define PKW_CRYPTOKI_LIBDESC            "PKCS#11 Interface for IBM 4758  "
#define PKW_CRYPTOKI_LIB_VERSION_MAJOR  1
#define PKW_CRYPTOKI_LIB_VERSION_MINOR  0
#define PKW_MAX_DEVICES                 10

#define MAX_TOK_OBJS  2048

CK_BBOOL pin_expired(CK_SESSION_INFO *, CK_FLAGS);
CK_BBOOL pin_locked(CK_SESSION_INFO *, CK_FLAGS);
void set_login_flags(CK_USER_TYPE, CK_FLAGS_32 *);

// the following enum is for performance measurements.  since the server runs
// as an NT service, it's difficult (impossible?) to use a standalone performance
// probe
//
enum {
   PRF_DUMMYFUNCTION = 1,
   PRF_FCVFUNCTION,
   PRF_INITIALIZE,
   PRF_FINALIZE,
   PRF_GETINFO,
   PRF_GETFUNCTIONLIST,
   PRF_GETSLOTLIST,
   PRF_GETSLOTINFO,
   PRF_GETTOKENINFO,
   PRF_GETMECHLIST,
   PRF_GETMECHINFO,
   PRF_INITTOKEN,
   PRF_INITPIN,
   PRF_SETPIN,
   PRF_OPENSESSION,
   PRF_CLOSESESSION,
   PRF_CLOSEALLSESSIONS,
   PRF_GETSESSIONINFO,
   PRF_GETOPERATIONSTATE,
   PRF_SETOPERATIONSTATE,
   PRF_LOGIN,
   PRF_LOGOUT,
   PRF_CREATEOBJECT,
   PRF_COPYOBJECT,
   PRF_DESTROYOBJECT,
   PRF_GETOBJECTSIZE,
   PRF_GETATTRIBUTEVALUE,
   PRF_SETATTRIBUTEVALUE,
   PRF_FINDOBJECTSINIT,
   PRF_FINDOBJECTS,
   PRF_FINDOBJECTSFINAL,
   PRF_ENCRYPTINIT,
   PRF_ENCRYPT,
   PRF_ENCRYPTUPDATE,
   PRF_ENCRYPTFINAL,
   PRF_DECRYPTINIT,
   PRF_DECRYPT,
   PRF_DECRYPTUPDATE,
   PRF_DECRYPTFINAL,
   PRF_DIGESTINIT,
   PRF_DIGEST,
   PRF_DIGESTUPDATE,
   PRF_DIGESTKEY,
   PRF_DIGESTFINAL,
   PRF_SIGNINIT,
   PRF_SIGN,
   PRF_SIGNUPDATE,
   PRF_SIGNFINAL,
   PRF_SIGNRECOVERINIT,
   PRF_SIGNRECOVER,
   PRF_VERIFYINIT,
   PRF_VERIFY,
   PRF_VERIFYUPDATE,
   PRF_VERIFYFINAL,
   PRF_VERIFYRECOVERINIT,
   PRF_VERIFYRECOVER,
   PRF_GENKEY,
   PRF_GENKEYPAIR,
   PRF_WRAPKEY,
   PRF_UNWRAPKEY,
   PRF_DERIVEKEY,
   PRF_GENRND,
   PRF_LASTENTRY
};

#define TOTAL 1
#define CARD  2

// Endianness-conversion routines.  This will be useful for folks trying
// to use the coprocessor on a big-endian architecture...
//
// htocl -- host to card long
// ctohl -- card to host long
//

#ifndef __BYTE_ORDER
#error "MUST DEFINE ENDIANESS"
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
  #define   HTOCL(x)   (x)
  #define   CTOHL(x)   (x)
#else
  #define   HTOCL(x)   (long_reverse(x))
  #define   CTOHL(x)   (long_reverse(x))
#endif


typedef struct _ENCR_DECR_CONTEXT
{
   CK_OBJECT_HANDLE  key;
   CK_MECHANISM	     mech;
   CK_BYTE          *context;
   CK_ULONG          context_len;
   CK_BBOOL          multi;
   CK_BBOOL          active;
} ENCR_DECR_CONTEXT;

typedef struct _DIGEST_CONTEXT
{
   CK_MECHANISM   mech;
   CK_BYTE       *context;
   CK_ULONG       context_len;
   CK_BBOOL       multi;
   CK_BBOOL       active;
} DIGEST_CONTEXT;

typedef struct _SIGN_VERIFY_CONTEXT
{
   CK_OBJECT_HANDLE key;
   CK_MECHANISM     mech;     // current sign mechanism
   CK_BYTE         *context;  // temporary work area
   CK_ULONG         context_len;
   CK_BBOOL         multi;    // is this a multi-part operation?
   CK_BBOOL         recover;  // are we in recover mode?
   CK_BBOOL         active;
} SIGN_VERIFY_CONTEXT;


typedef struct _SESSION
{
   CK_SESSION_HANDLE    handle;
   CK_SESSION_INFO      session_info;

   CK_OBJECT_HANDLE    *find_list;     // array of CK_OBJECT_HANDLE
   CK_ULONG_32             find_count;    // # handles in the list
   CK_ULONG_32             find_len;      // max # of handles in the list
   CK_ULONG_32             find_idx;      // current position
   CK_BBOOL             find_active;

   ENCR_DECR_CONTEXT    encr_ctx;
   ENCR_DECR_CONTEXT    decr_ctx;
   DIGEST_CONTEXT       digest_ctx;
   SIGN_VERIFY_CONTEXT  sign_ctx;
   SIGN_VERIFY_CONTEXT  verify_ctx;
} SESSION;

/* TODO:
 * Add compile-time checking that sizeof(void *) == sizeof(CK_SESSION_HANDLE)
 * */


typedef struct _DES_CONTEXT
{
   CK_BYTE  data[ DES_BLOCK_SIZE ];
   CK_ULONG len;
   CK_BBOOL cbc_pad;    // is this a CKM_DES_CBC_PAD operation?
} DES_CONTEXT;

typedef struct _AES_CONTEXT
{
   CK_BYTE  data[ AES_BLOCK_SIZE ];
   CK_ULONG len;
   CK_BBOOL cbc_pad;
} AES_CONTEXT;

typedef struct _SHA1_CONTEXT
{
   unsigned int  buf[16];
   unsigned int  hash_value[5];
   unsigned int bits_hi, bits_lo;    // # bits  processed so far

} SHA1_CONTEXT;

typedef SHA1_CONTEXT SHA2_CONTEXT;


typedef struct _MD2_CONTEXT
{
   CK_BYTE  state[16];             // state
   CK_BYTE  checksum[16];          // checksum
   CK_ULONG count;                 // number of bytes, modulo 16
   CK_BYTE  buffer[16];            // input buffer
} MD2_CONTEXT;


typedef struct _MD5_CONTEXT {
  CK_ULONG i[2];                   // number of _bits_ handled mod 2^64
  CK_ULONG buf[4];                 // scratch buffer
  CK_BYTE  in[64];                 // input buffer
  CK_BYTE  digest[16];             // actual digest after MD5Final call

} MD5_CONTEXT;


// linux
typedef pthread_mutex_t MUTEX;

typedef struct _TEMPLATE
{
   DL_NODE  *attribute_list;
} TEMPLATE;


typedef struct _OBJECT
{
   CK_OBJECT_CLASS   class;
   CK_BYTE           name[8];   // for token objects

   SESSION          *session;   // creator; only for session objects
   TEMPLATE         *template;
   CK_ULONG          count_hi;  // only significant for token objects
   CK_ULONG          count_lo;  // only significant for token objects
   CK_ULONG	     index;  // SAB  Index into the SHM
   CK_OBJECT_HANDLE  map_handle;
} OBJECT;


typedef struct _OBJECT_MAP
{
   CK_OBJECT_HANDLE     obj_handle;
   CK_BBOOL             is_private;
   CK_BBOOL             is_session_obj;
   SESSION            * session;
} OBJECT_MAP;

/* FIXME: Compile-time check that sizeof(void *) == sizeof(CK_OBJECT_HANDLE) */


typedef struct _ATTRIBUTE_PARSE_LIST
{
  CK_ATTRIBUTE_TYPE type;
  void             *ptr;
  CK_ULONG          len;
  CK_BBOOL          found;
} ATTRIBUTE_PARSE_LIST;


typedef struct _OP_STATE_DATA
{
   CK_STATE    session_state;
   CK_ULONG    active_operation;
   CK_ULONG    data_len;
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
typedef struct _TWEAK_VEC
{
   int   allow_weak_des   ;
   int   check_des_parity ;
   int   allow_key_mods   ;
   int   netscape_mods    ;
} TWEAK_VEC;

typedef struct _TOKEN_DATA
{
   CK_TOKEN_INFO_32 token_info;

   CK_BYTE   user_pin_sha[3 * DES_BLOCK_SIZE];
   CK_BYTE   so_pin_sha[3 * DES_BLOCK_SIZE];
   CK_BYTE   next_token_object_name[8];
   TWEAK_VEC tweak_vector;
} TOKEN_DATA;


typedef struct _SSL3_MAC_CONTEXT {
   DIGEST_CONTEXT hash_context;
   CK_BBOOL       flag;
} SSL3_MAC_CONTEXT;


typedef struct _RSA_DIGEST_CONTEXT {
   DIGEST_CONTEXT hash_context;
   CK_BBOOL       flag;
} RSA_DIGEST_CONTEXT;


typedef struct _MECH_LIST_ELEMENT
{
   CK_MECHANISM_TYPE    mech_type;
   CK_MECHANISM_INFO    mech_info;
} MECH_LIST_ELEMENT;

struct mech_list_item;

struct mech_list_item {
  struct mech_list_item *next;
  MECH_LIST_ELEMENT element;
};

struct mech_list_item *
find_mech_list_item_for_type(CK_MECHANISM_TYPE type,
                             struct mech_list_item *head);

/* mech_list.c */
CK_RV
ock_generic_get_mechanism_list(CK_MECHANISM_TYPE_PTR pMechanismList,
                               CK_ULONG_PTR pulCount);

/* mech_list.c */
CK_RV
ock_generic_get_mechanism_info(CK_MECHANISM_TYPE type,
                               CK_MECHANISM_INFO_PTR pInfo);

typedef struct _MASTER_KEY_FILE_T
{
   CK_BYTE     key[MASTER_KEY_SIZE];
   CK_BYTE     sha_hash[SHA1_HASH_SIZE];
} MASTER_KEY_FILE_T;


typedef struct _TOK_OBJ_ENTRY
{
   CK_BBOOL  deleted;
   char      name[8];
   CK_ULONG_32  count_lo;
   CK_ULONG_32  count_hi;
} TOK_OBJ_ENTRY;

typedef struct _LW_SHM_TYPE
{
   TOKEN_DATA     nv_token_data;
   CK_ULONG_32       num_priv_tok_obj;
   CK_ULONG_32       num_publ_tok_obj;
   CK_BBOOL       priv_loaded;
   CK_BBOOL       publ_loaded;
   TOK_OBJ_ENTRY  publ_tok_objs[ MAX_TOK_OBJS ];
   TOK_OBJ_ENTRY  priv_tok_objs[ MAX_TOK_OBJS ];
} LW_SHM_TYPE;

// These are the same for both AIX and Linux...
#define  MY_CreateMutex(x)    _CreateMutex((MUTEX *)(x))
#define  MY_DestroyMutex(x)    _DestroyMutex((MUTEX *)(x))
#define  MY_LockMutex(x)       _LockMutex((MUTEX *)(x))
#define  MY_UnlockMutex(x)     _UnlockMutex((MUTEX *)(x))

#endif
