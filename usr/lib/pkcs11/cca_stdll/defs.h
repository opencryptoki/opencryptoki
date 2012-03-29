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


// File:  defs.h
//
// Contains various definitions needed by both the host-side
// and coprocessor-side code.
//

#ifndef _DEFS_H
#define _DEFS_H

#define MASTER_KEY_SIZE			CCA_KEY_ID_SIZE

#if (LEEDS)
  #pragma pack(1)
  #pragma options align=packed
#endif

#if (LEEDS)
#include <linuxdef.h>
#else
#define PACK_DATA
#endif


#define MAX_SESSION_COUNT     64
#define MAX_PIN_LEN           128
#define MIN_PIN_LEN           4

#define MAX_SLOT_ID           10

#define LEEDS_MAX_REQ_LEN     4096

#ifndef MIN
  #define MIN(a, b)  ((a) < (b) ? (a) : (b))
#endif

// the following constants are used for sccSignOn
//
#define PKCS_11_PRG_ID         "pkcs11 2.01"
#define PKCS_11_DEVELOPER_ID   0xE
#define PKCS_11_VERSION        1
#define PKCS_11_INSTANCE       0
#define PKCS_11_QUEUE          0
#define LEEDS_PRG_ID_PKCS_11   "PKCS11"

// the following are "boolean" attributes
//
#define CKA_IBM_TWEAK_ALLOW_KEYMOD    0x80000001
#define CKA_IBM_TWEAK_ALLOW_WEAK_DES  0x80000002
#define CKA_IBM_TWEAK_DES_PARITY_CHK  0x80000003
#define CKA_IBM_TWEAK_NETSCAPE        0x80000004

#define MODE_COPY       (1 << 0)
#define MODE_CREATE     (1 << 1)
#define MODE_KEYGEN     (1 << 2)
#define MODE_MODIFY     (1 << 3)
#define MODE_DERIVE     (1 << 4)
#define MODE_UNWRAP     (1 << 5)

// RSA block formatting types
//
#define PKCS_BT_1       1
#define PKCS_BT_2       2

#define OP_ENCRYPT_INIT 1
#define OP_DECRYPT_INIT 2
#define OP_WRAP         3
#define OP_UNWRAP       4
#define OP_SIGN_INIT    5
#define OP_VERIFY_INIT  6


// saved-state identifiers
//
enum {
   STATE_INVALID = 0,
   STATE_ENCR,
   STATE_DECR,
   STATE_DIGEST,
   STATE_SIGN,
   STATE_VERIFY
};


#define AES_KEY_SIZE_256	32
#define AES_KEY_SIZE_192	24
#define AES_KEY_SIZE_128	16
#define AES_BLOCK_SIZE		16
#define AES_INIT_VECTOR_SIZE	AES_BLOCK_SIZE

#define DES_KEY_SIZE    8
#define DES_BLOCK_SIZE  8

#define SHA1_HASH_SIZE		20
#define SHA1_BLOCK_SIZE		64
#define SHA224_HASH_SIZE	28
#define SHA256_HASH_SIZE	32
#define SHA384_HASH_SIZE	48
#define SHA512_HASH_SIZE	64

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef struct _sha1_ctx {
   unsigned char hash[SHA1_HASH_SIZE+1];
   unsigned int hash_len, tail_len;
   int message_part;	/* needs to be seen across calls to update and final */
   char tail[64];	/* save the last (up to) 64 bytes which may need to be shaved */
   void *dev_ctx;
} oc_sha1_ctx;

#define SHA2_HASH_SIZE  32
#define SHA2_BLOCK_SIZE 64

typedef struct _sha2_ctx {
   unsigned char hash[SHA2_HASH_SIZE+1];
   unsigned int hash_len, tail_len;
   int message_part; /* needs to be seen across calls to update and
		      * final */
   char tail[64]; /* save the last (up to) 64 bytes which may need to
		   * be shaved */
   void *dev_ctx;
} oc_sha2_ctx;

#define MD2_HASH_SIZE   16
#define MD2_BLOCK_SIZE  48

#define MD5_HASH_SIZE   16
#define MD5_BLOCK_SIZE  64

#define DSA_SIGNATURE_SIZE  40

#define DEFAULT_SO_PIN  "87654321"

#define CCA_MAX_SHA256_DATA_LEN        (32 * 1024 * 1024 - 64) /* 32MB - 64 */
#define CCA_CHAIN_VECTOR_LEN   128
#define CCA_MAX_TAIL_LEN       64
#define CCA_HASH_PART_FIRST    0
#define CCA_HASH_PART_MIDDLE   1
#define CCA_HASH_PART_LAST     2
#define CCA_HASH_PART_ONLY     3

struct cca_sha256_ctx {
	unsigned char chain_vector[CCA_CHAIN_VECTOR_LEN];
	long chain_vector_len;
	unsigned char *tail;
	unsigned long tail_len;
	unsigned char scratch[SHA2_HASH_SIZE];
	unsigned long scratch_len;
	int part;
};

typedef enum {
   ALL = 1,
   PRIVATE,
   PUBLIC
} SESS_OBJ_TYPE;

#if (LEEDS_BUILD)

enum cmdconst {
   FIRST_ENTRY = 0,
   DUMMYFUNCTION = 1,
   FCVFUNCTION,
   UPDATETWEAKVALUES,
   QUERYTWEAKVALUES,

   PK_DES_KEYGEN,
   PK_CDMF_KEYGEN,
   PK_CDMF_TRANSFORM_KEY,
   PK_RSA_KEYPAIR_GEN,
   PK_DSA_KEYPAIR_GEN,

   PK_GENERATE_RND,

   PK_DES_ECB_ENCRYPT,
   PK_DES_ECB_DECRYPT,
   PK_DES_CBC_ENCRYPT,
   PK_DES_CBC_DECRYPT,

   PK_DES3_ECB_ENCRYPT,
   PK_DES3_ECB_DECRYPT,
   PK_DES3_CBC_ENCRYPT,
   PK_DES3_CBC_DECRYPT,

   PK_RSA_ENCRYPT,
   PK_RSA_DECRYPT,

   PK_DSA_SIGN,
   PK_DSA_VERIFY,

   PK_SHA1_DIGEST,
   PK_SHA1_UPDATE,
   PK_SHA1_FINAL,

   LAST_ENTRY
};


typedef struct _LEEDS_REQUEST
{
   CK_ULONG    pid;
   CK_ULONG    req_len;      // size of request data
   CK_ULONG    repl_max[4];
   // any command-specific request data gets appended here
   //
} PACK_DATA LEEDS_REQUEST;

typedef struct _LEEDS_REPLY
{
   CK_RV     rc;
   CK_ULONG  repl_len[4];   // size of data
   // any command-specific reply data gets appended here
   //
} PACK_DATA LEEDS_REPLY;

#endif

// this is a flattened version of the CK_SSL3_RANDOM_DATA
//
typedef struct _SSL3_RANDOM_DATA
{
   CK_ULONG    client_data_len;
   CK_ULONG    server_data_len;
   // client data is appended here
   // server data is appended here
   //
} PACK_DATA SSL3_RANDOM_DATA;


//
//
typedef struct _SSL3_MASTER_KEY_DERIVE_PARAMS
{
   CK_VERSION  version;
   CK_ULONG    client_data_len;
   CK_ULONG    server_data_len;
   // client data is appended here
   // server data is appended here
   //
} PACK_DATA SSL3_MASTER_KEY_DERIVE_PARAMS;


//
//
typedef struct _SSL3_KEY_MAT_OUT
{
   CK_OBJECT_HANDLE  client_mac_secret;
   CK_OBJECT_HANDLE  server_mac_secret;
   CK_OBJECT_HANDLE  client_key;
   CK_OBJECT_HANDLE  server_key;
   CK_ULONG          iv_len; // in bytes
   // client IV is appended here
   // server IV is appended here
   //
} PACK_DATA SSL3_KEY_MAT_OUT;


//
//
typedef struct _SSL3_KEY_MAT_PARAMS
{
   CK_ULONG mac_size_bits;
   CK_ULONG key_size_bits;
   CK_ULONG iv_size_bits;
   CK_BBOOL export;
   CK_ULONG client_data_len;
   CK_ULONG server_data_len;
   // client data is appended here
   // server data is appended here
   //
} PACK_DATA SSL3_KEY_MAT_PARAMS;


typedef struct _DL_NODE
{
   struct _DL_NODE   *next;
   struct _DL_NODE   *prev;
   void              *data;
} DL_NODE;



// Abstract this out and include a token specific headerfile
#include <tokenlocal.h>

#define PK_LITE_NV   "NVTOK.DAT"
#define PK_LITE_OBJ_DIR "TOK_OBJ"
#define PK_LITE_OBJ_IDX "OBJ.IDX"

#define DEL_CMD "/bin/rm -f"

#if  (LEEDS)
  #pragma options align=full
  #pragma pack() 
#endif

#endif
