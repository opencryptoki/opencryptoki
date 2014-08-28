/*
 * Licensed materials - Property of IBM
 *
 * pkcscca - A tool for PKCS#11 CCA token.
 * Currently, only migrates CCA private token objects from using a 
 * CCA cipher to using a software cipher.
 *
 * Copyright (C) International Business Machines Corp. 2014
 *
 */


#ifndef __PKCSCCA_H_
#define __PKCSCCA_H_

#define CCA_LIBRARY "libcsulcca.so"
#define TOK_DATASTORE   "/var/lib/opencryptoki/ccatok"
#define MASTER_KEY_SIZE 64
#define SHA1_HASH_SIZE 20
#define MD5_HASH_SIZE 16
#define DES_BLOCK_SIZE 8
#define DES_KEY_SIZE 8
#define compute_sha1(a,b,c)     compute_hash(HASH_SHA1,b,a,c)
#define compute_md5(a,b,c)      compute_hash(HASH_MD5,b,a,c)
#define HASH_SHA1   1
#define HASH_MD5    2

/* from host_defs.h */
#include "pkcs32.h"
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


#endif
