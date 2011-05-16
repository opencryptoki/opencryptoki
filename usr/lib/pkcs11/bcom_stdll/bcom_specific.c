#include <pthread.h>
#include <string.h>            // for memcmp() et al
#include <stdlib.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "args.h"
#include "errno.h"
#include "tok_specific.h"
#include "tok_struct.h"

#if 0
#include <openssl/des.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#endif
#ifndef NOAES
#include <openssl/aes.h>
#endif
#ifndef NODH
#include <openssl/dh.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>



// SAB Bcom Add
#include "ubsio.h"
//#include "unix_wrap.h"
#include "ubsec.h"
#include "ubsec_lib.h"
// SAB end Bcom Add

typedef unsigned int U32_t;

pthread_mutex_t  rngmtx = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t  nextmutex = PTHREAD_MUTEX_INITIALIZER;
unsigned int  rnginitialized=0;

CK_CHAR manuf[] = "IBM Corp.";
CK_CHAR model[] = "IBM BComHack";
CK_CHAR descr[] = "IBM PKCS#11 Bcom token";
CK_CHAR label[] = "IBM OS PKCS#11   ";

/* Broadcom needs a non null pointer even for keys it doesn't use */
unsigned char ZERO_KEY[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
/* Broadcom only implements CBC mode, to do ECB we need a zero IV */
unsigned char ZERO_IV[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

#include <stdio.h>


int bcomfd; // SAB FIXME Broadcom adapter file descriptor

void bignum_swapper(char *s, char *d, int size);
void swapper(char *s, char *d, int size);


CK_RV
token_specific_session(CK_SLOT_ID  slotid)
{
       return CKR_OK;

}

CK_RV
token_rng(CK_BYTE *output, CK_ULONG bytes)
{

#if 1
int bits = 0;
int rc = 1;

     bits = bytes*8;

     rc = rng_ioctl(bcomfd, UBSEC_RNG_SHA1, output, &bits);
     if ( rc != 0) {
	  return CKR_FUNCTION_FAILED;
     }

     return CKR_OK;

#else
  /* XXX change this to call Broadcom randomness */

  int  ranfd;
  int  r_len,total_len=0;

  ranfd = open("/dev/urandom",O_RDONLY);
  if (ranfd >= 0 ){
    
    do {
      r_len = read(ranfd,output+total_len,bytes-total_len);
      total_len += r_len;
    } while( total_len < bytes);
    return CKR_OK;
  } else {
    return CKR_FUNCTION_FAILED;
  }
#endif
  
}

// convert pkcs slot number to local representation
int
tok_slot2local(CK_SLOT_ID snum)
{
   return 1;  
}


CK_RV
token_specific_init(char * Correlator,CK_SLOT_ID SlotNumber)
{
   bcomfd = ubsec_open(UBSEC_KEY_DEVICE);
   return CKR_OK;
}

CK_RV
token_specific_final()
{
  
  ubsec_close(bcomfd);
  return CKR_OK;
}



CK_RV
token_specific_des_key_gen(CK_BYTE  *des_key,CK_ULONG _len)
{
  
  // Nothing different to do for DES or TDES here as this is just
  // random data...  Validation handles the rest
  rng_generate(des_key,_len);
  
  // we really need to validate the key for parity etc...
  // we should do that here... The caller validates the single des keys
  // against the known and suspected poor keys..
  return CKR_OK;
}

CK_RV
token_specific_des_ecb(CK_BYTE * in_data,
                       CK_ULONG in_data__len,
                       CK_BYTE *out_data,
                       CK_ULONG *out_data__len,
                       CK_BYTE  *key_value,
                       CK_BYTE  encrypt)
{
  CK_ULONG       rc;
  unsigned char in_block_data[8];
  unsigned char out_block_data[8];
  int i,j;
  int ret;
  ubsec_crypto_context_t ctx;
  
  // Initialize the crypto contexte	
  ubsec_crypto_init(key_value, ZERO_KEY, ZERO_KEY, 
		    ZERO_KEY, UBSEC_DES, 0, &ctx);
  
  // the des decrypt will only fail if the data _length is not evenly divisible
  // by 8
  if (in_data__len % 8 ){
    OCK_LOG_ERR(ERR_DATA_LEN_RANGE);
    rc = CKR_DATA_LEN_RANGE;
    goto done;
  }
  
  // Do the encryption or decryption
  // Broadcom only does CBC DES, so to do ECB we need to go DES block 
  // by DES block, with IV = 0
  if (encrypt) {
    for (i=0; i<in_data__len; i=i+8) {
      memcpy(in_block_data, in_data+i, 8);
      if ( 0 != ubsec_crypto_data_ioctl(bcomfd, UBSEC_ENCODE, &ctx, 
					in_block_data, ZERO_IV, 8, 0, 
					out_block_data, 8, NULL) ) {
	rc = CKR_FUNCTION_FAILED;
	goto done;
      }
      memcpy(out_data+i, out_block_data, 8);
    }
  } 
  else {
    for(j=0; j < in_data__len; j=j+8) {
      memcpy(in_block_data, in_data+j, 8);
      if ( 0 != ubsec_crypto_data_ioctl(bcomfd, UBSEC_DECODE, &ctx, 
					in_block_data, ZERO_IV, 8, 0, 
					out_block_data, 8, NULL) ) {
	rc = CKR_FUNCTION_FAILED;
	goto done;
      }
      memcpy(out_data+j, out_block_data, 8);
    }
  }
  
  *out_data__len = in_data__len;
  rc = CKR_OK;
 done:
  ubsec_crypto_done(&ctx);
  
  return rc;
}

CK_RV
token_specific_des_cbc(CK_BYTE * in_data,
                       CK_ULONG in_data__len,
                       CK_BYTE *out_data,
                       CK_ULONG *out_data__len,
                       CK_BYTE  *key_value, 
                       CK_BYTE *init_v,
                       CK_BYTE  encrypt)
{
  CK_ULONG       rc;
  int ret;
  ubsec_crypto_context_t ctx;
  
  // Initialize the crypto contexte	
  ubsec_crypto_init(key_value, ZERO_KEY, ZERO_KEY, 
		    ZERO_KEY, UBSEC_DES, 0, &ctx);
  
  // the des decrypt will only fail if the data _length is not evenly divisible
  // by 8
  if (in_data__len % 8 ){
    OCK_LOG_ERR(ERR_DATA_LEN_RANGE);
    rc = CKR_DATA_LEN_RANGE;
    goto done;
  }
  
  // Do the encryption or decryption
  *out_data__len = in_data__len;
  if ( 0 != ubsec_crypto_data_ioctl(bcomfd, encrypt?UBSEC_ENCODE:UBSEC_DECODE, 
				    &ctx, in_data, init_v, in_data__len, 0, 
				    out_data, *out_data__len, NULL) ) {
    rc = CKR_FUNCTION_FAILED;
    goto done;
  }
  
  rc = CKR_OK;
  
 done:
  ubsec_crypto_done(&ctx);
  
  return rc;
}

CK_RV
token_specific_tdes_ecb(CK_BYTE * in_data,
                       CK_ULONG in_data__len,
                       CK_BYTE *out_data,
                       CK_ULONG *out_data__len,
                       CK_BYTE  *key_value,
                       CK_BYTE  encrypt)
{
  CK_ULONG       rc;
  unsigned char in_block_data[8];
  unsigned char out_block_data[8];
  int i,j;
  int ret;
  ubsec_crypto_context_t ctx;
  
  // Initialize the crypto contexte	
  // the triple DES key is in the 24-byte array key_value
  ubsec_crypto_init(key_value, key_value+8, key_value+16, 
		    ZERO_KEY, UBSEC_3DES, 0, &ctx);
  
  // the des decrypt will only fail if the data _length is not evenly divisible
  // by 8
  if (in_data__len % 8 ){
    OCK_LOG_ERR(ERR_DATA_LEN_RANGE);
    rc = CKR_DATA_LEN_RANGE;
    goto done;
  }
  
  // Do the encryption or decryption
  // Broadcom only does CBC DES, so to do ECB we need to go DES block by DES 
  // block, with IV = 0
  if (encrypt) {
    for (i=0; i<in_data__len; i=i+8) {
      memcpy(in_block_data, in_data+i, 8);
      if ( 0 != ubsec_crypto_data_ioctl(bcomfd, UBSEC_ENCODE, &ctx, 
					in_block_data, ZERO_IV, 8, 0, 
					out_block_data, 8, NULL) ) {
	rc = CKR_FUNCTION_FAILED;
	goto done;
      }
      memcpy(out_data+i, out_block_data, 8);
    }
  } 
  else {
    for(j=0; j < in_data__len; j=j+8) {
      memcpy(in_block_data, in_data+j, 8);
      if ( 0 != ubsec_crypto_data_ioctl(bcomfd, UBSEC_DECODE, &ctx, in_block_data, 
					ZERO_IV, 8, 0, out_block_data, 8, NULL) ) {
	rc = CKR_FUNCTION_FAILED;
	goto done;
      }
      memcpy(out_data+j, out_block_data, 8);
    }
  }
  
  *out_data__len = in_data__len;
  rc = CKR_OK;
 done:
  ubsec_crypto_done(&ctx);
  
  return rc;
}

CK_RV
token_specific_tdes_cbc(CK_BYTE * in_data,
                       CK_ULONG in_data__len,
                       CK_BYTE *out_data,
                       CK_ULONG *out_data__len,
                       CK_BYTE  *key_value, 
                       CK_BYTE *init_v,
                       CK_BYTE  encrypt)
{
 CK_ULONG       rc;
  int ret;
  ubsec_crypto_context_t ctx;
  
  // Initialize the crypto contexte	
  // Triple DES key is in the 24-byte array key_value
  ubsec_crypto_init(key_value, key_value+8, key_value+16, 
		    ZERO_KEY, UBSEC_3DES, 0, &ctx);
  
  // the des decrypt will only fail if the data _length is not evenly divisible
  // by 8
  if (in_data__len % 8 ){
    OCK_LOG_ERR(ERR_DATA_LEN_RANGE);
    rc = CKR_DATA_LEN_RANGE;
    goto done;
  }
  
  // Do the encryption or decryption
  *out_data__len = in_data__len;
  if ( 0 != ubsec_crypto_data_ioctl(bcomfd, encrypt?UBSEC_ENCODE:UBSEC_DECODE, 
				    &ctx, in_data, init_v, in_data__len, 0, 
				    out_data, *out_data__len, NULL) ) {
    rc = CKR_FUNCTION_FAILED;
    goto done;
  }
  
  rc = CKR_OK;
  
 done:
  ubsec_crypto_done(&ctx);
  
  return rc;
}



#define RNG_BUF_SIZE 100


// This function is only required if public key cryptography
// has been selected in your variant set up.
// Set a mutex in this function and get a cache;
// using the ICA device to get random numbers a byte at a
//  time is VERY slow..  Keygen is gated by this function.

unsigned char
nextRandom (void) {

  static unsigned char  buffer[RNG_BUF_SIZE];
  unsigned char  byte;
  static int used = (RNG_BUF_SIZE); // protected access by the mutex

  pthread_mutex_lock(&nextmutex);
  if (used >= RNG_BUF_SIZE){
    rng_generate(buffer,sizeof(buffer));
    used = 0;
  }

  byte = buffer[used++];
  pthread_mutex_unlock(&nextmutex);
    return((unsigned char)byte);

}

void swapper(char *s, char *d, int size)
{
	int i=0;
	int j=size;

	for(i=0;i<size;i++)
		d[i]=s[--j];

}
/*
 *  if we swapp a number that looks like  XYZ0..0,
 *  we don't want to get 0..0ZYX, we want ZYX0..0
 */
void bignum_swapper(char *s, char *d, int size)
{
  int i;
  
  i = size -1;
  while (s[i] == 0x00) {
    d[i] = 0x00;
    i--;
  }
  swapper(s, d, i + 1);
}
    



CK_RV build_swapped_attribute(CK_ATTRIBUTE_TYPE type,
			      CK_BYTE          *data,
			      CK_ULONG          data_len, 
			      CK_ATTRIBUTE    **attrib)
{
  CK_BYTE *swapped_data;
  CK_RV rv;
  CK_ULONG pos;
  CK_ULONG real_data_len;

  swapped_data = (unsigned char *)malloc(data_len);
  if (! swapped_data) {
    return CKR_DEVICE_ERROR;
  }
  memset(swapped_data, 0, data_len);
  real_data_len = data_len;

  pos = data_len -1;
  while (data[pos--] == 0x00) {
    real_data_len--;
  }


  swapper(data, swapped_data, real_data_len);
  
  rv = build_attribute(type, swapped_data, data_len, attrib);
  
  if (swapped_data) {
    free(swapped_data);
  }

  return rv;
}

typedef struct  BCOM_RSA_PUB_KEY_s {
        U32_t *n;
        unsigned int n_len;
        U32_t *e;
        unsigned int e_len;
} BCOM_RSA_PUB_KEY_t;

typedef struct  BCOM_RSA_CRT_KEY_s {
  U32_t        *n;     /* modulo  */
  unsigned int n_len;
  U32_t        *p;     /* prime p */
  unsigned int p_len;
  U32_t        *q;     /* prime q */
  unsigned int q_len;
  U32_t         *d;    /* private decryption exponent */
  unsigned int d_len;
  U32_t        *dp;    /* CRT exp1 */
  unsigned int dp_len;
  U32_t        *dq;    /* CRT exp2 */
  unsigned int dq_len;
  U32_t        *pinv;  /* CRT Coeff */
  unsigned int pinv_len;
} BCOM_RSA_CRT_KEY_t;

int bcom_rsa_pub_new(BCOM_RSA_PUB_KEY_t **out_rsa_pub)
{
  int rc = -1;
  BCOM_RSA_PUB_KEY_t *rsa_pub;

  rsa_pub = (BCOM_RSA_PUB_KEY_t *)malloc(sizeof(BCOM_RSA_PUB_KEY_t));
  if (! rsa_pub) {
    goto error;
  }

  rsa_pub->n = (U32_t *)malloc(MAX_PUBLIC_KEY_BYTES*sizeof(unsigned char));
  memset(rsa_pub->n, 0, MAX_PUBLIC_KEY_BYTES);
  rsa_pub->n_len = 0;
  rsa_pub->e = (U32_t *)malloc(MAX_PUBLIC_KEY_BYTES*sizeof(unsigned char));
  memset(rsa_pub->e, 0, MAX_PUBLIC_KEY_BYTES);
  rsa_pub->e_len = 0;

  if (! (rsa_pub->n && rsa_pub->e)) {
    goto error;
  }

  *out_rsa_pub = rsa_pub;
  return 0;

 error:
  if (rsa_pub) {
    if (rsa_pub->n) {
      free(rsa_pub->n);
    }
    if (rsa_pub->e) {
      free(rsa_pub->e);
    }
    free (rsa_pub);
  }
  return -1;
}

/* 
 * Convert from the local PKCS11 template representation to
 * the BCOM representation.
 * This function allocates memory for a BCOM_RSA_PUB_KEY_t
 * object, which must be freed by a call to bcom_rsa__pub_free
 */
int bcom_rsa_pub_from_object(OBJECT *key_obj, BCOM_RSA_PUB_KEY_t **pubKey)
{
   CK_BBOOL            rc;
   CK_ATTRIBUTE        *obj_modulus = NULL;
   CK_ATTRIBUTE        *obj_pub_exp = NULL;
   BCOM_RSA_PUB_KEY_t  *mexp;
   BCOM_RSA_PUB_KEY_t  *tPubKey;
   
   /* retreive the RSA modulus and public exponent from the PKCS11 template */
   rc  = template_attribute_find( key_obj->template, CKA_MODULUS,         &obj_modulus );
   rc &= template_attribute_find( key_obj->template, CKA_PUBLIC_EXPONENT, &obj_pub_exp );
   if (rc == FALSE) {
      return -1;
   }
   
   /* allocate memory for a Broadom representation */
   rc = bcom_rsa_pub_new(&tPubKey);
   if (rc != 0) {
     pubKey = 0;
     return -1;
   }
   
   tPubKey->n_len = obj_modulus->ulValueLen; 
   tPubKey->e_len = obj_pub_exp->ulValueLen;
   bignum_swapper(obj_modulus->pValue, (unsigned char *)tPubKey->n, tPubKey->n_len);
   bignum_swapper(obj_pub_exp->pValue, (unsigned char *)tPubKey->e, tPubKey->e_len);
   
   *pubKey = tPubKey;

   return 0;
}

/* XXX revisite this to make sure I got if right */
void bcom_rsa_pub_free(BCOM_RSA_PUB_KEY_t **pubKey)
{
  BCOM_RSA_PUB_KEY_t  *tPubKey;
  
  if (pubKey) {
    tPubKey = *pubKey;
    if (tPubKey) {
      if (tPubKey->e) {
	free(tPubKey->e);
      }
      if (tPubKey->n) {
	free(tPubKey->n);
      }
      free(tPubKey);
    }
    *pubKey = 0;
  }
}
    
int bcom_rsa_crt_new(BCOM_RSA_CRT_KEY_t **out_rsa_priv)
{
  int rc = -1;
  BCOM_RSA_CRT_KEY_t *rsa_priv;
  
  rsa_priv = (BCOM_RSA_CRT_KEY_t *)malloc(sizeof(BCOM_RSA_CRT_KEY_t));
  if (! rsa_priv) {
    goto error;
  }
  
  rsa_priv->n = (U32_t *)malloc(MAX_PUBLIC_KEY_BYTES);
  memset(rsa_priv->n, 0, MAX_PUBLIC_KEY_BYTES);
  rsa_priv->d = (U32_t *)malloc(MAX_PUBLIC_KEY_BYTES);
  memset(rsa_priv->d, 0, MAX_PUBLIC_KEY_BYTES);
  rsa_priv->d_len = 0;
  rsa_priv->p = (U32_t *)malloc(MAX_PUBLIC_KEY_BYTES);
  memset(rsa_priv->p, 0, MAX_PUBLIC_KEY_BYTES);
  rsa_priv->p_len = 0;
  rsa_priv->q = (U32_t *)malloc(MAX_PUBLIC_KEY_BYTES);
  memset(rsa_priv->q, 0, MAX_PUBLIC_KEY_BYTES);
  rsa_priv->q_len = 0;
  rsa_priv->dp = (U32_t *)malloc(MAX_PUBLIC_KEY_BYTES);
  memset(rsa_priv->dp, 0, MAX_PUBLIC_KEY_BYTES);
  rsa_priv->dp_len = 0;
  rsa_priv->dq = (U32_t *)malloc(MAX_PUBLIC_KEY_BYTES);
  memset(rsa_priv->dq, 0, MAX_PUBLIC_KEY_BYTES);
  rsa_priv->dq_len = 0;
  rsa_priv->pinv = (U32_t *)malloc(MAX_PUBLIC_KEY_BYTES);
  memset(rsa_priv->pinv, 0, MAX_PUBLIC_KEY_BYTES);
  rsa_priv->pinv_len = 0;

  if (! (rsa_priv->p && rsa_priv->q && rsa_priv->dp && rsa_priv->dq && rsa_priv->pinv)) {
    goto error;
  }
  
  *out_rsa_priv = rsa_priv;
  return 0;
  
 error:
  if (rsa_priv) {
    if (rsa_priv->p) {
      free(rsa_priv->p);
    }
    if (rsa_priv->q) {
      free(rsa_priv->q);
    }
    if (rsa_priv->dp) {
      free(rsa_priv->dp);
    }
    if (rsa_priv->dq) {
      free(rsa_priv->dq);
    }
    if (rsa_priv->pinv) {
      free(rsa_priv->pinv);
    }
    free (rsa_priv);
  }
  return -1;
}

int bcom_rsa_crt_key_from_object(OBJECT *key_obj, BCOM_RSA_CRT_KEY_t **privKey)
{
  CK_ATTRIBUTE       *obj_modulus   = NULL;
  CK_ATTRIBUTE       *obj_priv_exp  = NULL;
  CK_ATTRIBUTE       *obj_prime1    = NULL;
  CK_ATTRIBUTE       *obj_prime2    = NULL;
  CK_ATTRIBUTE       *obj_priv_exp1 = NULL;
  CK_ATTRIBUTE       *obj_priv_exp2 = NULL;
  CK_ATTRIBUTE       *obj_coeff     = NULL;
  CK_BBOOL           rc;
  BCOM_RSA_CRT_KEY_t *tPrivKey;
  
  rc  = template_attribute_find( key_obj->template, CKA_MODULUS,          &obj_modulus );
  rc &= template_attribute_find( key_obj->template, CKA_PRIVATE_EXPONENT, &obj_priv_exp );
  rc &= template_attribute_find( key_obj->template, CKA_PRIME_1,          &obj_prime1 );
  rc &= template_attribute_find( key_obj->template, CKA_PRIME_2,          &obj_prime2 );
  rc &= template_attribute_find( key_obj->template, CKA_EXPONENT_1,       &obj_priv_exp1 );
  rc &= template_attribute_find( key_obj->template, CKA_EXPONENT_2,       &obj_priv_exp2 );
  rc &= template_attribute_find( key_obj->template, CKA_COEFFICIENT,      &obj_coeff );
  
  if (!obj_prime1 || !obj_prime2 || !obj_priv_exp1 || !obj_priv_exp2 || !obj_coeff || !obj_modulus) {
    return -1;
  }
  
  rc = bcom_rsa_crt_new(&tPrivKey);
  if (rc != 0) {
    return -1;
  }
  
  tPrivKey->n_len = obj_modulus->ulValueLen;
  bignum_swapper(obj_modulus->pValue, (unsigned char *)tPrivKey->n, tPrivKey->n_len);
  
  tPrivKey->d_len = obj_priv_exp->ulValueLen;
  bignum_swapper(obj_priv_exp->pValue, (unsigned char *)tPrivKey->d, tPrivKey->d_len);

  tPrivKey->p_len = obj_prime1->ulValueLen;
  bignum_swapper(obj_prime1->pValue,(unsigned char *) tPrivKey->p, tPrivKey->p_len);
  
  tPrivKey->q_len = obj_prime2->ulValueLen;
  bignum_swapper(obj_prime2->pValue, (unsigned char *)tPrivKey->q, tPrivKey->q_len);
  
  tPrivKey->dp_len = obj_priv_exp1->ulValueLen;
  bignum_swapper(obj_priv_exp1->pValue, (unsigned char *)tPrivKey->dp, tPrivKey->dp_len);
  
  tPrivKey->dq_len = obj_priv_exp2->ulValueLen;
  bignum_swapper(obj_priv_exp2->pValue, (unsigned char *)tPrivKey->dq, tPrivKey->dq_len);
  
  tPrivKey->pinv_len = obj_coeff->ulValueLen;
  bignum_swapper(obj_coeff->pValue, (unsigned char *)tPrivKey->pinv, tPrivKey->pinv_len);
  
  *privKey = tPrivKey;
  
  return 0;
}

/* XXX revisite this to make sure I got it right */
void bcom_rsa_crt_free(BCOM_RSA_CRT_KEY_t **crtKey)
{
  BCOM_RSA_CRT_KEY_t  *tCrtKey;
  
  if (crtKey) {
    tCrtKey = *crtKey;
    if (tCrtKey) {
      if (tCrtKey->d) {
	free(tCrtKey->d);
      }
      if (tCrtKey->p) {
	free(tCrtKey->p);
      }
      if (tCrtKey->q) {
	free(tCrtKey->q);
      }
      if (tCrtKey->dp) {
	free(tCrtKey->dp);
      }
      if (tCrtKey->dq) {
	free(tCrtKey->dq);
      }
      if (tCrtKey->pinv) {
	free(tCrtKey->pinv);
      }
      free(tCrtKey);
    }
    *crtKey = 0;
  }
}


CK_RV
os_specific_rsa_keygen(TEMPLATE *publ_tmpl,  TEMPLATE *priv_tmpl)
{
	CK_ATTRIBUTE       * publ_exp = NULL;
	CK_ATTRIBUTE       * attr     = NULL;
	CK_ULONG             mod_bits;
	CK_BBOOL             flag;
	CK_RV                rc;
	CK_ULONG             BN_Length;
	BCOM_RSA_CRT_KEY_t     * rsa_priv;
	BCOM_RSA_PUB_KEY_t        * rsa_pub;
	BCOM_RSA_CRT_KEY_t     * swapped_rsa_priv;
	BCOM_RSA_PUB_KEY_t        * swapper_rsa_pub;
	int ret;
	CK_ATTRIBUTE      * my_pub_exp = NULL;

	flag = template_attribute_find( publ_tmpl, CKA_MODULUS_BITS, &attr );
	if (!flag){
		OCK_LOG_ERR(ERR_TEMPLATE_INCOMPLETE);
		return CKR_TEMPLATE_INCOMPLETE;  // should never happen
        }

	mod_bits = *(CK_ULONG *)attr->pValue;

	// we don't support less than 512 bit keys or more than 2048 bit keys
	if (mod_bits < 512 || mod_bits > 2048) {
		OCK_LOG_ERR(ERR_KEY_SIZE_RANGE);
		return CKR_KEY_SIZE_RANGE;
	}

	ret = bcom_rsa_pub_new(&rsa_pub);
	if (ret != 0) {
	  OCK_LOG_ERR(ERR_GENERAL_ERROR);
	  rc = CKR_GENERAL_ERROR;
	  goto done;
	}

	/* get the value of the public exponent e from the template.
	   if I don't err, Cryptoki states that e should always be given.
	   XXX if not check flag returned to see if attribute exists ?
	*/
	flag = template_attribute_find( publ_tmpl, CKA_PUBLIC_EXPONENT, &publ_exp );
	if (!flag){
		OCK_LOG_ERR(ERR_TEMPLATE_INCOMPLETE);
		return CKR_TEMPLATE_INCOMPLETE;
	}

	/* PKCS11 defines big integers in big-endianess, Broadcom uses little-endianess */
	swapper(publ_exp->pValue, (unsigned char*)rsa_pub->e, publ_exp->ulValueLen);
	rsa_pub->e_len = ubsec_bytes_to_bits((unsigned char *)rsa_pub->e, publ_exp->ulValueLen);

	ret = bcom_rsa_crt_new(&rsa_priv);
	if (ret != 0) {
	  OCK_LOG_ERR(ERR_GENERAL_ERROR);
	  rc = CKR_GENERAL_ERROR;
	  goto done;
	}

	//	rsa = foo_RSA_generate_key(mod_bits, three, NULL, NULL);
	ret = ubsec_rsakeygen(bcomfd, 
			     mod_bits,
			     (unsigned char*)rsa_pub->e, &(rsa_pub->e_len),
			     (unsigned char*)rsa_priv->p, &(rsa_priv->p_len),
			     (unsigned char*)rsa_priv->q, &(rsa_priv->q_len),
			     (unsigned char*)rsa_pub->n, &(rsa_pub->n_len),
			     (unsigned char*)rsa_priv->d, &(rsa_priv->d_len),
			     (unsigned char*)rsa_priv->dp, &(rsa_priv->dp_len),
			     (unsigned char*)rsa_priv->dq, &(rsa_priv->dq_len),
			     (unsigned char*)rsa_priv->pinv, &(rsa_priv->pinv_len));
	if (ret != 0) {
	  OCK_LOG_ERR(ERR_GENERAL_ERROR);
	  rc = CKR_GENERAL_ERROR;
	  goto done;
	}
	
#if PRINT_BIGNUM
	fprintf(stderr, " ========= generated parameters ===========\n");
	fprintf(stderr, "e:\n");
	PrintNumber(stderr, rsa_pub->e, rsa_pub->e_len, 1);
	fprintf(stderr, "n:\n");
	PrintNumber(stderr, rsa_pub->n, rsa_pub->n_len, 1);
	fprintf(stderr, "p:\n");
	PrintNumber(stderr, rsa_priv->p, rsa_priv->p_len, 1);
	fprintf(stderr, "q:\n");
	PrintNumber(stderr, rsa_priv->q, rsa_priv->q_len, 1);
	fprintf(stderr, "d:\n");
	PrintNumber(stderr, rsa_priv->d, rsa_priv->d_len, 1);
	fprintf(stderr, "dp:\n");
	PrintNumber(stderr, rsa_priv->dp, rsa_priv->dp_len, 1);
	fprintf(stderr, "dq:\n");
	PrintNumber(stderr, rsa_priv->dq, rsa_priv->dq_len, 1);
	fprintf(stderr, "pinv:\n");
	PrintNumber(stderr, rsa_priv->pinv, rsa_priv->pinv_len, 1);
	fprintf(stderr, " ==========================================\n");
#endif


	// Now fill in the key objects objects..
	// Swapp the big integers from Broadcom's little-endian to PKCS11 big-endian

	// public key object
	// modulus n
	rc = build_swapped_attribute( CKA_MODULUS, (unsigned char *)rsa_pub->n, 
				      ubsec_bits_to_bytes(rsa_pub->n_len), &attr); // length in bytes
	if (rc != CKR_OK){
		OCK_LOG_ERR(ERR_BLD_ATTR);
		goto done;
        }
	template_update_attribute( publ_tmpl, attr );

	// public exponent
        rc = build_swapped_attribute( CKA_PUBLIC_EXPONENT, (unsigned char*)rsa_pub->e, 
				      ubsec_bits_to_bytes(rsa_pub->e_len), &attr);
        if (rc != CKR_OK){
                OCK_LOG_ERR(ERR_BLD_ATTR);
                goto done;
        }
        template_update_attribute( publ_tmpl, attr );

	// local = TRUE
	flag = TRUE;
	rc = build_attribute( CKA_LOCAL, &flag, sizeof(CK_BBOOL), &attr );
	if (rc != CKR_OK){
	  OCK_LOG_ERR(ERR_BLD_ATTR);
	  goto done;
	}
	template_update_attribute( publ_tmpl, attr );

	/*
	 * now, do the private key
	 */

	// Add the modulus to the private key information
	rc = build_swapped_attribute( CKA_MODULUS, (unsigned char*)rsa_pub->n, ubsec_bits_to_bytes(rsa_pub->n_len) ,&attr ); 
	if (rc != CKR_OK){
		OCK_LOG_ERR(ERR_BLD_ATTR);
		goto done;
	}
	template_update_attribute( priv_tmpl, attr );

	// private exponent
        rc = build_swapped_attribute( CKA_PRIVATE_EXPONENT, (unsigned char*)rsa_priv->d, 
				      ubsec_bits_to_bytes(rsa_priv->d_len), &attr );
        if (rc != CKR_OK){
                OCK_LOG_ERR(ERR_BLD_ATTR);
                goto done;
        }
        template_update_attribute( priv_tmpl, attr );

	// prime #1: p
	rc = build_swapped_attribute( CKA_PRIME_1, (unsigned char*)rsa_priv->p, 
				      ubsec_bits_to_bytes(rsa_priv->p_len), &attr );
	if (rc != CKR_OK){
		OCK_LOG_ERR(ERR_BLD_ATTR);
		goto done;
	}
	template_update_attribute( priv_tmpl, attr );

	// prime #2: q
	rc = build_swapped_attribute( CKA_PRIME_2, (unsigned char*)rsa_priv->q, 
				      ubsec_bits_to_bytes(rsa_priv->q_len), &attr );
	if (rc != CKR_OK){
		OCK_LOG_ERR(ERR_BLD_ATTR);
		goto done;
	}
	template_update_attribute( priv_tmpl, attr );

	// exponent 1: d mod(p-1)
	rc = build_swapped_attribute( CKA_EXPONENT_1, (unsigned char*)rsa_priv->dp, 
				      ubsec_bits_to_bytes(rsa_priv->dp_len), &attr );
	if (rc != CKR_OK){
		OCK_LOG_ERR(ERR_BLD_ATTR);
		goto done;
	}
	template_update_attribute( priv_tmpl, attr );

	// exponent 2: d mod(q-1)
	rc = build_swapped_attribute( CKA_EXPONENT_2, (unsigned char*)rsa_priv->dq, 
				      ubsec_bits_to_bytes(rsa_priv->dq_len), &attr );
	if (rc != CKR_OK){
		OCK_LOG_ERR(ERR_BLD_ATTR);
		goto done;
	}
	template_update_attribute( priv_tmpl, attr );

	// CRT coefficient:  q_inverse mod(p)
	rc = build_swapped_attribute( CKA_COEFFICIENT, (unsigned char*)rsa_priv->pinv, 
				      ubsec_bits_to_bytes(rsa_priv->pinv_len), &attr );
	if (rc != CKR_OK){
		OCK_LOG_ERR(ERR_BLD_ATTR);
		goto done;
	}
	template_update_attribute( priv_tmpl, attr );

	// flag TRUE
	flag = TRUE;
	rc = build_attribute( CKA_LOCAL, &flag, sizeof(CK_BBOOL), &attr );
	if (rc != CKR_OK){
		OCK_LOG_ERR(ERR_BLD_ATTR);
		goto done;
	}
	template_update_attribute( priv_tmpl, attr );

done:
	if (rsa_pub) {
	  bcom_rsa_pub_free(&rsa_pub);
	}
	if (rsa_priv) {
	  bcom_rsa_crt_free(&rsa_priv);
	}

	return rc;
}

CK_RV
token_specific_rsa_generate_keypair( TEMPLATE  * publ_tmpl,
                      TEMPLATE  * priv_tmpl )
{
  CK_RV                rc;
  
  rc = os_specific_rsa_keygen(publ_tmpl,priv_tmpl);
  if (rc != CKR_OK)
    OCK_LOG_ERR(ERR_KEYGEN);
  return rc;
}



CK_RV
token_specific_rsa_encrypt( CK_BYTE   *in_data,
			    CK_ULONG   in_data_len,
			    CK_BYTE   *out_data,
			    OBJECT    *key_obj )
{
  CK_RV               rc;
  BCOM_RSA_PUB_KEY_t  *pubKey;
  int                 out_len_bits;
  CK_BYTE             *tcipher, *tclear;
  
  rc = bcom_rsa_pub_from_object(key_obj, &pubKey);
  if ( rc != 0) {
    rc = CKR_FUNCTION_FAILED;
    goto done;
  }
  
  /* 
   * do some verification on size of in_data_len (make sure < size of n)
   */
  if (in_data_len > pubKey->n_len) {
    rc = CKR_FUNCTION_FAILED;
  }
  
  /* allocate enough memory (size of modulus)  
     for swapped cleartext and for ciphertext */
  tcipher = (CK_BYTE *)malloc(pubKey->n_len);
  memset(tcipher, 0, pubKey->n_len);
  tclear = (CK_BYTE *)malloc(pubKey->n_len);
  memset(tcipher, 0, pubKey->n_len);

  /* swapp the plaintext to get Broadcom representation */
  bignum_swapper(in_data, tclear, pubKey->n_len);
  
  /* bytes to bits */
  out_len_bits = in_data_len*8;
  
#if PRINT_BIGNUM
  fprintf(stderr, " ===== parameters used for RSA encrypt  =====\n");
  fprintf(stderr, "e = ");
  PrintNumber(stderr, pubKey->e, 
	      ubsec_bytes_to_bits((unsigned char *)pubKey->e, pubKey->e_len), 1);
  fprintf(stderr, "n = ", pubKey->n_len);
  PrintNumber(stderr, pubKey->n, 
	      ubsec_bytes_to_bits((unsigned char *)pubKey->n, pubKey->n_len), 1);
  fprintf(stderr, "msg = ");
  PrintNumber(stderr, tclear, ubsec_bytes_to_bits(tclear, in_data_len), 1);
  fprintf(stderr, " ============================================\n");
#endif  

  rc = rsa_mod_exp_ioctl(bcomfd,
			 tclear,
			 ubsec_bytes_to_bits(tclear, in_data_len),
			 (unsigned char *)pubKey->n,
			 ubsec_bytes_to_bits((unsigned char *)pubKey->n, pubKey->n_len),
			 (unsigned char *)pubKey->e,
			 ubsec_bytes_to_bits((unsigned char *)pubKey->e, pubKey->e_len),
			 tcipher,
			 &out_len_bits);	
  if ( rc != 0 ){
    rc = CKR_FUNCTION_FAILED;
    goto done;
  }
    
#if PRINT_BIGNUM
  fprintf(stderr, " ===== parameters used for RSA encrypt  =====\n");
  fprintf(stderr, "cip = ");
  PrintNumber(stderr, tcipher, ubsec_bytes_to_bits(tcipher, in_data_len), 1);
  fprintf(stderr, " ============================================\n");
#endif  

  /* swapp to get back PKCS11 representation */
  swapper(tcipher, out_data, in_data_len);
  
  rc = CKR_OK;
 done:
  
  if (pubKey) {
    bcom_rsa_pub_free(&pubKey);
  }
  if (tcipher) {
    free(tcipher);
  }
  if (tclear) {
    free(tclear);
  }
  
  return rc;
}


CK_RV
token_specific_rsa_decrypt( CK_BYTE   * in_data,
                 CK_ULONG    in_data_len,
                 CK_BYTE   * out_data,
                 OBJECT    * key_obj )
{
   CK_RV               rc;
   CK_ATTRIBUTE        *pkey = NULL;
   CK_BYTE             *tcipher, *tclear;
   BCOM_RSA_CRT_KEY_t  *privKey;
   int                 out_len;

   rc = bcom_rsa_crt_key_from_object(key_obj, &privKey);
   if (rc != 0) {
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }
    
   /* we don't decrypt a message which is longer than the modulus */
   if (in_data_len > privKey->n_len) {
     rc = CKR_FUNCTION_FAILED;
     goto done;
   }

   tcipher = (CK_BYTE *)malloc(privKey->n_len);
   tclear = (CK_BYTE *)malloc(privKey->n_len);
   if ( ! tcipher || ! tclear) {
     rc = CKR_FUNCTION_FAILED;
     goto done;
   }
     
   /* swapp from PKCS11 endianess to Broadcom endianess */
   bignum_swapper(in_data, tcipher, privKey->n_len);
   
#if PRINT_BIGNUM
   fprintf(stderr, " ===== parameters used for RSA decrypt  =====\n");
   fprintf(stderr, "p  = ");
   PrintNumber(stderr, privKey->p, 
	       ubsec_bytes_to_bits((unsigned char *)privKey->p, privKey->p_len), 1);
   fprintf(stderr, "q = ");
   PrintNumber(stderr, privKey->q, 
	       ubsec_bytes_to_bits((unsigned char *)privKey->q, privKey->q_len), 1);
   fprintf(stderr, "cipher to decrypt: cip = ");
   PrintNumber(stderr, tcipher, ubsec_bytes_to_bits(tcipher, in_data_len), 1);
   fprintf(stderr, " ============================================\n");
#endif

   /* bytes to bits for output length */
   out_len = in_data_len * 8;
   
   rc = rsa_mod_exp_crt_ioctl(bcomfd,
			      tcipher,
			      ubsec_bytes_to_bits(tcipher, in_data_len),
			      (unsigned char *)privKey->pinv, 
			      ubsec_bytes_to_bits((unsigned char *)privKey->pinv, privKey->pinv_len),
			      (unsigned char *)privKey->dq, 
			      ubsec_bytes_to_bits((unsigned char *)privKey->dq, privKey->dq_len),
			      (unsigned char *)privKey->q, 
			      ubsec_bytes_to_bits((unsigned char *)privKey->q, privKey->q_len),
			      (unsigned char *)privKey->dp, 
			      ubsec_bytes_to_bits((unsigned char *)privKey->dp, privKey->dp_len),
			      (unsigned char *)privKey->p, 
			      ubsec_bytes_to_bits((unsigned char *)privKey->p, privKey->p_len),
			      tclear, &out_len);				
    
   if (rc != 0) {
     rc = CKR_FUNCTION_FAILED;
     goto done;
   }

#if PRINT_BIGNUM
	fprintf(stderr, " ===== parameters used for RSA decrypt  =====\n");
	fprintf(stderr, "decryption result: msg = ");
	PrintNumber(stderr, tclear, ubsec_bytes_to_bits(tclear, in_data_len), 1);
	fprintf(stderr, " ============================================\n");
#endif

   swapper(tclear, out_data,in_data_len);
   

   rc = CKR_OK;
   
 done:
   if (privKey) {
     //     bcom_rsa_crt_free(&privKey);
   }

   return rc;

}


#if PRINT_BIGNUM
int
PrintNumber(FILE *ofptr, void *num, unsigned int bits, int xct_mode)
{
  int element = ((ROUNDUP_TO_32_BIT(bits)) / 32) -1;
  int i = 0;

  if (element < 1) element = 0;
  
  for( ; element >= 0; element--, i++) {
    if (xct_mode) {
      fprintf(ofptr, "%08X", ((UBS_UINT32 *)num)[element]);
    }
    else {
      if (((i%8) == 7) && element)
	fprintf(ofptr, "%08X\n", ((UBS_UINT32 *)num)[element]);
      else
	fprintf(ofptr, "%08X ", ((UBS_UINT32 *)num)[element]);
    }
  }
  fprintf(ofptr, "\n");
  return 0;
}

#endif

#ifndef NOAES
CK_RV
token_specific_aes_key_gen( CK_BYTE *key, CK_ULONG len )
{
        return rng_generate(key, len);
}

CK_RV
token_specific_aes_ecb( CK_BYTE         *in_data,
                        CK_ULONG        in_data_len,
                        CK_BYTE         *out_data,
                        CK_ULONG        *out_data_len,
                        CK_BYTE         *key_value,
                        CK_ULONG        key_len,
                        CK_BYTE         encrypt)
{
        AES_KEY         ssl_aes_key;
        int             i;
        /* There's a previous check that in_data_len % AES_BLOCK_SIZE == 0,
         * so this is fine */
        CK_ULONG        loops = (CK_ULONG)(in_data_len/AES_BLOCK_SIZE);

        memset( &ssl_aes_key, 0, sizeof(AES_KEY));

        // AES_ecb_encrypt encrypts only a single block, so we have to break up the
        // input data here
        if (encrypt) {
                AES_set_encrypt_key((unsigned char *)key_value, (key_len*8), &ssl_aes_key);
                for( i=0; i<loops; i++ ) {
                        AES_ecb_encrypt((unsigned char *)in_data + (i*AES_BLOCK_SIZE),
                                        (unsigned char *)out_data + (i*AES_BLOCK_SIZE),
                                        &ssl_aes_key,
                                        AES_ENCRYPT);
                }
        } else {
                AES_set_decrypt_key((unsigned char *)key_value, (key_len*8), &ssl_aes_key);
                for( i=0; i<loops; i++ ) {
                        AES_ecb_encrypt((unsigned char *)in_data + (i*AES_BLOCK_SIZE),
                                        (unsigned char *)out_data + (i*AES_BLOCK_SIZE),
                                        &ssl_aes_key,
                                        AES_DECRYPT);
                }
        }
        *out_data_len = in_data_len;
        return CKR_OK;
}

CK_RV
token_specific_aes_cbc( CK_BYTE         *in_data,
                        CK_ULONG        in_data_len,
                        CK_BYTE         *out_data,
                        CK_ULONG        *out_data_len,
                        CK_BYTE         *key_value,
                        CK_ULONG        key_len,
                        CK_BYTE         *init_v,
                        CK_BYTE         encrypt)
{
        AES_KEY         ssl_aes_key;
        int             i;

        memset( &ssl_aes_key, 0, sizeof(AES_KEY));

        // AES_cbc_encrypt chunks the data into AES_BLOCK_SIZE blocks, unlike
        // AES_ecb_encrypt, so no looping required.
        if (encrypt) {
                AES_set_encrypt_key((unsigned char *)key_value, (key_len*8), &ssl_aes_key);
                AES_cbc_encrypt((unsigned char *)in_data, (unsigned char *)out_data,
                                in_data_len,              &ssl_aes_key,
                                init_v,                   AES_ENCRYPT);
        } else {
                AES_set_decrypt_key((unsigned char *)key_value, (key_len*8), &ssl_aes_key);
                AES_cbc_encrypt((unsigned char *)in_data, (unsigned char *)out_data,
                                in_data_len,              &ssl_aes_key,
                                init_v,                   AES_DECRYPT);
        }
        *out_data_len = in_data_len;
        return CKR_OK;
}
#endif

#ifndef NODH
// This computes DH shared secret, where:
//     Output: z is computed shared secret
//     Input:  y is other party's public key
//             x is private key
//             p is prime
// All length's are in number of bytes. All data comes in as Big Endian.
 
CK_RV
token_specific_dh_pkcs_derive( CK_BYTE   *z,
                               CK_ULONG  *z_len,
                               CK_BYTE   *y,
                               CK_ULONG  y_len,
                               CK_BYTE   *x,
                               CK_ULONG  x_len,
                               CK_BYTE   *p,
                               CK_ULONG  p_len)
{
     CK_RV  rc ;
     BIGNUM *bn_z, *bn_y, *bn_x, *bn_p ;
     BN_CTX *ctx;
 
     //  Create and Init the BIGNUM structures.
     bn_y = BN_new() ;
     bn_x = BN_new() ;
     bn_p = BN_new() ;
     bn_z = BN_new() ;

     if (bn_z == NULL || bn_p == NULL || bn_x == NULL || bn_y == NULL) {
	     if (bn_y) BN_free(bn_y);
	     if (bn_x) BN_free(bn_x);
	     if (bn_p) BN_free(bn_p);
	     if (bn_z) BN_free(bn_z);
	     OCK_LOG_ERR(ERR_HOST_MEMORY);
	     return CKR_HOST_MEMORY;
     }
     
     BN_init(bn_y) ;
     BN_init(bn_x) ;
     BN_init(bn_p) ;
 
     // Initialize context
     ctx=BN_CTX_new();
     if (ctx == NULL)
     {
        OCK_LOG_ERR(ERR_FUNCTION_FAILED);
        return CKR_FUNCTION_FAILED;
     }
 
     // Add data into these new BN structures
 
     BN_bin2bn((char *)y, y_len, bn_y);
     BN_bin2bn((char *)x, x_len, bn_x);
     BN_bin2bn((char *)p, p_len, bn_p);
 
     rc = BN_mod_exp(bn_z,bn_y,bn_x,bn_p,ctx);
     if (rc == 0)
     {
        BN_free(bn_z);
        BN_free(bn_y);
        BN_free(bn_x);
        BN_free(bn_p);
        BN_CTX_free(ctx);
 
        OCK_LOG_ERR(ERR_FUNCTION_FAILED);
        return CKR_FUNCTION_FAILED;
     }
 
     *z_len = BN_num_bytes(bn_z);
     BN_bn2bin(bn_z, z);
 
     BN_free(bn_z);
     BN_free(bn_y);
     BN_free(bn_x);
     BN_free(bn_p);
     BN_CTX_free(ctx);
 
     return CKR_OK;
 
} /* end token_specific_dh_pkcs_derive() */
 
// This computes DH key pair, where:
//     Output: priv_tmpl is generated private key
//             pub_tmpl is computed public key
//     Input:  pub_tmpl is public key (prime and generator)
// All length's are in number of bytes. All data comes in as Big Endian.

CK_RV
token_specific_dh_pkcs_key_pair_gen( TEMPLATE  * publ_tmpl,
                                     TEMPLATE  * priv_tmpl )
{
    CK_BBOOL           rc;
    CK_ATTRIBUTE       *prime_attr = NULL;
    CK_ATTRIBUTE       *base_attr = NULL;
    CK_ATTRIBUTE       *temp_attr = NULL ;
    CK_ATTRIBUTE       *value_bits_attr = NULL;
    CK_BYTE            *temp_byte;
    CK_ULONG           temp_bn_len ;
 
    DH                 *dh ;
    BIGNUM             *bn_p ;
    BIGNUM             *bn_g ;
    BIGNUM             *temp_bn ;
 
    rc  = template_attribute_find( publ_tmpl, CKA_PRIME, &prime_attr );
    rc &= template_attribute_find( publ_tmpl, CKA_BASE, &base_attr );
 
    if (rc == FALSE) {
        OCK_LOG_ERR(ERR_FUNCTION_FAILED);
        return CKR_FUNCTION_FAILED;
    }
 
    if ((prime_attr->ulValueLen > 256) || (prime_attr->ulValueLen < 64))
    {
        OCK_LOG_ERR(ERR_FUNCTION_FAILED);
        return CKR_FUNCTION_FAILED;
    }
 
    dh = DH_new() ;
    if (dh == NULL)
    {
        OCK_LOG_ERR(ERR_FUNCTION_FAILED);
        return CKR_FUNCTION_FAILED;
    }

    // Create and init BIGNUM structs to stick in the DH struct
    bn_p = BN_new();
    bn_g = BN_new();
    if (bn_g == NULL || bn_p == NULL) {
	if (bn_g) BN_free(bn_g);
	if (bn_p) BN_free(bn_p);
	OCK_LOG_ERR(ERR_HOST_MEMORY);
	return CKR_HOST_MEMORY;
    }
    BN_init(bn_p);
    BN_init(bn_g);
 
    // Convert from strings to BIGNUMs and stick them in the DH struct
    BN_bin2bn((char *)prime_attr->pValue, prime_attr->ulValueLen, bn_p);
    dh->p = bn_p;
    BN_bin2bn((char *)base_attr->pValue, base_attr->ulValueLen, bn_g);
    dh->g = bn_g;
 
    // Generate the DH Key
    if (!DH_generate_key(dh))
    {
        OCK_LOG_ERR(ERR_FUNCTION_FAILED);
        return CKR_FUNCTION_FAILED;
    }
 
    // Extract the public and private key components from the DH struct,
    // and insert them in the publ_tmpl and priv_tmpl
 
    //
    // pub_key
    //
    //temp_bn = BN_new();
    temp_bn = dh->pub_key;
    temp_bn_len = BN_num_bytes(temp_bn);
    temp_byte = malloc(temp_bn_len);
    temp_bn_len = BN_bn2bin(temp_bn, temp_byte);
    rc = build_attribute( CKA_VALUE, temp_byte, temp_bn_len, &temp_attr ); // in bytes
    if (rc != CKR_OK)
    {
        OCK_LOG_ERR(ERR_FUNCTION_FAILED);
        return CKR_FUNCTION_FAILED;
    }
    template_update_attribute( publ_tmpl, temp_attr );
    free(temp_byte);

    //
    // priv_key
    //
    //temp_bn = BN_new();
    temp_bn = dh->priv_key;
    temp_bn_len = BN_num_bytes(temp_bn);
    temp_byte = malloc(temp_bn_len);
    temp_bn_len = BN_bn2bin(temp_bn, temp_byte);
    rc = build_attribute( CKA_VALUE, temp_byte, temp_bn_len, &temp_attr ); // in bytes
    if (rc != CKR_OK)
    {
        OCK_LOG_ERR(ERR_FUNCTION_FAILED);
        return CKR_FUNCTION_FAILED;
    }
    template_update_attribute( priv_tmpl, temp_attr );
    free(temp_byte);
 
    // Update CKA_VALUE_BITS attribute in the private key
    value_bits_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_ULONG) );
    value_bits_attr->type       = CKA_VALUE_BITS;
    value_bits_attr->ulValueLen = sizeof(CK_ULONG);
    value_bits_attr->pValue     = (CK_BYTE *)value_bits_attr + sizeof(CK_ATTRIBUTE);
    *(CK_ULONG *)value_bits_attr->pValue = 8*temp_bn_len;
    template_update_attribute( priv_tmpl, value_bits_attr );
 
    // Add prime and base to the private key template
    rc = build_attribute( CKA_PRIME,(char *)prime_attr->pValue,
                          prime_attr->ulValueLen, &temp_attr ); // in bytes
    if (rc != CKR_OK)
    {
        OCK_LOG_ERR(ERR_FUNCTION_FAILED);
        return CKR_FUNCTION_FAILED;
    }
    template_update_attribute( priv_tmpl, temp_attr );
 
    rc = build_attribute( CKA_BASE,(char *)base_attr->pValue,
                          base_attr->ulValueLen, &temp_attr ); // in bytes
    if (rc != CKR_OK)
    {
        OCK_LOG_ERR(ERR_FUNCTION_FAILED);
        return CKR_FUNCTION_FAILED;
    }
    template_update_attribute( priv_tmpl, temp_attr );

    // Cleanup DH key
    DH_free(dh) ;
 
    return CKR_OK ;
 
} /* end token_specific_dh_key_pair_gen() */
#endif /* #ifndef NODH */

MECH_LIST_ELEMENT mech_list[] = {
   { CKM_RSA_PKCS_KEY_PAIR_GEN,     512, 2048, CKF_HW | CKF_GENERATE_KEY_PAIR },
#if !(NODSA)
   { CKM_DSA_KEY_PAIR_GEN,          512, 1024, CKF_HW | CKF_GENERATE_KEY_PAIR },
#endif
   { CKM_DES_KEY_GEN,                 8,    8, CKF_HW | CKF_GENERATE },
   { CKM_DES3_KEY_GEN,                24,    24, CKF_HW | CKF_GENERATE },
#if !(NOCDMF)
   { CKM_CDMF_KEY_GEN,                0,    0, CKF_HW | CKF_GENERATE },
#endif

   { CKM_RSA_PKCS,                  512, 2048, CKF_HW           |
                                               CKF_ENCRYPT      | CKF_DECRYPT |
                                               CKF_WRAP         | CKF_UNWRAP  |
                                               CKF_SIGN         | CKF_VERIFY  |
                                               CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER },
#if !(NOX509)
   { CKM_RSA_X_509,                 512, 2048, CKF_HW           |
                                               CKF_ENCRYPT      | CKF_DECRYPT |
                                               CKF_WRAP         | CKF_UNWRAP  |
                                               CKF_SIGN         | CKF_VERIFY  |
                                               CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER },
#endif
#if !(NOMD2)
   { CKM_MD2_RSA_PKCS,              512, 2048, CKF_HW      |
                                               CKF_SIGN    | CKF_VERIFY },

#endif
#if !(NOMD5)
   { CKM_MD5_RSA_PKCS,              512, 2048, CKF_HW      |
                                               CKF_SIGN    | CKF_VERIFY },
#endif
#if !(NOSHA1)
   { CKM_SHA1_RSA_PKCS,             512, 2048, CKF_HW      |
                                               CKF_SIGN    | CKF_VERIFY },
#endif


#if !(NODSA)
   { CKM_DSA,                       512, 1024, CKF_HW      |
                                               CKF_SIGN    | CKF_VERIFY },
#endif

/* Begin code contributed by Corrent corp. */
#if !(NODH)
   { CKM_DH_PKCS_DERIVE,            512, 2048, CKF_HW | CKF_DERIVE },
   { CKM_DH_PKCS_KEY_PAIR_GEN,      512, 2048, CKF_HW | CKF_GENERATE_KEY_PAIR },
#endif
/* End code contributed by Corrent corp. */

   { CKM_DES_ECB,                     8,    8, CKF_HW      |
                                               CKF_ENCRYPT | CKF_DECRYPT |
                                               CKF_WRAP    | CKF_UNWRAP },

   { CKM_DES_CBC,                     8,    8, CKF_HW      |
                                               CKF_ENCRYPT | CKF_DECRYPT |
                                               CKF_WRAP    | CKF_UNWRAP },

   { CKM_DES_CBC_PAD,                 8,    8, CKF_HW      |
                                               CKF_ENCRYPT | CKF_DECRYPT |
                                               CKF_WRAP    | CKF_UNWRAP },

#if !(NOCDMF)
   { CKM_CDMF_ECB,                    0,    0, CKF_HW      |
                                               CKF_ENCRYPT | CKF_DECRYPT |
                                               CKF_WRAP    | CKF_UNWRAP },

   { CKM_CDMF_CBC,                    0,    0, CKF_HW      |
                                               CKF_ENCRYPT | CKF_DECRYPT |
                                               CKF_WRAP    | CKF_UNWRAP },
#endif

   { CKM_DES3_ECB,                    24,    24, CKF_HW      |
                                               CKF_ENCRYPT | CKF_DECRYPT |
                                               CKF_WRAP    | CKF_UNWRAP },

   { CKM_DES3_CBC,                    24,    24, CKF_HW      |
                                               CKF_ENCRYPT | CKF_DECRYPT |
                                               CKF_WRAP    | CKF_UNWRAP },

   { CKM_DES3_CBC_PAD,                24,    24, CKF_HW      |
                                               CKF_ENCRYPT | CKF_DECRYPT |
                                               CKF_WRAP    | CKF_UNWRAP },

#if !(NOSHA1)
   { CKM_SHA_1,                       0,    0, CKF_HW | CKF_DIGEST },
   { CKM_SHA_1_HMAC,                  0,    0, CKF_HW | CKF_SIGN | CKF_VERIFY },
   { CKM_SHA_1_HMAC_GENERAL,          0,    0, CKF_HW | CKF_SIGN | CKF_VERIFY },
   { CKM_SHA256,                       0,    0, CKF_HW | CKF_DIGEST },
   { CKM_SHA256_HMAC,                  0,    0, CKF_HW | CKF_SIGN | CKF_VERIFY },
   { CKM_SHA256_HMAC_GENERAL,          0,    0, CKF_HW | CKF_SIGN | CKF_VERIFY },
#endif

#if !(NOMD2)
   { CKM_MD2,                         0,    0, CKF_HW | CKF_DIGEST },
   { CKM_MD2_HMAC,                    0,    0, CKF_HW | CKF_SIGN | CKF_VERIFY },
   { CKM_MD2_HMAC_GENERAL,            0,    0, CKF_HW | CKF_SIGN | CKF_VERIFY },
#endif

#if !(NOMD5)
   { CKM_MD5,                         0,    0, CKF_HW | CKF_DIGEST },
   { CKM_MD5_HMAC,                    0,    0, CKF_HW | CKF_SIGN | CKF_VERIFY },
   { CKM_MD5_HMAC_GENERAL,            0,    0, CKF_HW | CKF_SIGN | CKF_VERIFY },
#endif

   { CKM_SSL3_PRE_MASTER_KEY_GEN,    48,   48, CKF_HW | CKF_GENERATE },
   { CKM_SSL3_MASTER_KEY_DERIVE,     48,   48, CKF_HW | CKF_DERIVE },
   { CKM_SSL3_KEY_AND_MAC_DERIVE,    48,   48, CKF_HW | CKF_DERIVE },
   { CKM_SSL3_MD5_MAC,              384,  384, CKF_HW | CKF_SIGN | CKF_VERIFY },
   { CKM_SSL3_SHA1_MAC,             384,  384, CKF_HW | CKF_SIGN | CKF_VERIFY },

#if !(NOAES)
   { CKM_AES_KEY_GEN,                16,   32, CKF_HW },
   { CKM_AES_ECB,                    16,   32, CKF_HW      |
   					       CKF_ENCRYPT | CKF_DECRYPT |
   					       CKF_WRAP    | CKF_UNWRAP },
   { CKM_AES_CBC,                    16,   32, CKF_HW      |
   					       CKF_ENCRYPT | CKF_DECRYPT |
   					       CKF_WRAP    | CKF_UNWRAP },
   { CKM_AES_CBC_PAD,                16,   32, CKF_HW      |
   					       CKF_ENCRYPT | CKF_DECRYPT |
   					       CKF_WRAP    | CKF_UNWRAP },
#endif
	
};

CK_ULONG mech_list_len = (sizeof(mech_list) / sizeof(MECH_LIST_ELEMENT));

CK_RV
token_specific_get_mechanism_list(CK_MECHANISM_TYPE_PTR pMechanismList,
				  CK_ULONG_PTR pulCount)
{
	int rc;
	/* common/mech_list.c */
	rc = ock_generic_get_mechanism_list(pMechanismList, pulCount);
	return rc;
}

CK_RV
token_specific_get_mechanism_info(CK_MECHANISM_TYPE type, 
				  CK_MECHANISM_INFO_PTR pInfo)
{
	int rc;
	/* common/mech_list.c */
	rc = ock_generic_get_mechanism_info(type, pInfo);
	return rc;
}
