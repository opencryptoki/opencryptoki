/*************************************************/
/* AEP Token Implementation.                     */
/* Currently it uses openssl's libcrypto.so      */
/* for DES, 3DES and key generation.             */
/* Modular Exponentiation (RSA encrypt/decrypt)  */
/* is done in hardware.                          */
/*************************************************/

#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "args.h"
#include "errno.h"
#include "tok_specific.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <openssl/des.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#ifndef NOAES
#include <openssl/aes.h>
#endif
#ifndef NODH
#include <openssl/dh.h>
#endif

typedef unsigned int uint32_t;

pthread_mutex_t  rngmtx = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t  nextmutex = PTHREAD_MUTEX_INITIALIZER;
unsigned int  rnginitialized=0;

CK_CHAR manuf[] = "IBM Corp.";
CK_CHAR model[] = "IBM AEPToken";
CK_CHAR descr[] = "IBM PKCS#11 AEP token";
CK_CHAR label[] = "AEP OS PKCS#11   ";

/* variable indicating if AEP hardware is available */
int cryptoki_aep_avail = TRUE;
/* max length of modulae which can be handled by the card */
static int max_key_len = 2176;

CK_RV
token_specific_session(CK_SLOT_ID  slotid)
{
	return CKR_OK;
}

CK_RV
token_rng(CK_BYTE *output, CK_ULONG bytes)
{
#if 0
	int bytes2 = 384;
	char state[bytes2];
	pthread_mutex_lock(&rngmtx);

	if (!rnginitialized) {
		RAND_seed(&state, bytes2);
		rnginitialized=1;
	}

	RAND_pseudo_bytes(output, bytes);
	pthread_mutex_unlock(&rngmtx);
#else
	int  ranfd;
	int  rlen,totallen=0;
	
	ranfd = open("/dev/urandom",O_RDONLY);
	if (ranfd >= 0 ){
		
		do {
			rlen = read(ranfd,output+totallen,bytes-totallen);
			totallen += rlen; 
		} while( totallen < bytes);
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
	return CKR_OK;
}

CK_RV
token_specific_final()
{
	return CKR_OK;
}

CK_RV
token_specific_des_key_gen(CK_BYTE  *des_key,CK_ULONG len)
{
      
	// Nothing different to do for DES or TDES here as this is just
	// random data...  Validation handles the rest
	rng_generate(des_key,len);
        
	// we really need to validate the key for parity etc...
	// we should do that here... The caller validates the single des keys
	// against the known and suspected poor keys..
	return CKR_OK;
}

CK_RV
token_specific_des_ecb(CK_BYTE * in_data,
                       CK_ULONG in_data_len,
                       CK_BYTE *out_data,
                       CK_ULONG *out_data_len,
                       CK_BYTE  *key_value,
                       CK_BYTE  encrypt)
{
	CK_ULONG       rc;
	
	des_key_schedule des_key2;
   	const_des_cblock key_val_SSL, in_key_data;
	des_cblock out_key_data;
	int i,j;
   	int ret;

  	// Create the key schedule
	memcpy(&key_val_SSL, key_value, 8);
	des_set_key_unchecked(&key_val_SSL, des_key2);

	// the des decrypt will only fail if the data length is not 
	// evenly divisible by 8
	if (in_data_len % 8 ){
		OCK_LOG_ERR(ERR_DATA_LEN_RANGE);
		return CKR_DATA_LEN_RANGE;
	}

	// Both the encrypt and the decrypt are done 8 bytes at a time
	if (encrypt) {
		for (i=0; i<in_data_len; i=i+8) {
			memcpy(in_key_data, in_data+i, 8);
			des_ecb_encrypt(&in_key_data, &out_key_data, 
					des_key2, DES_ENCRYPT);
			memcpy(out_data+i, out_key_data, 8);
		}

		*out_data_len = in_data_len;
		rc = CKR_OK;
	} else {
 
		for(j=0; j < in_data_len; j=j+8) {
			memcpy(in_key_data, in_data+j, 8);
			des_ecb_encrypt(&in_key_data, &out_key_data, 
					des_key2, DES_DECRYPT);
			memcpy(out_data+j, out_key_data, 8);
		}
     
	*out_data_len = in_data_len;
	rc = CKR_OK;
	}

   return rc;
}

CK_RV
token_specific_des_cbc(CK_BYTE * in_data,
                       CK_ULONG in_data_len,
                       CK_BYTE *out_data,
                       CK_ULONG *out_data_len,
                       CK_BYTE  *key_value, 
                       CK_BYTE *init_v,
                       CK_BYTE  encrypt)
{
	CK_ULONG         rc;
	
	des_cblock ivec;
	int ret;

	des_key_schedule des_key2;
   	const_des_cblock key_val_SSL, in_key_data;
	des_cblock out_key_data;

	// Create the key schedule
	memcpy(&key_val_SSL, key_value, 8);
   	des_set_key_unchecked(&key_val_SSL, des_key2);
   
	memcpy(&ivec, init_v, 8);
	// the des decrypt will only fail if the data length is not 
	// evenly divisible by 8
	if (in_data_len % 8 ){
		OCK_LOG_ERR(ERR_DATA_LEN_RANGE);
		return CKR_DATA_LEN_RANGE;
	}

	if ( encrypt){
		des_ncbc_encrypt(in_data, out_data, in_data_len, 
				 des_key2, &ivec, DES_ENCRYPT);
		*out_data_len = in_data_len;
		rc = CKR_OK;
	} else {
		des_ncbc_encrypt(in_data, out_data, in_data_len, 
				 des_key2, &ivec, DES_DECRYPT);
		*out_data_len = in_data_len;
		rc = CKR_OK;
	}
	return rc;
}

CK_RV
token_specific_tdes_ecb(CK_BYTE * in_data,
			CK_ULONG in_data_len,
			CK_BYTE *out_data,
			CK_ULONG *out_data_len,
			CK_BYTE  *key_value,
			CK_BYTE  encrypt)
{
	CK_RV  rc;
	
	int k,j, ret;
	des_cblock out_temp;
	des_key_schedule des_key1;
	des_key_schedule des_key2;
	des_key_schedule des_key3;

   	const_des_cblock key_SSL1, key_SSL2, key_SSL3, in_key_data;
	des_cblock out_key_data;

	// The key as passed is a 24 byte long string containing three des keys
	// pick them apart and create the 3 corresponding key schedules
	memcpy(&key_SSL1, key_value, 8);
	memcpy(&key_SSL2, key_value+8, 8);
	memcpy(&key_SSL3, key_value+16, 8);
	des_set_key_unchecked(&key_SSL1, des_key1);
	des_set_key_unchecked(&key_SSL2, des_key2);
	des_set_key_unchecked(&key_SSL3, des_key3);

	// the des decrypt will only fail if the data length is not 
	// evenly divisible by 8
	if (in_data_len % 8 ){
		OCK_LOG_ERR(ERR_DATA_LEN_RANGE);
		return CKR_DATA_LEN_RANGE;
	}

	// the encrypt and decrypt are done 8 bytes at a time
	if (encrypt) {
		for(k=0;k<in_data_len;k=k+8){
		memcpy(in_key_data, in_data+k, 8);
		des_ecb3_encrypt(&in_key_data, 
				&out_key_data, 
				des_key1, 
				des_key2,
				des_key3,
				DES_ENCRYPT);
		memcpy(out_data+k, out_key_data, 8);
	}
	*out_data_len = in_data_len;
	rc = CKR_OK;
	} else {
		for (j=0;j<in_data_len;j=j+8){
		memcpy(in_key_data, in_data+j, 8);
		des_ecb3_encrypt(&in_key_data,
				&out_key_data, 
				des_key1,
				des_key2,
				des_key3, 
				DES_DECRYPT);
		memcpy(out_data+j, out_key_data, 8);
	}
      *out_data_len = in_data_len;
      rc = CKR_OK;
   }
   return rc;
}

CK_RV
token_specific_tdes_cbc(CK_BYTE * in_data,
                       CK_ULONG in_data_len,
                       CK_BYTE *out_data,
                       CK_ULONG *out_data_len,
                       CK_BYTE  *key_value, 
                       CK_BYTE *init_v,
                       CK_BYTE  encrypt)
{

	CK_RV rc = CKR_OK;
	des_key_schedule des_key1;
	des_key_schedule des_key2;
	des_key_schedule des_key3;

   	const_des_cblock key_SSL1, key_SSL2, key_SSL3, in_key_data;
	des_cblock ivec;

	// The key as passed in is a 24 byte string containing 3 keys
	// pick it apart and create the key schedules
	memcpy(&key_SSL1, key_value, 8);
	memcpy(&key_SSL2, key_value+8, 8);
	memcpy(&key_SSL3, key_value+16, 8);
	des_set_key_unchecked(&key_SSL1, des_key1);
	des_set_key_unchecked(&key_SSL2, des_key2);
	des_set_key_unchecked(&key_SSL3, des_key3);

	memcpy(ivec, init_v, sizeof(ivec));

	// the des decrypt will only fail if the data length is not
	// evenly divisible by 8
	if (in_data_len % 8 ){
		OCK_LOG_ERR(ERR_DATA_LEN_RANGE);
		return CKR_DATA_LEN_RANGE;
	}

	// Encrypt or decrypt the data
	if (encrypt){
		des_ede3_cbc_encrypt(in_data,
			     out_data,
			     in_data_len,
			     des_key1,
			     des_key2,
			     des_key3,
			     &ivec,
			     DES_ENCRYPT);
	*out_data_len = in_data_len;
	rc = CKR_OK;
	} else {
		des_ede3_cbc_encrypt(in_data,
				     out_data,
				     in_data_len,
				     des_key1,
				     des_key2,
				     des_key3,
				     &ivec,
				     DES_DECRYPT);
		
		*out_data_len = in_data_len;
		rc = CKR_OK;
	}
	
	return rc;
}


// convert from the local PKCS11 template representation to
// the underlying requirement
// returns the pointer to the local key representation

void *
rsa_convert_public_key( OBJECT    * key_obj , int * mLen)
{
	CK_BBOOL           rc;
	CK_ATTRIBUTE      * modulus = NULL;
	CK_ATTRIBUTE      * pub_exp = NULL;

	RSA *rsa;
	BIGNUM *bn_mod, *bn_exp;

	rc  = template_attribute_find( key_obj->template, CKA_MODULUS,
				       &modulus );
	rc &= template_attribute_find( key_obj->template, CKA_PUBLIC_EXPONENT,
				       &pub_exp );

	if (rc == FALSE) {
		return NULL;
	}

	// Create an RSA key struct to return
	rsa = RSA_new();
	if (rsa == NULL)
		return NULL;
	RSA_blinding_off(rsa);

	// Create and init BIGNUM structs to stick in the RSA struct
	bn_mod = BN_new();
	if (bn_mod == NULL) {
		RSA_free(rsa);
		return NULL;
	}
	bn_exp = BN_new();
	if (bn_exp == NULL) {
		RSA_free(rsa);
		BN_free(bn_mod);
		return NULL;
	}
	
	BN_init(bn_mod);
	BN_init(bn_exp);

	// Convert from strings to BIGNUMs and stick them in the RSA struct
	BN_bin2bn((char *)modulus->pValue, modulus->ulValueLen, bn_mod);
	rsa->n = bn_mod;
	BN_bin2bn((char *)pub_exp->pValue, pub_exp->ulValueLen, bn_exp);
	rsa->e = bn_exp;

	/* get the length of modulus for the modexp operation */
	*mLen = BN_num_bits(rsa->n);

	return (void *)rsa;
}

void *
rsa_convert_private_key(OBJECT *key_obj, int * mLen)
{
	CK_ATTRIBUTE      * attr     = NULL;
	CK_ATTRIBUTE      * modulus  = NULL;
	CK_ATTRIBUTE      * priv_exp = NULL;
	CK_ATTRIBUTE      * prime1   = NULL;
	CK_ATTRIBUTE      * prime2   = NULL;
	CK_ATTRIBUTE      * exp1     = NULL;
	CK_ATTRIBUTE      * exp2     = NULL;
	CK_ATTRIBUTE      * coeff    = NULL;
	CK_BBOOL          rc;

	RSA *rsa;
	BIGNUM *bn_mod, *bn_priv_exp, *bn_p1, *bn_p2, *bn_e1, *bn_e2, *bn_cf;
	int tmp;

	rc  = template_attribute_find( key_obj->template, CKA_MODULUS,
				       &modulus );
	rc &= template_attribute_find( key_obj->template, CKA_PRIVATE_EXPONENT,
				       &priv_exp );
	rc &= template_attribute_find( key_obj->template, CKA_PRIME_1,
				       &prime1 );
	rc &= template_attribute_find( key_obj->template, CKA_PRIME_2,
				       &prime2 );
	rc &= template_attribute_find( key_obj->template, CKA_EXPONENT_1,
				       &exp1 );
	rc &= template_attribute_find( key_obj->template, CKA_EXPONENT_2,
				       &exp2 );
	rc &= template_attribute_find( key_obj->template, CKA_COEFFICIENT,
				       &coeff );

	if ( !prime2 && !modulus ){
        	return NULL;
	}

	// Create and init all the RSA and BIGNUM structs we need.
	rsa = RSA_new();
	if (rsa == NULL)
		return NULL;
	RSA_blinding_off(rsa);

	bn_mod = BN_new();
	bn_priv_exp = BN_new();
	bn_p1 = BN_new();
	bn_p2 = BN_new();
	bn_e1 = BN_new();
	bn_e2 = BN_new();
	bn_cf = BN_new();

	if ((bn_cf == NULL) || (bn_e2 == NULL) || (bn_e1 == NULL) || 
	    (bn_p2 == NULL) || (bn_p1 == NULL) || (bn_priv_exp == NULL) ||
	    (bn_mod == NULL))
	{
		if (rsa)	 RSA_free(rsa);
		if (bn_mod)	 BN_free(bn_mod);
		if (bn_priv_exp) BN_free(bn_priv_exp);
		if (bn_p1)	 BN_free(bn_p1);
		if (bn_p2)	 BN_free(bn_p2);
		if (bn_e1)	 BN_free(bn_e1);
		if (bn_e2)	 BN_free(bn_e2);
		if (bn_cf)	 BN_free(bn_cf);
		return NULL;
	}

	// CRT key?
	if ( prime1){

		if (!prime2 || !exp1 ||!exp2 || !coeff) {
			return NULL;
		}
		// Even though this is CRT key, OpenSSL requires the
		// modulus and exponents filled in or encrypt and decrypt will
		// not work
		BN_bin2bn((char *)modulus->pValue, 
			  modulus->ulValueLen, bn_mod);
		rsa->n = bn_mod;
		BN_bin2bn((char *)priv_exp->pValue, 
			  priv_exp->ulValueLen, bn_priv_exp);
		rsa->d = bn_priv_exp;
		BN_bin2bn((char *)prime1->pValue, 
			  prime1->ulValueLen, bn_p1);
		rsa->p = bn_p1;
		BN_bin2bn((char *)prime2->pValue, 
			  prime2->ulValueLen, bn_p2);
		rsa->q = bn_p2;
		BN_bin2bn((char *)exp1->pValue, 
			  exp1->ulValueLen, bn_e1);
		rsa->dmp1 = bn_e1;
		BN_bin2bn((char *)exp2->pValue, 
			  exp2->ulValueLen, bn_e2);
		rsa->dmq1 = bn_e2;
		BN_bin2bn((char *)coeff->pValue, 
			  coeff->ulValueLen, bn_cf);
		rsa->iqmp = bn_cf;

		/* get the length of modulus for the modexp operation */
		*mLen = BN_num_bits(rsa->p);
		tmp =  BN_num_bits(rsa->q);
		*mLen = (tmp > *mLen) ? tmp : *mLen;

		return rsa;

	} else {   // must be a non-CRT key
		if (!priv_exp) {
			return NULL;
		}
		BN_bin2bn((char *)modulus->pValue, 
			  modulus->ulValueLen, bn_mod);
		rsa->n = bn_mod;
		BN_bin2bn((char *)priv_exp->pValue,
			  priv_exp->ulValueLen, bn_priv_exp);
		rsa->d = bn_priv_exp;

		/* get the length of modulus for the modexp operation */
		*mLen = BN_num_bits(rsa->n);
	}
	return (void *)rsa;
}

#define RNG_BUF_SIZE 100


// This function is only required if public key cryptography
// has been selected in your variant set up.
// Set a mutex in this function and get a cache;
// using the ICA device to get random numbers a byte at a
//  time is VERY slow..  Keygen is gated by this function.

unsigned char
nextRandom (void) 
{

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


CK_RV
os_specific_rsa_keygen(TEMPLATE *publ_tmpl,  TEMPLATE *priv_tmpl)
{
	CK_ATTRIBUTE       * publ_exp = NULL;
	CK_ATTRIBUTE       * attr     = NULL;
	CK_ULONG             mod_bits;
	CK_BBOOL             flag;
	CK_RV                rc;
	CK_ULONG             BNLength;
	RSA *rsa;
	BIGNUM *bignum;
	CK_BYTE *ssl_ptr;
	unsigned long three = 3;
	unsigned char *exp_str;
	unsigned long exponent;

	flag = template_attribute_find( publ_tmpl, CKA_MODULUS_BITS, &attr );
	if (!flag){
		OCK_LOG_ERR(ERR_TEMPLATE_INCOMPLETE);
		return CKR_TEMPLATE_INCOMPLETE;  // should never happen
        }
	mod_bits = *(CK_ULONG *)attr->pValue;
	flag = template_attribute_find( publ_tmpl, CKA_PUBLIC_EXPONENT, 
					&publ_exp );
	if (!flag){
		OCK_LOG_ERR(ERR_TEMPLATE_INCOMPLETE);
		return CKR_TEMPLATE_INCOMPLETE;
	}

	if (mod_bits < 512 || mod_bits > 2048) {
		OCK_LOG_ERR(ERR_KEY_SIZE_RANGE);
		return CKR_KEY_SIZE_RANGE;
	}

	// Because of a limition of OpenSSL, this token only supports
	// 3 as an exponent in RSA key generation

	rsa = RSA_new();
	if (rsa == NULL) {
		OCK_LOG_ERR(ERR_HOST_MEMORY);
		return CKR_HOST_MEMORY;
	}
	RSA_blinding_off(rsa);
	rsa = RSA_generate_key(mod_bits, three, NULL, NULL);
	if (rsa == NULL) {
		OCK_LOG_ERR(ERR_FUNCTION_FAILED);
		return CKR_FUNCTION_FAILED;
	}

	// Now fill in the objects..
	//
	// modulus: n
	//
	bignum = rsa->n;
	BNLength = BN_num_bytes(bignum);
	ssl_ptr = malloc(BNLength);
	if (ssl_ptr == NULL) {
		OCK_LOG_ERR(ERR_HOST_MEMORY);
		rc = CKR_HOST_MEMORY;
		goto done;
	}
	BNLength = BN_bn2bin(bignum, ssl_ptr);
	rc = build_attribute( CKA_MODULUS, ssl_ptr, 
			      BNLength, &attr ); // in bytes
	if (rc != CKR_OK){
		OCK_LOG_ERR(ERR_BLD_ATTR);
		goto done;
        }
	template_update_attribute( publ_tmpl, attr );
	free(ssl_ptr);

	// Public Exponent
        bignum = rsa->e;
        BNLength = BN_num_bytes(bignum);
        ssl_ptr = malloc(BNLength);
	if (ssl_ptr == NULL) {
		OCK_LOG_ERR(ERR_HOST_MEMORY);
		rc = CKR_HOST_MEMORY;
		goto done;
	}
        BNLength = BN_bn2bin(bignum, ssl_ptr);
        rc = build_attribute( CKA_PUBLIC_EXPONENT, ssl_ptr, 
			      BNLength, &attr ); // in bytes
        if (rc != CKR_OK){
                OCK_LOG_ERR(ERR_BLD_ATTR);
                goto done;
        }
        template_update_attribute( publ_tmpl, attr );
        free(ssl_ptr);

	// local = TRUE
	//
	flag = TRUE;
	rc = build_attribute( CKA_LOCAL, &flag, sizeof(CK_BBOOL), &attr );
	if (rc != CKR_OK){
		OCK_LOG_ERR(ERR_BLD_ATTR);
		goto done;
	}
	template_update_attribute( publ_tmpl, attr );

	//
	// now, do the private key
	//
	// Cheat here and put the whole original key into the CKA_VALUE... 
	// remember to force the system to not return this for RSA keys..

	// Add the modulus to the private key information

	bignum = rsa->n;
	BNLength = BN_num_bytes(bignum);
	ssl_ptr = malloc(BNLength);
	if (ssl_ptr == NULL) {
		OCK_LOG_ERR(ERR_HOST_MEMORY);
		rc = CKR_HOST_MEMORY;
		goto done;
	}
	BNLength = BN_bn2bin(bignum, ssl_ptr);
	rc = build_attribute( CKA_MODULUS, ssl_ptr, 
			      BNLength ,&attr ); // in bytes
	if (rc != CKR_OK){
		OCK_LOG_ERR(ERR_BLD_ATTR);
		goto done;
	}
	template_update_attribute( priv_tmpl, attr );
	free(ssl_ptr);

	// Private Exponent

        bignum = rsa->d;
        BNLength = BN_num_bytes(bignum);
        ssl_ptr = malloc( BNLength);
	if (ssl_ptr == NULL) {
		OCK_LOG_ERR(ERR_HOST_MEMORY);
		rc = CKR_HOST_MEMORY;
		goto done;
	}
        BNLength = BN_bn2bin(bignum, ssl_ptr);
        rc = build_attribute( CKA_PRIVATE_EXPONENT, ssl_ptr, BNLength, &attr );
        if (rc != CKR_OK){
                OCK_LOG_ERR(ERR_BLD_ATTR);
                goto done;
        }
        template_update_attribute( priv_tmpl, attr );
        free(ssl_ptr);

	// prime #1: p
	//
	bignum = rsa->p;
	BNLength = BN_num_bytes(bignum);
	ssl_ptr = malloc(BNLength);
	if (ssl_ptr == NULL) {
		OCK_LOG_ERR(ERR_HOST_MEMORY);
		rc = CKR_HOST_MEMORY;
		goto done;
	}
	BNLength = BN_bn2bin(bignum, ssl_ptr);
	rc = build_attribute( CKA_PRIME_1, ssl_ptr, BNLength, &attr );
	if (rc != CKR_OK){
		OCK_LOG_ERR(ERR_BLD_ATTR);
		goto done;
	}
	template_update_attribute( priv_tmpl, attr );
	free(ssl_ptr);

	// prime #2: q
	//
	bignum = rsa->q;
	BNLength = BN_num_bytes(bignum);
	ssl_ptr = malloc(BNLength);
	if (ssl_ptr == NULL) {
		OCK_LOG_ERR(ERR_HOST_MEMORY);
		rc = CKR_HOST_MEMORY;
		goto done;
	}
	BNLength = BN_bn2bin(bignum, ssl_ptr);
	rc = build_attribute( CKA_PRIME_2, ssl_ptr, BNLength, &attr );
	if (rc != CKR_OK){
		OCK_LOG_ERR(ERR_BLD_ATTR);
		goto done;
	}
	template_update_attribute( priv_tmpl, attr );
	free(ssl_ptr);

	// exponent 1: d mod(p-1)
	//
	bignum = rsa->dmp1;
	BNLength = BN_num_bytes(bignum);
	ssl_ptr = malloc(BNLength);
	if (ssl_ptr == NULL) {
		OCK_LOG_ERR(ERR_HOST_MEMORY);
		rc = CKR_HOST_MEMORY;
		goto done;
	}
	BNLength = BN_bn2bin(bignum, ssl_ptr);
	rc = build_attribute( CKA_EXPONENT_1, ssl_ptr, BNLength, &attr );
	if (rc != CKR_OK){
		OCK_LOG_ERR(ERR_BLD_ATTR);
		goto done;
	}
	template_update_attribute( priv_tmpl, attr );
	free(ssl_ptr);

	// exponent 2: d mod(q-1)
	//
	bignum = rsa->dmq1;
	BNLength = BN_num_bytes(bignum);
	ssl_ptr = malloc(BNLength);
	if (ssl_ptr == NULL) {
		OCK_LOG_ERR(ERR_HOST_MEMORY);
		rc = CKR_HOST_MEMORY;
		goto done;
	}
	BNLength = BN_bn2bin(bignum, ssl_ptr);
	rc = build_attribute( CKA_EXPONENT_2, ssl_ptr, BNLength, &attr );
	if (rc != CKR_OK){
		OCK_LOG_ERR(ERR_BLD_ATTR);
		goto done;
	}
	template_update_attribute( priv_tmpl, attr );
	free(ssl_ptr);

	// CRT coefficient:  q_inverse mod(p)
	//
	bignum = rsa->iqmp;
	BNLength = BN_num_bytes(bignum);
	ssl_ptr = malloc(BNLength);
	if (ssl_ptr == NULL) {
		OCK_LOG_ERR(ERR_HOST_MEMORY);
		rc = CKR_HOST_MEMORY;
		goto done;
	}
	BNLength = BN_bn2bin(bignum, ssl_ptr);
	rc = build_attribute( CKA_COEFFICIENT, ssl_ptr, BNLength, &attr );
	if (rc != CKR_OK){
		OCK_LOG_ERR(ERR_BLD_ATTR);
		goto done;
	}
	template_update_attribute( priv_tmpl, attr );
	free(ssl_ptr);

	flag = TRUE;
	rc = build_attribute( CKA_LOCAL, &flag, sizeof(CK_BBOOL), &attr );
	if (rc != CKR_OK){
		OCK_LOG_ERR(ERR_BLD_ATTR);
		goto done;
	}
	template_update_attribute( priv_tmpl, attr );
	
done:
	RSA_free(rsa);
	return rc;
}

CK_RV
token_specific_rsa_generate_keypair( TEMPLATE  * publ_tmpl,
				     TEMPLATE  * priv_tmpl )
{
	CK_RV rc;
	
	rc = os_specific_rsa_keygen(publ_tmpl,priv_tmpl);
	if (rc != CKR_OK)
		OCK_LOG_ERR(ERR_KEYGEN);
	return rc;
}


CK_RV
token_specific_rsa_encrypt( CK_BYTE   * in_data,
			    CK_ULONG    in_data_len,
			    CK_BYTE   * out_data,
			    OBJECT    * key_obj )
{
	CK_RV rc;
	RSA *rsa;
	int mLen;
	
	// Convert the local representation to an RSA representation
	rsa = (RSA *)rsa_convert_public_key(key_obj, &mLen);
	if (rsa==NULL) {
		OCK_LOG_ERR(ERR_FUNCTION_FAILED);
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}
	
	if ( cryptoki_aep_avail == TRUE && mLen <= max_key_len) {
		/* use AEP device */
		rc = AEP_RSA_public_encrypt(in_data_len, in_data, out_data, rsa);
	}
	
	
	// The operation will fall back to software if AEP is not available
	// or the modulus length is greater than allowed.
	// We do another "if" instead of "else", as the variable 
	// cryptoki_aep_avail might have just been set to FALSE in the 
	// call of AEP_RSA_public_encrypt above !! 
	
	if ( cryptoki_aep_avail == FALSE || mLen > max_key_len) {
		/* do it in software */
		rc = RSA_public_encrypt(in_data_len, in_data, out_data, 
					rsa, RSA_NO_PADDING);
	}
	
	if (rc != 0) {
		rc = CKR_OK;
	} else {
		OCK_LOG_ERR(ERR_FUNCTION_FAILED);
		rc = CKR_FUNCTION_FAILED;
	}
	// Clean up after ourselves
	RSA_free(rsa);
	
 done:
	return rc;
}


CK_RV
token_specific_rsa_decrypt( CK_BYTE   * in_data,
			    CK_ULONG    in_data_len,
			    CK_BYTE   * out_data,
			    OBJECT    * key_obj )
{
	CK_RV  rc;
	RSA   *rsa;
	int mLen;

	// Convert the local key representation to an RSA key representaion
	rsa = (RSA *)rsa_convert_private_key(key_obj, &mLen);
	if (rsa == NULL) {
		OCK_LOG_ERR(ERR_FUNCTION_FAILED);
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	if ( cryptoki_aep_avail == TRUE && mLen <= max_key_len) {
		/* Use AEP device */
		rc =AEP_RSA_private_decrypt(in_data_len, in_data, out_data, rsa);
	}

	// The operation will fall back to software if AEP is not available
	// or the modulus length is greater than allowed.
	// We do another "if" instead of "else", as the variable 
	// cryptoki_aep_avail might have just been set to FALSE in the 
	// call of AEP_RSA_private_decrypt above !! 

 	if ( cryptoki_aep_avail == FALSE || mLen > max_key_len) {
		/* do it in software */
		rc = RSA_private_decrypt(in_data_len, in_data, out_data, 
					 rsa, RSA_NO_PADDING);
	}
	if (rc != 0) {
		rc = CKR_OK;
	} else {
		OCK_LOG_ERR(ERR_FUNCTION_FAILED);
		rc = CKR_FUNCTION_FAILED;
	}
	
	// Clean up
	RSA_free(rsa);
 done:
	return rc;
}

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
