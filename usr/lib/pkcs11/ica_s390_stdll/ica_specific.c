/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/* Modified for S390 by Robert Burroughs                             */

#include <pthread.h>
#include <string.h>            // for memcmp() et al
#include <strings.h>
#include <stdlib.h>

#ifndef NOAES
#include <openssl/aes.h>
#endif
#ifndef NODH
#include <openssl/dh.h>
#endif

#include "pkcs11types.h"
#include "p11util.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "trace.h"

#include "tok_specific.h"
#include "tok_struct.h"
#include "ica_specific.h"
#include "ica_api.h"
// declare the adapter open handle localy
ica_adapter_handle_t adapter_handle;

// Linux really does not need these so we just dummy them up
// so the common code across platforms is usable...
#define KEYTYPE_MODEXPO   1
#define KEYTYPE_PKCSCRT   2

#define MAX_GENERIC_KEY_SIZE 256

CK_CHAR manuf[] = "IBM Corp.";
CK_CHAR model[] = "IBM ICA     ";
CK_CHAR descr[] = "IBM PKCS#11 ICA token ";
CK_CHAR label[] = "IBM ICA  PKCS #11";

pthread_mutex_t  rngmtx = PTHREAD_MUTEX_INITIALIZER;
unsigned int  rnginitialized=0;

CK_RV
token_specific_rng(STDLL_TokData_t *tokdata, CK_BYTE *output, CK_ULONG bytes)
{
   unsigned int  rc;

      pthread_mutex_lock(&rngmtx);

      rc = ica_random_number_generate( (unsigned int) bytes, output);

      if (rc != 0) {
         pthread_mutex_unlock(&rngmtx);
         return CKR_GENERAL_ERROR;
         /* report error */
      }

      pthread_mutex_unlock(&rngmtx);
      return CKR_OK;

}

CK_RV
token_specific_init(STDLL_TokData_t *tokdata, CK_SLOT_ID  SlotNumber,
		    char *conf_name)
{
	CK_ULONG rc = CKR_OK;

	rc = mech_list_ica_initialize();
	if (rc != CKR_OK) {
		TRACE_ERROR("mech_list_ica_initialize failed\n");
		return rc;
	}

	TRACE_INFO("ica %s slot=%lu running\n", __func__, SlotNumber);
	return ica_open_adapter(&adapter_handle);
}

CK_RV
token_specific_final()
{
	TRACE_INFO("ica %s running\n", __func__);
	ica_close_adapter(adapter_handle);
	return CKR_OK;
}

// count_ones_in_byte: for use in adjust_des_key_parity_bits below
CK_BYTE
count_ones_in_byte(CK_BYTE byte)
{
   CK_BYTE and_mask,   // bit selector
           number_of_ones = 0;

   for (and_mask = 1; and_mask != 0; and_mask <<= 1) // for each bit,
      if (byte & and_mask) // if it's a one,
         ++number_of_ones; // count it

   return number_of_ones;
}

#define EVEN_PARITY TRUE
#define ODD_PARITY FALSE
 // adjust_des_key_parity_bits: to conform to NIST spec for DES and 3DES keys
void adjust_des_key_parity_bits(CK_BYTE *des_key, CK_ULONG key_size, CK_BBOOL parity)
{
   CK_BYTE *des_key_byte;

   for (des_key_byte = des_key; des_key_byte - des_key < key_size; ++des_key_byte)
         // look at each byte in the key
   {
      if ((count_ones_in_byte(*des_key_byte) % 2) ^ (parity == ODD_PARITY))
      {
         // if parity for this byte isn't what it should be,
         // flip the parity (least significant) bit
         *des_key_byte ^= 1;
      }
   }
}







CK_RV
token_specific_des_key_gen(STDLL_TokData_t *tokdata, CK_BYTE  *des_key,
			   CK_ULONG len, CK_ULONG keysize)
{

   // Nothing different to do for DES or TDES here as this is just
   // random data...  Validation handles the rest
   // Only check for weak keys when DES.
        if (len == (3 * DES_KEY_SIZE)) {
                rng_generate(tokdata, des_key,len);
		adjust_des_key_parity_bits(des_key, len, ODD_PARITY);
	} else {
                do {
                        rng_generate(tokdata, des_key, len);
			adjust_des_key_parity_bits(des_key, len, ODD_PARITY);
                } while (des_check_weak_key(des_key) == TRUE);
        }


   // we really need to validate the key for parity etc...
   // we should do that here... The caller validates the single des keys
   // against the known and suspected poor keys..<<
        return CKR_OK;

}

CK_RV
token_specific_des_ecb(STDLL_TokData_t *tokdata,
		       CK_BYTE * in_data,
                       CK_ULONG in_data_len,
                       CK_BYTE *out_data,
                       CK_ULONG *out_data_len,
                       OBJECT   *key,
                       CK_BYTE  encrypt)
{
   CK_RV rc;
   CK_ATTRIBUTE *attr = NULL;

   /*
    * checks for input and output data length and block sizes
    * are already being carried out in mech_des.c
    * so we skip those
    */

   if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
      TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
      return CKR_FUNCTION_FAILED;
   }

   if ( encrypt) {
      rc = ica_des_ecb(in_data, out_data, in_data_len, attr->pValue,
		       ICA_ENCRYPT);
   } else {
      rc = ica_des_ecb(in_data, out_data, in_data_len, attr->pValue,
		       ICA_DECRYPT);
   }

   if (rc != 0) {
      rc = CKR_FUNCTION_FAILED;
      TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
   }else {
      *out_data_len = in_data_len;
      rc = CKR_OK;
   }

   return rc;


}

CK_RV
token_specific_des_cbc(STDLL_TokData_t *tokdata,
		       CK_BYTE * in_data,
                       CK_ULONG in_data_len,
                       CK_BYTE *out_data,
                       CK_ULONG *out_data_len,
                       OBJECT   *key,
                       CK_BYTE *init_v,
                       CK_BYTE  encrypt)
{

   CK_RV rc;
   CK_ATTRIBUTE *attr = NULL;

   /*
    * checks for input and output data length and block sizes
    * are already being carried out in mech_des.c
    * so we skip those
    */

  // get the key value
  if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
      TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
      return CKR_FUNCTION_FAILED;
   }

   if ( encrypt ){
      rc = ica_des_cbc(in_data, out_data, in_data_len, attr->pValue, init_v,
		       ICA_ENCRYPT);
   } else {
      rc = ica_des_cbc(in_data, out_data, in_data_len, attr->pValue, init_v,
		       ICA_DECRYPT);
   }
   if (rc != 0) {
         TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
         rc = CKR_FUNCTION_FAILED;
   }else {
         *out_data_len = in_data_len;
         rc = CKR_OK;
   }

   return rc;
}

CK_RV
token_specific_tdes_ecb(STDLL_TokData_t *tokdata,
		       CK_BYTE * in_data,
                       CK_ULONG in_data_len,
                       CK_BYTE *out_data,
                       CK_ULONG *out_data_len,
                       OBJECT  *key,
                       CK_BYTE  encrypt)
{
   CK_RV rc;
   CK_ATTRIBUTE *attr = NULL;
   CK_KEY_TYPE	keytype;
   CK_BYTE key_value[3*DES_KEY_SIZE];

   /*
    * checks for input and output data length and block sizes
    * are already being carried out in mech_des3.c
    * so we skip those
    */

   // get the key type
   rc = template_attribute_find(key->template, CKA_KEY_TYPE, &attr);
   if (rc == FALSE) {
      TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
      return CKR_FUNCTION_FAILED;
   }
      keytype = *(CK_KEY_TYPE *)attr->pValue;

   // get the key value
   if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
      TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
      return CKR_FUNCTION_FAILED;
   }
   if (keytype == CKK_DES2) {
      memcpy(key_value, attr->pValue, 2*DES_KEY_SIZE);
      memcpy(key_value + (2*DES_KEY_SIZE), attr->pValue, DES_KEY_SIZE);
   } else
      memcpy(key_value, attr->pValue, 3*DES_KEY_SIZE);

   if ( encrypt) {
      rc = ica_3des_ecb(in_data, out_data, in_data_len, key_value,
			ICA_ENCRYPT);
   } else {
      rc = ica_3des_ecb(in_data, out_data, in_data_len, key_value,
			ICA_DECRYPT);
   }

   if (rc != 0) {
      TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
      rc = CKR_FUNCTION_FAILED;
   }else {
      *out_data_len = in_data_len;
      rc = CKR_OK;
   }

   return rc;


}

CK_RV
token_specific_tdes_cbc(STDLL_TokData_t *tokdata,
		       CK_BYTE * in_data,
                       CK_ULONG in_data_len,
                       CK_BYTE *out_data,
                       CK_ULONG *out_data_len,
                       OBJECT  *key,
                       CK_BYTE *init_v,
                       CK_BYTE  encrypt)
{

   CK_RV rc;
   CK_ATTRIBUTE *attr = NULL;
   CK_KEY_TYPE	keytype;
   CK_BYTE key_value[3*DES_KEY_SIZE];

   /*
    * checks for input and output data length and block sizes
    * are already being carried out in mech_des3.c
    * so we skip those
    */

   // get the key type
   rc = template_attribute_find(key->template, CKA_KEY_TYPE, &attr);
   if (rc == FALSE) {
      TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
      return CKR_FUNCTION_FAILED;
   }
      keytype = *(CK_KEY_TYPE *)attr->pValue;
   // get the key value
   if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
       TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
       return CKR_FUNCTION_FAILED;
   }
   if (keytype == CKK_DES2) {
      memcpy(key_value, attr->pValue, 2*DES_KEY_SIZE);
      memcpy(key_value + (2*DES_KEY_SIZE), attr->pValue, DES_KEY_SIZE);
   } else
      memcpy(key_value, attr->pValue, 3*DES_KEY_SIZE);

   if ( encrypt ){
      rc = ica_3des_cbc(in_data, out_data, in_data_len, key_value, init_v,
			ICA_ENCRYPT);
   } else {
      rc = ica_3des_cbc(in_data, out_data, in_data_len, key_value, init_v,
			ICA_DECRYPT);
   }
   if (rc != 0) {
         TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
         rc = CKR_FUNCTION_FAILED;
   }else {
         *out_data_len = in_data_len;
         rc = CKR_OK;
   }

   return rc;
}

/*
 *
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 */
CK_RV
token_specific_tdes_ofb(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
			CK_BYTE *out_data, CK_ULONG data_len,
                        OBJECT *key, CK_BYTE *iv, uint_32 direction)
{
   CK_RV rc;
   CK_ATTRIBUTE *attr = NULL;

   if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
       TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
       return CKR_FUNCTION_FAILED;
    }

   rc = ica_3des_ofb(in_data, out_data, (unsigned int) data_len,
                    (unsigned char *) attr->pValue, (unsigned char *) iv,
                    direction);

   if (rc != 0) {
         TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
         rc = CKR_FUNCTION_FAILED;
   }
   return rc;
}

/*
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 */
CK_RV
token_specific_tdes_cfb(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
			CK_BYTE *out_data, CK_ULONG data_len,
                        OBJECT *key, CK_BYTE *iv, uint_32 cfb_len,
                        uint_32 direction)
{
   CK_RV rc;
   CK_ATTRIBUTE *attr = NULL;

   if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
       TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
       return CKR_FUNCTION_FAILED;
    }

   rc = ica_3des_cfb(in_data, out_data, (unsigned int) data_len,
                    (unsigned char *) attr->pValue, (unsigned char *) iv,
                    cfb_len, direction);

   if (rc != 0) {
         TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
         rc = CKR_FUNCTION_FAILED;
   }
   return rc;
}

CK_RV
token_specific_tdes_mac(STDLL_TokData_t *tokdata, CK_BYTE *message,
			CK_ULONG message_len, OBJECT *key, CK_BYTE *mac)
{
   CK_RV rc;
   CK_ATTRIBUTE *attr = NULL;
   CK_KEY_TYPE  keytype;
   CK_BYTE key_value[3*DES_KEY_SIZE];

   // get the key type
   rc = template_attribute_find(key->template, CKA_KEY_TYPE, &attr);
   if (rc == FALSE) {
      TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
      return CKR_FUNCTION_FAILED;
   }
      keytype = *(CK_KEY_TYPE *)attr->pValue;

   // get the key value
   if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
       TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
       return CKR_FUNCTION_FAILED;
   }
   if (keytype == CKK_DES2) {
      memcpy(key_value, attr->pValue, 2*DES_KEY_SIZE);
      memcpy(key_value + (2*DES_KEY_SIZE), attr->pValue, DES_KEY_SIZE);
   } else
      memcpy(key_value, attr->pValue, 3*DES_KEY_SIZE);

   rc = ica_3des_cmac_intermediate(message, (unsigned long) message_len,
                                   (unsigned char *) key_value, mac);

   if (rc != 0) {
         TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
         rc = CKR_FUNCTION_FAILED;
   }
   return rc;
}

/*
 * Init SHA data structures
 */
CK_RV token_specific_sha_init(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
			      CK_MECHANISM *mech)
{
	unsigned int ctxsize, devctxsize;
	struct oc_sha_ctx *sc;

	ctxsize = (sizeof(struct oc_sha_ctx) + 0x000F) & ~0x000F;
	switch (mech->mechanism) {
	case CKM_SHA_1:
		devctxsize = sizeof(sha_context_t);
		break;
	case CKM_SHA256:
		devctxsize = sizeof(sha256_context_t);
		break;
	case CKM_SHA384:
		devctxsize = sizeof(sha512_context_t);
		break;
	case CKM_SHA512:
		devctxsize = sizeof(sha512_context_t);
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}

	/* (re)alloc ctx in one memory area */
	if (ctx->context)
		free (ctx->context);
	ctx->context_len = 0;
	ctx->context = malloc(ctxsize + devctxsize);
	if (ctx->context == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return CKR_HOST_MEMORY;
	}
	memset(ctx->context, 0, ctxsize + devctxsize);
	ctx->context_len = ctxsize + devctxsize;
	sc = (struct oc_sha_ctx *)ctx->context;
	sc->dev_ctx_offs = ctxsize;

	sc->message_part = SHA_MSG_PART_ONLY;
	switch (mech->mechanism) {
	case CKM_SHA_1:
		sc->hash_len = SHA1_HASH_SIZE;
		sc->hash_blksize = SHA1_BLOCK_SIZE;
		break;
	case CKM_SHA256:
		sc->hash_len = SHA2_HASH_SIZE;
		sc->hash_blksize = SHA2_BLOCK_SIZE;
		break;
	case CKM_SHA384:
		sc->hash_len = SHA3_HASH_SIZE;
		sc->hash_blksize = SHA3_BLOCK_SIZE;
		break;
	case CKM_SHA512:
		sc->hash_len = SHA5_HASH_SIZE;
		sc->hash_blksize = SHA5_BLOCK_SIZE;
		break;
	}

	return CKR_OK;
}

CK_RV token_specific_sha(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
			 CK_BYTE *in_data, CK_ULONG in_data_len,
			 CK_BYTE *out_data, CK_ULONG *out_data_len)
{
	int rc;
	CK_RV rv = CKR_OK;
	struct oc_sha_ctx *sc;
	void *dev_ctx;

	if (!ctx || !ctx->context)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (!in_data || !out_data)
		return CKR_ARGUMENTS_BAD;

	sc = (struct oc_sha_ctx *) ctx->context;
	dev_ctx = ((CK_BYTE *) sc) + sc->dev_ctx_offs;

	if(*out_data_len < sc->hash_len)
		return CKR_BUFFER_TOO_SMALL;

	sc->message_part = SHA_MSG_PART_ONLY;

	switch (ctx->mech.mechanism) {
	case CKM_SHA_1:
	{
		sha_context_t *ica_sha_ctx = (sha_context_t *) dev_ctx;
		rc = ica_sha1(sc->message_part, in_data_len,
				in_data, ica_sha_ctx, sc->hash);
		break;
	}
	case CKM_SHA256:
	{
		sha256_context_t *ica_sha2_ctx = (sha256_context_t *) dev_ctx;
		rc = ica_sha256(sc->message_part, in_data_len,
				in_data, ica_sha2_ctx, sc->hash);
		break;
	}
	case CKM_SHA384:
	{
		sha512_context_t *ica_sha3_ctx = (sha512_context_t *) dev_ctx;
		rc = ica_sha384(sc->message_part, in_data_len,
				in_data, ica_sha3_ctx, sc->hash);
		break;
	}
	case CKM_SHA512:
	{
		sha512_context_t *ica_sha5_ctx = (sha512_context_t *) dev_ctx;
		rc = ica_sha512(sc->message_part, in_data_len,
				in_data, ica_sha5_ctx, sc->hash);
		break;
	}
	default:
		return CKR_MECHANISM_INVALID;
	}

	if (rc == CKR_OK) {
		memcpy(out_data, sc->hash, sc->hash_len);
		*out_data_len = sc->hash_len;
	} else
		rv = CKR_FUNCTION_FAILED;

	return rv;
}

static CK_RV ica_sha_call(DIGEST_CONTEXT *ctx, CK_BYTE *data, CK_ULONG data_len)
{
	struct oc_sha_ctx *sc = (struct oc_sha_ctx *)ctx->context;
	void *dev_ctx = ((CK_BYTE *) sc) + sc->dev_ctx_offs;
	CK_RV ret;

	switch (ctx->mech.mechanism) {
	case CKM_SHA_1:
	{
		sha_context_t *ica_sha_ctx = (sha_context_t *) dev_ctx;
		if (ica_sha_ctx->runningLength == 0)
			sc->message_part = SHA_MSG_PART_FIRST;
		else
			sc->message_part = SHA_MSG_PART_MIDDLE;
		ret = ica_sha1(sc->message_part, data_len, data,
			       ica_sha_ctx, sc->hash);
		break;
	}
	case CKM_SHA256:
	{
		sha256_context_t *ica_sha_ctx = (sha256_context_t *) dev_ctx;
		if (ica_sha_ctx->runningLength == 0)
			sc->message_part = SHA_MSG_PART_FIRST;
		else
			sc->message_part = SHA_MSG_PART_MIDDLE;
		ret = ica_sha256(sc->message_part, data_len, data,
				 ica_sha_ctx, sc->hash);
		break;
	}
	case CKM_SHA384:
	{
		sha512_context_t *ica_sha_ctx = (sha512_context_t *) dev_ctx;
		if (ica_sha_ctx->runningLengthLow == 0 &&
		    ica_sha_ctx->runningLengthHigh == 0)
			sc->message_part = SHA_MSG_PART_FIRST;
		else
			sc->message_part = SHA_MSG_PART_MIDDLE;
		ret = ica_sha384(sc->message_part, data_len, data,
				 ica_sha_ctx, sc->hash);
		break;
	}
	case CKM_SHA512:
	{
		sha512_context_t *ica_sha_ctx = (sha512_context_t *) dev_ctx;
		if (ica_sha_ctx->runningLengthLow == 0 &&
		    ica_sha_ctx->runningLengthHigh == 0)
			sc->message_part = SHA_MSG_PART_FIRST;
		else
			sc->message_part = SHA_MSG_PART_MIDDLE;
		ret = ica_sha512(sc->message_part, data_len, data,
				 ica_sha_ctx, sc->hash);
		break;
	}
	default:
		return CKR_MECHANISM_INVALID;
	}

	return(ret ? CKR_FUNCTION_FAILED : CKR_OK);
}

CK_RV token_specific_sha_update(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
				CK_BYTE *in_data, CK_ULONG in_data_len)
{
	struct oc_sha_ctx *sc;
	int fill, len, rest, ret;

	if (!ctx || !ctx->context)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (!in_data_len)
		return CKR_OK;

	if (!in_data)
		return CKR_ARGUMENTS_BAD;

	sc = (struct oc_sha_ctx *) ctx->context;

	/* if less than blocksize, save to context buffer for next time */
	if (sc->tail_len + in_data_len < sc->hash_blksize) {
		memcpy(sc->tail + sc->tail_len, in_data, in_data_len);
		sc->tail_len += in_data_len;
		return CKR_OK;
	}

	/* we have at least one block */

	/* if some leftovers from the last update are available
	   copy together one block into the tail buffer and hash it */
	if (sc->tail_len) {
		fill = sc->hash_blksize - sc->tail_len;
		memcpy(sc->tail + sc->tail_len, in_data, fill);

		/* hash blksize bytes from the tail buffer */
		ret = ica_sha_call(ctx, sc->tail, sc->hash_blksize);
		if (ret != CKR_OK)
			return ret;

		/* tail buffer is empty now */
		sc->tail_len = 0;

		/* adjust input data pointer and input data len */
		in_data += fill;
		in_data_len -= fill;

		/* if there is no more data to process, we are done */
		if (!in_data_len)
			return CKR_OK;
	}

	/* The tail buffer is empty now, and in_data_len is > 0.
	 * Calculate amount of remaining bytes...
	 */
	rest = in_data_len % sc->hash_blksize;

	/* and amount of bytes fitting into hash blocks */
	len = in_data_len - rest;

	/* process the full hash blocks */
	if (len > 0) {
		/* hash len bytes from input starting at the beginning */
		ret = ica_sha_call(ctx, in_data, len);
		if (ret != CKR_OK)
			return ret;

		/* adjust input data pointer */
		in_data += len;
	}

	/* Store remaining bytes into the empty tail buffer */
	if (rest > 0) {
		memcpy(sc->tail, in_data, rest);
		sc->tail_len = rest;
	}

	return CKR_OK;
}

CK_RV token_specific_sha_final(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
			       CK_BYTE *out_data, CK_ULONG *out_data_len)
{
	int rc;
	CK_RV rv = CKR_OK;
	struct oc_sha_ctx *sc;
	void *dev_ctx;

	if (!ctx || !ctx->context)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (!out_data || !out_data_len)
		return CKR_ARGUMENTS_BAD;

	sc = (struct oc_sha_ctx *)ctx->context;
	dev_ctx = ((CK_BYTE *) sc) + sc->dev_ctx_offs;
	sc->message_part = SHA_MSG_PART_FINAL;

	if (*out_data_len < sc->hash_len)
		return CKR_BUFFER_TOO_SMALL;

	switch (ctx->mech.mechanism) {
	case CKM_SHA_1:
	{
		sha_context_t *ica_sha1_ctx = (sha_context_t *) dev_ctx;
		/* accommodate multi-part when input was so small
		 * that we never got to call into libica until final
		 */
		if (ica_sha1_ctx->runningLength == 0)
			sc->message_part = SHA_MSG_PART_ONLY;
		rc = ica_sha1(sc->message_part, sc->tail_len,
			     (unsigned char *)sc->tail, ica_sha1_ctx,
			      sc->hash);
		break;
	}
	case CKM_SHA256:
	{
		sha256_context_t *ica_sha2_ctx = (sha256_context_t *) dev_ctx;
		/* accommodate multi-part when input was so small
		 * that we never got to call into libica until final
		 */
		if (ica_sha2_ctx->runningLength == 0)
			sc->message_part = SHA_MSG_PART_ONLY;
		rc = ica_sha256(sc->message_part, sc->tail_len,
			      sc->tail, ica_sha2_ctx, sc->hash);
		break;
	}
	case CKM_SHA384:
	{
		sha512_context_t *ica_sha3_ctx = (sha512_context_t *) dev_ctx;
		/* accommodate multi-part when input was so small
		 * that we never got to call into libica until final
		 */
		if (ica_sha3_ctx->runningLengthLow == 0
		    && ica_sha3_ctx->runningLengthHigh == 0)
			sc->message_part = SHA_MSG_PART_ONLY;
		rc = ica_sha384(sc->message_part, sc->tail_len,
			      sc->tail, ica_sha3_ctx, sc->hash);
		break;
	}
	case CKM_SHA512:
	{
		sha512_context_t *ica_sha5_ctx = (sha512_context_t *) dev_ctx;
		/* accommodate multi-part when input was so small
		 * that we never got to call into libica until final
		 */
		if (ica_sha5_ctx->runningLengthLow == 0
		    && ica_sha5_ctx->runningLengthHigh == 0)
			sc->message_part = SHA_MSG_PART_ONLY;
		rc = ica_sha512(sc->message_part, sc->tail_len,
			      sc->tail, ica_sha5_ctx, sc->hash);
		break;
	}
	default:
		return CKR_MECHANISM_INVALID;
	}

	if (rc != CKR_OK) {
		rv = CKR_FUNCTION_FAILED;
		goto out;
	}

	memcpy(out_data, sc->hash, sc->hash_len);
	*out_data_len = sc->hash_len;

out:
	return rv;
}

#ifndef LITE
#define LITE
#endif

/* Creates a libICA modulus+exponent key representation using
 * PKCS#11 attributes
 */
ica_rsa_key_mod_expo_t *
rsa_convert_mod_expo_key( CK_ATTRIBUTE * modulus,
                          CK_ATTRIBUTE * mod_bits,
                          CK_ATTRIBUTE * exponent)
{
   CK_BYTE                * ptr     = NULL;
   ica_rsa_key_mod_expo_t * modexpokey = NULL;

   /* We need at least the modulus and a (public|private) exponent */
   if (!modulus || !exponent) {
      TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
      return NULL;
   }

   modexpokey = (ica_rsa_key_mod_expo_t *) calloc(1, sizeof(ica_rsa_key_mod_expo_t));
   if (modexpokey == NULL) {
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      goto err;
   }

   /* We can't rely solely on CKA_MODULUS_BITS here since Private Keys
    * using the modulus + private exponent representation may also go
    * through this path. Use modulus length in bytes as key_length if
    * no mod_bits is present */
   if (mod_bits != NULL && mod_bits->ulValueLen && (*(CK_ULONG *)mod_bits->pValue)) {
      modexpokey->key_length = ((* (CK_ULONG *) mod_bits->pValue) + 7 ) / 8;
   }
   else {
      modexpokey->key_length = modulus->ulValueLen;
   }

   /* maybe I'm over-cautious here */
   if ( (modulus->ulValueLen > modexpokey->key_length) ||
        (exponent->ulValueLen > modexpokey->key_length)) {
      TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
      goto err;
   }

   modexpokey->modulus = (unsigned char *) calloc(1, modexpokey->key_length);

   if (modexpokey->modulus == NULL) {
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      goto err;
   }

   /* right-justified fields */
   ptr = modexpokey->modulus + modexpokey->key_length - modulus->ulValueLen;
   memcpy(ptr, modulus->pValue, modexpokey->key_length);

   modexpokey->exponent = (unsigned char *) calloc(1, modexpokey->key_length);
   if (modexpokey->exponent == NULL) {
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      goto err;
   }

   ptr = modexpokey->exponent + modexpokey->key_length - exponent->ulValueLen;
   memcpy(ptr, exponent->pValue, exponent->ulValueLen);
   return modexpokey;

 err:
   free(modexpokey->modulus);
   free(modexpokey->exponent);
   free(modexpokey);
   return NULL;

}

/* Creates a libICA CRT key representation using
 * PKCS#11 attributes
 */
ica_rsa_key_crt_t *
rsa_convert_crt_key( CK_ATTRIBUTE * modulus,
                     CK_ATTRIBUTE * prime1,
                     CK_ATTRIBUTE * prime2,
                     CK_ATTRIBUTE * exp1,
                     CK_ATTRIBUTE * exp2,
                     CK_ATTRIBUTE * coeff)
{
   CK_BYTE           * ptr      = NULL;
   ica_rsa_key_crt_t * crtkey  = NULL;

   /* All the above params are required to build a CRT key
    * that can be used by libICA. Private Keys with modulus
    * and private exponent should use rsa_convert_mod_expo_key() */
   if (!modulus || !prime1 || !prime2 || !exp1 || !exp2 || !coeff ) {
      TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
      return NULL;
   }
   else {
      crtkey = (ica_rsa_key_crt_t *) calloc(1, sizeof(ica_rsa_key_crt_t));
      if (crtkey == NULL) {
         TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
         return NULL;
      }
      /* use modulus length in bytes as key_length */
      crtkey->key_length = modulus->ulValueLen;

      /* buffers pointed by p, q, dp, dq and qInverse in struct
       * ica_rsa_key_crt_t must be of size key_legth/2 or larger.
       * p, dp and qInverse have an additional 8-byte padding. */

      /* need to allocate the buffers. Also, all fields are
       * right-aligned, thus the use for ptr */

      /* FIXME: if individual components lengths are bigger then
       * what we support in libICA then we're in trouble,
       * but maybe explicitly checking them is being over-zealous? */
      if ( (prime1->ulValueLen > (crtkey->key_length/2)) ||
           (prime2->ulValueLen > (crtkey->key_length/2)) ||
           (exp1->ulValueLen   > (crtkey->key_length/2)) ||
           (exp2->ulValueLen   > (crtkey->key_length/2)) ||
           (coeff->ulValueLen  > (crtkey->key_length/2)) ) {
         TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
         goto err_crtkey;
      }
      crtkey->p = (unsigned char *) calloc(1, (crtkey->key_length/2) + 8);
      if (crtkey->p == NULL) {
         TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
         goto err_crtkey;
      }
      ptr = crtkey->p + (crtkey->key_length/2) + 8 - prime1->ulValueLen;
      memcpy(ptr, prime1->pValue, prime1->ulValueLen);

      crtkey->q = (unsigned char *) calloc(1, crtkey->key_length/2);

      if (crtkey->q == NULL) {
         TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
         goto err_crtkey;
      }
      ptr = crtkey->q + (crtkey->key_length/2) - prime2->ulValueLen;
      memcpy(ptr, prime2->pValue, prime2->ulValueLen);

      crtkey->dp = (unsigned char *) calloc(1, (crtkey->key_length/2) + 8);
      if (crtkey->dp == NULL) {
         TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
         goto err_crtkey;
      }
      ptr = crtkey->dp + (crtkey->key_length/2) + 8 - exp1->ulValueLen;
      memcpy(ptr, exp1->pValue, exp1->ulValueLen);

      crtkey->dq = (unsigned char *) calloc(1, crtkey->key_length/2);
      if (crtkey->dq == NULL) {
         TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
         goto err_crtkey;
      }
      ptr = crtkey->dq + (crtkey->key_length/2) - exp2->ulValueLen;
      memcpy(ptr, exp2->pValue, exp2->ulValueLen);

      crtkey->qInverse = (unsigned char *) calloc(1, (crtkey->key_length/2) + 8);
      if (crtkey->qInverse == NULL) {
         TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
         goto err_crtkey;
      }
      ptr = crtkey->qInverse + (crtkey->key_length/2) + 8 - coeff->ulValueLen;
      memcpy(ptr, coeff->pValue, coeff->ulValueLen);

      return crtkey;
   }

 err_crtkey:
   free(crtkey->p);
   free(crtkey->q);
   free(crtkey->dp);
   free(crtkey->dq);
   free(crtkey->qInverse);
   free(crtkey);
   return NULL;

}


//
CK_RV
os_specific_rsa_keygen(TEMPLATE *publ_tmpl,  TEMPLATE *priv_tmpl)
{
   CK_ATTRIBUTE       * publ_exp = NULL;
   CK_ATTRIBUTE       * attr     = NULL;
   CK_BYTE            * ptr      = NULL;
   CK_ULONG             mod_bits;
   CK_BBOOL             flag;
   unsigned long        tmpsize;
   CK_RV                rc;
   ica_rsa_key_mod_expo_t * publKey = NULL;
   ica_rsa_key_crt_t      * privKey = NULL;

   flag = template_attribute_find( publ_tmpl, CKA_MODULUS_BITS, &attr );
   if (!flag) {
       TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
       return CKR_TEMPLATE_INCOMPLETE;  // should never happen
   }
   mod_bits = *(CK_ULONG *)attr->pValue;

   flag = template_attribute_find( publ_tmpl, CKA_PUBLIC_EXPONENT, &publ_exp );
   if (!flag) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
	return CKR_TEMPLATE_INCOMPLETE;
   }


   // FIXME: is this check really necessary?
   if (mod_bits < 512 || mod_bits > 4096) {
      TRACE_ERROR("%s\n", ock_err(ERR_KEY_SIZE_RANGE));
     return CKR_KEY_SIZE_RANGE;
   }

   /* libICA replicates the openSSL requirement that the public exponent
    * can't be larger than the size of an unsigned long
    */
   if (publ_exp->ulValueLen > sizeof (unsigned long)) {
      TRACE_ERROR("%s\n", ock_err(ERR_KEY_SIZE_RANGE));
     return CKR_KEY_SIZE_RANGE;
   }

   /* Build publKey:
    * The buffers in ica_rsa_key_mod_expo_t must be
    * allocated by the caller, with key_length size
    * use calloc() so that memory is zeroed (right alignment) */
   publKey = (ica_rsa_key_mod_expo_t *) calloc(1, sizeof(ica_rsa_key_mod_expo_t));
   if (publKey == NULL) {
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      return CKR_HOST_MEMORY;
   }

   /* key_length is in terms of bytes */
   publKey->key_length = ((mod_bits + 7) / 8);

   publKey->modulus = (unsigned char *) calloc(1, publKey->key_length);
   if (publKey->modulus == NULL) {
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      rc = CKR_HOST_MEMORY;
      goto pubkey_cleanup;
   }

   publKey->exponent = (unsigned char *) calloc(1, publKey->key_length);
   if (publKey->exponent == NULL) {
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      rc = CKR_HOST_MEMORY;
      goto pubkey_cleanup;
   }

   /* Use the provided public exponent:
    * all fields must be right-aligned, so make
    * sure we only use the rightmost part */
   /* We know the pub_exp attribute has it's value in BIG ENDIAN        *
    * byte order, and we're assuming we're on s390(x) which is also     *
    * BIG ENDIAN, so no byte swapping required.                         *
    * FIXME: Will need to fix that if porting for little endian         */
   ptr = publKey->exponent + publKey->key_length - publ_exp->ulValueLen;
   memcpy(ptr, publ_exp->pValue, publ_exp->ulValueLen);

   /* If the public exponent is zero, libica will generate a random one *
    * If it is an even number, then we have a problem. Use ptr to cast  *
    * to unsigned int and check                                         */
   ptr = publKey->exponent + publKey->key_length - sizeof (unsigned long);
   if ( *( (unsigned long *)ptr) != 0 &&
        *( (unsigned long *)ptr) % 2 == 0 ) {
     TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
     return CKR_TEMPLATE_INCONSISTENT;
   }


   /* Build privKey:
    * buffers pointed by p, q, dp, dq and qInverse in struct
    * ica_rsa_key_crt_t must be of size key_legth/2 or larger.
    * p, dp and qInverse have an additional 8-byte padding */
   privKey = (ica_rsa_key_crt_t *) calloc(1, sizeof(ica_rsa_key_crt_t));
   if (privKey == NULL) {
     TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
     rc = CKR_HOST_MEMORY;
     goto pubkey_cleanup;
   }

   /* modexpo and crt key lengths are always the same */
   privKey->key_length = publKey->key_length;

   privKey->p = (unsigned char *) calloc(1, (privKey->key_length/2) + 8);
   if (privKey->p == NULL) {
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      rc = CKR_HOST_MEMORY;
      goto privkey_cleanup;
   }

   privKey->q = (unsigned char *) calloc(1, privKey->key_length/2);
   if (privKey->q == NULL) {
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      rc = CKR_HOST_MEMORY;
      goto privkey_cleanup;
   }

   privKey->dp = (unsigned char *) calloc(1, (privKey->key_length/2) + 8);
   if (privKey->dp == NULL) {
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      rc = CKR_HOST_MEMORY;
      goto privkey_cleanup;
   }

   privKey->dq = (unsigned char *) calloc(1, privKey->key_length/2);
   if (privKey->dq == NULL) {
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      rc = CKR_HOST_MEMORY;
      goto privkey_cleanup;
   }

   privKey->qInverse = (unsigned char *) calloc(1, (privKey->key_length/2) + 8);
   if (privKey->qInverse == NULL) {
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      rc = CKR_HOST_MEMORY;
      goto privkey_cleanup;
   }

   rc = ica_rsa_key_generate_crt(adapter_handle,
                                 (unsigned int)mod_bits,
                                 publKey,
                                 privKey);


   if(rc){
     TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
     rc = CKR_FUNCTION_FAILED;
     goto privkey_cleanup;
   }


   /* Build the PKCS#11 public key */
   // modulus: n
   //
   tmpsize = publKey->key_length;
   ptr = p11_bigint_trim(publKey->modulus, &tmpsize);
   if (tmpsize != publKey->key_length) {
      /* This is bad */
      TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
      rc = CKR_FUNCTION_FAILED;
      goto privkey_cleanup;
   }
   rc = build_attribute( CKA_MODULUS, ptr,
                        tmpsize, &attr );
   if (rc != CKR_OK){
      TRACE_DEVEL("build_attribute failed\n");
      goto privkey_cleanup;
   }
   template_update_attribute( publ_tmpl, attr );

   // public exponent
   //
   tmpsize = publKey->key_length;
   ptr = p11_bigint_trim(publKey->exponent, &tmpsize);
   rc = build_attribute( CKA_PUBLIC_EXPONENT, ptr,
                        tmpsize, &attr);
   if (rc != CKR_OK){
      TRACE_DEVEL("build attribute failed\n");
      goto privkey_cleanup;
   }
   template_update_attribute( publ_tmpl, attr );


   // local = TRUE
   //
   flag = TRUE;
   rc = build_attribute( CKA_LOCAL, &flag, sizeof(CK_BBOOL), &attr );
   if (rc != CKR_OK){
      TRACE_DEVEL("build_attribute failed\n");
      goto privkey_cleanup;
   }
   template_update_attribute( publ_tmpl, attr );

   //
   // now, do the private key
   //

   // public exponent: e
   //
   tmpsize = publKey->key_length;
   ptr = p11_bigint_trim(publKey->exponent, &tmpsize);
   rc = build_attribute( CKA_PUBLIC_EXPONENT, ptr, tmpsize, &attr );
   if (rc != CKR_OK) {
      TRACE_DEVEL("build_attribute failed\n");
      goto privkey_cleanup;
   }
   template_update_attribute( priv_tmpl, attr );

   // modulus: n
   //
   tmpsize = publKey->key_length;
   ptr = p11_bigint_trim(publKey->modulus, &tmpsize);
   if (tmpsize != publKey->key_length) {
      /* This is bad */
      TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
      rc = CKR_FUNCTION_FAILED;
      goto privkey_cleanup;
   }
   rc = build_attribute( CKA_MODULUS, ptr,
                        tmpsize, &attr );
   if (rc != CKR_OK){
      TRACE_DEVEL("build_attribute failed\n");
      goto privkey_cleanup;
   }
   template_update_attribute( priv_tmpl, attr );

   // exponent 1: d mod(p-1)
   //
   tmpsize = privKey->key_length/2;
   ptr = p11_bigint_trim(privKey->dp + 8, &tmpsize);
   rc = build_attribute( CKA_EXPONENT_1, ptr,
                        tmpsize, &attr );
   if (rc != CKR_OK){
      TRACE_DEVEL("build_attribute failed\n");
      goto privkey_cleanup;
   }
   template_update_attribute( priv_tmpl, attr );

   // exponent 2: d mod(q-1)
   //
   tmpsize = privKey->key_length/2;
   ptr = p11_bigint_trim(privKey->dq, &tmpsize);
   rc = build_attribute( CKA_EXPONENT_2, ptr,
                        tmpsize, &attr );
   if (rc != CKR_OK){
      TRACE_DEVEL("build_attribute failed\n");
      goto privkey_cleanup;
   }
   template_update_attribute( priv_tmpl, attr );

   // prime #1: p
   //
   tmpsize = privKey->key_length/2;
   ptr = p11_bigint_trim(privKey->p + 8, &tmpsize);
   rc = build_attribute( CKA_PRIME_1, ptr,
                        tmpsize, &attr );
   if (rc != CKR_OK){
      TRACE_DEVEL("build_attribute failed\n");
      goto privkey_cleanup;
   }
   template_update_attribute( priv_tmpl, attr );


   // prime #2: q
   //
   tmpsize = privKey->key_length/2;
   ptr = p11_bigint_trim(privKey->q, &tmpsize);
   rc = build_attribute( CKA_PRIME_2, privKey->q,
                        privKey->key_length/2, &attr );
   if (rc != CKR_OK){
      TRACE_DEVEL("build_attribute failed\n");
      goto privkey_cleanup;
   }
   template_update_attribute( priv_tmpl, attr );


   // CRT coefficient:  q_inverse mod(p)
   //
   tmpsize = privKey->key_length/2;
   ptr = p11_bigint_trim(privKey->qInverse + 8, &tmpsize);
   rc = build_attribute( CKA_COEFFICIENT, ptr,
                        tmpsize, &attr );
   if (rc != CKR_OK){
      TRACE_DEVEL("build_attribute failed\n");
      goto privkey_cleanup;
   }
   template_update_attribute( priv_tmpl, attr );

 privkey_cleanup:
   free(privKey->p);
   free(privKey->q);
   free(privKey->dp);
   free(privKey->dq);
   free(privKey->qInverse);
   free(privKey);
 pubkey_cleanup:
   free(publKey->modulus);
   free(publKey->exponent);
   free(publKey);
   return rc;

}

CK_RV
token_specific_rsa_generate_keypair( STDLL_TokData_t *tokdata,
				     TEMPLATE  * publ_tmpl,
				     TEMPLATE  * priv_tmpl )
{
   CK_RV                rc;

   rc = os_specific_rsa_keygen(publ_tmpl,priv_tmpl);
   if (rc != CKR_OK)
         TRACE_DEVEL("os_specific_rsa_keygen failed\n");
   return rc;
}


//
//
CK_RV
os_specific_rsa_encrypt( CK_BYTE   * in_data,
                 CK_ULONG    in_data_len,
                 CK_BYTE   * out_data,
                 OBJECT    * key_obj )
{
   CK_ATTRIBUTE      * modulus = NULL;
   CK_ATTRIBUTE      * pub_exp = NULL;
   CK_ATTRIBUTE      * mod_bits = NULL;
   ica_rsa_key_mod_expo_t * publKey  = NULL;
   CK_RV               rc;

   /* mech_sra.c:ckm_rsa_encrypt accepts only CKO_PUBLIC_KEY */
   template_attribute_find( key_obj->template, CKA_MODULUS,          &modulus  );
   template_attribute_find( key_obj->template, CKA_MODULUS_BITS,     &mod_bits );
   template_attribute_find( key_obj->template, CKA_PUBLIC_EXPONENT,  &pub_exp  );

   publKey = rsa_convert_mod_expo_key(modulus, mod_bits, pub_exp);
   if (publKey == NULL) {
      TRACE_ERROR("rsa_convert_mod_expo_key failed\n");
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   /* in_data must be in big endian format. 'in_data' size in bits must not
    * exceed the bit length of the key, and size in bytes must
    * be of the same length of the key */
   // FIXME: we're not cheking the size in bits of in_data - but how could we?
   if (publKey->key_length != in_data_len) {
      TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
      rc = CKR_DATA_LEN_RANGE;
      goto cleanup_pubkey;
   }
   rc = ica_rsa_mod_expo(adapter_handle, in_data,
                         publKey, out_data);

   if (rc != 0) {
      TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
      rc = CKR_FUNCTION_FAILED;
   } else {
      rc = CKR_OK;
   }

cleanup_pubkey:
   free(publKey->modulus);
   free(publKey->exponent);
   free(publKey);


done:
   return rc;
}

//
//
CK_RV
os_specific_rsa_decrypt( CK_BYTE   * in_data,
                 CK_ULONG    in_data_len,
                 CK_BYTE   * out_data,
                 OBJECT    * key_obj )
{
   CK_ATTRIBUTE      * modulus  = NULL;
   CK_ATTRIBUTE      * prime1   = NULL;
   CK_ATTRIBUTE      * prime2   = NULL;
   CK_ATTRIBUTE      * exp1     = NULL;
   CK_ATTRIBUTE      * exp2     = NULL;
   CK_ATTRIBUTE      * coeff    = NULL;
   CK_ATTRIBUTE           * priv_exp   = NULL;
   ica_rsa_key_crt_t      * crtKey     = NULL;
   ica_rsa_key_mod_expo_t * modexpoKey = NULL;
   CK_RV               rc;

   /* mech_rsa.c:ckm_rsa_decrypt accepts only CKO_PRIVATE_KEY,
    * but Private Key can have 2 representations (see PKCS#1):
    *  - Modulus + private exponent
    *  - p, q, dp, dq and qInv (CRT format)
    * The former should use ica_rsa_key_mod_expo_t and the latter
    * ica_rsa_key_crt_t. Detect what representation this
    * key_obj has and use the proper convert function */

   template_attribute_find( key_obj->template, CKA_MODULUS,          &modulus );
   template_attribute_find( key_obj->template, CKA_PRIVATE_EXPONENT, &priv_exp );
   template_attribute_find( key_obj->template, CKA_PRIME_1,          &prime1  );
   template_attribute_find( key_obj->template, CKA_PRIME_2,          &prime2  );
   template_attribute_find( key_obj->template, CKA_EXPONENT_1,       &exp1    );
   template_attribute_find( key_obj->template, CKA_EXPONENT_2,       &exp2    );
   template_attribute_find( key_obj->template, CKA_COEFFICIENT,      &coeff   );

   /* Need to check for CRT Key format *BEFORE* check for mod_expo key,
    * that's because opencryptoki *HAS* a CKA_PRIVATE_EXPONENT attribute
    * even in CRT keys (but with zero length) */
   // FIXME: Checking for non-zero lengths anyway (might be overkill)

   if (modulus && modulus->ulValueLen &&
       prime1  && prime1->ulValueLen  &&
       prime2  && prime2->ulValueLen  &&
       exp1    && exp1->ulValueLen    &&
       exp2    && exp2->ulValueLen    &&
       coeff   && coeff->ulValueLen     ) {
      /* ica_rsa_key_crt_t representation */
      crtKey = rsa_convert_crt_key(modulus, prime1, prime2, exp1, exp2, coeff);
      if (crtKey == NULL) {
         TRACE_ERROR("rsa_convert_crt_key failed\n");
         rc = CKR_FUNCTION_FAILED;
         goto done;
      }
      /* same check as above */
      if (crtKey->key_length != in_data_len) {
         TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
         rc = CKR_ENCRYPTED_DATA_LEN_RANGE;
         goto crt_cleanup;
      }

      rc = ica_rsa_crt(adapter_handle, in_data,
                       crtKey, out_data);

      if (rc != 0) {
         TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
         rc = CKR_FUNCTION_FAILED;
      } else {
         rc = CKR_OK;
      }
      goto crt_cleanup;
   }
   else if (modulus  && modulus->ulValueLen &&
            priv_exp && priv_exp->ulValueLen  ) {
      /* ica_rsa_key_mod_expo_t representation */
      modexpoKey = rsa_convert_mod_expo_key(modulus, NULL, priv_exp);
      if (modexpoKey == NULL) {
         TRACE_ERROR("rsa_convert_mod_expo_key failed\n");
         rc = CKR_FUNCTION_FAILED;
         goto done;
      }
      /* in_data must be in big endian format. Size in bits must not
       * exceed the bit length of the key, and size in bytes must
       * be the same */
      // FIXME: we're not cheking the size in bits of in_data - but how could we?
      if (modexpoKey->key_length != in_data_len) {
         TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
         rc = CKR_ENCRYPTED_DATA_LEN_RANGE;
         goto modexpo_cleanup;
      }

      rc = ica_rsa_mod_expo(adapter_handle, in_data,
                            modexpoKey, out_data);

      if (rc != 0) {
         TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
         rc = CKR_FUNCTION_FAILED;
      } else {
         rc = CKR_OK;
      }
      goto modexpo_cleanup;
   }
   else {
      /* should never happen */
      TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
      rc = CKR_MECHANISM_PARAM_INVALID;
      goto done;
   }

crt_cleanup:
   free(crtKey->p);
   free(crtKey->q);
   free(crtKey->dp);
   free(crtKey->dq);
   free(crtKey->qInverse);
   free(crtKey);
   goto done;

modexpo_cleanup:
   free(modexpoKey->modulus);
   free(modexpoKey->exponent);
   free(modexpoKey);

done:
   return rc;
}


CK_RV
token_specific_rsa_encrypt(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
			   CK_ULONG in_data_len, CK_BYTE *out_data,
			   CK_ULONG *out_data_len, OBJECT *key_obj)
{
	CK_RV		rc;
	CK_BYTE		clear[MAX_RSA_KEYLEN], cipher[MAX_RSA_KEYLEN];
	CK_ULONG	modulus_bytes;
	CK_BBOOL	flag;
	CK_ATTRIBUTE	*attr = NULL;

	flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
	if (flag == FALSE) {
		TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
		return CKR_FUNCTION_FAILED;
	} else
		modulus_bytes = attr->ulValueLen;

	/* format the data */
	rc = rsa_format_block(tokdata, in_data, in_data_len, clear,
			      modulus_bytes, PKCS_BT_2);
	if (rc != CKR_OK) {
		TRACE_DEVEL("rsa_format_block failed\n");
		return rc;
	}

	rc = os_specific_rsa_encrypt(clear, modulus_bytes, cipher, key_obj);
	if (rc == CKR_OK) {
		memcpy(out_data, cipher, modulus_bytes);
		*out_data_len = modulus_bytes;
	} else
		TRACE_DEVEL("os_specific_rsa_encrypt failed\n");

	return rc;
}


CK_RV
token_specific_rsa_decrypt(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
			   CK_ULONG in_data_len, CK_BYTE *out_data,
			   CK_ULONG *out_data_len, OBJECT *key_obj)
{
	CK_BYTE		out[MAX_RSA_KEYLEN];
	CK_RV		rc;

	rc = os_specific_rsa_decrypt(in_data, in_data_len, out, key_obj);

	if (rc != CKR_OK) {
		TRACE_DEVEL("os_specific_rsa_decrypt failed\n");
		return rc;
	}

	rc = rsa_parse_block(out,in_data_len,out_data,out_data_len,PKCS_BT_2);
	if (rc != CKR_OK) {
		TRACE_DEVEL("rsa_parse_block failed\n");
		return rc;
	}

	/*
	 * For PKCS #1 v1.5 padding, out_data_len must be less
	 * than in_data_len (which is modulus_bytes) - 11.
	 */
	if (*out_data_len > (in_data_len - 11)) {
		TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_LEN_RANGE));
		rc = CKR_ENCRYPTED_DATA_LEN_RANGE;
	}

	return rc;
}

CK_RV
token_specific_rsa_sign(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
			CK_ULONG in_data_len, CK_BYTE *out_data,
			CK_ULONG *out_data_len, OBJECT *key_obj)
{
	CK_ATTRIBUTE	*attr = NULL;
	CK_BBOOL	flag;
	CK_RV		rc;
	CK_BYTE		data[MAX_RSA_KEYLEN], sig[MAX_RSA_KEYLEN];
	CK_ULONG	modulus_bytes;

	flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
	if (flag == FALSE) {
		TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
		return CKR_FUNCTION_FAILED;
	} else
		modulus_bytes = attr->ulValueLen;

	rc = rsa_format_block(tokdata, in_data, in_data_len, data,
			      modulus_bytes, PKCS_BT_1);
	if (rc != CKR_OK) {
		TRACE_DEVEL("rsa_format_block failed\n");
		return rc;
	}

	/* signing is a private key operation --> decrypt  */
	rc = os_specific_rsa_decrypt(data, modulus_bytes, sig, key_obj);
	if (rc == CKR_OK) {
		memcpy( out_data, sig, modulus_bytes );
		*out_data_len = modulus_bytes;
	} else
		TRACE_DEVEL("os_specific_rsa_decrypt failed\n");
	return rc;
}

CK_RV
token_specific_rsa_verify (STDLL_TokData_t *tokdata, CK_BYTE *in_data,
			   CK_ULONG in_data_len, CK_BYTE *signature,
			   CK_ULONG sig_len, OBJECT *key_obj)
{
	CK_RV		rc;
        CK_BYTE		out[MAX_RSA_KEYLEN], out_data[MAX_RSA_KEYLEN];
	CK_BBOOL	flag;
	CK_ATTRIBUTE	*attr = NULL;
	CK_ULONG	modulus_bytes, out_data_len;

	out_data_len = MAX_RSA_KEYLEN;
	flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
	if (flag == FALSE) {
		TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
		return CKR_FUNCTION_FAILED;
	} else
		modulus_bytes = attr->ulValueLen;

	rc = os_specific_rsa_encrypt(signature, modulus_bytes, out, key_obj);
	if (rc == CKR_OK) {
		rc = rsa_parse_block(out, modulus_bytes, out_data, &out_data_len, PKCS_BT_1);
		if (rc == CKR_OK) {
			if (in_data_len != out_data_len) {
				TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
				return CKR_SIGNATURE_INVALID;
			}

			if (memcmp(in_data, out_data, out_data_len) != 0) {
				TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
				return CKR_SIGNATURE_INVALID;
			}
		} else if (rc == CKR_ENCRYPTED_DATA_INVALID ) {
                        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
                        return CKR_SIGNATURE_INVALID;
		} else {
			TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
			return CKR_FUNCTION_FAILED;
		}
	} else
		TRACE_DEVEL("rsa_parse_block failed\n");

	return rc;
}

CK_RV
token_specific_rsa_verify_recover(STDLL_TokData_t *tokdata, CK_BYTE *signature,
				  CK_ULONG sig_len, CK_BYTE *out_data,
				  CK_ULONG *out_data_len, OBJECT *key_obj)
{
	CK_RV		rc;
	CK_BYTE		out[MAX_RSA_KEYLEN];
	CK_BBOOL	flag;
	CK_ATTRIBUTE	*attr = NULL;
	CK_ULONG	modulus_bytes;

	flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
	if (flag == FALSE) {
		TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
		return CKR_FUNCTION_FAILED;
	} else
		modulus_bytes = attr->ulValueLen;

	rc = os_specific_rsa_encrypt(signature, modulus_bytes, out, key_obj);
	if (rc != CKR_OK) {
		TRACE_DEVEL("os_specific_rsa_encrypt failed\n");
		return rc;
	}

	rc = rsa_parse_block(out, modulus_bytes, out_data, out_data_len, PKCS_BT_1);
	if (rc == CKR_ENCRYPTED_DATA_INVALID ) {
		TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
		return CKR_SIGNATURE_INVALID;
	} else if (rc != CKR_OK)
		TRACE_DEVEL("rsa_parse_block failed\n");

	return rc;
}

CK_RV
token_specific_rsa_x509_encrypt(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
				CK_ULONG in_data_len, CK_BYTE *out_data,
				CK_ULONG *out_data_len, OBJECT *key_obj)
{
	CK_RV		rc;
	CK_BYTE		clear[MAX_RSA_KEYLEN], cipher[MAX_RSA_KEYLEN];
	CK_BBOOL	flag;
	CK_ATTRIBUTE	*attr = NULL;
	CK_ULONG	modulus_bytes;

	flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
	if (flag == FALSE) {
		TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
		return CKR_FUNCTION_FAILED;
	} else
		modulus_bytes = attr->ulValueLen;

	// prepad with zeros
	//
	memset(clear, 0x0, modulus_bytes - in_data_len);
	memcpy(&clear[modulus_bytes - in_data_len], in_data, in_data_len);

	rc = os_specific_rsa_encrypt(clear, modulus_bytes, cipher, key_obj);
	if (rc == CKR_OK) {
		memcpy(out_data, cipher, modulus_bytes);
		*out_data_len = modulus_bytes;
	} else
		TRACE_DEVEL("os_specific_rsa_encrypt failed\n");

	return rc;
}

CK_RV
token_specific_rsa_x509_decrypt(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
				CK_ULONG in_data_len, CK_BYTE *out_data,
				CK_ULONG *out_data_len, OBJECT *key_obj)
{
	CK_RV		rc;
	CK_BYTE		out[MAX_RSA_KEYLEN];
	CK_BBOOL	flag;
	CK_ATTRIBUTE	*attr = NULL;
	CK_ULONG	modulus_bytes;

	flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
	if (flag == FALSE) {
		TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
		return CKR_FUNCTION_FAILED;
	} else
		modulus_bytes = attr->ulValueLen;

	rc = os_specific_rsa_decrypt(in_data, modulus_bytes, out, key_obj);
	if (rc == CKR_OK) {
		memcpy(out_data, out, modulus_bytes);
		*out_data_len = modulus_bytes;
	} else
		TRACE_DEVEL("os_specific_rsa_decrypt failed\n");

	return rc;
}

CK_RV
token_specific_rsa_x509_sign(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
			     CK_ULONG in_data_len, CK_BYTE *out_data,
			     CK_ULONG *out_data_len, OBJECT *key_obj)
{
	CK_RV		rc;
	CK_BYTE		data[MAX_RSA_KEYLEN], sig[MAX_RSA_KEYLEN];
	CK_BBOOL	flag;
	CK_ATTRIBUTE	*attr = NULL;
	CK_ULONG	modulus_bytes;

	flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
	if (flag == FALSE) {
		TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
		return CKR_FUNCTION_FAILED;
	} else
		modulus_bytes = attr->ulValueLen;

	// prepad with zeros
	//
	memset(data, 0x0, modulus_bytes - in_data_len);
	memcpy(&data[modulus_bytes - in_data_len], in_data, in_data_len);

	rc = os_specific_rsa_decrypt(data, modulus_bytes, sig ,key_obj);
	if (rc == CKR_OK) {
		memcpy(out_data, sig, modulus_bytes);
		*out_data_len = modulus_bytes;
	} else
		TRACE_DEVEL("os_specific_rsa_decrypt failed\n");
	return rc;
}


CK_RV
token_specific_rsa_x509_verify(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
			       CK_ULONG in_data_len, CK_BYTE *signature,
			       CK_ULONG sig_len, OBJECT *key_obj)
{
	CK_RV		rc;
	CK_BYTE		out[MAX_RSA_KEYLEN];
	CK_BBOOL	flag;
	CK_ATTRIBUTE	*attr = NULL;
	CK_ULONG	modulus_bytes;

	flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
	if (flag == FALSE) {
		TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
		return CKR_FUNCTION_FAILED;
	} else
		modulus_bytes = attr->ulValueLen;

	rc = os_specific_rsa_encrypt(signature, modulus_bytes, out ,key_obj);
	if (rc == CKR_OK) {
		CK_ULONG pos1, pos2, len;

		// it should be noted that in_data_len is not necessarily
		// the same as the modulus length
		//
		for (pos1=0; pos1 < in_data_len; pos1++)
			if (in_data[pos1] != 0)
				break;

		for (pos2=0; pos2 < modulus_bytes; pos2++)
			if (out[pos2] != 0)

		// at this point, pos1 and pos2 point to the first non-zero
		// bytes in the input data and the decrypted signature
		// (the recovered data), respectively.
		//

		if ((in_data_len - pos1) != (modulus_bytes - pos2)) {
			TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
			return CKR_SIGNATURE_INVALID;
		}
		len = in_data_len - pos1;

		if (memcmp(&in_data[pos1], &out[pos2], len) != 0) {
			TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
			return CKR_SIGNATURE_INVALID;
		}
		return CKR_OK;
	} else
		TRACE_DEVEL("os_specific_rsa_encrypt failed\n");

	return rc;
}


CK_RV
token_specific_rsa_x509_verify_recover(STDLL_TokData_t *tokdata,
				       CK_BYTE *signature, CK_ULONG sig_len,
				       CK_BYTE *out_data,
				       CK_ULONG *out_data_len, OBJECT *key_obj)
{
	CK_RV		rc;
	CK_BYTE		out[MAX_RSA_KEYLEN];
	CK_BBOOL	flag;
	CK_ATTRIBUTE	*attr = NULL;
	CK_ULONG	modulus_bytes;

	flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
	if (flag == FALSE) {
		TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
		return CKR_FUNCTION_FAILED;
	} else
		modulus_bytes = attr->ulValueLen;

	rc = os_specific_rsa_encrypt(signature, modulus_bytes, out, key_obj);
	if (rc == CKR_OK) {
		memcpy(out_data, out, modulus_bytes);
		*out_data_len = modulus_bytes;
	} else
		TRACE_DEVEL("os_specific_rsa_encrypt failed\n");

	return rc;
}

CK_RV token_specific_rsa_oaep_encrypt(STDLL_TokData_t *tokdata,
				      ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
				      CK_ULONG in_data_len, CK_BYTE *out_data,
				      CK_ULONG *out_data_len, CK_BYTE *hash,
				      CK_ULONG hlen)
{
	CK_RV rc;
	CK_BYTE cipher[MAX_RSA_KEYLEN];
	CK_ULONG modulus_bytes;
	CK_BBOOL flag;
	CK_ATTRIBUTE *attr = NULL;
	CK_BYTE *em_data = NULL;
	OBJECT *key_obj = NULL;
	CK_RSA_PKCS_OAEP_PARAMS_PTR oaepParms = NULL;

	if (!in_data || !out_data || !hash) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}

	oaepParms = (CK_RSA_PKCS_OAEP_PARAMS_PTR)ctx->mech.pParameter;

	rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj);
	if (rc != CKR_OK) {
		TRACE_DEVEL("object_mgr_find_in_map1 failed\n");
		return rc;
	}

	flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
	if (flag == FALSE) {
		TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
		return CKR_FUNCTION_FAILED;
	} else
		modulus_bytes = attr->ulValueLen;

	/* pkcs1v2.2, section 7.1.1 Step 2:
	 * EME-OAEP encoding.
	 */
	em_data = (CK_BYTE *)malloc(modulus_bytes);
	if (em_data == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return CKR_HOST_MEMORY;
	}

	rc = encode_eme_oaep(tokdata, in_data, in_data_len, em_data,
			     modulus_bytes, oaepParms->mgf, hash, hlen);
        if (rc != CKR_OK)
		goto done;

        rc = os_specific_rsa_encrypt(em_data, modulus_bytes, cipher, key_obj);
        if (rc == CKR_OK) {
                memcpy(out_data, cipher, modulus_bytes);
                *out_data_len = modulus_bytes;
        } else
                TRACE_DEVEL("os_specific_rsa_encrypt failed\n");

done:
	if (em_data)
		free(em_data);
        return rc;
}

CK_RV token_specific_rsa_oaep_decrypt(STDLL_TokData_t *tokdata,
				      ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
				      CK_ULONG in_data_len, CK_BYTE *out_data,
				      CK_ULONG *out_data_len, CK_BYTE *hash,
				      CK_ULONG hlen)
{
	CK_RV rc;
	CK_BYTE *decr_data = NULL;
	OBJECT *key_obj = NULL;
	CK_BBOOL flag;
	CK_ATTRIBUTE *attr = NULL;
	CK_RSA_PKCS_OAEP_PARAMS_PTR oaepParms = NULL;

	if (!in_data || !out_data || !hash) {
		TRACE_ERROR("Invalid function arguments.\n");
		return CKR_FUNCTION_FAILED;
	}

	oaepParms = (CK_RSA_PKCS_OAEP_PARAMS_PTR)ctx->mech.pParameter;

	rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj);
	if (rc != CKR_OK) {
		TRACE_DEVEL("object_mgr_find_in_map1 failed\n");
		return rc;
	}

	flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
	if (flag == FALSE) {
		TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
		return CKR_FUNCTION_FAILED;
	} else
		*out_data_len = attr->ulValueLen;

	decr_data = (CK_BYTE *)malloc(in_data_len);
	if (decr_data == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return CKR_HOST_MEMORY;
	}

	rc = os_specific_rsa_decrypt(in_data, in_data_len, decr_data, key_obj);
	if (rc != CKR_OK)
		return rc;

	/* pkcs1v2.2, section 7.1.2 Step 2:
	 * EME-OAEP decoding.
	 */
	rc = decode_eme_oaep(tokdata, decr_data, in_data_len, out_data,
			     out_data_len, oaepParms->mgf, hash, hlen);

	if (decr_data)
		free(decr_data);
	return rc;
}

CK_RV token_specific_rsa_pss_sign(STDLL_TokData_t *tokdata,
				  SIGN_VERIFY_CONTEXT *ctx,
				  CK_BYTE *in_data, CK_ULONG in_data_len,
				  CK_BYTE *sig, CK_ULONG *sig_len)
{
	CK_RV rc;
	CK_ULONG modbytes;
	CK_BBOOL flag;
	CK_ATTRIBUTE *attr = NULL;
	OBJECT *key_obj = NULL;
	CK_BYTE *emdata = NULL;
	CK_RSA_PKCS_PSS_PARAMS *pssParms = NULL;

	/* check the arguments */
	if (!in_data || !sig) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}

	if (!ctx) {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
		return CKR_FUNCTION_FAILED;
	}

	pssParms = (CK_RSA_PKCS_PSS_PARAMS *)ctx->mech.pParameter;

	/* get the key */
	rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj);
	if (rc != CKR_OK) {
		TRACE_DEVEL("object_mgr_find_in_map1 failed\n");
		return rc;
	}

        flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
        if (flag == FALSE) {
		TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
                return CKR_FUNCTION_FAILED;
        } else
                modbytes = attr->ulValueLen;

	emdata = (CK_BYTE *)malloc(modbytes);
	if (emdata == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return CKR_HOST_MEMORY;
	}

	rc = emsa_pss_encode(tokdata, pssParms, in_data, in_data_len, emdata,
			     &modbytes);
	if (rc != CKR_OK)
		goto done;

	/* signing is a private key operation --> decrypt  */
	rc = os_specific_rsa_decrypt(emdata, modbytes, sig, key_obj);
	if (rc == CKR_OK)
		*sig_len = modbytes;
	else
		TRACE_DEVEL("os_specific_rsa_decrypt failed\n");

done:
	if (emdata)
		free(emdata);
	return rc;
}


CK_RV token_specific_rsa_pss_verify(STDLL_TokData_t *tokdata, SIGN_VERIFY_CONTEXT *ctx,
				    CK_BYTE *in_data, CK_ULONG in_data_len,
				    CK_BYTE *signature, CK_ULONG sig_len)
{
	CK_RV rc;
	CK_ULONG modbytes;
	OBJECT *key_obj = NULL;
	CK_BBOOL flag;
	CK_ATTRIBUTE *attr = NULL;
	CK_BYTE out[MAX_RSA_KEYLEN];
	CK_RSA_PKCS_PSS_PARAMS *pssParms = NULL;

	/* check the arguments */
	if (!in_data || !signature) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}

	if (!ctx) {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
		return CKR_FUNCTION_FAILED;
	}

	pssParms = (CK_RSA_PKCS_PSS_PARAMS *)ctx->mech.pParameter;

	/* get the key */
	rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj);
	if (rc != CKR_OK) {
		TRACE_DEVEL("object_mgr_find_in_map1 failed\n");
		return rc;
	}

	/* verify is a public key operation ... encrypt */
	rc = os_specific_rsa_encrypt(signature, sig_len, out, key_obj);
	if (rc != CKR_OK) {
		TRACE_DEVEL("os_specific_rsa_encrypt failed\n");
		return rc;
	}

	flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
	if (flag == FALSE) {
		TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
		return CKR_FUNCTION_FAILED;
	} else
		modbytes = attr->ulValueLen;

	/* call the pss verify scheme */
	rc = emsa_pss_verify(tokdata, pssParms, in_data, in_data_len, out,
			     modbytes);
	return rc;
}

#ifndef NOAES

CK_RV
token_specific_aes_key_gen(STDLL_TokData_t *tokdata, CK_BYTE *key,
			   CK_ULONG len, CK_ULONG keysize)
{
        return rng_generate(tokdata, key, len);
}

CK_RV
token_specific_aes_ecb(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
		       CK_ULONG in_data_len,
		       CK_BYTE *out_data, CK_ULONG *out_data_len,
		       OBJECT *key, CK_BYTE encrypt)
{
	int rc = CKR_OK;
	CK_ATTRIBUTE *attr = NULL;

   /*
    * checks for input and output data length and block sizes
    * are already being carried out in mech_aes.c
    * so we skip those
    */
	// get the key value
	rc = template_attribute_find(key->template, CKA_VALUE, &attr);
	if (rc == FALSE) {
		TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
		return CKR_FUNCTION_FAILED;
	}

        if (encrypt) {
		rc = ica_aes_ecb(in_data, out_data, in_data_len, attr->pValue,
				 attr->ulValueLen, ICA_ENCRYPT);
        } else {
		rc = ica_aes_ecb(in_data, out_data, in_data_len, attr->pValue,
				 attr->ulValueLen, ICA_DECRYPT);
        }
	if (rc != 0) {
        (*out_data_len) = 0;
		rc = CKR_FUNCTION_FAILED;
	} else {
		(*out_data_len) = in_data_len;
		rc = CKR_OK;
	}
        return rc;
}

CK_RV
token_specific_aes_cbc(STDLL_TokData_t *tokdata,
		       CK_BYTE         *in_data,
		       CK_ULONG        in_data_len,
		       CK_BYTE         *out_data,
		       CK_ULONG        *out_data_len,
		       OBJECT          *key,
		       CK_BYTE         *init_v,
		       CK_BYTE         encrypt)
{
	CK_RV rc;
	CK_ATTRIBUTE *attr = NULL;

   /*
    * checks for input and output data length and block sizes
    * are already being carried out in mech_aes.c
    * so we skip those
    */

	// get the key value
	if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
		TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
		return CKR_FUNCTION_FAILED;
	}

	if (encrypt) {
		rc = ica_aes_cbc(in_data, out_data, in_data_len, attr->pValue,
				 attr->ulValueLen, init_v, ICA_ENCRYPT);
	} else {
		rc = ica_aes_cbc(in_data, out_data, in_data_len, attr->pValue,
				 attr->ulValueLen, init_v, ICA_DECRYPT);
	}
	if (rc != 0) {
        (*out_data_len) = 0;
		rc = CKR_FUNCTION_FAILED;
	} else {
		(*out_data_len) = in_data_len;
		rc = CKR_OK;
	}
	return rc;
}
CK_RV
token_specific_aes_ctr(STDLL_TokData_t  *tokdata,
		       CK_BYTE          *in_data,
		       CK_ULONG		 in_data_len,
		       CK_BYTE 		*out_data,
		       CK_ULONG		*out_data_len,
		       OBJECT		*key,
		       CK_BYTE          *counterblock,
		       CK_ULONG          counter_width,
		       CK_BYTE 		 encrypt)
{
   CK_RV rc;
   CK_ATTRIBUTE *attr = NULL;

   /*
    * checks for input and output data length and block sizes
    * are already being carried out in mech_aes.c
    * so we skip those
    */
  /* in libica for AES-Counter Mode if uses one function for both encrypt and decrypt
   * so they use variable direction to know if the data is to be encrypted or decrypted
   * 0 -- Decrypt
   * 1 -- Encrypt
   */

   // get the key value
   if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
      TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
      return CKR_FUNCTION_FAILED;
   }

   if (encrypt){
      rc = ica_aes_ctr( in_data, out_data, (unsigned int) in_data_len,
                        attr->pValue, (unsigned int) attr->ulValueLen,
                        counterblock, (unsigned int ) counter_width,
		        1);
   }
   else{
      rc = ica_aes_ctr( in_data, out_data, (unsigned int) in_data_len,
                        attr->pValue, (unsigned int) attr->ulValueLen,
                        counterblock, (unsigned int ) counter_width,
                        0);
   }
   if( rc != 0){
     (*out_data_len) = 0;
     rc = CKR_FUNCTION_FAILED;
   }
   else
   {
     (*out_data_len) = in_data_len;
     rc = CKR_OK;
   }
   return rc;
}

CK_RV token_specific_aes_gcm_init(STDLL_TokData_t *tokdata, SESSION *sess,
				  ENCR_DECR_CONTEXT *ctx, CK_MECHANISM *mech,
				  CK_OBJECT_HANDLE key, CK_BYTE encrypt)
{
	CK_RV rc = CKR_OK;
	OBJECT *key_obj = NULL;
	CK_ATTRIBUTE *attr = NULL;
	CK_GCM_PARAMS *aes_gcm_param = NULL;
	AES_GCM_CONTEXT *context = NULL;
	CK_BYTE *icv, *icb, *ucb, *subkey;
	CK_ULONG icv_length;

	/* find key object */
	rc = object_mgr_find_in_map1 (tokdata, key, &key_obj);
	if (rc != CKR_OK){
		TRACE_ERROR("Failed to find specified object.\n");
		return rc;
	}

	/* get the key value */
	rc = template_attribute_find(key_obj->template, CKA_VALUE, &attr);
	if (rc == FALSE) {
		TRACE_ERROR("Could not find CKA_KEY_VALUE for the key.\n");
		return CKR_FUNCTION_FAILED;
	}

	/* prepare initial counterblock */
	aes_gcm_param = (CK_GCM_PARAMS *)mech->pParameter;
	context = (AES_GCM_CONTEXT *)ctx->context;

	context->ulAlen = aes_gcm_param->ulAADLen;
	icb = (CK_BYTE *)context->icb;
	ucb = (CK_BYTE *)context->ucb;
	subkey = (CK_BYTE *)context->subkey;

	icv = (CK_BYTE *)aes_gcm_param->pIv;
	icv_length = aes_gcm_param->ulIvLen;

	if (encrypt) {
		rc = ica_aes_gcm_initialize(icv, icv_length,
				            (char *)attr->pValue,
					    attr->ulValueLen, icb, ucb,
					    subkey, 1);
	} else {
		rc = ica_aes_gcm_initialize(icv, icv_length,
					    (char *)attr->pValue,
					    attr->ulValueLen, icb, ucb,
					    subkey, 0);
	}
	if (rc != 0) {
		TRACE_ERROR("ica_aes_gcm_initialize() failed.\n");
		return CKR_FUNCTION_FAILED;
	} else
		return CKR_OK;
}

CK_RV token_specific_aes_gcm(STDLL_TokData_t *tokdata, SESSION *sess,
			     ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
			     CK_ULONG in_data_len, CK_BYTE *out_data,
			     CK_ULONG *out_data_len, CK_BYTE encrypt)
{
	CK_RV rc;
	OBJECT *key = NULL;
	CK_ATTRIBUTE *attr = NULL;
	CK_GCM_PARAMS *aes_gcm_param = NULL;
	CK_BYTE *counterblock;
	CK_ULONG counter_width;
	CK_BYTE *tag_data,*auth_data;
	CK_ULONG auth_data_len;
	CK_ULONG tag_data_len;

	/*
	 * Checks for input and output data length and block sizes are already
	 * being carried out in mech_aes.c, so we skip those
	 *
	 * libica for AES-GCM Mode uses one function for both encrypt
	 * and decrypt, so they use the variable 'direction' to know if
	 * the data is to be encrypted or decrypted.
	 * 0 -- Decrypt
	 * 1 -- Encrypt
	 */

	aes_gcm_param = (CK_GCM_PARAMS *)ctx->mech.pParameter;
	counterblock = (CK_BYTE *)aes_gcm_param->pIv;
	counter_width = aes_gcm_param->ulIvLen;
	auth_data = (CK_BYTE *)aes_gcm_param->pAAD;
	auth_data_len = aes_gcm_param->ulAADLen;
	tag_data_len = (aes_gcm_param->ulTagBits + 7) / 8;

	/* find key object */
	rc = object_mgr_find_in_map1(tokdata, ctx->key, &key);
	if (rc != CKR_OK) {
		TRACE_ERROR("Failed to find specified object.\n");
		return rc;
	}

	/* get key value */
	if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
		TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
		return CKR_FUNCTION_FAILED;
	}

	if (encrypt) {
		tag_data = out_data + in_data_len;
		rc = ica_aes_gcm(in_data, (unsigned int) in_data_len, out_data,
				 counterblock, (unsigned int) counter_width,
				 auth_data, (unsigned int) auth_data_len,
				 tag_data, AES_BLOCK_SIZE, attr->pValue,
				 (unsigned int) attr->ulValueLen, 1);
		if (rc == 0) {
			(*out_data_len) = in_data_len + tag_data_len;
			rc = CKR_OK;
		}
	} else {
		unsigned int len;

		tag_data = in_data + in_data_len - tag_data_len;
		len = in_data_len - tag_data_len;
		rc = ica_aes_gcm(out_data,
				 (unsigned int)len, in_data, counterblock,
				 (unsigned int ) counter_width, auth_data,
				 (unsigned int) auth_data_len, tag_data,
				 (unsigned int)tag_data_len, attr->pValue,
				 (unsigned int) attr->ulValueLen, 0);
		if (rc == 0) {
			(*out_data_len) = len;
			rc = CKR_OK;
		}
	}

	if (rc != 0) {
		TRACE_ERROR("ica_aes_gcm failed with rc = 0x%lx.\n", rc);
		(*out_data_len) = 0;
		rc = CKR_FUNCTION_FAILED;
	}

	return rc;
}

CK_RV token_specific_aes_gcm_update(STDLL_TokData_t *tokdata, SESSION *sess,
				    ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
				    CK_ULONG in_data_len, CK_BYTE *out_data,
				    CK_ULONG *out_data_len, CK_BYTE encrypt)
{
	CK_RV rc;
	CK_ATTRIBUTE *attr = NULL;
	OBJECT *key = NULL;
	AES_GCM_CONTEXT *context = NULL;
	CK_GCM_PARAMS *aes_gcm_param = NULL;
	CK_ULONG total, tag_data_len, remain, auth_data_len;
	CK_ULONG out_len;
	CK_BYTE *auth_data, *tag_data;
	CK_BYTE *ucb, *subkey;
	CK_BYTE *buffer = NULL;

	context = (AES_GCM_CONTEXT *)ctx->context;
	total = (context->len + in_data_len);
	ucb = (CK_BYTE *)context->ucb;
	tag_data = context->hash;
	auth_data_len = context->ulAlen;
	subkey = (CK_BYTE *)context->subkey;

	aes_gcm_param = (CK_GCM_PARAMS *)ctx->mech.pParameter;
	tag_data_len = (aes_gcm_param->ulTagBits + 7) / 8;
	auth_data = (CK_BYTE *)aes_gcm_param->pAAD;

	/* if there isn't enough data to make a block, just save it */
	if (encrypt) {
		remain = (total % AES_BLOCK_SIZE);
		if (total < AES_BLOCK_SIZE) {
			memcpy(context->data + context->len, in_data, in_data_len);
			context->len += in_data_len;
			*out_data_len = 0;
			return CKR_OK;
		}
	 } else {
		/* decrypt */
		remain = ((total - tag_data_len)  % AES_BLOCK_SIZE)
			  + tag_data_len;
		if (total < AES_BLOCK_SIZE + tag_data_len) {
			memcpy(context->data + context->len, in_data, in_data_len);
			context->len += in_data_len;
			*out_data_len = 0;
			return CKR_OK;
		}
	}

	/* At least we have 1 block */
	/* find key object */
	rc = object_mgr_find_in_map_nocache(ctx->key, &key);
	if(rc != CKR_OK) {
		TRACE_ERROR("Failed to find specified object.\n");
		return rc;
	}

	/* get key value */
	if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
		TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
		return CKR_FUNCTION_FAILED;
	}

	out_len = total - remain;

	buffer = (CK_BYTE*)malloc(out_len);
	if (!buffer) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		rc = CKR_HOST_MEMORY;
		goto done;
	}

	if (encrypt) {
		/* copy all the leftover data from previous encryption first */
		memcpy (buffer, context->data, context->len);
		memcpy (buffer+context->len, in_data, out_len - context->len);

		TRACE_DEVEL("Ciphertext length (%ld bytes).\n", in_data_len);

		rc = ica_aes_gcm_intermediate(buffer, (unsigned int)out_len,
					      out_data, ucb, auth_data,
					      (unsigned int)auth_data_len,
					      tag_data, AES_BLOCK_SIZE,
					      attr->pValue,
					      (unsigned int)attr->ulValueLen,
					      subkey, 1);

		/* save any remaining data */
		if (remain != 0)
			memcpy(context->data, in_data + (in_data_len - remain),
			       remain);
		context->len = remain;

	} else {
		/* decrypt */
		/* copy all the leftover data from previous encryption first */
		if (in_data_len >= tag_data_len) { /* case 1  */
			/* copy complete context to buffer first*/
			memcpy (buffer, context->data, context->len);
			/* Append in_data to buffer */
			memcpy (buffer + context->len, in_data,
				out_len - context->len);
			/* copy remaining data to context */
			memcpy(context->data, in_data + out_len - context->len,
				remain);
			context->len = remain;
		} else { /* case 2 - partial data */
			memcpy(buffer, context->data, AES_BLOCK_SIZE);
			memcpy(context->data, context->data + AES_BLOCK_SIZE,
			       context->len - AES_BLOCK_SIZE);
			memcpy(context->data + context->len - AES_BLOCK_SIZE,
			       in_data, in_data_len);
			context->len = context->len - AES_BLOCK_SIZE
				       + in_data_len;
		}

		rc = ica_aes_gcm_intermediate(out_data, (unsigned int)out_len,
					      buffer, ucb, auth_data,
					      (unsigned int)auth_data_len,
					      tag_data,
					      (unsigned int)tag_data_len,
					      attr->pValue,
					      (unsigned int)attr->ulValueLen,
					      subkey, 0);

	}

	if( rc != 0) {
		TRACE_ERROR("ica_aes_gcm_update failed with rc = 0x%lx.\n", rc);
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	(*out_data_len) = out_len;

	context->ulClen += out_len;

	/* AAD only processed in first update seuence,
	 * mark it empty for all subsequent calls
	 */
	context->ulAlen = 0;

done:
	if (buffer)
		free(buffer);

	return rc;
}

CK_RV token_specific_aes_gcm_final(STDLL_TokData_t *tokdata, SESSION *sess,
				   ENCR_DECR_CONTEXT *ctx, CK_BYTE *out_data,
				   CK_ULONG *out_data_len, CK_BYTE encrypt)
{
	CK_RV rc = CKR_OK;
	CK_ATTRIBUTE *attr = NULL;
	OBJECT *key = NULL;
	AES_GCM_CONTEXT  *context = NULL;
	CK_GCM_PARAMS *aes_gcm_param = NULL;
	CK_BYTE *icb, *ucb;
	CK_BYTE *tag_data, *subkey, *auth_data, *final_tag_data;
	CK_ULONG auth_data_len, tag_data_len;
	CK_BYTE *buffer = NULL;

	/* find key object */
	rc = object_mgr_find_in_map_nocache(ctx->key, &key);
	if(rc != CKR_OK) {
		TRACE_ERROR("Failed to find specified object.\n");
		return rc;
	}
	if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
		TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
		return CKR_FUNCTION_FAILED;
	}

	context = (AES_GCM_CONTEXT *)ctx->context;
	ucb = (CK_BYTE *)context->ucb;
	icb = (CK_BYTE *)context->icb;
	tag_data = context->hash;
	subkey = (CK_BYTE *)context->subkey;

	aes_gcm_param = (CK_GCM_PARAMS *)ctx->mech.pParameter;
	auth_data = (CK_BYTE *)aes_gcm_param->pAAD;
	auth_data_len = aes_gcm_param->ulAADLen;
	tag_data_len = (aes_gcm_param->ulTagBits + 7) / 8;

	if (encrypt) {
		if (context->len != 0) {
			buffer = (CK_BYTE*) malloc (AES_BLOCK_SIZE);
			if (!buffer) {
				TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
				return CKR_HOST_MEMORY;
			}
			memcpy(buffer, context->data, context->len);

			rc = ica_aes_gcm_intermediate(buffer, context->len,
						 out_data, ucb, auth_data,
						 context->ulAlen, tag_data,
						 AES_BLOCK_SIZE, attr->pValue,
						 (unsigned int)attr->ulValueLen,
						 subkey, 1);

			if (rc != 0) {
				TRACE_ERROR("ica_aes_gcm_intermediate() "
					    "failed to encrypt\n");
				rc = CKR_FUNCTION_FAILED;
				goto done;
			}

			context->ulClen += context->len;
			*out_data_len = context->len + tag_data_len;
		} else
			*out_data_len = tag_data_len;

		TRACE_DEVEL("GCM Final: context->len=%ld, tag_data_len=%ld, out_data_len=%ld\n",
			    context->len, tag_data_len, *out_data_len);

		rc = ica_aes_gcm_last(icb, (unsigned int)auth_data_len,
				      (unsigned int)context->ulClen, tag_data,
				      NULL, 0, attr->pValue,
				      (unsigned int) attr->ulValueLen,
				      subkey, 1);

		if (rc != 0) {
			TRACE_ERROR("ica_aes_gcm_final failed with rc = 0x%lx.\n", rc);
			rc = CKR_FUNCTION_FAILED;
			goto done;
		}

		memcpy(out_data + context->len, tag_data, tag_data_len);
	} else {
		/* decrypt */

		if (context->len > tag_data_len) {
			buffer = (CK_BYTE*) malloc(AES_BLOCK_SIZE);
			if (!buffer) {
				TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
				rc = CKR_HOST_MEMORY;
				goto done;
			}
			memcpy(buffer, context->data,
			       context->len - tag_data_len);

			rc = ica_aes_gcm_intermediate(out_data,
					(unsigned int)context->len-tag_data_len,
					buffer, ucb, auth_data,
					(unsigned int)context->ulAlen, tag_data,
					AES_BLOCK_SIZE, attr->pValue,
					(unsigned int) attr->ulValueLen,
					subkey, 0);

			if (rc != 0) {
				TRACE_ERROR("ica_aes_gcm_intermediate() "
					    "failed to decrypt.\n");
				rc = CKR_FUNCTION_FAILED;
				goto done;
			}
			(*out_data_len) = context->len - tag_data_len;
			context->ulClen += context->len - tag_data_len;

		} else if (context->len == tag_data_len) {
			/* remaining data are tag data */
			*out_data_len = 0;
		} else { /* (context->len < tag_data_len) */
			TRACE_ERROR("Incoming data are not consistent.\n");
			rc = CKR_DATA_INVALID;
			goto done;
		}

		final_tag_data = context->data + context->len - tag_data_len;

		rc = ica_aes_gcm_last(icb, aes_gcm_param->ulAADLen,
				      context->ulClen, tag_data, final_tag_data,
				      tag_data_len, attr->pValue,
				      (unsigned int)attr->ulValueLen, subkey,
				      0);
		if (rc != 0) {
			TRACE_ERROR("ica_aes_gcm_final failed with rc = 0x%lx.\n", rc);
			rc = CKR_FUNCTION_FAILED;
		}
	}

done:
	if (buffer)
		free(buffer);

	return rc;
}

/**
 * In libica for AES-OFB Mode it uses one function for both encrypt and decrypt
 * The variable direction is used as an indicator either for encrypt or decrypt
 * 0 -- Decrypt
 * 1 -- Encrypt
 */
CK_RV
token_specific_aes_ofb(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
		       CK_ULONG in_data_len, CK_BYTE *out_data, OBJECT *key,
		       CK_BYTE *init_v, uint_32 direction)
{
   CK_RV rc;
   CK_ATTRIBUTE *attr = NULL;

   if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
      TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
      return CKR_FUNCTION_FAILED;
   }

   rc = ica_aes_ofb(in_data, out_data, (unsigned long) in_data_len,
                    attr->pValue, (unsigned int) attr->ulValueLen,
		    init_v, direction);

   if (rc != 0) {
         TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
         rc = CKR_FUNCTION_FAILED;
   }
   return rc;
}

/**
 * In libica for AES-CFB Mode it uses one function for both encrypt and decrypt
 * The variable direction is used as an indicator either for encrypt or decrypt
 *  0 -- Decrypt
 *  1 -- Encrypt
 */
CK_RV
token_specific_aes_cfb(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
		       CK_ULONG in_data_len, CK_BYTE *out_data, OBJECT *key,
		       CK_BYTE *init_v, uint_32 lcfb, uint_32 direction)
{
   CK_RV rc;
   CK_ATTRIBUTE *attr = NULL;

   if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
      TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
      return CKR_FUNCTION_FAILED;
   }

   rc = ica_aes_cfb(in_data, out_data, (unsigned long) in_data_len,
                    attr->pValue, (unsigned int) attr->ulValueLen, init_v,
                    lcfb, direction);

   if (rc != 0) {
         TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
         rc = CKR_FUNCTION_FAILED;
   }
   return rc;
}

CK_RV
token_specific_aes_mac(STDLL_TokData_t *tokdata, CK_BYTE *message,
		       CK_ULONG message_len, OBJECT *key, CK_BYTE *mac)
{
   CK_RV rc;
   CK_ATTRIBUTE *attr = NULL;

   if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
      TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
      return CKR_FUNCTION_FAILED;
   }

   rc = ica_aes_cmac_intermediate(message, (unsigned long) message_len,
                   attr->pValue, (unsigned int) attr->ulValueLen, mac);

   if (rc != 0) {
         TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
         rc = CKR_FUNCTION_FAILED;
   }
   return rc;
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
	     TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
	     return CKR_HOST_MEMORY;
     }

     BN_init(bn_y) ;
     BN_init(bn_x) ;
     BN_init(bn_p) ;

     // Initialize context
     ctx=BN_CTX_new();
     if (ctx == NULL)
     {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
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

        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
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
	TRACE_ERROR("Could not find CKA_PRIME or CKA_BASE for the key.\n");
        return CKR_FUNCTION_FAILED;
    }

    if ((prime_attr->ulValueLen > 256) || (prime_attr->ulValueLen < 64))
    {
	TRACE_ERROR("CKA_PRIME attribute value is invalid.\n");
	return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    dh = DH_new() ;
    if (dh == NULL)
    {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    // Create and init BIGNUM structs to stick in the DH struct
    bn_p = BN_new();
    bn_g = BN_new();
    if (bn_g == NULL || bn_p == NULL) {
	if (bn_g) BN_free(bn_g);
	if (bn_p) BN_free(bn_p);
	TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
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
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
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
        TRACE_DEVEL("build_attribute failed\n");
        return rc;
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
        TRACE_DEVEL("build_attribute failed\n");
        return rc;
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
        TRACE_DEVEL("build_attribute failed\n");
        return rc;
    }
    template_update_attribute( priv_tmpl, temp_attr );

    rc = build_attribute( CKA_BASE,(char *)base_attr->pValue,
                          base_attr->ulValueLen, &temp_attr ); // in bytes
    if (rc != CKR_OK)
    {
        TRACE_DEVEL("build_attribute failed\n");
        return rc;
    }
    template_update_attribute( priv_tmpl, temp_attr );

    // Cleanup DH key
    DH_free(dh) ;

    return CKR_OK ;

} /* end token_specific_dh_key_pair_gen() */

#endif /* #ifndef NODH */

REF_MECH_LIST_ELEMENT ref_mech_list[] = {

	{92, CKM_RSA_PKCS_KEY_PAIR_GEN,
	 {512, 4096, CKF_HW|CKF_GENERATE_KEY_PAIR}},
#if !(NODSA)
//	{1, CKM_DSA_KEY_PAIR_GEN, {512, 1024, CKF_HW|CKF_GENERATE_KEY_PAIR}},
#endif
#if !(NOCDMF)
//	{4, CKM_CDMF_KEY_GEN, {0, 0, CKF_HW|CKF_GENERATE}},
#endif
	{80, CKM_DES_KEY_GEN, {8, 8, CKF_HW|CKF_GENERATE}},

	{80, CKM_DES3_KEY_GEN, {24, 24, CKF_HW|CKF_GENERATE}},

	{90, CKM_RSA_PKCS,
	 {512, 4096, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|CKF_UNWRAP|
	  CKF_SIGN|CKF_VERIFY|CKF_SIGN_RECOVER|CKF_VERIFY_RECOVER}},

#if !(NOX509)
	{90, CKM_RSA_X_509,
	 {512, 4096, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|CKF_UNWRAP|
	  CKF_SIGN|CKF_VERIFY|CKF_SIGN_RECOVER|CKF_VERIFY_RECOVER}},
#endif
	{90, CKM_RSA_PKCS_OAEP,
	 {512, 4096, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|CKF_UNWRAP}},

	{90, CKM_RSA_PKCS_PSS, {512, 4096, CKF_HW|CKF_SIGN|CKF_VERIFY}},

	{107, CKM_MD2_RSA_PKCS, {512, 4096, CKF_HW|CKF_SIGN|CKF_VERIFY}},

	{108, CKM_MD5_RSA_PKCS, {512, 4096, CKF_HW|CKF_SIGN|CKF_VERIFY}},

	{190, CKM_SHA1_RSA_PKCS, {512, 4096, CKF_HW|CKF_SIGN|CKF_VERIFY}},

	{190, CKM_SHA256_RSA_PKCS, {512, 4096, CKF_HW|CKF_SIGN|CKF_VERIFY}},

	{190, CKM_SHA384_RSA_PKCS, {512, 4096, CKF_HW|CKF_SIGN|CKF_VERIFY}},

	{190, CKM_SHA512_RSA_PKCS, {512, 4096, CKF_HW|CKF_SIGN|CKF_VERIFY}},

	{20, CKM_DES_ECB,
	 {8, 8, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|CKF_UNWRAP}},

	{21, CKM_DES_CBC,
	 {8, 8, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT| CKF_WRAP|CKF_UNWRAP}},

	{21, CKM_DES_CBC_PAD,
	 {8, 8, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|CKF_UNWRAP}},

	{41, CKM_DES3_ECB,
	 {24, 24, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|CKF_UNWRAP}},

	{42, CKM_DES3_CBC,
	 {24, 24, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|CKF_UNWRAP}},

	{42, CKM_DES3_CBC_PAD,
	 {24, 24, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|CKF_UNWRAP}},

	{49, CKM_DES3_MAC, {24, 24, CKF_HW|CKF_SIGN|CKF_VERIFY}},

	{49, CKM_DES3_MAC_GENERAL, {24, 24, CKF_HW|CKF_SIGN|CKF_VERIFY}},

	{24, CKM_DES_CFB8, {8, 8, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT}},

	{44, CKM_DES_OFB64, {8, 8, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT}},

	{45, CKM_DES_CFB64, {8, 8, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT}},

	{01, CKM_SHA_1, {0, 0, CKF_HW|CKF_DIGEST}},

	{01, CKM_SHA_1_HMAC, {0, 0, CKF_HW|CKF_SIGN|CKF_VERIFY}},

	{01, CKM_SHA_1_HMAC_GENERAL, {0, 0, CKF_HW|CKF_SIGN|CKF_VERIFY}},

	{03, CKM_SHA256, {0, 0, CKF_HW|CKF_DIGEST}},

	{03, CKM_SHA256_HMAC, {0, 0, CKF_HW|CKF_SIGN|CKF_VERIFY}},

	{03, CKM_SHA256_HMAC_GENERAL, {0, 0, CKF_HW|CKF_SIGN|CKF_VERIFY}},

	{04, CKM_SHA384, {0, 0, CKF_HW|CKF_DIGEST}},

	{04, CKM_SHA384_HMAC, {0, 0, CKF_HW|CKF_SIGN|CKF_VERIFY}},

	{04, CKM_SHA384_HMAC_GENERAL, {0, 0, CKF_HW|CKF_SIGN|CKF_VERIFY}},

	{05, CKM_SHA512, {0, 0, CKF_HW|CKF_DIGEST}},

	{05, CKM_SHA512_HMAC, {0, 0, CKF_HW|CKF_SIGN|CKF_VERIFY}},

	{05, CKM_SHA512_HMAC_GENERAL, {0, 0, CKF_HW|CKF_SIGN|CKF_VERIFY}},

#if !(NOMD5)
	{53, CKM_MD5, {0, 0, CKF_HW|CKF_DIGEST}},

	{54, CKM_MD5_HMAC, {0, 0, CKF_HW|CKF_SIGN|CKF_VERIFY}},

	{55, CKM_MD5_HMAC_GENERAL, {0, 0, CKF_HW|CKF_SIGN|CKF_VERIFY}},
#endif
#if !(NOAES)
	{80, CKM_AES_KEY_GEN, {16, 32, CKF_HW|CKF_GENERATE}},

	{60, CKM_AES_ECB,
	 {16, 32, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|CKF_UNWRAP}},

	{61, CKM_AES_CBC,
	 {16, 32, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|CKF_UNWRAP}},

	{61, CKM_AES_CBC_PAD,
	 {16, 32, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|CKF_UNWRAP}},

	{63, CKM_AES_OFB,
	 {16, 32, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|CKF_UNWRAP}},

	{64, CKM_AES_CFB8,
	 {16, 32, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP| CKF_UNWRAP}},

	{64, CKM_AES_CFB64,
	 {16, 32, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|CKF_UNWRAP}},

	{64, CKM_AES_CFB128,
	 {16, 32, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|CKF_UNWRAP}},

	{65, CKM_AES_CTR,
	 {16, 32, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|CKF_UNWRAP}},

	{70, CKM_AES_GCM, {16, 32, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT}},

	{68, CKM_AES_MAC, {16, 32, CKF_HW|CKF_SIGN|CKF_VERIFY}},

	{68, CKM_AES_MAC_GENERAL, {16, 32, CKF_HW|CKF_SIGN|CKF_VERIFY}},
#endif
        {80, CKM_GENERIC_SECRET_KEY_GEN, {80, 2048, CKF_HW|CKF_GENERATE}},
};

CK_ULONG ref_mech_list_len = (sizeof(ref_mech_list) / sizeof(REF_MECH_LIST_ELEMENT));

/**
 * new ica-token mechanism table
 * this list will be initialized the first time
 * when ica_get_functionlist (from libica) is called.
 * (preinitialized with software only supported mechanisms)
 */
MECH_LIST_ELEMENT mech_list[] = {
	{CKM_MD5, {0, 0, CKF_DIGEST}},
	{CKM_MD5_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
	{CKM_MD5_HMAC_GENERAL, {0, 0, CKF_SIGN | CKF_VERIFY}},
	{0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}},
	{0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}},
	{0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}},
	{0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}},
	{0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}},
	{0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}},
	{0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}},
	{0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}},
	{0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}},
	{0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}},
	{0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}},
	{0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}}, {0,{0,0,0}} };

CK_ULONG mech_list_len = 3;

CK_RV
token_specific_get_mechanism_list(STDLL_TokData_t *tokdata,
				  CK_MECHANISM_TYPE_PTR pMechanismList,
				  CK_ULONG_PTR pulCount)
{
	CK_ULONG rc = CKR_OK;

	rc = ica_specific_get_mechanism_list(pMechanismList, pulCount);
	if (rc != CKR_OK) {
		return CKR_FUNCTION_FAILED;
	}

	return rc;
}

CK_RV
ica_specific_get_mechanism_list(CK_MECHANISM_TYPE_PTR pMechanismList,
				CK_ULONG_PTR pulCount)
{
	unsigned int i;

	if (pulCount == NULL) {
		return CKR_ARGUMENTS_BAD;
	}

	if (pMechanismList == NULL) {
		*pulCount = mech_list_len;
		return CKR_OK;
	}

	if ((*pulCount) < mech_list_len) {
		(*pulCount) = mech_list_len;
		TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
		return CKR_BUFFER_TOO_SMALL;
	}

	/* copy mechanisms from the internal mech_ica_list */
	for (i=0; i < mech_list_len; i++) {
		pMechanismList[i] = mech_list[i].mech_type;
	}
	(*pulCount) = mech_list_len;

	return CKR_OK;
}

CK_RV
token_specific_get_mechanism_info(STDLL_TokData_t *tokdata,
				  CK_MECHANISM_TYPE type,
				  CK_MECHANISM_INFO_PTR pInfo)
{
	CK_ULONG rc = CKR_OK;

	rc = ica_specific_get_mechanism_info(type, pInfo);
	return rc;
}

CK_RV ica_specific_get_mechanism_info (CK_MECHANISM_TYPE type,
				       CK_MECHANISM_INFO_PTR pInfo)
{
	unsigned int i;

	/*
	 * find the requested mechanism and grab additional
	 * mechanism specific information (mech_info) from mech_list_ica
	 */
	for (i=0; i < mech_list_len; i++) {
		if (mech_list[i].mech_type == type) {
			pInfo->flags = mech_list[i].mech_info.flags;
			pInfo->ulMinKeySize = mech_list[i].mech_info.ulMinKeySize;
			pInfo->ulMaxKeySize = mech_list[i].mech_info.ulMaxKeySize;
			return CKR_OK;
		}
	}

	TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
	return CKR_MECHANISM_INVALID;
}

CK_RV
getRefListIdxfromId(CK_ULONG ica_idx, CK_ULONG_PTR pRefIdx)
{
	unsigned int n;

	for (n=*pRefIdx; n < ref_mech_list_len; n++) {
		if (ica_idx == ref_mech_list[n].lica_idx) {
			*pRefIdx =  n;
			return CKR_OK;
		}
	}
	return CKR_MECHANISM_INVALID;
}

CK_RV
getRefListIdxfromMech(CK_ULONG mech, CK_ULONG_PTR pRefIdx)
{
	unsigned int n;

	for (n=*pRefIdx; n < ref_mech_list_len; n++) {
		if (mech == ref_mech_list[n].mech_type) {
			*pRefIdx =  n;
			return CKR_OK;
		}
	}
	return CKR_MECHANISM_INVALID;
}

CK_BBOOL
isMechanismAvailable(CK_ULONG mechanism)
{
	unsigned int i;

	for (i = 0; i < mech_list_len; i++) {
		if (mech_list[i].mech_type == mechanism)
			return TRUE;
	}
	return FALSE;
}

CK_RV
addMechanismToList(CK_ULONG mechanism)
{
	CK_ULONG ret;
	CK_ULONG refIdx = 0;

	ret = getRefListIdxfromMech(mechanism, &refIdx);
	if (ret != CKR_OK) {
		return CKR_FUNCTION_FAILED;
	}
	mech_list[mech_list_len].mech_type  = ref_mech_list[refIdx].mech_type;
	mech_list[mech_list_len].mech_info.flags = (ref_mech_list[refIdx].mech_info.flags & 0xfffffffe);
	mech_list[mech_list_len].mech_info.ulMinKeySize = ref_mech_list[refIdx].mech_info.ulMinKeySize;
	mech_list[mech_list_len].mech_info.ulMaxKeySize = ref_mech_list[refIdx].mech_info.ulMaxKeySize;
	mech_list_len++;

	return CKR_OK;
}

/*
 * call libica to receive list of supported mechanisms
 * This method is called once per opencryptoki instance (application context)
 */
CK_RV
mech_list_ica_initialize(void)
{
	CK_ULONG ret, rc = CKR_OK;
	unsigned int i, n;
	unsigned int ica_specific_mech_list_len;
	CK_ULONG tmp, ulActMechCtr, ulPreDefMechCtr, refIdx;

	rc = ica_get_functionlist(NULL, &ica_specific_mech_list_len);
	if (rc != CKR_OK) {
		TRACE_ERROR("ica_get_functionlist failed\n");
		return CKR_FUNCTION_FAILED;
	}
	libica_func_list_element libica_func_list[ica_specific_mech_list_len];
	rc = ica_get_functionlist(libica_func_list, &ica_specific_mech_list_len);
	if (rc != CKR_OK) {
		TRACE_ERROR("ica_get_functionlist failed\n");
		return CKR_FUNCTION_FAILED;
	}

	/*
	 * grab the mechanism of the corresponding ID returned by libICA
	 * from the internel reference list put the mechanism ID and the
	 * HW support indication into an internel ica_mech_list and get
	 * additional flag information from the reference list
	 */
	ulPreDefMechCtr = mech_list_len;
	for (i=0; i < ica_specific_mech_list_len; i++) {

		if (libica_func_list[i].flags == 0)
			continue;

		// loop over libica supported list
		ulActMechCtr = -1;

		/* --- walk through the whole reflist and fetch all
		 * matching mechanism's (if present) ---
		 */
		refIdx = 0;
		while (refIdx >= 0) {
			ret = getRefListIdxfromId(libica_func_list[i].mech_mode_id, &refIdx);
			if (ret != CKR_OK) {
				// continue with the next libica mechanism
				break;
			}

			/* Loop over the predefined mechanism list and check
			 * if we have to overrule a software implemented
			 * mechanism from token by libica HW supported
			 * mechanism.
			 */
			for (n=0; n < ulPreDefMechCtr; n++) {
				if (mech_list[n].mech_type == ref_mech_list[refIdx].mech_type){
					ulActMechCtr = n;
					break;
				}
			}
			if (ulActMechCtr == -1) {
				/* add a new entry */
				mech_list[mech_list_len].mech_type  = ref_mech_list[refIdx].mech_type;
				mech_list[mech_list_len].mech_info.flags = (libica_func_list[i].flags & 0x01) | (ref_mech_list[refIdx].mech_info.flags & 0xfffffffe);
				mech_list[mech_list_len].mech_info.ulMinKeySize = ref_mech_list[refIdx].mech_info.ulMinKeySize;
				mech_list[mech_list_len].mech_info.ulMaxKeySize = ref_mech_list[refIdx].mech_info.ulMaxKeySize;
				mech_list_len++;
			} else {
				/* replace existing entry */
				mech_list[ulActMechCtr].mech_info.flags = (libica_func_list[i].flags & 0x01) | mech_list[ulActMechCtr].mech_info.flags ;
			}
			refIdx++;
		}
	}

	/*
	 * check if special combined mechanisms are supported
	 * if SHA1 and RSA is available   -> insert CKM_SHA1_RSA_PKCS
	 * if SHA256 and RSA is available -> insert CKM_SHA256_RSA_PKCS
	 * if MD2 and RSA is available    -> insert CKM_MD2_RSA_PKCS
	 * if MD5 and RSA is available    -> insert CKM_MD5_RSA_PKCS
	 */
	if (isMechanismAvailable(CKM_SHA_1) && isMechanismAvailable(CKM_RSA_PKCS))
		addMechanismToList(CKM_SHA1_RSA_PKCS);
	if (isMechanismAvailable(CKM_SHA256) && isMechanismAvailable(CKM_RSA_PKCS))
		addMechanismToList(CKM_SHA256_RSA_PKCS);
	if (isMechanismAvailable(CKM_SHA384) && isMechanismAvailable(CKM_RSA_PKCS))
		addMechanismToList(CKM_SHA384_RSA_PKCS);
	if (isMechanismAvailable(CKM_SHA512) && isMechanismAvailable(CKM_RSA_PKCS))
		addMechanismToList(CKM_SHA512_RSA_PKCS);
	if (isMechanismAvailable(CKM_MD2) && isMechanismAvailable(CKM_RSA_PKCS))
		addMechanismToList(CKM_MD2_RSA_PKCS);
	if (isMechanismAvailable(CKM_MD5) && isMechanismAvailable(CKM_RSA_PKCS))
		addMechanismToList(CKM_MD5_RSA_PKCS);

	/* sort the mech_list_ica by mechanism ID's (bubble sort)  */
	for(i=0;i < mech_list_len ; i++) {
		for (n=i; n < mech_list_len; n++) {
			if (mech_list[i].mech_type > mech_list[n].mech_type) {
				tmp = mech_list[i].mech_type;
				mech_list[i].mech_type = mech_list[n].mech_type;
				mech_list[n].mech_type = tmp;

				tmp = mech_list[i].mech_info.ulMinKeySize;
				mech_list[i].mech_info.ulMinKeySize = mech_list[n].mech_info.ulMinKeySize;
				mech_list[n].mech_info.ulMinKeySize = tmp;

				tmp = mech_list[i].mech_info.ulMaxKeySize;
				mech_list[i].mech_info.ulMaxKeySize = mech_list[n].mech_info.ulMaxKeySize;
				mech_list[n].mech_info.ulMaxKeySize = tmp;

				tmp = mech_list[i].mech_info.flags;
				mech_list[i].mech_info.flags = mech_list[n].mech_info.flags;
				mech_list[n].mech_info.flags = tmp;
			}
		}
	}
	mech_list_ica_init = TRUE;
	return rc;
}

CK_RV token_specific_generic_secret_key_gen(STDLL_TokData_t *tokdata, TEMPLATE *tmpl)
{
	CK_ATTRIBUTE *attr = NULL;
	CK_RV rc = CKR_OK;
	CK_BYTE secret_key[MAX_GENERIC_KEY_SIZE];
	CK_ULONG key_length = 0;
	CK_ULONG key_length_in_bits = 0;
	CK_ATTRIBUTE *value_attr = NULL;

	rc = template_attribute_find(tmpl, CKA_VALUE_LEN, &attr);
	if (rc == FALSE) {
		TRACE_ERROR("CKA_VALUE_LEM missing in key template\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	key_length = *(CK_ULONG *)attr->pValue; //app specified key length in bytes
	key_length_in_bits = key_length * 8;

	/* After looking at fips cavs test vectors for HMAC ops,
	 * it was decided that the key length should fall between
	 * 80 and 2048 bits inclusive.
	 */
	if ((key_length_in_bits < 80) || (key_length_in_bits > 2048 )) {
		TRACE_ERROR("Generic secret key size of %lu bits not within"
			    " required range of 80-2048 bits\n", key_length_in_bits);
		return CKR_KEY_SIZE_RANGE;
	}

        /* libica does not have generic secret key generation,
	 * so call token rng here.
	 */
	rc = rng_generate(tokdata, secret_key, key_length);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Generic secret key generation failed.\n");
		return rc;
        }

	rc = build_attribute(CKA_VALUE, secret_key, key_length, &value_attr);
	if (rc != CKR_OK) {
		TRACE_DEVEL("build_attribute(CKA_VALUE) failed\n");
		return rc;
	}
	rc = template_update_attribute(tmpl, value_attr);
        if (rc != CKR_OK)
                TRACE_DEVEL("template_update_attribute(CKA_VALUE) failed\n");

        return rc;
}
