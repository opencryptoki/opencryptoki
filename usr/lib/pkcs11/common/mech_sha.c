/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  mech_sha.c
//
// Mechanisms for SHA-1 related routines
//
// The following applies to the software SHA implementation:
//    Written 2 September 1992, Peter C. Gutmann.
//    This implementation placed in the public domain.
//
//    Modified 1 June 1993, Colin Plumb.
//    Modified for the new SHS based on Peter Gutmann's work,
//    18 July 1994, Colin Plumb.
//    Gutmann's work.
//    Renamed to SHA and comments updated a bit 1 November 1995, Colin Plumb.
//    These modifications placed in the public domain.
//
//    Comments to pgut1@cs.aukuni.ac.nz
//

#include <pthread.h>
#include <string.h>            // for memcmp() et al
#include <stdlib.h>
#include <memory.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "trace.h"

#define SHA_HARDWARE_THRESHHOLD 128000

// The SHA f()-functions.  The f1 and f3 functions can be optimized to
// save one boolean operation each - thanks to Rich Schroeppel,
// rcs@cs.arizona.edu for discovering this
//
#define f1(x,y,z) (z ^ (x & (y ^ z)))        // Rounds  0-19
#define f2(x,y,z) (x ^ y ^ z)                // Rounds 20-39
#define f3(x,y,z) ((x & y) | (z & (x | y)))  // Rounds 40-59
#define f4(x,y,z) (x ^ y ^ z)                // Rounds 60-79

// The SHA Mysterious Constants.
// K1 = floor(sqrt(2)  * 2^30)
// K2 = floor(sqrt(3)  * 2^30)
// K3 = floor(sqrt(5)  * 2^30)
// K4 = floor(sqrt(10) * 2^30)
//
#define K1  0x5A827999L // Rounds  0-19
#define K2  0x6ED9EBA1L // Rounds 20-39
#define K3  0x8F1BBCDCL // Rounds 40-59
#define K4  0xCA62C1D6L // Rounds 60-79

// SHA initial values
//
#define h0init 0x67452301
#define h1init 0xEFCDAB89
#define h2init 0x98BADCFE
#define h3init 0x10325476
#define h4init 0xC3D2E1F0

//
// Note that it may be necessary to add parentheses to these macros
// if they are to be called with expressions as arguments.
//

// 32-bit rotate left - kludged with shifts
//

#define ROTL(n,X)  ((X << n) | (X >> (32-n)))

// The initial expanding function
//
// The hash function is defined over an 80-word expanded input array W,
// where the first 16 are copies of the input data, and the remaining 64
// are defined by W[i] = W[i-16] ^ W[i-14] ^ W[i-8] ^ W[i-3].  This
// implementation generates these values on the fly in a circular buffer.
//

#define expand(W,i) \
   (W[i&15] ^= W[(i-14)&15] ^ W[(i-8)&15] ^ W[(i-3)&15], W[i&15] = ROTL(1, W[i&15]))

// The prototype SHA sub-round
//
// The fundamental sub-round is
// a' = e + ROTL(5,a) + f(b, c, d) + k + data;
// b' = a;
// c' = ROTL(30,b);
// d' = c;
// e' = d;
// ... but this is implemented by unrolling the loop 5 times and renaming
// the variables (e,a,b,c,d) = (a',b',c',d',e') each iteration.
//
#define subRound(a, b, c, d, e, f, k, data)  \
   (e += ROTL(5,a) + f(b, c, d) + k + data, b = ROTL(30, b))

/*
 * Perform the SHA transformation.  Note that this code, like MD5, seems to
 * break some optimizing compilers due to the complexity of the expressions
 * and the size of the basic block.  It may be necessary to split it into
 * sections, e.g. based on the four subrounds
 *
 * Note that this corrupts the sha->data area
 */
void shaTransform(SHA1_CONTEXT *ctx)
{
	register unsigned int A, B, C, D, E;

	// Set up first buffer
	//
	A = ctx->hash_value[0];
	B = ctx->hash_value[1];
	C = ctx->hash_value[2];
	D = ctx->hash_value[3];
	E = ctx->hash_value[4];

	// Heavy mangling, in 4 sub-rounds of 20 interations each.
	//
	subRound(A, B, C, D, E, f1, K1, ctx->buf[ 0]);
	subRound(E, A, B, C, D, f1, K1, ctx->buf[ 1]);
	subRound(D, E, A, B, C, f1, K1, ctx->buf[ 2]);
	subRound(C, D, E, A, B, f1, K1, ctx->buf[ 3]);
	subRound(B, C, D, E, A, f1, K1, ctx->buf[ 4]);
	subRound(A, B, C, D, E, f1, K1, ctx->buf[ 5]);
	subRound(E, A, B, C, D, f1, K1, ctx->buf[ 6]);
	subRound(D, E, A, B, C, f1, K1, ctx->buf[ 7]);
	subRound(C, D, E, A, B, f1, K1, ctx->buf[ 8]);
	subRound(B, C, D, E, A, f1, K1, ctx->buf[ 9]);
	subRound(A, B, C, D, E, f1, K1, ctx->buf[10]);
	subRound(E, A, B, C, D, f1, K1, ctx->buf[11]);
	subRound(D, E, A, B, C, f1, K1, ctx->buf[12]);
	subRound(C, D, E, A, B, f1, K1, ctx->buf[13]);
	subRound(B, C, D, E, A, f1, K1, ctx->buf[14]);
	subRound(A, B, C, D, E, f1, K1, ctx->buf[15]);
	subRound(E, A, B, C, D, f1, K1, expand(ctx->buf, 16));
	subRound(D, E, A, B, C, f1, K1, expand(ctx->buf, 17));
	subRound(C, D, E, A, B, f1, K1, expand(ctx->buf, 18));
	subRound(B, C, D, E, A, f1, K1, expand(ctx->buf, 19));

	subRound(A, B, C, D, E, f2, K2, expand(ctx->buf, 20));
	subRound(E, A, B, C, D, f2, K2, expand(ctx->buf, 21));
	subRound(D, E, A, B, C, f2, K2, expand(ctx->buf, 22));
	subRound(C, D, E, A, B, f2, K2, expand(ctx->buf, 23));
	subRound(B, C, D, E, A, f2, K2, expand(ctx->buf, 24));
	subRound(A, B, C, D, E, f2, K2, expand(ctx->buf, 25));
	subRound(E, A, B, C, D, f2, K2, expand(ctx->buf, 26));
	subRound(D, E, A, B, C, f2, K2, expand(ctx->buf, 27));
	subRound(C, D, E, A, B, f2, K2, expand(ctx->buf, 28));
	subRound(B, C, D, E, A, f2, K2, expand(ctx->buf, 29));
	subRound(A, B, C, D, E, f2, K2, expand(ctx->buf, 30));
	subRound(E, A, B, C, D, f2, K2, expand(ctx->buf, 31));
	subRound(D, E, A, B, C, f2, K2, expand(ctx->buf, 32));
	subRound(C, D, E, A, B, f2, K2, expand(ctx->buf, 33));
	subRound(B, C, D, E, A, f2, K2, expand(ctx->buf, 34));
	subRound(A, B, C, D, E, f2, K2, expand(ctx->buf, 35));
	subRound(E, A, B, C, D, f2, K2, expand(ctx->buf, 36));
	subRound(D, E, A, B, C, f2, K2, expand(ctx->buf, 37));
	subRound(C, D, E, A, B, f2, K2, expand(ctx->buf, 38));
	subRound(B, C, D, E, A, f2, K2, expand(ctx->buf, 39));

	subRound(A, B, C, D, E, f3, K3, expand(ctx->buf, 40));
	subRound(E, A, B, C, D, f3, K3, expand(ctx->buf, 41));
	subRound(D, E, A, B, C, f3, K3, expand(ctx->buf, 42));
	subRound(C, D, E, A, B, f3, K3, expand(ctx->buf, 43));
	subRound(B, C, D, E, A, f3, K3, expand(ctx->buf, 44));
	subRound(A, B, C, D, E, f3, K3, expand(ctx->buf, 45));
	subRound(E, A, B, C, D, f3, K3, expand(ctx->buf, 46));
	subRound(D, E, A, B, C, f3, K3, expand(ctx->buf, 47));
	subRound(C, D, E, A, B, f3, K3, expand(ctx->buf, 48));
	subRound(B, C, D, E, A, f3, K3, expand(ctx->buf, 49));
	subRound(A, B, C, D, E, f3, K3, expand(ctx->buf, 50));
	subRound(E, A, B, C, D, f3, K3, expand(ctx->buf, 51));
	subRound(D, E, A, B, C, f3, K3, expand(ctx->buf, 52));
	subRound(C, D, E, A, B, f3, K3, expand(ctx->buf, 53));
	subRound(B, C, D, E, A, f3, K3, expand(ctx->buf, 54));
	subRound(A, B, C, D, E, f3, K3, expand(ctx->buf, 55));
	subRound(E, A, B, C, D, f3, K3, expand(ctx->buf, 56));
	subRound(D, E, A, B, C, f3, K3, expand(ctx->buf, 57));
	subRound(C, D, E, A, B, f3, K3, expand(ctx->buf, 58));
	subRound(B, C, D, E, A, f3, K3, expand(ctx->buf, 59));

	subRound(A, B, C, D, E, f4, K4, expand(ctx->buf, 60));
	subRound(E, A, B, C, D, f4, K4, expand(ctx->buf, 61));
	subRound(D, E, A, B, C, f4, K4, expand(ctx->buf, 62) );
	subRound(C, D, E, A, B, f4, K4, expand(ctx->buf, 63) );
	subRound(B, C, D, E, A, f4, K4, expand(ctx->buf, 64) );
	subRound(A, B, C, D, E, f4, K4, expand(ctx->buf, 65) );
	subRound(E, A, B, C, D, f4, K4, expand(ctx->buf, 66) );
	subRound(D, E, A, B, C, f4, K4, expand(ctx->buf, 67) );
	subRound(C, D, E, A, B, f4, K4, expand(ctx->buf, 68) );
	subRound(B, C, D, E, A, f4, K4, expand(ctx->buf, 69) );
	subRound(A, B, C, D, E, f4, K4, expand(ctx->buf, 70) );
	subRound(E, A, B, C, D, f4, K4, expand(ctx->buf, 71) );
	subRound(D, E, A, B, C, f4, K4, expand(ctx->buf, 72) );
	subRound(C, D, E, A, B, f4, K4, expand(ctx->buf, 73) );
	subRound(B, C, D, E, A, f4, K4, expand(ctx->buf, 74) );
	subRound(A, B, C, D, E, f4, K4, expand(ctx->buf, 75) );
	subRound(E, A, B, C, D, f4, K4, expand(ctx->buf, 76) );
	subRound(D, E, A, B, C, f4, K4, expand(ctx->buf, 77) );
	subRound(C, D, E, A, B, f4, K4, expand(ctx->buf, 78) );
	subRound(B, C, D, E, A, f4, K4, expand(ctx->buf, 79) );

	// Build message digest
	//
	ctx->hash_value[0] += A;
	ctx->hash_value[1] += B;
	ctx->hash_value[2] += C;
	ctx->hash_value[3] += D;
	ctx->hash_value[4] += E;
}

/*
* SHA is defined in big-endian form, so this converts the buffer from
* bytes to words, independent of the machine's native endianness.
*
* Assuming a consistent byte ordering for the machine, this also
* has the magic property of being self-inverse.  It is used as
* such.
*/
static void byteReverse(unsigned int *buffer, unsigned int byteCount)
{
#ifndef __BYTE_ORDER
#error  "Endianess MUST be defined"
#endif
#if  __BYTE_ORDER == __LITTLE_ENDIAN
	CK_ULONG value, val;

	byteCount /= sizeof(CK_ULONG_32);

	while (byteCount--) {
		val = *buffer;
		value = ((0x000000FF & val) << 24) |
			((0x0000FF00 & val) << 8 ) |
			((0x00FF0000 & val) >> 8 ) |
			((0xFF000000 & val) >> 24);

		*buffer++ = value;
	}
#endif

	/*
	 * JRM - this code gives funky results on Linux/Intel.
	 * I assume this is a GCC issue since regression tests passed on NT
	 *
	 * byteCount /= sizeof(CK_ULONG);
	 * while ( byteCount-- ) {
	 * 	value = (CK_ULONG)((unsigned)((CK_BYTE *)buffer)[0] << 8 |
	 *	    ((CK_BYTE *)buffer)[1]) << 16 |
	 *	    ((unsigned)((CK_BYTE *)buffer)[2] << 8 |
	 *	    ((CK_BYTE *)buffer)[3]);
	 * 	*buffer++ = value;
	 * }
	 */
}


void shaUpdate(SHA1_CONTEXT *ctx, CK_BYTE const *buffer, CK_ULONG count)
{
	CK_ULONG t;

	// Update bitcount
	//
	t = ctx->bits_lo;
	if ((ctx->bits_lo = t + count) < t)
		ctx->bits_hi++;   // Carry from low to high

	t &= 0x3f;  // Bytes already in ctx->buf

	// Handle any leading odd-sized chunks
	//
	if (t) {
		CK_BYTE *p = (CK_BYTE *)ctx->buf + t;

		t = 64-t;
		if (count < t) {
			memcpy(p, buffer, count);
			return;
		}
		memcpy(p, buffer, t);
		byteReverse(ctx->buf, SHA1_BLOCK_SIZE);
		shaTransform(ctx);
		buffer += t;
		count -= t;
	}

	// Process data in SHA1_BLOCK_SIZE chunks
	//
	while (count >= SHA1_BLOCK_SIZE) {
		memcpy(ctx->buf, buffer, SHA1_BLOCK_SIZE);
		byteReverse(ctx->buf, SHA1_BLOCK_SIZE);
		shaTransform(ctx);
		buffer += SHA1_BLOCK_SIZE;
		count -= SHA1_BLOCK_SIZE;
	}

	// Handle any remaining bytes of data.
	//
	memcpy(ctx->buf, buffer, count);
}


/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
void shaFinal(SHA1_CONTEXT *ctx, CK_BYTE *hash)
{
	int count;
	CK_BYTE *p;

	// Compute number of bytes mod 64
	//
	count = (int)ctx->bits_lo & 0x3F;

	// Set the first char of padding to 0x80.
	// This is safe since there is always at least one byte free
	//
	p = (CK_BYTE *)ctx->buf + count;
	*p++ = 0x80;

	// Bytes of padding needed to make 64 bytes
	//
	count = SHA1_BLOCK_SIZE - 1 - count;

	// Pad out to 56 mod 64
	//
	if (count < 8) {
		// Two lots of padding:  Pad the first block to 64 bytes
		//
		memset(p, 0, count);
		byteReverse(ctx->buf, SHA1_BLOCK_SIZE);
		shaTransform(ctx);

		// Now fill the next block with 56 bytes
		//
		memset(ctx->buf, 0, SHA1_BLOCK_SIZE-8);
	} else {
		// Pad block to 56 bytes
		//
		memset(p, 0, count-8);
	}
	byteReverse(ctx->buf, SHA1_BLOCK_SIZE-8);

	// Append length in *bits* and transform
	//
	ctx->buf[14] = ctx->bits_hi << 3 | ctx->bits_lo >> 29;
	ctx->buf[15] = ctx->bits_lo << 3;

	shaTransform(ctx);

	// Store output hash in buffer
	//
	byteReverse(ctx->hash_value, SHA1_HASH_SIZE);
	memcpy(hash, ctx->hash_value, SHA1_HASH_SIZE);
}

//
// Software SHA-1 implementation
//

void sw_sha1_init(DIGEST_CONTEXT *ctx)
{
	// Set the h-vars to their initial values
	SHA1_CONTEXT *sha1_ctx;
	/* Allocate the context */
	ctx->context_len = sizeof(SHA1_CONTEXT);
	ctx->context = (CK_BYTE *)malloc(sizeof(SHA1_CONTEXT));
	if (ctx->context == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		// TODO: propagate error up?
		return;
	}

	sha1_ctx = (SHA1_CONTEXT *)ctx->context;
	sha1_ctx->hash_value[0]  = h0init;
	sha1_ctx->hash_value[1]  = h1init;
	sha1_ctx->hash_value[2]  = h2init;
	sha1_ctx->hash_value[3]  = h3init;
	sha1_ctx->hash_value[4]  = h4init;

	// Initialise bit count
 	sha1_ctx->bits_lo = sha1_ctx->bits_hi = 0;
}

CK_RV sw_sha1_hash(DIGEST_CONTEXT *ctx, CK_BYTE *in_data, CK_ULONG in_data_len,
		   CK_BYTE *out_data, CK_ULONG *out_data_len)
{

	if (!ctx || !out_data_len) {
		TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	if (*out_data_len < SHA1_HASH_SIZE) {
		TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
		return CKR_BUFFER_TOO_SMALL;
	}

	if (ctx->context == NULL)
		return CKR_HOST_MEMORY;

	shaUpdate((SHA1_CONTEXT *)ctx->context, in_data, in_data_len);
	shaFinal((SHA1_CONTEXT *)ctx->context, out_data);
	*out_data_len = SHA1_HASH_SIZE;
	return CKR_OK;
}

CK_RV sha_hash(STDLL_TokData_t *tokdata, SESSION *sess, CK_BBOOL length_only,
	       DIGEST_CONTEXT *ctx, CK_BYTE *in_data, CK_ULONG in_data_len,
	       CK_BYTE *out_data, CK_ULONG *out_data_len)
{
	CK_ULONG hsize;

	if (!ctx || !out_data_len) {
		TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	switch(ctx->mech.mechanism) {
	case CKM_SHA_1:
		hsize = SHA1_HASH_SIZE;
		break;
	case CKM_SHA256:
		hsize = SHA2_HASH_SIZE;
		break;
	case CKM_SHA384:
		hsize = SHA3_HASH_SIZE;
		break;
	case CKM_SHA512:
		hsize = SHA5_HASH_SIZE;
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}

	if (length_only == TRUE) {
		*out_data_len = hsize;
		return CKR_OK;
	}

	if (*out_data_len < hsize) {
		TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
		return CKR_BUFFER_TOO_SMALL;
	}

	if (ctx->context == NULL)
		return CKR_HOST_MEMORY;

	if (token_specific.t_sha != NULL)
		return token_specific.t_sha(tokdata, ctx, in_data, in_data_len,
					    out_data, out_data_len);
	else {
		if (ctx->mech.mechanism == CKM_SHA_1)
			return sw_sha1_hash(ctx, in_data, in_data_len, out_data,
					    out_data_len);
		else
			return CKR_MECHANISM_INVALID;
	}
}

//
//
CK_RV sha_hash_update(STDLL_TokData_t *tokdata, SESSION *sess,
		      DIGEST_CONTEXT *ctx, CK_BYTE *in_data,
		      CK_ULONG in_data_len)
{
	/* if no data to hash, just return */
	if (!in_data_len)
		return CKR_OK;

	if (token_specific.t_sha_update != NULL)
		return token_specific.t_sha_update(tokdata, ctx, in_data,
						   in_data_len);
	else {
		if (ctx->mech.mechanism == CKM_SHA_1) {
			shaUpdate((SHA1_CONTEXT *)ctx->context, in_data,
				  in_data_len);
			return CKR_OK;
		} else
			return CKR_MECHANISM_INVALID;
	}
}

CK_RV sha_hash_final(STDLL_TokData_t *tokdata, SESSION *sess,
		     CK_BYTE length_only, DIGEST_CONTEXT *ctx,
		     CK_BYTE *out_data, CK_ULONG *out_data_len)
{
	CK_ULONG hsize;

	if (!out_data_len) {
		TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	switch(ctx->mech.mechanism) {
	case CKM_SHA_1:
		hsize = SHA1_HASH_SIZE;
		break;
	case CKM_SHA256:
		hsize = SHA2_HASH_SIZE;
		break;
	case CKM_SHA384:
		hsize = SHA3_HASH_SIZE;
		break;
	case CKM_SHA512:
		hsize = SHA5_HASH_SIZE;
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}

	if (length_only == TRUE) {
		*out_data_len = hsize;
		return CKR_OK;
	}

        if (*out_data_len < hsize) {
            TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
            return CKR_BUFFER_TOO_SMALL;
        }

	if (token_specific.t_sha_final != NULL)
		return token_specific.t_sha_final(tokdata, ctx, out_data,
						  out_data_len);
	else {
		if (ctx->mech.mechanism == CKM_SHA_1) {
			shaFinal((SHA1_CONTEXT *)ctx->context, out_data);
			*out_data_len = hsize;
			return CKR_OK;
		} else
			return CKR_MECHANISM_INVALID;
	}
}

// this routine gets called for two mechanisms actually:
//    CKM_SHA_1_HMAC
//    CKM_SHA_1_HMAC_GENERAL
//
CK_RV sha1_hmac_sign(STDLL_TokData_t *tokdata,
		     SESSION *sess, CK_BBOOL length_only,
		     SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
		     CK_ULONG in_data_len, CK_BYTE *out_data,
		     CK_ULONG *out_data_len)
{
	OBJECT *key_obj = NULL;
	CK_ATTRIBUTE *attr = NULL;
	CK_BYTE hash[SHA1_HASH_SIZE];
	DIGEST_CONTEXT digest_ctx;
	CK_MECHANISM digest_mech;
	CK_BYTE k_ipad[SHA1_BLOCK_SIZE];
	CK_BYTE k_opad[SHA1_BLOCK_SIZE];
	CK_ULONG key_bytes, hash_len, hmac_len;
	CK_ULONG i;
	CK_RV rc;

	if (!sess || !ctx || !out_data_len) {
		TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	if (ctx->mech.mechanism == CKM_SHA_1_HMAC_GENERAL) {
		hmac_len = *(CK_ULONG *)ctx->mech.pParameter;

		if (hmac_len == 0) {
			*out_data_len = 0;
			return CKR_OK;
		}
	} else
		hmac_len = SHA1_HASH_SIZE;

	if (length_only == TRUE) {
		*out_data_len = hmac_len;
		return CKR_OK;
	}

	if (token_specific.t_hmac_sign != NULL)
		return token_specific.t_hmac_sign(tokdata, sess, in_data,
						  in_data_len, out_data,
						  out_data_len);

	/* Do manual hmac if token doesn't have an hmac crypto call.
	 * Secure tokens should not do manual hmac.
	 */

	memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

	rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj);
	if (rc != CKR_OK) {
		TRACE_ERROR("Failed to acquire key from specified handle");
		if (rc == CKR_OBJECT_HANDLE_INVALID)
			return CKR_KEY_HANDLE_INVALID;
		else
			return rc;
	}

	rc = template_attribute_find(key_obj->template, CKA_VALUE, &attr);
	if (rc == FALSE) {
		TRACE_ERROR("Could not find CKA_VALUE in the template\n");
		return CKR_FUNCTION_FAILED;
	} else
		key_bytes = attr->ulValueLen;


	// build (K XOR ipad), (K XOR opad)
	//
	if (key_bytes > SHA1_BLOCK_SIZE) {
		digest_mech.mechanism = CKM_SHA_1;
		digest_mech.ulParameterLen = 0;
		digest_mech.pParameter = NULL;

		rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
		if (rc != CKR_OK) {
			TRACE_DEVEL("Digest Mgr Init failed.\n");
			return rc;
		}

		hash_len = sizeof(hash);
		rc = digest_mgr_digest(tokdata, sess, FALSE, &digest_ctx,
				       attr->pValue, attr->ulValueLen, hash,
				       &hash_len);
		if (rc != CKR_OK) {
			TRACE_DEVEL("Digest Mgr Digest failed.\n");
			return rc;
		}

		memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

		for (i=0; i < hash_len; i++) {
			k_ipad[i] = hash[i] ^ 0x36;
			k_opad[i] = hash[i] ^ 0x5C;
		}

		memset(&k_ipad[i], 0x36, SHA1_BLOCK_SIZE - i);
		memset(&k_opad[i], 0x5C, SHA1_BLOCK_SIZE - i);
	} else {
		CK_BYTE *key = attr->pValue;

		for (i=0; i < key_bytes; i++) {
			k_ipad[i] = key[i] ^ 0x36;
			k_opad[i] = key[i] ^ 0x5C;
		}

		memset(&k_ipad[i], 0x36, SHA1_BLOCK_SIZE - key_bytes);
		memset(&k_opad[i], 0x5C, SHA1_BLOCK_SIZE - key_bytes);
	}

	digest_mech.mechanism = CKM_SHA_1;
	digest_mech.ulParameterLen = 0;
	digest_mech.pParameter = NULL;

	// inner hash
	//
	rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Init failed.\n");
		return rc;
	}

	rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, k_ipad,
				      SHA1_BLOCK_SIZE);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Update failed.\n");
		return rc;
	}

	rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, in_data,
				      in_data_len);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Update failed.\n");
		return rc;
	}

	hash_len = sizeof(hash);
	rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, hash,
				     &hash_len);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Final failed.\n");
		return rc;
	}

	memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

	// outer hash
	//
	rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Init failed.\n");
		return rc;
	}

	rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, k_opad,
					SHA1_BLOCK_SIZE);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Update failed.\n");
		return rc;
	}

	rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, hash,
				      hash_len);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Update failed.\n");
		return rc;
	}

	hash_len = sizeof(hash);
	rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, hash,
				     &hash_len);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Final failed.\n");
		return rc;
	}

	memcpy(out_data, hash, hmac_len);
	*out_data_len = hmac_len;

	return CKR_OK;
}

/** This routine gets called for two mechanisms actually:
 *    CKM_SHA256_HMAC
 *    CKM_SHA256_HMAC_GENERAL
 */
CK_RV sha2_hmac_sign(STDLL_TokData_t *tokdata,
		     SESSION *sess, CK_BBOOL length_only,
		     SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
		     CK_ULONG in_data_len, CK_BYTE *out_data,
		     CK_ULONG *out_data_len)
{
	OBJECT *key_obj = NULL;
	CK_ATTRIBUTE *attr = NULL;
	CK_BYTE hash[SHA2_HASH_SIZE];
	DIGEST_CONTEXT digest_ctx;
	CK_MECHANISM digest_mech;
	CK_BYTE k_ipad[SHA2_BLOCK_SIZE];
	CK_BYTE k_opad[SHA2_BLOCK_SIZE];
	CK_ULONG key_bytes, hash_len, hmac_len;
	CK_ULONG i;
	CK_RV rc;

	if (!sess || !ctx || !out_data_len) {
		TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	if (ctx->mech.mechanism == CKM_SHA256_HMAC_GENERAL) {
		hmac_len = *(CK_ULONG *)ctx->mech.pParameter;

		if (hmac_len == 0) {
			*out_data_len = 0;
			return CKR_OK;
		}
	} else
		hmac_len = SHA2_HASH_SIZE;

	if (length_only == TRUE) {
		*out_data_len = hmac_len;
		return CKR_OK;
	}

	if (token_specific.t_hmac_sign != NULL)
		return token_specific.t_hmac_sign(tokdata, sess, in_data,
						  in_data_len, out_data,
						  out_data_len);

	/* Do manual hmac if token doesn't have an hmac crypto call.
	 * Secure tokens should not do manual hmac.
	 */
	memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

	rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj);
	if (rc != CKR_OK) {
		TRACE_ERROR("Failed to acquire key from specified handle");
		if (rc == CKR_OBJECT_HANDLE_INVALID)
			return CKR_KEY_HANDLE_INVALID;
		else
			return rc;
	}
	rc = template_attribute_find(key_obj->template, CKA_VALUE, &attr);
	if (rc == FALSE) {
		TRACE_ERROR("Could not find CKA_VALUE in the template\n");
		return CKR_FUNCTION_FAILED;
	} else
		key_bytes = attr->ulValueLen;

	// build (K XOR ipad), (K XOR opad)
	//
	if (key_bytes > SHA2_BLOCK_SIZE) {
		digest_mech.mechanism = CKM_SHA256;
		digest_mech.ulParameterLen = 0;
		digest_mech.pParameter = NULL;

		rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
		if (rc != CKR_OK) {
			TRACE_DEVEL("Digest Mgr Init failed.\n");
			return rc;
		}

		hash_len = sizeof(hash);
		rc = digest_mgr_digest(tokdata, sess, FALSE, &digest_ctx,
				       attr->pValue, attr->ulValueLen,
				       hash, &hash_len);
		if (rc != CKR_OK) {
			TRACE_DEVEL("Digest Mgr Digest failed.\n");
			return rc;
		}

		memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

		for (i=0; i < hash_len; i++) {
			k_ipad[i] = hash[i] ^ 0x36;
			k_opad[i] = hash[i] ^ 0x5C;
		}

		memset(&k_ipad[i], 0x36, SHA2_BLOCK_SIZE - i);
		memset(&k_opad[i], 0x5C, SHA2_BLOCK_SIZE - i);
	} else {
		CK_BYTE *key = attr->pValue;

		for (i=0; i < key_bytes; i++) {
			k_ipad[i] = key[i] ^ 0x36;
			k_opad[i] = key[i] ^ 0x5C;
		}

		memset(&k_ipad[i], 0x36, SHA2_BLOCK_SIZE - key_bytes);
		memset(&k_opad[i], 0x5C, SHA2_BLOCK_SIZE - key_bytes);
	}

	digest_mech.mechanism = CKM_SHA256;
	digest_mech.ulParameterLen = 0;
	digest_mech.pParameter = NULL;

	// inner hash
	//
	rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Init failed.\n");
		return rc;
	}

	rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, k_ipad,
				      SHA2_BLOCK_SIZE);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Update failed.\n");
		return rc;
	}

	rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, in_data,
				      in_data_len);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Update failed.\n");
		return rc;
	}

	hash_len = sizeof(hash);
	rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, hash,
				     &hash_len);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Final failed.\n");
		return rc;
	}

	memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

	// outer hash
	//
	rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Init failed.\n");
		return rc;
	}

	rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, k_opad,
				      SHA2_BLOCK_SIZE);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Update failed.\n");
		return rc;
	}

	rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, hash,
				      hash_len);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Update failed.\n");
		return rc;
	}

	hash_len = sizeof(hash);
	rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, hash,
				     &hash_len);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Final failed.\n");
		return rc;
	}

	memcpy(out_data, hash, hmac_len);
	*out_data_len = hmac_len;

	return CKR_OK;
}

/** This routine gets called for two mechanisms actually:
 *    CKM_SHA384_HMAC
 *    CKM_SHA384_HMAC_GENERAL
 */
CK_RV sha3_hmac_sign(STDLL_TokData_t *tokdata,
		     SESSION *sess, CK_BBOOL length_only,
		     SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
		     CK_ULONG in_data_len, CK_BYTE *out_data,
		     CK_ULONG *out_data_len)
{
	OBJECT *key_obj = NULL;
	CK_ATTRIBUTE *attr = NULL;
	CK_BYTE hash[SHA3_HASH_SIZE];
	DIGEST_CONTEXT digest_ctx;
	CK_MECHANISM digest_mech;
	CK_BYTE k_ipad[SHA3_BLOCK_SIZE];
	CK_BYTE k_opad[SHA3_BLOCK_SIZE];
	CK_ULONG key_bytes, hash_len, hmac_len;
	CK_ULONG i;
	CK_RV rc;

	if (!sess || !ctx || !out_data_len) {
		TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	if (ctx->mech.mechanism == CKM_SHA384_HMAC_GENERAL) {
		hmac_len = *(CK_ULONG *)ctx->mech.pParameter;

		if (hmac_len == 0) {
			*out_data_len = 0;
			return CKR_OK;
		}
   	} else
		hmac_len = SHA3_HASH_SIZE;

	if (length_only == TRUE) {
		*out_data_len = hmac_len;
		return CKR_OK;
	}

	if (token_specific.t_hmac_sign != NULL)
		return token_specific.t_hmac_sign(tokdata, sess, in_data,
						  in_data_len, out_data,
						  out_data_len);

	/* Do manual hmac if token doesn't have an hmac crypto call.
	 * Secure tokens should not do manual hmac.
	 */

	memset( &digest_ctx, 0x0, sizeof(DIGEST_CONTEXT) );

	rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj);
	if (rc != CKR_OK) {
		TRACE_ERROR("Failed to acquire key from specified handle");
		if (rc == CKR_OBJECT_HANDLE_INVALID)
			return CKR_KEY_HANDLE_INVALID;
		else
			return rc;
	}
	rc = template_attribute_find(key_obj->template, CKA_VALUE, &attr);
	if (rc == FALSE) {
		TRACE_ERROR("Could not find CKA_VALUE in the template\n");
		return CKR_FUNCTION_FAILED;
	} else
		key_bytes = attr->ulValueLen;

	// build (K XOR ipad), (K XOR opad)
	//
	if (key_bytes > SHA3_BLOCK_SIZE) {
		digest_mech.mechanism = CKM_SHA384;
		digest_mech.ulParameterLen = 0;
		digest_mech.pParameter = NULL;

		rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
		if (rc != CKR_OK) {
			TRACE_DEVEL("Digest Mgr Init failed.\n");
			return rc;
		}

		hash_len = sizeof(hash);
		rc = digest_mgr_digest(tokdata, sess, FALSE, &digest_ctx,
				       attr->pValue, attr->ulValueLen, hash,
				       &hash_len);
		if (rc != CKR_OK) {
			TRACE_DEVEL("Digest Mgr Digest failed.\n");
			return rc;
		}

		memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

		for (i=0; i < hash_len; i++) {
			k_ipad[i] = hash[i] ^ 0x36;
			k_opad[i] = hash[i] ^ 0x5C;
		}

		memset(&k_ipad[i], 0x36, SHA3_BLOCK_SIZE - i);
		memset(&k_opad[i], 0x5C, SHA3_BLOCK_SIZE - i);
	} else {
		CK_BYTE *key = attr->pValue;

		for (i=0; i < key_bytes; i++) {
			k_ipad[i] = key[i] ^ 0x36;
			k_opad[i] = key[i] ^ 0x5C;
		}

		memset(&k_ipad[i], 0x36, SHA3_BLOCK_SIZE - key_bytes);
		memset(&k_opad[i], 0x5C, SHA3_BLOCK_SIZE - key_bytes);
	}

	digest_mech.mechanism = CKM_SHA384;
	digest_mech.ulParameterLen = 0;
	digest_mech.pParameter = NULL;

	// inner hash
	//
	rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Init failed.\n");
		return rc;
	}

	rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, k_ipad,
				      SHA3_BLOCK_SIZE);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Update failed.\n");
		return rc;
	}

	rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, in_data,
				      in_data_len);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Update failed.\n");
		return rc;
	}

	hash_len = sizeof(hash);
	rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, hash,
				     &hash_len);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Final failed.\n");
		return rc;
	}

	memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

	// outer hash
	//
	rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Init failed.\n");
		return rc;
	}

	rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, k_opad,
				      SHA3_BLOCK_SIZE);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Update failed.\n");
		return rc;
	}

	rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, hash,
				      hash_len);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Update failed.\n");
		return rc;
	}

	hash_len = sizeof(hash);
	rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, hash,
				     &hash_len);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Final failed.\n");
		return rc;
	}

	memcpy(out_data, hash, hmac_len);
	*out_data_len = hmac_len;

	return CKR_OK;
}

/** This routine gets called for two mechanisms actually:
 *    CKM_SHA512_HMAC
 *    CKM_SHA512_HMAC_GENERAL
 */
CK_RV sha5_hmac_sign(STDLL_TokData_t *tokdata,
		     SESSION *sess, CK_BBOOL length_only,
		     SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
		     CK_ULONG in_data_len, CK_BYTE *out_data,
		     CK_ULONG *out_data_len)
{
	OBJECT *key_obj = NULL;
	CK_ATTRIBUTE *attr = NULL;
	CK_BYTE hash[SHA5_HASH_SIZE];
	DIGEST_CONTEXT digest_ctx;
	CK_MECHANISM digest_mech;
	CK_BYTE k_ipad[SHA5_BLOCK_SIZE];
	CK_BYTE k_opad[SHA5_BLOCK_SIZE];
	CK_ULONG key_bytes, hash_len, hmac_len;
	CK_ULONG i;
	CK_RV rc;

	if (!sess || !ctx || !out_data_len) {
		TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	if (ctx->mech.mechanism == CKM_SHA512_HMAC_GENERAL) {
		hmac_len = *(CK_ULONG *)ctx->mech.pParameter;

		if (hmac_len == 0) {
			*out_data_len = 0;
			return CKR_OK;
		}
	} else
		hmac_len = SHA5_HASH_SIZE;

	if (length_only == TRUE) {
		*out_data_len = hmac_len;
		return CKR_OK;
	}

	if (token_specific.t_hmac_sign != NULL)
		return token_specific.t_hmac_sign(tokdata, sess, in_data,
						  in_data_len,
						  out_data, out_data_len);

	/* Do manual hmac if token doesn't have an hmac crypto call.
	 * Secure tokens should not do manual hmac.
	 */
	memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

	rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj);
	if (rc != CKR_OK) {
		TRACE_ERROR("Failed to acquire key from specified handle");
		if (rc == CKR_OBJECT_HANDLE_INVALID)
			return CKR_KEY_HANDLE_INVALID;
		else
			return rc;
	}
	rc = template_attribute_find(key_obj->template, CKA_VALUE, &attr);
	if (rc == FALSE) {
		TRACE_ERROR("Could not find CKA_VALUE in the template\n");
		return CKR_FUNCTION_FAILED;
	} else
		key_bytes = attr->ulValueLen;

	// build (K XOR ipad), (K XOR opad)
	//
	if (key_bytes > SHA5_BLOCK_SIZE) {
		digest_mech.mechanism = CKM_SHA512;
		digest_mech.ulParameterLen = 0;
		digest_mech.pParameter = NULL;

		rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
		if (rc != CKR_OK) {
			TRACE_DEVEL("Digest Mgr Init failed.\n");
			return rc;
		}

		hash_len = sizeof(hash);
		rc = digest_mgr_digest(tokdata, sess, FALSE, &digest_ctx,
				       attr->pValue, attr->ulValueLen, hash,
				       &hash_len);
		if (rc != CKR_OK) {
			TRACE_DEVEL("Digest Mgr Digest failed.\n");
			return rc;
		}

		memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

		for (i=0; i < hash_len; i++) {
			k_ipad[i] = hash[i] ^ 0x36;
			k_opad[i] = hash[i] ^ 0x5C;
		}

		memset(&k_ipad[i], 0x36, SHA5_BLOCK_SIZE - i);
		memset(&k_opad[i], 0x5C, SHA5_BLOCK_SIZE - i);
	} else {
		CK_BYTE *key = attr->pValue;

		for (i=0; i < key_bytes; i++) {
			k_ipad[i] = key[i] ^ 0x36;
			k_opad[i] = key[i] ^ 0x5C;
		}

		memset(&k_ipad[i], 0x36, SHA5_BLOCK_SIZE - key_bytes);
		memset(&k_opad[i], 0x5C, SHA5_BLOCK_SIZE - key_bytes);
	}

	digest_mech.mechanism = CKM_SHA512;
	digest_mech.ulParameterLen = 0;
	digest_mech.pParameter = NULL;

	// inner hash
	//
	rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Init failed.\n");
		return rc;
	}

	rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, k_ipad,
				      SHA5_BLOCK_SIZE);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Update failed.\n");
		return rc;
	}

	rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, in_data,
				      in_data_len);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Update failed.\n");
		return rc;
	}

	hash_len = sizeof(hash);
	rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, hash,
				     &hash_len);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Final failed.\n");
		return rc;
	}

	if (token_specific.t_hmac_sign != NULL)
		return token_specific.t_hmac_sign(tokdata, sess, in_data,
						  in_data_len, out_data,
						  out_data_len);

	/* Do manual hmac if token doesn't have an hmac crypto call.
	 * Secure tokens should not do manual hmac.
	 */
	memset( &digest_ctx, 0x0, sizeof(DIGEST_CONTEXT) );

	// outer hash
	//
	rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Init failed.\n");
		return rc;
	}

	rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, k_opad,
				      SHA5_BLOCK_SIZE);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Update failed.\n");
		return rc;
	}

	rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, hash,
				      hash_len);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Update failed.\n");
		return rc;
	}

	hash_len = sizeof(hash);
	rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, hash,
				     &hash_len);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Digest Mgr Final failed.\n");
		return rc;
	}

	memcpy(out_data, hash, hmac_len);
	*out_data_len = hmac_len;

	return CKR_OK;
}

CK_RV sha1_hmac_verify(STDLL_TokData_t *tokdata, SESSION *sess,
		       SIGN_VERIFY_CONTEXT *ctx,
		       CK_BYTE *in_data, CK_ULONG in_data_len,
		       CK_BYTE *signature, CK_ULONG sig_len)
{
	CK_BYTE hmac[SHA1_HASH_SIZE];
	SIGN_VERIFY_CONTEXT hmac_ctx;
	CK_ULONG hmac_len, len;
	CK_RV rc;

	if (!sess || !ctx || !in_data || !signature) {
		TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	if (token_specific.t_hmac_verify != NULL)
		return token_specific.t_hmac_verify(tokdata, sess, in_data,
						    in_data_len, signature,
						    sig_len);

	/* Do manual hmac verify  if token doesn't have an hmac crypto call.
	 * Secure tokens should not do manual hmac.
	 */
	if (ctx->mech.mechanism == CKM_SHA_1_HMAC_GENERAL)
		hmac_len = *(CK_ULONG *)ctx->mech.pParameter;
	else
		hmac_len = SHA1_HASH_SIZE;

	memset(&hmac_ctx, 0, sizeof(SIGN_VERIFY_CONTEXT));

	rc = sign_mgr_init(tokdata, sess, &hmac_ctx, &ctx->mech, FALSE, ctx->key);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Sign Mgr Init failed.\n");
		goto done;
	}
	len = sizeof(hmac);
	rc = sign_mgr_sign(tokdata, sess, FALSE, &hmac_ctx, in_data, in_data_len,
			   hmac, &len);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Sign Mgr Sign failed.\n");
		goto done;
	}
	if ((len != hmac_len) || (len != sig_len)) {
		TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_LEN_RANGE));
		rc = CKR_SIGNATURE_LEN_RANGE;
		goto done;
	}

	if (memcmp(hmac, signature, hmac_len) != 0) {
		TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
		rc = CKR_SIGNATURE_INVALID;
	}

done:
	sign_mgr_cleanup(&hmac_ctx);
	return rc;
}

CK_RV sha2_hmac_verify(STDLL_TokData_t *tokdata,
		       SESSION *sess, SIGN_VERIFY_CONTEXT *ctx,
		       CK_BYTE *in_data, CK_ULONG in_data_len,
		       CK_BYTE *signature, CK_ULONG sig_len)
{
	CK_BYTE hmac[SHA2_HASH_SIZE];
	SIGN_VERIFY_CONTEXT hmac_ctx;
	CK_ULONG hmac_len, len;
	CK_RV rc;

	if (!sess || !ctx || !in_data || !signature) {
		TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	if (token_specific.t_hmac_verify != NULL)
		return token_specific.t_hmac_verify(tokdata, sess, in_data,
						    in_data_len, signature,
						    sig_len);

	/* Do manual hmac verify  if token doesn't have an hmac crypto call.
	 * Secure tokens should not do manual hmac.
	 */
	if (ctx->mech.mechanism == CKM_SHA256_HMAC_GENERAL)
		hmac_len = *(CK_ULONG *)ctx->mech.pParameter;
	else
		hmac_len = SHA2_HASH_SIZE;

	memset(&hmac_ctx, 0, sizeof(SIGN_VERIFY_CONTEXT));

	rc = sign_mgr_init(tokdata, sess, &hmac_ctx, &ctx->mech, FALSE, ctx->key);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Sign Mgr Init failed.\n");
		goto done;
	}

	len = sizeof(hmac);
	rc = sign_mgr_sign(tokdata, sess, FALSE, &hmac_ctx, in_data, in_data_len,
			   hmac, &len);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Sign Mgr Sign failed.\n");
		goto done;
	}

	if ((len != hmac_len) || (len != sig_len)) {
		TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_LEN_RANGE));
		rc = CKR_SIGNATURE_LEN_RANGE;
		goto done;
	}

	if (memcmp(hmac, signature, hmac_len) != 0) {
		TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
		rc = CKR_SIGNATURE_INVALID;
	}

done:
	sign_mgr_cleanup(&hmac_ctx);
	return rc;
}

CK_RV sha3_hmac_verify(STDLL_TokData_t *tokdata,
		       SESSION *sess, SIGN_VERIFY_CONTEXT *ctx,
		       CK_BYTE *in_data, CK_ULONG in_data_len,
		       CK_BYTE *signature, CK_ULONG sig_len)
{
	CK_BYTE hmac[SHA3_HASH_SIZE];
	SIGN_VERIFY_CONTEXT hmac_ctx;
	CK_ULONG hmac_len, len;
	CK_RV rc;

	if (!sess || !ctx || !in_data || !signature) {
		TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}
	if (token_specific.t_hmac_verify != NULL)
		return token_specific.t_hmac_verify(tokdata, sess, in_data,
						    in_data_len, signature,
						    sig_len);

	/* Do manual hmac verify  if token doesn't have an hmac crypto call.
	 * Secure tokens should not do manual hmac.
	 */
	if (ctx->mech.mechanism == CKM_SHA384_HMAC_GENERAL)
		hmac_len = *(CK_ULONG *)ctx->mech.pParameter;
	else
		hmac_len = SHA3_HASH_SIZE;

	memset(&hmac_ctx, 0, sizeof(SIGN_VERIFY_CONTEXT));

	rc = sign_mgr_init(tokdata, sess, &hmac_ctx, &ctx->mech, FALSE, ctx->key);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Sign Mgr Init failed.\n");
		goto done;
	}
	len = sizeof(hmac);
	rc = sign_mgr_sign(tokdata, sess, FALSE, &hmac_ctx, in_data, in_data_len,
			   hmac, &len);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Sign Mgr Sign failed.\n");
		goto done;
	}
	if ((len != hmac_len) || (len != sig_len)) {
		TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_LEN_RANGE));
		rc = CKR_SIGNATURE_LEN_RANGE;
		goto done;
	}

	if (memcmp(hmac, signature, hmac_len) != 0) {
		TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
		rc = CKR_SIGNATURE_INVALID;
	}
done:
	sign_mgr_cleanup(&hmac_ctx);
	return rc;
}

CK_RV sha5_hmac_verify(STDLL_TokData_t *tokdata,
		       SESSION *sess, SIGN_VERIFY_CONTEXT *ctx,
		       CK_BYTE *in_data, CK_ULONG in_data_len,
		       CK_BYTE *signature, CK_ULONG sig_len)
{
	CK_BYTE hmac[SHA5_HASH_SIZE];
	SIGN_VERIFY_CONTEXT hmac_ctx;
	CK_ULONG hmac_len, len;
	CK_RV rc;

	if (!sess || !ctx || !in_data || !signature) {
		TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}
	if (token_specific.t_hmac_verify != NULL)
		return token_specific.t_hmac_verify(tokdata, sess, in_data,
						    in_data_len, signature,
						    sig_len);

	/* Do manual hmac verify  if token doesn't have an hmac crypto call.
	 * Secure tokens should not do manual hmac.
	 */
	if (ctx->mech.mechanism == CKM_SHA512_HMAC_GENERAL)
		hmac_len = *(CK_ULONG *)ctx->mech.pParameter;
	else
		hmac_len = SHA5_HASH_SIZE;

	memset(&hmac_ctx, 0, sizeof(SIGN_VERIFY_CONTEXT));

	rc = sign_mgr_init(tokdata, sess, &hmac_ctx, &ctx->mech, FALSE, ctx->key);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Sign Mgr Init failed.\n");
		goto done;
	}
	len = sizeof(hmac);
	rc = sign_mgr_sign(tokdata, sess, FALSE, &hmac_ctx, in_data, in_data_len,
			   hmac, &len);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Sign Mgr Sign failed.\n");
		goto done;
	}
	if ((len != hmac_len) || (len != sig_len)) {
		TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_LEN_RANGE));
		rc = CKR_SIGNATURE_LEN_RANGE;
		goto done;
	}

	if (memcmp(hmac, signature, hmac_len) != 0) {
		TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
		rc = CKR_SIGNATURE_INVALID;
	}
done:
	sign_mgr_cleanup(&hmac_ctx);
	return rc;
}

CK_RV sha_init(STDLL_TokData_t *tokdata, SESSION *sess, DIGEST_CONTEXT *ctx,
	       CK_MECHANISM *mech)
{
	if (token_specific.t_sha_init != NULL)
		return token_specific.t_sha_init(tokdata, ctx, mech);
	else {
		/* For current tokens, continue legacy of using software
		 *  implemented SHA-1 if the token does not have its own
		 *  SHA-1 implementation.
		 *  Future tokens' crypto should be its own so that
		 *  opencryptoki is not responsible for crypto. If token
		 *  does not have SHA-1, then should be mechanism not
		 *  supported. JML
		 */
		if (mech->mechanism == CKM_SHA_1) {
			sw_sha1_init(ctx);
			return CKR_OK;
		} else
			return CKR_MECHANISM_INVALID;
	}
}

CK_RV hmac_sign_init(STDLL_TokData_t *tokdata, SESSION *sess,
		     CK_MECHANISM *mech, CK_OBJECT_HANDLE hkey)
{
	if (token_specific.t_hmac_sign_init != NULL)
                return token_specific.t_hmac_sign_init(tokdata, sess, mech, hkey);
	else
		/* Return ok with the intention that the local hmac
		 * implementation will get used instead.
		 * For those tokens not supporting HMAC at all,
		 * will need to return CKR_MECHANISM_INVALID.
		 */
		return CKR_OK;
}

CK_RV hmac_sign_update(STDLL_TokData_t *tokdata, SESSION *sess,
		       CK_BYTE *in_data, CK_ULONG in_data_len)
{
	SIGN_VERIFY_CONTEXT *ctx = &sess->sign_ctx;

	if (!sess || !ctx) {
		TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	if (token_specific.t_hmac_sign_update != NULL)
		return token_specific.t_hmac_sign_update(tokdata, sess,
							 in_data,
							 in_data_len);
	else {
		TRACE_ERROR("hmac-update is not supported\n");
		return CKR_MECHANISM_INVALID;
	}
}

CK_RV hmac_sign_final(STDLL_TokData_t *tokdata, SESSION *sess,
		      CK_BYTE *signature, CK_ULONG *sig_len)
{
	SIGN_VERIFY_CONTEXT *ctx = &sess->sign_ctx;

	if (!sess || !ctx) {
		TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	if (token_specific.t_hmac_sign_final != NULL)
		return token_specific.t_hmac_sign_final(tokdata, sess,
							signature,
							sig_len);
	else {
		TRACE_ERROR("hmac-final is not supported\n");
		return CKR_MECHANISM_INVALID;
	}
}

CK_RV hmac_verify_init(STDLL_TokData_t *tokdata, SESSION *sess,
		       CK_MECHANISM *mech, CK_OBJECT_HANDLE hkey)
{
	if (token_specific.t_hmac_verify_init != NULL)
                return token_specific.t_hmac_verify_init(tokdata, sess, mech,
							 hkey);
	else
		/* Return ok with the intention that the local hmac
		 * implementation will get used instead.
		 * For those tokens not supporting HMAC at all,
		 * will need to return CKR_MECHANISM_INVALID.
		 */
		return CKR_OK;
}

CK_RV hmac_verify_update(STDLL_TokData_t *tokdata, SESSION *sess,
			 CK_BYTE *in_data, CK_ULONG in_data_len)
{
	SIGN_VERIFY_CONTEXT *ctx = &sess->sign_ctx;

	if (!sess || !ctx) {
		TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	if (token_specific.t_hmac_verify_update != NULL)
		return token_specific.t_hmac_verify_update(tokdata, sess,
							   in_data,
							   in_data_len);
	else {
		TRACE_ERROR("hmac-update is not supported\n");
		return CKR_MECHANISM_INVALID;
	}
}

CK_RV hmac_verify_final(STDLL_TokData_t *tokdata, SESSION *sess,
			CK_BYTE *signature, CK_ULONG sig_len)
{
	SIGN_VERIFY_CONTEXT *ctx = &sess->sign_ctx;

	if (!sess || ! ctx) {
		TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	if (token_specific.t_hmac_verify_final != NULL)
		return token_specific.t_hmac_verify_final(tokdata, sess,
							  signature,
							  sig_len);
	else {
		TRACE_ERROR("hmac-final is not supported\n");
		return CKR_MECHANISM_INVALID;
	}
}

CK_RV ckm_generic_secret_key_gen(STDLL_TokData_t *tokdata, TEMPLATE *tmpl)
{
	if (token_specific.t_generic_secret_key_gen == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return CKR_MECHANISM_INVALID;
	} else
		return token_specific.t_generic_secret_key_gen(tokdata, tmpl);
}
