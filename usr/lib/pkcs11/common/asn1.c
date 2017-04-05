/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// ASN.1 encoding/decoding routines
//
// This code is a mess...
//

#include <pthread.h>
#include <stdlib.h>
#include <string.h>  // for memcmp() et al

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "trace.h"


//
//
CK_ULONG
ber_encode_INTEGER( CK_BBOOL    length_only,
                    CK_BYTE  ** ber_int,
                    CK_ULONG  * ber_int_len,
                    CK_BYTE   * data,
                    CK_ULONG    data_len )
{
   CK_BYTE   *buf = NULL;
   CK_ULONG   len, padding = 0;

   // ber encoded integers are alway signed. So if the msb of the first byte
   // is set, this would indicate an negative value if we just copy the
   // (unsigned) big integer from *data to the ber buffer. So in this case
   // a preceding 0x00 byte is stored before the actual data. The decode
   // function does the reverse and may skip this padding.

   if ((length_only && (!data || *data & 0x80))
       || (*data & 0x80))
	   padding = 1;

   // if data_len < 127 use short-form length id
   // if data_len < 256 use long-form length id with 1-byte length field
   // if data_len < 65536 use long-form length id with 2-byte length field
   // if data_len < 16777216 use long-form length id with 3-byte length field
   //
   if (data_len + padding < 128)
      len = 1 + 1 + padding + data_len;
   else if (data_len + padding < 256)
      len = 1 + (1 + 1) + padding + data_len;
   else if (data_len + padding < (1 << 16))
      len = 1 + (1 + 2) + padding + data_len;
   else if (data_len + padding < (1 << 24))
      len = 1 + (1 + 3) + padding + data_len;
   else{
      TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
      return CKR_FUNCTION_FAILED;
   }
   if (length_only == TRUE) {
      *ber_int_len = len;
      return CKR_OK;
   }

   buf = (CK_BYTE *)malloc( len );
   if (!buf){
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      return CKR_HOST_MEMORY;
   }
   if (data_len + padding < 128) {
      buf[0] = 0x02;
      buf[1] = data_len + padding;
      if (padding) {
	      buf[2] = 0x00;
	      memcpy( &buf[3], data, data_len );
      } else
	      memcpy( &buf[2], data, data_len );
      *ber_int_len = len;
      *ber_int     = buf;
      return CKR_OK;
   }

   if (data_len + padding < 256) {
      buf[0] = 0x02;
      buf[1] = 0x81;
      buf[2] = data_len + padding;
      if (padding) {
	      buf[3] = 0x00;
	      memcpy( &buf[4], data, data_len );
      } else
	      memcpy( &buf[3], data, data_len );
      *ber_int_len = len;
      *ber_int     = buf;
      return CKR_OK;
   }

   if (data_len + padding < (1 << 16)) {
      buf[0] = 0x02;
      buf[1] = 0x82;
      buf[2] = ((data_len + padding) >> 8) & 0xFF;
      buf[3] = ((data_len + padding)     ) & 0xFF;
      if (padding) {
	      buf[4] = 0x00;
	      memcpy( &buf[5], data, data_len );
      } else
	      memcpy( &buf[4], data, data_len );
      *ber_int_len = len;
      *ber_int     = buf;
      return CKR_OK;
   }

   if (data_len + padding < (1 << 24)) {
      buf[0] = 0x02;
      buf[1] = 0x83;
      buf[2] = ((data_len + padding) >> 16) & 0xFF;
      buf[3] = ((data_len + padding) >>  8) & 0xFF;
      buf[4] = ((data_len + padding)      ) & 0xFF;
      if (padding) {
	      buf[5] = 0x00;
	      memcpy( &buf[6], data, data_len );
      } else
	      memcpy( &buf[5], data, data_len );
      *ber_int_len = len;
      *ber_int     = buf;
      return CKR_OK;
   }

   // we should never reach this
   //
   free( buf );
   TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
   return CKR_FUNCTION_FAILED;
}


//
//
CK_RV
ber_decode_INTEGER( CK_BYTE   * ber_int,
                    CK_BYTE  ** data,
                    CK_ULONG  * data_len,
                    CK_ULONG  * field_len )
{
   CK_ULONG  len, length_octets;

   if (!ber_int){
      TRACE_ERROR("Invalid function argument.\n");
      return CKR_FUNCTION_FAILED;
   }
   if (ber_int[0] != 0x02){
      TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
      return CKR_FUNCTION_FAILED;
   }

   // ber encoded integers are alway signed. So it may be that the very first
   // byte is just a padding 0x00 value because the following byte has the msb
   // set and without the padding the value would indicate a negative value.
   // However, opencryptoki always stores big integers 'unsigned' meaning
   // even when the msb is set, there is no preceding 0x00. Even more some
   // tests may fail e.g. the size in bytes of a modulo big integer should be
   // modulo bits / 8 which is not true with preceeding 0x00 byte.

   // short form lengths are easy
   //
   if ((ber_int[1] & 0x80) == 0) {
      len = ber_int[1] & 0x7F;
      *data      = &ber_int[2];
      *data_len  = len;
      if (ber_int[2] == 0x00) {
	      *data      = &ber_int[3];
	      *data_len  = len - 1;
      }
      *field_len = 1 + 1 + len;
      return CKR_OK;
   }

   length_octets = ber_int[1] & 0x7F;

   if (length_octets == 1) {
      len = ber_int[2];
      *data      = &ber_int[3];
      *data_len  = len;
      if (ber_int[3] == 0x00) {
	      *data      = &ber_int[4];
	      *data_len  = len - 1;
      }
      *field_len = 1 + (1 + 1) + len;
      return CKR_OK;
   }

   if (length_octets == 2) {
      len = ber_int[2];
      len = len << 8;
      len |= ber_int[3];
      *data      = &ber_int[4];
      *data_len  = len;
      if (ber_int[4] == 0x00) {
	      *data      = &ber_int[5];
	      *data_len  = len - 1;
      }
      *field_len = 1 + (1 + 2) + len;
      return CKR_OK;
   }

   if (length_octets == 3) {
      len = ber_int[2];
      len = len << 8;
      len |= ber_int[3];
      len = len << 8;
      len |= ber_int[4];
      *data      = &ber_int[5];
      *data_len  = len;
      if (ber_int[5] == 0x00) {
	      *data      = &ber_int[6];
	      *data_len  = len - 1;
      }
      *field_len = 1 + (1 + 3) + len;
      return CKR_OK;
   }

   // > 3 length octets implies a length > 16MB which isn't possible for
   // the coprocessor
   //
   TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
   return CKR_FUNCTION_FAILED;
}


//
//
CK_RV
ber_encode_OCTET_STRING( CK_BBOOL    length_only,
                         CK_BYTE  ** str,
                         CK_ULONG  * str_len,
                         CK_BYTE   * data,
                         CK_ULONG    data_len )
{
   CK_BYTE   *buf = NULL;
   CK_ULONG   len;

   // I only support Primitive encoding for OCTET STRINGS
   //

   // if data_len < 128 use short-form length id
   // if data_len < 256 use long-form length id with 1-byte length field
   // if data_len < 65536 use long-form length id with 2-byte length field
   //

   if (data_len < 128)
      len = 1 + 1 + data_len;
   else if (data_len < 256)
      len = 1 + (1 + 1) + data_len;
   else if (data_len < (1 << 16))
      len = 1 + (1 + 2) + data_len;
   else if (data_len < (1 << 24))
      len = 1 + (1 + 3) + data_len;
   else{
      TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
      return CKR_FUNCTION_FAILED;
   }
   if (length_only == TRUE) {
      *str_len = len;
      return CKR_OK;
   }

   buf = (CK_BYTE *)malloc( len );
   if (!buf){
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      return CKR_HOST_MEMORY;
   }

   if (data_len < 128) {
      buf[0] = 0x04;       // primitive, OCTET STRING
      buf[1] = data_len;
      memcpy( &buf[2], data, data_len );

      *str_len = len;
      *str = buf;
      return CKR_OK;
   }

   if (data_len < 256) {
      buf[0] = 0x04;       // primitive, OCTET STRING
      buf[1] = 0x81;       // length header -- 1 length octets
      buf[2] = data_len;

      memcpy( &buf[3], data, data_len );

      *str_len = len;
      *str = buf;
      return CKR_OK;
   }

   if (data_len < (1 << 16)) {
      buf[0] = 0x04;       // primitive, OCTET STRING
      buf[1] = 0x82;       // length header -- 2 length octets
      buf[2] = (data_len >> 8) & 0xFF;
      buf[3] = (data_len     ) & 0xFF;

      memcpy( &buf[4], data, data_len );

      *str_len = len;
      *str = buf;
      return CKR_OK;
   }

   if (data_len < (1 << 24)) {
      buf[0] = 0x04;       // primitive, OCTET STRING
      buf[1] = 0x83;       // length header -- 3 length octets
      buf[2] = (data_len >> 16) & 0xFF;
      buf[3] = (data_len >>  8) & 0xFF;
      buf[4] = (data_len      ) & 0xFF;

      memcpy( &buf[5], data, data_len );

      *str_len = len;
      *str = buf;
      return CKR_OK;
   }

   // we should never reach this
   //
   free( buf );
   TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
   return CKR_FUNCTION_FAILED;
}


//
//
CK_RV
ber_decode_OCTET_STRING( CK_BYTE  * str,
                         CK_BYTE ** data,
                         CK_ULONG * data_len,
                         CK_ULONG * field_len )
{
   CK_ULONG  len, length_octets;

   // I only support decoding primitive OCTET STRINGS
   //

   if (!str){
      TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
      return CKR_FUNCTION_FAILED;
   }
   if (str[0] != 0x04){
      TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
      return CKR_FUNCTION_FAILED;
   }
   // short form lengths are easy
   //
   if ((str[1] & 0x80) == 0) {
      len = str[1] & 0x7F;

      *data = &str[2];
      *data_len  = len;
      *field_len = 1 + (1) + len;
      return CKR_OK;
   }

   length_octets = str[1] & 0x7F;

   if (length_octets == 1) {
      len = str[2];

      *data = &str[3];
      *data_len  = len;
      *field_len = 1 + (1 + 1) + len;
      return CKR_OK;
   }

   if (length_octets == 2) {
      len = str[2];
      len = len << 8;
      len |= str[3];

      *data = &str[4];
      *data_len  = len;
      *field_len = 1 + (1 + 2) + len;
      return CKR_OK;
   }

   if (length_octets == 3) {
      len = str[2];
      len = len << 8;
      len |= str[3];
      len = len << 8;
      len |= str[4];

      *data = &str[5];
      *data_len  = len;
      *field_len = 1 + (1 + 3) + len;
      return CKR_OK;
   }

   // > 3 length octets implies a length > 16MB
   //
   TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
   return CKR_FUNCTION_FAILED;
}


//
//
CK_RV
ber_encode_SEQUENCE( CK_BBOOL    length_only,
                     CK_BYTE  ** seq,
                     CK_ULONG  * seq_len,
                     CK_BYTE   * data,
                     CK_ULONG    data_len )
{
   CK_BYTE   *buf = NULL;
   CK_ULONG   len;

   // if data_len < 127 use short-form length id
   // if data_len < 65536 use long-form length id with 2-byte length field
   //

   if (data_len < 128)
      len = 1 + 1 + data_len;
   else if (data_len < 256)
      len = 1 + (1 + 1) + data_len;
   else if (data_len < (1 << 16))
      len = 1 + (1 + 2) + data_len;
   else if (data_len < (1 << 24))
      len = 1 + (1 + 3) + data_len;
   else{
      TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
      return CKR_FUNCTION_FAILED;
   }
   if (length_only == TRUE) {
      *seq_len = len;
      return CKR_OK;
   }

   buf = (CK_BYTE *)malloc( len );
   if (!buf){
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      return CKR_HOST_MEMORY;
   }

   if (data_len < 128) {
      buf[0] = 0x30;       // constructed, SEQUENCE
      buf[1] = data_len;
      memcpy( &buf[2], data, data_len );

      *seq_len = len;
      *seq = buf;
      return CKR_OK;
   }

   if (data_len < 256) {
      buf[0] = 0x30;       // constructed, SEQUENCE
      buf[1] = 0x81;       // length header -- 1 length octets
      buf[2] = data_len;

      memcpy( &buf[3], data, data_len );

      *seq_len = len;
      *seq = buf;
      return CKR_OK;
   }

   if (data_len < (1 << 16)) {
      buf[0] = 0x30;       // constructed, SEQUENCE
      buf[1] = 0x82;       // length header -- 2 length octets
      buf[2] = (data_len >> 8) & 0xFF;
      buf[3] = (data_len     ) & 0xFF;

      memcpy( &buf[4], data, data_len );

      *seq_len = len;
      *seq = buf;
      return CKR_OK;
   }

   if (data_len < (1 << 24)) {
      buf[0] = 0x30;       // constructed, SEQUENCE
      buf[1] = 0x83;       // length header -- 3 length octets
      buf[2] = (data_len >> 16) & 0xFF;
      buf[3] = (data_len >>  8) & 0xFF;
      buf[4] = (data_len      ) & 0xFF;

      memcpy( &buf[5], data, data_len );

      *seq_len = len;
      *seq = buf;
      return CKR_OK;
   }

   free( buf );
   TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
   return CKR_FUNCTION_FAILED;
}


//
//
CK_RV
ber_decode_SEQUENCE( CK_BYTE  * seq,
                     CK_BYTE ** data,
                     CK_ULONG * data_len,
                     CK_ULONG * field_len )
{
   CK_ULONG  len, length_octets;


   if (!seq){
      TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
      return CKR_FUNCTION_FAILED;
   }
   if (seq[0] != 0x30){
      TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
      return CKR_FUNCTION_FAILED;
   }
   // short form lengths are easy
   //
   if ((seq[1] & 0x80) == 0) {
      len = seq[1] & 0x7F;

      *data = &seq[2];
      *data_len  = len;
      *field_len = 1 + (1) + len;
      return CKR_OK;
   }

   length_octets = seq[1] & 0x7F;

   if (length_octets == 1) {
      len = seq[2];

      *data = &seq[3];
      *data_len  = len;
      *field_len = 1 + (1 + 1) + len;
      return CKR_OK;
   }

   if (length_octets == 2) {
      len = seq[2];
      len = len << 8;
      len |= seq[3];

      *data = &seq[4];
      *data_len  = len;
      *field_len = 1 + (1 + 2) + len;
      return CKR_OK;
   }

   if (length_octets == 3) {
      len = seq[2];
      len = len << 8;
      len |= seq[3];
      len = len << 8;
      len |= seq[4];

      *data = &seq[5];
      *data_len  = len;
      *field_len = 1 + (1 + 3) + len;
      return CKR_OK;
   }

   // > 3 length octets implies a length > 16MB
   //
   TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
   return CKR_FUNCTION_FAILED;
}



// PrivateKeyInfo ::= SEQUENCE {
//    version  Version  -- always '0' for now
//    privateKeyAlgorithm PrivateKeyAlgorithmIdentifier
//    privateKey  PrivateKey
//    attributes
// }
//
CK_RV
ber_encode_PrivateKeyInfo( CK_BBOOL    length_only,
                           CK_BYTE  ** data,
                           CK_ULONG  * data_len,
                           CK_BYTE   * algorithm_id,
                           CK_ULONG    algorithm_id_len,
                           CK_BYTE   * priv_key,
                           CK_ULONG    priv_key_len )
{
   CK_BYTE  * buf = NULL;
   CK_BYTE  * tmp = NULL;
   CK_BYTE    version[] = { 0 };
   CK_ULONG   len, total;
   CK_RV      rc;

   len = 0;

   rc = ber_encode_INTEGER( TRUE, NULL, &total, version, sizeof(version) );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_encode_INTEGER failed\n");
      return rc;
   }
   else
      len += total;

   len += algorithm_id_len;

   rc = ber_encode_OCTET_STRING( TRUE, NULL, &total, priv_key, priv_key_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_encode_OCTET_STRING failed\n");
      return rc;
   }
   else
      len += total;

   // for this stuff, attributes can be suppressed.
   //

   if (length_only == TRUE) {
      rc = ber_encode_SEQUENCE( TRUE, NULL, &total, NULL, len );

      if (rc == CKR_OK)
         *data_len = total;
      if (rc != CKR_OK)
         TRACE_DEVEL("ber_encode_SEQUENCE failed\n");
      return rc;
   }

   buf = (CK_BYTE *)malloc(len);
   if (!buf){
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      return CKR_HOST_MEMORY;
   }
   len = 0;
   rc = ber_encode_INTEGER( FALSE, &tmp, &total, version, sizeof(version) );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_encode_INTEGER failed\n");
      goto error;
   }
   memcpy( buf+len, tmp, total );
   len += total;
   free( tmp );

   memcpy( buf+len, algorithm_id, algorithm_id_len );
   len += algorithm_id_len;

   rc = ber_encode_OCTET_STRING( FALSE, &tmp, &total, priv_key, priv_key_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_encode_OCTET_STRING failed\n");
      goto error;
   }
   memcpy( buf+len, tmp, total );
   len += total;
   free( tmp );

   rc = ber_encode_SEQUENCE( FALSE, data, data_len, buf, len );
   if (rc != CKR_OK)
      TRACE_DEVEL("ber_encode_SEQUENCE failed\n");

error:
   free( buf );
   return rc;
}


//
//
CK_RV
ber_decode_PrivateKeyInfo( CK_BYTE   * data,
                           CK_ULONG    data_len,
                           CK_BYTE  ** algorithm,
                           CK_ULONG  * alg_len,
                           CK_BYTE  ** priv_key )
{
   CK_BYTE  *buf = NULL;
   CK_BYTE  *alg = NULL;
   CK_BYTE  *ver = NULL;
   CK_ULONG  buf_len, offset, len, field_len;
   CK_RV     rc;

   if (!data || (data_len == 0)){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }
   rc = ber_decode_SEQUENCE( data, &buf, &buf_len, &field_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_decode_SEQUENCE failed\n");
      return rc;
   }
   // version -- we just ignore this
   //
   offset = 0;
   rc = ber_decode_INTEGER( buf+offset, &ver, &len, &field_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_decode_INTEGER failed\n");
      return rc;
   }
   offset += field_len;

   // 'buf' is now pointing to the PrivateKeyAlgorithmIdentifier
   //
   rc = ber_decode_SEQUENCE( buf+offset, &alg, &len, &field_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_decode_SEQUENCE failed\n");
      return rc;
   }
   *algorithm = alg;
   *alg_len   = len;

   rc = ber_decode_OCTET_STRING( alg + len, priv_key, &buf_len, &field_len );
   if (rc != CKR_OK)
      TRACE_DEVEL("ber_decode_OCTET_STRING failed\n");
   return rc;
}


// RSAPrivateKey ::= SEQUENCE {
//    version  Version  -- always '0' for now
//    modulus  INTEGER
//    publicExponent  INTEGER
//    if secure key
//       opaque  OCTET_STRING
//    else
//       privateExponent INTEGER
//       prime1  INTEGER
//       prime2  INTEGER
//       exponent1  INTEGER
//       exponent2  INTEGER
//       coefficient INTEGER
// }
//
CK_RV
ber_encode_RSAPrivateKey( CK_BBOOL    length_only,
                          CK_BYTE  ** data,
                          CK_ULONG  * data_len,
                          CK_ATTRIBUTE * modulus,
                          CK_ATTRIBUTE * publ_exp,
                          CK_ATTRIBUTE * priv_exp,
                          CK_ATTRIBUTE * prime1,
                          CK_ATTRIBUTE * prime2,
                          CK_ATTRIBUTE * exponent1,
                          CK_ATTRIBUTE * exponent2,
                          CK_ATTRIBUTE * coeff,
                          CK_ATTRIBUTE * opaque )

{
   CK_BYTE   *buf = NULL;
   CK_BYTE   *buf2 = NULL;
   CK_ULONG   len, offset;
   CK_BYTE    version[] = { 0 };
   CK_RV      rc;


   offset = 0;
   rc = 0;

   rc |= ber_encode_INTEGER( TRUE, NULL, &len, NULL,         sizeof(version) ); offset += len;
   rc |= ber_encode_INTEGER( TRUE, NULL, &len, NULL,   modulus->ulValueLen ); offset += len;
   rc |= ber_encode_INTEGER( TRUE, NULL, &len, NULL,  publ_exp->ulValueLen ); offset += len;
   if (opaque != NULL) {
      rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, opaque->ulValueLen); offset += len;
   } else {
      rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, priv_exp->ulValueLen); offset += len;
      rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, prime1->ulValueLen); offset += len;
      rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, prime2->ulValueLen); offset += len;
      rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, exponent1->ulValueLen); offset += len;
      rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, exponent2->ulValueLen); offset += len;
      rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, coeff->ulValueLen); offset += len;
   }

   if (rc != CKR_OK){
      TRACE_DEVEL("ber_encode_INTEGER failed\n");
      return CKR_FUNCTION_FAILED;
   }
   if (length_only == TRUE) {
      rc = ber_encode_SEQUENCE( TRUE, NULL, &len, NULL, offset );
      if (rc != CKR_OK){
         TRACE_DEVEL("ber_encode_SEQUENCE failed\n");
         return rc;
      }
      rc = ber_encode_PrivateKeyInfo( TRUE,
                                      NULL, data_len,
                                      NULL, ber_AlgIdRSAEncryptionLen,
                                      NULL, len );
      if (rc != CKR_OK){
         TRACE_DEVEL("ber_encode_PrivateKeyInfo failed\n");
         return rc;
      }
      return rc;
   }

   buf = (CK_BYTE *)malloc(offset);
   if (!buf){
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      return CKR_HOST_MEMORY;
   }
   offset = 0;
   rc = 0;

   rc = ber_encode_INTEGER( FALSE, &buf2, &len, version, sizeof(version) );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_encode_INTEGER failed\n");
      goto error;
   }
   memcpy( buf+offset, buf2, len );
   offset += len;
   free( buf2 );
   buf2 = NULL;

   rc = ber_encode_INTEGER( FALSE, &buf2, &len, (CK_BYTE *)modulus + sizeof(CK_ATTRIBUTE), modulus->ulValueLen );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_encode_INTEGER failed\n");
      goto error;
   }
   memcpy( buf+offset, buf2, len );
   offset += len;
   free( buf2 );
   buf2 = NULL;

   rc = ber_encode_INTEGER( FALSE, &buf2, &len, (CK_BYTE *)publ_exp + sizeof(CK_ATTRIBUTE), publ_exp->ulValueLen );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_encode_INTEGER failed\n");
      goto error;
   }
   memcpy( buf+offset, buf2, len );
   offset += len;
   free( buf2 );
   buf2 = NULL;

   if (opaque != NULL) {
      // the CKA_IBM_OPAQUE attrib
      rc = ber_encode_OCTET_STRING( FALSE, &buf2, &len, (CK_BYTE *)opaque + sizeof(CK_ATTRIBUTE), opaque->ulValueLen );
      if (rc != CKR_OK){
         TRACE_DEVEL("ber_encode_OCTET_STRING failed\n");
         goto error;
      }
      memcpy( buf+offset, buf2, len );
      offset += len;
      free( buf2 );
      buf2 = NULL;
   } else {
      rc = ber_encode_INTEGER( FALSE, &buf2, &len, (CK_BYTE *)priv_exp  + sizeof(CK_ATTRIBUTE),  priv_exp->ulValueLen );
      if (rc != CKR_OK){
         TRACE_DEVEL("ber_encode_INTEGER failed\n");
         goto error;
      }
      memcpy( buf+offset, buf2, len );
      offset += len;
      free( buf2 );
      buf2 = NULL;

      rc = ber_encode_INTEGER( FALSE, &buf2, &len, (CK_BYTE *)prime1    + sizeof(CK_ATTRIBUTE),    prime1->ulValueLen );
      if (rc != CKR_OK){
         TRACE_DEVEL("ber_encode_INTEGER failed\n");
         goto error;
      }
      memcpy( buf+offset, buf2, len );
      offset += len;
      free( buf2 );
      buf2 = NULL;

      rc = ber_encode_INTEGER( FALSE, &buf2, &len, (CK_BYTE *)prime2    + sizeof(CK_ATTRIBUTE),    prime2->ulValueLen );
      if (rc != CKR_OK){
         TRACE_DEVEL("ber_encode_INTEGER failed\n");
         goto error;
      }
      memcpy( buf+offset, buf2, len );
      offset += len;
      free( buf2 );
      buf2 = NULL;

      rc = ber_encode_INTEGER( FALSE, &buf2, &len, (CK_BYTE *)exponent1 + sizeof(CK_ATTRIBUTE), exponent1->ulValueLen );
      if (rc != CKR_OK){
         TRACE_DEVEL("ber_encode_INTEGER failed\n");
         goto error;
      }
      memcpy( buf+offset, buf2, len );
      offset += len;
      free( buf2 );
      buf2 = NULL;

      rc = ber_encode_INTEGER( FALSE, &buf2, &len, (CK_BYTE *)exponent2 + sizeof(CK_ATTRIBUTE), exponent2->ulValueLen );
      if (rc != CKR_OK){
         TRACE_DEVEL("ber_encode_INTEGER failed\n");
         goto error;
      }
      memcpy( buf+offset, buf2, len );
      offset += len;
      free( buf2 );
      buf2 = NULL;

      rc = ber_encode_INTEGER( FALSE, &buf2, &len, (CK_BYTE *)coeff     + sizeof(CK_ATTRIBUTE),     coeff->ulValueLen );
      if (rc != CKR_OK){
         TRACE_DEVEL("ber_encode_INTEGER failed\n");
         goto error;
      }
      memcpy( buf+offset, buf2, len );
      offset += len;
      free( buf2 );
      buf2 = NULL;
   }

   rc = ber_encode_SEQUENCE( FALSE, &buf2, &len, buf, offset );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_encode_SEQUENCE failed\n");
      goto error;
   }
   rc = ber_encode_PrivateKeyInfo( FALSE,
                                   data,   data_len,
                                   ber_AlgIdRSAEncryption, ber_AlgIdRSAEncryptionLen,
                                   buf2,  len );
   if (rc != CKR_OK) {
      TRACE_ERROR("ber_encode_PrivateKeyInfo failed\n");
   }
error:
   if (buf2) free( buf2 );
   if (buf)  free( buf );
   return rc;
}


//
//
CK_RV
ber_decode_RSAPrivateKey( CK_BYTE    * data,
                          CK_ULONG     data_len,
                          CK_ATTRIBUTE ** modulus,
                          CK_ATTRIBUTE ** publ_exp,
                          CK_ATTRIBUTE ** priv_exp,
                          CK_ATTRIBUTE ** prime1,
                          CK_ATTRIBUTE ** prime2,
                          CK_ATTRIBUTE ** exponent1,
                          CK_ATTRIBUTE ** exponent2,
                          CK_ATTRIBUTE ** coeff,
                          CK_ATTRIBUTE ** opaque,
			  CK_BBOOL     isopaque )
{
   CK_ATTRIBUTE *n_attr = NULL;
   CK_ATTRIBUTE *e_attr = NULL;
   CK_ATTRIBUTE *d_attr = NULL;
   CK_ATTRIBUTE *p_attr = NULL;
   CK_ATTRIBUTE *q_attr = NULL;
   CK_ATTRIBUTE *e1_attr = NULL;
   CK_ATTRIBUTE *e2_attr = NULL;
   CK_ATTRIBUTE *coeff_attr = NULL;
   CK_ATTRIBUTE *o_attr = NULL;

   CK_BYTE  *alg          = NULL;
   CK_BYTE  *rsa_priv_key = NULL;
   CK_BYTE  *buf          = NULL;
   CK_BYTE  *tmp          = NULL;
   CK_ULONG  offset, buf_len, field_len, len;
   CK_RV     rc;

   rc = ber_decode_PrivateKeyInfo( data, data_len, &alg, &len, &rsa_priv_key );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_decode_PrivateKeyInfo failed\n");
      return rc;
   }
   // make sure we're dealing with an RSA key
   //
   if (memcmp(alg, ber_rsaEncryption, ber_rsaEncryptionLen) != 0){
      TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
      return CKR_FUNCTION_FAILED;  // probably ought to use a different error
   }
   rc = ber_decode_SEQUENCE( rsa_priv_key, &buf, &buf_len, &field_len );
   if (rc != CKR_OK)
      return rc;

   // parse the RSAPrivateKey
   //
   offset = 0;

   // Version
   //
   rc = ber_decode_INTEGER( buf+offset, &tmp, &len, &field_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_decode_INTEGER failed\n");
      goto cleanup;
   }
   offset += field_len;

   // modulus
   //
   rc = ber_decode_INTEGER( buf+offset, &tmp, &len, &field_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_decode_INTEGER failed\n");
      goto cleanup;
   }
   offset += field_len;

   // public exponent
   //
   rc = ber_decode_INTEGER( buf+offset, &tmp, &len, &field_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_decode_INTEGER failed\n");
      goto cleanup;
   }
   offset += field_len;

   if (isopaque) {
      // opaque attribute, the CCA key
      //
      rc = ber_decode_OCTET_STRING( buf+offset, &tmp, &len, &field_len );
      if (rc != CKR_OK){
         TRACE_DEVEL("ber_decode_OCTET_STRING failed\n");
         goto cleanup;
      }
      offset += field_len;
   } else {

     // private exponent
     //
     rc = ber_decode_INTEGER( buf+offset, &tmp, &len, &field_len );
     if (rc != CKR_OK){
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
     }
     offset += field_len;

     // prime #1
     //
     rc = ber_decode_INTEGER( buf+offset, &tmp, &len, &field_len );
     if (rc != CKR_OK){
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
     }
     offset += field_len;

     // prime #2
     //
     rc = ber_decode_INTEGER( buf+offset, &tmp, &len, &field_len );
     if (rc != CKR_OK){
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
     }
     offset += field_len;

     // exponent #1
     //
     rc = ber_decode_INTEGER( buf+offset, &tmp, &len, &field_len );
     if (rc != CKR_OK){
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
     }
     offset += field_len;

     // exponent #2
     //
     rc = ber_decode_INTEGER( buf+offset, &tmp, &len, &field_len );
     if (rc != CKR_OK){
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
     }
     offset += field_len;

     // coefficient
     //
     rc = ber_decode_INTEGER( buf+offset, &tmp, &len, &field_len );
     if (rc != CKR_OK){
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
     }
     offset += field_len;

     if (offset > buf_len){
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
     }
   }

   //
   // it looks okay.  build the attributes
   //

   offset = 0;

   // skip the version
   //
   rc = ber_decode_INTEGER( buf+offset, &tmp, &len, &field_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_decode_INTEGER failed\n");
      goto cleanup;
   }
   offset += field_len;

   // modulus
   //
   rc = ber_decode_INTEGER( buf+offset, &tmp, &len, &field_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_decode_INTEGER failed\n");
      goto cleanup;
   }
   else {
      rc = build_attribute( CKA_MODULUS, tmp, len, &n_attr );
      if (rc != CKR_OK){
         TRACE_DEVEL("build_attribute failed\n");
         goto cleanup;
      }
      offset += field_len;
   }

   // public exponent
   //
   rc = ber_decode_INTEGER( buf+offset, &tmp, &len, &field_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_decode_INTEGER failed\n");
      goto cleanup;
   }
   else {
      rc = build_attribute( CKA_PUBLIC_EXPONENT, tmp, len, &e_attr );
      if (rc != CKR_OK){
         TRACE_DEVEL("build_attribute failed\n");
         goto cleanup;
      }
      offset += field_len;
   }

   if (isopaque) {
      // opaque attribute, the CCA key
      //
      rc = ber_decode_OCTET_STRING( buf+offset, &tmp, &len, &field_len );
      if (rc != CKR_OK){
         TRACE_DEVEL("ber_decode_OCTET_STRING failed\n");
         goto cleanup;
      }
      else {
         rc = build_attribute( CKA_IBM_OPAQUE, tmp, len, &o_attr );
         if (rc != CKR_OK){
            TRACE_DEVEL("build_attribute failed\n");
            goto cleanup;
         }
         offset += field_len;
      }
      *opaque    = o_attr;
   } else {
      // private exponent
      //
      rc = ber_decode_INTEGER( buf+offset, &tmp, &len, &field_len );
      if (rc != CKR_OK){
         TRACE_DEVEL("ber_decode_INTEGER failed\n");
         goto cleanup;
      }
      else {
         rc = build_attribute( CKA_PRIVATE_EXPONENT, tmp, len, &d_attr );
         if (rc != CKR_OK){
            TRACE_DEVEL("build_attribute failed\n");
            goto cleanup;
         }
         offset += field_len;
      }

      // prime #1
      //
      rc = ber_decode_INTEGER( buf+offset, &tmp, &len, &field_len );
      if (rc != CKR_OK){
         TRACE_DEVEL("ber_decode_INTEGER failed\n");
         goto cleanup;
      }
      else {
         rc = build_attribute( CKA_PRIME_1, tmp, len, &p_attr );
         if (rc != CKR_OK){
            TRACE_DEVEL("build_attribute failed\n");
            goto cleanup;
         }
         offset += field_len;
      }

      // prime #2
      //
      rc = ber_decode_INTEGER( buf+offset, &tmp, &len, &field_len );
      if (rc != CKR_OK){
         TRACE_DEVEL("ber_decode_INTEGER failed\n");
         goto cleanup;
      }
      else {
         rc = build_attribute( CKA_PRIME_2, tmp, len, &q_attr );
         if (rc != CKR_OK){
            TRACE_DEVEL("build_attribute failed\n");
            goto cleanup;
         }
         offset += field_len;
      }

      // exponent #1
      //
      rc = ber_decode_INTEGER( buf+offset, &tmp, &len, &field_len );
      if (rc != CKR_OK){
         TRACE_DEVEL("ber_decode_INTEGER failed\n");
         goto cleanup;
      }
      else {
         rc = build_attribute( CKA_EXPONENT_1, tmp, len, &e1_attr );
         if (rc != CKR_OK){
            TRACE_DEVEL("build_attribute failed\n");
            goto cleanup;
         }
         offset += field_len;
      }

      // exponent #2
      //
      rc = ber_decode_INTEGER( buf+offset, &tmp, &len, &field_len );
      if (rc != CKR_OK){
         TRACE_DEVEL("ber_decode_INTEGER failed\n");
         goto cleanup;
      }
      else {
         rc = build_attribute( CKA_EXPONENT_2, tmp, len, &e2_attr );
         if (rc != CKR_OK){
            TRACE_DEVEL("build_attribute failed\n");
            goto cleanup;
         }
         offset += field_len;
      }

      // coefficient
      //
      rc = ber_decode_INTEGER( buf+offset, &tmp, &len, &field_len );
      if (rc != CKR_OK){
         TRACE_DEVEL("ber_decode_INTEGER failed\n");
         goto cleanup;
      }
      else {
         rc = build_attribute( CKA_COEFFICIENT, tmp, len, &coeff_attr );
         if (rc != CKR_OK){
            TRACE_DEVEL("build_attribute failed\n");
            goto cleanup;
         }
         offset += len;
      }
      *priv_exp  = d_attr;
      *prime1    = p_attr;
      *prime2    = q_attr;
      *exponent1 = e1_attr;
      *exponent2 = e2_attr;
      *coeff     = coeff_attr;
   }

      *modulus   = n_attr;
      *publ_exp  = e_attr;

   return CKR_OK;

cleanup:
   if (n_attr)     free(n_attr);
   if (e_attr)     free(e_attr);
   if (isopaque) {
      if (o_attr)     free(o_attr);
   } else {
      if (d_attr)     free(d_attr);
      if (p_attr)     free(p_attr);
      if (q_attr)     free(q_attr);
      if (e1_attr)    free(e1_attr);
      if (e2_attr)    free(e2_attr);
      if (coeff_attr) free(coeff_attr);
   }

   return rc;
}


// DSA is a little different from RSA
//
// DSAPrivateKey ::= INTEGER
//
// The 'parameters' field of the AlgorithmIdentifier are as follows:
//
// DSSParameters ::= SEQUENCE {
//    prime1  INTEGER
//    prime2  INTEGER
//    base    INTEGER
// }
//
CK_RV
ber_encode_DSAPrivateKey( CK_BBOOL    length_only,
                          CK_BYTE  ** data,
                          CK_ULONG  * data_len,
                          CK_ATTRIBUTE * prime1,
                          CK_ATTRIBUTE * prime2,
                          CK_ATTRIBUTE * base,
                          CK_ATTRIBUTE * priv_key )
{
   CK_BYTE  *param = NULL;
   CK_BYTE  *buf = NULL;
   CK_BYTE  *tmp = NULL;
   CK_BYTE  *alg = NULL;
   CK_ULONG  offset, len, param_len;
   CK_ULONG  alg_len;
   CK_RV     rc;


   // build the DSS parameters first
   //
   offset = 0;
   rc = 0;

   rc |= ber_encode_INTEGER( TRUE, NULL, &len, NULL, prime1->ulValueLen );  offset += len;
   rc |= ber_encode_INTEGER( TRUE, NULL, &len, NULL, prime2->ulValueLen );  offset += len;
   rc |= ber_encode_INTEGER( TRUE, NULL, &len, NULL, base->ulValueLen   );  offset += len;

   if (rc != CKR_OK){
      TRACE_DEVEL("ber_encode_INTEGER failed\n");
      return CKR_FUNCTION_FAILED;
   }
   if (length_only == TRUE) {
      rc = ber_encode_SEQUENCE( TRUE, NULL, &param_len, NULL, offset );
      if (rc != CKR_OK){
         TRACE_DEVEL("ber_encode_SEQUENCE failed\n");
         return rc;
      }
      rc = ber_encode_INTEGER( TRUE, NULL, &len, NULL, priv_key->ulValueLen );
      if (rc != CKR_OK){
         TRACE_DEVEL("ber_encode_INTEGER failed\n");
         return rc;
      }
      rc = ber_encode_PrivateKeyInfo( TRUE,
                                      NULL,  data_len,
                                      NULL,  ber_idDSALen + param_len,
                                      NULL,  len );
      if (rc != CKR_OK){
         TRACE_DEVEL("ber_encode_PrivateKeyInfo failed\n");
      }
      return rc;
   }

   // 'buf' will be the sequence data for the AlgorithmIdentifyer::parameter
   //
   buf = (CK_BYTE *)malloc(offset);
   if (!buf){
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      return CKR_HOST_MEMORY;
   }
   len = 0;
   offset = 0;

   rc = ber_encode_INTEGER( FALSE, &tmp, &len, (CK_BYTE *)prime1 + sizeof(CK_ATTRIBUTE), prime1->ulValueLen );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_encode_INTEGER failed\n");
      goto error;
   }
   memcpy( buf+offset, tmp, len );
   offset += len;
   free( tmp );
   tmp = NULL;

   rc = ber_encode_INTEGER( FALSE, &tmp, &len, (CK_BYTE *)prime2 + sizeof(CK_ATTRIBUTE), prime2->ulValueLen );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_encode_INTEGER failed\n");
      goto error;
   }
   memcpy( buf+offset, tmp, len );
   offset += len;
   free( tmp );
   tmp = NULL;

   rc = ber_encode_INTEGER( FALSE, &tmp, &len, (CK_BYTE *)base   + sizeof(CK_ATTRIBUTE), base->ulValueLen   );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_encode_INTEGER failed\n");
      goto error;
   }
   memcpy( buf+offset, tmp, len );
   offset += len;
   free( tmp );
   tmp = NULL;

   rc = ber_encode_SEQUENCE( FALSE, &param, &param_len, buf, offset );
   if (rc != CKR_OK) {
      TRACE_DEVEL("ber_encode_SEQUENCE failed\n");
      free(buf);
      return rc;
   }

   free( buf );
   buf = NULL;

   // Build the DSA AlgorithmIdentifier
   //
   // AlgorithmIdentifier ::= SEQUENCE {
   //    algorithm  OBJECT IDENTIFIER
   //    parameters ANY DEFINED BY algorithm OPTIONAL
   // }
   //
   len = ber_idDSALen + param_len;
   buf = (CK_BYTE *)malloc( len );
   if (!buf){
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      goto error;
   }
   memcpy( buf,                ber_idDSA, ber_idDSALen );
   memcpy( buf + ber_idDSALen, param,     param_len    );

   free( param );
   param = NULL;

   rc = ber_encode_SEQUENCE( FALSE, &alg, &alg_len, buf, len );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_encode_SEQUENCE failed\n");
      goto error;
   }
   free( buf );
   buf = NULL;

   // build the private key INTEGER
   //
   rc = ber_encode_INTEGER( FALSE, &buf, &len, (CK_BYTE *)priv_key + sizeof(CK_ATTRIBUTE), priv_key->ulValueLen );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_encode_INTEGER failed\n");
      goto error;
   }

   rc = ber_encode_PrivateKeyInfo( FALSE,
                                   data,    data_len,
                                   alg,     alg_len,
                                   buf,     len );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_encode_PrivateKeyInfo failed\n");
      goto error;
   }

error:
   if (alg)   free( alg );
   if (buf)   free( buf );
   if (param) free( param );
   if (tmp)   free( tmp );

   return rc;
}


//
//
CK_RV
ber_decode_DSAPrivateKey( CK_BYTE     * data,
                          CK_ULONG      data_len,
                          CK_ATTRIBUTE  ** prime,
                          CK_ATTRIBUTE  ** subprime,
                          CK_ATTRIBUTE  ** base,
                          CK_ATTRIBUTE  ** priv_key )
{
   CK_ATTRIBUTE  *p_attr = NULL;
   CK_ATTRIBUTE  *q_attr = NULL;
   CK_ATTRIBUTE  *g_attr = NULL;
   CK_ATTRIBUTE  *x_attr = NULL;
   CK_BYTE    *alg    = NULL;
   CK_BYTE    *buf    = NULL;
   CK_BYTE    *dsakey = NULL;
   CK_BYTE    *tmp    = NULL;
   CK_ULONG    buf_len, field_len, len, offset;
   CK_RV       rc;


   rc = ber_decode_PrivateKeyInfo( data, data_len, &alg, &len, &dsakey );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_decode_PrivateKeyInfo failed\n");
      return rc;
   }

   // make sure we're dealing with a DSA key.  just compare the OBJECT
   // IDENTIFIER
   //
   if (memcmp(alg, ber_idDSA, ber_idDSALen) != 0){
      TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
      return CKR_FUNCTION_FAILED;
   }

   // extract the parameter data into ATTRIBUTES
   //
   rc = ber_decode_SEQUENCE( alg + ber_idDSALen, &buf, &buf_len, &field_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_decode_SEQUENCE failed\n");
      return rc;
   }
   offset = 0;

   // prime
   //
   rc = ber_decode_INTEGER( buf+offset, &tmp, &len, &field_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_decode_INTEGER failed\n");
      goto cleanup;
   }
   offset += field_len;

   // subprime
   //
   rc = ber_decode_INTEGER( buf+offset, &tmp, &len, &field_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_decode_INTEGER failed\n");
      goto cleanup;
   }
   offset += field_len;

   // base
   //
   rc = ber_decode_INTEGER( buf+offset, &tmp, &len, &field_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_decode_INTEGER failed\n");
      goto cleanup;
   }
   offset += field_len;

   if (offset > buf_len){
      TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
      return CKR_FUNCTION_FAILED;
   }
   //
   // it looks okay.  build the attributes
   //

   offset = 0;

   // prime
   //
   rc = ber_decode_INTEGER( buf+offset, &tmp, &len, &field_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_decode_INTEGER failed\n");
      goto cleanup;
   }
   else {
      rc = build_attribute( CKA_PRIME, tmp, len, &p_attr );
      if (rc != CKR_OK){
         TRACE_DEVEL("build_attribute failed\n");
         goto cleanup;
      }
      offset += field_len;
   }

   // subprime
   //
   rc = ber_decode_INTEGER( buf+offset, &tmp, &len, &field_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_decode_INTEGER failed\n");
      goto cleanup;
   }
   else {
      rc = build_attribute( CKA_SUBPRIME, tmp, len, &q_attr );
      if (rc != CKR_OK){
         TRACE_DEVEL("build_attribute failed\n");
         goto cleanup;
      }
      offset += field_len;
   }

   // base
   //
   rc = ber_decode_INTEGER( buf+offset, &tmp, &len, &field_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_decode_INTEGER failed\n");
      goto cleanup;
   }
   else {
      rc = build_attribute( CKA_BASE, tmp, len, &g_attr );
      if (rc != CKR_OK){
         TRACE_DEVEL("build_attribute failed\n");
         goto cleanup;
      }
      offset += field_len;
   }

   // now get the private key
   //
   rc = ber_decode_INTEGER( dsakey, &tmp, &len, &field_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("ber_decode_INTEGER failed\n");
      goto cleanup;
   }
   else {
      rc = build_attribute( CKA_VALUE, tmp, len, &x_attr );
      if (rc != CKR_OK){
         TRACE_DEVEL("build_attribute failed\n");
         goto cleanup;
      }
      offset += field_len;
   }

   *prime = p_attr;
   *subprime = q_attr;
   *base = g_attr;
   *priv_key = x_attr;

   return CKR_OK;

cleanup:
   if (p_attr)  free(p_attr);
   if (q_attr)  free(q_attr);
   if (g_attr)  free(g_attr);
   if (x_attr)  free(x_attr);

   return rc;
}
