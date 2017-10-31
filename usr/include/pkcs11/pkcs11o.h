 /*
  * COPYRIGHT (c) International Business Machines Corp. 2001-2017
  *
  * This program is provided under the terms of the Common Public License,
  * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
  * software constitutes recipient's acceptance of CPL-1.0 terms which can be
  * found in the file LICENSE file or at
  * https://opensource.org/licenses/cpl1.0.php
  */

#ifndef _PKCS11OBJECTS_H
#define _PKCS11OBJECTS_H

#include "pkcs11types.h"

#define SC_CLASS          0x00
#define SC_TOKEN          0x01
#define SC_PRIVATE        0x02
#define SC_MODIFIABLE     0x03
#define SC_LABEL          0x04

#define SC_KEY_TYPE       0x05
#define SC_KEY_ID         0x06
#define SC_KEY_START      0x07
#define SC_KEY_END        0x08
#define SC_KEY_DERIVE     0x09
#define SC_KEY_LOCAL      0x10

typedef union SC_OBJECT {
   struct {
      CK_ATTRIBUTE         class;        /* Object type                      */
      CK_ATTRIBUTE         token;        /* True for token object            */
      CK_ATTRIBUTE         bPrivate;     /* True for private objects         */
      CK_ATTRIBUTE         bModifiable;  /* True if can be modified          */
      CK_ATTRIBUTE         label;        /* Description of the object        */
      CK_ATTRIBUTE         application;  /* Description of the managing app  */
      CK_ATTRIBUTE         value;        /* Value of the object              */
   } Data;

   struct {
      CK_ATTRIBUTE         class;        /* Object type                      */
      CK_ATTRIBUTE         token;        /* True for token object            */
      CK_ATTRIBUTE         bPrivate;     /* True for private objects         */
      CK_ATTRIBUTE         bModifiable;  /* True if can be modified          */
      CK_ATTRIBUTE         label;        /* Description of the object        */
      CK_ATTRIBUTE         type;         /* Type of Certificate              */
      CK_ATTRIBUTE         subject;     /* DER encoded subject name         */
      CK_ATTRIBUTE         id;          /* Key identifier for key pair      */
      CK_ATTRIBUTE         issuer;      /* DER encoded issuer name          */
      CK_ATTRIBUTE         serial;      /* DER encoded serial number        */
      CK_ATTRIBUTE         value;       /* BER encoding of the certificate  */
   } Cert;

   struct {
      CK_ATTRIBUTE         class;        /* Object type                      */
      CK_ATTRIBUTE         token;        /* True for token object            */
      CK_ATTRIBUTE         bPrivate;     /* True for private objects         */
      CK_ATTRIBUTE         bModifiable;  /* True if can be modified          */
      CK_ATTRIBUTE         label;        /* Description of the object        */

      CK_ATTRIBUTE         type;         /* Type of Key                      */
      CK_ATTRIBUTE         id;           /* Key identifier for the key       */
      CK_ATTRIBUTE         start;        /* Start date for the key           */
      CK_ATTRIBUTE         end;          /* End date for the key             */
      CK_ATTRIBUTE         derive;       /* TRUE: keys can be derived from   */
      CK_ATTRIBUTE         local;        /* Generated locally                */

      CK_ATTRIBUTE         subject;      /* DER encoded key subject name     */
      CK_ATTRIBUTE         encrypt;      /* TRUE: can encrypt                */
      CK_ATTRIBUTE         verify;       /* TRUE: sign is an appendix        */
      CK_ATTRIBUTE         v_recover;    /* TRUE: verify where data in sign  */
      CK_ATTRIBUTE         wrap;         /* TRUE: if can wrap other keys     */
      CK_ATTRIBUTE         modulus;      /* Modulus n                        */
      CK_ATTRIBUTE         length;       /* Length in bits of modulus n      */
      CK_ATTRIBUTE         exponent;     /* Public Exponent e                */
   } PubKey;

   struct {
      CK_ATTRIBUTE         class;        /* Object type                      */
      CK_ATTRIBUTE         token;        /* True for token object            */
      CK_ATTRIBUTE         bPrivate;     /* True for private objects         */
      CK_ATTRIBUTE         bModifiable;  /* True if can be modified          */
      CK_ATTRIBUTE         label;        /* Description of the object        */

      CK_ATTRIBUTE         type;         /* Type of Key                      */
      CK_ATTRIBUTE         id;           /* Key identifier for the key       */
      CK_ATTRIBUTE         start;        /* Start date for the key           */
      CK_ATTRIBUTE         end;          /* End date for the key             */
      CK_ATTRIBUTE         derive;       /* TRUE: keys can be derived from   */
      CK_ATTRIBUTE         local;        /* Generated locally                */

      CK_ATTRIBUTE         subject;      /* DER encoded key subject name     */
      CK_ATTRIBUTE         sensitive;    /* TRUE: key is sensitive           */
      CK_ATTRIBUTE         decrypt;      /* TRUE: can decrypt                */
      CK_ATTRIBUTE         sign;         /* TRUE: sign as an appendix        */
      CK_ATTRIBUTE         s_recover;    /* TRUE: verify where data in sign  */
      CK_ATTRIBUTE         unwrap;       /* TRUE: if can unwrap other keys   */
      CK_ATTRIBUTE         extractable;  /* TRUE: can be extracted           */
      CK_ATTRIBUTE         always_sens;  /* TRUE: if sensitive always been T */
      CK_ATTRIBUTE         never_extract;/* TRUE: if extractable never set T */
      CK_ATTRIBUTE         modulus;     /* Modulus n                        */
      CK_ATTRIBUTE         pub_exp;     /* Public Exponent e                */
      CK_ATTRIBUTE         priv_exp;    /* Public Exponent d                */
      CK_ATTRIBUTE         prime1;      /* Prime p                          */
      CK_ATTRIBUTE         prime2;      /* Prime q                          */
      CK_ATTRIBUTE         exp1;        /* Private Exponent d modulo p-1    */
      CK_ATTRIBUTE         exp2;        /* Private Exponent d modulo q-1    */
      CK_ATTRIBUTE         coefficient; /* CRT coefficient q^(-1) mod p     */
   } PrivKey;

   struct {
      CK_ATTRIBUTE         class;        /* Object type                      */
      CK_ATTRIBUTE         token;        /* True for token object            */
      CK_ATTRIBUTE         bPrivate;     /* True for private objects         */
      CK_ATTRIBUTE         bModifiable;  /* True if can be modified          */
      CK_ATTRIBUTE         label;        /* Description of the object        */

      CK_ATTRIBUTE         type;         /* Type of Key                      */
      CK_ATTRIBUTE         id;           /* Key identifier for the key       */
      CK_ATTRIBUTE         start;        /* Start date for the key           */
      CK_ATTRIBUTE         end;          /* End date for the key             */
      CK_ATTRIBUTE         derive;       /* TRUE: keys can be derived from   */
      CK_ATTRIBUTE         local;        /* Generated locally                */

      CK_ATTRIBUTE         sensitive;    /* TRUE: key is sensitive           */
      CK_ATTRIBUTE         encrypt;      /* TRUE: can encrypt                */
      CK_ATTRIBUTE         decrypt;      /* TRUE: can decrypt                */
      CK_ATTRIBUTE         sign;         /* TRUE: sign as an appendix        */
      CK_ATTRIBUTE         verify;       /* TRUE: sign is an appendix        */
      CK_ATTRIBUTE         wrap;         /* TRUE: if can wrap other keys     */
      CK_ATTRIBUTE         unwrap;       /* TRUE: if can unwrap other keys   */
      CK_ATTRIBUTE         extractable;  /* TRUE: can be extracted           */
      CK_ATTRIBUTE         always_sens;  /* TRUE: if sensitive always been T */
      CK_ATTRIBUTE         never_extract;/* TRUE: if extractable never set T */
      CK_ATTRIBUTE         value;        /* Key value                        */
      CK_ATTRIBUTE         len;          /* Length in bytes of key           */
   } SecretKey;

   CK_ATTRIBUTE         generic[28];  // PrivKey is the largest structure with 28 Attributes
} SC_OBJECT;

typedef SC_OBJECT         * SC_OBJECT_PTR;
typedef struct SC_SESSION_HANDLE * SC_SESSION_HANDLE_PTR;
typedef struct SC_OBJECT_HANDLE  * SC_OBJECT_HANDLE_PTR;

typedef struct SC_SESSION_HANDLE {
   CK_SESSION_HANDLE     session;
   SC_SESSION_HANDLE_PTR next;
} SC_SESSION_HANDLE;

typedef struct SC_OBJECT_HANDLE {
   CK_OBJECT_HANDLE     object;
   SC_OBJECT_HANDLE_PTR next;
} SC_OBJECT_HANDLE;
#endif
