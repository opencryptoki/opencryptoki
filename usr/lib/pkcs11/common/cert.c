/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  cert.c
//
// Functions contained within:
//
//    cert_check_required_attributes
//    cert_validate_attribute
//    cert_x509_check_required_attributes
//    cert_x509_set_default_attributes
//    cert_x509_validate_attribute
//    cert_vendor_check_required_attributes
//    cert_vendor_validate_attribute
//

#include <pthread.h>
#include <stdlib.h>

  #include <string.h>  // for memcmp() et al

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "trace.h"


// cert_check_required_attributes
//
// Checks for required attributes for generic CKO_CERTIFICATE objects
//
//    CKA_CERTIFICATE_TYPE : must be present on MODE_CREATE.
//
CK_RV
cert_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE        * attr = NULL;
   CK_BBOOL              found;

   if (!tmpl)
      return CKR_FUNCTION_FAILED;

   if (mode == MODE_CREATE) {
      found = template_attribute_find( tmpl, CKA_CERTIFICATE_TYPE, &attr );
      if (found == FALSE){
         TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
         return CKR_TEMPLATE_INCOMPLETE;
      }
      // don't bother checking the value.  it was checked in the 'validate'
      // routine.
   }

   return template_check_required_base_attributes( tmpl, mode );
}


// cert_validate_attribute()
//
CK_RV
cert_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   CK_CERTIFICATE_TYPE  type;

   switch (attr->type) {
      case CKA_CERTIFICATE_TYPE:
         {
            if (mode != MODE_CREATE){
               TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
               return CKR_ATTRIBUTE_READ_ONLY;
            }
            type = *(CK_CERTIFICATE_TYPE *)attr->pValue;
            if (type == CKC_X_509 || type >= CKC_VENDOR_DEFINED)
               return CKR_OK;
            else{
               TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
         }
         break;

      default:
         return template_validate_base_attribute( tmpl, attr, mode );
   }
}


// cert_x509_check_required_attributes()
//
CK_RV
cert_x509_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL      found;

   found = template_attribute_find( tmpl, CKA_SUBJECT, &attr );
   if (!found){
      TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
      return CKR_TEMPLATE_INCOMPLETE;
   }
   found = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (!found){
      TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
      return CKR_TEMPLATE_INCOMPLETE;
   }
   return cert_check_required_attributes( tmpl, mode );
}


// cert_x509_set_default_attributes()
//
// Set the default attributes for X.509 certificates
//
//    CKA_ID            : empty string
//    CKA_ISSUER        : empty string
//    CKA_SERIAL_NUMBER : empty string
//
CK_RV
cert_x509_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE * id_attr = NULL;
   CK_ATTRIBUTE * issuer_attr = NULL;
   CK_ATTRIBUTE * serial_attr = NULL;

   // satisfy compiler warning....
   //
   if (mode)
      id_attr = NULL;

   id_attr     = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   issuer_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   serial_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );

   if (!id_attr || !issuer_attr || !serial_attr) {
      if (id_attr)      free( id_attr     );
      if (issuer_attr)  free( issuer_attr );
      if (serial_attr)  free( serial_attr );
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));

      return CKR_HOST_MEMORY;
   }

   id_attr->type            = CKA_ID;
   id_attr->ulValueLen      = 0;   // empty string
   id_attr->pValue          = NULL;

   issuer_attr->type        = CKA_ISSUER;
   issuer_attr->ulValueLen  = 0;   // empty byte array
   issuer_attr->pValue      = NULL;

   serial_attr->type        = CKA_SERIAL_NUMBER;
   serial_attr->ulValueLen  = 0;   // empty byte array
   serial_attr->pValue      = NULL;

   template_update_attribute( tmpl, id_attr     );
   template_update_attribute( tmpl, issuer_attr );
   template_update_attribute( tmpl, serial_attr );

   return CKR_OK;
}


// cert_x509_validate_attributes()
//
CK_RV
cert_x509_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   switch (attr->type) {
      case CKA_SUBJECT:
         if (mode != MODE_CREATE){
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
            return CKR_ATTRIBUTE_READ_ONLY;
         }
         else
            return CKR_OK;

      case CKA_ID:
      case CKA_ISSUER:
      case CKA_SERIAL_NUMBER:
         return CKR_OK;

      case CKA_VALUE:
         if (mode != MODE_CREATE){
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
            return CKR_ATTRIBUTE_READ_ONLY;
         }
         else
            return CKR_OK;

      default:
         return cert_validate_attribute( tmpl, attr, mode );
   }
}


// cert_vendor_check_required_attributes()
//
CK_RV
cert_vendor_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   // CKC_VENDOR has no required attributes
   //
   return cert_check_required_attributes( tmpl, mode );
}


// cert_vendor_validate_attribute()
//
CK_RV
cert_vendor_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   // cryptoki specifies no attributes for CKC_VENDOR certificates
   //
   return cert_validate_attribute( tmpl, attr, mode );
}
