
/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2005 International Business
 * Machines Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Common Public License as published by
 * IBM Corporation; either version 1 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Common Public License for more details.
 *
 * You should have received a copy of the Common Public License
 * along with this program; if not, a copy can be viewed at
 * http://www.opensource.org/licenses/cpl1.0.php.
 */

/* (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2005 */


// File:  mech_rng.c
//
// Mechanisms for Random Numbers
//
// PKCS #11 doesn't consider random number generator to be a "mechanism"
//

//#include <windows.h>

#include <pthread.h>

#include <string.h>            // for memcmp() et al
#include <stdlib.h>

#include "pkcs11/pkcs11types.h"
#include <pkcs11/stdll.h>
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
//#include "args.h"

#include "tok_spec_struct.h"

//
//
CK_RV
rng_generate( CK_BYTE *output, CK_ULONG bytes )
{
   CK_ULONG  req_len, repl_len, expected_repl_len;
   CK_RV     rc;

   rc = token_rng(output, bytes);
   if (rc != CKR_OK)
      st_err_log(111, __FILE__, __LINE__);
   return rc;
}
