 /*
  * COPYRIGHT (c) International Business Machines Corp. 2001-2017
  *
  * This program is provided under the terms of the Common Public License,
  * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
  * software constitutes recipient's acceptance of CPL-1.0 terms which can be
  * found in the file LICENSE file or at
  * https://opensource.org/licenses/cpl1.0.php
  */

#ifndef _STDLL_DECRYPT_H
#define _STDLL_DECRYPT_H

#include <bsafe.h>
#include "stdll_gen.h"

B_ALGORITHM_OBJ         DecryptObj [ CKS_NUMBER_OF_SLOTS   ]
                                   [ CKS_MAX_SESSIONS      ];

B_ALGORITHM_OBJ         BSafe_Algorithm_Object;

B_ALGORITHM_METHOD  *RSA_DECRYPT_CHOOSER[] = {
   &AM_RSA_CRT_DECRYPT,
   (B_ALGORITHM_METHOD *)NULL_PTR};

#endif
