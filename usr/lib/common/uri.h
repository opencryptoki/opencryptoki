/*
 * COPYRIGHT (c) International Business Machines Corp. 2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef __URI_H
#define __URI_H

#include <pkcs11types.h>
#include <buffer.h>

struct p11_uri {
    CK_INFO_PTR info;
    CK_SLOT_ID slot_id;
    CK_SLOT_INFO_PTR slot_info;
    CK_TOKEN_INFO_PTR token_info;
    CK_ATTRIBUTE obj_id[1];
    CK_ATTRIBUTE obj_label[1];
    CK_ATTRIBUTE obj_class[1];
    char *pin_value;
    char *pin_source;
    void *priv;
};

const char *p11_uri_format(struct p11_uri *uri);
struct p11_uri *p11_uri_new(void);
void p11_uri_attributes_free(struct p11_uri *uri);
void p11_uri_free(struct p11_uri *uri);

#endif                          /* __URI_H */
