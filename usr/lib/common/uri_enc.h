/*
 * COPYRIGHT (c) International Business Machines Corp. 2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef __URI_ENC_H
#define __URI_ENC_H

#define URL_UNRES                \
    "abcdefghijklmnopqrstuvwxyz" \
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
    "0123456789_-."

#define P11_URI_UNRES            \
    ":[]@!$\'()*+,="

#define P11_URI_P_UNRES          \
    URL_UNRES                    \
    P11_URI_UNRES                \
    "&"

#define P11_URI_Q_UNRES          \
    URL_UNRES                    \
    P11_URI_UNRES                \
    "/?|"

#endif /* __URI_ENC_H */
