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
#include <string.h>
#include <lber.h>

#include "pkcs11types.h"
#include "p11util.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "trace.h"


//
//
CK_ULONG ber_encode_INTEGER(CK_BBOOL length_only,
                            CK_BYTE **ber_int,
                            CK_ULONG *ber_int_len, CK_BYTE *data,
                            CK_ULONG data_len)
{
    CK_BYTE *buf = NULL;
    CK_ULONG len, padding = 0;

    // ber encoded integers are alway signed. So if the msb of the first byte
    // is set, this would indicate an negative value if we just copy the
    // (unsigned) big integer from *data to the ber buffer. So in this case
    // a preceding 0x00 byte is stored before the actual data. The decode
    // function does the reverse and may skip this padding.

    if ((length_only && data_len && (!data || *data & 0x80))
        || (data_len && data && *data & 0x80))
        padding = 1;

    // if data_len < 127 use short-form length id
    // if data_len < 256 use long-form length id with 1-byte length field
    // if data_len < 65536 use long-form length id with 2-byte length field
    // if data_len < 16777216 use long-form length id with 3-byte length field
    //
    if (data_len + padding < 128) {
        len = 1 + 1 + padding + data_len;
    } else if (data_len + padding < 256) {
        len = 1 + (1 + 1) + padding + data_len;
    } else if (data_len + padding < (1 << 16)) {
        len = 1 + (1 + 2) + padding + data_len;
    } else if (data_len + padding < (1 << 24)) {
        len = 1 + (1 + 3) + padding + data_len;
    } else {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }
    if (length_only == TRUE) {
        *ber_int_len = len;
        return CKR_OK;
    }

    buf = (CK_BYTE *) malloc(len);
    if (!buf) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    if (data_len + padding < 128) {
        buf[0] = 0x02;
        buf[1] = data_len + padding;
        if (padding) {
            buf[2] = 0x00;
            if (data && data_len)
                memcpy(&buf[3], data, data_len);
        } else {
            if (data && data_len)
                memcpy(&buf[2], data, data_len);
        }
        *ber_int_len = len;
        *ber_int = buf;
        return CKR_OK;
    }

    if (data_len + padding < 256) {
        buf[0] = 0x02;
        buf[1] = 0x81;
        buf[2] = data_len + padding;
        if (padding) {
            buf[3] = 0x00;
            if (data && data_len)
                memcpy(&buf[4], data, data_len);
        } else {
            if (data && data_len)
                memcpy(&buf[3], data, data_len);
        }
        *ber_int_len = len;
        *ber_int = buf;
        return CKR_OK;
    }

    if (data_len + padding < (1 << 16)) {
        buf[0] = 0x02;
        buf[1] = 0x82;
        buf[2] = ((data_len + padding) >> 8) & 0xFF;
        buf[3] = ((data_len + padding)) & 0xFF;
        if (padding) {
            buf[4] = 0x00;
            if (data && data_len)
                memcpy(&buf[5], data, data_len);
        } else {
            if (data && data_len)
                memcpy(&buf[4], data, data_len);
        }
        *ber_int_len = len;
        *ber_int = buf;
        return CKR_OK;
    }

    if (data_len + padding < (1 << 24)) {
        buf[0] = 0x02;
        buf[1] = 0x83;
        buf[2] = ((data_len + padding) >> 16) & 0xFF;
        buf[3] = ((data_len + padding) >> 8) & 0xFF;
        buf[4] = ((data_len + padding)) & 0xFF;
        if (padding) {
            buf[5] = 0x00;
            if (data)
                memcpy(&buf[6], data, data_len);
        } else {
            if (data)
                memcpy(&buf[5], data, data_len);
        }
        *ber_int_len = len;
        *ber_int = buf;
        return CKR_OK;
    }
    // we should never reach this
    //
    free(buf);
    TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));

    return CKR_FUNCTION_FAILED;
}


//
//
CK_RV ber_decode_INTEGER(CK_BYTE *ber_int,
                         CK_BYTE **data, CK_ULONG *data_len,
                         CK_ULONG *field_len)
{
    CK_ULONG len, length_octets;

    if (!ber_int) {
        TRACE_ERROR("Invalid function argument.\n");
        return CKR_FUNCTION_FAILED;
    }
    if (ber_int[0] != 0x02) {
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
        *data = &ber_int[2];
        *data_len = len;
        if (ber_int[2] == 0x00) {
            *data = &ber_int[3];
            *data_len = len - 1;
        }
        *field_len = 1 + 1 + len;
        return CKR_OK;
    }

    length_octets = ber_int[1] & 0x7F;

    if (length_octets == 1) {
        len = ber_int[2];
        *data = &ber_int[3];
        *data_len = len;
        if (ber_int[3] == 0x00) {
            *data = &ber_int[4];
            *data_len = len - 1;
        }
        *field_len = 1 + (1 + 1) + len;
        return CKR_OK;
    }

    if (length_octets == 2) {
        len = ber_int[2];
        len = len << 8;
        len |= ber_int[3];
        *data = &ber_int[4];
        *data_len = len;
        if (ber_int[4] == 0x00) {
            *data = &ber_int[5];
            *data_len = len - 1;
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
        *data = &ber_int[5];
        *data_len = len;
        if (ber_int[5] == 0x00) {
            *data = &ber_int[6];
            *data_len = len - 1;
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
CK_RV ber_encode_OCTET_STRING(CK_BBOOL length_only,
                              CK_BYTE **str,
                              CK_ULONG *str_len, CK_BYTE *data,
                              CK_ULONG data_len)
{
    CK_BYTE *buf = NULL;
    CK_ULONG len;

    // I only support Primitive encoding for OCTET STRINGS
    //

    // if data_len < 128 use short-form length id
    // if data_len < 256 use long-form length id with 1-byte length field
    // if data_len < 65536 use long-form length id with 2-byte length field
    //

    if (data_len < 128) {
        len = 1 + 1 + data_len;
    } else if (data_len < 256) {
        len = 1 + (1 + 1) + data_len;
    } else if (data_len < (1 << 16)) {
        len = 1 + (1 + 2) + data_len;
    } else if (data_len < (1 << 24)) {
        len = 1 + (1 + 3) + data_len;
    } else {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }
    if (length_only == TRUE) {
        *str_len = len;
        return CKR_OK;
    }

    buf = (CK_BYTE *) malloc(len);
    if (!buf) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    if (data_len < 128) {
        buf[0] = 0x04;          // primitive, OCTET STRING
        buf[1] = data_len;
        memcpy(&buf[2], data, data_len);

        *str_len = len;
        *str = buf;
        return CKR_OK;
    }

    if (data_len < 256) {
        buf[0] = 0x04;          // primitive, OCTET STRING
        buf[1] = 0x81;          // length header -- 1 length octets
        buf[2] = data_len;

        memcpy(&buf[3], data, data_len);

        *str_len = len;
        *str = buf;
        return CKR_OK;
    }

    if (data_len < (1 << 16)) {
        buf[0] = 0x04;          // primitive, OCTET STRING
        buf[1] = 0x82;          // length header -- 2 length octets
        buf[2] = (data_len >> 8) & 0xFF;
        buf[3] = (data_len) & 0xFF;

        memcpy(&buf[4], data, data_len);

        *str_len = len;
        *str = buf;
        return CKR_OK;
    }

    if (data_len < (1 << 24)) {
        buf[0] = 0x04;          // primitive, OCTET STRING
        buf[1] = 0x83;          // length header -- 3 length octets
        buf[2] = (data_len >> 16) & 0xFF;
        buf[3] = (data_len >> 8) & 0xFF;
        buf[4] = (data_len) & 0xFF;

        memcpy(&buf[5], data, data_len);

        *str_len = len;
        *str = buf;
        return CKR_OK;
    }
    // we should never reach this
    //
    free(buf);
    TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));

    return CKR_FUNCTION_FAILED;
}


//
//
CK_RV ber_decode_OCTET_STRING(CK_BYTE *str,
                              CK_BYTE **data,
                              CK_ULONG *data_len, CK_ULONG *field_len)
{
    CK_ULONG len, length_octets;

    // I only support decoding primitive OCTET STRINGS
    //

    if (!str) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }
    if (str[0] != 0x04) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }
    // short form lengths are easy
    //
    if ((str[1] & 0x80) == 0) {
        len = str[1] & 0x7F;

        *data = &str[2];
        *data_len = len;
        *field_len = 1 + (1) + len;
        return CKR_OK;
    }

    length_octets = str[1] & 0x7F;

    if (length_octets == 1) {
        len = str[2];

        *data = &str[3];
        *data_len = len;
        *field_len = 1 + (1 + 1) + len;
        return CKR_OK;
    }

    if (length_octets == 2) {
        len = str[2];
        len = len << 8;
        len |= str[3];

        *data = &str[4];
        *data_len = len;
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
        *data_len = len;
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
CK_RV ber_decode_BIT_STRING(CK_BYTE *str,
                            CK_BYTE **data,
                            CK_ULONG *data_len, CK_ULONG *field_len)
{
    CK_ULONG len, length_octets;

    if (!str) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }
    if (str[0] != 0x03) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    if ((str[1] & 0x80) == 0) {
        len = str[1] & 0x7F;

        *data = &str[2];
        *data_len = len;
        *field_len = 1 + (1) + len;
        return CKR_OK;
    }

    length_octets = str[1] & 0x7F;

    if (length_octets == 1) {
        len = str[2];

        *data = &str[3];
        *data_len = len;
        *field_len = 1 + (1 + 1) + len;
        return CKR_OK;
    }

    if (length_octets == 2) {
        len = str[2];
        len = len << 8;
        len |= str[3];

        *data = &str[4];
        *data_len = len;
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
        *data_len = len;
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
CK_RV ber_encode_SEQUENCE(CK_BBOOL length_only,
                          CK_BYTE **seq,
                          CK_ULONG *seq_len, CK_BYTE *data, CK_ULONG data_len)
{
    CK_BYTE *buf = NULL;
    CK_ULONG len;

    // if data_len < 127 use short-form length id
    // if data_len < 65536 use long-form length id with 2-byte length field
    //

    if (data_len < 128) {
        len = 1 + 1 + data_len;
    } else if (data_len < 256) {
        len = 1 + (1 + 1) + data_len;
    } else if (data_len < (1 << 16)) {
        len = 1 + (1 + 2) + data_len;
    } else if (data_len < (1 << 24)) {
        len = 1 + (1 + 3) + data_len;
    } else {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }
    if (length_only == TRUE) {
        *seq_len = len;
        return CKR_OK;
    }

    buf = (CK_BYTE *) malloc(len);
    if (!buf) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    if (data_len < 128) {
        buf[0] = 0x30;          // constructed, SEQUENCE
        buf[1] = data_len;
        memcpy(&buf[2], data, data_len);

        *seq_len = len;
        *seq = buf;
        return CKR_OK;
    }

    if (data_len < 256) {
        buf[0] = 0x30;          // constructed, SEQUENCE
        buf[1] = 0x81;          // length header -- 1 length octets
        buf[2] = data_len;

        memcpy(&buf[3], data, data_len);

        *seq_len = len;
        *seq = buf;
        return CKR_OK;
    }

    if (data_len < (1 << 16)) {
        buf[0] = 0x30;          // constructed, SEQUENCE
        buf[1] = 0x82;          // length header -- 2 length octets
        buf[2] = (data_len >> 8) & 0xFF;
        buf[3] = (data_len) & 0xFF;

        memcpy(&buf[4], data, data_len);

        *seq_len = len;
        *seq = buf;
        return CKR_OK;
    }

    if (data_len < (1 << 24)) {
        buf[0] = 0x30;          // constructed, SEQUENCE
        buf[1] = 0x83;          // length header -- 3 length octets
        buf[2] = (data_len >> 16) & 0xFF;
        buf[3] = (data_len >> 8) & 0xFF;
        buf[4] = (data_len) & 0xFF;

        memcpy(&buf[5], data, data_len);

        *seq_len = len;
        *seq = buf;
        return CKR_OK;
    }

    free(buf);
    TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));

    return CKR_FUNCTION_FAILED;
}


//
//
CK_RV ber_decode_SEQUENCE(CK_BYTE *seq,
                          CK_BYTE **data, CK_ULONG *data_len,
                          CK_ULONG *field_len)
{
    CK_ULONG len, length_octets;


    if (!seq) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }
    if (seq[0] != 0x30) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }
    // short form lengths are easy
    //
    if ((seq[1] & 0x80) == 0) {
        len = seq[1] & 0x7F;

        *data = &seq[2];
        *data_len = len;
        *field_len = 1 + (1) + len;
        return CKR_OK;
    }

    length_octets = seq[1] & 0x7F;

    if (length_octets == 1) {
        len = seq[2];

        *data = &seq[3];
        *data_len = len;
        *field_len = 1 + (1 + 1) + len;
        return CKR_OK;
    }

    if (length_octets == 2) {
        len = seq[2];
        len = len << 8;
        len |= seq[3];

        *data = &seq[4];
        *data_len = len;
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
        *data_len = len;
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
CK_RV ber_encode_CHOICE(CK_BBOOL length_only,
                        CK_BYTE option,
                        CK_BYTE **str,
                        CK_ULONG *str_len, CK_BYTE *data, CK_ULONG data_len)
{
    CK_BYTE *buf = NULL;
    CK_ULONG len;

    /*
     *  if data_len < 127 use short-form length id
     *  if data_len < 65536 use long-form length id with 2-byte length field
     */

    if (data_len < 128) {
        len = 1 + 1 + data_len;
    } else if (data_len < 256) {
        len = 1 + (1 + 1) + data_len;
    } else if (data_len < (1 << 16)) {
        len = 1 + (1 + 2) + data_len;
    } else if (data_len < (1 << 24)) {
        len = 1 + (1 + 3) + data_len;
    } else {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }
    if (length_only == TRUE) {
        *str_len = len;
        return CKR_OK;
    }

    buf = (CK_BYTE *) malloc(len);
    if (!buf) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    if (data_len < 128) {
        buf[0] = 0xA0 | option; // constructed, CHOICE
        buf[1] = data_len;
        memcpy(&buf[2], data, data_len);

        *str_len = len;
        *str = buf;
        return CKR_OK;
    }

    if (data_len < 256) {
        buf[0] = 0xA0 | option; // constructed, CHOICE
        buf[1] = 0x81;          // length header -- 1 length octets
        buf[2] = data_len;

        memcpy(&buf[3], data, data_len);

        *str_len = len;
        *str = buf;
        return CKR_OK;
    }

    if (data_len < (1 << 16)) {
        buf[0] = 0xA0 | option; // constructed, CHOICE
        buf[1] = 0x82;          // length header -- 2 length octets
        buf[2] = (data_len >> 8) & 0xFF;
        buf[3] = (data_len) & 0xFF;

        memcpy(&buf[4], data, data_len);

        *str_len = len;
        *str = buf;
        return CKR_OK;
    }
    if (data_len < (1 << 24)) {
        buf[0] = 0xA0 | option; // constructed, CHOICE
        buf[1] = 0x83;          // length header -- 3 length octets
        buf[2] = (data_len >> 16) & 0xFF;
        buf[3] = (data_len >> 8) & 0xFF;
        buf[4] = (data_len) & 0xFF;

        memcpy(&buf[5], data, data_len);

        *str_len = len;
        *str = buf;
        return CKR_OK;
    }

    free(buf);
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
CK_RV ber_decode_CHOICE(CK_BYTE *choice,
                        CK_BYTE **data,
                        CK_ULONG *data_len, CK_ULONG *field_len,
                        CK_ULONG *option)
{
    CK_ULONG len, length_octets;


    if (!choice) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    if ((choice[0] & 0xE0) != 0xA0) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    *option = choice[0] & 0x1F;

    // short form lengths are easy
    //
    if ((choice[1] & 0x80) == 0) {
        len = choice[1] & 0x7F;
        *data = &choice[2];
        *data_len = len;
        *field_len = 1 + (1) + len;
        return CKR_OK;
    }

    length_octets = choice[1] & 0x7F;

    if (length_octets == 1) {
        len = choice[2];
        *data = &choice[3];
        *data_len = len;
        *field_len = 1 + (1 + 1) + len;
        return CKR_OK;
    }

    if (length_octets == 2) {
        len = choice[2];
        len = len << 8;
        len |= choice[3];
        *data = &choice[4];
        *data_len = len;
        *field_len = 1 + (1 + 2) + len;
        return CKR_OK;
    }

    if (length_octets == 3) {
        len = choice[2];
        len = len << 8;
        len |= choice[3];
        len = len << 8;
        len |= choice[4];
        *data = &choice[5];
        *data_len = len;
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
CK_RV ber_encode_PrivateKeyInfo(CK_BBOOL length_only,
                                CK_BYTE **data,
                                CK_ULONG *data_len,
                                CK_BYTE *algorithm_id,
                                CK_ULONG algorithm_id_len,
                                CK_BYTE *priv_key, CK_ULONG priv_key_len)
{
    CK_BYTE *buf = NULL;
    CK_BYTE *tmp = NULL;
    CK_BYTE version[] = { 0 };
    CK_ULONG len, total;
    CK_RV rc;

    len = 0;

    rc = ber_encode_INTEGER(TRUE, NULL, &total, version, sizeof(version));
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_INTEGER failed\n");
        return rc;
    } else {
        len += total;
    }

    len += algorithm_id_len;

    rc = ber_encode_OCTET_STRING(TRUE, NULL, &total, priv_key, priv_key_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_OCTET_STRING failed\n");
        return rc;
    }

    len += total;

    // for this stuff, attributes can be suppressed.
    //

    if (length_only == TRUE) {
        rc = ber_encode_SEQUENCE(TRUE, NULL, &total, NULL, len);

        if (rc == CKR_OK)
            *data_len = total;
        if (rc != CKR_OK)
            TRACE_DEVEL("ber_encode_SEQUENCE failed\n");
        return rc;
    }

    buf = (CK_BYTE *) malloc(len);
    if (!buf) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }
    len = 0;
    rc = ber_encode_INTEGER(FALSE, &tmp, &total, version, sizeof(version));
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_INTEGER failed\n");
        goto error;
    }
    if (tmp != NULL) {
        memcpy(buf + len, tmp, total);
        len += total;
        free(tmp);
    }

    memcpy(buf + len, algorithm_id, algorithm_id_len);
    len += algorithm_id_len;

    rc = ber_encode_OCTET_STRING(FALSE, &tmp, &total, priv_key, priv_key_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_OCTET_STRING failed\n");
        goto error;
    }
    memcpy(buf + len, tmp, total);
    len += total;
    free(tmp);

    rc = ber_encode_SEQUENCE(FALSE, data, data_len, buf, len);
    if (rc != CKR_OK)
        TRACE_DEVEL("ber_encode_SEQUENCE failed\n");

error:
    free(buf);

    return rc;
}


//
//
CK_RV ber_decode_PrivateKeyInfo(CK_BYTE *data,
                                CK_ULONG data_len,
                                CK_BYTE **algorithm,
                                CK_ULONG *alg_len, CK_BYTE **priv_key)
{
    CK_BYTE *buf = NULL;
    CK_BYTE *alg = NULL;
    CK_BYTE *ver = NULL;
    CK_ULONG buf_len, offset, len, field_len;
    CK_RV rc;

    if (!data || (data_len == 0)) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    rc = ber_decode_SEQUENCE(data, &buf, &buf_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_SEQUENCE failed\n");
        return rc;
    }
    // version -- we just ignore this
    //
    offset = 0;
    rc = ber_decode_INTEGER(buf + offset, &ver, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        return rc;
    }
    offset += field_len;

    // 'buf' is now pointing to the PrivateKeyAlgorithmIdentifier
    //
    rc = ber_decode_SEQUENCE(buf + offset, &alg, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_SEQUENCE failed\n");
        return rc;
    }
    *algorithm = alg;
    *alg_len = len;

    rc = ber_decode_OCTET_STRING(alg + len, priv_key, &buf_len, &field_len);
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
CK_RV ber_encode_RSAPrivateKey(CK_BBOOL length_only,
                               CK_BYTE **data,
                               CK_ULONG *data_len,
                               CK_ATTRIBUTE *modulus,
                               CK_ATTRIBUTE *publ_exp,
                               CK_ATTRIBUTE *priv_exp,
                               CK_ATTRIBUTE *prime1,
                               CK_ATTRIBUTE *prime2,
                               CK_ATTRIBUTE *exponent1,
                               CK_ATTRIBUTE *exponent2,
                               CK_ATTRIBUTE *coeff, CK_ATTRIBUTE *opaque)
{
    CK_BYTE *buf = NULL;
    CK_BYTE *buf2 = NULL;
    CK_ULONG len, offset;
    CK_BYTE version[] = { 0 };
    CK_RV rc;


    offset = 0;
    rc = 0;

    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, sizeof(version));
    offset += len;
    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, modulus->ulValueLen);
    offset += len;
    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, publ_exp->ulValueLen);
    offset += len;
    if (opaque != NULL) {
        rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, opaque->ulValueLen);
        offset += len;
    } else {
        rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, priv_exp->ulValueLen);
        offset += len;
        rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, prime1->ulValueLen);
        offset += len;
        rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, prime2->ulValueLen);
        offset += len;
        rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, exponent1->ulValueLen);
        offset += len;
        rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, exponent2->ulValueLen);
        offset += len;
        rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, coeff->ulValueLen);
        offset += len;
    }

    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_INTEGER failed\n");
        return CKR_FUNCTION_FAILED;
    }
    if (length_only == TRUE) {
        rc = ber_encode_SEQUENCE(TRUE, NULL, &len, NULL, offset);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_SEQUENCE failed\n");
            return rc;
        }
        rc = ber_encode_PrivateKeyInfo(TRUE,
                                       NULL, data_len,
                                       NULL, ber_AlgIdRSAEncryptionLen,
                                       NULL, len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_PrivateKeyInfo failed\n");
            return rc;
        }
        return rc;
    }

    buf = (CK_BYTE *) malloc(offset);
    if (!buf) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }
    offset = 0;
    rc = 0;

    rc = ber_encode_INTEGER(FALSE, &buf2, &len, version, sizeof(version));
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_INTEGER failed\n");
        goto error;
    }
    if (buf2 != NULL) {
        memcpy(buf + offset, buf2, len);
        offset += len;
        free(buf2);
        buf2 = NULL;
    }

    rc = ber_encode_INTEGER(FALSE, &buf2, &len,
                            (CK_BYTE *) modulus + sizeof(CK_ATTRIBUTE),
                            modulus->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_INTEGER failed\n");
        goto error;
    }
    if (buf2 != NULL) {
        memcpy(buf + offset, buf2, len);
        offset += len;
        free(buf2);
        buf2 = NULL;
    }

    rc = ber_encode_INTEGER(FALSE, &buf2, &len,
                            (CK_BYTE *) publ_exp + sizeof(CK_ATTRIBUTE),
                            publ_exp->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_INTEGER failed\n");
        goto error;
    }
    if (buf2 != NULL) {
        memcpy(buf + offset, buf2, len);
        offset += len;
        free(buf2);
        buf2 = NULL;
    }

    if (opaque != NULL) {
        // the CKA_IBM_OPAQUE attrib
        rc = ber_encode_OCTET_STRING(FALSE, &buf2, &len,
                                     (CK_BYTE *) opaque +
                                     sizeof(CK_ATTRIBUTE), opaque->ulValueLen);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_OCTET_STRING failed\n");
            goto error;
        }
        memcpy(buf + offset, buf2, len);
        offset += len;
        free(buf2);
        buf2 = NULL;
    } else {
        rc = ber_encode_INTEGER(FALSE, &buf2, &len,
                                (CK_BYTE *) priv_exp + sizeof(CK_ATTRIBUTE),
                                priv_exp->ulValueLen);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_INTEGER failed\n");
            goto error;
        }
        if (buf2 != NULL) {
            memcpy(buf + offset, buf2, len);
            offset += len;
            free(buf2);
            buf2 = NULL;
        }

        rc = ber_encode_INTEGER(FALSE, &buf2, &len,
                                (CK_BYTE *) prime1 + sizeof(CK_ATTRIBUTE),
                                prime1->ulValueLen);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_INTEGER failed\n");
            goto error;
        }
        if (buf2 != NULL) {
            memcpy(buf + offset, buf2, len);
            offset += len;
            free(buf2);
            buf2 = NULL;
        }

        rc = ber_encode_INTEGER(FALSE, &buf2, &len,
                                (CK_BYTE *) prime2 + sizeof(CK_ATTRIBUTE),
                                prime2->ulValueLen);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_INTEGER failed\n");
            goto error;
        }
        if (buf2 != NULL) {
            memcpy(buf + offset, buf2, len);
            offset += len;
            free(buf2);
            buf2 = NULL;
        }

        rc = ber_encode_INTEGER(FALSE, &buf2, &len,
                                (CK_BYTE *) exponent1 + sizeof(CK_ATTRIBUTE),
                                exponent1->ulValueLen);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_INTEGER failed\n");
            goto error;
        }
        if (buf2 != NULL) {
            memcpy(buf + offset, buf2, len);
            offset += len;
            free(buf2);
            buf2 = NULL;
        }

        rc = ber_encode_INTEGER(FALSE, &buf2, &len,
                                (CK_BYTE *) exponent2 + sizeof(CK_ATTRIBUTE),
                                exponent2->ulValueLen);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_INTEGER failed\n");
            goto error;
        }
        if (buf2 != NULL) {
            memcpy(buf + offset, buf2, len);
            offset += len;
            free(buf2);
            buf2 = NULL;
        }

        rc = ber_encode_INTEGER(FALSE, &buf2, &len,
                                (CK_BYTE *) coeff + sizeof(CK_ATTRIBUTE),
                                coeff->ulValueLen);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_INTEGER failed\n");
            goto error;
        }
        if (buf2 != NULL) {
            memcpy(buf + offset, buf2, len);
            offset += len;
            free(buf2);
            buf2 = NULL;
        }
    }

    rc = ber_encode_SEQUENCE(FALSE, &buf2, &len, buf, offset);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_SEQUENCE failed\n");
        goto error;
    }
    rc = ber_encode_PrivateKeyInfo(FALSE,
                                   data, data_len,
                                   ber_AlgIdRSAEncryption,
                                   ber_AlgIdRSAEncryptionLen, buf2, len);
    if (rc != CKR_OK) {
        TRACE_ERROR("ber_encode_PrivateKeyInfo failed\n");
    }
error:
    if (buf2)
        free(buf2);
    if (buf)
        free(buf);

    return rc;
}


//
//
CK_RV ber_decode_RSAPrivateKey(CK_BYTE *data,
                               CK_ULONG data_len,
                               CK_ATTRIBUTE **modulus,
                               CK_ATTRIBUTE **publ_exp,
                               CK_ATTRIBUTE **priv_exp,
                               CK_ATTRIBUTE **prime1,
                               CK_ATTRIBUTE **prime2,
                               CK_ATTRIBUTE **exponent1,
                               CK_ATTRIBUTE **exponent2,
                               CK_ATTRIBUTE **coeff,
                               CK_ATTRIBUTE **opaque, CK_BBOOL isopaque)
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

    CK_BYTE *alg = NULL;
    CK_BYTE *rsa_priv_key = NULL;
    CK_BYTE *buf = NULL;
    CK_BYTE *tmp = NULL;
    CK_ULONG offset, buf_len, field_len, len;
    CK_RV rc;

    rc = ber_decode_PrivateKeyInfo(data, data_len, &alg, &len, &rsa_priv_key);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_PrivateKeyInfo failed\n");
        return rc;
    }
    // make sure we're dealing with an RSA key
    //
    if (memcmp(alg, ber_rsaEncryption, ber_rsaEncryptionLen) != 0) {
        // probably ought to use a different error
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }
    rc = ber_decode_SEQUENCE(rsa_priv_key, &buf, &buf_len, &field_len);
    if (rc != CKR_OK)
        return rc;

    // parse the RSAPrivateKey
    //
    offset = 0;

    // Version
    //
    rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
    }
    offset += field_len;

    // modulus
    //
    rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
    }
    offset += field_len;

    // public exponent
    //
    rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
    }
    offset += field_len;

    if (isopaque) {
        // opaque attribute, the CCA key
        //
        rc = ber_decode_OCTET_STRING(buf + offset, &tmp, &len, &field_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_decode_OCTET_STRING failed\n");
            goto cleanup;
        }
        offset += field_len;
    } else {

        // private exponent
        //
        rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_decode_INTEGER failed\n");
            goto cleanup;
        }
        offset += field_len;

        // prime #1
        //
        rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_decode_INTEGER failed\n");
            goto cleanup;
        }
        offset += field_len;

        // prime #2
        //
        rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_decode_INTEGER failed\n");
            goto cleanup;
        }
        offset += field_len;

        // exponent #1
        //
        rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_decode_INTEGER failed\n");
            goto cleanup;
        }
        offset += field_len;

        // exponent #2
        //
        rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_decode_INTEGER failed\n");
            goto cleanup;
        }
        offset += field_len;

        // coefficient
        //
        rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_decode_INTEGER failed\n");
            goto cleanup;
        }
        offset += field_len;

        if (offset > buf_len) {
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
    rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
    }
    offset += field_len;

    // modulus
    //
    rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
    } else {
        rc = build_attribute(CKA_MODULUS, tmp, len, &n_attr);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_attribute failed\n");
            goto cleanup;
        }
        offset += field_len;
    }

    // public exponent
    //
    rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
    } else {
        rc = build_attribute(CKA_PUBLIC_EXPONENT, tmp, len, &e_attr);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_attribute failed\n");
            goto cleanup;
        }
        offset += field_len;
    }

    if (isopaque) {
        // opaque attribute, the CCA key
        //
        rc = ber_decode_OCTET_STRING(buf + offset, &tmp, &len, &field_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_decode_OCTET_STRING failed\n");
            goto cleanup;
        } else {
            rc = build_attribute(CKA_IBM_OPAQUE, tmp, len, &o_attr);
            if (rc != CKR_OK) {
                TRACE_DEVEL("build_attribute failed\n");
                goto cleanup;
            }
            offset += field_len;
        }
        *opaque = o_attr;
    } else {
        // private exponent
        //
        rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_decode_INTEGER failed\n");
            goto cleanup;
        } else {
            rc = build_attribute(CKA_PRIVATE_EXPONENT, tmp, len, &d_attr);
            if (rc != CKR_OK) {
                TRACE_DEVEL("build_attribute failed\n");
                goto cleanup;
            }
            offset += field_len;
        }

        // prime #1
        //
        rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_decode_INTEGER failed\n");
            goto cleanup;
        } else {
            rc = build_attribute(CKA_PRIME_1, tmp, len, &p_attr);
            if (rc != CKR_OK) {
                TRACE_DEVEL("build_attribute failed\n");
                goto cleanup;
            }
            offset += field_len;
        }

        // prime #2
        //
        rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_decode_INTEGER failed\n");
            goto cleanup;
        } else {
            rc = build_attribute(CKA_PRIME_2, tmp, len, &q_attr);
            if (rc != CKR_OK) {
                TRACE_DEVEL("build_attribute failed\n");
                goto cleanup;
            }
            offset += field_len;
        }

        // exponent #1
        //
        rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_decode_INTEGER failed\n");
            goto cleanup;
        } else {
            rc = build_attribute(CKA_EXPONENT_1, tmp, len, &e1_attr);
            if (rc != CKR_OK) {
                TRACE_DEVEL("build_attribute failed\n");
                goto cleanup;
            }
            offset += field_len;
        }

        // exponent #2
        //
        rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_decode_INTEGER failed\n");
            goto cleanup;
        } else {
            rc = build_attribute(CKA_EXPONENT_2, tmp, len, &e2_attr);
            if (rc != CKR_OK) {
                TRACE_DEVEL("build_attribute failed\n");
                goto cleanup;
            }
            offset += field_len;
        }

        // coefficient
        //
        rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_decode_INTEGER failed\n");
            goto cleanup;
        } else {
            rc = build_attribute(CKA_COEFFICIENT, tmp, len, &coeff_attr);
            if (rc != CKR_OK) {
                TRACE_DEVEL("build_attribute failed\n");
                goto cleanup;
            }
            offset += len;
        }
        *priv_exp = d_attr;
        *prime1 = p_attr;
        *prime2 = q_attr;
        *exponent1 = e1_attr;
        *exponent2 = e2_attr;
        *coeff = coeff_attr;
    }

    *modulus = n_attr;
    *publ_exp = e_attr;

    return CKR_OK;

cleanup:
    if (n_attr)
        free(n_attr);
    if (e_attr)
        free(e_attr);
    if (isopaque) {
        if (o_attr)
            free(o_attr);
    } else {
        if (d_attr)
            free(d_attr);
        if (p_attr)
            free(p_attr);
        if (q_attr)
            free(q_attr);
        if (e1_attr)
            free(e1_attr);
        if (e2_attr)
            free(e2_attr);
        if (coeff_attr)
            free(coeff_attr);
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
CK_RV ber_encode_DSAPrivateKey(CK_BBOOL length_only,
                               CK_BYTE **data,
                               CK_ULONG *data_len,
                               CK_ATTRIBUTE *prime1,
                               CK_ATTRIBUTE *prime2,
                               CK_ATTRIBUTE *base, CK_ATTRIBUTE *priv_key)
{
    CK_BYTE *param = NULL;
    CK_BYTE *buf = NULL;
    CK_BYTE *tmp = NULL;
    CK_BYTE *alg = NULL;
    CK_ULONG offset, len, param_len;
    CK_ULONG alg_len;
    CK_RV rc;


    // build the DSS parameters first
    //
    offset = 0;
    rc = 0;

    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, prime1->ulValueLen);
    offset += len;
    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, prime2->ulValueLen);
    offset += len;
    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, base->ulValueLen);
    offset += len;

    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_INTEGER failed\n");
        return CKR_FUNCTION_FAILED;
    }
    if (length_only == TRUE) {
        rc = ber_encode_SEQUENCE(TRUE, NULL, &param_len, NULL, offset);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_SEQUENCE failed\n");
            return rc;
        }
        rc = ber_encode_INTEGER(TRUE, NULL, &len, NULL, priv_key->ulValueLen);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_INTEGER failed\n");
            return rc;
        }
        rc = ber_encode_PrivateKeyInfo(TRUE,
                                       NULL, data_len,
                                       NULL, ber_idDSALen + param_len,
                                       NULL, len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_PrivateKeyInfo failed\n");
        }
        return rc;
    }
    // 'buf' will be the sequence data for the AlgorithmIdentifyer::parameter
    //
    buf = (CK_BYTE *) malloc(offset);
    if (!buf) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }
    len = 0;
    offset = 0;

    rc = ber_encode_INTEGER(FALSE, &tmp, &len,
                            (CK_BYTE *) prime1 + sizeof(CK_ATTRIBUTE),
                            prime1->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_INTEGER failed\n");
        goto error;
    }
    if (tmp != NULL) {
        memcpy(buf + offset, tmp, len);
        offset += len;
        free(tmp);
        tmp = NULL;
    }

    rc = ber_encode_INTEGER(FALSE, &tmp, &len,
                            (CK_BYTE *) prime2 + sizeof(CK_ATTRIBUTE),
                            prime2->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_INTEGER failed\n");
        goto error;
    }
    if (tmp != NULL) {
        memcpy(buf + offset, tmp, len);
        offset += len;
        free(tmp);
        tmp = NULL;
    }

    rc = ber_encode_INTEGER(FALSE, &tmp, &len,
                            (CK_BYTE *) base + sizeof(CK_ATTRIBUTE),
                            base->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_INTEGER failed\n");
        goto error;
    }
    if (tmp != NULL) {
        memcpy(buf + offset, tmp, len);
        offset += len;
        free(tmp);
        tmp = NULL;
    }

    rc = ber_encode_SEQUENCE(FALSE, &param, &param_len, buf, offset);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_SEQUENCE failed\n");
        free(buf);
        return rc;
    }

    free(buf);
    buf = NULL;

    // Build the DSA AlgorithmIdentifier
    //
    // AlgorithmIdentifier ::= SEQUENCE {
    //    algorithm  OBJECT IDENTIFIER
    //    parameters ANY DEFINED BY algorithm OPTIONAL
    // }
    //
    len = ber_idDSALen + param_len;
    buf = (CK_BYTE *) malloc(len);
    if (!buf) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        goto error;
    }
    memcpy(buf, ber_idDSA, ber_idDSALen);
    memcpy(buf + ber_idDSALen, param, param_len);

    free(param);
    param = NULL;

    rc = ber_encode_SEQUENCE(FALSE, &alg, &alg_len, buf, len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_SEQUENCE failed\n");
        goto error;
    }
    free(buf);
    buf = NULL;

    // build the private key INTEGER
    //
    rc = ber_encode_INTEGER(FALSE, &buf, &len,
                            (CK_BYTE *) priv_key + sizeof(CK_ATTRIBUTE),
                            priv_key->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_INTEGER failed\n");
        goto error;
    }

    rc = ber_encode_PrivateKeyInfo(FALSE,
                                   data, data_len, alg, alg_len, buf, len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_PrivateKeyInfo failed\n");
        goto error;
    }

error:
    if (alg)
        free(alg);
    if (buf)
        free(buf);
    if (param)
        free(param);
    if (tmp)
        free(tmp);

    return rc;
}


//
//
CK_RV ber_decode_DSAPrivateKey(CK_BYTE *data,
                               CK_ULONG data_len,
                               CK_ATTRIBUTE **prime,
                               CK_ATTRIBUTE **subprime,
                               CK_ATTRIBUTE **base, CK_ATTRIBUTE **priv_key)
{
    CK_ATTRIBUTE *p_attr = NULL;
    CK_ATTRIBUTE *q_attr = NULL;
    CK_ATTRIBUTE *g_attr = NULL;
    CK_ATTRIBUTE *x_attr = NULL;
    CK_BYTE *alg = NULL;
    CK_BYTE *buf = NULL;
    CK_BYTE *dsakey = NULL;
    CK_BYTE *tmp = NULL;
    CK_ULONG buf_len, field_len, len, offset;
    CK_RV rc;


    rc = ber_decode_PrivateKeyInfo(data, data_len, &alg, &len, &dsakey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_PrivateKeyInfo failed\n");
        return rc;
    }
    // make sure we're dealing with a DSA key.  just compare the OBJECT
    // IDENTIFIER
    //
    if (memcmp(alg, ber_idDSA, ber_idDSALen) != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }
    // extract the parameter data into ATTRIBUTES
    //
    rc = ber_decode_SEQUENCE(alg + ber_idDSALen, &buf, &buf_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_SEQUENCE failed\n");
        return rc;
    }
    offset = 0;

    // prime
    //
    rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
    }
    offset += field_len;

    // subprime
    //
    rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
    }
    offset += field_len;

    // base
    //
    rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
    }
    offset += field_len;

    if (offset > buf_len) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }
    //
    // it looks okay.  build the attributes
    //

    offset = 0;

    // prime
    //
    rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
    } else {
        rc = build_attribute(CKA_PRIME, tmp, len, &p_attr);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_attribute failed\n");
            goto cleanup;
        }
        offset += field_len;
    }

    // subprime
    //
    rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
    } else {
        rc = build_attribute(CKA_SUBPRIME, tmp, len, &q_attr);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_attribute failed\n");
            goto cleanup;
        }
        offset += field_len;
    }

    // base
    //
    rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
    } else {
        rc = build_attribute(CKA_BASE, tmp, len, &g_attr);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_attribute failed\n");
            goto cleanup;
        }
        offset += field_len;
    }

    // now get the private key
    //
    rc = ber_decode_INTEGER(dsakey, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
    } else {
        rc = build_attribute(CKA_VALUE, tmp, len, &x_attr);
        if (rc != CKR_OK) {
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
    if (p_attr)
        free(p_attr);
    if (q_attr)
        free(q_attr);
    if (g_attr)
        free(g_attr);
    if (x_attr)
        free(x_attr);

    return rc;
}

/*
 * ECC Functions
 */
//
//
CK_RV ecdsa_priv_unwrap_get_data(TEMPLATE *tmpl,
                                 CK_BYTE *data, CK_ULONG total_length)
{
    CK_ATTRIBUTE *params = NULL;
    CK_ATTRIBUTE *point = NULL;
    CK_RV rc;

    rc = der_decode_ECPublicKey(data, total_length, &params, &point);

    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_ECPrivateKey failed\n");
        return rc;
    }

    p11_attribute_trim(params);
    p11_attribute_trim(point);

    rc = template_update_attribute(tmpl, params);
    if (rc != CKR_OK)
        TRACE_DEVEL("template_update_attribute(CKA_EC_PARAMS) failed\n");
    rc = template_update_attribute(tmpl, point);
    if (rc != CKR_OK)
        TRACE_DEVEL("template_update_attribute(CKA_EC_POINT) failed\n");

    return CKR_OK;
}


//
//
CK_RV der_encode_ECPrivateKey(CK_BBOOL length_only,
                              CK_BYTE **data,
                              CK_ULONG *data_len,
                              CK_ATTRIBUTE *params,
                              CK_ATTRIBUTE *point,
                              CK_ATTRIBUTE *opaque, CK_ATTRIBUTE *pubkey)
{
    CK_BYTE *buf = NULL;
    CK_BYTE *buf2 = NULL;
    CK_ULONG len, offset = 0;
    CK_BYTE version[] = { 1 };  // ecPrivkeyVer1
    CK_BYTE der_AlgIdEC[der_AlgIdECBaseLen + params->ulValueLen];
    CK_ULONG der_AlgIdECLen = sizeof(der_AlgIdEC);
    BerElement *ber;
    BerValue *val;
    CK_RV rc = 0;

    /* Calculate BER encoding length
     * Inner SEQUENCE of
     * Integer (version), OCTET STRING (private key)
     * and CHOICE [1] BIT STRING (public key)
     */
    // version
    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, sizeof(version));
    offset += len;

    // private key octet
    if (opaque != NULL) {
        rc |= ber_encode_OCTET_STRING(TRUE, NULL, &len, NULL,
                                      opaque->ulValueLen);
        offset += len;
    } else {
        rc |= ber_encode_OCTET_STRING(TRUE, NULL, &len, NULL,
                                      point->ulValueLen);
        offset += len;
    }
    if (rc != CKR_OK) {
        TRACE_DEVEL("der encoding failed\n");
        return CKR_FUNCTION_FAILED;
    }
    // public key bit string
    if (pubkey && pubkey->pValue) {
        ber = ber_alloc_t(LBER_USE_DER);
        rc = ber_put_bitstring(ber, pubkey->pValue,
                               pubkey->ulValueLen * 8, 0x03);
        rc = ber_flatten(ber, &val);

        ber_encode_CHOICE(TRUE, 1, &buf2, &len, (CK_BYTE *)val->bv_val,
                          val->bv_len);
        offset += len;
        ber_free(ber, 1);
    }

    if (length_only == TRUE) {
        rc = ber_encode_SEQUENCE(TRUE, NULL, &len, NULL, offset);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_SEQUENCE failed\n");
            return rc;
        }
        rc = ber_encode_PrivateKeyInfo(TRUE, NULL, data_len, NULL,
                                       der_AlgIdECLen, NULL, len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_PrivateKeyInfo failed\n");
            return rc;
        }
        return rc;
    }

    /* Now starting with the real data */
    buf = (CK_BYTE *) malloc(offset);
    if (!buf) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }
    offset = 0;
    rc = 0;

    rc = ber_encode_INTEGER(FALSE, &buf2, &len, version, sizeof(version));
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_INTEGER failed\n");
        goto error;
    }
    if (buf2 != NULL) {
        memcpy(buf + offset, buf2, len);
        offset += len;
        free(buf2);
        buf2 = NULL;
    }

    if (opaque != NULL) {
        // the CKA_IBM_OPAQUE attrib
        rc = ber_encode_OCTET_STRING(FALSE, &buf2, &len,
                                     (CK_BYTE *) opaque +
                                     sizeof(CK_ATTRIBUTE), opaque->ulValueLen);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_OCTET_STRING failed\n");
            goto error;
        }
        memcpy(buf + offset, buf2, len);
        offset += len;
        free(buf2);
        buf2 = NULL;
    } else {
        rc = ber_encode_OCTET_STRING(FALSE, &buf2, &len,
                                     (CK_BYTE *) point +
                                     sizeof(CK_ATTRIBUTE), point->ulValueLen);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_INTEGER failed\n");
            goto error;
        }
        if (buf2 != NULL) {
            memcpy(buf + offset, buf2, len);
            offset += len;
            free(buf2);
            buf2 = NULL;
        }
    }

    /* generate optional bit-string of public key */
    if (pubkey && pubkey->pValue) {
        ber = ber_alloc_t(LBER_USE_DER);
        rc = ber_put_bitstring(ber, pubkey->pValue,
                               pubkey->ulValueLen * 8, 0x03);
        rc = ber_flatten(ber, &val);

        ber_encode_CHOICE(FALSE, 1, &buf2, &len, (CK_BYTE *)val->bv_val,
                          val->bv_len);
        memcpy(buf + offset, buf2, len);
        offset += len;
        free(buf2);
        buf2 = NULL;
        ber_free(ber, 1);
    }

    rc = ber_encode_SEQUENCE(FALSE, &buf2, &len, buf, offset);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_SEQUENCE failed\n");
        goto error;
    }

    /* concatenate EC algorithm-id + specific curve id */
    memcpy(der_AlgIdEC, der_AlgIdECBase, der_AlgIdECBaseLen);
    memcpy(der_AlgIdEC + der_AlgIdECBaseLen, params->pValue,
           params->ulValueLen);
    /* adjust length field */
    der_AlgIdEC[1] = der_AlgIdEC[1] + params->ulValueLen;

    rc = ber_encode_PrivateKeyInfo(FALSE, data, data_len, der_AlgIdEC,
                                   der_AlgIdECLen, buf2, len);
    if (rc != CKR_OK) {
        TRACE_ERROR("ber_encode_PrivateKeyInfo failed\n");
    }

error:
    if (buf2)
        free(buf2);
    if (buf)
        free(buf);

    return rc;
}

//
// From RFC 5915:
//
//   ECPrivateKey ::= SEQUENCE {
//     version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
//     privateKey     OCTET STRING,
//     parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
//     publicKey  [1] BIT STRING OPTIONAL
//   }
//
CK_RV der_decode_ECPrivateKey(CK_BYTE *data,
                              CK_ULONG data_len,
                              CK_ATTRIBUTE **params,
                              CK_ATTRIBUTE **pub_key,
                              CK_ATTRIBUTE **priv_key,
                              CK_ATTRIBUTE **opaque_key, CK_BBOOL isOpaque)
{
    CK_ATTRIBUTE *pub_attr = NULL;
    CK_ATTRIBUTE *priv_attr = NULL;
    CK_ATTRIBUTE *opaque_attr = NULL;
    CK_ATTRIBUTE *parm_attr = NULL;
    CK_BYTE *alg = NULL;
    CK_BYTE *buf = NULL;
    CK_BYTE *priv_buf = NULL;
    CK_BYTE *pub_buf = NULL;
    CK_BYTE *parm_buf = NULL;
    CK_BYTE *eckey = NULL;
    CK_BYTE *version = NULL;
    CK_BYTE *choice = NULL;
    CK_ULONG version_len, alg_len, priv_len, pub_len, parm_len, buf_len;
    CK_ULONG buf_offset, field_len, offset, choice_len, option;
    CK_ULONG pubkey_available = 0;
    CK_RV rc;


    /* Decode PrivateKeyInfo into alg and eckey */
    rc = ber_decode_PrivateKeyInfo(data, data_len, &alg, &alg_len, &eckey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_PrivateKeyInfo failed\n");
        return rc;
    }

    /* Check OBJECT IDENTIFIER to make sure this is an EC key */
    if (memcmp(alg, ber_idEC, ber_idECLen) != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    /* Decode the ecdhkey into buf */
    rc = ber_decode_SEQUENCE(eckey, &buf, &buf_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_SEQUENCE failed\n");
        return rc;
    }
    offset = 0;

    /* Decode version (INTEGER) */
    rc = ber_decode_INTEGER(buf + offset, &version, &version_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
    }
    offset += field_len;

    /* Decode private key (OCTET_STRING) */
    rc = ber_decode_OCTET_STRING(buf + offset, &priv_buf, &priv_len,
                                 &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_OCTET_STRING failed\n");
        goto cleanup;
    }
    offset += field_len;

    /* Check if there is an optional public key */
    buf_offset = buf - data;
    if (buf_offset + offset < data_len) {

        /* Decode CHOICE */
        rc = ber_decode_CHOICE(buf + offset, &choice, &choice_len, &field_len,
                               &option);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_decode_CHOICE failed\n");
            goto cleanup;
        }
        offset += field_len - choice_len;

        /* Decode public key (BIT_STRING) according to option */
        switch (option) {
        case 0:
            /* parameters [0] ECParameters {{ NamedCurve }} OPTIONAL
             * These params, if available, are assumed to be the same as algo
             * above, so nothing to do here.
             */
            break;
        case 1:
            /* publicKey  [1] BIT STRING OPTIONAL */
            rc = ber_decode_BIT_STRING(buf + offset, &pub_buf, &pub_len,
                                       &field_len);
            if (rc != CKR_OK) {
                TRACE_DEVEL("ber_decode_BIT_STRING failed\n");
                goto cleanup;
            }
            pubkey_available = 1;
            break;
        default:
            TRACE_DEVEL("ber_decode_CHOICE returned invalid or unsupported "
                        "option %ld\n", option);
            goto cleanup;
        }
    }

    /* Now build attribute for CKA_ECDSA_PARAMS */
    parm_buf = alg + ber_idECLen;
    parm_len = alg_len - ber_idECLen;
    rc = build_attribute(CKA_ECDSA_PARAMS, parm_buf, parm_len, &parm_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute for CKA_ECDSA_PARAMS failed\n");
        goto cleanup;
    }

    /* Build attr for public key */
    if (pubkey_available) {
        rc = build_attribute(CKA_EC_POINT, pub_buf, pub_len, &pub_attr);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_attribute for public key failed\n");
            goto cleanup;
        }
    }

    /* Build attr for private key */
    if (isOpaque) {
        rc = build_attribute(CKA_IBM_OPAQUE, priv_buf, priv_len, &opaque_attr);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_attribute for private key failed\n");
            goto cleanup;
        }
    } else {
        rc = build_attribute(CKA_VALUE, priv_buf, priv_len, &priv_attr);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_attribute for private key failed\n");
            goto cleanup;
        }
    }

    *pub_key = pub_attr;        // may be NULL if no BIT_STRING available
    *priv_key = priv_attr;      // may be NULL if key is opaque
    *opaque_key = opaque_attr;
    *params = parm_attr;

    return CKR_OK;

cleanup:
    if (pub_attr)
        free(pub_attr);
    if (priv_attr)
        free(priv_attr);
    if (opaque_attr)
        free(opaque_attr);
    if (parm_attr)
        free(parm_attr);

    return rc;
}

/*
 * ASN.1 type PrivateKeyInfo ::= SEQUENCE {
 *    version Version
 *    privateKeyAlgorithm  PrivateKeyAlgorithmIdentifier
 *    privateKey PrivateKey
 *    attributes OPTIONAL
 * }
 *
 * Where PrivateKey is defined as follows for EC:
 *
 * ASN.1 type RSAPrivateKey
 *
 * ECPrivateKey ::= SEQUENCE {
 *   version Version
 *   privateKey OCTET STRING
 *   parameters [0] ECParameters (OPTIONAL)
 *   publicKey  [1] BIT STRING (OPTIONAL)
 * }
 */
CK_RV der_decode_ECPublicKey(CK_BYTE *data,
                             CK_ULONG data_len,
                             CK_ATTRIBUTE **ec_params,
                             CK_ATTRIBUTE **ec_point)
{
    CK_ATTRIBUTE *params_attr = NULL;
    CK_ATTRIBUTE *point_attr = NULL;

    CK_BYTE *inner_seq = NULL;
    CK_BYTE *algid = NULL;
    CK_ULONG algid_len;
    CK_BYTE *algid_ECBase = NULL;
    CK_BYTE *param = NULL;
    CK_ULONG param_len;
    CK_BYTE *point = NULL;
    CK_ULONG point_len;
    CK_ULONG offset = 0;
    CK_ULONG field_len, len;
    CK_RV rc;

    UNUSED(data_len); // XXX can this parameter be removed ?

    rc = ber_decode_SEQUENCE(data, &inner_seq, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_PrivateKeyInfo failed\n");
        return rc;
    }

    rc = ber_decode_SEQUENCE(inner_seq, &algid, &algid_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_SEQUENCE failed\n");
        return rc;
    }
    offset += field_len;

    /*
     * Make sure we're dealing with an EC key.
     * Extract base alg-id of DER encoded EC byte string
     * and compare against the decoded alg-id from the inner sequence
     */
    rc = ber_decode_SEQUENCE(der_AlgIdECBase, &algid_ECBase, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_SEQUENCE failed\n");
        return rc;
    }

    if (memcmp(algid, algid_ECBase, len) != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    /* skip the generic EC publ key ID and
     * point to the curve specific parameter
     */
    param = algid + algid[1] + 2;
    param_len = algid_len - algid[1] - 2;

    rc = ber_decode_BIT_STRING(inner_seq + offset, &point, &point_len,
                               &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_OCTET_STRING failed\n");
        goto cleanup;
    }
    // build ec-parameter attribute
    rc = build_attribute(CKA_EC_PARAMS, param, param_len, &params_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto cleanup;
    }
    // build ec-point attribute
    rc = build_attribute(CKA_EC_POINT, point, point_len, &point_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto cleanup;
    }

    *ec_params = params_attr;
    *ec_point = point_attr;
    return CKR_OK;

cleanup:
    if (params_attr)
        free(params_attr);
    if (point_attr)
        free(point_attr);

    return rc;
}

// DH is a little different from RSA
//
// DHPrivateKey ::= INTEGER
//
// The 'parameters' field of the AlgorithmIdentifier are as follows:
//
// DSSParameters ::= SEQUENCE {
//    prime   INTEGER
//    base    INTEGER
// }
//
CK_RV ber_encode_DHPrivateKey(CK_BBOOL length_only,
                              CK_BYTE **data,
                              CK_ULONG *data_len,
                              CK_ATTRIBUTE *prime,
                              CK_ATTRIBUTE *base, CK_ATTRIBUTE *priv_key)
{
    CK_BYTE *param = NULL;
    CK_BYTE *buf = NULL;
    CK_BYTE *tmp = NULL;
    CK_BYTE *alg = NULL;
    CK_ULONG offset, len, param_len;
    CK_ULONG alg_len;
    CK_RV rc;

    // build the DSS parameters first
    offset = 0;
    rc = 0;

    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, prime->ulValueLen);
    offset += len;
    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, base->ulValueLen);
    offset += len;

    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_INTEGER failed\n");
        return CKR_FUNCTION_FAILED;
    }
    if (length_only == TRUE) {
        rc = ber_encode_SEQUENCE(TRUE, NULL, &param_len, NULL, offset);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_SEQUENCE failed\n");
            return rc;
        }
        rc = ber_encode_INTEGER(TRUE, NULL, &len, NULL, priv_key->ulValueLen);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_INTEGER failed\n");
            return rc;
        }
        rc = ber_encode_PrivateKeyInfo(TRUE,
                                       NULL, data_len,
                                       NULL, ber_idDHLen + param_len,
                                       NULL, len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_PrivateKeyInfo failed\n");
        }
        return rc;
    }
    // 'buf' will be the sequence data for the AlgorithmIdentifyer::parameter
    buf = (CK_BYTE *) malloc(offset);
    if (!buf) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }
    len = 0;
    offset = 0;

    rc = ber_encode_INTEGER(FALSE, &tmp, &len, prime->pValue,
                            prime->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_INTEGER failed\n");
        goto error;
    }
    if (tmp != NULL) {
        memcpy(buf + offset, tmp, len);
        offset += len;
        free(tmp);
        tmp = NULL;
    }

    rc = ber_encode_INTEGER(FALSE, &tmp, &len, base->pValue, base->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_INTEGER failed\n");
        goto error;
    }
    if (tmp != NULL) {
        memcpy(buf + offset, tmp, len);
        offset += len;
        free(tmp);
        tmp = NULL;
    }

    rc = ber_encode_SEQUENCE(FALSE, &param, &param_len, buf, offset);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_SEQUENCE failed\n");
        free(buf);
        return rc;
    }

    free(buf);
    buf = NULL;

    // Build the DSA AlgorithmIdentifier
    //
    // AlgorithmIdentifier ::= SEQUENCE {
    //    algorithm  OBJECT IDENTIFIER
    //    parameters ANY DEFINED BY algorithm OPTIONAL
    // }
    //
    len = ber_idDHLen + param_len;
    buf = (CK_BYTE *) malloc(len);
    if (!buf) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        goto error;
    }
    memcpy(buf, ber_idDH, ber_idDHLen);
    memcpy(buf + ber_idDHLen, param, param_len);

    free(param);
    param = NULL;

    rc = ber_encode_SEQUENCE(FALSE, &alg, &alg_len, buf, len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_SEQUENCE failed\n");
        goto error;
    }
    free(buf);
    buf = NULL;

    // build the private key INTEGER
    rc = ber_encode_INTEGER(FALSE, &buf, &len, priv_key->pValue,
                            priv_key->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_INTEGER failed\n");
        goto error;
    }

    rc = ber_encode_PrivateKeyInfo(FALSE,
                                   data, data_len, alg, alg_len, buf, len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_PrivateKeyInfo failed\n");
        goto error;
    }

error:
    if (alg)
        free(alg);
    if (buf)
        free(buf);
    if (param)
        free(param);
    if (tmp)
        free(tmp);

    return rc;
}

//
//
CK_RV ber_decode_DHPrivateKey(CK_BYTE *data,
                              CK_ULONG data_len,
                              CK_ATTRIBUTE **prime,
                              CK_ATTRIBUTE **base, CK_ATTRIBUTE **priv_key)
{
    CK_ATTRIBUTE *p_attr = NULL;
    CK_ATTRIBUTE *g_attr = NULL;
    CK_ATTRIBUTE *x_attr = NULL;
    CK_BYTE *alg = NULL;
    CK_BYTE *buf = NULL;
    CK_BYTE *dhkey = NULL;
    CK_BYTE *tmp = NULL;
    CK_ULONG buf_len, field_len, len, offset;
    CK_RV rc;

    rc = ber_decode_PrivateKeyInfo(data, data_len, &alg, &len, &dhkey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_PrivateKeyInfo failed\n");
        return rc;
    }
    // make sure we're dealing with a DH key.  just compare the OBJECT
    // IDENTIFIER
    if (memcmp(alg, ber_idDH, ber_idDHLen) != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }
    // extract the parameter data into ATTRIBUTES
    //
    rc = ber_decode_SEQUENCE(alg + ber_idDSALen, &buf, &buf_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_SEQUENCE failed\n");
        return rc;
    }
    offset = 0;

    // prime
    rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
    }
    offset += field_len;

    // base
    rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
    }
    offset += field_len;

    if (offset > buf_len) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }
    // it looks okay.  build the attributes

    offset = 0;

    // prime
    rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
    } else {
        rc = build_attribute(CKA_PRIME, tmp, len, &p_attr);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_attribute failed\n");
            goto cleanup;
        }
        offset += field_len;
    }

    // base
    rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
    } else {
        rc = build_attribute(CKA_BASE, tmp, len, &g_attr);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_attribute failed\n");
            goto cleanup;
        }
        offset += field_len;
    }

    // now get the private key
    rc = ber_decode_INTEGER(dhkey, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
    } else {
        rc = build_attribute(CKA_VALUE, tmp, len, &x_attr);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_attribute failed\n");
            goto cleanup;
        }
        offset += field_len;
    }

    *prime = p_attr;
    *base = g_attr;
    *priv_key = x_attr;

    return CKR_OK;

cleanup:
    if (p_attr)
        free(p_attr);
    if (g_attr)
        free(g_attr);
    if (x_attr)
        free(x_attr);

    return rc;
}
