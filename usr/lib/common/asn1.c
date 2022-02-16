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
#include "pqc_defs.h"


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

/**
 * Here we assume that the indication about unused bits is NOT
 * part of the data. It will be added by this function.
 */
CK_ULONG ber_encode_BIT_STRING(CK_BBOOL length_only,
                            CK_BYTE **ber_str,
                            CK_ULONG *ber_str_len, CK_BYTE *data,
                            CK_ULONG data_len,
                            CK_BYTE unused_bits)
{
    CK_BYTE *buf = NULL;
    CK_ULONG len;

    // if data_len < 127 use short-form length id
    // if data_len < 256 use long-form length id with 1-byte length field
    // if data_len < 65536 use long-form length id with 2-byte length field
    // if data_len < 16777216 use long-form length id with 3-byte length field

    if (data_len + 1 < 128) {
        len = 1 + 1 + 1 + data_len;
    } else if (data_len + 1 < 256) {
        len = 1 + (1 + 1) + 1 + data_len;
    } else if (data_len + 1 < (1 << 16)) {
        len = 1 + (1 + 2) + 1 + data_len;
    } else if (data_len + 1 < (1 << 24)) {
        len = 1 + (1 + 3) + 1 + data_len;
    } else {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }
    if (length_only == TRUE) {
        *ber_str_len = len;
        return CKR_OK;
    }

    buf = (CK_BYTE *) malloc(len);
    if (!buf) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    if (data_len + 1 < 128) {
        buf[0] = 0x03;
        buf[1] = data_len + 1;
        buf[2] = unused_bits;
        if (data && data_len)
            memcpy(&buf[3], data, data_len);
        *ber_str_len = len;
        *ber_str = buf;
        return CKR_OK;
    }

    if (data_len + 1 < 256) {
        buf[0] = 0x03;
        buf[1] = 0x81;
        buf[2] = data_len + 1;
        buf[3] = unused_bits;
        if (data && data_len)
            memcpy(&buf[4], data, data_len);
        *ber_str_len = len;
        *ber_str = buf;
        return CKR_OK;
    }

    if (data_len + 1 < (1 << 16)) {
        buf[0] = 0x03;
        buf[1] = 0x82;
        buf[2] = ((data_len + 1) >> 8) & 0xFF;
        buf[3] = ((data_len + 1)) & 0xFF;
        buf[4] = unused_bits;
        if (data && data_len)
            memcpy(&buf[5], data, data_len);
        *ber_str_len = len;
        *ber_str = buf;
        return CKR_OK;
    }

    if (data_len + 1 < (1 << 24)) {
        buf[0] = 0x03;
        buf[1] = 0x83;
        buf[2] = ((data_len + 1) >> 16) & 0xFF;
        buf[3] = ((data_len + 1) >> 8) & 0xFF;
        buf[4] = ((data_len + 1)) & 0xFF;
        buf[5] = unused_bits;
        if (data)
            memcpy(&buf[6], data, data_len);
        *ber_str_len = len;
        *ber_str = buf;
        return CKR_OK;
    }
    // we should never reach this
    //
    free(buf);
    TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));

    return CKR_FUNCTION_FAILED;
}

/**
 * Here the 'unused bits' byte is part of the returned decoded data.
 * The first byte of output parm *data is the number of unused bits and must
 * be removed later by the calling function.
 */
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
                                const CK_BYTE *algorithm_id,
                                const CK_ULONG algorithm_id_len,
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
        tmp = NULL;
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
    tmp = NULL;

    rc = ber_encode_SEQUENCE(FALSE, data, data_len, buf, len);
    if (rc != CKR_OK)
        TRACE_DEVEL("ber_encode_SEQUENCE failed\n");

error:
    if (tmp != NULL)
        free(tmp);
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

/*Extract data from an SPKI
 *   SubjectPublicKeyInfo ::= SEQUENCE {
 *     algorithm         AlgorithmIdentifier,
 *     subjectPublicKey  BIT STRING
 *   }
 *
 *   AlgorithmIdentifier ::= SEQUENCE {
 *     algorithm   OBJECT IDENTIFIER,
 *     parameters  ANY DEFINED BY algorithm OPTIONAL
 *   }
 */
CK_RV ber_decode_SPKI(CK_BYTE *spki, CK_BYTE **alg_oid, CK_ULONG *alg_oid_len,
                      CK_BYTE **param, CK_ULONG *param_len,
                      CK_BYTE **key, CK_ULONG *key_len)
{
    CK_BYTE *out_seq, *id_seq, *bit_str;
    CK_BYTE *data;
    CK_ULONG data_len;
    CK_ULONG field_len;
    CK_RV rc;

    *alg_oid_len = 0;
    *param_len = 0;
    *key_len = 0;
    out_seq = spki;
    rc = ber_decode_SEQUENCE(out_seq, &data, &data_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_decode_SEQUENCE #1 failed rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    id_seq = out_seq + field_len - data_len;
    /* get id seq */
    rc = ber_decode_SEQUENCE(id_seq, &data, &data_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_decode_SEQUENCE #2 failed rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    *alg_oid = data;
    *alg_oid_len = data[1] + 2;

    *param = data + *alg_oid_len;
    *param_len = data_len - *alg_oid_len;

    bit_str = id_seq + field_len;
    /* get bitstring */
    rc = ber_decode_BIT_STRING(bit_str, key, key_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_decode_BIT_STRING failed rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    (*key_len)--; /* remove 'unused bits' byte from length */
    (*key)++;

    return CKR_OK;
}


// RSAPrivateKey ::= SEQUENCE {
//    version  Version  -- always '0' for now
//    modulus  INTEGER
//    publicExponent  INTEGER
//    privateExponent INTEGER
//    prime1  INTEGER
//    prime2  INTEGER
//    exponent1  INTEGER
//    exponent2  INTEGER
//    coefficient INTEGER
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
                               CK_ATTRIBUTE *coeff)
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
                               CK_ATTRIBUTE **coeff)
{
    CK_ATTRIBUTE *n_attr = NULL;
    CK_ATTRIBUTE *e_attr = NULL;
    CK_ATTRIBUTE *d_attr = NULL;
    CK_ATTRIBUTE *p_attr = NULL;
    CK_ATTRIBUTE *q_attr = NULL;
    CK_ATTRIBUTE *e1_attr = NULL;
    CK_ATTRIBUTE *e2_attr = NULL;
    CK_ATTRIBUTE *coeff_attr = NULL;

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

    *modulus = n_attr;
    *publ_exp = e_attr;

    return CKR_OK;

cleanup:
    if (n_attr)
        free(n_attr);
    if (e_attr)
        free(e_attr);
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

    return rc;
}

CK_RV ber_encode_RSAPublicKey(CK_BBOOL length_only, CK_BYTE **data,
                              CK_ULONG *data_len, CK_ATTRIBUTE *modulus,
                              CK_ATTRIBUTE *publ_exp)
{
    CK_ULONG len = 0, offset, total, total_len;
    CK_RV rc;
    CK_BYTE *buf = NULL;
    CK_BYTE *buf2 = NULL;
    CK_BYTE *buf3 = NULL;
    BerValue *val = NULL;
    BerElement *ber;

    UNUSED(length_only);

    offset = 0;
    rc = 0;
    total_len = ber_AlgIdRSAEncryptionLen;
    total = 0;

    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, modulus->ulValueLen);
    offset += len;
    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, publ_exp->ulValueLen);
    offset += len;

    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
        return rc;
    }

    buf = (CK_BYTE *) malloc(offset);
    if (!buf) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }
    offset = 0;

    rc = ber_encode_INTEGER(FALSE, &buf2, &len,
                            (CK_BYTE *) modulus + sizeof(CK_ATTRIBUTE),
                            modulus->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
        free(buf);
        return rc;
    }
    memcpy(buf + offset, buf2, len);
    offset += len;
    free(buf2);

    rc = ber_encode_INTEGER(FALSE, &buf2, &len,
                            (CK_BYTE *) publ_exp + sizeof(CK_ATTRIBUTE),
                            publ_exp->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
        free(buf);
        return rc;
    }
    memcpy(buf + offset, buf2, len);
    offset += len;
    free(buf2);

    rc = ber_encode_SEQUENCE(FALSE, &buf2, &len, buf, offset);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Seq failed with rc=0x%lx\n", __func__, rc);
        free(buf);
        return rc;
    }
    free(buf);

    /* length of outer sequence */
    rc = ber_encode_OCTET_STRING(TRUE, NULL, &total, buf2, len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Oct_Str failed with rc=0x%lx\n", __func__,
                    rc);
        free(buf2);
        return rc;
    } else {
        total_len += total + 1;
    }

    /* mem for outer sequence */
    buf3 = (CK_BYTE *) malloc(total_len);
    if (!buf3) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        free(buf2);
        return CKR_HOST_MEMORY;
    }
    total_len = 0;

    /* copy alg id */
    memcpy(buf3 + total_len, ber_AlgIdRSAEncryption, ber_AlgIdRSAEncryptionLen);
    total_len += ber_AlgIdRSAEncryptionLen;

    /* need a bitstring */
    ber = ber_alloc_t(LBER_USE_DER);
    rc = (ber_put_bitstring(ber, (char *)buf2, len * 8, 0x03) <= 0 ? 1 : 0);
    rc |= ber_flatten(ber, &val);
    if (rc != 0) {
        TRACE_DEVEL("%s ber_alloc_t/ber_flatten failed \n", __func__);
        rc = CKR_FUNCTION_FAILED;
        ber_free(ber, 1);
        ber_bvfree(val);
        free(buf2);
        goto out;
    }
    memcpy(buf3 + total_len, val->bv_val, val->bv_len);
    total_len += val->bv_len;
    ber_free(ber, 1);
    ber_bvfree(val);
    free(buf2);

    rc = ber_encode_SEQUENCE(FALSE, data, data_len, buf3, total_len);
    if (rc != CKR_OK)
        TRACE_DEVEL("%s ber_encode_Seq failed with rc=0x%lx\n", __func__, rc);

out:
    free(buf3);
    return rc;
}

CK_RV ber_decode_RSAPublicKey(CK_BYTE *data,
                              CK_ULONG data_len,
                              CK_ATTRIBUTE **modulus,
                              CK_ATTRIBUTE **publ_exp)
{
    CK_ATTRIBUTE *modulus_attr = NULL;
    CK_ATTRIBUTE *publ_exp_attr = NULL;

    CK_BYTE *algid_RSABase = NULL;
    CK_BYTE *algid = NULL;
    CK_ULONG algid_len;
    CK_BYTE *param = NULL;
    CK_ULONG param_len;
    CK_BYTE *val = NULL;
    CK_ULONG val_len;
    CK_BYTE *seq;
    CK_ULONG seq_len;
    CK_BYTE *mod;
    CK_ULONG mod_len;
    CK_BYTE *exp;
    CK_ULONG exp_len;
    CK_ULONG field_len, offset, len;
    CK_RV rc;

    UNUSED(data_len); // XXX can this parameter be removed ?

    rc = ber_decode_SPKI(data, &algid, &algid_len, &param, &param_len,
                         &val, &val_len);
    if (rc != CKR_OK) {
       TRACE_DEVEL("ber_decode_SPKI failed\n");
       return rc;
    }

    /*
     * Make sure we're dealing with an DH key.
     */
    rc = ber_decode_SEQUENCE((CK_BYTE *)ber_AlgIdRSAEncryption, &algid_RSABase,
                             &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_SEQUENCE failed\n");
        return rc;
    }

    if (memcmp(algid, algid_RSABase, len) != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    rc = ber_decode_SEQUENCE(val, &seq, &seq_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_SEQUENCE failed\n");
        return rc;
    }

    rc = ber_decode_INTEGER(seq, &mod, &mod_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        return rc;
    }

    offset = field_len;
    rc = ber_decode_INTEGER(seq + offset, &exp, &exp_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        return rc;
    }

    // build modulus attribute
    rc = build_attribute(CKA_MODULUS, mod, mod_len, &modulus_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto cleanup;
    }
    // build base attribute
    rc = build_attribute(CKA_PUBLIC_EXPONENT, exp, exp_len, &publ_exp_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto cleanup;
    }

    *modulus = modulus_attr;
    *publ_exp = publ_exp_attr;
    return CKR_OK;

cleanup:
    if (modulus_attr)
        free(modulus_attr);
    if (publ_exp_attr)
        free(publ_exp_attr);

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
    len = 0;

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

CK_RV ber_encode_DSAPublicKey(CK_BBOOL length_only, CK_BYTE **data,
                              CK_ULONG *data_len, CK_ATTRIBUTE *prime,
                              CK_ATTRIBUTE *subprime, CK_ATTRIBUTE *base,
                              CK_ATTRIBUTE *value)
{
    CK_ULONG len = 0, parm_len, id_len, pub_len, offset, total;
    CK_RV rc = 0;
    CK_BYTE *buf = NULL;
    CK_BYTE *buf2 = NULL;
    BerValue *val = NULL;
    BerElement *ber;

    /* Calculate the BER container length
     *
     * SPKI := SEQUENCE {
     *  SEQUENCE {
     *      OID
     *      Parameters
     *  }
     *  BITSTRING public key
     * }
     */

    offset = 0;
    rc = 0;
    total = 0;
    parm_len = 0;
    id_len = 0;
    pub_len = 0;

    /* OID and parameters */
    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, prime->ulValueLen);
    offset += len;
    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, subprime->ulValueLen);
    offset += len;
    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, base->ulValueLen);
    offset += len;
    rc |= ber_encode_SEQUENCE(TRUE, NULL, &parm_len, NULL, offset);
    rc |=
        ber_encode_SEQUENCE(TRUE, NULL, &id_len, NULL, ber_idDSALen + parm_len);

    /* public key */
    rc |=
        ber_encode_INTEGER(FALSE, &buf, &len, value->pValue, value->ulValueLen);
    ber = ber_alloc_t(LBER_USE_DER);
    rc |= (ber_put_bitstring(ber, (char *)buf, len * 8, 0x03) <= 0 ? 1 : 0);
    rc |= ber_flatten(ber, &val);
    if (rc != 0) {
        TRACE_DEVEL("%s ber_alloc_t/ber_flatten failed \n", __func__);
        ber_free(ber, 1);
        ber_bvfree(val);
        free(buf);
        return CKR_FUNCTION_FAILED;
    }

    pub_len = val->bv_len;
    ber_free(ber, 1);
    free(buf);
    ber_bvfree(val);

    rc = ber_encode_SEQUENCE(TRUE, NULL, &total, NULL, id_len + pub_len);

    if (rc != CKR_OK) {
        TRACE_DEVEL("%s der_encode_sequence failed with rc=0x%lx\n", __func__,
                    rc);
        return rc;
    }

    if (length_only == TRUE) {
        *data_len = total;
        return rc;
    }

    buf = (CK_BYTE *) malloc(id_len + pub_len);
    if (!buf) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }

    /* Parameters */
    offset = 0;
    rc = ber_encode_INTEGER(FALSE, &buf2, &len, prime->pValue,
                            prime->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
        free(buf);
        return rc;
    }
    memcpy(buf + offset, buf2, len);
    offset += len;
    free(buf2);

    rc = ber_encode_INTEGER(FALSE, &buf2, &len, subprime->pValue,
                            subprime->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
        free(buf);
        return rc;
    }
    memcpy(buf + offset, buf2, len);
    offset += len;
    free(buf2);

    rc = ber_encode_INTEGER(FALSE, &buf2, &len, base->pValue, base->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
        free(buf);
        return rc;
    }
    memcpy(buf + offset, buf2, len);
    offset += len;
    free(buf2);

    rc = ber_encode_SEQUENCE(FALSE, &buf2, &parm_len, buf, offset);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Seq failed with rc=0x%lx\n", __func__, rc);
        free(buf);
        return rc;
    }

    /* OID and parameters */
    memcpy(buf, ber_idDSA, ber_idDSALen);
    memcpy(buf + ber_idDSALen, buf2, parm_len);
    free(buf2);

    rc = ber_encode_SEQUENCE(FALSE, &buf2, &id_len, buf,
                             ber_idDSALen + parm_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Seq failed with rc=0x%lx\n", __func__, rc);
        free(buf);
        return rc;
    }
    free(buf);

    /* public key */
    rc = ber_encode_INTEGER(FALSE, &buf, &len, value->pValue,
                            value->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
        free(buf2);
        return rc;
    }

    ber = ber_alloc_t(LBER_USE_DER);
    rc = (ber_put_bitstring(ber, (char *)buf, len * 8, 0x03) <= 0 ? 1 : 0);
    rc |= ber_flatten(ber, &val);
    free(buf);
    if (rc != 0) {
        TRACE_DEVEL("%s ber_put_bitstring/ber_flatten failed\n", __func__);
        ber_free(ber, 1);
        ber_bvfree(val);
        free(buf2);
        return CKR_FUNCTION_FAILED;
    }

    buf = (CK_BYTE *) malloc(id_len + val->bv_len);
    if (!buf) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        ber_free(ber, 1);
        ber_bvfree(val);
        free(buf2);
        return CKR_HOST_MEMORY;
    }
    memcpy(buf, buf2, id_len);
    memcpy(buf + id_len, val->bv_val, val->bv_len);
    free(buf2);
    ber_free(ber, 1);
    ber_bvfree(val);

    /* outer sequence */
    rc = ber_encode_SEQUENCE(FALSE, data, data_len, buf, id_len + pub_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s der_encode_Seq failed with rc=0x%lx\n", __func__, rc);
        free(buf);
        return rc;
    }
    free(buf);

    return rc;
}

CK_RV ber_decode_DSAPublicKey(CK_BYTE *data,
                              CK_ULONG data_len,
                              CK_ATTRIBUTE **prime,
                              CK_ATTRIBUTE **subprime,
                              CK_ATTRIBUTE **base,
                              CK_ATTRIBUTE **value)
{
    CK_ATTRIBUTE *prime_attr = NULL;
    CK_ATTRIBUTE *subprime_attr = NULL;
    CK_ATTRIBUTE *base_attr = NULL;
    CK_ATTRIBUTE *value_attr = NULL;

    CK_BYTE *algid = NULL;
    CK_ULONG algid_len;
    CK_BYTE *param = NULL;
    CK_ULONG param_len;
    CK_BYTE *val = NULL;
    CK_ULONG val_len;
    CK_BYTE *seq;
    CK_ULONG seq_len;
    CK_BYTE *p;
    CK_ULONG p_len;
    CK_BYTE *sp;
    CK_ULONG sp_len;
    CK_BYTE *b;
    CK_ULONG b_len;
    CK_ULONG field_len, offset;
    CK_RV rc;

    UNUSED(data_len); // XXX can this parameter be removed ?

    rc = ber_decode_SPKI(data, &algid, &algid_len, &param, &param_len,
                         &val, &val_len);
    if (rc != CKR_OK) {
       TRACE_DEVEL("ber_decode_SPKI failed\n");
       return rc;
    }

    /*
     * Make sure we're dealing with an DSA key.
     */
    if (memcmp(algid, ber_idDSA, ber_idDSALen) != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    rc = ber_decode_SEQUENCE(param, &seq, &seq_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_SEQUENCE failed\n");
        return rc;
    }

    rc = ber_decode_INTEGER(seq, &p, &p_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        return rc;
    }

    offset = field_len;
    rc = ber_decode_INTEGER(seq + offset, &sp, &sp_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        return rc;
    }

    offset += field_len;
    rc = ber_decode_INTEGER(seq + offset, &b, &b_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        return rc;
    }

    // build prime attribute
    rc = build_attribute(CKA_PRIME, p, p_len, &prime_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto cleanup;
    }
    // build subprime attribute
    rc = build_attribute(CKA_SUBPRIME, sp, sp_len, &subprime_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto cleanup;
    }
    // build base attribute
    rc = build_attribute(CKA_BASE, b, b_len, &base_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto cleanup;
    }
    // build value attribute
    rc = build_attribute(CKA_VALUE, val, val_len, &value_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto cleanup;
    }

    *prime = prime_attr;
    *subprime = subprime_attr;
    *base = base_attr;
    *value = value_attr;
    return CKR_OK;

cleanup:
    if (prime_attr)
        free(prime_attr);
    if (subprime_attr)
        free(subprime_attr);
    if (base_attr)
        free(base_attr);
    if (value_attr)
        free(value_attr);

    return rc;
}


/*
 * ECC Functions
 */
//
//



//
//
CK_RV der_encode_ECPrivateKey(CK_BBOOL length_only,
                              CK_BYTE **data,
                              CK_ULONG *data_len,
                              CK_ATTRIBUTE *params,
                              CK_ATTRIBUTE *point,
                              CK_ATTRIBUTE *pubkey)
{
    CK_BYTE *buf = NULL;
    CK_BYTE *buf2 = NULL;
    CK_ULONG len, offset = 0;
    CK_BYTE version[] = { 1 };  // ecPrivkeyVer1
    CK_BYTE der_AlgIdEC[der_AlgIdECBaseLen + params->ulValueLen];
    CK_ULONG der_AlgIdECLen = sizeof(der_AlgIdEC);
    CK_BYTE *ecpoint;
    CK_ULONG ecpoint_len, field_len;
    BerElement *ber;
    BerValue *val = NULL;
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
    rc |= ber_encode_OCTET_STRING(TRUE, NULL, &len, NULL,
                                  point->ulValueLen);
    offset += len;
    if (rc != CKR_OK) {
        TRACE_DEVEL("der encoding failed\n");
        return CKR_FUNCTION_FAILED;
    }
    // public key bit string
    if (pubkey && pubkey->pValue) {
        rc = ber_decode_OCTET_STRING(pubkey->pValue, &ecpoint, &ecpoint_len,
                                     &field_len);
        if (rc != CKR_OK || pubkey->ulValueLen != field_len) {
            TRACE_DEVEL("ber decoding of public key failed\n");
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        ber = ber_alloc_t(LBER_USE_DER);
        rc = (ber_put_bitstring(ber, (char *)ecpoint, ecpoint_len * 8, 0x03)
                                                            <= 0 ? 1 : 0);
        rc |= ber_flatten(ber, &val);
        if (rc != 0) {
            TRACE_DEVEL("ber_put_bitstring/ber_flatten failed\n");
            ber_free(ber, 1);
            ber_bvfree(val);
            return CKR_FUNCTION_FAILED;
       }

        rc = ber_encode_CHOICE(TRUE, 1, &buf2, &len, (CK_BYTE *)val->bv_val,
                               val->bv_len);
        if (rc != 0) {
            TRACE_DEVEL("ber_encode_CHOICE failed\n");
            ber_free(ber, 1);
            ber_bvfree(val);
            return CKR_FUNCTION_FAILED;
       }

        offset += len;
        ber_free(ber, 1);
        ber_bvfree(val);
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

    /* generate optional bit-string of public key */
    if (pubkey && pubkey->pValue) {
        rc = ber_decode_OCTET_STRING(pubkey->pValue, &ecpoint, &ecpoint_len,
                                     &field_len);
        if (rc != CKR_OK || pubkey->ulValueLen != field_len) {
            TRACE_DEVEL("ber decoding of public key failed\n");
            rc = CKR_ATTRIBUTE_VALUE_INVALID;
            goto error;
        }

        ber = ber_alloc_t(LBER_USE_DER);
        rc = (ber_put_bitstring(ber, (char *)ecpoint, ecpoint_len * 8, 0x03)
                                                                <= 0 ? 1 : 0);
        rc |= ber_flatten(ber, &val);
        if (rc != 0) {
            TRACE_DEVEL("ber_put_bitstring/ber_flatten failed\n");
            ber_free(ber, 1);
            ber_bvfree(val);
            rc = CKR_FUNCTION_FAILED;
            goto error;
       }

        rc = ber_encode_CHOICE(FALSE, 1, &buf2, &len, (CK_BYTE *)val->bv_val,
                               val->bv_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_CHOICE failed\n");
            ber_free(ber, 1);
            ber_bvfree(val);
            goto error;
        }

        memcpy(buf + offset, buf2, len);
        offset += len;
        free(buf2);
        buf2 = NULL;
        ber_free(ber, 1);
        ber_bvfree(val);
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
                              CK_ATTRIBUTE **priv_key)
{
    CK_ATTRIBUTE *pub_attr = NULL;
    CK_ATTRIBUTE *priv_attr = NULL;
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
    CK_BYTE *ecpoint = NULL;
    CK_ULONG ecpoint_len;
    CK_RV rc;

    /*
     * For unwrapping, the data passed to this function may be larger than the
     * actual sequence, due to padding. So look at the data only up to the
     * length in the first SEQUENCE.
     * Since an EC private key may include an optional public key, we need to
     * know the actual length to be able to find out of the optional public key
     * is present or not.
     */
    rc = ber_decode_SEQUENCE(data, &buf, &buf_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_SEQUENCE failed\n");
        return rc;
    }
    if (field_len > data_len) {
        TRACE_DEVEL("passed data is too short\n");
        return CKR_FUNCTION_FAILED;
    }
    data_len = field_len;

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
            pub_buf++; /* Remove unused-bits byte */
            pub_len--;
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

    /* Build attr for public key as BER encoded OCTET STRING */
    if (pubkey_available) {
        rc = ber_encode_OCTET_STRING(FALSE, &ecpoint, &ecpoint_len,
                                     pub_buf, pub_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_OCTET_STRING failed\n");
            goto cleanup;
        }

        rc = build_attribute(CKA_EC_POINT, ecpoint, ecpoint_len, &pub_attr);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_attribute for public key failed\n");
            goto cleanup;
        }
    }

    /* Build attr for private key */
    rc = build_attribute(CKA_VALUE, priv_buf, priv_len, &priv_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute for private key failed\n");
        goto cleanup;
    }

    *pub_key = pub_attr;        // may be NULL if no BIT_STRING available
    *priv_key = priv_attr;
    *params = parm_attr;
    if (ecpoint)
        free(ecpoint);

    return CKR_OK;

cleanup:
    if (pub_attr)
        free(pub_attr);
    if (priv_attr)
        free(priv_attr);
    if (parm_attr)
        free(parm_attr);
    if (ecpoint)
        free(ecpoint);

    return rc;
}

CK_RV ber_encode_ECPublicKey(CK_BBOOL length_only, CK_BYTE **data,
                             CK_ULONG *data_len, CK_ATTRIBUTE *params,
                             CK_ATTRIBUTE *point)
{
    CK_ULONG len, total;
    CK_ULONG algid_len = der_AlgIdECBaseLen + params->ulValueLen;
    CK_RV rc = 0;
    CK_BYTE *buf = NULL;
    BerValue *val = NULL;
    BerElement *ber;
    CK_BYTE *ecpoint;
    CK_ULONG ecpoint_len, field_len;

    /* CKA_EC_POINT is an BER encoded OCTET STRING. Extract it. */
    rc = ber_decode_OCTET_STRING((CK_BYTE *)point->pValue, &ecpoint,
                                 &ecpoint_len, &field_len);
    if (rc != CKR_OK || point->ulValueLen != field_len) {
        TRACE_DEVEL("%s ber_decode_OCTET_STRING failed\n", __func__);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    /* Calculate the BER container length
     *
     * SPKI := SEQUENCE {
     *      SEQUENCE {
     *              OID
     *              Parameters
     *      }
     *      BITSTRING public key
     * }
     */
    rc = ber_encode_SEQUENCE(TRUE, NULL, &len, NULL, algid_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s der_encode_sequence failed with rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    /* public key */
    ber = ber_alloc_t(LBER_USE_DER);
    rc = (ber_put_bitstring(ber, (char *)ecpoint, ecpoint_len * 8, 0x03)
                                                            <= 0 ? 1 : 0);
    rc |= ber_flatten(ber, &val);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_put_bitstring/ber_flatten failed\n", __func__);
        ber_free(ber, 1);
        ber_bvfree(val);
        return CKR_FUNCTION_FAILED;
    }

    rc = ber_encode_SEQUENCE(TRUE, NULL, &total, NULL, len + val->bv_len);
    ber_free(ber, 1);
    ber_bvfree(val);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s der_encode_sequence failed with rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    if (length_only == TRUE) {
        *data_len = total;
        return rc;
    }

    /* Now compute with real data */
    buf = (CK_BYTE *) malloc(total);
    if (!buf) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }

    memcpy(buf, der_AlgIdECBase, der_AlgIdECBaseLen);
    memcpy(buf + der_AlgIdECBaseLen, params->pValue, params->ulValueLen);
    buf[1] += params->ulValueLen;

    /* generate bitstring */
    ber = ber_alloc_t(LBER_USE_DER);
    rc = (ber_put_bitstring(ber, (char *)ecpoint, ecpoint_len * 8, 0x03)
                                                            <= 0 ? 1 : 0);
    rc |= ber_flatten(ber, &val);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_put_bitstring/ber_flatten failed\n", __func__);
        ber_free(ber, 1);
        ber_bvfree(val);
        free(buf);
        return CKR_FUNCTION_FAILED;
    }

    memcpy(buf + der_AlgIdECBaseLen + params->ulValueLen, val->bv_val,
           val->bv_len);
    ber_free(ber, 1);

    rc = ber_encode_SEQUENCE(FALSE, data, data_len, buf,
                             der_AlgIdECBaseLen +
                             params->ulValueLen + val->bv_len);
    ber_bvfree(val);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s der_encode_Seq failed with rc=0x%lx\n", __func__, rc);
        free(buf);
        return rc;
    }
    free(buf);

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

    CK_BYTE *algid = NULL;
    CK_ULONG algid_len;
    CK_BYTE *algid_ECBase = NULL;
    CK_BYTE *param = NULL;
    CK_ULONG param_len;
    CK_BYTE *point = NULL;
    CK_ULONG point_len;
    CK_BYTE *ecpoint = NULL;
    CK_ULONG ecpoint_len;
    CK_ULONG field_len, len;
    CK_RV rc;

    UNUSED(data_len); // XXX can this parameter be removed ?

    rc = ber_decode_SPKI(data, &algid, &algid_len, &param, &param_len,
                         &point, &point_len);
    if (rc != CKR_OK) {
       TRACE_DEVEL("ber_decode_SPKI failed\n");
       return rc;
    }

    /*
     * Make sure we're dealing with an EC key.
     * Extract base alg-id of DER encoded EC byte string
     * and compare against the decoded alg-id from the inner sequence
     */
    rc = ber_decode_SEQUENCE((CK_BYTE *)der_AlgIdECBase, &algid_ECBase, &len,
                             &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_SEQUENCE failed\n");
        return rc;
    }

    if (memcmp(algid, algid_ECBase, len) != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    // build ec-parameter attribute
    rc = build_attribute(CKA_EC_PARAMS, param, param_len, &params_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto cleanup;
    }
    /* build ec-point attribute as BER encoded OCTET STRING */
    rc = ber_encode_OCTET_STRING(FALSE, &ecpoint, &ecpoint_len,
                                 point, point_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_OCTET_STRING failed\n");
        goto cleanup;
    }
    rc = build_attribute(CKA_EC_POINT, ecpoint, ecpoint_len, &point_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto cleanup;
    }

    free(ecpoint);
    *ec_params = params_attr;
    *ec_point = point_attr;
    return CKR_OK;

cleanup:
    if (params_attr)
        free(params_attr);
    if (point_attr)
        free(point_attr);
    if (ecpoint)
        free(ecpoint);

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
    len = 0;

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

CK_RV ber_encode_DHPublicKey(CK_BBOOL length_only, CK_BYTE **data,
                             CK_ULONG *data_len, CK_ATTRIBUTE *prime,
                             CK_ATTRIBUTE *base, CK_ATTRIBUTE *value)
{
    CK_ULONG len = 0, parm_len, id_len, pub_len, offset, total;
    CK_RV rc = 0;
    CK_BYTE *buf = NULL;
    CK_BYTE *buf2 = NULL;
    BerValue *val = NULL;
    BerElement *ber;

    /* Calculate the BER container length
     *
     * SPKI := SEQUENCE {
     *  SEQUENCE {
     *      OID
     *      Parameters
     *  }
     *  BITSTRING public key
     * }
     */

    offset = 0;
    rc = 0;
    total = 0;
    parm_len = 0;
    id_len = 0;
    pub_len = 0;

    /* OID and parameters */
    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, prime->ulValueLen);
    offset += len;
    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, base->ulValueLen);
    offset += len;
    rc |= ber_encode_SEQUENCE(TRUE, NULL, &parm_len, NULL, offset);
    rc |=
        ber_encode_SEQUENCE(TRUE, NULL, &id_len, NULL, ber_idDHLen + parm_len);

    /* public key */
    rc |=
        ber_encode_INTEGER(FALSE, &buf, &len, value->pValue, value->ulValueLen);
    ber = ber_alloc_t(LBER_USE_DER);
    rc |= (ber_put_bitstring(ber, (char *)buf, len * 8, 0x03) <= 0 ? 1 : 0);
    rc |= ber_flatten(ber, &val);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_put_bitstring/ber_flatten failed\n", __func__);
        ber_free(ber, 1);
        ber_bvfree(val);
        free(buf);
        return CKR_FUNCTION_FAILED;
    }

    pub_len = val->bv_len;
    ber_free(ber, 1);
    ber_bvfree(val);
    free(buf);

    rc |= ber_encode_SEQUENCE(TRUE, NULL, &total, NULL, id_len + pub_len);

    if (rc != CKR_OK) {
        TRACE_DEVEL("%s der_encode_sequence failed with rc=0x%lx\n", __func__,
                    rc);
        return rc;
    }

    if (length_only == TRUE) {
        *data_len = total;
        return rc;
    }

    buf = (CK_BYTE *) malloc(id_len + pub_len);
    if (!buf) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }

    /* Parameters */
    offset = 0;
    rc = ber_encode_INTEGER(FALSE, &buf2, &len, prime->pValue,
                            prime->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
        free(buf);
        return rc;
    }
    memcpy(buf + offset, buf2, len);
    offset += len;
    free(buf2);

    rc = ber_encode_INTEGER(FALSE, &buf2, &len, base->pValue, base->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
        free(buf);
        return rc;
    }
    memcpy(buf + offset, buf2, len);
    offset += len;
    free(buf2);

    rc = ber_encode_SEQUENCE(FALSE, &buf2, &parm_len, buf, offset);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Seq failed with rc=0x%lx\n", __func__, rc);
        free(buf);
        return rc;
    }

    /* OID and parameters */
    memcpy(buf, ber_idDH, ber_idDHLen);
    memcpy(buf + ber_idDHLen, buf2, parm_len);
    free(buf2);

    rc = ber_encode_SEQUENCE(FALSE, &buf2, &id_len, buf,
                             ber_idDHLen + parm_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Seq failed with rc=0x%lx\n", __func__, rc);
        free(buf);
        return rc;
    }
    free(buf);

    /* public key */
    rc = ber_encode_INTEGER(FALSE, &buf, &len, value->pValue,
                            value->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
        free(buf2);
        return rc;
    }

    ber = ber_alloc_t(LBER_USE_DER);
    rc = (ber_put_bitstring(ber, (char *)buf, len * 8, 0x03) <= 0 ? 1 : 0);
    rc |= ber_flatten(ber, &val);
    free(buf);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_put_bitstring/ber_flatten failed\n", __func__);
        ber_free(ber, 1);
        ber_bvfree(val);
        free(buf2);
        return CKR_FUNCTION_FAILED;
    }

    buf = (CK_BYTE *) malloc(id_len + val->bv_len);
    if (!buf) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        ber_free(ber, 1);
        ber_bvfree(val);
        free(buf2);
        return CKR_HOST_MEMORY;
    }
    memcpy(buf, buf2, id_len);
    memcpy(buf + id_len, val->bv_val, val->bv_len);
    free(buf2);
    ber_free(ber, 1);
    ber_bvfree(val);

    /* outer sequence */
    rc = ber_encode_SEQUENCE(FALSE, data, data_len, buf, id_len + pub_len);
    free(buf);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s der_encode_Seq failed with rc=0x%lx\n", __func__, rc);
        return rc;
    }

    return rc;
}


CK_RV ber_decode_DHPublicKey(CK_BYTE *data,
                             CK_ULONG data_len,
                             CK_ATTRIBUTE **prime,
                             CK_ATTRIBUTE **base,
                             CK_ATTRIBUTE **value)
{
    CK_ATTRIBUTE *prime_attr = NULL;
    CK_ATTRIBUTE *base_attr = NULL;
    CK_ATTRIBUTE *value_attr = NULL;

    CK_BYTE *algid = NULL;
    CK_ULONG algid_len;
    CK_BYTE *param = NULL;
    CK_ULONG param_len;
    CK_BYTE *val = NULL;
    CK_ULONG val_len;
    CK_BYTE *seq;
    CK_ULONG seq_len;
    CK_BYTE *p;
    CK_ULONG p_len;
    CK_BYTE *b;
    CK_ULONG b_len;
    CK_ULONG field_len, offset;
    CK_RV rc;

    UNUSED(data_len); // XXX can this parameter be removed ?

    rc = ber_decode_SPKI(data, &algid, &algid_len, &param, &param_len,
                         &val, &val_len);
    if (rc != CKR_OK) {
       TRACE_DEVEL("ber_decode_SPKI failed\n");
       return rc;
    }

    /*
     * Make sure we're dealing with an DH key.
     */
    if (memcmp(algid, ber_idDH, ber_idDHLen) != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    rc = ber_decode_SEQUENCE(param, &seq, &seq_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_SEQUENCE failed\n");
        return rc;
    }

    rc = ber_decode_INTEGER(seq, &p, &p_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        return rc;
    }

    offset = field_len;
    rc = ber_decode_INTEGER(seq + offset, &b, &b_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        return rc;
    }

    // build prime attribute
    rc = build_attribute(CKA_PRIME, p, p_len, &prime_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto cleanup;
    }
    // build base attribute
    rc = build_attribute(CKA_BASE, b, b_len, &base_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto cleanup;
    }
    // build value attribute
    rc = build_attribute(CKA_VALUE, val, val_len, &value_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto cleanup;
    }

    *prime = prime_attr;
    *base = base_attr;
    *value = value_attr;
    return CKR_OK;

cleanup:
    if (prime_attr)
        free(prime_attr);
    if (base_attr)
        free(base_attr);
    if (value_attr)
        free(value_attr);

    return rc;
}

/**
 * An IBM Dilithium public key is given by:
 *
 *  SEQUENCE (2 elem)
 *    SEQUENCE (2 elem)
 *      OBJECT IDENTIFIER 1.3.6.1.4.1.2.267.xxx
 *      NULL
 *    BIT STRING (1 elem)
 *      SEQUENCE (2 elem)
 *        BIT STRING (256 bit)   = 32 bytes
 *        BIT STRING (13824 bit) = 1728 bytes
 */
CK_RV ber_encode_IBM_DilithiumPublicKey(CK_BBOOL length_only,
                                        CK_BYTE **data, CK_ULONG *data_len,
                                        const CK_BYTE *oid, CK_ULONG oid_len,
                                        CK_ATTRIBUTE *rho, CK_ATTRIBUTE *t1)
{
    CK_BYTE *buf = NULL, *buf2 = NULL, *buf3 = NULL, *buf4 = NULL;
    CK_BYTE *buf5 = NULL, *algid = NULL;
    CK_ULONG len = 0, len4, offset, total, total_len, algid_len;
    CK_RV rc;

    UNUSED(length_only);

    offset = 0;
    rc = 0;
    total_len = 0;
    total = 0;

    /* Calculate storage for AlgID sequence */
    rc |= ber_encode_SEQUENCE(TRUE, NULL, &total_len, NULL,
                              oid_len + ber_NULLLen);

    /* Calculate storage for inner sequence */
    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, rho->ulValueLen);
    offset += len;
    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, t1->ulValueLen);
    offset += len;

    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
        return rc;
    }

    /* Allocate storage for inner sequence */
    buf = (CK_BYTE *) malloc(offset);
    if (!buf) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }

    /**
     *    SEQUENCE (2 elem)
     *       BIT STRING -> rho
     *       BIT STRING -> t
     */
    offset = 0;
    rc = ber_encode_BIT_STRING(FALSE, &buf2, &len,
                               rho->pValue, rho->ulValueLen, 0);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }
    memcpy(buf + offset, buf2, len);
    offset += len;
    free(buf2);
    buf2 = NULL;

    rc = ber_encode_BIT_STRING(FALSE, &buf2, &len,
                               t1->pValue, t1->ulValueLen, 0);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }
    memcpy(buf + offset, buf2, len);
    offset += len;
    free(buf2);
    buf2 = NULL;

    rc = ber_encode_SEQUENCE(FALSE, &buf2, &len, buf, offset);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_encode_Seq failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }
    free(buf);
    buf = NULL;

    /* Calculate length of outer sequence */
    rc = ber_encode_BIT_STRING(TRUE, NULL, &total, buf2, len, 0);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_encode_Oct_Str failed with rc=0x%lx\n", __func__, rc);
        goto error;
    } else {
        total_len += total;
    }

    /* Allocate storage for outer sequence and bit string */
    buf3 = (CK_BYTE *) malloc(total_len);
    if (!buf3) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    /*
     * SEQUENCE (2 elem)
     *      OBJECT IDENTIFIER 1.3.6.1.4.1.2.267.xxx
     *      NULL  <- no parms for this oid
     */
    buf5 = (CK_BYTE *) malloc(oid_len + ber_NULLLen);
    if (!buf5) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        rc = CKR_HOST_MEMORY;
        goto error;
    }
    memcpy(buf5, oid, oid_len);
    memcpy(buf5 + oid_len, ber_NULL, ber_NULLLen);

    rc = ber_encode_SEQUENCE(FALSE, &algid, &algid_len, buf5,
                             oid_len + ber_NULLLen);
    free(buf5);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_encode_SEQUENCE failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    total_len = algid_len;
    memcpy(buf3, algid, algid_len);
    free(algid);
    algid = NULL;

    /*
     * BIT STRING (1 elem)
     *       SEQUENCE (2 elem)
     *          BIT STRING  -> rho
     *          BIT STRING  -> t1
     */
    rc = ber_encode_BIT_STRING(FALSE, &buf4, &len4, buf2, len, 0);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_encode_BIT_STRING failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }
    memcpy(buf3 + total_len, buf4, len4);
    total_len += len4;
    free(buf4);
    buf4 = NULL;

    /**
     * SEQUENCE (2 elem)
     *    SEQUENCE (2 elem)
     *       OBJECT IDENTIFIER 1.3.6.1.4.1.2.267.1.6.5
     *       NULL -> no parms for this oid
     *    BIT STRING (1 elem)
     *       SEQUENCE (2 elem)
     *          BIT STRING  -> rho
     *          BIT STRING  -> t1
     */
    rc = ber_encode_SEQUENCE(FALSE, data, data_len, buf3, total_len);
    if (rc != CKR_OK)
        TRACE_ERROR("%s ber_encode_Seq failed with rc=0x%lx\n", __func__, rc);

error:

    if (buf)
        free(buf);
    if (buf2)
        free(buf2);
    if (buf3)
        free(buf3);

    return rc;
}


CK_RV ber_decode_IBM_DilithiumPublicKey(CK_BYTE *data,
                                        CK_ULONG data_len,
                                        CK_ATTRIBUTE **rho_attr,
                                        CK_ATTRIBUTE **t1_attr)
{
    CK_ATTRIBUTE *rho_attr_temp = NULL;
    CK_ATTRIBUTE *t1_attr_temp = NULL;

    CK_BYTE *algoid = NULL;
    CK_ULONG algoid_len;
    CK_BYTE *param = NULL;
    CK_ULONG param_len;
    CK_BYTE *val = NULL;
    CK_ULONG val_len;
    CK_BYTE *seq;
    CK_ULONG seq_len;
    CK_BYTE *rho;
    CK_ULONG rho_len;
    CK_BYTE *t1;
    CK_ULONG t1_len;
    CK_ULONG field_len, offset;
    CK_RV rc;

    UNUSED(data_len); // XXX can this parameter be removed ?

    rc = ber_decode_SPKI(data, &algoid, &algoid_len, &param, &param_len,
                         &val, &val_len);
    if (rc != CKR_OK) {
       TRACE_DEVEL("ber_decode_SPKI failed\n");
       return rc;
    }

    if (algoid_len != dilithium_r2_65_len ||
        memcmp(algoid, dilithium_r2_65, dilithium_r2_65_len) != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    /* Decode sequence:
     *     SEQUENCE (2 elem)
     *       BIT STRING = rho
     *       BIT STRING = t1
     */
    rc = ber_decode_SEQUENCE(val, &seq, &seq_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_SEQUENCE failed\n");
        return rc;
    }

    /* Decode rho */
    rc = ber_decode_BIT_STRING(seq, &rho, &rho_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        return rc;
    }
    rho++; /* Remove unused-bits byte */
    rho_len--;

    /* Decode t1 */
    offset = field_len;
    rc = ber_decode_BIT_STRING(seq + offset, &t1, &t1_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        return rc;
    }
    t1++; /* Remove unused-bits byte */
    t1_len--;

    /* Build rho attribute */
    rc = build_attribute(CKA_IBM_DILITHIUM_RHO, rho, rho_len, &rho_attr_temp);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto cleanup;
    }

    /* Build t1 attribute */
    rc = build_attribute(CKA_IBM_DILITHIUM_T1, t1, t1_len, &t1_attr_temp);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto cleanup;
    }

    *rho_attr = rho_attr_temp;
    *t1_attr = t1_attr_temp;

    return CKR_OK;

cleanup:
    if (rho_attr_temp)
        free(rho_attr_temp);
    if (t1_attr_temp)
        free(t1_attr_temp);

    return rc;
}

/**
 * An IBM Dilithium private key is given by:
 *
 *     DilithiumPrivateKey ::= SEQUENCE {
 *       version INTEGER,     -- v0, reserved 0
 *       rho BIT STRING,      -- nonce
 *       key BIT STRING,      -- key/seed/D
 *       tr  BIT STRING,      -- PRF bytes ('CRH' in spec)
 *       s1  BIT STRING,      -- vector(L)
 *       s2  BIT STRING,      -- vector(K)
 *       t0  BIT STRING       -- low bits(vector L)
 *       t1 [0] IMPLICIT OPTIONAL {
 *         t1  BIT STRING     -- high bits(vector L)  -- see also public key
 *       }
 *     }
 */
CK_RV ber_encode_IBM_DilithiumPrivateKey(CK_BBOOL length_only,
                                         CK_BYTE **data,
                                         CK_ULONG *data_len,
                                         const CK_BYTE *oid, CK_ULONG oid_len,
                                         CK_ATTRIBUTE *rho,
                                         CK_ATTRIBUTE *seed,
                                         CK_ATTRIBUTE *tr,
                                         CK_ATTRIBUTE *s1,
                                         CK_ATTRIBUTE *s2,
                                         CK_ATTRIBUTE *t0,
                                         CK_ATTRIBUTE *t1)
{
    CK_BYTE *buf = NULL, *buf2 = NULL, *buf3 = NULL;
    CK_BYTE *algid = NULL, *algid_buf = NULL;
    CK_ULONG len, len2 = 0, offset, algid_len = 0;
    CK_BYTE version[] = { 0 };
    CK_RV rc;

    /* Calculate storage for sequence */
    offset = 0;
    rc = 0;

    rc |= ber_encode_SEQUENCE(TRUE, NULL, &algid_len, NULL,
                              oid_len + ber_NULLLen);

    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, sizeof(version));
    offset += len;
    rc |= ber_encode_BIT_STRING(TRUE, NULL, &len, NULL, rho->ulValueLen, 0);
    offset += len;
    rc |= ber_encode_BIT_STRING(TRUE, NULL, &len, NULL, seed->ulValueLen, 0);
    offset += len;
    rc |= ber_encode_BIT_STRING(TRUE, NULL, &len, NULL, tr->ulValueLen, 0);
    offset += len;
    rc |= ber_encode_BIT_STRING(TRUE, NULL, &len, NULL, s1->ulValueLen, 0);
    offset += len;
    rc |= ber_encode_BIT_STRING(TRUE, NULL, &len, NULL, s2->ulValueLen, 0);
    offset += len;
    rc |= ber_encode_BIT_STRING(TRUE, NULL, &len, NULL, t0->ulValueLen, 0);
    offset += len;
    if (t1) {
        rc |= ber_encode_BIT_STRING(TRUE, NULL, &len2, NULL, t1->ulValueLen, 0);
        rc |= ber_encode_CHOICE(TRUE, 0, NULL, &len, NULL, len2);
        offset += len;
    }

    if (rc != CKR_OK) {
        TRACE_DEVEL("Calculate storage for sequence failed\n");
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
                                       NULL, algid_len,
                                       NULL, len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_PrivateKeyInfo failed\n");
            return rc;
        }
        return rc;
    }

    /* Allocate storage for sequence */
    buf = (CK_BYTE *) malloc(offset);
    if (!buf) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }
    offset = 0;

    /* Version */
    rc = ber_encode_INTEGER(FALSE, &buf2, &len, version, sizeof(version));
    if (rc != CKR_OK) {
        TRACE_ERROR("ber_encode_INTEGER of version failed\n");
        goto error;
    }
    memcpy(buf + offset, buf2, len);
    offset += len;
    free(buf2);
    buf2 = NULL;

    /* rho */
    rc = ber_encode_BIT_STRING(FALSE, &buf2, &len,
                            rho->pValue, rho->ulValueLen, 0);
    if (rc != CKR_OK) {
        TRACE_ERROR("ber_encode_BIT_STRING of rho failed\n");
        goto error;
    }
    memcpy(buf + offset, buf2, len);
    offset += len;
    free(buf2);
    buf2 = NULL;

    /* seed */
    rc = ber_encode_BIT_STRING(FALSE, &buf2, &len,
                            seed->pValue, seed->ulValueLen, 0);
    if (rc != CKR_OK) {
        TRACE_ERROR("ber_encode_BIT_STRING of seed failed\n");
        goto error;
    }
    memcpy(buf + offset, buf2, len);
    offset += len;
    free(buf2);
    buf2 = NULL;

    /* tr */
    rc = ber_encode_BIT_STRING(FALSE, &buf2, &len,
                               tr->pValue, tr->ulValueLen, 0);
    if (rc != CKR_OK) {
        TRACE_ERROR("ber_encode_BIT_STRING of (tr) failed\n");
        goto error;
    }
    memcpy(buf + offset, buf2, len);
    offset += len;
    free(buf2);
    buf2 = NULL;

    /* s1 */
    rc = ber_encode_BIT_STRING(FALSE, &buf2, &len,
                               s1->pValue, s1->ulValueLen, 0);
    if (rc != CKR_OK) {
        TRACE_ERROR("ber_encode_BIT_STRING of (s1) failed\n");
        goto error;
    }
    memcpy(buf + offset, buf2, len);
    offset += len;
    free(buf2);
    buf2 = NULL;

    /* s2 */
    rc = ber_encode_BIT_STRING(FALSE, &buf2, &len,
                               s2->pValue, s2->ulValueLen, 0);
    if (rc != CKR_OK) {
        TRACE_ERROR("ber_encode_BIT_STRING of (s2) failed\n");
        goto error;
    }
    memcpy(buf + offset, buf2, len);
    offset += len;
    free(buf2);
    buf2 = NULL;

    /* t0 */
    rc = ber_encode_BIT_STRING(FALSE, &buf2, &len,
                               t0->pValue, t0->ulValueLen, 0);
    if (rc != CKR_OK) {
        TRACE_ERROR("ber_encode_BIT_STRING of (t0) failed\n");
        goto error;
    }
    memcpy(buf + offset, buf2, len);
    offset += len;
    free(buf2);
    buf2 = NULL;

    /* (t1) Optional bit-string of public key */
    if (t1 && t1->pValue) {
        rc = ber_encode_BIT_STRING(FALSE, &buf3, &len2, t1->pValue, t1->ulValueLen, 0);
        rc |= ber_encode_CHOICE(FALSE, 0, &buf2, &len, buf3, len2);
        if (rc != CKR_OK) {
            TRACE_ERROR("encoding of t1 value failed\n");
            goto error;
        }
        memcpy(buf + offset, buf2, len);
        offset += len;
        free(buf2);
        buf2 = NULL;
    }

    /* Encode sequence */
    rc = ber_encode_SEQUENCE(FALSE, &buf2, &len, buf, offset);
    if (rc != CKR_OK) {
        TRACE_ERROR("ber_encode_SEQUENCE failed\n");
        goto error;
    }

    algid_buf = (CK_BYTE *) malloc(oid_len + ber_NULLLen);
    if (!algid_buf) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        rc = CKR_HOST_MEMORY;
        goto error;
    }
    memcpy(algid_buf, oid, oid_len);
    memcpy(algid_buf + oid_len, ber_NULL, ber_NULLLen);

    rc = ber_encode_SEQUENCE(FALSE, &algid, &algid_len, algid_buf,
                             oid_len + ber_NULLLen);
    free(algid_buf);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_encode_SEQUENCE failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    rc = ber_encode_PrivateKeyInfo(FALSE,
                                   data, data_len,
                                   algid, algid_len,
                                   buf2, len);
    if (rc != CKR_OK) {
        TRACE_ERROR("ber_encode_PrivateKeyInfo failed\n");
    }

error:
    if (buf3)
        free(buf3);
    if (buf2)
        free(buf2);
    if (buf)
        free(buf);
    if (algid)
        free(algid);

    return rc;
}

/**
 * decode an IBM Dilithium private key:
 *
 *       DilithiumPrivateKey ::= SEQUENCE {
 *         version INTEGER,     -- v0, reserved 0
 *         rho BIT STRING,      -- nonce
 *         key BIT STRING,      -- key/seed/D
 *         tr  BIT STRING,      -- PRF bytes ('CRH' in spec)
 *         s1  BIT STRING,      -- vector(L)
 *         s2  BIT STRING,      -- vector(K)
 *         t0  BIT STRING       -- low bits(vector L)
 *         t1 [0] IMPLICIT OPTIONAL {
 *           t1  BIT STRING     -- high bits(vector L)  -- see also public key
 *         }
 *       }
 */
CK_RV ber_decode_IBM_DilithiumPrivateKey(CK_BYTE *data,
                                         CK_ULONG data_len,
                                         CK_ATTRIBUTE **rho,
                                         CK_ATTRIBUTE **seed,
                                         CK_ATTRIBUTE **tr,
                                         CK_ATTRIBUTE **s1,
                                         CK_ATTRIBUTE **s2,
                                         CK_ATTRIBUTE **t0,
                                         CK_ATTRIBUTE **t1)
{
    CK_ATTRIBUTE *rho_attr = NULL, *seed_attr = NULL;
    CK_ATTRIBUTE *tr_attr = NULL, *s1_attr = NULL, *s2_attr = NULL;
    CK_ATTRIBUTE *t0_attr = NULL, *t1_attr = NULL;
    CK_BYTE *algoid = NULL;
    CK_BYTE *dilithium_priv_key = NULL;
    CK_BYTE *buf = NULL;
    CK_BYTE *tmp = NULL;
    CK_ULONG offset, buf_len, field_len, len, option;
    CK_RV rc;

    /* Check if this is a Dilithium private key */
    rc = ber_decode_PrivateKeyInfo(data, data_len, &algoid, &len,
                                   &dilithium_priv_key);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_PrivateKeyInfo failed\n");
        return rc;
    }

    if (len != dilithium_r2_65_len + ber_NULLLen ||
        memcmp(algoid, dilithium_r2_65, dilithium_r2_65_len) != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    /* Decode private Dilithium key */
    rc = ber_decode_SEQUENCE(dilithium_priv_key, &buf, &buf_len, &field_len);
    if (rc != CKR_OK)
        return rc;

    /* Now build the attributes */
    offset = 0;

    /* Skip the version */
    rc = ber_decode_INTEGER(buf + offset, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_INTEGER failed\n");
        goto cleanup;
    }
    offset += field_len;

    /* rho */
    rc = ber_decode_BIT_STRING(buf + offset, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_BIT_STRING of (rho) failed\n");
        goto cleanup;
    } else {
        tmp++; /* Remove unused-bits byte */
        len--;
        rc = build_attribute(CKA_IBM_DILITHIUM_RHO, tmp, len, &rho_attr);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_attribute for (rho) failed\n");
            goto cleanup;
        }
        offset += field_len;
    }

    /* seed */
    rc = ber_decode_BIT_STRING(buf + offset, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_BIT_STRING of (seed) failed\n");
        goto cleanup;
    } else {
        tmp++; /* Remove unused-bits byte */
        len--;
        rc = build_attribute(CKA_IBM_DILITHIUM_SEED, tmp, len, &seed_attr);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_attribute for (seed) failed\n");
            goto cleanup;
        }
        offset += field_len;
    }

    /* tr */
    rc = ber_decode_BIT_STRING(buf + offset, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_BIT_STRING of (tr) failed\n");
        goto cleanup;
    } else {
        tmp++; /* Remove unused-bits byte */
        len--;
        rc = build_attribute(CKA_IBM_DILITHIUM_TR, tmp, len, &tr_attr);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_attribute for (tr) failed\n");
            goto cleanup;
        }
        offset += field_len;
    }

    /* s1 */
    rc = ber_decode_BIT_STRING(buf + offset, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_BIT_STRING of (s1) failed\n");
        goto cleanup;
    } else {
        tmp++; /* Remove unused-bits byte */
        len--;
        rc = build_attribute(CKA_IBM_DILITHIUM_S1, tmp, len, &s1_attr);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_attribute for (s1) failed\n");
            goto cleanup;
        }
        offset += field_len;
    }

    /* s2 */
    rc = ber_decode_BIT_STRING(buf + offset, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_BIT_STRING of (s2) failed\n");
        goto cleanup;
    } else {
        tmp++; /* Remove unused-bits byte */
        len--;
        rc = build_attribute(CKA_IBM_DILITHIUM_S2, tmp, len, &s2_attr);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_attribute for (s2) failed\n");
            goto cleanup;
        }
        offset += field_len;
    }

    /* t0 */
    rc = ber_decode_BIT_STRING(buf + offset, &tmp, &len, &field_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_BIT_STRING of (t0) failed\n");
        goto cleanup;
    } else {
        tmp++; /* Remove unused-bits byte */
        len--;
        rc = build_attribute(CKA_IBM_DILITHIUM_T0, tmp, len, &t0_attr);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_attribute for (t0) failed\n");
            goto cleanup;
        }
        offset += field_len;
    }

    /* t1 (optional, within choice) */
    if (offset < buf_len) {
        rc = ber_decode_CHOICE(buf + offset, &tmp, &len, &field_len, &option);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_decode_BIT_STRING of (t1) failed\n");
            goto cleanup;
        }

        if (option != 0x00) {
            TRACE_DEVEL("ber_decode_CHOICE returned invalid option %ld\n",
                        option);
            goto cleanup;
        }

        offset += field_len - len;

        rc = ber_decode_BIT_STRING(buf + offset, &tmp, &len, &field_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_decode_BIT_STRING of (t1) failed\n");
            goto cleanup;
        }
        tmp++; /* Remove unused-bits byte */
        len--;

        rc = build_attribute(CKA_IBM_DILITHIUM_T1, tmp, len, &t1_attr);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_attribute for (t1) failed\n");
            goto cleanup;
        }
        offset += field_len;
    }

    /* Check if buffer big enough */
    if (offset > buf_len) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto cleanup;
    }

    *rho = rho_attr;
    *seed = seed_attr;
    *tr = tr_attr;
    *s1 = s1_attr;
    *s2 = s2_attr;
    *t0 = t0_attr;
    *t1 = t1_attr;

    return CKR_OK;

cleanup:

    if (seed_attr)
        free(seed_attr);
    if (t1_attr)
        free(t1_attr);
    if (rho_attr)
        free(rho_attr);
    if (tr_attr)
        free(tr_attr);
    if (s1_attr)
        free(s1_attr);
    if (s2_attr)
        free(s2_attr);
    if (t0_attr)
        free(t0_attr);

    return rc;
}
