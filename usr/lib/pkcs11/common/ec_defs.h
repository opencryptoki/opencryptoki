/*
 * Licensed materials, Property of IBM Corp.
 *
 * openCryptoki
 *
 * (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2006
 *
 *
 */

#ifndef _EC_DEFS
#define _EC_DEFS


// Elliptic Curve type
//
#define PRIME_CURVE		0x00
#define BRAINPOOL_CURVE		0x01

// Elliptic Curve length in bits
//
#define CURVE160		0x00A0
#define CURVE192		0x00C0
#define CURVE224		0x00E0
#define CURVE256		0x0100
#define CURVE320		0x0140
#define CURVE384		0x0180
#define CURVE512		0x0200
#define CURVE521		0x0209

/* Supported Elliptic Curves */
#define NUMEC			12	/* number of supported curves */
extern CK_BYTE brainpoolP160r1[];
extern CK_BYTE brainpoolP192r1[];
extern CK_BYTE brainpoolP224r1[];
extern CK_BYTE brainpoolP256r1[];
extern CK_BYTE brainpoolP320r1[];
extern CK_BYTE brainpoolP384r1[];
extern CK_BYTE brainpoolP512r1[];
extern CK_BYTE prime192[];
extern CK_BYTE secp224[];
extern CK_BYTE prime256[];
extern CK_BYTE secp384[];
extern CK_BYTE secp521[];


// structure of supported Elliptic Curves

struct _ec {
	uint8_t		curve_type;	/* uint8_t - prime or brainpool curve */
	uint16_t	len_bits;	/* uint16_t - len in bits */
	CK_ULONG	data_size;
	CK_VOID_PTR	data;
}__attribute__ ((__packed__));

extern struct _ec der_ec_supported[NUMEC];
#endif
