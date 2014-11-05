#include "pkcs11types.h"

#define DES_KEY_SIZE 8
#define DES_IV_SIZE 8
#define MAX_TEXT_SIZE 8
#define DES_BLOCK_SIZE 8
#define MAX_CHUNKS 8

char des_cbc_iv[] =  {0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef};

struct CK_MECHANISM des_keygen = {
	.mechanism = CKM_DES_KEY_GEN,
	.ulParameterLen = 0,
	.pParameter = NULL,
};

struct des_test_vector {
	char key[DES_KEY_SIZE];
	unsigned char klen;
	char iv [DES_IV_SIZE];
	unsigned char ivlen;
	char plaintext[MAX_TEXT_SIZE];
	unsigned char plen;
	char ciphertext[MAX_TEXT_SIZE];
	unsigned char clen;
	int chunks[MAX_CHUNKS];
	int num_chunks;
};

struct published_test_suite_info {
	const char *name;
	unsigned int tvcount;
	struct des_test_vector *tv;
	unsigned long mechanism;
};

struct generated_test_suite_info {
	const char *name;
	CK_MECHANISM mech;
};

/** FIPS PUB 81 - DES MODES OF OPERATION
    http://www.itl.nist.gov/fipspubs/fip81.htm
    Table B1 - AN EXAMPLE OF THE ELECTRONIC CODEBOOK (ECB) MODE
**/
static struct des_test_vector des_ecb_tv[] = {
	{   // 1
		.key = 		{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef},
		.klen = 8,
		.iv   =	 {},
		.ivlen = 0,
		.plaintext = 	{0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74},
		.plen = 8,
		.ciphertext = 	{0x3f,0xa4,0x0e,0x8a,0x98,0x4d,0x48,0x15},
		.clen = 8
	}, { // 2
		.key = 		{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef},
		.klen = 8,
		.iv =	   {},
		.ivlen = 0,
		.plaintext = 	{0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20},
		.plen = 8,
		.ciphertext = 	{0x6a,0x27,0x17,0x87,0xab,0x88,0x83,0xf9},
		.clen = 8,
		.num_chunks = 3,
		.chunks = 	{ 3, 0, 5 },
	}, { // 3
		.key = 		{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef},
		.klen = 8,
		.iv =	   {},
		.ivlen = 0,
		.plaintext = 	{0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20},
		.plen = 8,
		.ciphertext = 	{0x89,0x3d,0x51,0xec,0x4b,0x56,0x3b,0x53},
		.clen = 8,
		.num_chunks = 3,
		.chunks = 	{ 4, -1, 4 },
	},
};

/** NIST Special Publication 800-17
    http://csrc.nist.gov/publications/nistpubs/800-17/800-17.pdf
    Appendix B - Variable Key Known Answer Test
**/
static struct des_test_vector des_cbc_tv[] = {
	{       // round 0
		.key =	  	{0x80,0x01,0x01,0x01,0x01,0x01,0x01,0x01},
		.klen = 8,
		.iv =	   	{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
		.ivlen = 8,
		.plaintext =    {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
		.plen = 8,
		.ciphertext =   {0x95,0xA8,0xD7,0x28,0x13,0xDA,0xA9,0x4D},
		.clen = 8,
	}, {       // round 1
		.key =	  	{0x40,0x01,0x01,0x01,0x01,0x01,0x01,0x01},
		.klen = 8,
		.iv =	   	{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
		.ivlen = 8,
		.plaintext =    {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
		.plen = 8,
		.ciphertext =   {0x0E,0xEC,0x14,0x87,0xDD,0x8C,0x26,0xD5},
		.clen = 8,
		.num_chunks = 3,
		.chunks = 	{ 3, 0, 5 },
	}, {       // round 2
		.key =	  	{0x20,0x01,0x01,0x01,0x01,0x01,0x01,0x01},
		.klen = 8,
		.iv =	   	{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
		.ivlen = 8,
		.plaintext =    {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
		.plen = 8,
		.ciphertext =   {0x7A,0xD1,0x6F,0xFB,0x79,0xC4,0x59,0x26},
		.clen = 8,
		.num_chunks = 3,
		.chunks = 	{ 4, -1, 4 },
	},
};


# define NUM_OF_PUBLISHED_TESTSUITES	2

struct published_test_suite_info published_test_suites[] = {
	{
		.name ="DES_ECB",
		.tvcount = 3,
		.tv = des_ecb_tv,
		.mechanism = CKM_DES_ECB,
	}, {
		.name = "DES_CBC",
		.tvcount = 3,
		.tv = des_cbc_tv,
		.mechanism = CKM_DES_CBC,
	}
};

#define NUM_OF_GENERATED_TESTSUITES 3

static struct generated_test_suite_info generated_test_suites[]  = {
	{
		.name = "DES_ECB",
		.mech = {CKM_DES_ECB, 0, 0},
	}, {
		.name = "DES_CBC",
		.mech = {CKM_DES_CBC, &des_cbc_iv, DES_IV_SIZE},
	}, {
		.name = "DES_CBC_PAD",
		.mech = {CKM_DES_CBC_PAD, &des_cbc_iv, DES_IV_SIZE},
	}

};
