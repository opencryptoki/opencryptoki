#!/usr/bin/perl
# This script parses the RSA test vectors found in $in_file
# and formats them for openCryptoki tests
#
# Fionnuala Gunter <fin@linux.vnet.ibm.com>
# August 18, 2011
#
#
# To run:
# download ftp://ftp.rsa.com/pub/rsalabs/tmp/pkcs1v15sign-vectors.tx
# ./rsa_parser.pl > rsa.h
#
#
#TODO: For some reason, there are extra blank lines printed...
#

# constants
$max_tv = 300; # maximum number of test vectors to add to file
$sub_max = 3;  # maximum number of messages/signatures per key pair
$count = 0;    # current number of test vectors added to file
$in_file = "pkcs1v15sign-vectors.txt"; # test vector source

# tmp
$string;

# input
$example = "# Example \d+: A \d+-bit RSA key pair";
$key = '# Private key';
$modulus = '# Modulus: ';
$publicexponent = '# Public exponent: ';
$privateexponent = '# Exponent: ';
$prime1_ = '# Prime 1: ';
$prime2_ = '# Prime 2: ';
$exponent1 = '# Prime exponent 1: ';
$exponent2 = '# Prime exponent 2: ';
$coefficient = '# Coefficient: ';
$msgblock = "# PKCS#1 v1.5 signing of 20 random messages ";
$msgsighead = "# PKCS#1 v1.5 Signature Example $num_msg ";
$msghead = '# Message to be signed:';
$sighead = '# Signature:';

# output
$begin_struct = "//ftp://ftp.rsa.com/pub/rsalabs/tmp/pkcs1v15sign-vectors.txt\n".
		"struct RSA_PUBLISHED_TEST_VECTOR ".
		"rsa_sha1_pkcs_sigver_published_tv[] = {\n";
$end_struct = "};\n";
$begin_ele = "\t{";
$end_ele = "\t},\n";
$begin_mod = "\t\t.mod = ";
$begin_pubexp = "\t\t.pub_exp = ";
$begin_privexp = "\t\t.priv_exp = ";
$begin_prime1 = "\t\t.prime1 = ";
$begin_prime2 = "\t\t.prime2 = ";
$begin_exp1 = "\t\t.exp1 = ";
$begin_exp2 = "\t\t.exp2 = ";
$begin_coef = "\t\t.coef = ";
$begin_msg = "\t\t.msg = ";
$begin_sig = "\t\t.sig = ";
$begin_modlen = "\t\t.mod_len = ";
$begin_pubexplen = "\t\t.pubexp_len = ";
$begin_privexplen = "\t\t.privexp_len = ";
$begin_prime1len = "\t\t.prime1_len = ";
$begin_prime2len = "\t\t.prime2_len = ";
$begin_exp1len = "\t\t.exp1_len = ";
$begin_exp2len = "\t\t.exp2_len = ";
$begin_coeflen = "\t\t.coef_len = ";
$begin_msglen = "\t\t.msg_len = ";
$begin_siglen = "\t\t.sig_len = ";


# giant block of generated tests that I copy-pasted here.
# this could be replaced with some functions that generate the data below
# TODO: CKM_CDMF_KEY_GEN doesn't seem to be supported by ICA, CCA or SoftTok,
# so those tests can be removed
$defheader = "#include \"pkcs11types.h\"
#define MAX_MODULUS_SIZE 256
#define MAX_EXPONENT_SIZE 256
#define MAX_MESSAGE_SIZE 512
#define MAX_SIGNATURE_SIZE 512
#define MAX_PRIME_SIZE  128
#define MAX_COEFFICIENT_SIZE 128
#define PKCS11_MAX_KEY_LEN 512


struct RSA_GENERATED_TEST_VECTOR {
	CK_ULONG modbits;
	CK_ULONG publ_exp_len;
	CK_BYTE  publ_exp[4];
	CK_ULONG inputlen;
	CK_MECHANISM keytype;
	CK_ULONG keylen;
};

static struct RSA_GENERATED_TEST_VECTOR rsa_keywrap_generated_tv[] = {
	{	// 0
		.modbits = 512,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 1,
		.keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
	}, {	// 1
		.modbits = 512,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 8,
		.keytype = {CKM_CDMF_KEY_GEN, 0, 0},
	}, {	// 2
		.modbits = 512,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 8,
		.keytype = {CKM_DES_KEY_GEN, 0, 0},
	}, {	// 3
		.modbits = 512,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 24,
		.keytype = {CKM_DES3_KEY_GEN, 0, 0},
	}, {	// 4
		.modbits = 512,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 16,
		.keytype = {CKM_AES_KEY_GEN, 0, 0},
	}, {	// 5
		.modbits = 512,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 32,
		.keytype = {CKM_AES_KEY_GEN, 0, 0},
	},{	// 6
                .modbits = 512,
                .publ_exp_len = 1,
                .publ_exp = { 0x03 },
                .keylen = 64,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        }, {	// 7
                .modbits = 512,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 1,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        }, {	// 8
                .modbits = 512,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 8,
                .keytype = {CKM_CDMF_KEY_GEN, 0, 0},
        }, {	// 9
                .modbits = 512,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 8,
                .keytype = {CKM_DES_KEY_GEN, 0, 0},
        }, {	// 10
                .modbits = 512,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 24,
                .keytype = {CKM_DES3_KEY_GEN, 0, 0},
        }, {	// 11
                .modbits = 512,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 16,
                .keytype = {CKM_AES_KEY_GEN, 0, 0},
        }, {	// 12
                .modbits = 512,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 32,
                .keytype = {CKM_AES_KEY_GEN, 0, 0},
        }, {	// 13
                .modbits = 512,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 64,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        }, {	// 14
                .modbits = 512,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 1,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        }, {	// 15
                .modbits = 512,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 8,
                .keytype = {CKM_CDMF_KEY_GEN, 0, 0},
        }, {	// 16
                .modbits = 512,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 8,
                .keytype = {CKM_DES_KEY_GEN, 0, 0},
        }, {	// 17
                .modbits = 512,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 24,
                .keytype = {CKM_DES3_KEY_GEN, 0, 0},
        }, {	// 18
                .modbits = 512,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 16,
                .keytype = {CKM_AES_KEY_GEN, 0, 0},
        }, {	// 19
                .modbits = 512,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 32,
                .keytype = {CKM_AES_KEY_GEN, 0, 0},
        },{	// 20
                .modbits = 512,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 64,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        }, {	// 21
		.modbits = 768,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 1,
		.keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0}
	}, {	// 22
		.modbits = 768,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 8,
		.keytype = {CKM_CDMF_KEY_GEN, 0, 0},
	}, {	// 23
		.modbits = 768,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 8,
		.keytype = {CKM_DES_KEY_GEN, 0, 0},
	}, {	// 24
		.modbits = 768,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 24,
		.keytype = {CKM_DES3_KEY_GEN, 0, 0},
	}, {	// 25
		.modbits = 768,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 16,
		.keytype = {CKM_AES_KEY_GEN, 0, 0},
	}, {	// 26
		.modbits = 768,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 32,
		.keytype = {CKM_AES_KEY_GEN, 0, 0},
	},{	// 27
                .modbits = 768,
                .publ_exp_len = 1,
                .publ_exp = { 0x03 },
                .keylen = 64,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        }, {	// 28
                .modbits = 768,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 1,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        }, {	// 29
                .modbits = 768,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 8,
                .keytype = {CKM_CDMF_KEY_GEN, 0, 0},
        }, {	// 30
                .modbits = 768,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 8,
                .keytype = {CKM_DES_KEY_GEN, 0, 0},
        }, {	// 31
                .modbits = 768,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 24,
                .keytype = {CKM_DES3_KEY_GEN, 0, 0}
        }, {	// 32
                .modbits = 768,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 16,
                .keytype = {CKM_AES_KEY_GEN, 0, 0},
        }, {	// 33
                .modbits = 768,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 32,
                .keytype = {CKM_AES_KEY_GEN, 0, 0},
        },{	// 34
                .modbits = 768,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 64,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        }, {	// 35
                .modbits = 768,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 1,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        }, {	// 36
                .modbits = 768,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 8,
                .keytype = {CKM_CDMF_KEY_GEN, 0, 0},
        }, {	// 37
                .modbits = 768,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 8,
                .keytype = {CKM_DES_KEY_GEN, 0, 0},
        }, {	// 38
                .modbits = 768,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 24,
                .keytype = {CKM_DES3_KEY_GEN, 0, 0},
        }, {	// 39
                .modbits = 768,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 16,
                .keytype = {CKM_AES_KEY_GEN, 0, 0},
        }, {	// 40
                .modbits = 768,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 32,
                .keytype = {CKM_AES_KEY_GEN, 0, 0},
        }, {	// 41
		.modbits = 768,
		.publ_exp_len = 3,
		.publ_exp = { 0x01, 0x00, 0x01 },
		.keylen = 96,
		.keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
	}, {	// 42
                .modbits = 1024,
                .publ_exp_len = 1,
                .publ_exp = { 0x03 },
                .keylen = 1,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        }, {	// 43
		.modbits = 1024,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 8,
		.keytype = {CKM_CDMF_KEY_GEN, 0, 0},
	}, {	// 44
		.modbits = 1024,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 8,
		.keytype = {CKM_DES_KEY_GEN, 0, 0},
	}, {	// 45
		.modbits = 1024,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 24,
		.keytype = {CKM_DES3_KEY_GEN, 0, 0},
	}, {	// 46
		.modbits = 1024,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 16,
		.keytype = {CKM_AES_KEY_GEN, 0, 0},
	}, {	// 47
		.modbits = 1024,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 32,
		.keytype = {CKM_AES_KEY_GEN, 0, 0},
	},{	// 48
                .modbits = 1024,
                .publ_exp_len = 1,
                .publ_exp = { 0x03 },
                .keylen = 96,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        }, {	// 49
                .modbits = 1024,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 1,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        }, {	// 50
                .modbits = 1024,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 8,
                .keytype = {CKM_CDMF_KEY_GEN, 0, 0},
        }, {	// 51
                .modbits = 1024,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 8,
                .keytype = {CKM_DES_KEY_GEN, 0, 0},
        }, {	// 52
                .modbits = 1024,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 24,
                .keytype = {CKM_DES3_KEY_GEN, 0, 0},
        }, {	// 53
                .modbits = 1024,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 16,
                .keytype = {CKM_AES_KEY_GEN, 0, 0},
        }, {	// 54
                .modbits = 1024,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 32,
                .keytype = {CKM_AES_KEY_GEN, 0, 0},
        },{	// 55
                .modbits = 1024,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 128,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        }, {	// 56
                .modbits = 1024,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 1,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        }, {	// 57
                .modbits = 1024,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 8,
                .keytype = {CKM_CDMF_KEY_GEN, 0, 0},
        }, {	// 58
                .modbits = 1024,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 8,
                .keytype = {CKM_DES_KEY_GEN, 0, 0},
        }, {	// 59
                .modbits = 1024,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 24,
                .keytype = {CKM_DES3_KEY_GEN, 0, 0},
        }, {	// 60
                .modbits = 1024,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 16,
                .keytype = {CKM_AES_KEY_GEN, 0, 0},
        }, {	// 61
                .modbits = 1024,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 32,
                .keytype = {CKM_AES_KEY_GEN, 0, 0},
        }, {	// 62
                .modbits = 1024,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 128,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        }, {	// 63
		.modbits = 2048,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 1,
		.keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
	}, {	// 64
		.modbits = 2048,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 8,
		.keytype = {CKM_CDMF_KEY_GEN, 0, 0},
	}, {	// 65
		.modbits = 2048,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 8,
		.keytype = {CKM_DES_KEY_GEN, 0, 0},
	}, {	// 66
		.modbits = 2048,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 24,
		.keytype = {CKM_DES3_KEY_GEN, 0, 0},
	}, {	// 67
		.modbits = 2048,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 16,
		.keytype = {CKM_AES_KEY_GEN, 0, 0},
	}, {	// 68
		.modbits = 2048,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 32,
		.keytype = {CKM_AES_KEY_GEN, 0, 0},
	},{	// 69
                .modbits = 2048,
                .publ_exp_len = 1,
                .publ_exp = { 0x03 },
                .keylen = 256,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        }, {	// 70
                .modbits = 2048,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 1,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        }, {	// 71
                .modbits = 2048,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 8,
                .keytype = {CKM_CDMF_KEY_GEN, 0, 0},
        }, {	// 72
                .modbits = 2048,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 8,
                .keytype = {CKM_DES_KEY_GEN, 0, 0},
        }, {	// 73
                .modbits = 2048,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 24,
                .keytype = {CKM_DES3_KEY_GEN, 0, 0},
        }, {	// 74
                .modbits = 2048,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 16,
                .keytype = {CKM_AES_KEY_GEN, 0, 0},
        }, {	// 75
                .modbits = 2048,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 32,
                .keytype = {CKM_AES_KEY_GEN, 0, 0},
        },{	// 76
                .modbits = 2048,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 256,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        }, {	// 77
                .modbits = 2048,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 1,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        },{	// 78
                .modbits = 2048,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 8,
                .keytype = {CKM_CDMF_KEY_GEN, 0, 0},
        }, {	// 79
                .modbits = 2048,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 8,
                .keytype = {CKM_DES_KEY_GEN, 0, 0},
        }, {	// 80
                .modbits = 2048,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 24,
                .keytype = {CKM_DES3_KEY_GEN, 0, 0},
        }, {	// 81
                .modbits = 2048,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 16,
                .keytype = {CKM_AES_KEY_GEN, 0, 0},
        }, {	// 82
                .modbits = 2048,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 32,
                .keytype = {CKM_AES_KEY_GEN, 0, 0},
        }, {	// 83
                .modbits = 2048,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 256,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        }, {	// 84
		.modbits = 4096,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 1,
		.keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
	}, {	// 85
		.modbits = 4096,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 8,
		.keytype = {CKM_CDMF_KEY_GEN, 0, 0},
	}, {	// 86
		.modbits = 4096,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 8,
		.keytype = {CKM_DES_KEY_GEN, 0, 0},
	}, {	// 87
		.modbits = 4096,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 24,
		.keytype = {CKM_DES3_KEY_GEN, 0, 0},
	}, {	// 88
		.modbits = 4096,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 16,
		.keytype = {CKM_AES_KEY_GEN, 0, 0},
	}, {	// 89
		.modbits = 4096,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.keylen = 32,
		.keytype = {CKM_AES_KEY_GEN, 0, 0},
	},{	// 90
                .modbits = 4096,
                .publ_exp_len = 1,
                .publ_exp = { 0x03 },
                .keylen = 512,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        }, {	// 91
                .modbits = 4096,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 1,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        }, {	// 92
                .modbits = 4096,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 8,
                .keytype = {CKM_CDMF_KEY_GEN, 0, 0},
        }, {	// 93
                .modbits = 4096,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 8,
                .keytype = {CKM_DES_KEY_GEN, 0, 0},
        }, {	// 94
                .modbits = 4096,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 24,
                .keytype = {CKM_DES3_KEY_GEN, 0, 0},
        }, {	// 95
                .modbits = 4096,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 16,
                .keytype = {CKM_AES_KEY_GEN, 0, 0},
        }, {	// 96
                .modbits = 4096,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 32,
                .keytype = {CKM_AES_KEY_GEN, 0, 0},
        },{	// 97
                .modbits = 4096,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .keylen = 512,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        }, {	// 98
                .modbits = 4096,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 1,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        },{	// 99
                .modbits = 4096,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 8,
                .keytype = {CKM_CDMF_KEY_GEN, 0, 0},
        }, {	// 100
                .modbits = 4096,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 8,
                .keytype = {CKM_DES_KEY_GEN, 0, 0},
        }, {	// 101
                .modbits = 4096,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 24,
                .keytype = {CKM_DES3_KEY_GEN, 0, 0},
        }, {	// 102
                .modbits = 4096,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 16,
                .keytype = {CKM_AES_KEY_GEN, 0, 0},
        }, {	// 103
                .modbits = 4096,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 32,
                .keytype = {CKM_AES_KEY_GEN, 0, 0},
        }, {	// 104
                .modbits = 4096,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .keylen = 512,
                .keytype = {CKM_GENERIC_SECRET_KEY_GEN, 0, 0},
        }

};

static struct RSA_GENERATED_TEST_VECTOR rsa_generated_tv[] = {
	{	// tv[0]
		.modbits = 512,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.inputlen = 1,
	}, {	//tv[1]
		.modbits = 512,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.inputlen = 53,
	}, {	//tv[2]
		.modbits = 512,
		.publ_exp_len = 2,
		.publ_exp = { 0x00, 0x11 },
		.inputlen = 1,
	}, {	//tv[3]
		.modbits = 512,
		.publ_exp_len = 2,
		.publ_exp = { 0x00, 0x11 },
		.inputlen = 53,
	}, {	//tv[4]
		.modbits = 512,
		.publ_exp_len = 3,
		.publ_exp = { 0x03, 0x00, 0x01 },
		.inputlen = 1,
	}, {	//tv[5]
		.modbits = 512,
		.publ_exp_len = 3,
		.publ_exp = { 0x03, 0x00, 0x01 },
		.inputlen = 53,
	}, {	//tv[6]
		.modbits = 768,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.inputlen = 1,
	}, {	//tv[7]
		.modbits = 768,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.inputlen = 85,
	}, {	//tv[8]
		.modbits = 768,
		.publ_exp_len = 2,
		.publ_exp = { 0x00, 0x11 },
		.inputlen = 1,
	}, {	//tv[9]
		.modbits = 768,
		.publ_exp_len = 2,
		.publ_exp = { 0x00, 0x11 },
		.inputlen = 85,
	}, {	//tv[10]
		.modbits = 768,
		.publ_exp_len = 3,
		.publ_exp = { 0x01, 0x00, 0x01 },
		.inputlen = 1,
	}, {	//tv[11]
		.modbits = 768,
		.publ_exp_len = 3,
		.publ_exp = { 0x01, 0x00, 0x01 },
		.inputlen = 85,
	}, {	//tv[12]
		.modbits = 1024,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.inputlen = 1,
	}, {	//tv[13]
		.modbits = 1024,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.inputlen = 117,
	}, {	//tv[14]
		.modbits = 1024,
		.publ_exp_len = 2,
		.publ_exp = { 0x00, 0x11 },
		.inputlen = 1,
	}, {	//tv[15]
		.modbits = 1024,
		.publ_exp_len = 2,
		.publ_exp = { 0x00, 0x11 },
		.inputlen = 117,
	}, {	//tv[16]
		.modbits = 1024,
		.publ_exp_len = 3,
		.publ_exp = { 0x01, 0x00, 0x01 },
		.inputlen = 1,
	}, {	//tv[17]
		.modbits = 1024,
		.publ_exp_len = 3,
		.publ_exp = { 0x01, 0x00, 0x01 },
		.inputlen = 117,
	}, {	//tv[18]
                .modbits = 2048,
                .publ_exp_len = 1,
                .publ_exp = { 0x03 },
                .inputlen = 1,
        }, {	//tv[19]
                .modbits = 2048,
                .publ_exp_len = 1,
                .publ_exp = { 0x03 },
                .inputlen = 245,
        }, {	//tv[20]
                .modbits = 2048,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .inputlen = 1,
        }, {	//tv[21]
                .modbits = 2048,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .inputlen = 245,
        }, {	//tv[22]
                .modbits = 2048,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .inputlen = 1,
        }, {	//tv[23]
                .modbits = 2048,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .inputlen = 245,
        }, {	//tv[24]
                .modbits = 4096,
                .publ_exp_len = 1,
                .publ_exp = { 0x03 },
                .inputlen = 1,
        }, {	//tv[25]
                .modbits = 4096,
                .publ_exp_len = 1,
                .publ_exp = { 0x03 },
                .inputlen = 501,
        }, {	//tv[26]
                .modbits = 4096,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .inputlen = 1,
        }, {	//tv[27]
                .modbits = 4096,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .inputlen = 501,
        }, {	//tv[28]
                .modbits = 4096,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .inputlen = 1,
        }, {	//tv[29]
                .modbits = 4096,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .inputlen = 501,
        },


};

static struct RSA_GENERATED_TEST_VECTOR rsa_x509_generated_tv[] = {
	{	// tv[0]
		.modbits = 512,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.inputlen = 1,
	}, {	// tv[1]
		.modbits = 512,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.inputlen = 64,
	}, {	// tv[2]
		.modbits = 512,
		.publ_exp_len = 2,
		.publ_exp = { 0x00, 0x11 },
		.inputlen = 1,
	}, {	// tv[3]
		.modbits = 512,
		.publ_exp_len = 2,
		.publ_exp = { 0x00, 0x11 },
		.inputlen = 64,
	}, {	// tv[4]
		.modbits = 512,
		.publ_exp_len = 3,
		.publ_exp = { 0x01, 0x00, 0x01 },
		.inputlen = 1,
	}, {	// tv[5]
		.modbits = 512,
		.publ_exp_len = 3,
		.publ_exp = { 0x01, 0x00, 0x01 },
		.inputlen = 64,
	}, {    // tv[6]
                .modbits = 768,
                .publ_exp_len = 1,
                .publ_exp = { 0x03 },
                .inputlen = 1,
        }, {    // tv[7]
                .modbits = 768,
                .publ_exp_len = 1,
                .publ_exp = { 0x03 },
                .inputlen = 96,
        }, {    // tv[8]
                .modbits = 768,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .inputlen = 1,
        }, {    // tv[9]
                .modbits = 768,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .inputlen = 96,
        }, {    // tv[10]
                .modbits = 768,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .inputlen = 1,
        }, {    // tv[11]
                .modbits = 768,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .inputlen = 96,
        }, {	// tv[12]
		.modbits = 1024,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.inputlen = 1
	}, {	// tv[13]
		.modbits = 1024,
		.publ_exp_len = 1,
		.publ_exp = { 0x03 },
		.inputlen = 128,
	}, {	// tv[14]
		.modbits = 1024,
		.publ_exp_len = 2,
		.publ_exp = { 0x00, 0x11 },
		.inputlen = 1,
	}, {	// tv[15]
		.modbits = 1024,
		.publ_exp_len = 2,
		.publ_exp = { 0x00, 0x11 },
		.inputlen = 128,
	}, {	// tv[16]
		.modbits = 1024,
		.publ_exp_len = 3,
		.publ_exp = { 0x01, 0x00, 0x01 },
		.inputlen = 1
	}, {	// tv[17]
		.modbits = 1024,
		.publ_exp_len = 3,
		.publ_exp = { 0x01, 0x00, 0x01 },
		.inputlen = 128,
	}, {     // tv[18]
                .modbits = 2048,
                .publ_exp_len = 1,
                .publ_exp = { 0x03 },
                .inputlen = 1
        }, {    // tv[19]
                .modbits = 2048,
                .publ_exp_len = 1,
                .publ_exp = { 0x03 },
                .inputlen = 256,
        }, {    // tv[20]
                .modbits = 2048,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .inputlen = 1,
        }, {    // tv[21]
                .modbits = 2048,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .inputlen = 256,
        }, {    // tv[22]
                .modbits = 2048,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .inputlen = 1
        }, {    // tv[23]
                .modbits = 2048,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .inputlen = 256,
        }, {     // tv[24]
                .modbits = 4096,
                .publ_exp_len = 1,
                .publ_exp = { 0x03 },
                .inputlen = 1
        }, {    // tv[25]
                .modbits = 4096,
                .publ_exp_len = 1,
                .publ_exp = { 0x03 },
                .inputlen = 512,
        }, {    // tv[26]
                .modbits = 4096,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .inputlen = 1,
        }, {    // tv[27]
                .modbits = 4096,
                .publ_exp_len = 2,
                .publ_exp = { 0x00, 0x11 },
                .inputlen = 512,
        }, {    // tv[28]
                .modbits = 4096,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .inputlen = 1
        }, {    // tv[29]
                .modbits = 4096,
                .publ_exp_len = 3,
                .publ_exp = { 0x01, 0x00, 0x01 },
                .inputlen = 512,
        }
};

struct GENERATED_TEST_SUITE_INFO {
	const char *name;
	unsigned int tvcount;
	struct RSA_GENERATED_TEST_VECTOR *tv;
	CK_MECHANISM mech;
};

#define NUM_OF_GENERATED_KEYWRAP_TESTSUITES 2
struct GENERATED_TEST_SUITE_INFO generated_keywrap_test_suites[] = {
	{
		.name = \"RSA PKCS\",
		.tvcount = 105,
		.tv = rsa_keywrap_generated_tv,
		.mech = {CKM_RSA_PKCS, 0, 0},
	}, {
		.name = \"RSA X.509\",
		.tvcount = 105,
		.tv = rsa_keywrap_generated_tv,
		.mech = {CKM_RSA_X_509, 0, 0},
	}
};


#define NUM_OF_GENERATED_SIGVER_TESTSUITES 5
struct GENERATED_TEST_SUITE_INFO generated_sigver_test_suites[] = {
	{
		.name = \"RSA PKCS\",
		.tvcount = 30,
		.tv = rsa_generated_tv,
		.mech = {CKM_RSA_PKCS, 0, 0},
	}, {
		.name = \"RSA SHA1 PKCS\",
		.tvcount = 30,
		.tv = rsa_generated_tv,
		.mech = {CKM_SHA1_RSA_PKCS, 0, 0},
	}, {
		.name = \"RSA MD2 PKCS\",
		.tvcount = 30,
		.tv = rsa_generated_tv,
		.mech = {CKM_MD2_RSA_PKCS, 0, 0},
	}, {
		.name = \"RSA MD5 PKCS\",
		.tvcount = 30,
		.tv = rsa_generated_tv,
		.mech = {CKM_MD5_RSA_PKCS, 0 , 0},
	}, {
		.name = \"RSA X.509\",
		.tvcount = 30,
		.tv = rsa_x509_generated_tv,
		.mech = {CKM_RSA_X_509, 0 , 0},
	}
};

#define NUM_OF_GENERATED_CRYPTO_TESTSUITES 2
struct GENERATED_TEST_SUITE_INFO generated_crypto_test_suites[] = {
	{
		.name = \"RSA PKCS\",
		.tvcount = 30,
		.tv = rsa_generated_tv,
		.mech = {CKM_RSA_PKCS, 0, 0},
	}, {
		.name = \"RSA X.509\",
		.tvcount = 30,
		.tv = rsa_x509_generated_tv,
		.mech = {CKM_RSA_X_509, 0, 0},
	}
};

struct RSA_PUBLISHED_TEST_VECTOR {
        CK_BYTE mod[MAX_MODULUS_SIZE];          // n
        CK_ULONG mod_len;
        CK_BYTE prime1[MAX_PRIME_SIZE];         // p
        CK_ULONG prime1_len;
        CK_BYTE prime2[MAX_PRIME_SIZE];         // q
        CK_ULONG prime2_len;
        CK_BYTE exp1[MAX_EXPONENT_SIZE];        // d % (p-1)
        CK_ULONG exp1_len;
        CK_BYTE exp2[MAX_EXPONENT_SIZE];        // d % (q-1)
        CK_ULONG exp2_len;
        CK_BYTE coef[MAX_COEFFICIENT_SIZE]; 	// (q^-1) % p
        CK_ULONG coef_len;
        CK_BYTE pub_exp[MAX_EXPONENT_SIZE];     // e
        CK_ULONG pubexp_len;
        CK_BYTE priv_exp[MAX_EXPONENT_SIZE];    // d
        CK_ULONG privexp_len;
        CK_BYTE msg[MAX_MESSAGE_SIZE];
        CK_ULONG msg_len;
        CK_BYTE sig[MAX_SIGNATURE_SIZE];
        CK_ULONG sig_len;
};\n";

# vars

@mod;
@pubexp;
@privexp;
@prime1;
@prime2;
@exp1;
@exp2;
@coef;
@msg;
@sig;

$modlen = 0;
$pubexplen = 0;
$privexplen = 0;
$prime1len = 0;
$prime2len = 0;
$exp1len = 0;
$exp2len = 0;
$coeflen = 0;
$msglen = 0;
$siglen = 0;

# open test vector file
# parse contents
# print results
open ($file, $in_file);
print $defheader;
print $begin_struct;
my $subcount;
while (<$file>) {
	# parse key pair
	if ($_ =~ $key){
		parse_keys();
		$subcount = 0;
	}
	# parse message
	if ($_ =~ $msghead){
		#print "\n";
		parse_msg();
	}
	# parse signature and print struct element
	if ($_ =~ $sighead){
		#print "\n";
		parse_sig();
		if ($subcount < $sub_max){
			print_ele();
			$count++;
		}
		if ($count > $max_tv){
			last;
		}
		#$count++;
		$subcount++;
	}
}
print $end_struct;
print "\n";

$footer = "struct PUBLISHED_TEST_SUITE_INFO {
        const char *name;
        unsigned int tvcount;
        struct RSA_PUBLISHED_TEST_VECTOR *tv;
        CK_MECHANISM mech;
        unsigned int result;
};

#define NUM_OF_PUBLISHED_TESTSUITES 1
struct PUBLISHED_TEST_SUITE_INFO published_test_suites[] = {
        {
                .name = \"RSA SHA-1 PKCS v1.5\",
                .tvcount = $count,
                .tv = rsa_sha1_pkcs_sigver_published_tv,
                .mech = {CKM_SHA1_RSA_PKCS, 0, 0},
        }


};";

print $footer;
close ($file);

sub parse_keys(){
	while (<$file>){
		print "\n";
                # skip # -----
                if ($_ =~ m/^# -/){
			next;
                }

                # skip " "
                elsif (length($_) == 1 || length($_) == 2 || (!$_)){
			next;
                }

                # parse modulus
                elsif ($_ =~ $modulus){
                        parse_mod();
                        next;
                }

                # parse public exponent
                elsif ($_ =~ $publicexponent){
                        parse_pubexp();
                        next;
                }

		# parse private exponent
                elsif ($_ =~ $privateexponent){
                        parse_privexp();
                        next;
                }

                # parse prime1
                elsif ($_ =~ $prime1_){
                        parse_prime1();
                        next;
                }

                # parse prime2
                elsif ($_ =~ $prime2_){
                        parse_prime2();
                        next;
                }

                # parse exponent1
                elsif ($_ =~ $exponent1){
                        parse_exp1();
                        next;
                }

		# parse exponent2
                elsif ($_ =~ $exponent2){
                        parse_exp2();
                        next;
                }

                # parse coefficient
                elsif ($_ =~ $coefficient){
                        parse_coef();
			last;
                }
	}
}

# parse modulus
sub parse_mod(){
	@mod = ();
	while (<$file>){
                if ($_ =~ m{\S+}){
                        for (my $n = 0; ($n + 2) < length($_); $n+=3) {
				$string = "0x".substr($_, $n, 2);
				push(@mod, $string);
                        }
                }
                else {
			$modlen = @mod;
                        last;
                }
        }
}

# parse public exponent
sub parse_pubexp(){
	@pubexp = ();
        while (<$file>){
                if ($_ =~ m{\S+}){
                        for (my $n = 0; ($n + 2) < length($_); $n+=3) {
                                $string = "0x".substr($_, $n, 2);
                                push(@pubexp, $string);
                        }
                }
                else {
			$pubexplen = @pubexp;
                        last;
                }
        }
}

# parse private exponent
sub parse_privexp(){
        @privexp = ();
        while (<$file>){
                if ($_ =~ m{\S+}){
                        for (my $n = 0; ($n + 2) < length($_); $n+=3) {
                                $string = "0x".substr($_, $n, 2);
                                push(@privexp, $string);
                        }
                }
                else {
			$privexplen = @privexp;
                        last;
                }
        }
}

# parse prime 1
sub parse_prime1(){
        @prime1 = ();
        while (<$file>){
                if ($_ =~ m{\S+}){
                        for (my $n = 0; ($n + 2) < length($_); $n+=3) {
                                $string = "0x".substr($_, $n, 2);
                                push(@prime1, $string);
                        }
                }
                else {
			$prime1len = @prime1;
                        last;
                }
        }
}

# parse prime 2
sub parse_prime2(){
        @prime2 = ();
        while (<$file>){
                if ($_ =~ m{\S+}){
                        for (my $n = 0; ($n + 2) < length($_); $n+=3) {
                                $string = "0x".substr($_, $n, 2);
                                push(@prime2, $string);
                        }
                }
                else {
			$prime2len = @prime2;
                        last;
                }
        }
}

# parse exponent 1
sub parse_exp1(){
        @exp1 = ();
        while (<$file>){
                if ($_ =~ m{\S+}){
                        for (my $n = 0; ($n + 2) < length($_); $n+=3) {
                                $string = "0x".substr($_, $n, 2);
                                push(@exp1, $string);
                        }
                }
                else {
			$exp1len = @exp1;
                        last;
                }
        }
}

# parse exponent 2
sub parse_exp2(){
        @exp2 = ();
        while (<$file>){
                if ($_ =~ m{\S+}){
                        for (my $n = 0; ($n + 2) < length($_); $n+=3) {
                                $string = "0x".substr($_, $n, 2);
                                push(@exp2, $string);
                        }
                }
                else {
			$exp2len = @exp2;
                        last;
                }
        }
}

# parse coefficient
sub parse_coef(){
        @coef = ();
        while (<$file>){
                if ($_ =~ m{\S+}){
                        for (my $n = 0; ($n + 2) < length($_); $n+=3) {
                                $string = "0x".substr($_, $n, 2);
                                push(@coef, $string);
                        }
                }
                else {
			$coeflen = @coef;
                        last;
                }
        }
}

# parse message
sub parse_msg(){
        @msg = ();
        while (<$file>){
                if ($_ =~ m{\S+}){
                        for (my $n = 0; ($n + 2) < length($_); $n+=3) {
                                $string = "0x".substr($_, $n, 2);
                                push(@msg, $string);
                        }
                }
                else {
			$msglen = @msg;
                        last;
                }
        }
}

# parse signature
sub parse_sig(){
        @sig = ();
        while (<$file>){
                if ($_ =~ m{\S+}){
                        for (my $n = 0; ($n + 2) < length($_); $n+=3) {
                                $string = "0x".substr($_, $n, 2);
                                push(@sig, $string);
                        }
                }
                else {
			$siglen = @sig;
                        last;
                }
        }
}

# prints test vector
sub print_ele(){
	print $begin_ele;
	print "\t/\/\ $count\n"; # new
        print_mod();
        print_pubexp();
        print_privexp();
        print_prime1();
        print_prime2();
        print_exp1();
        print_exp2();
        print_coef();
        print_msg();
	print_sig();
	print $end_ele;
}

# prints modulus
sub print_mod(){
	print $begin_mod;
	print "\t      { ";
	for (my $n = 0; $n < $modlen; $n++){
		print $mod[$n];
		if ($n + 1 < $modlen){
			print ",";
		}
		if (($n + 1 < $modlen) && !(($n + 1) % 8)){
			print "\n\t\t\t\t";
		}
	}
	print " },\n";
	print $begin_modlen;
	print $modlen;
	print ",\n";
}

# prints public exponent
sub print_pubexp(){
	print $begin_pubexp;
	print "   { ";
	for (my $n = 0; $n < $pubexplen; $n++){
		print $pubexp[$n];
		if ($n + 1 < $pubexplen){
			print ",";
		}
	}
	print " },\n";
	print $begin_pubexplen;
	print $pubexplen;
	print ",\n";
}

# prints private exponent
sub print_privexp(){
        print $begin_privexp;
        print "  { ";
        for (my $n = 0; $n < $privexplen; $n++){
                print $privexp[$n];
		if ($n + 1 < $privexplen){
			print ",";
		}
		if (($n + 1 < $privexplen) && !(($n + 1) % 8)){
                        print "\n\t\t\t\t";
                }

        }
        print " },\n";
	print $begin_privexplen;
	print $privexplen;
	print ",\n";
}

# prints prime 1
sub print_prime1(){
        print $begin_prime1;
        print "    { ";
        for (my $n = 0; $n < $prime1len; $n++){
                print $prime1[$n];
                if ($n + 1 < $prime1len){
			print ",";
		}
		if (($n + 1 < $prime1len) && !(($n + 1) % 8)){
                        print "\n\t\t\t\t";
                }

        }
        print " },\n";
	print $begin_prime1len;
	print $prime1len;
	print ",\n";
}

# prints prime 2
sub print_prime2(){
        print $begin_prime2;
        print "    { ";
        for (my $n = 0; $n < $prime2len; $n++){
                print $prime2[$n];
		if ($n + 1 < $prime2len){
			print ",";
		}
		if (($n + 1 < $prime2len) && !(($n + 1) % 8)){
                        print "\n\t\t\t\t";
                }

        }
        print " },\n";
	print $begin_prime2len;
	print $prime2len;
	print ",\n";
}

# prints exponent 1
sub print_exp1(){
        print $begin_exp1;
        print "      { ";
        for (my $n = 0; $n < $exp1len; $n++){
                print $exp1[$n];
                if ($n + 1 < $exp1len){
			print ",";
		}
		if (($n + 1 < $exp1len) && !(($n + 1) % 8)){
                        print "\n\t\t\t\t";
                }

        }
        print " },\n";
	print $begin_exp1len;
	print $exp1len;
	print ",\n";
}

# prints exponent 2
sub print_exp2(){
        print $begin_exp2;
        print "      { ";
        for (my $n = 0; $n < $exp2len; $n++){
                print $exp2[$n];
                if ($n + 1 < $exp2len){
			print ",";
		}
		if (($n + 1 < $exp2len) && !(($n + 1) % 8)){
                        print "\n\t\t\t\t";
                }

        }
        print " },\n";
	print $begin_exp2len;
	print $exp2len;
	print ",\n";
}

# prints coefficient
sub print_coef(){
        print $begin_coef;
        print "      { ";
        for (my $n = 0; $n < $coeflen; $n++){
                print $coef[$n];
                if ($n + 1 < $coeflen){
			print ",";
		}
		if (($n + 1 < $coeflen) && !(($n + 1) % 8)){
                        print "\n\t\t\t\t";
                }

        }
        print " },\n";
	print $begin_coeflen;
	print $coeflen;
	print ",\n";
}

# prints message
sub print_msg(){
        print $begin_msg;
        print "       { ";
        for (my $n = 0; $n < $msglen; $n++){
                print $msg[$n];
                if ($n + 1 < $msglen){
			print ",";
		}
		if (($n + 1 < $msglen) && !(($n + 1) % 8)){
                        print "\n\t\t\t\t";
                }

        }
        print " },\n";
	print $begin_msglen;
	print $msglen;
	print ",\n";
}

# prints signature
sub print_sig(){
        print $begin_sig;
        print "       { ";
        for (my $n = 0; $n < $siglen; $n++){
                print $sig[$n];
                if ($n + 1 < $siglen){
			print ",";
		}
		if (($n + 1 < $siglen) && !(($n + 1) % 8)){
                        print "\n\t\t\t\t";
                }

        }
        print " },\n";
	print $begin_siglen;
	print $siglen;
	print ",\n";
}

