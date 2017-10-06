/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * openCryptoki CCA token
 *
 * Author: Kent E. Yoder <yoder1@us.ibm.com>
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <limits.h>
#include <syslog.h>
#include <dlfcn.h>
#include <arpa/inet.h>
#include "cca_stdll.h"
#include "pkcs11types.h"
#include "p11util.h"
#include "defs.h"
#include "host_defs.h"
#include "tok_specific.h"
#include "tok_struct.h"
#include "h_extern.h"
#include "csulincl.h"
#include "ec_defs.h"
#include "trace.h"
#include "cca_func.h"

CK_CHAR manuf[] = "IBM Corp.";
CK_CHAR model[] = "IBM CCA Token";
CK_CHAR descr[] = "IBM PKCS#11 CCA Token";
CK_CHAR label[] = "IBM PKCS#11 for CCA";

#define CCASHAREDLIB "libcsulcca.so"

static CSNBCKI_t	dll_CSNBCKI;
static CSNBCKM_t	dll_CSNBCKM;
static CSNBDKX_t	dll_CSNBDKX;
static CSNBDKM_t	dll_CSNBDKM;
static CSNBMKP_t	dll_CSNBMKP;
static CSNBKEX_t	dll_CSNBKEX;
static CSNBKGN_t	dll_CSNBKGN;
static CSNBKGN2_t	dll_CSNBKGN2;
static CSNBKIM_t	dll_CSNBKIM;
static CSNBKPI_t	dll_CSNBKPI;
static CSNBKPI2_t	dll_CSNBKPI2;
static CSNBKSI_t	dll_CSNBKSI;
static CSNBKRC_t	dll_CSNBKRC;
static CSNBAKRC_t	dll_CSNBAKRC;
static CSNBKRD_t	dll_CSNBKRD;
static CSNBKRL_t	dll_CSNBKRL;
static CSNBKRR_t	dll_CSNBKRR;
static CSNBKRW_t	dll_CSNBKRW;
static CSNDKRC_t	dll_CSNDKRC;
static CSNDKRD_t	dll_CSNDKRD;
static CSNDKRL_t	dll_CSNDKRL;
static CSNDKRR_t	dll_CSNDKRR;
static CSNDKRW_t	dll_CSNDKRW;
static CSNBKYT_t	dll_CSNBKYT;
static CSNBKYTX_t	dll_CSNBKYTX;
static CSNBKTC_t	dll_CSNBKTC;
static CSNBKTR_t	dll_CSNBKTR;
static CSNBRNG_t	dll_CSNBRNG;
static CSNBSAE_t	dll_CSNBSAE;
static CSNBSAD_t	dll_CSNBSAD;
static CSNBDEC_t	dll_CSNBDEC;
static CSNBENC_t	dll_CSNBENC;
static CSNBMGN_t	dll_CSNBMGN;
static CSNBMVR_t	dll_CSNBMVR;
static CSNBKTB_t	dll_CSNBKTB;
static CSNBKTB2_t	dll_CSNBKTB2;
static CSNDPKG_t	dll_CSNDPKG;
static CSNDPKB_t	dll_CSNDPKB;
static CSNBOWH_t	dll_CSNBOWH;
static CSNDPKI_t	dll_CSNDPKI;
static CSNDDSG_t	dll_CSNDDSG;
static CSNDDSV_t	dll_CSNDDSV;
static CSNDKTC_t	dll_CSNDKTC;
static CSNDPKX_t	dll_CSNDPKX;
static CSNDSYI_t	dll_CSNDSYI;
static CSNDSYX_t	dll_CSNDSYX;
static CSUACFQ_t	dll_CSUACFQ;
static CSUACFC_t	dll_CSUACFC;
static CSNDSBC_t	dll_CSNDSBC;
static CSNDSBD_t	dll_CSNDSBD;
static CSUALCT_t	dll_CSUALCT;
static CSUAACM_t	dll_CSUAACM;
static CSUAACI_t	dll_CSUAACI;
static CSNDPKH_t	dll_CSNDPKH;
static CSNDPKR_t	dll_CSNDPKR;
static CSUAMKD_t	dll_CSUAMKD;
static CSNDRKD_t	dll_CSNDRKD;
static CSNDRKL_t	dll_CSNDRKL;
static CSNDSYG_t	dll_CSNDSYG;
static CSNBPTR_t	dll_CSNBPTR;
static CSNBCPE_t	dll_CSNBCPE;
static CSNBCPA_t	dll_CSNBCPA;
static CSNBPGN_t	dll_CSNBPGN;
static CSNBPVR_t	dll_CSNBPVR;
static CSNBDKG_t	dll_CSNBDKG;
static CSNBEPG_t	dll_CSNBEPG;
static CSNBCVE_t	dll_CSNBCVE;
static CSNBCSG_t	dll_CSNBCSG;
static CSNBCSV_t	dll_CSNBCSV;
static CSNBCVG_t	dll_CSNBCVG;
static CSNBKTP_t	dll_CSNBKTP;
static CSNDPKE_t	dll_CSNDPKE;
static CSNDPKD_t	dll_CSNDPKD;
static CSNBPEX_t	dll_CSNBPEX;
static CSNBPEXX_t	dll_CSNBPEXX;
static CSUARNT_t	dll_CSUARNT;
static CSNBCVT_t	dll_CSNBCVT;
static CSNBMDG_t	dll_CSNBMDG;
static CSUACRA_t	dll_CSUACRA;
static CSUACRD_t	dll_CSUACRD;
static CSNBTRV_t	dll_CSNBTRV;
static CSNBSKY_t	dll_CSNBSKY;
static CSNBSPN_t	dll_CSNBSPN;
static CSNBPCU_t	dll_CSNBPCU;
static CSUAPCV_t	dll_CSUAPCV;
static CSUAPRB_t	dll_CSUAPRB;
static CSUADHK_t	dll_CSUADHK;
static CSUADHQ_t	dll_CSUADHQ;
static CSNDTBC_t	dll_CSNDTBC;
static CSNDRKX_t	dll_CSNDRKX;
static CSNBKET_t	dll_CSNBKET;
static CSNBHMG_t	dll_CSNBHMG;
static CSNBHMV_t	dll_CSNBHMV;

/* mechanisms provided by this token */
MECH_LIST_ELEMENT mech_list[] = {
	{CKM_DES_KEY_GEN, {8, 8, CKF_HW|CKF_GENERATE}},
	{CKM_DES3_KEY_GEN, {24, 24, CKF_HW|CKF_GENERATE}},
	{CKM_RSA_PKCS_KEY_PAIR_GEN, {512, 4096, CKF_HW|CKF_GENERATE_KEY_PAIR}},
	{CKM_RSA_PKCS, {512, 4096, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_SIGN|
				  CKF_VERIFY}},
	{CKM_MD5_RSA_PKCS, {512,4096, CKF_HW|CKF_SIGN|CKF_VERIFY}},
	{CKM_SHA1_RSA_PKCS, {512, 4096, CKF_HW|CKF_SIGN|CKF_VERIFY}},
	{CKM_SHA256_RSA_PKCS, {512, 4096, CKF_HW|CKF_SIGN|CKF_VERIFY}},
	{CKM_DES_CBC, {8, 8, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|CKF_UNWRAP}},
	{CKM_DES_CBC_PAD, {8, 8, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|
				CKF_UNWRAP}},
	{CKM_DES3_CBC, {24, 24, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|
				CKF_UNWRAP}},
	{CKM_DES3_CBC_PAD, {24, 24, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|
				   CKF_UNWRAP}},
	{CKM_AES_KEY_GEN, {16, 32, CKF_HW|CKF_GENERATE}},
	{CKM_AES_ECB, {16, 32, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|
			      CKF_UNWRAP}},
	{CKM_AES_CBC, {16, 32, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|
			      CKF_UNWRAP}},
	{CKM_AES_CBC_PAD, {16, 32, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|
				  CKF_UNWRAP}},
	{CKM_SHA512, {0, 0, CKF_HW|CKF_DIGEST}},
	{CKM_SHA512_HMAC, {80, 2048, CKF_SIGN|CKF_VERIFY}},
	{CKM_SHA512_HMAC_GENERAL, {80, 2048, CKF_SIGN|CKF_VERIFY}},
	{CKM_SHA384, {0, 0, CKF_HW|CKF_DIGEST}},
	{CKM_SHA384_HMAC, {80, 2048, CKF_SIGN|CKF_VERIFY}},
	{CKM_SHA384_HMAC_GENERAL, {80, 2048, CKF_SIGN|CKF_VERIFY}},
	{CKM_SHA256, {0, 0, CKF_HW|CKF_DIGEST}},
	{CKM_SHA256_HMAC, {80, 2048, CKF_SIGN|CKF_VERIFY}},
	{CKM_SHA256_HMAC_GENERAL, {80, 2048, CKF_SIGN|CKF_VERIFY}},
	{CKM_SHA_1, {0, 0, CKF_DIGEST}},
	{CKM_SHA_1_HMAC, {80, 2048, CKF_SIGN|CKF_VERIFY}},
	{CKM_SHA_1_HMAC_GENERAL, {80, 2048, CKF_SIGN|CKF_VERIFY}},
	{CKM_MD5, {0, 0, CKF_DIGEST}},
	{CKM_MD5_HMAC, {0, 0, CKF_SIGN|CKF_VERIFY}},
	{CKM_MD5_HMAC_GENERAL, {0, 0, CKF_SIGN|CKF_VERIFY}},
	{CKM_EC_KEY_PAIR_GEN, {160, 521, CKF_HW|CKF_GENERATE_KEY_PAIR|
					CKF_EC_NAMEDCURVE|CKF_EC_F_P}},
	{CKM_ECDSA, {160, 521, CKF_HW|CKF_SIGN|CKF_VERIFY|CKF_EC_NAMEDCURVE|
					CKF_EC_F_P}},
	{CKM_ECDSA_SHA1, {160, 521, CKF_HW|CKF_SIGN|CKF_VERIFY|
					CKF_EC_NAMEDCURVE|CKF_EC_F_P}},
		{CKM_GENERIC_SECRET_KEY_GEN, {80, 2048, CKF_HW|CKF_GENERATE}},
	{CKM_ECDSA_SHA256, {160, 521, CKF_HW|CKF_SIGN|CKF_VERIFY|
					CKF_EC_NAMEDCURVE|CKF_EC_F_P}},
		{CKM_GENERIC_SECRET_KEY_GEN, {80, 2048, CKF_HW|CKF_GENERATE}},
	{CKM_ECDSA_SHA384, {160, 521, CKF_HW|CKF_SIGN|CKF_VERIFY|
					CKF_EC_NAMEDCURVE|CKF_EC_F_P}},
		{CKM_GENERIC_SECRET_KEY_GEN, {80, 2048, CKF_HW|CKF_GENERATE}},
	{CKM_ECDSA_SHA512, {160, 521, CKF_HW|CKF_SIGN|CKF_VERIFY|
					CKF_EC_NAMEDCURVE|CKF_EC_F_P}},
		{CKM_GENERIC_SECRET_KEY_GEN, {80, 2048, CKF_HW|CKF_GENERATE}}
};

CK_ULONG mech_list_len = (sizeof(mech_list) / sizeof(MECH_LIST_ELEMENT));

CK_RV
token_specific_rng(CK_BYTE *output, CK_ULONG bytes)
{
	long return_code, reason_code;
	unsigned char form[CCA_KEYWORD_SIZE], random_number[CCA_RNG_SIZE];
	CK_ULONG bytes_so_far = 0, bytes_left;
	CK_RV rv;

	memcpy(form, "RANDOM  ", (size_t)CCA_KEYWORD_SIZE);

	while (bytes_so_far < bytes) {
		dll_CSNBRNG(&return_code,
			&reason_code,
			NULL,
			NULL,
			form,
			random_number);

		if (return_code != CCA_SUCCESS) {
			TRACE_ERROR("CSNBRNG failed. return:%ld, reason:%ld\n",
				   return_code, reason_code);
			rv = CKR_FUNCTION_FAILED;
			return rv;
		}

		if (bytes_so_far + CCA_RNG_SIZE > bytes) {
			bytes_left = bytes - bytes_so_far;
			memcpy(&output[bytes_so_far], random_number, (size_t)bytes_left);
			bytes_so_far += bytes_left;
		} else {
			memcpy(&output[bytes_so_far], random_number, (size_t)CCA_RNG_SIZE);
			bytes_so_far += CCA_RNG_SIZE;
		}
	}

	return CKR_OK;
}

CK_RV cca_resolve_lib_sym(void *hdl) {
	char *error = NULL;

	dlerror(); /* Clear existing error */

	dll_CSNBCKI	= (CSNBCKI_t)dlsym(hdl, "CSNBCKI");
	dll_CSNBCKM	= (CSNBCKM_t)dlsym(hdl, "CSNBCKM");
	dll_CSNBDKX	= (CSNBDKX_t)dlsym(hdl, "CSNBDKX");
	dll_CSNBDKM	= (CSNBDKM_t)dlsym(hdl, "CSNBDKM");
	dll_CSNBMKP	= (CSNBMKP_t)dlsym(hdl, "CSNBMKP");
	dll_CSNBKEX	= (CSNBKEX_t)dlsym(hdl, "CSNBKEX");
	dll_CSNBKGN	= (CSNBKGN_t)dlsym(hdl, "CSNBKGN");
	dll_CSNBKGN2	= (CSNBKGN2_t)dlsym(hdl, "CSNBKGN2");
	dll_CSNBKIM	= (CSNBKIM_t)dlsym(hdl, "CSNBKIM");
	dll_CSNBKPI	= (CSNBKPI_t)dlsym(hdl, "CSNBKPI");
	dll_CSNBKPI2	= (CSNBKPI2_t)dlsym(hdl, "CSNBKPI2");
	dll_CSNBKSI	= (CSNBKSI_t)dlsym(hdl, "CSNBKSI");
	dll_CSNBKRC	= (CSNBKRC_t)dlsym(hdl, "CSNBKRC");
	dll_CSNBAKRC	= (CSNBAKRC_t)dlsym(hdl, "CSNBAKRC");
	dll_CSNBKRD	= (CSNBKRD_t)dlsym(hdl, "CSNBKRD");
	dll_CSNBKRL	= (CSNBKRL_t)dlsym(hdl, "CSNBKRL");
	dll_CSNBKRR	= (CSNBKRR_t)dlsym(hdl, "CSNBKRR");
	dll_CSNBKRW	= (CSNBKRW_t)dlsym(hdl, "CSNBKRW");
	dll_CSNDKRC	= (CSNDKRC_t)dlsym(hdl, "CSNDKRC");
	dll_CSNDKRD	= (CSNDKRD_t)dlsym(hdl, "CSNDKRD");
	dll_CSNDKRL	= (CSNDKRL_t)dlsym(hdl, "CSNDKRL");
	dll_CSNDKRR	= (CSNDKRR_t)dlsym(hdl, "CSNDKRR");
	dll_CSNDKRW	= (CSNDKRW_t)dlsym(hdl, "CSNDKRW");
	dll_CSNBKYT	= (CSNBKYT_t)dlsym(hdl, "CSNBKYT");
	dll_CSNBKYTX	= (CSNBKYTX_t)dlsym(hdl, "CSNBKYTX");
	dll_CSNBKTC	= (CSNBKTC_t)dlsym(hdl, "CSNBKTC");
	dll_CSNBKTR	= (CSNBKTR_t)dlsym(hdl, "CSNBKTR");
	dll_CSNBRNG	= (CSNBRNG_t)dlsym(hdl, "CSNBRNG");
	dll_CSNBSAE	= (CSNBSAE_t)dlsym(hdl, "CSNBSAE");
	dll_CSNBSAD	= (CSNBSAD_t)dlsym(hdl, "CSNBSAD");
	dll_CSNBDEC	= (CSNBDEC_t)dlsym(hdl, "CSNBDEC");
	dll_CSNBENC	= (CSNBENC_t)dlsym(hdl, "CSNBENC");
	dll_CSNBMGN	= (CSNBMGN_t)dlsym(hdl, "CSNBMGN");
	dll_CSNBMVR	= (CSNBMVR_t)dlsym(hdl, "CSNBMVR");
	dll_CSNBKTB	= (CSNBKTB_t)dlsym(hdl, "CSNBKTB");
	dll_CSNBKTB2	= (CSNBKTB2_t)dlsym(hdl, "CSNBKTB2");
	dll_CSNDPKG	= (CSNDPKG_t)dlsym(hdl, "CSNDPKG");
	dll_CSNDPKB	= (CSNDPKB_t)dlsym(hdl, "CSNDPKB");
	dll_CSNBOWH	= (CSNBOWH_t)dlsym(hdl, "CSNBOWH");
	dll_CSNDPKI	= (CSNDPKI_t)dlsym(hdl, "CSNDPKI");
	dll_CSNDDSG	= (CSNDDSG_t)dlsym(hdl, "CSNDDSG");
	dll_CSNDDSV	= (CSNDDSV_t)dlsym(hdl, "CSNDDSV");
	dll_CSNDKTC	= (CSNDKTC_t)dlsym(hdl, "CSNDKTC");
	dll_CSNDPKX	= (CSNDPKX_t)dlsym(hdl, "CSNDPKX");
	dll_CSNDSYI	= (CSNDSYI_t)dlsym(hdl, "CSNDSYI");
	dll_CSNDSYX	= (CSNDSYX_t)dlsym(hdl, "CSNDSYX");
	dll_CSUACFQ	= (CSUACFQ_t)dlsym(hdl, "CSUACFQ");
	dll_CSUACFC	= (CSUACFC_t)dlsym(hdl, "CSUACFC");
	dll_CSNDSBC	= (CSNDSBC_t)dlsym(hdl, "CSNDSBC");
	dll_CSNDSBD	= (CSNDSBD_t)dlsym(hdl, "CSNDSBD");
	dll_CSUALCT	= (CSUALCT_t)dlsym(hdl, "CSUALCT");
	dll_CSUAACM	= (CSUAACM_t)dlsym(hdl, "CSUAACM");
	dll_CSUAACI	= (CSUAACI_t)dlsym(hdl, "CSUAACI");
	dll_CSNDPKH	= (CSNDPKH_t)dlsym(hdl, "CSNDPKH");
	dll_CSNDPKR	= (CSNDPKR_t)dlsym(hdl, "CSNDPKR");
	dll_CSUAMKD	= (CSUAMKD_t)dlsym(hdl, "CSUAMKD");
	dll_CSNDRKD	= (CSNDRKD_t)dlsym(hdl, "CSNDRKD");
	dll_CSNDRKL	= (CSNDRKL_t)dlsym(hdl, "CSNDRKL");
	dll_CSNDSYG	= (CSNDSYG_t)dlsym(hdl, "CSNDSYG");
	dll_CSNBPTR	= (CSNBPTR_t)dlsym(hdl, "CSNBPTR");
	dll_CSNBCPE	= (CSNBCPE_t)dlsym(hdl, "CSNBCPE");
	dll_CSNBCPA	= (CSNBCPA_t)dlsym(hdl, "CSNBCPA");
	dll_CSNBPGN	= (CSNBPGN_t)dlsym(hdl, "CSNBPGN");
	dll_CSNBPVR	= (CSNBPVR_t)dlsym(hdl, "CSNBPVR");
	dll_CSNBDKG	= (CSNBDKG_t)dlsym(hdl, "CSNBDKG");
	dll_CSNBEPG	= (CSNBEPG_t)dlsym(hdl, "CSNBEPG");
	dll_CSNBCVE	= (CSNBCVE_t)dlsym(hdl, "CSNBCVE");
	dll_CSNBCSG	= (CSNBCSG_t)dlsym(hdl, "CSNBCSG");
	dll_CSNBCSV	= (CSNBCSV_t)dlsym(hdl, "CSNBCSV");
	dll_CSNBCVG	= (CSNBCVG_t)dlsym(hdl, "CSNBCVG");
	dll_CSNBKTP	= (CSNBKTP_t)dlsym(hdl, "CSNBKTP");
	dll_CSNDPKE	= (CSNDPKE_t)dlsym(hdl, "CSNDPKE");
	dll_CSNDPKD	= (CSNDPKD_t)dlsym(hdl, "CSNDPKD");
	dll_CSNBPEX	= (CSNBPEX_t)dlsym(hdl, "CSNBPEX");
	dll_CSNBPEXX	= (CSNBPEXX_t)dlsym(hdl, "CSNBPEXX");
	dll_CSUARNT	= (CSUARNT_t)dlsym(hdl, "CSUARNT");
	dll_CSNBCVT	= (CSNBCVT_t)dlsym(hdl, "CSNBCVT");
	dll_CSNBMDG	= (CSNBMDG_t)dlsym(hdl, "CSNBMDG");
	dll_CSUACRA	= (CSUACRA_t)dlsym(hdl, "CSUACRA");
	dll_CSUACRD	= (CSUACRD_t)dlsym(hdl, "CSUACRD");
	dll_CSNBTRV	= (CSNBTRV_t)dlsym(hdl, "CSNBTRV");
	dll_CSNBSKY	= (CSNBSKY_t)dlsym(hdl, "CSNBSKY");
	dll_CSNBSPN	= (CSNBSPN_t)dlsym(hdl, "CSNBSPN");
	dll_CSNBPCU	= (CSNBPCU_t)dlsym(hdl, "CSNBPCU");
	dll_CSUAPCV	= (CSUAPCV_t)dlsym(hdl, "CSUAPCV");
	dll_CSUAPRB	= (CSUAPRB_t)dlsym(hdl, "CSUAPRB");
	dll_CSUADHK	= (CSUADHK_t)dlsym(hdl, "CSUADHK");
	dll_CSUADHQ	= (CSUADHQ_t)dlsym(hdl, "CSUADHQ");
	dll_CSNDTBC	= (CSNDTBC_t)dlsym(hdl, "CSNDTBC");
	dll_CSNDRKX	= (CSNDRKX_t)dlsym(hdl, "CSNDRKX");
	dll_CSNBKET	= (CSNBKET_t)dlsym(hdl, "CSNBKET");
	dll_CSNBHMG	= (CSNBHMG_t)dlsym(hdl, "CSNBHMG");
	dll_CSNBHMV	= (CSNBHMV_t)dlsym(hdl, "CSNBHMV");

	if ((error = dlerror()) != NULL)  {
		OCK_SYSLOG(LOG_ERR, "%s\n", error);
		exit(EXIT_FAILURE);
	}
	else
		return CKR_OK;
}

CK_RV
token_specific_init(STDLL_TokData_t *tokdata, CK_SLOT_ID SlotNumber,
		    char *conf_name)
{
	unsigned char rule_array[256] = { 0, };
	long return_code, reason_code, rule_array_count, verb_data_length;
	void *lib_csulcca;
	CK_RV rc;

	TRACE_INFO("cca %s slot=%lu running\n", __func__, SlotNumber);

	lib_csulcca = dlopen(CCASHAREDLIB, RTLD_GLOBAL | RTLD_NOW);
	if (lib_csulcca == NULL) {
		OCK_SYSLOG(LOG_ERR, "%s: Error loading library: '%s' [%s]\n",
			   __func__, CCASHAREDLIB, dlerror());
		TRACE_ERROR("%s: Error loading shared library '%s' [%s]\n",
			    __func__, CCASHAREDLIB, dlerror());
		return CKR_FUNCTION_FAILED;
	}

	rc = cca_resolve_lib_sym(lib_csulcca);
	if (rc)
		exit(rc);

	memcpy(rule_array, "STATCCAE", 8);

	rule_array_count = 1;
	verb_data_length = 0;
	dll_CSUACFQ(&return_code,
		&reason_code,
		NULL,
		NULL,
		&rule_array_count,
		rule_array,
		&verb_data_length,
		NULL);

	if (return_code != CCA_SUCCESS) {
		TRACE_ERROR("CSUACFQ failed. return:%ld, reason:%ld\n",
			    return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	}

	/* This value should be 2 if the master key is set in the card */
	if (memcmp(&rule_array[CCA_STATCCAE_SYM_CMK_OFFSET], "2       ", 8)) {
		OCK_SYSLOG(LOG_WARNING, "Warning: CCA symmetric master key is not yet loaded");
	}
	if (memcmp(&rule_array[CCA_STATCCAE_ASYM_CMK_OFFSET], "2       ", 8)) {
		OCK_SYSLOG(LOG_WARNING, "Warning: CCA asymmetric master key is not yet loaded");
	}

	return CKR_OK;
}

CK_RV
token_specific_final()
{
	TRACE_INFO("cca %s running\n", __func__);
	return CKR_OK;
}

CK_RV cca_key_gen(enum cca_key_type type, CK_BYTE *key, unsigned char *key_form,
		  unsigned char *key_type_1, CK_ULONG key_size)
{

	long return_code, reason_code;
	unsigned char key_length[CCA_KEYWORD_SIZE];
	unsigned char key_type_2[CCA_KEYWORD_SIZE] = { 0, };
	unsigned char kek_key_identifier_1[CCA_KEY_ID_SIZE] = { 0, };
	unsigned char kek_key_identifier_2[CCA_KEY_ID_SIZE] = { 0, };
	unsigned char generated_key_identifier_2[CCA_KEY_ID_SIZE] = { 0, };

	if (type == CCA_DES_KEY) {
		switch (key_size) {
		case 8:
			memcpy(key_length, "KEYLN8  ", (size_t)CCA_KEYWORD_SIZE);
			break;
		case 24:
			memcpy(key_length, "KEYLN24 ", (size_t)CCA_KEYWORD_SIZE);
			break;
		default:
			TRACE_ERROR("Invalid key length: %lu\n", key_size);
			return CKR_KEY_SIZE_RANGE;
		}
	} else if (type == CCA_AES_KEY) {
		switch (key_size) {
		case 16:
			memcpy(key_length, "KEYLN16 ", CCA_KEYWORD_SIZE);
			break;
		case 24:
			memcpy(key_length, "KEYLN24 ", (size_t)CCA_KEYWORD_SIZE);
			break;
		case 32:
			memcpy(key_length, "        ", (size_t)CCA_KEYWORD_SIZE);
			break;
		default:
			TRACE_ERROR("Invalid key length: %lu\n", key_size);
			return CKR_KEY_SIZE_RANGE;
		}
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
		return CKR_FUNCTION_FAILED;
	}

	dll_CSNBKGN(&return_code,
		&reason_code,
		NULL,
		NULL,
		key_form,
		key_length,
		key_type_1,
		key_type_2,
		kek_key_identifier_1,
		kek_key_identifier_2,
		key,
		generated_key_identifier_2);

	if (return_code != CCA_SUCCESS) {
		TRACE_ERROR("CSNBKGN(KEYGEN) failed. return:%ld, reason:%ld\n",
			    return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}

CK_RV
token_specific_des_key_gen(STDLL_TokData_t *tokdata, CK_BYTE *des_key,
			   CK_ULONG len, CK_ULONG keysize)
{
	unsigned char key_form[CCA_KEYWORD_SIZE];
	unsigned char key_type_1[CCA_KEYWORD_SIZE];

	/* make sure key is the right size for the token */
	if (len != CCA_KEY_ID_SIZE)
		return CKR_FUNCTION_FAILED;

	memcpy(key_form, "OP      ", (size_t)CCA_KEYWORD_SIZE);
	memcpy(key_type_1, "DATA    ", (size_t)CCA_KEYWORD_SIZE);

	return cca_key_gen(CCA_DES_KEY, des_key, key_form, key_type_1, keysize);
}


CK_RV
token_specific_des_ecb(STDLL_TokData_t *tokdata,
		       CK_BYTE  *in_data,
		       CK_ULONG  in_data_len,
		       CK_BYTE  *out_data,
		       CK_ULONG *out_data_len,
		       OBJECT   *key,
		       CK_BYTE   encrypt)
{
	TRACE_INFO("Unsupported function reached.\n");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
token_specific_des_cbc(STDLL_TokData_t *tokdata,
		       CK_BYTE  *in_data,
		       CK_ULONG  in_data_len,
		       CK_BYTE  *out_data,
		       CK_ULONG *out_data_len,
		       OBJECT   *key,
		       CK_BYTE  *init_v,
		       CK_BYTE   encrypt)
{
	long return_code, reason_code, rule_array_count, length;
	long pad_character = 0;
	//char iv[8] = { 0xfe, 0x43, 0x12, 0xed, 0xaa, 0xbb, 0xdd, 0x90 };
	unsigned char chaining_vector[CCA_OCV_SIZE];
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE];
	CK_BYTE *local_out = out_data;
	CK_ATTRIBUTE *attr = NULL;

	if (template_attribute_find(key->template, CKA_IBM_OPAQUE, &attr) == FALSE) {
		TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
		return CKR_FUNCTION_FAILED;
	}

	/* We need to have 8 bytes more than the in data length in case CCA
	 * adds some padding, although this extra 8 bytes may not be needed.
	 * If *out_data_len is not 8 bytes larger than in_data_len, then
	 * we'll malloc the needed space and get the data back from CCA in this
	 * malloc'd buffer. If it turns out that the extra 8 bytes wasn't
	 * needed, we just silently copy the data to the user's buffer and
	 * free our malloc'd space, returning as normal. If the space was
	 * needed, we return an error and no memory corruption happens. */
	if (*out_data_len < (in_data_len + 8)) {
		local_out = malloc(in_data_len + 8);
		if (!local_out) {
			TRACE_ERROR("Malloc of %lu bytes failed.\n",
				    in_data_len + 8);
			return CKR_HOST_MEMORY;
		}
	}

	length = in_data_len;

	rule_array_count = 1;
	memcpy(rule_array, "CBC     ", (size_t)CCA_KEYWORD_SIZE);

	if (encrypt) {
		dll_CSNBENC(&return_code,
			&reason_code,
			NULL,
			NULL,
			attr->pValue, //id,
			&length,
			in_data, //in,
			init_v, //iv,
			&rule_array_count,
			rule_array,
			&pad_character,
			chaining_vector,
			local_out);//out_data); //out);
	} else {
		dll_CSNBDEC(&return_code,
			&reason_code,
			NULL,
			NULL,
			attr->pValue, //id,
			&length,
			in_data, //in,
			init_v, //iv,
			&rule_array_count,
			rule_array,
			chaining_vector,
			local_out);//out_data); //out);
	}

	if (return_code != CCA_SUCCESS) {
		if (encrypt)
			TRACE_ERROR("CSNBENC (DES ENCRYPT) failed. return:%ld,"
			    " reason:%ld\n", return_code, reason_code);
		else
			TRACE_ERROR("CSNBDEC (DES DECRYPT) failed. return:%ld,"
			    " reason:%ld\n", return_code, reason_code);
		if (out_data != local_out)
			free(local_out);
		return CKR_FUNCTION_FAILED;
	} else if (reason_code != 0) {
		if (encrypt)
			TRACE_WARNING("CSNBENC (DES ENCRYPT) succeeded, but"
				      " returned reason:%ld\n", reason_code);
		else
			TRACE_WARNING("CSNBDEC (DES DECRYPT) succeeded, but"
				      " returned reason:%ld\n", reason_code);
	}

	/* If we malloc'd a new buffer due to overflow concerns and the data
	 * coming out turned out to be bigger than expected, return an error.
	 *
	 * Else, memcpy the data back to the user's buffer
	 */
	if ((local_out != out_data) && ((CK_ULONG)length > *out_data_len)) {
		TRACE_DEVEL("CKR_BUFFER_TOO_SMALL: %ld bytes to write into %ld "
			    "bytes space\n", length, *out_data_len);
		TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
		free(local_out);
		return CKR_BUFFER_TOO_SMALL;
	} else if (local_out != out_data) {
		memcpy(out_data, local_out, (size_t)length);
		free(local_out);
	}

	*out_data_len = length;

	return CKR_OK;
}

CK_RV
token_specific_tdes_ecb(STDLL_TokData_t *tokdata,
			CK_BYTE  *in_data,
			CK_ULONG  in_data_len,
			CK_BYTE  *out_data,
			CK_ULONG *out_data_len,
			OBJECT   *key,
			CK_BYTE   encrypt)
{
	TRACE_WARNING("Unsupported function reached.\n");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
token_specific_tdes_cbc(STDLL_TokData_t *tokdata,
			CK_BYTE  *in_data,
			CK_ULONG  in_data_len,
			CK_BYTE  *out_data,
			CK_ULONG *out_data_len,
			OBJECT  *key,
			CK_BYTE  *init_v,
			CK_BYTE   encrypt)
{
	/* Since keys are opaque objects in this token and there's only
	 * one encipher command to CCA, we can just pass through */
	return token_specific_des_cbc(tokdata, in_data, in_data_len, out_data,
				      out_data_len, key, init_v, encrypt);
}

uint16_t
cca_inttok_privkey_get_len(CK_BYTE *tok)
{
	return *(uint16_t *)&tok[CCA_RSA_INTTOK_PRIVKEY_LENGTH_OFFSET];
}

/* Given a CCA internal token private key object, get the modulus */
CK_RV
cca_inttok_privkey_get_n(CK_BYTE *tok, CK_ULONG *n_len, CK_BYTE *n)
{
	uint16_t privkey_length, n_length;
	uint32_t privkey_n_offset;

	privkey_length = *(uint16_t *)&tok[CCA_RSA_INTTOK_PRIVKEY_LENGTH_OFFSET];
	n_length = *(uint16_t *)&tok[CCA_RSA_INTTOK_PRIVKEY_N_LENGTH_OFFSET];

	if (n_length > (*n_len)) {
		TRACE_ERROR("Not enough room to return n.(Got %lu, need %hu)\n",
			    *n_len, n_length);
		return CKR_FUNCTION_FAILED;
	}

	privkey_n_offset = privkey_length - n_length;

	memcpy(n, &tok[privkey_n_offset], (size_t)n_length);
	*n_len = n_length;

	return CKR_OK;
}

/* Given a CCA internal token pubkey object, get the public exponent */
CK_RV
cca_inttok_pubkey_get_e(CK_BYTE *tok, CK_ULONG *e_len, CK_BYTE *e)
{
	uint16_t e_length;

	e_length = *(uint16_t *)&tok[CCA_RSA_INTTOK_PUBKEY_E_LENGTH_OFFSET];

	if (e_length > (*e_len)) {
		TRACE_ERROR("Not enough room to return e.(Got %lu, need %hu)\n",
			    *e_len, e_length);
		return CKR_FUNCTION_FAILED;
	}

	memcpy(e, &tok[CCA_RSA_INTTOK_PUBKEY_E_OFFSET], (size_t)e_length);
	*e_len = (CK_ULONG)e_length;

	return CKR_OK;
}

CK_RV
token_create_keypair_object(TEMPLATE *tmpl, CK_ULONG tok_len, CK_BYTE *tok)
{
	uint16_t privkey_len, pubkey_offset;
	CK_BYTE n[CCATOK_MAX_N_LEN], e[CCATOK_MAX_E_LEN];
	CK_ULONG n_len = CCATOK_MAX_N_LEN, e_len = CCATOK_MAX_E_LEN;
	CK_ATTRIBUTE *modulus, *pub_exp, *opaque_key;
	CK_RV rv;

	privkey_len = cca_inttok_privkey_get_len(&tok[CCA_RSA_INTTOK_PRIVKEY_OFFSET]);
	pubkey_offset = privkey_len + CCA_RSA_INTTOK_HDR_LENGTH;

	/* That's right, n is stored in the private key area. Get it there */
	if ((rv = cca_inttok_privkey_get_n(&tok[CCA_RSA_INTTOK_PRIVKEY_OFFSET],
					   &n_len, n))) {
		TRACE_DEVEL("cca_inttok_privkey_get_n() failed. rv=0x%lx\n",
			    rv);
		return rv;
	}

	/* Get e */
	if ((rv = cca_inttok_pubkey_get_e(&tok[pubkey_offset], &e_len, e))) {
		TRACE_DEVEL("cca_inttok_pubkey_get_e() failed. rv=0x%lx\n", rv);
		return rv;
	}

	/* Add n's value to the template */
	if ((rv = build_attribute(CKA_MODULUS, n, n_len, &modulus))) {
		TRACE_DEVEL("build_attribute for n failed. rv=0x%lx\n", rv);
		return rv;
	}
	template_update_attribute(tmpl, modulus);

	/* Add e's value to the template */
	if ((rv = build_attribute(CKA_PUBLIC_EXPONENT, e, e_len, &pub_exp))) {
		TRACE_DEVEL("build_attribute for e failed. rv=0x%lx\n", rv);
		return rv;
	}
	template_update_attribute(tmpl, pub_exp);

	/* Add the opaque key object to the template */
	if ((rv = build_attribute(CKA_IBM_OPAQUE, tok, tok_len, &opaque_key))) {
		TRACE_DEVEL("build_attribute for opaque key failed. rv=0x%lx\n",
			     rv);
		return rv;
	}
	template_update_attribute(tmpl, opaque_key);

	return CKR_OK;
}

#if 0
CK_RV
token_create_priv_key(TEMPLATE *priv_tmpl, CK_ULONG tok_len, CK_BYTE *tok)
{
	CK_BYTE n[CCATOK_MAX_N_LEN];
	CK_ULONG n_len = CCATOK_MAX_N_LEN;
	CK_RV rv;
	CK_ATTRIBUTE *opaque_key, *modulus;

	/* That's right, n is stored in the private key area. Get it there */
	if ((rv = cca_inttok_privkey_get_n(&tok[CCA_RSA_INTTOK_PRIVKEY_OFFSET],
					   &n_len, n))) {
		TRACE_DEVEL("cca_inttok_privkey_get_n() failed. rv=0x%lx", rv);
		return rv;
	}

	/* Add n's value to the template. We need to do this for the private
	 * key as well as the public key because openCryptoki checks data
	 * sizes against the size of the CKA_MODULUS attribute of whatever
	 * key object it gets */
	if ((rv = build_attribute(CKA_MODULUS, n, n_len, &modulus))) {
		TRACE_DEVEL("build_attribute for n failed. rv=0x%lx", rv);
		return rv;
	}
	template_update_attribute(priv_tmpl, modulus);

	/* Add the opaque key object to the template */
	if ((rv = build_attribute(CKA_IBM_OPAQUE, tok, tok_len, &opaque_key))) {
		TRACE_DEVEL("build_attribute for opaque key failed. rv=0x%lx",
			    rv);
		return rv;
	}
	template_update_attribute(priv_tmpl, opaque_key);

	return CKR_OK;
}
#endif

CK_RV
token_specific_rsa_generate_keypair(STDLL_TokData_t *tokdata,
				    TEMPLATE *publ_tmpl,
				    TEMPLATE *priv_tmpl)
{
	long return_code, reason_code, rule_array_count;
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };

	long key_value_structure_length;
	long private_key_name_length, key_token_length;
	unsigned char key_value_structure[CCA_KEY_VALUE_STRUCT_SIZE] = { 0, };
	unsigned char private_key_name[CCA_PRIVATE_KEY_NAME_SIZE] = { 0, };
	unsigned char key_token[CCA_KEY_TOKEN_SIZE] = { 0, };

	long regeneration_data_length, generated_key_token_length;
	unsigned char regeneration_data[CCA_REGENERATION_DATA_SIZE] = { 0, };
	unsigned char transport_key_identifier[CCA_KEY_ID_SIZE] = { 0, };
	unsigned char generated_key_token[CCA_KEY_TOKEN_SIZE] = { 0, };

	uint16_t size_of_e;
	uint16_t mod_bits;
	CK_ATTRIBUTE *pub_exp = NULL, *attr = NULL;
	CK_RV rv;
	CK_BYTE_PTR ptr;
	CK_ULONG tmpsize, tmpexp;


	if (!template_attribute_find(publ_tmpl, CKA_MODULUS_BITS, &attr)) {
		TRACE_ERROR("Could not find CKA_MODULUS_BITS for the key.\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}
	mod_bits = *(CK_ULONG *)attr->pValue;


	/* If e is specified in the template, use it */
	rv = template_attribute_find(publ_tmpl, CKA_PUBLIC_EXPONENT, &pub_exp);
	if (rv == TRUE) {

		/* Per CCA manual, we really only support 3 values here:        *
		 * * 0 (generate random public exponent)                        *
		 * * 3 or                                                       *
		 * * 65537                                                      *
		 * Trim the P11 value so we can check what's comming our way    */

		tmpsize = pub_exp->ulValueLen;
		ptr = p11_bigint_trim(pub_exp->pValue, &tmpsize);
		/* If we trimmed the number correctly, only 3 bytes are         *
		 * sufficient to hold 65537 (0x010001)                          */
		if (tmpsize > 3)
			return CKR_TEMPLATE_INCONSISTENT;

		/* make pValue into CK_ULONG so we can compare */
		tmpexp = 0;
		memcpy((void *)&tmpexp + sizeof(CK_ULONG) - tmpsize,    // right align
		       ptr, tmpsize);

		/* Check for one of the three allowed values */
		if ( (tmpexp != 0) &&
		     (tmpexp != 3) &&
		     (tmpexp != 65537) )
			return CKR_TEMPLATE_INCONSISTENT;


		size_of_e = (uint16_t)tmpsize;

		memcpy(&key_value_structure[CCA_PKB_E_SIZE_OFFSET],
		       &size_of_e, (size_t)CCA_PKB_E_SIZE);
		memcpy(&key_value_structure[CCA_PKB_E_OFFSET],
		       ptr, (size_t)tmpsize);
	}

	key_value_structure_length = CCA_KEY_VALUE_STRUCT_SIZE;
	memcpy(key_value_structure, &mod_bits, sizeof(uint16_t));

	/* One last check. CCA can't auto-generate a random public      *
	 * exponent if the modulus length is more than 2048 bits        *
	 * We should be ok checking the public exponent length in the   *
	 * key_value_structure, since either the caller never           *
	 * specified it or we trimmed it's size. The size should be     *
	 * zero if the value is zero in both cases.                     *
	 * public exponent has CCA_PKB_E_SIZE_OFFSET offset with        *
	 * 2-bytes size                                                 */
	if (mod_bits > 2048 &&
	    key_value_structure[CCA_PKB_E_SIZE_OFFSET] == 0x00 &&
	    key_value_structure[CCA_PKB_E_SIZE_OFFSET + 1] == 0x00) {
		return CKR_TEMPLATE_INCONSISTENT;
	}

	rule_array_count = 2;
	memcpy(rule_array, "RSA-CRT KEY-MGMT", (size_t)(CCA_KEYWORD_SIZE * 2));

	private_key_name_length = 0;

	key_token_length = CCA_KEY_TOKEN_SIZE;

	dll_CSNDPKB(&return_code,
		&reason_code,
		NULL,
		NULL,
		&rule_array_count,
		rule_array,
		&key_value_structure_length,
		key_value_structure,
		&private_key_name_length,
		private_key_name,
		0,
		NULL,
		0,
		NULL,
		0,
		NULL,
		0,
		NULL,
		0,
		NULL,
		&key_token_length,
		key_token);

	if (return_code != CCA_SUCCESS) {
		TRACE_ERROR("CSNDPKB (RSA KEY TOKEN BUILD) failed. return:%ld,"
			    " reason:%ld\n", return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	}

	rule_array_count = 1;
	memset(rule_array, 0, sizeof(rule_array));
	memcpy(rule_array, "MASTER  ", (size_t)CCA_KEYWORD_SIZE);

	generated_key_token_length = CCA_KEY_TOKEN_SIZE;

	regeneration_data_length = 0;

	dll_CSNDPKG(&return_code,
		&reason_code,
		NULL,
		NULL,
		&rule_array_count,
		rule_array,
		&regeneration_data_length,
		regeneration_data,
		&key_token_length,
		key_token,
		transport_key_identifier,
		&generated_key_token_length,
		generated_key_token);

	if (return_code != CCA_SUCCESS) {
		TRACE_ERROR("CSNDPKG (RSA KEY GENERATE) failed. return:%ld,"
			    " reason:%ld\n", return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	}

	TRACE_DEVEL("RSA secure key token generated. size: %ld\n",
		    generated_key_token_length);

	rv = token_create_keypair_object(publ_tmpl, generated_key_token_length,
					 generated_key_token);
	if (rv != CKR_OK) {
		TRACE_DEVEL("token_create_keypair_object failed. rv:%lu\n", rv);
		return rv;
	}

	rv = token_create_keypair_object(priv_tmpl, generated_key_token_length,
					 generated_key_token);
	if (rv != CKR_OK)
		TRACE_DEVEL("token_create_keypair_object failed. rv:%lu\n", rv);
	return rv;
}


CK_RV
token_specific_rsa_encrypt(STDLL_TokData_t *tokdata,
			   CK_BYTE  *in_data,
			   CK_ULONG  in_data_len,
			   CK_BYTE  *out_data,
			   CK_ULONG *out_data_len,
			   OBJECT   *key_obj)
{
	long return_code, reason_code, rule_array_count, data_structure_length;
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
	CK_ATTRIBUTE *attr;

	/* Find the secure key token */
	if (!template_attribute_find(key_obj->template, CKA_IBM_OPAQUE, &attr)) {
		TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
		return CKR_TEMPLATE_INCOMPLETE;
	}

	/* The max value allowable by CCA for out_data_len is 512, so cap the incoming value if its
	 * too large. CCA will throw error 8, 72 otherwise. */
	if (*out_data_len > 512)
		*out_data_len = 512;

	rule_array_count = 1;
	memcpy(rule_array, "PKCS-1.2", CCA_KEYWORD_SIZE);

	data_structure_length = 0;

	dll_CSNDPKE(&return_code,
		&reason_code,
		NULL,
		NULL,
		&rule_array_count,
		rule_array,
		(long *)&in_data_len,
		in_data,
		&data_structure_length, // must be 0
		NULL,                   // ignored
		(long *)&(attr->ulValueLen),
		attr->pValue,
		(long *)out_data_len,
		out_data);

	if (return_code != CCA_SUCCESS) {
		TRACE_ERROR("CSNDPKE (RSA ENCRYPT) failed. return:%ld,"
			    " reason:%ld\n", return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	 } else if (reason_code != 0) {
		TRACE_WARNING("CSNDPKE (RSA ENCRYPT) succeeded, but"
			      " returned reason:%ld\n", reason_code);
	}

	return CKR_OK;
}

CK_RV
token_specific_rsa_decrypt(STDLL_TokData_t *tokdata,
			   CK_BYTE  *in_data,
			   CK_ULONG  in_data_len,
			   CK_BYTE  *out_data,
			   CK_ULONG *out_data_len,
			   OBJECT   *key_obj)
{
	long return_code, reason_code, rule_array_count, data_structure_length;
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
	CK_ATTRIBUTE *attr;

	/* Find the secure key token */
	if (!template_attribute_find(key_obj->template, CKA_IBM_OPAQUE, &attr)) {
		TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
		return CKR_TEMPLATE_INCOMPLETE;
	}

	/* The max value allowable by CCA for out_data_len is 512, so cap the incoming value if its
	 * too large. CCA will throw error 8, 72 otherwise. */
	if (*out_data_len > 512)
		*out_data_len = 512;

	rule_array_count = 1;
	memcpy(rule_array, "PKCS-1.2", CCA_KEYWORD_SIZE);

	data_structure_length = 0;

	dll_CSNDPKD(&return_code,
		&reason_code,
		NULL,
		NULL,
		&rule_array_count,
		rule_array,
		(long *)&in_data_len,
		in_data,
		&data_structure_length, // must be 0
		NULL,                   // ignored
		(long *)&(attr->ulValueLen),
		attr->pValue,
		(long *)out_data_len,
		out_data);

	if (return_code != CCA_SUCCESS) {
		TRACE_ERROR("CSNDPKD (RSA DECRYPT) failed. return:%ld,"
			    " reason:%ld\n", return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	} else if (reason_code != 0) {
		TRACE_WARNING("CSNDPKD (RSA DECRYPT) succeeded, but"
			      " returned reason:%ld\n", reason_code);
	}

	return CKR_OK;
}

CK_RV
token_specific_rsa_sign(STDLL_TokData_t *tokdata,
			CK_BYTE  * in_data,
			CK_ULONG   in_data_len,
			CK_BYTE  * out_data,
			CK_ULONG * out_data_len,
			OBJECT   * key_obj )
{
	long return_code, reason_code, rule_array_count;
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
	long signature_bit_length;
	CK_ATTRIBUTE *attr;

	/* Find the secure key token */
	if (!template_attribute_find(key_obj->template, CKA_IBM_OPAQUE, &attr)) {
		TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
		return CKR_TEMPLATE_INCOMPLETE;
	}

	rule_array_count = 1;
	memcpy(rule_array, "PKCS-1.1", CCA_KEYWORD_SIZE);

	dll_CSNDDSG(&return_code,
		&reason_code,
		NULL,
		NULL,
		&rule_array_count,
		rule_array,
		(long *)&(attr->ulValueLen),
		attr->pValue,
		(long *)&in_data_len,
		in_data,
		(long *)out_data_len,
		&signature_bit_length,
		out_data);

	if (return_code != CCA_SUCCESS) {
		TRACE_ERROR("CSNDDSG (RSA SIGN) failed. return :%ld, "
			    "reason: %ld\n", return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	} else if (reason_code != 0) {
		TRACE_WARNING("CSNDDSG (RSA SIGN) succeeded, but "
			      "returned reason: %ld\n", reason_code);
	}

	return CKR_OK;
}

CK_RV
token_specific_rsa_verify(STDLL_TokData_t *tokdata,
			  CK_BYTE  * in_data,
			  CK_ULONG   in_data_len,
			  CK_BYTE  * out_data,
			  CK_ULONG   out_data_len,
			  OBJECT   * key_obj )
{
	long return_code, reason_code, rule_array_count;
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
	CK_ATTRIBUTE *attr;

	/* Find the secure key token */
	if (!template_attribute_find(key_obj->template, CKA_IBM_OPAQUE, &attr)) {
		TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
		return CKR_TEMPLATE_INCOMPLETE;
	}

	rule_array_count = 1;
	memcpy(rule_array, "PKCS-1.1", CCA_KEYWORD_SIZE);

	dll_CSNDDSV(&return_code,
		&reason_code,
		NULL,
		NULL,
		&rule_array_count,
		rule_array,
		(long *)&(attr->ulValueLen),
		attr->pValue,
		(long *)&in_data_len,
		in_data,
		(long *)&out_data_len,
		out_data);

	if (return_code == 4 && reason_code == 429) {
		return CKR_SIGNATURE_INVALID;
	} else if (return_code != CCA_SUCCESS) {
		TRACE_ERROR("CSNDDSV (RSA VERIFY) failed. return:%ld,"
			    " reason:%ld\n", return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	} else if (reason_code != 0) {
		TRACE_WARNING("CSNDDSV (RSA VERIFY) succeeded, but"
			      " returned reason:%ld\n", reason_code);
	}

	return CKR_OK;
}


#ifndef NOAES
CK_RV
token_specific_aes_key_gen(STDLL_TokData_t *tokdata, CK_BYTE *aes_key,
			   CK_ULONG len, CK_ULONG key_size)
{
	long return_code, reason_code;
	unsigned char key_token[CCA_KEY_ID_SIZE] = { 0, };
	unsigned char key_form[CCA_KEYWORD_SIZE];
	unsigned char key_type[CCA_KEYWORD_SIZE];
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0x20, };
	long exit_data_len = 0, rule_array_count;
	unsigned char exit_data[4] = { 0, };
	unsigned char reserved_1[4] = { 0, };
	unsigned char point_to_array_of_zeros = 0;
	unsigned char mkvp[16] = { 0, };

	/* make sure key is the right size for the token */
	if (len != CCA_KEY_ID_SIZE)
		return CKR_FUNCTION_FAILED;

	memcpy(rule_array, "INTERNALAES     NO-KEY  ", (size_t) (CCA_KEYWORD_SIZE*3));
	memcpy(key_type, "DATA    ", (size_t)CCA_KEYWORD_SIZE);

	switch (key_size) {
		case 16:
			memcpy(rule_array + 3*CCA_KEYWORD_SIZE, "KEYLN16 ", CCA_KEYWORD_SIZE);
			break;
		case 24:
			memcpy(rule_array + 3*CCA_KEYWORD_SIZE, "KEYLN24 ", (size_t)CCA_KEYWORD_SIZE);
			break;
		case 32:
			memcpy(rule_array + 3*CCA_KEYWORD_SIZE, "KEYLN32 ", (size_t)CCA_KEYWORD_SIZE);
			break;
		default:
			TRACE_ERROR("Invalid key length: %lu\n", key_size);
			return CKR_KEY_SIZE_RANGE;
	}
#ifdef DEBUG
		{
			uint32_t j;
			TRACE_DEBUG("Rule Array:");
			for ( j = 0; j < 32; j++)
				printf("%c", rule_array[j]);
			printf("\n");
			for ( j = 0; j < 8; j++)
				printf("%c", key_type[j]);
		}
#endif
	rule_array_count = 4;
	dll_CSNBKTB(&return_code,
		&reason_code,
		&exit_data_len,
		exit_data,
		key_token,
		key_type,
		&rule_array_count,
		rule_array,
		NULL,
		reserved_1,
		NULL,
		&point_to_array_of_zeros,
		NULL,
		NULL,
		NULL,
		NULL,
		mkvp);

	if (return_code != CCA_SUCCESS) {
		TRACE_ERROR("CSNBTKB (TOKEN BUILD) failed. return:%ld,"
			    " reason:%ld\n", return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	}
	memcpy(key_form, "OP      ", (size_t)CCA_KEYWORD_SIZE);
	memcpy(key_type, "AESTOKEN", (size_t) CCA_KEYWORD_SIZE);
	memcpy(aes_key, key_token, (size_t)CCA_KEY_ID_SIZE);

	return cca_key_gen(CCA_AES_KEY, aes_key, key_form, key_type, key_size);
}

CK_RV
token_specific_aes_ecb(STDLL_TokData_t *tokdata,
		       CK_BYTE  *in_data,
		       CK_ULONG  in_data_len,
		       CK_BYTE	*out_data,
		       CK_ULONG	*out_data_len,
		       OBJECT	*key,
		       CK_BYTE	 encrypt)
{

	long return_code, reason_code, rule_array_count;
	long block_size = 16;
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE];
	long opt_data_len = 0, key_params_len =0, exit_data_len = 0, IV_len = 0, chain_vector_len = 0;
	char exit_data[0];
	CK_BYTE *local_out = out_data;
	CK_ATTRIBUTE *attr = NULL;
	CK_ULONG key_len;

	if (template_attribute_find(key->template, CKA_IBM_OPAQUE, &attr) == FALSE) {
		TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
		return CKR_FUNCTION_FAILED;
	}

	key_len = 64;
	rule_array_count = 4;
	memcpy(rule_array, "AES     ECB     KEYIDENTINITIAL ",
	       rule_array_count*(size_t)CCA_KEYWORD_SIZE);

	if (encrypt) {
		dll_CSNBSAE(&return_code,
			&reason_code,
			&exit_data_len,
			exit_data,
			&rule_array_count,
			rule_array,
			&key_len,
			attr->pValue,
			&key_params_len,
			NULL,
			&block_size,
			&IV_len,
			NULL,
			&chain_vector_len,
			NULL,
			&in_data_len,
			in_data,
			out_data_len,
			local_out,
			&opt_data_len,
			NULL);
	} else {
		dll_CSNBSAD(&return_code,
			&reason_code,
			&exit_data_len,
			exit_data,
			&rule_array_count,
			rule_array,
			&key_len,
			attr->pValue,
			&key_params_len,
			NULL,
			&block_size,
			&IV_len,
			NULL,
			&chain_vector_len,
			NULL,
			&in_data_len,
			in_data,
			out_data_len,
			local_out,
			&opt_data_len,
			NULL);
	}

	if (return_code != CCA_SUCCESS) {
		if (encrypt)
			TRACE_ERROR("CSNBSAE (AES ENCRYPT) failed. return:%ld,"
				    " reason:%ld\n", return_code, reason_code);
		else
			TRACE_ERROR("CSNBSAD (AES DECRYPT) failed. return:%ld,"
				    " reason:%ld\n", return_code, reason_code);
		(*out_data_len) = 0;
		return CKR_FUNCTION_FAILED;
	} else if (reason_code != 0) {
		if (encrypt)
			TRACE_WARNING("CSNBSAE (AES ENCRYPT) succeeded, but"
				      " returned reason:%ld\n", reason_code);
		else
			TRACE_WARNING("CSNBSAD (AES DECRYPT) succeeded, but"
				      " returned reason:%ld\n", reason_code);
	}

	return CKR_OK;
}

CK_RV
token_specific_aes_cbc(STDLL_TokData_t *tokdata,
		       CK_BYTE  *in_data,
		       CK_ULONG	 in_data_len,
		       CK_BYTE	*out_data,
		       CK_ULONG	*out_data_len,
		       OBJECT	*key,
		       CK_BYTE	*init_v,
		       CK_BYTE	 encrypt)
{
	long return_code, reason_code, rule_array_count, length;
	long block_size = 16;
	unsigned char chaining_vector[32];
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE];
	long opt_data_len = 0, key_params_len =0, exit_data_len = 0, IV_len = 16, chain_vector_len = 32;
	CK_BYTE *local_out = out_data;
	char exit_data[0];
	CK_ATTRIBUTE *attr = NULL;
	CK_ULONG key_len;

	// get the key value
	if (template_attribute_find(key->template, CKA_IBM_OPAQUE, &attr) == FALSE) {
		TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
		return CKR_FUNCTION_FAILED;
	}

	if (in_data_len%16 == 0) {
		rule_array_count = 3;
		memcpy(rule_array, "AES     KEYIDENTINITIAL ",
		       rule_array_count*(size_t)CCA_KEYWORD_SIZE);
	} else {
		if ((encrypt) && (*out_data_len < (in_data_len + 16))) {
			local_out = malloc(in_data_len + 16);
			if (!local_out) {
				TRACE_ERROR("Malloc of %lu bytes failed.\n",
					    in_data_len + 16);
				return CKR_HOST_MEMORY;
			}
		}

		rule_array_count = 3;
		memcpy(rule_array, "AES     PKCS-PADKEYIDENT",
		       rule_array_count*(size_t)CCA_KEYWORD_SIZE);
	}

	length = in_data_len;
	key_len = 64;
	if (encrypt) {
		dll_CSNBSAE(&return_code,
			&reason_code,
			&exit_data_len,
			exit_data,
			&rule_array_count,
			rule_array,
			&key_len,
			attr->pValue,
			&key_params_len,
			exit_data,
			&block_size,
			&IV_len,
			init_v,
			&chain_vector_len,
			chaining_vector,
			&length,
			in_data,
			out_data_len,
			out_data,
			&opt_data_len,
			NULL);
	} else {
		dll_CSNBSAD(&return_code,
			&reason_code,
			&exit_data_len,
			exit_data,
			&rule_array_count,
			rule_array,
			&key_len,
			attr->pValue,
			&key_params_len,
			NULL,
			&block_size,
			&IV_len,
			init_v,
			&chain_vector_len,
			chaining_vector,
			&length,
			in_data,
			out_data_len,
			out_data,
			&opt_data_len,
			NULL);
	}

	if (return_code != CCA_SUCCESS) {
		if (encrypt)
			TRACE_ERROR("CSNBSAE (AES ENCRYPT) failed. return:%ld,"
				    " reason:%ld\n", return_code, reason_code);
		else
			TRACE_ERROR("CSNBSAD (AES DECRYPT) failed. return:%ld,"
				    " reason:%ld\n", return_code, reason_code);
		(*out_data_len) = 0;
		return CKR_FUNCTION_FAILED;
	} else if (reason_code != 0) {
		if (encrypt)
			TRACE_WARNING("CSNBSAE (AES ENCRYPT) succeeded, but"
				      " returned reason:%ld\n", reason_code);
		else
			TRACE_WARNING("CSNBSAD (AES DECRYPT) succeeded, but"
				      " returned reason:%ld\n", reason_code);
	}

	/* If we malloc'd a new buffer due to overflow concerns and the data
	 * coming out turned out to be bigger than expected, return an error.
	 *
	 * Else, memcpy the data back to the user's buffer
	 */
	if ((local_out != out_data) && ((CK_ULONG)length > *out_data_len)) {
		TRACE_ERROR("buffer too small: %ld bytes to write into %ld "
			    "bytes space\n", length, *out_data_len);
		free(local_out);
		return CKR_BUFFER_TOO_SMALL;
	} else if (local_out != out_data) {
		memcpy(out_data, local_out, (size_t)length);
		free(local_out);
	}

	*out_data_len = length;

	return CKR_OK;
}
#endif

#ifndef NODH
/* Begin code contributed by Corrent corp. */
CK_RV
token_specific_dh_pkcs_derive(CK_BYTE  *z,
			      CK_ULONG *z_len,
			      CK_BYTE  *y,
			      CK_ULONG  y_len,
			      CK_BYTE  *x,
			      CK_ULONG  x_len,
			      CK_BYTE  *p,
			      CK_ULONG  p_len)
{
	TRACE_DEVEL("Unsupported function reached.\n");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
token_specific_dh_pkcs_key_pair_gen(TEMPLATE *publ_tmpl,
				    TEMPLATE *priv_tmpl )
{
	TRACE_DEVEL("Unsupported function reached.\n");
	return CKR_FUNCTION_NOT_SUPPORTED;
}
/* End code contributed by Corrent corp. */
#endif

/* See the top of this file for the declarations of mech_list and
 * mech_list_len.
 */
CK_RV
token_specific_get_mechanism_list(STDLL_TokData_t *tokdata,
				  CK_MECHANISM_TYPE *pMechanismList,
				  CK_ULONG *pulCount)
{
	CK_ULONG i;

	if (pMechanismList == NULL) {
		(*pulCount) = mech_list_len;
		return CKR_OK;
	}

	if ((*pulCount) < mech_list_len) {
		(*pulCount) = mech_list_len;
		TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
		return CKR_BUFFER_TOO_SMALL;
	}

	for (i = 0; i < mech_list_len; i++)
		pMechanismList[i] = mech_list[i].mech_type;
	(*pulCount) = mech_list_len;

	return CKR_OK;
}

CK_RV
token_specific_get_mechanism_info(CK_MECHANISM_TYPE type, CK_MECHANISM_INFO *pInfo)
{
	CK_ULONG i;

	for (i = 0; i < mech_list_len; i++) {
		if (mech_list[i].mech_type == type) {
			memcpy(pInfo, &mech_list[i].mech_info,
			       sizeof(CK_MECHANISM_INFO));
			return CKR_OK;
		}
	}

	TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
	return CKR_MECHANISM_INVALID;
}

CK_RV
build_update_attribute(TEMPLATE *tmpl,
		CK_ATTRIBUTE_TYPE  type,
		CK_BYTE *data,
		CK_ULONG data_len)
{
	CK_ATTRIBUTE *attr;
	CK_RV rv;
	if ((rv = build_attribute(type, data, data_len, &attr))) {
		TRACE_DEVEL("Build attribute for type=%lu failed rv=0x%lx\n",
			    type, rv);
		return rv;
	}
	template_update_attribute(tmpl, attr);
	return CKR_OK;
}

uint16_t
cca_ec_privkey_offset(CK_BYTE *tok)
{
	uint8_t privkey_id = CCA_PRIVKEY_ID, privkey_rec;
	privkey_rec = ntohs(*(uint8_t*)&tok[CCA_EC_HEADER_SIZE]);
	if ((memcmp(&privkey_rec, &privkey_id, sizeof(uint8_t)) == 0)) {
		return CCA_EC_HEADER_SIZE;
	}
	TRACE_WARNING("+++++++++ Token key private section is CORRUPTED\n");
	return CCA_EC_HEADER_SIZE;
}

uint16_t
cca_ec_publkey_offset(CK_BYTE *tok)
{
	uint16_t priv_offset, privSec_len;
	uint8_t publkey_id = CCA_PUBLKEY_ID, publkey_rec;

	priv_offset = cca_ec_privkey_offset(tok);
	privSec_len = ntohs(*(uint16_t*)&tok[priv_offset + CCA_SECTION_LEN_OFFSET]);
	publkey_rec = ntohs(*(uint8_t*)&tok[priv_offset + privSec_len]);
	if ((memcmp(&publkey_rec, &publkey_id, sizeof(uint8_t)) == 0)) {
		return (priv_offset + privSec_len);
	}
	TRACE_WARNING("++++++++ Token key public section is CORRUPTED\n");
	return (priv_offset + privSec_len);
}

CK_RV
token_create_ec_keypair(TEMPLATE *publ_tmpl,
		TEMPLATE *priv_tmpl,
		CK_ULONG tok_len,
		CK_BYTE *tok)
{
	uint16_t pubkey_offset, qlen_offset, q_offset;
	CK_ULONG q_len;
	CK_BYTE q[CCATOK_EC_MAX_Q_LEN];
	CK_RV rv;
	CK_ATTRIBUTE *attr = NULL;

	/*
	 * The token includes the header section first,
	 * the private key section in the middle,
	 * and the public key section last.
	 */

	/* The pkcs#11v2.20:
	 * CKA_ECDSA_PARAMS must be in public key's template when
	 * generating key pair and added to private key template.
	 * CKA_EC_POINT added to public key when key is generated.
	 */

	/*
	 * Get Q data for public key.
	 */
	pubkey_offset = cca_ec_publkey_offset(tok);

	qlen_offset =  pubkey_offset + CCA_EC_INTTOK_PUBKEY_Q_LEN_OFFSET;
	q_len = *(uint16_t *)&tok[qlen_offset];
	q_len = ntohs(q_len);

	if (q_len > CCATOK_EC_MAX_Q_LEN) {
		TRACE_ERROR("Not enough room to return q. (Got %d, need %ld)\n",
			    CCATOK_EC_MAX_Q_LEN, q_len);
		return CKR_FUNCTION_FAILED;
	}

	q_offset = pubkey_offset + CCA_EC_INTTOK_PUBKEY_Q_OFFSET;
	memcpy(q, &tok[q_offset], (size_t)q_len);

	if ((rv = build_update_attribute(publ_tmpl, CKA_EC_POINT, q, q_len)))
	{
		TRACE_DEVEL("build_update_attribute for q failed rv=0x%lx\n",
			    rv);
		return rv;
	}

	/* Add ec params to private key */
	if (!template_attribute_find(publ_tmpl, CKA_ECDSA_PARAMS, &attr)) {
		TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
		return CKR_TEMPLATE_INCOMPLETE;
	}

	if ((rv = build_update_attribute(priv_tmpl, CKA_ECDSA_PARAMS,
					attr->pValue, attr->ulValueLen))) {
		TRACE_DEVEL("build_update_attribute for der data failed "
			    "rv=0x%lx\n", rv);
		return rv;
	}

	/*
	 * Save the CKA_IBM_OPAQUE for both keys.
	 */
	if ((rv = build_update_attribute(publ_tmpl, CKA_IBM_OPAQUE, tok, tok_len))) {
		TRACE_DEVEL("build_update_attribute for tok failed rv=0x%lx\n",
			    rv);
		return rv;
	}

	if ((rv = build_update_attribute(priv_tmpl, CKA_IBM_OPAQUE, tok, tok_len))) {
		TRACE_DEVEL("build_update_attribute for tok failed rv=0x%lx\n",
			    rv);
		return rv;
	}

	return CKR_OK;
}

CK_RV
token_specific_ec_generate_keypair(STDLL_TokData_t *tokdata, TEMPLATE *publ_tmpl,
				   TEMPLATE *priv_tmpl)
{
	long return_code, reason_code, rule_array_count, exit_data_len = 0;
	unsigned char *exit_data = NULL;
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
	long key_value_structure_length, private_key_name_length, key_token_length;
	unsigned char key_value_structure[CCA_EC_KEY_VALUE_STRUCT_SIZE] = { 0, };
	unsigned char private_key_name[CCA_PRIVATE_KEY_NAME_SIZE] = { 0, };
	unsigned char key_token[CCA_KEY_TOKEN_SIZE] = { 0, };
	long regeneration_data_length, generated_key_token_length;
	unsigned char regeneration_data[CCA_REGENERATION_DATA_SIZE] = { 0, };
	unsigned char transport_key_identifier[CCA_KEY_ID_SIZE] = { 0, };
	unsigned char generated_key_token[CCA_KEY_TOKEN_SIZE] = { 0, };
	unsigned int i;
	CK_BBOOL found = FALSE;
	CK_ATTRIBUTE *attr = NULL;
	CK_RV rv;
	long param1=0;
	unsigned char *param2=NULL;

	if (!template_attribute_find(publ_tmpl, CKA_ECDSA_PARAMS, &attr)) {
		TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
		return CKR_TEMPLATE_INCOMPLETE;
	}

	for (i = 0; i < NUMEC; i++) {
		if ((attr->ulValueLen == der_ec_supported[i].data_size) &&
				(memcmp(attr->pValue, der_ec_supported[i].data,
				attr->ulValueLen) == 0)) {
			found = TRUE;
			break;
		}
	}

	if(found == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
		return CKR_MECHANISM_PARAM_INVALID;
	}

	/*
	 * See CCA doc: page 94 for offset of data in key_value_structure
	 */
	memcpy(key_value_structure,
			&(der_ec_supported[i].curve_type), sizeof(uint8_t));
	memcpy(&key_value_structure[CCA_PKB_EC_LEN_OFFSET],
			&(der_ec_supported[i].len_bits), sizeof(uint16_t));

	key_value_structure_length = CCA_EC_KEY_VALUE_STRUCT_SIZE;

	rule_array_count = 1;
	memcpy(rule_array, "ECC-PAIR", (size_t)(CCA_KEYWORD_SIZE));

	private_key_name_length = 0;

	key_token_length = CCA_KEY_TOKEN_SIZE;

	dll_CSNDPKB(&return_code,
			&reason_code,
			&exit_data_len,
			exit_data,
			&rule_array_count,
			rule_array,
			&key_value_structure_length,
			key_value_structure,
			&private_key_name_length,
			private_key_name,
			&param1,
			param2,
			&param1,
			param2,
			&param1,
			param2,
			&param1,
			param2,
			&param1,
			param2,
			&key_token_length,
			key_token);

	if (return_code != CCA_SUCCESS) {
		TRACE_ERROR("CSNDPKB (EC KEY TOKEN BUILD) failed. return:%ld,"
			    " reason:%ld\n", return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	}

	rule_array_count = 1;
	memset(rule_array, 0, sizeof(rule_array));
	memcpy(rule_array, "MASTER  ", (size_t)CCA_KEYWORD_SIZE);

	generated_key_token_length = CCA_KEY_TOKEN_SIZE;

	regeneration_data_length = 0;

	dll_CSNDPKG(&return_code,
			&reason_code,
			NULL,
			NULL,
			&rule_array_count,
			rule_array,
			&regeneration_data_length,
			regeneration_data,
			&key_token_length,
			key_token,
			transport_key_identifier,
			&generated_key_token_length,
			generated_key_token);

	if (return_code != CCA_SUCCESS) {
			TRACE_ERROR("CSNDPKG (EC KEY GENERATE) failed."
				    " return:%ld, reason:%ld\n",
				    return_code, reason_code);
			return CKR_FUNCTION_FAILED;
	}

	TRACE_DEVEL("ECC secure key token generated. size: %ld\n",
		     generated_key_token_length);

	rv = token_create_ec_keypair(publ_tmpl, priv_tmpl,
			generated_key_token_length, generated_key_token);
	if (rv != CKR_OK) {
		TRACE_DEVEL("token_create_ec_keypair failed. rv: %lu\n", rv);
		return rv;
	}

	return rv;
}

CK_RV
token_specific_ec_sign(STDLL_TokData_t * tokdata,
			CK_BYTE  * in_data,
			CK_ULONG   in_data_len,
			CK_BYTE  * out_data,
			CK_ULONG * out_data_len,
			OBJECT   * key_obj )
{
	long return_code, reason_code, rule_array_count;
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
	long signature_bit_length;
	CK_ATTRIBUTE *attr;

	/* Find the secure key token */
	if (!template_attribute_find(key_obj->template, CKA_IBM_OPAQUE, &attr)) {
		TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
		return CKR_TEMPLATE_INCOMPLETE;
	}

	/* CCA doc: page 113 */
	rule_array_count = 1;
	memcpy(rule_array, "ECDSA   ", CCA_KEYWORD_SIZE);

	dll_CSNDDSG(&return_code,
			&reason_code,
			NULL,
			NULL,
			&rule_array_count,
			rule_array,
			(long *)&(attr->ulValueLen),
			attr->pValue,
			(long *)&in_data_len,
			in_data,
			(long *)out_data_len,
			&signature_bit_length,
			out_data);

	if (return_code != CCA_SUCCESS) {
		TRACE_ERROR("CSNDDSG (EC SIGN) failed. return:%ld,"
				    " reason:%ld\n", return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	} else if (reason_code != 0) {
		TRACE_WARNING("CSNDDSG (EC SIGN) succeeded, but"
			    " returned reason:%ld\n", reason_code);
	}

	return CKR_OK;
}

CK_RV
token_specific_ec_verify(STDLL_TokData_t * tokdata,
			  CK_BYTE  * in_data,
			  CK_ULONG   in_data_len,
			  CK_BYTE  * out_data,
			  CK_ULONG   out_data_len,
			  OBJECT   * key_obj )
{
	long return_code, reason_code, rule_array_count;
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
	CK_ATTRIBUTE *attr;

	/* Find the secure key token */
	if (!template_attribute_find(key_obj->template, CKA_IBM_OPAQUE, &attr))	{
		TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
		return CKR_TEMPLATE_INCOMPLETE;
	}

	/* CCA doc: page 118 */
	rule_array_count = 1;
	memcpy(rule_array, "ECDSA   ", CCA_KEYWORD_SIZE);

	dll_CSNDDSV(&return_code,
			&reason_code,
			NULL,
			NULL,
			&rule_array_count,
			rule_array,
			(long *)&(attr->ulValueLen),
			attr->pValue,
			(long *)&in_data_len,
			in_data,
			(long *)&out_data_len,
			out_data);

	if (return_code == 4 && reason_code == 429) {
		return CKR_SIGNATURE_INVALID;
	} else if (return_code != CCA_SUCCESS) {
		TRACE_ERROR("CSNDDSV (EC VERIFY) failed. return:%ld,"
			    " reason:%ld\n", return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	} else if (reason_code != 0) {
		TRACE_WARNING("CSNDDSV (EC VERIFY) succeeded, but"
			      " returned reason:%ld\n", reason_code);
	}

	return CKR_OK;
}

CK_RV token_specific_sha_init(DIGEST_CONTEXT *ctx, CK_MECHANISM *mech)
{
	CK_ULONG hash_size;
	struct cca_sha_ctx *cca_ctx;

	switch(mech->mechanism) {
	case CKM_SHA_1:
		hash_size = SHA1_HASH_SIZE;
		break;
	case CKM_SHA256:
		hash_size = SHA2_HASH_SIZE;
		break;
	case CKM_SHA384:
		hash_size = SHA3_HASH_SIZE;
		break;
	case CKM_SHA512:
		hash_size = SHA5_HASH_SIZE;
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}

	ctx->context = calloc(1, sizeof(struct cca_sha_ctx));
	if (ctx->context == NULL) {
		TRACE_ERROR("malloc failed in sha digest init\n");
		return CKR_HOST_MEMORY;
	}
	ctx->context_len = sizeof(struct cca_sha_ctx);

	cca_ctx = (struct cca_sha_ctx *)ctx->context;
	cca_ctx->chain_vector_len = CCA_CHAIN_VECTOR_LEN;
	cca_ctx->hash_len = hash_size;
	/* tail_len is already 0 */

	return CKR_OK;
}

CK_RV token_specific_sha(DIGEST_CONTEXT *ctx, CK_BYTE *in_data,
			 CK_ULONG in_data_len, CK_BYTE *out_data,
			 CK_ULONG *out_data_len)
{
	struct cca_sha_ctx *cca_ctx;
	long return_code, reason_code, rule_array_count = 2;
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };

	if (!ctx || !ctx->context)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (!in_data || !out_data)
		return CKR_ARGUMENTS_BAD;

	cca_ctx = (struct cca_sha_ctx *)ctx->context;

	if (*out_data_len < cca_ctx->hash_len)
		return CKR_BUFFER_TOO_SMALL;

	switch (ctx->mech.mechanism) {
	case CKM_SHA_1:
		memcpy(rule_array, "SHA-1   ONLY    ", CCA_KEYWORD_SIZE * 2);
		cca_ctx->part = CCA_HASH_PART_ONLY;
		break;
	case CKM_SHA256:
		memcpy(rule_array, "SHA-256 ONLY    ", CCA_KEYWORD_SIZE * 2);
		cca_ctx->part = CCA_HASH_PART_ONLY;
		break;
	case CKM_SHA384:
		memcpy(rule_array, "SHA-384 ONLY    ", CCA_KEYWORD_SIZE * 2);
		cca_ctx->part = CCA_HASH_PART_ONLY;
		break;
	case CKM_SHA512:
		memcpy(rule_array, "SHA-512 ONLY    ", CCA_KEYWORD_SIZE * 2);
		cca_ctx->part = CCA_HASH_PART_ONLY;
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}


	dll_CSNBOWH(&return_code, &reason_code, NULL, NULL, &rule_array_count,
		rule_array, &in_data_len, in_data, &cca_ctx->chain_vector_len,
		cca_ctx->chain_vector, &cca_ctx->hash_len, cca_ctx->hash);

	if (return_code != CCA_SUCCESS) {
		TRACE_ERROR("CSNBOWH failed. return:%ld, reason:%ld\n",
			    return_code, reason_code);
		free(cca_ctx->tail);
		return CKR_FUNCTION_FAILED;
	}

	memcpy(out_data, cca_ctx->hash, cca_ctx->hash_len);
	*out_data_len = cca_ctx->hash_len;

	/* ctx->context should get freed in digest_mgr_cleanup() */
	return CKR_OK;
}

CK_RV token_specific_sha_update(DIGEST_CONTEXT *ctx, CK_BYTE *in_data,
				CK_ULONG in_data_len)
{
	struct cca_sha_ctx *cca_ctx;
	long return_code, reason_code, total, buffer_len, rule_array_count = 2;
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
	CK_RV rc = CKR_OK;
	unsigned char *buffer = NULL;
	int blocksz, blocksz_mask, use_buffer = 0;

	if (!in_data)
		return CKR_ARGUMENTS_BAD;

	if (!ctx || !ctx->context)
		return CKR_OPERATION_NOT_INITIALIZED;

	switch(ctx->mech.mechanism) {
	case CKM_SHA_1:
		blocksz = SHA1_BLOCK_SIZE;
		blocksz_mask = SHA1_BLOCK_SIZE_MASK;
		break;
	case CKM_SHA256:
		blocksz = SHA2_BLOCK_SIZE;
		blocksz_mask = SHA2_BLOCK_SIZE_MASK;
		break;
	case CKM_SHA384:
		blocksz = SHA3_BLOCK_SIZE;
		blocksz_mask = SHA3_BLOCK_SIZE_MASK;
		break;
	case CKM_SHA512:
		blocksz = SHA5_BLOCK_SIZE;
		blocksz_mask = SHA5_BLOCK_SIZE_MASK;
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}

	cca_ctx = (struct cca_sha_ctx *)ctx->context;

	/* just send if input a multiple of block size and
	 * cca_ctx-> tail is empty.
	 */
	if ((cca_ctx->tail_len == 0) && ((in_data_len & blocksz_mask) == 0))
		goto send;

	/* at this point, in_data is not multiple of blocksize
	 * and/or there is saved data from previous update still
	 * needing to be processed
	 */

	/* get totals */
	total = cca_ctx->tail_len + in_data_len;

	/* see if we have enough to fill a block */
	if (total >= blocksz) {
		int remainder;

		remainder = total & blocksz_mask;
		buffer_len = total - remainder;

		/* allocate a buffer for sending... */
		if (!(buffer = malloc(buffer_len))) {
			TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
			rc = CKR_HOST_MEMORY;
			goto done;
		}

		memcpy(buffer, cca_ctx->tail, cca_ctx->tail_len);
		memcpy(buffer + cca_ctx->tail_len, in_data,
			in_data_len - remainder);
		use_buffer = 1;

		/* save remainder data for next time */
		if (remainder)
			memcpy(cca_ctx->tail,
				in_data + (in_data_len - remainder), remainder);
		cca_ctx->tail_len = remainder;

	} else {
		/* not enough to fill a block, save off data for next round */
		memcpy(cca_ctx->tail + cca_ctx->tail_len, in_data, in_data_len);
		cca_ctx->tail_len += in_data_len;
		return CKR_OK;
	}

send:
	switch(ctx->mech.mechanism) {
	case CKM_SHA_1:
		if (cca_ctx->part == CCA_HASH_PART_FIRST) {
			memcpy(rule_array, "SHA-1   FIRST   ",
				CCA_KEYWORD_SIZE * 2);
			cca_ctx->part = CCA_HASH_PART_MIDDLE;
		} else {
			memcpy(rule_array, "SHA-1   MIDDLE  ",
				CCA_KEYWORD_SIZE * 2);
		}
		break;
	case CKM_SHA256:
		if (cca_ctx->part == CCA_HASH_PART_FIRST) {
			memcpy(rule_array, "SHA-256 FIRST   ",
				CCA_KEYWORD_SIZE * 2);
			cca_ctx->part = CCA_HASH_PART_MIDDLE;
		} else {
			memcpy(rule_array, "SHA-256 MIDDLE  ",
				CCA_KEYWORD_SIZE * 2);
		}
		break;
	case CKM_SHA384:
		if (cca_ctx->part == CCA_HASH_PART_FIRST) {
			memcpy(rule_array, "SHA-384 FIRST   ",
				CCA_KEYWORD_SIZE * 2);
			cca_ctx->part = CCA_HASH_PART_MIDDLE;
		} else {
			memcpy(rule_array, "SHA-384 MIDDLE  ",
				CCA_KEYWORD_SIZE * 2);
		}
		break;
	case CKM_SHA512:
		if (cca_ctx->part == CCA_HASH_PART_FIRST) {
			memcpy(rule_array, "SHA-512 FIRST   ",
				CCA_KEYWORD_SIZE * 2);
			cca_ctx->part = CCA_HASH_PART_MIDDLE;
		} else {
			memcpy(rule_array, "SHA-512 MIDDLE  ",
				CCA_KEYWORD_SIZE * 2);
		}
		break;
	}

	dll_CSNBOWH(&return_code, &reason_code, NULL, NULL, &rule_array_count,
		rule_array, use_buffer ? &buffer_len : (long *)&in_data_len,
		use_buffer ? buffer : in_data, &cca_ctx->chain_vector_len,
		cca_ctx->chain_vector, &cca_ctx->hash_len, cca_ctx->hash);

	if (return_code != CCA_SUCCESS) {
		TRACE_ERROR("CSNBOWH (SHA UPDATE) failed. return:%ld,"
			    " reason:%ld\n", return_code, reason_code);
		rc = CKR_FUNCTION_FAILED;
	}

done:
	if (buffer)
		free(buffer);
	return rc;
}

CK_RV token_specific_sha_final(DIGEST_CONTEXT *ctx, CK_BYTE *out_data,
			       CK_ULONG *out_data_len)
{
	struct cca_sha_ctx *cca_ctx;
	long return_code, reason_code, rule_array_count = 2;
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
	unsigned char dummy_buf[1] = { 0 };

	if (!ctx || !ctx->context)
		return CKR_OPERATION_NOT_INITIALIZED;

	cca_ctx = (struct cca_sha_ctx *)ctx->context;
	if (*out_data_len < cca_ctx->hash_len) {
		TRACE_ERROR("out buf too small for hash: %lu\n", *out_data_len);
		return CKR_BUFFER_TOO_SMALL;
	}

	switch(ctx->mech.mechanism) {
	case CKM_SHA_1:
		if (cca_ctx->part == CCA_HASH_PART_FIRST) {
			memcpy(rule_array, "SHA-1   ONLY    ",
				CCA_KEYWORD_SIZE * 2);
		} else {
			/* there's some extra data we need to hash to
			 * complete the operation
			 */
			memcpy(rule_array, "SHA-1   LAST    ",
				CCA_KEYWORD_SIZE * 2);
		}
		break;
	case CKM_SHA256:
		if (cca_ctx->part == CCA_HASH_PART_FIRST) {
			memcpy(rule_array, "SHA-256 ONLY    ",
				CCA_KEYWORD_SIZE * 2);
		} else {
			/* there's some extra data we need to hash to
			 * complete the operation
			 */
			memcpy(rule_array, "SHA-256 LAST    ",
				CCA_KEYWORD_SIZE * 2);
		}
		break;
	case CKM_SHA384:
		if (cca_ctx->part == CCA_HASH_PART_FIRST) {
			memcpy(rule_array, "SHA-384 ONLY    ",
				CCA_KEYWORD_SIZE * 2);
		} else {
			/* there's some extra data we need to hash to
			 * complete the operation
			 */
			memcpy(rule_array, "SHA-384 LAST    ",
				CCA_KEYWORD_SIZE * 2);
		}
		break;
	case CKM_SHA512:
		if (cca_ctx->part == CCA_HASH_PART_FIRST) {
			memcpy(rule_array, "SHA-512 ONLY    ",
				CCA_KEYWORD_SIZE * 2);
		} else {
			/* there's some extra data we need to hash to
			 * complete the operation
			 */
			memcpy(rule_array, "SHA-512 LAST    ",
				CCA_KEYWORD_SIZE * 2);
		}
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}

	TRACE_DEBUG("tail_len: %lu, tail: %p, cvl: %lu, sl: %lu\n",
		    cca_ctx->tail_len,
		    cca_ctx->tail ? cca_ctx->tail : dummy_buf,
		    cca_ctx->chain_vector_len, cca_ctx->hash_len);

	dll_CSNBOWH(&return_code, &reason_code, NULL, NULL, &rule_array_count,
		rule_array, &cca_ctx->tail_len,
		cca_ctx->tail ? cca_ctx->tail : dummy_buf,
		&cca_ctx->chain_vector_len, cca_ctx->chain_vector,
		&cca_ctx->hash_len, cca_ctx->hash);

	if (return_code != CCA_SUCCESS) {
		TRACE_ERROR("CSNBOWH (SHA FINAL) failed. return:%ld,"
			    " reason:%ld\n", return_code, reason_code);
		free(cca_ctx->tail);
		return CKR_FUNCTION_FAILED;
	}

	memcpy(out_data, cca_ctx->hash, cca_ctx->hash_len);
	*out_data_len = cca_ctx->hash_len;

	/* ctx->context should get freed in digest_mgr_cleanup() */
	return CKR_OK;
}

static long get_mac_len(CK_MECHANISM *mech)
{
	switch (mech->mechanism) {
	case CKM_SHA_1_HMAC_GENERAL:
	case CKM_SHA256_HMAC_GENERAL:
	case CKM_SHA384_HMAC_GENERAL:
	case CKM_SHA512_HMAC_GENERAL:
		return *(CK_ULONG *)(mech->pParameter);
	case CKM_SHA_1_HMAC:
		return SHA1_HASH_SIZE;
	case CKM_SHA256_HMAC:
		return SHA2_HASH_SIZE;
	case CKM_SHA384_HMAC:
		return SHA3_HASH_SIZE;
	case CKM_SHA512_HMAC:
		return SHA5_HASH_SIZE;
	default:
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return -1;
	}
}

static CK_RV ccatok_hmac_init(SIGN_VERIFY_CONTEXT *ctx, CK_MECHANISM *mech,
			      CK_OBJECT_HANDLE key)
{
	struct cca_sha_ctx *cca_ctx;
	long maclen = -1;

	maclen = get_mac_len(mech);
	if (maclen < 0)
		return CKR_MECHANISM_INVALID;

	ctx->context = calloc(1, sizeof(struct cca_sha_ctx));
	if (ctx->context == NULL) {
		TRACE_ERROR("malloc failed in sha digest init\n");
		return CKR_HOST_MEMORY;
	}
	ctx->context_len = sizeof(struct cca_sha_ctx);

	cca_ctx = (struct cca_sha_ctx *)ctx->context;

	memset(cca_ctx, 0, sizeof(struct cca_sha_ctx));
	cca_ctx->chain_vector_len = CCA_CHAIN_VECTOR_LEN;
	cca_ctx->hash_len = maclen;

        return CKR_OK;
}

CK_RV token_specific_hmac_sign_init(STDLL_TokData_t *tokdata, SESSION *sess,
				    CK_MECHANISM *mech, CK_OBJECT_HANDLE key)
{
	return ccatok_hmac_init(&sess->sign_ctx, mech, key);
}

CK_RV token_specific_hmac_verify_init(STDLL_TokData_t *tokdata, SESSION *sess,
				      CK_MECHANISM *mech, CK_OBJECT_HANDLE key)
{
	return ccatok_hmac_init(&sess->verify_ctx, mech, key);
}

CK_RV ccatok_hmac(STDLL_TokData_t *tokdata, SIGN_VERIFY_CONTEXT *ctx,
		  CK_BYTE *in_data, CK_ULONG in_data_len, CK_BYTE *signature,
		  CK_ULONG *sig_len, CK_BBOOL sign)
{
	struct cca_sha_ctx *cca_ctx;
	long return_code = 0, reason_code = 0, rule_array_count = 3;
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE];
	OBJECT *key = NULL;
	CK_ATTRIBUTE *attr = NULL;
	CK_RV rc = CKR_OK;

	if (!ctx || !ctx->context) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	if (sign && !sig_len) {
		TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	rc = object_mgr_find_in_map1(ctx->key, &key);
	if (rc != CKR_OK) {
		TRACE_ERROR("Failed to find specified object.\n");
		return rc;
	}

	if (template_attribute_find(key->template, CKA_IBM_OPAQUE,
				    &attr) == FALSE) {
		TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
		return CKR_FUNCTION_FAILED;
	}

	cca_ctx = (struct cca_sha_ctx *)ctx->context;

	switch (ctx->mech.mechanism) {
	case CKM_SHA_1_HMAC_GENERAL:
	case CKM_SHA_1_HMAC:
		memcpy(rule_array, "HMAC    SHA-1   ONLY    ",
		       3 * CCA_KEYWORD_SIZE);
		break;
	case CKM_SHA256_HMAC_GENERAL:
	case CKM_SHA256_HMAC:
		memcpy(rule_array, "HMAC    SHA-256 ONLY    ",
		       3 * CCA_KEYWORD_SIZE);
		break;
	case CKM_SHA384_HMAC_GENERAL:
	case CKM_SHA384_HMAC:
		memcpy(rule_array, "HMAC    SHA-384 ONLY    ",
		       3 * CCA_KEYWORD_SIZE);
		break;
	case CKM_SHA512_HMAC_GENERAL:
	case CKM_SHA512_HMAC:
		memcpy(rule_array, "HMAC    SHA-512 ONLY    ",
		       3 * CCA_KEYWORD_SIZE);
		break;
	default:
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return CKR_MECHANISM_INVALID;
	}

	TRACE_INFO("ccatok_hmac: key length is %lu\n", attr->ulValueLen);
	TRACE_INFO("The mac length is %ld\n", cca_ctx->hash_len);

	if (sign) {
		dll_CSNBHMG(&return_code, &reason_code, NULL, NULL,
			&rule_array_count, rule_array, &attr->ulValueLen,
			attr->pValue, &in_data_len, in_data,
			&cca_ctx->chain_vector_len, cca_ctx->chain_vector,
			&cca_ctx->hash_len, cca_ctx->hash);

		if (return_code != CCA_SUCCESS) {
			TRACE_ERROR("CSNBHMG (HMAC GENERATE) failed. "
				    "return:%ld, reason:%ld\n", return_code,
				    reason_code);
			*sig_len = 0;
			return CKR_FUNCTION_FAILED;
		}

		/* Copy the signature into the user supplied variable.
		 * For hmac general mechs, only copy over the specified
		 * number of bytes for the mac.
		 */
		memcpy(signature, cca_ctx->hash, cca_ctx->hash_len);
		*sig_len = cca_ctx->hash_len;
	} else {		// verify
		dll_CSNBHMV(&return_code, &reason_code, NULL, NULL,
			&rule_array_count, rule_array, &attr->ulValueLen,
			attr->pValue, &in_data_len, in_data,
			&cca_ctx->chain_vector_len, cca_ctx->chain_vector,
			&cca_ctx->hash_len, signature);

		if (return_code == 4 && (reason_code == 429 ||
		    reason_code == 1)) {
			TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
			return CKR_SIGNATURE_INVALID;
		} else if (return_code != CCA_SUCCESS) {
			TRACE_ERROR("CSNBHMV (HMAC VERIFY) failed. return:%ld,"
				    " reason:%ld\n", return_code, reason_code);
			return CKR_FUNCTION_FAILED;
		} else if (reason_code != 0) {
			TRACE_WARNING("CSNBHMV (HMAC VERIFY) succeeded, but"
				      " returned reason:%ld\n", reason_code);
		}
	}

	return CKR_OK;
}

CK_RV token_specific_hmac_sign(STDLL_TokData_t *tokdata, SESSION *sess,
			       CK_BYTE *in_data, CK_ULONG in_data_len,
			       CK_BYTE *signature, CK_ULONG *sig_len)
{
	return ccatok_hmac(tokdata, &sess->sign_ctx, in_data, in_data_len,
			   signature, sig_len, TRUE);
}

CK_RV token_specific_hmac_verify(STDLL_TokData_t *tokdata, SESSION *sess,
				 CK_BYTE *in_data, CK_ULONG in_data_len,
				 CK_BYTE *signature, CK_ULONG sig_len)
{
	return ccatok_hmac(tokdata, &sess->verify_ctx, in_data, in_data_len,
			   signature, &sig_len, FALSE);
}

CK_RV ccatok_hmac_update(STDLL_TokData_t *tokdata, SIGN_VERIFY_CONTEXT *ctx,
			 CK_BYTE *in_data, CK_ULONG in_data_len, CK_BBOOL sign)
{
	struct cca_sha_ctx *cca_ctx;
	long return_code, reason_code, total, buffer_len;
	long hsize, rule_array_count = 3;
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
	unsigned char *buffer = NULL;
	int blocksz, blocksz_mask, use_buffer = 0;
	OBJECT *key = NULL;
	CK_ATTRIBUTE *attr = NULL;
	CK_RV rc = CKR_OK;

	if (!ctx || !ctx->context) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	/* if zero input data, then just do nothing and return.
	 * "final" should catch if this is case of hashing zero input.
	 */
	if (in_data_len == 0)
		return CKR_OK;

	rc = object_mgr_find_in_map1(ctx->key, &key);
	if (rc != CKR_OK) {
		TRACE_ERROR("Failed to find specified object.\n");
		return rc;
	}

	if (template_attribute_find(key->template, CKA_IBM_OPAQUE,
				    &attr) == FALSE) {
		TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
		return CKR_FUNCTION_FAILED;
	}

	switch(ctx->mech.mechanism) {
	case CKM_SHA_1_HMAC:
	case CKM_SHA_1_HMAC_GENERAL:
	case CKM_SHA256_HMAC:
	case CKM_SHA256_HMAC_GENERAL:
		blocksz = SHA1_BLOCK_SIZE;		// set to 64 bytes
		blocksz_mask = SHA1_BLOCK_SIZE_MASK;	// set to 63
		break;
	case CKM_SHA384_HMAC:
	case CKM_SHA384_HMAC_GENERAL:
	case CKM_SHA512_HMAC:
	case CKM_SHA512_HMAC_GENERAL:
		blocksz = SHA5_BLOCK_SIZE;		// set to 128 bytes
		blocksz_mask = SHA5_BLOCK_SIZE_MASK;	// set to 127
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}

	cca_ctx = (struct cca_sha_ctx *)ctx->context;

	/* just send if input a multiple of block size and
	 * cca_ctx-> tail is empty.
	 */
        if ((cca_ctx->tail_len == 0) && ((in_data_len & blocksz_mask) == 0))
                goto send;

	/* at this point, in_data is not multiple of blocksize
	 * and/or there is saved data from previous update still
	 * needing to be processed
	 */

	/* get totals */
	total = cca_ctx->tail_len + in_data_len;

	/* see if we have enough to fill a block */
	if (total >= blocksz) {
		int remainder;

		remainder = total & blocksz_mask;	// save left over
		buffer_len = total - remainder;

		/* allocate a buffer for sending... */
		if (!(buffer = malloc(buffer_len))) {
			TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
			rc = CKR_HOST_MEMORY;
			goto done;
		}

		/* copy data to send.
		 * first get any data saved in tail from prior call,
		 * then fill up remaining space in block with in_data
		 */
		memcpy(buffer, cca_ctx->tail, cca_ctx->tail_len);
		memcpy(buffer + cca_ctx->tail_len, in_data,
			in_data_len - remainder);
		use_buffer = 1;

		/* save remainder data for next time */
		if (remainder)
			memcpy(cca_ctx->tail,
			       in_data + (in_data_len - remainder), remainder);
		cca_ctx->tail_len = remainder;
	} else {
		/* not enough to fill a block,
		 * so save off data for next round
		 */
		memcpy(cca_ctx->tail + cca_ctx->tail_len, in_data, in_data_len);
		cca_ctx->tail_len += in_data_len;
		return CKR_OK;
	}

send:
	switch(ctx->mech.mechanism) {
	case CKM_SHA_1_HMAC:
	case CKM_SHA_1_HMAC_GENERAL:
		hsize = SHA1_HASH_SIZE;
		memcpy(rule_array, "HMAC    SHA-1   ", CCA_KEYWORD_SIZE * 2);
                break;
	case CKM_SHA256_HMAC:
	case CKM_SHA256_HMAC_GENERAL:
		hsize = SHA2_HASH_SIZE;
		memcpy(rule_array, "HMAC    SHA-256 ", CCA_KEYWORD_SIZE * 2);
		break;
	case CKM_SHA384_HMAC:
	case CKM_SHA384_HMAC_GENERAL:
		hsize = SHA3_HASH_SIZE;
		memcpy(rule_array, "HMAC    SHA-384 ", CCA_KEYWORD_SIZE * 2);
                break;
	case CKM_SHA512_HMAC:
	case CKM_SHA512_HMAC_GENERAL:
		hsize = SHA5_HASH_SIZE;
		memcpy(rule_array, "HMAC    SHA-512 ", CCA_KEYWORD_SIZE * 2);
                break;
        }

	if (cca_ctx->part == CCA_HASH_PART_FIRST) {
		memcpy(rule_array + (CCA_KEYWORD_SIZE*2), "FIRST   ",
		       CCA_KEYWORD_SIZE);
		cca_ctx->part = CCA_HASH_PART_MIDDLE;
	} else {
		memcpy(rule_array + (CCA_KEYWORD_SIZE*2), "MIDDLE  ",
		       CCA_KEYWORD_SIZE);
	}

	TRACE_INFO("CSNBHMG: key length is %lu\n", attr->ulValueLen);

	if (sign) {
		dll_CSNBHMG(&return_code, &reason_code, NULL, NULL,
			&rule_array_count, rule_array, &attr->ulValueLen,
			attr->pValue,
			use_buffer ? &buffer_len : (long *)&in_data_len,
			use_buffer ? buffer : in_data,
			&cca_ctx->chain_vector_len, cca_ctx->chain_vector,
			&hsize, cca_ctx->hash);

		if (return_code != CCA_SUCCESS) {
			TRACE_ERROR("CSNBHMG (HMAC SIGN UPDATE) failed. "
				     "return:%ld, reason:%ld\n", return_code,
				     reason_code);
			rc = CKR_FUNCTION_FAILED;
		}
	} else {	// verify
		dll_CSNBHMV(&return_code, &reason_code, NULL, NULL,
			&rule_array_count, rule_array, &attr->ulValueLen,
			attr->pValue,
			use_buffer ? &buffer_len : (long *)&in_data_len,
			use_buffer ? buffer : in_data,
			&cca_ctx->chain_vector_len, cca_ctx->chain_vector,
			&hsize, cca_ctx->hash);
		if (return_code != CCA_SUCCESS) {
			TRACE_ERROR("CSNBHMG (HMAC VERIFY UPDATE) failed. "
				    "return:%ld, reason:%ld\n", return_code,
				    reason_code);
			rc =  CKR_FUNCTION_FAILED;
		}
	}
done:
	if (buffer)
		free(buffer);
	return rc;
}

CK_RV token_specific_hmac_sign_update(STDLL_TokData_t *tokdata, SESSION *sess,
				      CK_BYTE *in_data, CK_ULONG in_data_len)
{
	return ccatok_hmac_update(tokdata, &sess->sign_ctx, in_data,
				  in_data_len, TRUE);
}

CK_RV token_specific_hmac_verify_update(STDLL_TokData_t *tokdata, SESSION *sess,
					CK_BYTE *in_data, CK_ULONG in_data_len)
{
	return ccatok_hmac_update(tokdata, &sess->verify_ctx, in_data,
				  in_data_len, FALSE);
}

CK_RV ccatok_hmac_final(STDLL_TokData_t *tokdata, SIGN_VERIFY_CONTEXT *ctx,
			CK_BYTE *signature, CK_ULONG *sig_len, CK_BBOOL sign)
{
	struct cca_sha_ctx *cca_ctx;
	long return_code, reason_code, rule_array_count = 3;
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
	OBJECT *key = NULL;
	CK_ATTRIBUTE *attr = NULL;
	CK_RV rc = CKR_OK;

	if (!ctx || !ctx->context) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	rc = object_mgr_find_in_map1(ctx->key, &key);
	if (rc != CKR_OK) {
		TRACE_ERROR("Failed to find specified object.\n");
		return rc;
	}

	if (template_attribute_find(key->template, CKA_IBM_OPAQUE,
				    &attr) == FALSE) {
		TRACE_ERROR("Could not find CKA_IBM_OPAQUE for the key.\n");
		return CKR_FUNCTION_FAILED;
	}

	cca_ctx = (struct cca_sha_ctx *)ctx->context;

	switch(ctx->mech.mechanism) {
	case CKM_SHA_1_HMAC:
	case CKM_SHA_1_HMAC_GENERAL:
		memcpy(rule_array, "HMAC    SHA-1   ", CCA_KEYWORD_SIZE * 2);
                break;
	case CKM_SHA256_HMAC:
	case CKM_SHA256_HMAC_GENERAL:
		memcpy(rule_array, "HMAC    SHA-256 ", CCA_KEYWORD_SIZE * 2);
		break;
	case CKM_SHA384_HMAC:
	case CKM_SHA384_HMAC_GENERAL:
		memcpy(rule_array, "HMAC    SHA-384 ", CCA_KEYWORD_SIZE * 2);
                break;
	case CKM_SHA512_HMAC:
	case CKM_SHA512_HMAC_GENERAL:
		memcpy(rule_array, "HMAC    SHA-512 ", CCA_KEYWORD_SIZE * 2);
                break;
	default:
		return CKR_MECHANISM_INVALID;
        }

	if (cca_ctx->part == CCA_HASH_PART_FIRST)
		memcpy(rule_array + (CCA_KEYWORD_SIZE*2), "ONLY    ",
		       CCA_KEYWORD_SIZE);
	else
		memcpy(rule_array + (CCA_KEYWORD_SIZE*2), "LAST    ",
		       CCA_KEYWORD_SIZE);

	TRACE_INFO("CSNBHMG: key length is %lu\n", attr->ulValueLen);
	TRACE_INFO("The mac length is %ld\n", cca_ctx->hash_len);

	if (sign) {
		dll_CSNBHMG(&return_code, &reason_code, NULL, NULL,
			&rule_array_count, rule_array, &attr->ulValueLen,
			attr->pValue, &cca_ctx->tail_len, cca_ctx->tail,
			&cca_ctx->chain_vector_len, cca_ctx->chain_vector,
			&cca_ctx->hash_len, cca_ctx->hash);

		if (return_code != CCA_SUCCESS) {
			TRACE_ERROR("CSNBHMG (HMAC SIGN FINAL) failed. "
				    "return:%ld, reason:%ld\n", return_code,
				     reason_code);
			*sig_len = 0;
			return CKR_FUNCTION_FAILED;
		}
		/* Copy the signature into the user supplied variable.
		 * For hmac general mechs, only copy over the specified
		 * number of bytes for the mac.
		 */
		memcpy(signature, cca_ctx->hash, cca_ctx->hash_len);
		*sig_len = cca_ctx->hash_len;

	} else {		// verify
		dll_CSNBHMV(&return_code, &reason_code, NULL, NULL,
			&rule_array_count,rule_array, &attr->ulValueLen,
			attr->pValue, &cca_ctx->tail_len, cca_ctx->tail,
			&cca_ctx->chain_vector_len, cca_ctx->chain_vector,
			&cca_ctx->hash_len, signature);

		if (return_code == 4 && (reason_code == 429 ||
		    reason_code == 1)) {
			TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
			return CKR_SIGNATURE_INVALID;
		} else if (return_code != CCA_SUCCESS) {
			TRACE_ERROR("CSNBHMV (HMAC VERIFY) failed. return:%ld,"
				    " reason:%ld\n", return_code, reason_code);
			return CKR_FUNCTION_FAILED;
		} else if (reason_code != 0) {
			TRACE_WARNING("CSNBHMV (HMAC VERIFY) succeeded, but"
				      " returned reason:%ld\n", reason_code);
		}

	}

	return CKR_OK;
}

CK_RV token_specific_hmac_sign_final(STDLL_TokData_t *tokdata, SESSION *sess,
				     CK_BYTE *signature, CK_ULONG *sig_len)
{
	return ccatok_hmac_final(tokdata, &sess->sign_ctx, signature, sig_len,
				 TRUE);
}

CK_RV token_specific_hmac_verify_final(STDLL_TokData_t *tokdata, SESSION *sess,
				       CK_BYTE *signature, CK_ULONG sig_len)
{
	return ccatok_hmac_final(tokdata, &sess->verify_ctx, signature,
				 &sig_len, FALSE);
}

static CK_RV rsa_import_privkey_crt(TEMPLATE *priv_tmpl)
{
	long return_code, reason_code, rule_array_count, total = 0;
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };

	long offset, key_value_structure_length = CCA_KEY_VALUE_STRUCT_SIZE;
	long private_key_name_length, key_token_length,
	target_key_token_length;

	unsigned char key_value_structure[CCA_KEY_VALUE_STRUCT_SIZE] = { 0, };
	unsigned char private_key_name[CCA_PRIVATE_KEY_NAME_SIZE] = { 0, };
	unsigned char key_token[CCA_KEY_TOKEN_SIZE] = { 0, };
	unsigned char target_key_token[CCA_KEY_TOKEN_SIZE] = { 0, };
	unsigned char transport_key_identifier[CCA_KEY_ID_SIZE] = { 0, };

	uint16_t size_of_e;
	uint16_t mod_bits, mod_bytes, bytes;
	CK_ATTRIBUTE *opaque_key = NULL, *pub_exp = NULL, *mod = NULL,
	*p_prime=NULL, *q_prime=NULL, *dmp1=NULL, *dmq1=NULL, *iqmp=NULL;
	CK_RV rc;

	/* Look for parameters to set key in the CRT format */
	if (!template_attribute_find(priv_tmpl, CKA_PRIME_1, &p_prime)) {
		TRACE_ERROR("CKA_PRIME_1 attribute missing for CRT.\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}
	total += p_prime->ulValueLen;

	if (!template_attribute_find(priv_tmpl, CKA_PRIME_2, &q_prime)) {
		TRACE_ERROR("CKA_PRIME_2 attribute missing for CRT.\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}
	total += q_prime->ulValueLen;

	if (!template_attribute_find(priv_tmpl, CKA_EXPONENT_1, &dmp1)) {
		TRACE_ERROR("CKA_EXPONENT_1 attribute missing for CRT.\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}
	total += dmp1->ulValueLen;

	if (!template_attribute_find(priv_tmpl, CKA_EXPONENT_2, &dmq1)) {
		TRACE_ERROR("CKA_EXPONENT_2 attribute missing for CRT.\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}
	total += dmq1->ulValueLen;

	if (!template_attribute_find(priv_tmpl, CKA_COEFFICIENT, &iqmp)) {
		TRACE_ERROR("CKA_COEFFICIENT attribute missing for CRT.\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}
	total += iqmp->ulValueLen;

	if (!template_attribute_find(priv_tmpl, CKA_PUBLIC_EXPONENT, &pub_exp)) {
		TRACE_ERROR("CKA_PUBLIC_EXPONENT attribute missing for CRT.\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}
	total += pub_exp->ulValueLen;

	if (!template_attribute_find(priv_tmpl, CKA_MODULUS, &mod)) {
		TRACE_ERROR("CKA_MODULUS attribute missing for CRT.\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}
	total += mod->ulValueLen;

	/* check total length does not exceed key_value_structure_length */
	if ((total + 18) > key_value_structure_length) {
		TRACE_ERROR("total length of key exceeds CCA_KEY_VALUE_STRUCT_SIZE.\n");
		return CKR_KEY_SIZE_RANGE;
	}

	/* Build key token for RSA-PRIV format.
	 * Fields according to Table 9.
	 * PKA_Key_Token_Build key-values-structure
	 */

	memset(key_value_structure, 0, key_value_structure_length);

	/* Field #1 - Length of modulus in bits */
	mod_bits = htons(mod->ulValueLen * 8);
	memcpy(&key_value_structure[0], &mod_bits, sizeof(uint16_t));

	/* Field #2 - Length of modulus field in bytes */
	mod_bytes = htons(mod->ulValueLen);
	memcpy(&key_value_structure[2], &mod_bytes, sizeof(uint16_t));

	/* Field #3 - Length of public exponent field in bytes */
	size_of_e = htons(pub_exp->ulValueLen);
	memcpy(&key_value_structure[4], &size_of_e, sizeof(uint16_t));

	/* Field #4 - Reserved, binary zero, two bytes */

	/* Field #5 - Length of prime P */
	bytes = htons(p_prime->ulValueLen);
	memcpy(&key_value_structure[8], &bytes, sizeof(uint16_t));

	/* Field #6 - Length of prime Q */
	bytes = htons(q_prime->ulValueLen);
	memcpy(&key_value_structure[10], &bytes, sizeof(uint16_t));

	/* Field #7 - Length of dp in bytes */
	bytes = htons(dmp1->ulValueLen);
	memcpy(&key_value_structure[12], &bytes, sizeof(uint16_t));

	/* Field #8 - Length of dq in bytes */
	bytes = htons(dmq1->ulValueLen);
	memcpy(&key_value_structure[14], &bytes, sizeof(uint16_t));

	/* Field #9 - Length of U in bytes */
	bytes = htons(iqmp->ulValueLen);
	memcpy(&key_value_structure[16], &bytes, sizeof(uint16_t));

	/* Field #10 - Modulus */
	memcpy(&key_value_structure[18], mod->pValue, mod_bytes);

	offset = 18 + mod_bytes;

	/* Field #11 - Public Exponent */
	memcpy(&key_value_structure[offset],
		pub_exp->pValue, pub_exp->ulValueLen);

	offset += pub_exp->ulValueLen;

	/* Field #12 - Prime numer, p */
	memcpy(&key_value_structure[offset],
		p_prime->pValue, p_prime->ulValueLen);

	offset += p_prime->ulValueLen;

	/* Field #13 - Prime numer, q */
	memcpy(&key_value_structure[offset],
		q_prime->pValue, q_prime->ulValueLen);

	offset += q_prime->ulValueLen;

	/* Field #14 - dp = dmod(p-1) */
	memcpy(&key_value_structure[offset],
		dmp1->pValue, dmp1->ulValueLen);

	offset += dmp1->ulValueLen;

	/* Field #15 - dq = dmod(q-1) */
	memcpy(&key_value_structure[offset],
		dmq1->pValue, dmq1->ulValueLen);

	offset += dmq1->ulValueLen;

	/* Field #16 - U = (q^-1)mod(p)  */
	memcpy(&key_value_structure[offset],
		iqmp->pValue, iqmp->ulValueLen);

	/* Now build a key token with the imported public key */

	rule_array_count = 2;
	memcpy(rule_array, "RSA-CRT KEY-MGMT", (size_t)(CCA_KEYWORD_SIZE * 2));

	private_key_name_length = 0;

	key_token_length = CCA_KEY_TOKEN_SIZE;

	dll_CSNDPKB(&return_code, &reason_code, NULL, NULL, &rule_array_count,
		rule_array, &key_value_structure_length, key_value_structure,
		&private_key_name_length, private_key_name, 0, NULL, 0, NULL,
		0, NULL, 0, NULL, 0, NULL, &key_token_length, key_token);

	if (return_code != CCA_SUCCESS) {
		TRACE_ERROR("CSNDPKB (RSA KEY TOKEN BUILD RSA CRT) failed."
			    " return:%ld, reason:%ld\n",
			    return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	}

	/* Now import the PKA key token */
	rule_array_count = 0;
	/* memcpy(rule_array, "        ", (size_t)(CCA_KEYWORD_SIZE * 1)); */

	target_key_token_length = CCA_KEY_TOKEN_SIZE;

	key_token_length = CCA_KEY_TOKEN_SIZE;

	dll_CSNDPKI(&return_code, &reason_code, NULL, NULL, &rule_array_count,
		rule_array, &key_token_length, key_token,
		transport_key_identifier, &target_key_token_length,
		target_key_token);

	if (return_code != CCA_SUCCESS) {
		TRACE_ERROR("CSNDPKI (RSA KEY TOKEN IMPORT) failed."
			    " return:%ld, reason:%ld\n",
			    return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	}

	/* Add the key object to the template */
	if ((rc = build_attribute(CKA_IBM_OPAQUE, target_key_token,
				  target_key_token_length, &opaque_key))) {
		TRACE_DEVEL("build_attribute failed\n");
		return rc;
	}
	rc = template_update_attribute(priv_tmpl, opaque_key);
	if (rc != CKR_OK) {
		TRACE_DEVEL("template_update_attribute failed\n");
		return rc;
	}

	return CKR_OK;
}

static CK_RV rsa_import_pubkey(TEMPLATE *publ_tmpl)
{
	long return_code, reason_code, rule_array_count;
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };

	long key_value_structure_length = CCA_KEY_VALUE_STRUCT_SIZE;
	long private_key_name_length, key_token_length;
	unsigned char key_value_structure[CCA_KEY_VALUE_STRUCT_SIZE] = { 0, };
	unsigned char private_key_name[CCA_PRIVATE_KEY_NAME_SIZE] = { 0, };
	unsigned char key_token[CCA_KEY_TOKEN_SIZE] = { 0, };

	uint16_t size_of_e;
	uint16_t mod_bits, mod_bytes;
	CK_ATTRIBUTE *opaque_key = NULL, *pub_exp = NULL;
	CK_ATTRIBUTE *pub_mod = NULL, *attr = NULL;
	CK_RV rc;

	/* check that modulus and public exponent are available */
	if (!template_attribute_find(publ_tmpl, CKA_PUBLIC_EXPONENT, &pub_exp)){
		TRACE_ERROR("CKA_PUBLIC_EXPONENT attribute missing.\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	if (!template_attribute_find(publ_tmpl, CKA_MODULUS, &pub_mod)) {
		TRACE_ERROR("CKA_MODULUS attribute missing.\n" );
		return CKR_TEMPLATE_INCOMPLETE;
	}

	if (!template_attribute_find(publ_tmpl, CKA_MODULUS_BITS, &attr)) {
		TRACE_ERROR("CKA_MODULUS_BITS attribute missing.\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	/* check total length does not exceed key_value_structure_length */
	if ((pub_mod->ulValueLen + 8) > key_value_structure_length) {
		TRACE_ERROR("total length of key exceeds CCA_KEY_VALUE_STRUCT_SIZE.\n");
		return CKR_KEY_SIZE_RANGE;
	}

	/* In case the application hasn't filled it */
	if (*(CK_ULONG *)attr->pValue == 0)
		mod_bits = htons(pub_mod->ulValueLen * 8);
	else
		mod_bits = htons(*(CK_ULONG *)attr->pValue);

	/* Build key token for RSA-PUBL format */
	memset(key_value_structure, 0, key_value_structure_length);

	/* Fields according to Table 9.
	 * PKA_Key_Token_Build key-values-structure
	 */

	/* Field #1 - Length of modulus in bits */
	memcpy(&key_value_structure[0], &mod_bits, sizeof(uint16_t));

	/* Field #2 - Length of modulus field in bytes */
	mod_bytes = htons(pub_mod->ulValueLen);
	memcpy(&key_value_structure[2], &mod_bytes, sizeof(uint16_t));

	/* Field #3 - Length of public exponent field in bytes */
	size_of_e = htons((uint16_t)pub_exp->ulValueLen);
	memcpy(&key_value_structure[4], &size_of_e, sizeof(uint16_t));

	/* Field #4 - private key exponent length; skip */

	/* Field #5 - Modulus */
	memcpy(&key_value_structure[8], pub_mod->pValue,
		(size_t)pub_mod->ulValueLen);

	/* Field #6 - Public exponent. Its offset depends on modulus size */
	memcpy(&key_value_structure[8 + mod_bytes],
		pub_exp->pValue, (size_t)pub_exp->ulValueLen);

	/* Field #7 - Private exponent. Skip */

	rule_array_count = 1;
	memcpy(rule_array, "RSA-PUBL", (size_t)(CCA_KEYWORD_SIZE * 1));

	private_key_name_length = 0;

	key_token_length = CCA_KEY_TOKEN_SIZE;

	// Create a key token for the public key.
	// Public keys do not need to be wrapped, so just call PKB.
	dll_CSNDPKB(&return_code, &reason_code, NULL, NULL, &rule_array_count,
		rule_array, &key_value_structure_length, key_value_structure,
		&private_key_name_length, private_key_name, 0, NULL, 0,
		NULL, 0, NULL, 0, NULL, 0, NULL, &key_token_length, key_token);

	if (return_code != CCA_SUCCESS) {
		TRACE_ERROR("CSNDPKB (RSA KEY TOKEN BUILD RSA-PUBL) failed."
			    " return:%ld, reason:%ld\n",
			    return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	}

	// Add the key object to the template.
	if ((rc = build_attribute(CKA_IBM_OPAQUE, key_token, key_token_length,
				  &opaque_key))) {
		TRACE_DEVEL("build_attribute failed\n");
		return rc;
	}

	rc = template_update_attribute(publ_tmpl, opaque_key);
	if (rc != CKR_OK) {
		TRACE_DEVEL("template_update_attribute failed\n");
		return rc;
	}

	return CKR_OK;
}

static CK_RV import_symmetric_key(OBJECT *object, CK_ULONG keytype)
{
	CK_RV rc;
	long return_code, reason_code, rule_array_count;
	unsigned char target_key_id[CCA_KEY_ID_SIZE] = { 0 };
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0 };
	CK_ATTRIBUTE *opaque_key = NULL;
	CK_ATTRIBUTE *attr = NULL;

	rc = template_attribute_find(object->template, CKA_VALUE, &attr);
	if (rc == FALSE) {
		TRACE_ERROR("Incomplete key template\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	switch(keytype) {
	case CKK_AES:
		memcpy(rule_array, "AES     ", CCA_KEYWORD_SIZE);
		break;
	case CKK_DES:
	case CKK_DES3:
		memcpy(rule_array, "DES     ", CCA_KEYWORD_SIZE);
		break;
	default:
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
	}

	rule_array_count = 1;

	dll_CSNBCKM(&return_code, &reason_code, NULL, NULL, &rule_array_count,
		rule_array, &attr->ulValueLen, attr->pValue, target_key_id);

	if (return_code != CCA_SUCCESS) {
		TRACE_ERROR("CSNBCKM failed. return:%ld, reason:%ld\n",
			     return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	}

	/* Add the key object to the template */
	if ((rc = build_attribute(CKA_IBM_OPAQUE, target_key_id,
				  CCA_KEY_ID_SIZE, &opaque_key))) {
		TRACE_DEVEL("build_attribute(CKA_IBM_OPAQUE) failed\n");
		return rc;
	}
	rc = template_update_attribute(object->template, opaque_key);
	if (rc != CKR_OK) {
		TRACE_DEVEL("template_update_attribute(CKA_IBM_OPAQUE) failed\n");
		return rc;
	}

	/* zero clear key value */
	memset(attr->pValue, 0, attr->ulValueLen);

	return CKR_OK;
}


static CK_RV import_generic_secret_key(OBJECT *object)
{
	CK_RV rc;
	long return_code, reason_code, rule_array_count;
	unsigned char key_token[CCA_KEY_TOKEN_SIZE] = { 0 };
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0 };
	long key_name_len = 0, clr_key_len = 0;
	long user_data_len = 0, key_part_len = 0;
	long token_data_len = 0, verb_data_len = 0;
	long key_token_len = sizeof(key_token);
	CK_ATTRIBUTE *opaque_key = NULL;
	CK_ATTRIBUTE *attr = NULL;
	CK_ULONG keylen;

	rc = template_attribute_find(object->template, CKA_VALUE, &attr);
	if (rc == FALSE) {
		TRACE_ERROR("Incomplete Generic Secret (HMAC) key template\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}
	keylen = attr->ulValueLen;
	/* key len needs to be 80-2048 bits */
	if (8*keylen < 80 || 8*keylen > 2048) {
		TRACE_ERROR("HMAC key size of %lu bits not within"
			    " CCA required range of 80-2048 bits\n", 8*keylen);
		return CKR_KEY_SIZE_RANGE;
	}

	memcpy(rule_array, "INTERNALNO-KEY  HMAC    MAC     GENERATE",
	       5 * CCA_KEYWORD_SIZE);
	 rule_array_count = 5;

	dll_CSNBKTB2(&return_code, &reason_code, NULL, NULL, &rule_array_count,
		 rule_array, &clr_key_len, NULL, &key_name_len, NULL,
		 &user_data_len, NULL, &token_data_len, NULL, &verb_data_len,
		 NULL, &key_token_len, key_token);
	if (return_code != CCA_SUCCESS) {
		TRACE_ERROR("CSNBKTB2 (HMAC KEY TOKEN BUILD) failed."
			    " return:%ld, reason:%ld\n",
			    return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	}

	memcpy(rule_array, "HMAC    FIRST   MIN1PART", 3 * CCA_KEYWORD_SIZE);
	rule_array_count = 3;
	key_part_len = keylen * 8;
	key_token_len = sizeof(key_token);

	dll_CSNBKPI2(&return_code, &reason_code, NULL, NULL, &rule_array_count,
		 rule_array, &key_part_len, attr->pValue, &key_token_len,
		 key_token);
	if (return_code != CCA_SUCCESS) {
		TRACE_ERROR("CSNBKPI2 (HMAC KEY IMPORT FIRST) failed."
			    " return:%ld, reason:%ld\n",
			    return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	}

	memcpy(rule_array, "HMAC    COMPLETE", 2 * CCA_KEYWORD_SIZE);
	rule_array_count = 2;
	key_part_len = 0;
	key_token_len = sizeof(key_token);

	dll_CSNBKPI2(&return_code, &reason_code, NULL, NULL, &rule_array_count,
		 rule_array, &key_part_len, NULL, &key_token_len, key_token);
	if (return_code != CCA_SUCCESS) {
		TRACE_ERROR("CSNBKPI2 (HMAC KEY IMPORT COMPLETE) failed."
			    " return:%ld, reason:%ld\n",
			    return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	}

	/* Add the key object to the template */
	if ((rc = build_attribute(CKA_IBM_OPAQUE, key_token, key_token_len,
				  &opaque_key))) {
		TRACE_DEVEL("build_attribute(CKA_IBM_OPAQUE) failed\n");
		return rc;
	}
	rc = template_update_attribute(object->template, opaque_key);
	if (rc != CKR_OK) {
		TRACE_DEVEL("template_update_attribute(CKA_IBM_OPAQUE) failed\n");
		return rc;
	}

	/* zero clear key value */
	memset(attr->pValue, 0, attr->ulValueLen);

	return CKR_OK;
}

CK_RV token_specific_object_add(STDLL_TokData_t *tokdata, OBJECT *object)
{

	CK_RV rc;
	CK_ATTRIBUTE *attr = NULL;
	CK_KEY_TYPE keytype;
	CK_OBJECT_CLASS keyclass;

	if (!object) {
		TRACE_ERROR("Invalid argument\n");
		return CKR_FUNCTION_FAILED;
	}

	rc = template_attribute_find(object->template, CKA_KEY_TYPE, &attr);
	if (rc == FALSE) {
		// not a key, so nothing to do. Just return.
		TRACE_DEVEL("object not a key, no need to import.\n");
		return CKR_OK;
	}

	keytype = *(CK_KEY_TYPE *)attr->pValue;

	switch (keytype) {
	case CKK_RSA:
		rc = template_attribute_find(object->template, CKA_CLASS, &attr);
		if (rc == FALSE) {
			TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
			return CKR_TEMPLATE_INCOMPLETE;
		} else
			keyclass = *(CK_OBJECT_CLASS *)attr->pValue;

		switch(keyclass) {
		case CKO_PUBLIC_KEY:
			// do import public key and create opaque object
			rc = rsa_import_pubkey(object->template);
			break;

		case CKO_PRIVATE_KEY:
			// do import keypair and create opaque object
			rc = rsa_import_privkey_crt(object->template);
			break;

		default:
			TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
			return CKR_KEY_TYPE_INCONSISTENT;
		}

		if (rc != CKR_OK) {
			TRACE_DEVEL("rsa import failed\n");
			return rc;
		}

		break;

	case CKK_AES:
	case CKK_DES:
	case CKK_DES3:
		rc = import_symmetric_key(object, keytype);
		if (rc != CKR_OK) {
			TRACE_DEVEL("Symmetric key import failed, rc=0x%lx\n",
				     rc);
			return CKR_FUNCTION_FAILED;
		}
		TRACE_INFO("symmetric key with len=%ld successful imported\n",
			    attr->ulValueLen);
		break;

	case CKK_GENERIC_SECRET:
		rc = import_generic_secret_key(object);
		if (rc != CKR_OK) {
			TRACE_DEVEL("Generic Secret (HMAC) key import failed "
				    " with rc=0x%lx\n", rc);
			return CKR_FUNCTION_FAILED;
		}
		TRACE_INFO("Generic Secret (HMAC) key with len=%ld successfully"
			   " imported\n", attr->ulValueLen);
		break;

	default:
		/* unknown/unsupported key type */
		TRACE_ERROR("Unknown/unsupported key type 0x%lx\n", keytype);
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
	}

	return CKR_OK;
}

CK_RV token_specific_generic_secret_key_gen (STDLL_TokData_t *tokdata,
					     TEMPLATE *template)
{
	CK_RV rc;
	long return_code, reason_code, rule_array_count;
	long zero_length = 0;
	long key_name_length = 0, clear_key_length = 0, user_data_length = 0;
	CK_ATTRIBUTE *opaque_key = NULL;
	CK_ATTRIBUTE *attr = NULL;
	CK_ULONG keylength = 0;
	unsigned char key_type1[8] = {0};
	unsigned char key_type2[8] = {0};
	unsigned char key_token[CCA_KEY_TOKEN_SIZE] = { 0 };
	long key_token_length = sizeof(key_token);
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0 };

	rc = template_attribute_find(template, CKA_VALUE_LEN, &attr);
	if (rc == FALSE) {
		TRACE_ERROR("Incomplete Generic Secret (HMAC) key template\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	keylength = *(CK_ULONG *)attr->pValue;

	/* HMAC key length needs to be 80-2048 bits */
	if (((8*keylength) < 80) || ((8*keylength) > 2048)) {
		TRACE_ERROR("HMAC key size of %lu bits not within CCA required "
			    "range of 80-2048 bits\n", 8*keylength);
		return CKR_KEY_SIZE_RANGE;
	}

	rule_array_count = 4;
	memcpy(rule_array, "INTERNALHMAC    MAC     GENERATE",
	       4 * CCA_KEYWORD_SIZE);

	dll_CSNBKTB2(&return_code, &reason_code, NULL, NULL, &rule_array_count,
		 rule_array, &clear_key_length, NULL, &key_name_length,
		 NULL, &user_data_length, NULL, &zero_length, NULL,
		 &zero_length, NULL, &key_token_length, key_token);

	if (return_code != CCA_SUCCESS) {
		TRACE_ERROR("CSNBKTB2 (HMAC KEY TOKEN BUILD) failed."
			    " return:%ld, reason:%ld\n",
			    return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	}

	/** generate the hmac key here **/
	/* reset some values usually previously */
	rule_array_count = 2;
	memset(rule_array, 0, sizeof(rule_array));

	key_token_length = sizeof(key_token);

	/* create rule_array with 2 keywords */
	memcpy(rule_array, "HMAC    OP      ", 2 * CCA_KEYWORD_SIZE);

	/* ask to create the hmac key with application
	 * specified key length in bits
	 */
	clear_key_length = keylength * 8;
	memcpy(key_type1, "TOKEN   ", CCA_KEYWORD_SIZE);

        /* for only one copy of key generated, specify 8 spaces in
	 * key_type2 per CCA basic services guide
	 */
	memcpy(key_type2, "        ", CCA_KEYWORD_SIZE);

	dll_CSNBKGN2(&return_code, &reason_code, &zero_length, NULL,
		 &rule_array_count, rule_array, &clear_key_length, key_type1,
		 key_type2, &key_name_length, NULL, &key_name_length, NULL,
		 &user_data_length, NULL, &user_data_length, NULL, &zero_length,
		 NULL, &zero_length, NULL, &key_token_length, key_token,
		 &zero_length, NULL);

	if (return_code != CCA_SUCCESS) {
		TRACE_ERROR("CSNBKGN2 (HMAC KEY GENERATE) failed."
			    " return:%ld, reason:%ld\n",
			    return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	}

	/* Add the key object to the template */
	rc = build_attribute(CKA_IBM_OPAQUE, key_token, key_token_length,
			     &opaque_key);
	if (rc != CKR_OK) {
		TRACE_DEVEL("build_attribute(CKA_IBM_OPAQUE) failed\n");
		return rc;
	}

	rc = template_update_attribute(template, opaque_key);
	if (rc != CKR_OK) {
		TRACE_DEVEL("template_update_attribute(CKA_IBM_OPAQUE) failed.\n");
		return rc;
	}

	return CKR_OK;
}
