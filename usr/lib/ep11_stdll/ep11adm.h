/*
 * (C) Copyright IBM Corp. 2012, 2024
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 *
 *----------------------------------------------------------------------
 *  EP11 service mail address: EP11SERV@de.ibm.com
 *
 *  Use this mail address for Bugs and Comments with the EP11 product.
 *----------------------------------------------------------------------
 */

#if ! defined(__xcpadm_h__)
#define __xcpadm_h__

#if !defined(INT64_MIN)
#error "We need 32/64-bit <stdint.h> types, please include before this file."
#endif

#if !defined(XCP_SERIALNR_CHARS)
#error "We need <ep11.h> types, please include before this file."
#endif


//-------------------------------------
// flags common to all functions that have a flag parameter
//
#define  XCP_ADMFL_DOMAIN     1   // query/command targets domain not full card
#define  XCP_ADMFL_FORCE   0x80   // force an action otherwise canceled

//-------------------------------------
// error codes returned by administrative functions
// for common error codes see the XCP_E* defines in ep11.h
// if not noted otherwise a function returns XCP_OK for successfully completion
// see the header of the functions for more details about the errors
//
// generic administrative errors
#define  XCP_ADMERR_MIN                      ((long)(1UL<<(sizeof(long)*8-1)))
                                       /* all error codes > XCP_ADMERR_MIN. */
#define  XCP_ADMERR_QUERY_FAILED             (XCP_ADMERR_MIN+0x101)
#define  XCP_ADMERR_NOT_ENOUGH_SIGNATURES    (XCP_ADMERR_MIN+0x102)
#define  XCP_ADMERR_SIGNING_CB_FAILED        (XCP_ADMERR_MIN+0x103)
#define  XCP_ADMERR_COMMAND_FAILED           (XCP_ADMERR_MIN+0x104)
#define  XCP_ADMERR_CARD_CPS_QUERY           (XCP_ADMERR_MIN+0x105)
#define  XCP_ADMERR_CMD_UNEXPECTED_RV        (XCP_ADMERR_MIN+0x106)
#define  XCP_ADMERR_COMPLIANCE_MODE_CONFLICT (XCP_ADMERR_MIN+0x107)
#define  XCP_ADMERR_NEEDS_FORCE              (XCP_ADMERR_MIN+0x108)
#define  XCP_ADMERR_CTR_SIZE_INVALID         (XCP_ADMERR_MIN+0x109)
// signerinfo related errors
#define  XCP_ADMERR_SI_HSH_MECH_UNSUPPORTED  (XCP_ADMERR_MIN+0x151)
#define  XCP_ADMERR_SI_SIG_MECH_UNSUPPORTED  (XCP_ADMERR_MIN+0x152)
#define  XCP_ADMERR_SI_OID_MECH_MISMATCH     (XCP_ADMERR_MIN+0x153)
#define  XCP_ADMERR_SI_SIG_EMPTY             (XCP_ADMERR_MIN+0x154)
#define  XCP_ADMERR_SI_SIZE                  (XCP_ADMERR_MIN+0x155)
// recipientinfo related errors
#define  XCP_ADMERR_RI_ENC_EMPTY             (XCP_ADMERR_MIN+0x181)
#define  XCP_ADMERR_RI_UKM_INVALID           (XCP_ADMERR_MIN+0x182)
#define  XCP_ADMERR_RI_IMPR_INVALID          (XCP_ADMERR_MIN+0x183)
#define  XCP_ADMERR_RI_RSA_ALG_INVALID       (XCP_ADMERR_MIN+0x184)
#define  XCP_ADMERR_RI_KWRAPSIZE_INVALID     (XCP_ADMERR_MIN+0x185)
#define  XCP_ADMERR_RI_ECPUB_INVALID         (XCP_ADMERR_MIN+0x186)
#define  XCP_ADMERR_RI_SKI_INVALID           (XCP_ADMERR_MIN+0x187)
#define  XCP_ADMERR_RI_RSA_OID_INVALID       (XCP_ADMERR_MIN+0x188)
#define  XCP_ADMERR_RI_EC_OID_INVALID        (XCP_ADMERR_MIN+0x189)
#define  XCP_ADMERR_RI_VERSION_INVALID       (XCP_ADMERR_MIN+0x18a)
#define  XCP_ADMERR_RI_KWRAPALG_INVALID      (XCP_ADMERR_MIN+0x18b)


#define  DOMAIN_MASK_LENGTH XCP_DOMAINS/8 // space for 256 domains

//-------------------------------------
// Key-Part-Holder template
// contain credentials of a key-part holder. Those credentials
// can be file based and/or smart card based references.
struct KPH {
	const unsigned char *cert;        // certificate
	size_t              clen;         // certificate length
	const char          *id;          // private key
	const char          *pw;          // private key passphrase
	const char          *kpfname;     // filename of the key-part
	char                scard;        // indicates a smart card user
	char                ski_id;       // subject key identifier ID
	int                 rdr_id;       // smart card reader number
	char                kp_id;        // key-part ID
	uint64_t            sigmech;      // signature mechenism
	const char          *padmode;     // padding mode
} ;


//-------------------------------------
// Export WK Request template (including preamble for import state command)
//
// requesting 2-of-n keyparts
//
// append n certificate sections and load with XCP_ADM_IMPORT_STATE command
// certificate sections are ASN.1 octet strings starting with a 2-Byte tag
// value of 0x1d followed by the four Byte certificate index followed by the
// certificate:
//   0x04,0x82,0x02,0x32,
//   0x00,0x1d,
//   0x00,0x00,0x00,0x01,
//   ...cert data...
//
static const unsigned char expreqhdr[] = {
	0x00,0x00,0x00,XCP_FILEID_EXPREQUEST,    /* export file id            */
	0x00,0x00,0x00,0x00,                     /* offset, 0 for full file   */
	0x00,0x00,0x00,0x00,                     /* length of part following  */
	0x30,0x82,0x00,0x00,
} ;


//-------------------------------------
// admin response structure
typedef struct XCPadmresp {
	uint32_t fn;
	uint32_t domain;
	uint32_t domainInst;

	/* module ID || module instance */
	unsigned char module[ XCP_SERIALNR_CHARS + XCP_SERIALNR_CHARS ];
	unsigned char   modNr[ XCP_SERIALNR_CHARS ];
	unsigned char modInst[ XCP_SERIALNR_CHARS ];

	unsigned char   tctr[ XCP_ADMCTR_BYTES ];     /* transaction counter */

	CK_RV rv;
	uint32_t reason;

	// points to original response; NULL if no payload
	// make sure it's copied if used after releasing response block
	//
	const unsigned char *payload;
	size_t pllen;
} *XCPadmresp_t;
//
#define  XCP_ADMRESP_INIT0  { 0,0,0, {0},{0},{0}, {0}, CKR_OK, 0, NULL,0, }


//-------------------------------------
// listing of CP modes with their respective sets of control points that are
// either required or prohibited
//
// the CPs that can never be turned on are not included in any compliance
// modes prohibited list (see XCP_CPB_ALG_RAW_RSA, XCP_CPB_KEYSZ_BELOW80BIT,
// XCP_CPB_KEYSZ_HMAC_ANY, XCP_CPB_SKIP_KEYTESTS and XCP_CPB_ALG_NBSI2009)
//
static const struct {
	uint32_t mode;
	const char *name;
	unsigned int num_prohibited;
	XCP_CPbit_t prohibited[ XCP_CPCOUNT ];
	unsigned int num_required;
	XCP_CPbit_t required[ XCP_CPCOUNT ];
} ep11_cpt_modes[] = {
	{ XCP_ADMS_FIPS2009, "fips2009",    // default mode, can't be left
		0,
		{                                                         },
		0,
		{                                                         },
	},
	{ XCP_ADMS_FIPS2011, "fips2011",
		3,
		{ XCP_CPB_ALG_NFIPS2011,      XCP_CPB_KEYSZ_80BIT,
		  XCP_CPB_KEYSZ_RSA65536,                                 },
		0,
		{                                                         },
	},
	{ XCP_ADMS_BSI2009, "bsi2009",
		2,
		{ XCP_CPB_ALG_NBSI2009,       XCP_CPB_NON_ATTRBOUND       },
		0,
		{                                                         },
	},
	{ XCP_ADMS_BSI2011, "bsi2011",
		3,
		{ XCP_CPB_ALG_NBSI2011,       XCP_CPB_NON_ATTRBOUND,
		  XCP_CPB_KEYSZ_80BIT                                     },
		0,
		{                                                         },
	},
	{ XCP_ADMS_BSICC2017, "bsicc2017",
		12,
		{ XCP_CPB_NON_ATTRBOUND,      XCP_CPB_RNG_SEED,
		  XCP_CPB_KEYSZ_RSA65536,     XCP_CPB_USER_SET_TRUSTED,
		  XCP_CPB_ALG_SKIP_CROSSCHK,  XCP_CPB_WRAP_CRYPT_KEYS,
		  XCP_CPB_SIGN_CRYPT_KEYS,    XCP_CPB_WRAP_SIGN_KEYS,
		  XCP_CPB_USER_SET_ATTRBOUND, XCP_CPB_ALLOW_PASSPHRASE,
		  XCP_CPB_WRAP_STRONGER_KEY,  XCP_CPB_WRAP_WITH_RAW_SPKI  },
		27,
		{ XCP_CPB_SIGN_ASYMM,         XCP_CPB_ENCRYPT_SYMM,
		  XCP_CPB_DECRYPT_ASYMM,      XCP_CPB_DECRYPT_SYMM,
		  XCP_CPB_WRAP_ASYMM,         XCP_CPB_WRAP_SYMM,
		  XCP_CPB_UNWRAP_ASYMM,       XCP_CPB_UNWRAP_SYMM,
		  XCP_CPB_KEYGEN_ASYMM,       XCP_CPB_KEYGEN_SYMM,
		  XCP_CPB_RETAINKEYS,         XCP_CPB_MODIFY_OBJECTS,
		  XCP_CPB_ALG_NBSI2009,       XCP_CPB_KEYSZ_80BIT,
		  XCP_CPB_KEYSZ_112BIT,       XCP_CPB_KEYSZ_128BIT,
		  XCP_CPB_KEYSZ_192BIT,       XCP_CPB_KEYSZ_256BIT,
		  XCP_CPB_ALG_RSA,            XCP_CPB_ALG_DSA,
		  XCP_CPB_ALG_EC,             XCP_CPB_ALG_EC_BPOOLCRV,
		  XCP_CPB_ALG_EC_NISTCRV,     XCP_CPB_ALG_NFIPS2011,
		  XCP_CPB_ALG_NBSI2011,       XCP_CPB_ALG_DH,
		  XCP_CPB_DERIVE                                          },
	},
	{ XCP_ADMS_FIPS2021, "fips2021",
		17,
		{ XCP_CPB_ALG_NFIPS2011,      XCP_CPB_KEYSZ_80BIT,
		  XCP_CPB_KEYSZ_RSA65536,
		  XCP_CPB_ALG_NFIPS2021,      XCP_CPB_ALG_EC_25519,
		  XCP_CPB_ALG_PQC,            XCP_CPB_BTC,
		  XCP_CPB_ECDSA_OTHER,        XCP_CPB_ALLOW_NONSESSION,
		  XCP_CPB_ALG_EC_SECGCRV,     XCP_CPB_ALG_EC_BPOOLCRV,
		  XCP_CPB_COMPAT_LEGACY_SHA3, XCP_CPB_DSA_PARAMETER_GEN,
		  XCP_CPB_WRAP_ASYMM,         XCP_CPB_UNWRAP_ASYMM,
		  XCP_CPB_ALLOW_LOGIN_PRE_F2021,
		  XCP_CPB_ALG_RSA_OAEP
		},
		0,
		{                                                         },
	},
	{ XCP_ADMS_FIPS2024, "fips2024",
		18,
		{ XCP_CPB_ALG_NFIPS2011,      XCP_CPB_KEYSZ_80BIT,
		  XCP_CPB_KEYSZ_RSA65536,
		  XCP_CPB_ALG_NFIPS2021,      XCP_CPB_ALG_EC_25519,
		  XCP_CPB_ALG_PQC,            XCP_CPB_BTC,
		  XCP_CPB_ECDSA_OTHER,        XCP_CPB_ALLOW_NONSESSION,
		  XCP_CPB_ALG_EC_SECGCRV,     XCP_CPB_ALG_EC_BPOOLCRV,
		  XCP_CPB_ALG_NFIPS2024,      XCP_CPB_COMPAT_LEGACY_SHA3,
		  XCP_CPB_DSA_PARAMETER_GEN,  XCP_CPB_WRAP_ASYMM,
		  XCP_CPB_UNWRAP_ASYMM,       XCP_CPB_ALLOW_LOGIN_PRE_F2021,
		  XCP_CPB_ALG_RSA_OAEP
		},
		0,
		{                                                         },
	// XCP_ADMC_ADM_FIPS2021 is not reported here as it is not set with
	// control points
	}
} ;

//-------------------------------------
// Structure to collect all relevant data for state export/import
//
// statefname:    file name of the serialized state data
// restrict_mode: restriction mode
// 		  set to 0 -> no restriction (complete state export)
// 		  set to 1 -> XCP_STDATA_DOMAIN (domain data only)
// 		  set to 2 -> XCP_STDATA_NONSENSITIVE (non sensitive data)
// domainmask:    mask of domains to export/import
//
struct STATESAVE {
	const char          *statefname;
	unsigned int        restrict_mode;
	unsigned char       domainmask[DOMAIN_MASK_LENGTH];
} ;


//-------------------------------------
// callback function prototype definition for library functions
// that have to send sign commands but are not fixed on how
// to generate the signatures
// they take two parameters:
//  1. a function pointer to the callback function
//  2. a void pointer to an arbitrary data structure that gets directly
//     pass through to the call back function in the signopts parm
//
// should return >0 if requested signatures generated successfully
//               =0    not enough signatures could be generated
//               <0    anything else fails
//
typedef long (*xcpa_admin_signs_cb_t)(unsigned char *sigs, size_t slen,
                                const unsigned char *data, size_t dlen,
                                         const void *signopts) ;


//-------------------------------------
// build a query block to (blk,blen), querying 'fn'
// (payload,plen) copied to query block if non-NULL
//
// *minf used for module ID and transaction counter
//       ignored for commands where those fields are ignored
//
// returns written bytecount; size query if blk is NULL
//         <0 if anything fails
//
// Possible error return codes:
//  XCP_ETARGET: a group target is supplied
//  XCP_ESIZE:   the payload is too big, the output buffer is too small or the
//               size of the query block can not be represented in a single
//               byte
//               This restriction will be lifted in the future if a need arises
//
long xcpa_queryblock(unsigned char *blk,     size_t blen,
                      unsigned int fn,     target_t domain,
               const unsigned char *payload, size_t plen) ;


//-------------------------------------
// build a query block to (blk,blen), querying 'fn'
// (payload,plen) copied to query block if non-NULL
//
// *minf used for module ID and transaction counter
//       ignored for commands where those fields are ignored
//
// returns written bytecount; size query if blk is NULL
//         <0 if anything fails
//
// Possible error return codes:
//  XCP_EARG:                    an argument is missing
//  XCP_ESIZE:                   the output buffer is too small
//  XCP_ADMERR_CTR_SIZE_INVALID: the transaction counter overflows
//
long xcpa_cmdblock(unsigned char *blk,     size_t blen,
                    unsigned int fn,
         const struct XCPadmresp *minf,
             const unsigned char *tctr,    /* XCP_ADMCTR_BYTES */
             const unsigned char *payload, size_t plen) ;


//-------------------------------------
// construct the DER encapsulation of cert replacement as follows (blk):
// SEQUENCE {
//     OCTET STRING ski
//     OCTET STRING cert
// }
//
// returns size of constructed sequence in success case.
//         <0 if anything fails
//
// Possible error return codes:
//  XCP_EARG:  an argument is missing
//  XCP_ESIZE: blen is not big enough
//
long xcpa_certreplace(unsigned char *blk, size_t blen,
                      const unsigned char *ski, size_t slen,
                      const unsigned char *cert, size_t clen) ;


//-------------------------------------
// Queries the current/next WK for the given target
//
// WK Hash is returned in (*wk, wlen) on success if wk is not NULL
//
// returns >0 (bytecount) if present
//          0 if valid but no current WK
//         <0 if anything failed
//
// Possible error return codes:
//  XCP_ERESPONSE:           the domain info request failed
//  XCP_ADMERR_QUERY_FAILED: the WK query failed
//  XCP_ESIZE:               the output buffer is too small
//
// Uses xcpa_queryblock() - See function header for possible return codes
//
long xcpa_query_wk(unsigned char *wk, size_t wlen, int type, target_t target) ;


//-------------------------------------
// get current module ID, transaction counter to *blk
// performs card or module query, depending on 'is_card'
//
// copies all fields except 'payload', which will be left NULL
//
// basic sanity check on 'target' with NULL blk (SNH if target is present)
//
// flags   e.g. domain or card, see XCP_ADMFL_... constants
//
// returns <0 if anything fails
//          0 otherwise
//
// Possible error return codes:
//  XCP_ERESPONSE:           outer return value is not CKR_OK.
//  XCP_ADMERR_QUERY_FAILED: inner return value indicated an error. See the
//                           reason code for more information.
//
// Uses xcpa_queryblock() - See function header for possible return codes
//
long xcpa_state(struct XCPadmresp *blk, target_t target, unsigned int flags) ;


//-------------------------------------
// gets current instance id for domain
//
// returns <0 if query failed
//          0 otherwise, setting *inst if non-NULL
//
// see xcpa_state() for possible error return values
//
long xcpa_dom_instance(uint32_t *inst, target_t target) ;


//-------------------------------------
// submit query/command block from (req,reqlen), optionally with signature/s
// verify that return value (internal or external) matches exprv
//
// returns >0 if (rsp1,rsp1len) has been written. returns response size
//          0 if size query (rsp1 is NULL) which was successful
//                 (setting *rsp1len) if expecting CKR_OK    OR
//                 if encountered expected error, and not returning results
//         <0 otherwise
//
// points non-NULL rb to response, within (rsp1, rsp1len) if successful
// non-NULL rv is updated to retrieved PKCS#11 result
//
// msg, rb, rv, (rsp2,rsp2len), (sigs,slen) are optional
// non-NULL msg is used for annotating debug messages (not viewable by
// customers)
// (rsp2,rsp2len) contains reason code if provided by backend
//
// Possible error return codes:
//  XCP_EARG:                     missing arguments
//  XCP_ADMERR_CMD_UNEXPECTED_RV: the outer/inner rv does not match the
//                                expected rv. see *rv for more information
//  XCP_EINVALID:                 transport error or invalid formated response
//                                (unexpected)
//
long xcpa_admin_call(unsigned char *rsp1, size_t *rsp1len,
                     unsigned char *rsp2, size_t *rsp2len,
               const unsigned char *req,  size_t reqlen,
               const unsigned char *sigs, size_t slen,
                          target_t target,
                        const char *msg,
                 struct XCPadmresp *rb,
                             CK_RV *rv,
                             CK_RV exprv) ;


//-------------------------------------
// flags >0 domain, otherwise card
//
// (*val) set to the requested integer attribute value
//
// returns  0 with the request int attr for the given target (card/domain)
//         <0 if something fails
//
// Possible error return codes:
//  XCP_EARG: bad arguments
//
// Uses xcpa_query_admin_attrs() - See function header for possible return codes
//
long xcpa_admin_attr(target_t target, unsigned int flags,
                XCP_AdmAttr_t attr,       uint32_t *val) ;


//-------------------------------------
// flags   e.g. domain or card, see XCP_ADMFL_... constants
//
// sets *mode to the operating mode of card/domain
//
// returns <0 if query failed
//          0 if still imprinting, setting *mode to full word
//         >0 if out of imprint mode, setting *mode to full word
//
// See for possible error return codes xcpa_query_admin_attrs()
//
long xcpa_admin_attr_mode (target_t target, unsigned int flags,
                           uint32_t *mode) ;


//-------------------------------------
// flags >0 domain, otherwise card
//
// Sets *perms to the permissions of card/domain
//
// returns <0 if query failed
//          0 if 1-sign not allowed,  setting *perms to full word
//         >0 if 1-sign     allowed,  setting *perms to full word
//
// See for possible error return codes xcpa_query_admin_attrs()
//
long xcpa_admin_attr_perms (target_t target, unsigned int flags,
                            uint32_t *perms) ;


//-------------------------------------
// if *val is non-NULL, and index 'idx' is found, *val is set to its value
//
// updates a32[] entries which are within bounds, ignoring others
//
// returns  0 with val and a32 set when non-NULL
//         <0 if something fails
//
// Possible error return codes:
//  XCP_EARG: attrs is NULL or alen is too small
//
long xcpa_report_attrs_field (const unsigned char *attrs,     size_t alen,
                                         uint32_t *a32, unsigned int acount,
                                         uint32_t idx,      uint32_t *val) ;


//-------------------------------------
// returns bytecount written to (attrs,alen), which is 8*attribute count
//         size query with NULL attrs, ignoring alen
//
// a32[] is updated if non-NULL and has sufficient entries;
// fails if a32 is non-NULL but acount is too low
// indexes interpreted as one-based (attr indexes intentionally skip 0),
// a32[] transformed back to zero-based representation
//
// *rb updated to current state, if non-NULL
//
// flags e.g. domain or card, see XCP_ADMFL_... constants
//
// Possible error return codes:
//  XCP_ADMERR_QUERY_FAILED: query failed (with reason code in *rb if non NULL)
//  XCP_EINVALID:            response from card could not be correctly parsed
//
// Uses xcpa_queryblock() - See function header for possible return codes
//
long xcpa_query_admin_attrs(target_t target,
                       unsigned char *attrs,     size_t alen,
                            uint32_t *a32, unsigned int acount,
                   struct XCPadmresp *rb,
                        unsigned int flags) ;


//-------------------------------------
// set attributes from pre-formated set-attr field in (attrs,alen)
//
// (*attrs,    attributes to set
//   alen)
// (sign_cb,   provide the callback for generating signatures,
//  signopts)  may be NULL if no signatures required,
//             see xcpl_admin_signs
// flags       e.g. domain or card, see XCP_ADMFL_... constants
// exprv       the expected return value to check for
//
// updates *rb if not NULL
//
// returns  0 on success (expected RV met)
//         <0 on failure
//
// Other possible return codes
//  XCP_ADMERR_SIGNING_CB_FAILED:     signing callback failed
//  XCP_ADMERR_NOT_ENOUGH_SIGNATURES: not enough signatures to fulfill
//                                    threshold value
//  XCP_ADMERR_CMD_UNEXPECTED_RV:     see reason code in *rb if non NULL
//
// uses xcpa_cmdblock() - see function header for more return codes
// uses xcpa_state() if rb is NULL, see the function for possible return codes
// uses xcpa_admin_call() - see function header for more return codes
//
// See rb->reason for the reason code in an error case.
//
long xcpa_set_admin_attrs(target_t target,
                     unsigned char *attrs, size_t alen,
                 struct XCPadmresp *rb,
                      unsigned int flags,
             xcpa_admin_signs_cb_t sign_cb, const void *signopts,
                             CK_RV exprv) ;


//-------------------------------------
// set single attribute
//
// (idx, val)  attribute index and value to set
// (sign_cb,
//  signopts)  provide the callback for generating signatures,
//             may be NULL if no signatures required,
//             see xcpl_admin_signs
// flags       e.g. domain or card, see XCP_ADMFL_... constants
// exprv       the expected return value to check for
//
// updates *rb if not NULL
//
// returns  0 on success (expected RV met)
//         <0 on failure
//
// Other possible return codes
//  XCP_ADMERR_SIGNING_CB_FAILED:     signing callback failed
//  XCP_ADMERR_NOT_ENOUGH_SIGNATURES: not enough signatures to fulfill
//                                    threshold value
//  XCP_ADMERR_CMD_UNEXPECTED_RV:     see reason code in *rb if non NULL
//
// uses xcpa_cmdblock() - see function header for more return codes
// uses xcpa_state() if rb is NULL, see the function for possible return codes
// uses xcpa_admin_call() - see function header for more return codes
//
// See rb->reason for the reason code in an error case.
//
long xcpa_set_admin_attr(target_t target, uint32_t idx, uint32_t val,
                struct XCPadmresp *rb,
                     unsigned int flags,
            xcpa_admin_signs_cb_t sign_cb, const void *signopts,
                            CK_RV exprv) ;


//-------------------------------------
// returns bytecount written to (cps,cplen)
//
// *cps is updated if non-NULL and has sufficient size, see XCP_CP_BYTES
//
// *rb updated to current state, if non-NULL
//
// flags, must have domain, see XCP_ADMFL_... constants
//
// returns size of control points, if query was successful
//         <0  on failure
//
// uses xcpa_state() if rb is NULL, see the function for possible rc's
//
// Other possible return codes
//  XCP_ADMERR_CARD_CPS_QUERY: trying to get card control points which are
//                             not supported
//  XCP_ADMERR_QUERY_FAILED:   the CP query failed (see the reason code)
//  XCP_ESIZE:                 cplen is not large enough (cplen <XCP_CP_BYTES)
//
long xcpa_query_cps(target_t target,
               unsigned char *cps, size_t cplen,
           struct XCPadmresp *rb,
                unsigned int flags) ;


//-------------------------------------
// set control points (currently domain only)
//
// (sign_cb,   provide the callback for generating signatures,
//  signopts)  may be NULL if no signatures required,
//             see xcpl_admin_signs
// flags       e.g. domain or card, see XCP_ADMFL_... constants
// exprv       the expected return value to check for
//
// updates *rb if not NULL (updates reason code in error case)
//
// returns  0 on success (expected RV met)
//         <0  on failure
//
// Other possible return codes
//  XCP_ADMERR_CARD_CPS_QUERY:        trying to get card control points which
//                                    are not supported
//  XCP_ESIZE:                        cplen is not large enough (cplen
//                                    <XCP_CP_BYTES)
//  XCP_ADMERR_SIGNING_CB_FAILED:     signing callback failed
//  XCP_ADMERR_NOT_ENOUGH_SIGNATURES: not enough signatures to fulfill threshold
//                                    value
//
// uses xcpa_cmdblock() - see function header for more return codes
// uses xcpa_state() if rb is NULL, see the function for possible return codes
// uses xcpa_admin_call() - see function header for more return codes
//
// See rb->reason for the reason code in an error case.
//
long xcpa_set_cps(target_t target,
       const unsigned char *cps,         /* XCP_CP_BYTES */
         struct XCPadmresp *rb,
              unsigned int flags,
     xcpa_admin_signs_cb_t sign_cb, const void *signopts,
                     CK_RV exprv) ;


//-------------------------------------
// get compliance mode from CP set (see ep11_cpt_modes[] for possible compliance
// modes)
// can not check for administrative compliance modes
//
// cps         CP set of XCP_CP_BYTES length, see xcpa_query_cps
//
// returns >0  compliance mode (see XCP_ADMS_...)
//
// does not verify CP set
//
uint32_t xcpa_cps2compliance(const unsigned char *cps /* XCP_CP_BYTES */) ;


//-------------------------------------
// set compliance mode (domain only)
//
// mode        compliance mode(s) to set (see XCP_ADMS_...)
// (sign_cb,
//  signopts)  provide the callback for generating signatures,
//             may be NULL if no signatures required,
//             see xcpl_admin_signs
// flags       e.g. domain or card, see XCP_ADMFL_... constants
// exprv       the expected return value to check for
//
// returns  0 on success
//         <0 on failure
//
// See xcpa_query_cps() and xcpa_set_cps() for possible error return codes
//
// updates *rb if not NULL
//
long xcpa_set_compliance(target_t target, uint64_t mode,
                struct XCPadmresp *rb,
                     unsigned int flags,
            xcpa_admin_signs_cb_t sign_cb, const void *signopts) ;


//--------------------------------------
// is bit number bitidx set in big-endian bitmask?
// returns 0/1, not in-bitmask power-of-two value
//
// bitidx is zero-based; 0 -> 0x80 of first byte, 1 -> 0x40 of first byte etc.
//
// tolerates missing/too-small bitmask, which does not contain any set bits
//
static inline
int xcpa_bitmask_has_bit(const unsigned char *bm, size_t bmbytes,
                          const unsigned int bitidx)
{
	return (bm && bmbytes && (bmbytes > bitidx / 8))
	       ? !!(bm[ bitidx /8 ] & ((unsigned char) 0x80 >> (bitidx %8)))
	       : 0;
}


//--------------------------------------
// set bit number bitidx in big-endian bitmask to 0 (set==0) or 1 (set!=0)
// returns 0/1, not in-bitmask/bit set
//
// bitidx is zero-based; 0 -> 0x80 of first byte, 1 -> 0x40 of first byte etc.
//
// tolerates missing/too-small bitmask
//
static inline
int xcpa_bitmask_set_bit(unsigned char *bm, size_t bmbytes,
                    const unsigned int bitidx,
                    const unsigned int set)
{
	if (!bm || !bmbytes || (bmbytes <= bitidx / 8))
		return 0;

	if (set)
		bm[ bitidx /8 ] |=  ((unsigned char) 0x80 >> (bitidx %8));
	else
		bm[ bitidx /8 ] &= ~((unsigned char) 0x80 >> (bitidx %8));

	return 1;
}


//-------------------------------------
// test if specified CPbit is set
//
// returns 0/1, not in-bitmask power-of-two value
// bitidx is zero-based; 0 -> 0x80 of first byte, 1 -> 0x40 of first byte etc.
//
// tolerates missing/too-small bitmask, which does not contain any set bits
//
static inline int xcpa_cpb_is_set(const unsigned char cps[ XCP_CP_BYTES ],
                                   const unsigned int cpbit)
{
	return xcpa_bitmask_has_bit(cps, XCP_CP_BYTES, cpbit);
}


//-------------------------------------
// enables a specific CP for the given CPs field,
// do nothing if cps is NULL or cpbit greater than XCP_CPBITS_MAX
//
static inline void xcpa_cpb_add(unsigned char cps[ XCP_CP_BYTES ],
                           const unsigned int cpbit)
{
	if ((NULL != cps) && (XCP_CPBITS_MAX >= cpbit))
		cps[ cpbit /8 ] |= (unsigned char) (0x80 >> (cpbit %8));
}


//-------------------------------------
// enable a specific CP for the given CPs field,
// do nothing if cps is NULL or cpbit greater than XCP_CPBITS_MAX
//
static inline void xcpa_cpb_del(unsigned char cps[ XCP_CP_BYTES ],
                           const unsigned int cpbit)
{
	if ((NULL != cps) && (XCP_CPBITS_MAX >= cpbit))
		cps[ cpbit /8 ] &= ~((unsigned char) (0x80 >> (cpbit %8)));
}


//-------------------------------------
// call with full-sized CP bitmask (XCP_CP_BYTES)
// returns 0/1, not bit position
//
#define  CPB_IS_SET(cps, cpbit) xcpa_cpb_is_set((cps), (cpbit))

// call with full-sized CP bitmask (XCP_CP_BYTES)
// returns 0/1
//
#define  CPB_ADD(cps, cpbit)  xcpa_cpb_add((cps), (cpbit))

// call with full-sized CP bitmask (XCP_CP_BYTES)
// returns 0/1
//
#define  CPB_DEL(cps, cpbit)  xcpa_cpb_del((cps), (cpbit))


//-------------------------------------
// supported size for user key material
#define XCP_RI_UKM_BYTES           40
//
// key import
typedef struct Encrdkey {
		// EC only: RSA recipients must keep these lengths 0
		//
		// largest supported curve: P-521
	unsigned char srcprivate[ 66 ];      /* private key (PKCS#8)    */
	size_t sprivlen;                     /* priv. key byte count    */
	unsigned char *oid;                  /* EC curve OID            */
	size_t olen;                         /* EC curve OID length     */
	unsigned char srcpublic[ 1+66+66 ];  /* originator public point */
	size_t splen;                        /* pub. point bytecount    */

	unsigned char ukm[ XCP_RI_UKM_BYTES ];  /* user keymaterial */
	size_t ulen;
			//
			// /EC-only parameters

			// importer information
	const unsigned char *spki;
	size_t spkilen;
	unsigned char ski[ XCP_CERTHASH_BYTES ];

	int ktype;      /* one of the wire-specified types */

	CK_MECHANISM *alg;  /* currently, ignored */
	unsigned char wrap_alg[25];          /* AES Key Wrap algorithm OID */
			// largest supported importer type: 4096-bit RSA
	unsigned char raw[ 4096/8 ];               /* actual encrypted bytes */
	size_t rlen;
} *Encrdkey_t;


//-------------------------------------
// Recipient info used for encrypted key part transport
//
typedef struct Recipient_info {
	uint32_t version;                    /* struct version               */
	unsigned char data[ 1024 ];          /* ASN.1 encoded recipient info */
	size_t dlen;                         /* length of recipient info     */
} *Recipient_info_t;

//-------------------------------------
// turn user key material (UKM), target key bitcount, wrapping alg into
// RFC 3278 SharedInfo structure
//
// We currently only support UKMs of size where the compound has a single-byte
// size (i.e., <=0x7f bytes). This is an arbitrary limitation, and may be
// removed in the future.
//
// kbits,wrapalg currently only take default zero (0->256, 0->AES256/wrap)
// size restriction on ulen, see above
//
// returns written size, or failure if anything is invalid
// size query (sinfo == NULL) returns exact size, not a conservative estimate
//
// Other possible return codes
//  XCP_ADMERR_RI_KWRAPSIZE_INVALID: invalid key wrap size (not zero or 256)
//  XCP_ADMERR_RI_KWRAPALG_INVALID:  invalid key wrap algorithm (not zero)
//  XCP_ADMERR_RI_UKM_INVALID:       invalid user key material (size)
//  XCP_ESIZE:                       too small output buffer
//
long xcp_rcptinfo_sharedinfo(unsigned char *sinfo, size_t slen,
                       const unsigned char *ukm,   size_t ulen,
                             unsigned int  kbits,     int wrapalg) ;


//-------------------------------------
// creates RecipientInfo ASN.1 sequence (asn) from encr structure following RFC
// 3852 for RSA and RFC 5753 for EC
//
// verifies if a known importer key is used and if the SPKI does match
// the importer key type
//
// returns size of created rcptinfo if RecipientInfo could be created
//         <0 if an error occurred
//
// Other possible return codes
//  XCP_EARG:                   if encr is missing
//  XCP_ADMERR_RI_IMPR_INVALID: if the importer type or the key import structure
//                              encr is not supported / invalid
//
long xcp_rcptinfo (unsigned char *asn, size_t alen,
           const struct Encrdkey *encr,
              const CK_MECHANISM *encrmech) ;


//-------------------------------------
// reads ASN.1 formatted RecipientInfo (asn) and turns it into rinfo structure
//
// returns size of RecipientInfo if asn could be read and rinfo (if non NULL)
// could be filled. Otherwise return failure.
//
// Note: Depending on the ASN.1 information xcp_rcptinfo_read() may not
// necessarily update all available fields of the Encrdkey structure.
// It will not wipe the Encrdkey structure before, hence it may contain
// unfilled sections. It's recommended to provide a zeroized Encrdkey struct.
//
// possible error return codes:
//  XCP_EARG:                      missing RecipientInfo
//  XCP_EINVALD: invalid ASN.1     formated sequence
//  XCP_ADMERR_RI_VERSION_INVALID: invalid rcptinfo version
//  XCP_ADMERR_RI_SKI_INVALID:     SKI (size) invalid
//  XCP_ADMERR_RI_RSA_OID_INVALID: No valid RSA OID (unsupported or invalid)
//  XCP_ADMERR_RI_EC_OID_INVALID:  No valid EC OID (unsupported or invalid)
//  XCP_ADMERR_RI_IMPR_INVALID:    Public key size does not match supporte
//                                 importer key type
//  XCP_ADMERR_RI_ECPUB_INVALID:   invalid public key bit string
//  XCP_ESIZE:                     EC public key is bigger then the Encrdkey
//                                 structure can encompass
//
long xcp_rcptinfo_read (struct Encrdkey *rinfo,
                    const unsigned char *asn, size_t alen) ;


//-------------------------------------
// construct administrative request for key part import:
//
// xcpAdminReq ::= SEQUENCE
//     functionId      OCTET STRING,      -- m_admin()
//     domain          OCTET STRING,      -- raw domain (wire 6.2) (4 bytes)
//     administrative  OCTET STRING encapsulates {
//         command  xcpAdminBlk
//     }
//     signatures      OCTET STRING {
//         -- signerInfo/s, without encapsulating SET OF
//     }
//
// returns size of created request if successfully
//         <0 if an error occurred
//
// Other possible return codes
//  XCP_EARG:  arguments are missing
//  XCP_ESIZE: output buffer is too small or olen/slen are too big
//
long xcpa_import_keypart (unsigned char *out,    size_t olen,
                    const unsigned char *cmdblk, size_t clen,
                    const unsigned char *sig,    size_t slen,
                const struct XCPadmresp *minf,
                          const target_t target) ;


//-------------------------------------
// construct single import piece: one command block with one recipientInfo
// to be signed by one admin
// xcpa_import_keypart() turns this block and its signature into final form
//
// restrictions: RSA keys must have 2048, 3072 or 4096-bit modulus with exponent
//               0x10001. EC must be one of the supported importers
//
// SPKI used only to find out importer key type; SKI identifies recipient
// both must be already imported into *key
//
// module info (minf) must be identical to all simultaneously imported parts
//
// tctr is transaction counter; if non-NULL, must be XCP_ADMCTR_BYTES
// otherwise derived from minf
//
// returns length of ASN.1 formated command block if successful, otherwise error
//
// possible error return codes:
//  XCP_EARG:                   missing parameters
//  XCP_ADMERR_RI_ENC_EMPTY:    spki not supplied within Encrdkey struture
//  XCP_ADMERR_RI_IMPR_INVALID: importer key type invalid / unsupported or does
//                              not match SPKI
//
// uses xcpa_cmdblock() - see function header for more return codes
//
long xcpa_import_cmdblock (unsigned char *out, size_t olen,
                   const struct Encrdkey *key,
                 const struct XCPadmresp *minf,
                     const unsigned char *tctr) ;


//-------------------------------------
// Validate if EC OID does match any supported EC importer type
// Sets importer type in type if not NULL
//
// Return 0 if no match and 1 for match and XCP_EARG if an OID is not supplied
int xcp_valid_ec_oid2imprtype(XCP_IMPRKEY_t *type,
                        const unsigned char *oid, size_t olen) ;


//-------------------------------------
// Matches importer type to EC OID
// Sets EC OID in oid if not NULL
//
// Returns 0 if no match and 1 for match
int xcp_valid_ec_imprtype2oid(const unsigned char **oid, size_t *olen,
                                    XCP_IMPRKEY_t type) ;


//-------------------------------------
// parse embedded return value from response, writes to *rv if non-NULL
// (outside envelope always reports CKR_OK, unless infrastructure failed)
//
// possible error return codes:
//  XCP_EINVALID: response is malformed or contents invalid
//  XCP_EARG:     arguments are missing
//
long xcpa_internal_rv(const unsigned char *rsp,   size_t rlen,
                        struct XCPadmresp *rspblk, CK_RV *rv) ;


//-------------------------------------
// returns net bytecount (full T+L+V) if start of (asn,alen) is full tag
//         0   if invalid
//
// sets *voffs to T+L bytecount if non-NULL
//
size_t xcpa_asn_tag(size_t *voffs, const unsigned char *asn, size_t alen);


//-------------------------------------
// return raw bytecount of ASN.1 SEQ
// return XCP_EINVALID if malformed and XCP_ESIZE if ASN.1 lengths are not
// correct
//
long xcpa_asn_bytes(const void *asn, size_t alen);


//-------------------------------------
// return offset of value in ASN.1 SEQ
// return XCP_EINVALID if malformed and XCP_ESIZE if ASN.1 lengths are not
// correct
//
long xcpa_asn_value_offset(const void *asn, size_t alen) ;


//-------------------------------------
// nonzero tag is compared to that of (asn,alen)
// returns T+L+V bytecount  in case of success
//         XCP_EINVALID     if asn is malformed
//         XCP_EARG         if asn or alen arguments are invalid
//         XCP_ESIZE        if ASN.1 lengths are not correct
//
long xcpa_asn_tlv (const void *asn, size_t alen,
                 unsigned int tag,  size_t *voffset,
                       size_t *vbytes);


//-------------------------------------
// DH ASN.1 SEQ's need to be split up, since we only need public value (X)
// full input is (potentially MACed) DH SPKI
//
// SEQUENCE {
//    SEQUENCE {
//       ...OID, P, G    /* not verified */
//    }
//    BIT STRING {       /* 0 unused bits -> single-byte 00 before INT
//       INTEGER {
//          Y         /* reminder: possibly with leading zero/es */
//       }
//    }
// }
//
// bits is derived from SEQUENCE if 0 (not currently used/supported!)
// must be full bytes, otherwise (no partial-byte moduluses supported)
//
// returns >0 if recognized; X is at (pub+offs, length)
//          0 if input appears to be invalid
//
size_t xcpa_dh_asn2y(const unsigned char *pub, size_t plen,
                                  size_t *offs);


//-------------------------------------
// parses public value (Y) from Diffie-Hellman public key (ASN)
// accepts MACed public keys
//
// sets *offs to offset of Y within (asn,alen) if non-NULL
//
// returns >0 if parsing successful (raw bytecount of public value)
//          0 if anything failed, logging reason
//
size_t xcpa_dh_pub2y(size_t *offs, const unsigned char *asn, size_t alen);


//-------------------------------------
// EC ASN.1 SEQ's need to be split up, since we only need public value (X)
// full input is (potentially MACed) DH SPKI
//
// SEQUENCE {
//    SEQUENCE {
//       OID(EC)
//       OID(curve)      /* not verified */
//    }
//    BIT STRING {       /* 0 unused bits -> single-byte 00 before INT
//       Y               /* raw value */
//    }
// }
//
// bits is derived from SEQUENCE if 0 (not currently used/supported!)
// must be full bytes, otherwise (no partial-byte moduluses supported)
//
// returns >0 if recognized; X is at (pub+offs, length)
//          0 if input appears to be invalid
//
size_t xcpa_ec_asn2y(const unsigned char *pub, size_t plen,
                                  size_t *offs);


//-------------------------------------
// parses public value (Y) from EC public key (ASN)
// accepts MACed public keys
//
// sets *offs to offset of Y within (asn,alen) if non-NULL
//
// returns >0 if parsing successful (raw bytecount of public value)
//          0 if anything failed, logging reason
//
size_t xcpa_ec_pub2y(size_t *offs, const unsigned char *asn, size_t alen);


//-------------------------------------
// generates the export request in an ASN.1 structure
// reuired for export wk or export state
//
// asn               pointer to the resulting ASN.1 buffer
// alen              max. ASN.1 buffer len
// certs             pointer to the KPH certificates
// ccnt              number of KPHs
// exportstate       set to 0 if exportwk is requested
//                   set to 1 if exportstate is requested
// statesave         contains properties for exportstate
// restriction_mask  mask of exportwk restrictions
long xcpa_fill_export_req(unsigned char *asn,         size_t alen,
                       const struct KPH *certs, unsigned int ccnt,
                                    int exportstate,
                       struct STATESAVE *statesave, uint32_t restriction_mask);


//-------------------------------------
// Constructs key part file with ASN.1 envelope
// writes output to (*reqprep, reqpreplen)
//
// domainmask target domain mask
// kphs       keypart holder certificates
// kcnt       number of kphs
// ekps       contains re-encrypted keyparts
// reqprep    output buffer
// reqpreplen output length
// headerinfo set to 0 if no header info requested
//            set to 1 if header info requested
//
// returns  0 if successful
//         <0 if something fails
long xcpa_construct_keypart_file(unsigned char *domainmask,
                              const struct KPH *kphs,
                         const struct Encrdkey *ekps,
                                  unsigned int kcnt,
                                 unsigned char *reqprep,
                                        size_t *reqpreplen,
                                  unsigned int headerinfo);


//-------------------------------------
// Enable export WK permission
//
// target      target domain
// sign_cb     provide the callback for generating signatures
//             may be NULL if no signatures required
// signopts    number of signatures requested
long xcpa_enable_exportwk(target_t target,
             xcpa_admin_signs_cb_t sign_cb, const void *signopts);


//-------------------------------------
// Enable export state permission
//
// target      target module/domain
// sign_cb     provide the callback for generating signatures
//             may be NULL if no signatures required
// signopts    number of signatures requested
//
long xcpa_enable_export_state(target_t target,
                 xcpa_admin_signs_cb_t sign_cb, const void *signopts);


//-------------------------------------
// Enable import WK permission
//
// target      target domain
// sign_cb     provide the callback for generating signatures
//             may be NULL if no signatures required
// signopts    number of signatures requested
long xcpa_enable_importwk(target_t target,
             xcpa_admin_signs_cb_t sign_cb, const void *signopts);


//-------------------------------------
// Enable import state permission
//
// target      target module/domain
// sign_cb     provide the callback for generating signatures
//             may be NULL if no signatures required
// signopts    number of signatures requested
//
long xcpa_enable_import_state(target_t target,
                 xcpa_admin_signs_cb_t sign_cb, const void *signopts);


//-------------------------------------
// Export the domain WK of the given target
// writes output to (*resp, resplen)
//
// target      addresses target module/domain
// wktype      indicates either current or next WK
// keyparts    pointer to the encrypted keyparts
// keypartlen  length of encrypted keyparts
// request     pointer to the export request data
// requestlen  length of request data
// sign_cb     provide the callback for generating signatures
//             may be NULL if no signatures required
// signopts    number of signatures requested
long xcpa_export_wk(target_t target,         int wktype,
               unsigned char *keyparts,   size_t *keypartlen,
         const unsigned char *request,    size_t requestlen,
       xcpa_admin_signs_cb_t sign_cb, const void *signopts);


//-------------------------------------
// Export the state of the given target
// writes output to (*state/statelen, tkps/tkpslen)
//
// target      addresses target module/domain
// state       pointer to exported state data
// statelen    length of exported state data
// keyparts    pointer to transport keyparts
// keypartlen  length of transport keyparts
// request     pointer to the export request
// requestlen  length of export request
// sign_cb     provide the callback for generating signatures
//             may be NULL if no signatures required
// signopts    number of signatures requested
//
long xcpa_export_state(target_t target,
                  unsigned char *state,      size_t *statelen,
                  unsigned char *tkps,       size_t *tkplen,
            const unsigned char *request,    size_t requestlen,
          xcpa_admin_signs_cb_t sign_cb, const void *signopts);


//-------------------------------------
// Import a domain WK (from recipient info) to the given target
//
// target      addresses target module/domain
// rinfo       contains recipient infos
// ricnt       number of recipient infos
// wkvp        WK verification pattern
// sign_cb     provide the callback for generating signatures
//             may be NULL if no signatures required
// signopts    number of signatures requested
long xcpa_import_wk_rcptinfo(target_t target,
                struct Recipient_info *rinfo, unsigned int ricnt,
                  const unsigned char *wkvp,
                xcpa_admin_signs_cb_t sign_cb,  const void *signopts);


//-------------------------------------
// Import a domain WK (from ekps struct) to the given target
//
// target      addresses target module/domain
// ekps        contains re-encrypted keyparts
// kcnt        number of keyparts
// wkvp        WK verification pattern
// sign_cb     provide the callback for generating signatures
//             may be NULL if no signatures required
// signopts    number of signatures requested
long xcpa_import_wk(target_t target, const struct Encrdkey *ekps,
                unsigned int kcnt,     const unsigned char *wkvp,
       xcpa_admin_signs_cb_t sign_cb,           const void *signopts);



//-------------------------------------
// Import module state data to a target
//
// target      addresses target module
// domainmask  list of affected domains
// ekps        contains re-encrypted keyparts
// kpcnt       number of keyparts
// state       module state data
// statelen    state data len
// sign_cb     provide the callback for generating signatures
//             may be NULL if no signatures required
// signopts    number of signatures requested
//
long xcpa_import_state(target_t target, unsigned char *domainmask,
                  unsigned char *state,        size_t statelen,
                struct Encrdkey *ekps,   unsigned int kpcnt,
          xcpa_admin_signs_cb_t sign_cb,   const void *signopts);


//-------------------------------------
// Commit a domain WK of the given target
//
// target      addresses target module/domain
// wkvp        WK verification pattern
// sign_cb     provide the callback for generating signatures
//             may be NULL if no signatures required
// signopts    number of signatures requested
long xcpa_commit_wk(target_t target, const unsigned char *wkvp,
       xcpa_admin_signs_cb_t sign_cb,         const void *signopts);


//-------------------------------------
// Finalize a domain WK of the given target
//
// target      addresses target module/domain
// wkvp        WK verification pattern
long xcpa_finalize_wk(target_t target, const unsigned char *wkvp);


//-------------------------------------
// Generate a random WK for the given target
//
// target      addresses target module/domain
// wkvp        WK verification pattern
// sign_cb     provide the callback for generating signatures
//             may be NULL if no signatures required
// signopts    number of signatures requested
long xcpa_gen_random_wk(target_t target, unsigned char *wkvp,
           xcpa_admin_signs_cb_t sign_cb, const void *signopts);


//-------------------------------------
// SKI-based SignerInfo form
//
// 30(02(03)                       // v3: signer identified by SKI
//    80(...SKI...)
//    30(...digest OID...)
//    30(...signature_alg OID...)
//    04(...signature...)
// )
//
// we construct ASN.1 following these rules:
//   1. lengths, except that of the signature, are single-byte (<127)
//      - this is true for all forms we support
//   2. signature and whole SEQUENCE use two-byte length fields (82 xx yy)
//   3. version is minimal-encoded
//   4. OIDs always contain trailing NULL (05 00)
//      - we tolerate the lack of this, see si_read below

// sigmech may be a combined hash+sign mechanism, then hashmech is ignored
//
// placeholder 'signature' is added if sig is NULL: siglen is bytecount then
//
// if encoding a generic 'rsaEncryption' mode, use CKM_RSA_X_509 and
// separate hash in hashmech
//
// returns length of ASN.1 formated SignerInfo if successful, otherwise failure
//
// possible error return codes:
//  XCP_EARG:                           missing arguments or bad ski length
//  XCP_ADMERR_SI_SIZE:                 bad signature length
//  XCP_ESIZE:                          other lengths are over the 127 limit
//                                      or output buffer too small
//  XCP_ADMERR_SI_SIG_MECH_UNSUPPORTED: unsupported signature mechanism
//  XCP_ADMERR_SI_HSH_MECH_UNSUPPORTED: unsupported hash mechanism
//  XCP_ADMERR_SI_OID_MECH_MISMATCH:    mismatch between signature and hash
//                                      mechanism
//
long xcp_signerinfo (unsigned char *asn, size_t alen,
               const unsigned char *ski, size_t skilen,  /* signer */
               const unsigned char *sig, size_t siglen,
               const  CK_MECHANISM *sigmech,
               const  CK_MECHANISM *hashmech) ;


//-------------------------------------
// checks if valid and parses signer info into components
//
// (ski,skilen) and (sig,siglen) are within (sinfo,silen), if set
//
// returns signerinfo struct bytecount if successful
//
// possible error return codes:
//  XCP_EARG:                           missing arguments
//  XCP_EINVALID:                       could not read signerinfo
//  XCP_ADMERR_SI_SIG_EMPTY:            no signature present
//  XCP_ADMERR_SI_SIG_MECH_UNSUPPORTED: unsupported signature mechanism
//  XCP_ADMERR_SI_HSH_MECH_UNSUPPORTED: unsupported hash mechanism
//  XCP_ADMERR_SI_OID_MECH_MISMATCH:    mismatch between signature and hash
//                                      mechanism
//
// no length checks on signature or SKI, other than checking both for non-empty
//
long xcp_signerinfo_read (const unsigned char *sinfo, size_t silen,
                          const unsigned char **ski,  size_t *skilen,
                          const unsigned char **sig,  size_t *siglen,
                          const unsigned char **hoid, size_t *hoidlen,
                          const unsigned char **soid, size_t *soidlen,
                                 CK_MECHANISM *signmech,
                                 CK_MECHANISM *hashmech) ;


//-------------------------------------
// given an SPKI, return its raw public key (which hashes into the SKI):
//
// SEQUENCE {
//     SEQUENCE ...      -- type information (which we do not parse)
//     BIT STRING {      -- SKI base is net content of this BIT STRING
//                       -- without leading byte (==unused bits' count)
//         SEQUENCE {    -- capture this T+L+V (or raw public value for EC key)
//             ...
//         }
//     }
//
// returns SKI-base bytecount, setting *ski to start of SKI base, if non-NULL
//         XCP_EINVALID if input does not look like an SPKI
//         XCP_EARG     if missing arguments
//
// note: we do not verify other details of SPKI; caller must do so
//
long xcp_spki2pubkey (const unsigned char **bitstr,
                  const unsigned char *spki, size_t slen) ;




/*
 * Parse the list of indices and ranges and construct corresponding bitmask
 * args        pointer to a comma separated list of indices
 *             (ranges of indices are also allowed)
 * mask        pointer to an 32 byte array that represents our domain mask
 * masksize    bit-length of the mask
 */
int xcp_args2mask(char *args, unsigned char *mask, int masksize);


/*
 * Fills in 'file-ID', 'offset' and 'length' parameter into the file header
 * hdr         pointer to the file header
 * hlen        length of the header
 * fileid      fileid to refer the file type
 * offset      offset of data pointer
 * bytes       number of bytes to transfer
 */
int xcpa_write_filepart_hdr(unsigned char *hdr,     size_t hlen,
                                 uint32_t fileid, uint32_t offset,
                                 uint32_t bytes);


/* reads partial data from target/fileid
 * returning payload to res, rlen
 *
 * returns >0 on success (bytecount)
 *          0 if file access failed (not available, etc.)
 *         <0 if anything unexpected failed
 */
long xcpa_query_filepart(unsigned char *res, size_t rlen,
                   const unsigned char *hdr, size_t hlen,
                              target_t target,
                                 CK_RV exprv);


/* reads complete data from target/fileid
 * returning payload to res, rlen
 *
 * returns >0 on success (bytecount)
 *          0 if file access failed (not available, etc.)
 *         <0 if anything unexpected failed
 */
long xcpa_query_full_file(unsigned char *res, size_t rlen,
                               target_t target,
                           unsigned int fileid,
                           unsigned int block);


/* writes data to internal files
 * takes data, dlen to write to target/fileid
 *
 * returns >0 if results have been all written
 *         <0 if anything unexpected failed
 */
long xcpa_write_full_file(target_t target,
             xcpa_admin_signs_cb_t sign_cb,  const void *signopts,
               const unsigned char *data,        size_t dlen,
                      unsigned int fileid, unsigned int block);


long xcpa_remove_file(target_t target, unsigned int fileid,
         xcpa_admin_signs_cb_t sign_cb,  const void *signopts);


/* brute-force section parser: enumerate all encrypted-KP sections
 *
 * returns >0 offset of full OCTET STRING T+L+V section
 *         0  when there are no more sections
 *         <0 if encoding is invalid (which SNH)
 *
 * sets *kpidx to index (sub-type) of keypart found if not NULL
 *
 * since external compound is SEQUENCE, it can't match KP at offset 0
 * therefore, comparing <current offset> > <idx> is correct
 */
long xcpa_kp_next_section(const unsigned char *kps,  size_t kplen,
                                unsigned long idx, uint32_t *kpidx);


/* retrieve recipient infos from keypart sections
 *
 * returns >0 number of recipient infos found
 *         <0 if anything failed
 */
long xcpa_kps_retrieve_rcptinfo(struct Recipient_info *rcpti,
                                         unsigned int rimax,
                                  const unsigned char *kpexport,
                                               size_t kplen);


/*
 * report domain compliance
 *
 * returns compliance bitmask if successful and 0 if anything failed
 * (as zero is invalid as we always have a default compliance active)
 *
 */
uint64_t get_dom_compl(target_t target);

#endif /* !defined(__xcpadm_h__) */

