/*----------------------------------------------------------------------
 * (C) COPYRIGHT INTERNATIONAL BUSINESS MACHINES CORPORATION 2011
 *			  ALL RIGHTS RESERVED
 *                     IBM Research & Development
 *----------------------------------------------------------------------
 *  Author: Gehrmann, Tobias (tobias.gehrmann@de.ibm.com)
 *----------------------------------------------------------------------*/

#if !defined(__EP11ADM_H__)
#define __EP11ADM_H__

#if !defined(INT64_MIN)
#error "We need 32/64-bit <stdint.h> types, please include before this file."
#endif

// these numbers apply to current version, subject to change
//
#if !defined(EP11_SERIALNR_CHARS)
#define  EP11_SERIALNR_CHARS        8
#endif

#if !defined(EP11_KEYCSUM_BYTES)
#define  EP11_KEYCSUM_BYTES         (256/8) /* full size of verific. pattern */
#endif

#if !defined(EP11_ADMCTR_BYTES)
#define  EP11_ADMCTR_BYTES          (128/8)    /* admin transaction ctrs */
#endif

#if !defined(EP11_ADM_REENCRYPT)
#define  EP11_ADM_REENCRYPT         25    /* transform blobs to next WK */
#endif

#if !defined(CK_IBM_EP11Q_DOMAIN)
#define  CK_IBM_EP11Q_DOMAIN        3     /* list domain's WK hashes */
#endif

#if !defined(CK_IBM_DOM_COMMITTED_NWK)
#define  CK_IBM_DOM_COMMITTED_NWK   8     /* next WK is active(committed) */
#endif


typedef struct ep11_admresp {
	uint32_t fn;
	uint32_t domain;
	uint32_t domainInst;

	/* module ID || module instance */
	unsigned char  module[ EP11_SERIALNR_CHARS + EP11_SERIALNR_CHARS ];
	unsigned char   modNr[ EP11_SERIALNR_CHARS ];
	unsigned char modInst[ EP11_SERIALNR_CHARS ];

	unsigned char    tctr[ EP11_ADMCTR_BYTES ];    /* transaction counter */

	CK_RV rv;
	uint32_t reason;

	// points to original response; NULL if no payload
	// make sure it's copied if used after releasing response block
	//
	const unsigned char *payload;
	size_t pllen;
} *ep11_admresp_t;


#if !defined(__XCP_H__)
typedef struct CK_IBM_DOMAIN_INFO {
	CK_ULONG    domain;
	CK_BYTE     wk[ EP11_KEYCSUM_BYTES ];
 	CK_BYTE nextwk[ EP11_KEYCSUM_BYTES ];
	CK_ULONG  flags;
	CK_BYTE   mode[ 8 ];
} CK_IBM_DOMAIN_INFO;
#endif


/*----------------------------------------------------------------------
 *  build a command block to (blk,blen), querying 'fn'
 *  (payload,plen) copied to query block if non-NULL
 *
 *  returns written bytecount; size query if blk is NULL
 *   *minf used for module ID and transaction counter
 *  ignored for commands where those fields are ignored
 */
long ep11a_cmdblock(unsigned char *blk, size_t blen,
                    unsigned int fn,
              const struct ep11_admresp *minf,
              const unsigned char *tctr,    /* EP11_ADMCTR_BYTES */
              const unsigned char *payload, size_t plen);


/*----------------------------------------------------------------------
 *  returns <0 if response is malformed, or contents invalid
 *
 *  parse embedded return value from response, writes to *rv if non-NULL
 *  (outside envelope always reports CKR_OK, unless infrastructure
 *  failed)
 */
long ep11a_internal_rv(const unsigned char *rsp, size_t rlen,
		       struct ep11_admresp *rspblk, CK_RV *rv);


/*----------------------------------------------------------------------
 *  in:  [0] query type
 *  out: [0] packed info structure
 *
 *  outputs are fixed size, except CK_IBM_XCPQ_DOMAINS, which returns a
 *  list therefore, infbytes is ignored by other types (we still check
 *  if present)
 */
CK_RV m_get_ep11_info(CK_VOID_PTR pinfo, CK_ULONG_PTR infbytes,
                      unsigned int query,
                      unsigned int subquery,
                      uint64_t target);


#endif /* !defined(__EP11ADM_H__) */
