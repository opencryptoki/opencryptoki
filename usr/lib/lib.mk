if ENABLE_LIBRARY
include %D%/api/api.mk
endif
if ENABLE_CCATOK
include %D%/cca_stdll/cca_stdll.mk
endif
if ENABLE_EP11TOK
include %D%/ep11_stdll/ep11_stdll.mk
endif
if ENABLE_ICATOK
include %D%/ica_s390_stdll/ica_s390_stdll.mk
endif
if ENABLE_SWTOK
include %D%/soft_stdll/soft_stdll.mk
endif
if ENABLE_TPMTOK
include %D%/tpm_stdll/tpm_stdll.mk
endif
if ENABLE_ICSFTOK
include %D%/icsf_stdll/icsf_stdll.mk
endif

include %D%/common/common.mk
