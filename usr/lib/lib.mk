if ENABLE_LIBRARY
include usr/lib/api/api.mk
endif
if ENABLE_CCATOK
include usr/lib/cca_stdll/cca_stdll.mk
endif
if ENABLE_EP11TOK
include usr/lib/ep11_stdll/ep11_stdll.mk
endif
if ENABLE_ICATOK
include usr/lib/ica_s390_stdll/ica_s390_stdll.mk
endif
if ENABLE_SWTOK
include usr/lib/soft_stdll/soft_stdll.mk
endif
if ENABLE_TPMTOK
include usr/lib/tpm_stdll/tpm_stdll.mk
endif
if ENABLE_ICSFTOK
include usr/lib/icsf_stdll/icsf_stdll.mk
endif

include usr/lib/common/common.mk
include usr/lib/config/config.mk
include usr/lib/hsm_mk_change/hsm_mk_change.mk
