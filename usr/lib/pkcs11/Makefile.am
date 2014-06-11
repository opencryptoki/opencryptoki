if ENABLE_ICATOK
ICA_DLL = ica_s390_stdll
endif

if ENABLE_EP11TOK
EP11_DLL = ep11_stdll
endif

if ENABLE_SWTOK
SW_DLL = soft_stdll
endif

if ENABLE_TPMTOK
TPM_DLL = tpm_stdll
endif

if ENABLE_CCATOK
CCA_DLL = cca_stdll
endif

if ENABLE_ICSFTOK
ICSF_DLL = icsf_stdll
endif

if ENABLE_LIBRARY
API = api
endif 

SUBDIRS = $(API) $(SW_DLL) $(ICA_DLL) $(TPM_DLL) $(CCA_DLL) $(ICSF_DLL) $(EP11_DLL)

