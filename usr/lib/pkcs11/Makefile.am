if ENABLE_ICATOK
ICA_DLL = ica_s390_stdll
endif

if ENABLE_SWTOK
SW_DLL = soft_stdll
endif

if ENABLE_TPMTOK
TPM_DLL = tpm_stdll
endif

if ENABLE_ICCTOK
LEEDS_DLL= methods leeds_stdll 
endif

if ENABLE_AEPTOK
AEP_DLL = aep_stdll
endif

if ENABLE_BCOMTOK
BCOM_DLL = bcom_stdll
endif

if ENABLE_CRTOK
CR_DLL = cr_stdll
endif

if ENABLE_CCATOK
CCA_DLL = cca_stdll
endif

if ENABLE_LIBRARY
API = api
endif 

SUBDIRS = $(API) $(SW_DLL) $(ICA_DLL) $(TPM_DLL) $(LEEDS_DLL) $(AEP_DLL) $(BCOM_DLL) $(CR_DLL) $(CCA_DLL)

