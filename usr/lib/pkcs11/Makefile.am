if S390

if DEFAULT_DLL
DEFAULT = ica_s390_stdll 
endif

else

if DEFAULT_DLL
DEFAULT = soft_stdll 
endif

endif

if ICA
ICA_DLL = ica_stdll
endif
if TPM
TPM_DLL = tpm_stdll
endif
if ICC
LEEDS_DLL= methods leeds_stdll 
endif
if AEP
AEP_DLL = aep_stdll
endif
if BCOM
BCOM_DLL = bcom_stdll
endif
if CR
CR_DLL = cr_stdll
endif
if SAMPLE
SAMPLE_DLL = sample_stdll
endif

if LIBRARY
API = api
endif 

SUBDIRS = common $(API) $(DEFAULT) $(ICA_DLL) $(TPM_DLL) $(LEEDS_DLL) $(AEP_DLL) $(BCOM_DLL) $(CR_DLL) $(SAMPLE_DLL) 

