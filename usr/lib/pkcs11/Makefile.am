ROOT = api methods
if ICC
LEEDS_DLL= leeds_stdll 
endif
if ICA
ICA_DLL = ica_stdll
endif
if SOFT
SOFT_DLL= soft_stdll
endif
if BCOM
BCOM_DLL = bcom_stdll
endif
if AEP
AEP_DLL = aep_stdll
endif
if CR
CR_DLL = cr_stdll
endif
if S390
S390_DLL = ica_s390_stdll 
SUBDIRS = $(ROOT) $(S390_DLL)
else
SUBDIRS = $(ROOT) $(LEEDS_DLL) $(ICA_DLL) $(SOFT_DLL) $(BCOM_DLL) $(AEP_DLL)  $(CR_DLL)
endif
