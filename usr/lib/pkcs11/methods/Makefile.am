if BUILD_UTILS
ROOT = 4758_startup pkcsconf
else
ROOT =
endif

if ICC
LEEDS_DLL = 4758_status
endif
if S390
SUBDIRS = $(ROOT)
else
SUBDIRS = $(ROOT) $(LEEDS_DLL)
endif
