if ENABLE_DAEMON
DAEMONDIRS = include sbin
endif

SUBDIRS = lib $(DAEMONDIRS)

install-data-hook:
	$(MKDIR_P) $(lockdir)
	$(CHGRP) pkcs11 $(lockdir)
	$(CHMOD) 0770 $(lockdir)
