if ENABLE_DAEMON
DAEMONDIRS = include sbin
endif

SUBDIRS = lib $(DAEMONDIRS)

install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(lockdir)
	$(GROUPADD) -f pkcs11
	$(CHGRP) pkcs11 $(DESTDIR)$(lockdir)
	$(CHMOD) 0770 $(DESTDIR)$(lockdir)
