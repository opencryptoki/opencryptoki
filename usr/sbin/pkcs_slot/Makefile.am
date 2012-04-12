sbin_SCRIPTS = pkcs_slot

EXTRA_DIST = pkcs_slot.in

CLEANFILES = pkcs_slot

pkcs_slot: pkcs_slot.in
	@SED@ 	-e s!\@libdir\@!"@libdir@"!g			\
		-e s!\@localstatedir\@!"@localstatedir@"!g	\
		-e s!\@lockdir\@!"@lockdir@"!g	\
		-e s!\@MKDIR_P\@!"@MKDIR_P@"!g			\
		-e s!\@CHGRP\@!"@CHGRP@"!g			\
		-e s!\@CHMOD\@!"@CHMOD@"!g < $< > $@-t
	@CHMOD@ +x $@-t
	mv $@-t $@

install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki
