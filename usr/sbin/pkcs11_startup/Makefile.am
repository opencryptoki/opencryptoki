sbin_SCRIPTS = pkcs11_startup

EXTRA_DIST = pkcs11_startup.in

CLEANFILES = pkcs11_startup

pkcs11_startup: pkcs11_startup.in
	@SED@ 	-e s!\@sbindir\@!"@sbindir@"!g 			\
		-e s!\@libdir\@!"@libdir@"!g			\
		-e s!\@libexecdir\@!"@libexecdir@"!g		\
		-e s!\@localstatedir\@!"@localstatedir@"!g	\
		-e s!\@ID\@!"@ID@"!g				\
		-e s!\@CAT\@!"@CAT@"!g				\
		-e s!\@SED\@!"@SED@"!g				\
		-e s!\@GROUPADD\@!"@GROUPADD@"!g		\
		-e s!\@USERMOD\@!"@USERMOD@"!g < $< > $@-t
	@CHMOD@ +x $@-t
	mv $@-t $@
