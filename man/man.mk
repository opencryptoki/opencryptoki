MAN_SUBST = $(AM_V_GEN)@SED@ \
	-e s!\@sysconfdir\@!"$(sysconfdir)"!g \
	-e s!\@localstatedir\@!"$(localstatedir)"!g \
	-e s!\@sbindir\@!"$(sbindir)"!g \
	-e s!\@pkcs_group\@!"$(pkcs_group)"!g \
	-e s!\@pkcsslotd_user\@!"$(pkcsslotd_user)"!g \
	-e s!\@PACKAGE_VERSION\@!"$(PACKAGE_VERSION)"!g

include man/man1/man1.mk
include man/man5/man5.mk
include man/man7/man7.mk
include man/man8/man8.mk
