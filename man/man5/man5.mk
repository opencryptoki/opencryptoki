man5_MANS += man/man5/opencryptoki.conf.5 man/man5/strength.conf.5 man/man5/policy.conf.5

if ENABLE_P11SAK
man5_MANS += man/man5/p11sak_defined_attrs.conf.5
endif

if ENABLE_P11KMIP
man5_MANS += man/man5/p11kmip.conf.5
endif

man/man5/%.5: man/man5/%.5.in
	@$(MKDIR_P) man/man5
	$(MAN_SUBST) < $< > $@-t && $(am__mv) $@-t $@

EXTRA_DIST += man/man5/opencryptoki.conf.5.in \
	      man/man5/strength.conf.5.in \
	      man/man5/policy.conf.5.in \
	      man/man5/p11sak_defined_attrs.conf.5.in \
	      man/man5/p11kmip.conf.5.in
CLEANFILES += man/man5/*.5
