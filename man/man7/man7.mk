man7_MANS += man/man7/opencryptoki.7

man/man7/%.7: man/man7/%.7.in
	@$(MKDIR_P) man/man7
	$(MAN_SUBST) < $< > $@-t && $(am__mv) $@-t $@

EXTRA_DIST += man/man7/opencryptoki.7.in
CLEANFILES += man/man7/*.7
