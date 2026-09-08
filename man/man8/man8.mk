man8_MANS += man/man8/pkcsslotd.8

man/man8/%.8: man/man8/%.8.in
	@$(MKDIR_P) man/man8
	$(MAN_SUBST) < $< > $@-t && $(am__mv) $@-t $@

EXTRA_DIST += man/man8/pkcsslotd.8.in
CLEANFILES += man/man8/*.8
