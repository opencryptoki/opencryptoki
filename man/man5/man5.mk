man5_MANS += man/man5/opencryptoki.conf.5 man/man5/strength.conf.5 man/man5/policy.conf.5

if ENABLE_P11SAK
man5_MANS += man/man5/p11sak_defined_attrs.conf.5
endif

EXTRA_DIST += $(man5_MANS)
CLEANFILES += man/man5/*.5
