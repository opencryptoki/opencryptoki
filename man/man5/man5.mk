man5_MANS += man/man5/opencryptoki.conf.5

if ENABLE_P11SAK
man5_MANS += man/man5/p11sak_defined_attrs.conf.5
endif

EXTRA_DIST += $(man5_MANS)
CLEANFILES += $(man5_MANS)
