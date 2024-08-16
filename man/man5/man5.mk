man5_MANS += man/man5/opencryptoki.conf.5 man/man5/strength.conf.5 man/man5/policy.conf.5

if ENABLE_P11SAK
man5_MANS += man/man5/p11sak_defined_attrs.conf.5
endif

if ENABLE_P11KMIP
man5_MANS += man/man5/p11kmip.conf.5
endif