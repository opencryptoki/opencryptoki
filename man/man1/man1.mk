man1_MANS += man/man1/pkcsconf.1 man/man1/pkcsicsf.1

if ENABLE_PKCSEP11_MIGRATE
man1_MANS += man/man1/pkcsep11_migrate.1
endif

if ENABLE_PKCSEP11_SESSION
man1_MANS += man/man1/pkcsep11_session.1
endif

if ENABLE_CCATOK
man1_MANS += man/man1/pkcscca.1
endif

EXTRA_DIST += $(man1_MANS)
CLEANFILES += $(man1_MANS)
