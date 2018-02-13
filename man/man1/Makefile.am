man1_MANS=pkcsconf.1 pkcsicsf.1

if ENABLE_PKCSEP11_MIGRATE
man1_MANS += pkcsep11_migrate.1
endif

if ENABLE_PKCSEP11_SESSION
man1_MANS += pkcsep11_session.1
endif

if ENABLE_CCATOK
man1_MANS += pkcscca.1
endif

EXTRA_DIST = $(man1_MANS)
CLEANFILES = $(man1_MANS)
