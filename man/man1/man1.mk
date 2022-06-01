man1_MANS += man/man1/pkcsconf.1 man/man1/pkcsicsf.1

if ENABLE_PKCSHSM_MK_CHANGE
man1_MANS += man/man1/pkcshsm_mk_change.1
endif

if ENABLE_PKCSSTATS
man1_MANS += man/man1/pkcsstats.1
endif

if ENABLE_PKCSTOK_MIGRATE
man1_MANS += man/man1/pkcstok_migrate.1
endif

if ENABLE_PKCSEP11_MIGRATE
man1_MANS += man/man1/pkcsep11_migrate.1
endif

if ENABLE_PKCSEP11_SESSION
man1_MANS += man/man1/pkcsep11_session.1
endif

if ENABLE_CCATOK
man1_MANS += man/man1/pkcscca.1
endif

if ENABLE_P11SAK
man1_MANS += man/man1/p11sak.1
endif

EXTRA_DIST += $(man1_MANS)
CLEANFILES += man/man1/*.1
