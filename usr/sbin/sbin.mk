if ENABLE_ICSFTOK
include usr/sbin/pkcsicsf/pkcsicsf.mk
endif
if ENABLE_PKCSEP11_MIGRATE
include usr/sbin/pkcsep11_migrate/pkcsep11_migrate.mk
endif
if ENABLE_PKCSEP11_SESSION
include usr/sbin/pkcsep11_session/pkcsep11_session.mk
endif
if ENABLE_CCATOK
include usr/sbin/pkcscca/pkcscca.mk
endif
if ENABLE_P11SAK
include usr/sbin/p11sak/p11sak.mk
endif
if ENABLE_PKCSTOK_MIGRATE
include usr/sbin/pkcstok_migrate/pkcstok_migrate.mk
endif
if ENABLE_PKCSSTATS
include usr/sbin/pkcsstats/pkcsstats.mk
endif
if ENABLE_PKCSHSM_MK_CHANGE
include usr/sbin/pkcshsm_mk_change/pkcshsm_mk_change.mk
endif

include usr/sbin/pkcsslotd/pkcsslotd.mk
include usr/sbin/pkcsconf/pkcsconf.mk
