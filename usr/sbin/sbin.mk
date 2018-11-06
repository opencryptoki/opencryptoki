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

include usr/sbin/pkcsslotd/pkcsslotd.mk
include usr/sbin/pkcsconf/pkcsconf.mk
