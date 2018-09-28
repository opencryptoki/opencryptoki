if ENABLE_ICSFTOK
include %D%/pkcsicsf/pkcsicsf.mk
endif
if ENABLE_PKCSEP11_MIGRATE
include %D%/pkcsep11_migrate/pkcsep11_migrate.mk
endif
if ENABLE_PKCSEP11_SESSION
include %D%/pkcsep11_session/pkcsep11_session.mk
endif
if ENABLE_CCATOK
include %D%/pkcscca/pkcscca.mk
endif

include %D%/pkcsslotd/pkcsslotd.mk
include %D%/pkcsconf/pkcsconf.mk
