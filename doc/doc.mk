doc_DATA = doc/strength-example.conf doc/opencryptoki-howto.md doc/README.token_data
nodist_doc_DATA = doc/policy-example.conf

doc/policy-example.conf: tools/policyexamplegen
	$(AM_V_GEN) $(MKDIR_P) doc && tools/policyexamplegen > doc/policy-example.conf

EXTRA_DIST += $(doc_DATA)
CLEANFILES += doc/policy-example.conf

if ENABLE_CCATOK
EXTRA_DIST += doc/README.cca_stdll
endif
if ENABLE_EP11TOK
EXTRA_DIST += doc/README.ep11_stdll
endif
if ENABLE_ICSFTOK
EXTRA_DIST += doc/README.icsf_stdll
endif
if ENABLE_TPMTOK
EXTRA_DIST += doc/README.tpm_stdll
endif
