doc_DATA = doc/strength-example.conf
nodist_doc_DATA = doc/policy-example.conf

doc/policy-example.conf: tools/policyexamplegen
	$(AM_V_GEN) $(MKDIR_P) doc && tools/policyexamplegen > doc/policy-example.conf

EXTRA_DIST += $(doc_DATA)
