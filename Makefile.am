SUBDIRS = usr testcases
SPEC=rpm//openCryptoki-$(shell uname -m).spec

rpm: ${SPEC}
	rm -rf /usr/src/openCryptoki
	mkdir -p /usr/src/openCryptoki/BUILD
	mkdir -p /usr/src/openCryptoki/RPMS/$(shell uname -m)
	mkdir -p /usr/src/openCryptoki/SRPMS
	mkdir -p /usr/src/openCryptoki/SPEC
	mkdir -p /usr/src/openCryptoki/SOURCES
	tar zcf /usr/src/openCryptoki/SOURCES/openCryptoki.tar.gz ./*
	rpmbuild -bb ${SPEC} || rpm -bb ${SPEC}
#	rpmbuild -bb rpm/openCryptoki-debug.spec

${SPEC}:
	if [ ! -e ${SPEC} ]; then \
	ln -s openCryptoki.spec ${SPEC}; fi

.PHONY: rpm
