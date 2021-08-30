nobase_lib_LTLIBRARIES += opencryptoki/stdll/libpkcs11_icsf.la

noinst_HEADERS +=							\
	usr/lib/icsf_stdll/icsf.h usr/lib/icsf_stdll/pbkdf.h		\
	usr/lib/icsf_stdll/icsf_config.h				\
	usr/lib/icsf_stdll/icsf_specific.h				\
	usr/lib/icsf_stdll/tok_struct.h

BUILT_SOURCES += usr/lib/icsf_stdll/icsf_config_parse.h
CLEANFILES +=								\
	usr/lib/icsf_stdll/icsf_config_lexer.c				\
	usr/lib/icsf_stdll/icsf_config_parse.c				\
	usr/lib/icsf_stdll/icsf_config_parse.h				\
	usr/lib/icsf_stdll/icsf_config_parse.output

opencryptoki_stdll_libpkcs11_icsf_la_CFLAGS =				\
	-DNOCDMF -DNODSA -DNODH	-DMMAP -I${srcdir}/usr/lib/icsf_stdll	\
	-I${srcdir}/usr/lib/common -I${srcdir}/usr/include		\
	-DSTDLL_NAME=\"icsftok\"					\
	-DTOK_NEW_DATA_STORE=0xffffffff					\
	-I${top_builddir}/usr/lib/icsf_stdll

opencryptoki_stdll_libpkcs11_icsf_la_LDFLAGS =				\
	-shared	-Wl,-z,defs,-Bsymbolic -lcrypto	-lldap -lpthread	\
	-lrt -llber							\
	-Wl,--version-script=${srcdir}/opencryptoki_tok.map

opencryptoki_stdll_libpkcs11_icsf_la_SOURCES =				\
	usr/lib/common/asn1.c usr/lib/common/dig_mgr.c			\
	usr/lib/common/hwf_obj.c usr/lib/common/trace.c			\
	usr/lib/common/key.c usr/lib/common/mech_dh.c			\
	usr/lib/common/mech_rng.c usr/lib/common/sign_mgr.c		\
	usr/lib/common/cert.c usr/lib/common/dp_obj.c			\
	usr/lib/common/mech_aes.c usr/lib/common/mech_rsa.c		\
	usr/lib/common/mech_ec.c usr/lib/common/obj_mgr.c		\
	usr/lib/common/template.c usr/lib/common/p11util.c		\
	usr/lib/common/data_obj.c usr/lib/common/encr_mgr.c		\
	usr/lib/common/key_mgr.c usr/lib/common/mech_md2.c		\
	usr/lib/common/mech_sha.c usr/lib/common/object.c		\
	usr/lib/common/decr_mgr.c usr/lib/common/globals.c		\
	usr/lib/common/sw_crypt.c usr/lib/common/loadsave.c		\
	usr/lib/common/utility.c usr/lib/common/mech_des.c		\
	usr/lib/common/mech_des3.c usr/lib/common/mech_md5.c		\
	usr/lib/common/mech_ssl3.c usr/lib/common/verify_mgr.c		\
	usr/lib/common/mech_list.c usr/lib/common/shared_memory.c	\
	usr/lib/common/attributes.c usr/lib/icsf_stdll/new_host.c	\
	usr/lib/common/profile_obj.c usr/lib/common/dlist.c		\
	usr/lib/icsf_stdll/pbkdf.c usr/lib/icsf_stdll/icsf_specific.c	\
	usr/lib/icsf_stdll/icsf_config_parse.y				\
	usr/lib/icsf_stdll/icsf_config_lexer.l				\
	usr/lib/icsf_stdll/icsf.c

if ENABLE_LOCKS
opencryptoki_stdll_libpkcs11_icsf_la_SOURCES +=				\
	usr/lib/common/lock_btree.c usr/lib/common/lock_sess_mgr.c
else
opencryptoki_stdll_libpkcs11_icsf_la_LDFLAGS += -litm
opencryptoki_stdll_libpkcs11_icsf_la_SOURCES +=				\
	usr/lib/common/btree.c usr/lib/common/sess_mgr.c
endif

usr/lib/icsf_stdll/icsf_config_parse.c usr/lib/icsf_stdll/icsf_config_parse.output: usr/lib/icsf_stdll/icsf_config_parse.y
	$(AM_V_YACC)$(am__skipyacc) $(SHELL) $(YLWRAP) $< icsf_config_parse.tab.c usr/lib/icsf_stdll/icsf_config_parse.c icsf_config_parse.tab.h usr/lib/icsf_stdll/icsf_config_parse.h icsf_config_parse.output usr/lib/icsf_stdll/icsf_config_parse.output -- $(YACCCOMPILE)

usr/lib/icsf_stdll/icsf_config_lexer.c usr/lib/icsf_stdll/icsf_config_lexer.h: usr/lib/icsf_stdll/icsf_config_lexer.l
	$(AM_V_LEX)$(am__skiplex) $(SHELL) $(YLWRAP) $< lex.yy.c usr/lib/icsf_stdll/icsf_config_lexer.c lex.yy.h usr/lib/icsf_stdll/icsf_config_lexer.h -- $(LEXCOMPILE)
