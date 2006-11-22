noinst_LTLIBRARIES = opencryptoki/libcommon.la

AM_CFLAGS = -DSPINXPL -DNOCDMF -DNOMD2 -DNODSA \
	    -fPIC -I/usr/include -I. \
	    -I../../../include/pkcs11/stdll \
	    -I../../../include/pkcs11 

# don't know about mech_dsa.c yet
opencryptoki_libcommon_la_SOURCES = asn1.c \
			     cert.c	  \
			     hwf_obj.c	  \
			     dp_obj.c	  \
			     data_obj.c	  \
			     decr_mgr.c	  \
			     dig_mgr.c	  \
			     encr_mgr.c	  \
			     globals.c	  \
			     loadsave.c	  \
			     key.c	  \
			     key_mgr.c	  \
			     mech_aes.c	  \
			     mech_des.c	  \
			     mech_des3.c  \
			     mech_dh.c	  \
			     mech_md5.c	  \
			     mech_md2.c	  \
			     mech_rng.c	  \
			     mech_rsa.c	  \
			     mech_sha.c	  \
			     mech_ssl3.c  \
			     new_host.c	  \
			     obj_mgr.c	  \
			     object.c	  \
			     sess_mgr.c	  \
			     sign_mgr.c	  \
			     template.c	  \
			     utility.c	  \
			     verify_mgr.c \
			     log.c	  \
			     sw_default.c 
