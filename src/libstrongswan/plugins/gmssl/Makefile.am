AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-gmssl.la
else
plugin_LTLIBRARIES = libstrongswan-gmssl.la
endif

libstrongswan_gmssl_la_SOURCES = \
	gmssl_plugin.h gmssl_plugin.c	\
	gmssl_hasher.h gmssl_hasher.c	\
	gmssl_crypter.h gmssl_crypter.c	\
	gmssl_hmac.h gmssl_hmac.c

if USE_CUSTOM_EXT_ATTR_IKEV1_SM
libstrongswan_gmssl_la_SOURCES +=	\
	gmssl_sm2_private_key.h gmssl_sm2_private_key.c 	\
	gmssl_sm2_public_key.h gmssl_sm2_public_key.c 	\
	gmssl_util.h gmssl_util.c
endif

libstrongswan_gmssl_la_LDFLAGS = -module -avoid-version
libstrongswan_gmssl_la_LIBADD  = $(GMSSL_LIB) $(OPENSSL_LIB)
