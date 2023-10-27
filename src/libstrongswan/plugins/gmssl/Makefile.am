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

libstrongswan_gmssl_la_LDFLAGS = -module -avoid-version
libstrongswan_gmssl_la_LIBADD  = $(GMSSL_LIB)
