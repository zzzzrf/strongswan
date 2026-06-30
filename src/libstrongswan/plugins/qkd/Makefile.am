AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

QKD_QSS_LIBDIR = $(abs_top_srcdir)/src/libstrongswan/plugins/qkd/platforms/x86test/libs

# shared by plugin and unit tests
noinst_LTLIBRARIES = libqkd-vendor-a.la libqkd-qss.la
libqkd_vendor_a_la_SOURCES = \
	platforms/vendor_a.h platforms/vendor_a.c

libqkd_qss_la_SOURCES = \
	platforms/platform_qss.c platforms/platform_qss.h platforms/qss_sdk.h

libqkd_qss_la_LIBADD = \
	-L$(QKD_QSS_LIBDIR) \
	-lqss_sdk -loqs -lcrypto -lssl -lrt -lpthread -ldl -lstdc++

libqkd_qss_la_LDFLAGS = \
	-Wl,-rpath,$(QKD_QSS_LIBDIR)

libstrongswan_qkd_la_LIBADD = libqkd-vendor-a.la libqkd-qss.la

if MONOLITHIC
noinst_LTLIBRARIES += libstrongswan-qkd.la
else
plugin_LTLIBRARIES = libstrongswan-qkd.la
endif

libstrongswan_qkd_la_SOURCES = \
	qkd_plugin.h qkd_plugin.c

libstrongswan_qkd_la_LDFLAGS = -module -avoid-version -Wl,-rpath,$(QKD_QSS_LIBDIR)

SUBDIRS = tests
