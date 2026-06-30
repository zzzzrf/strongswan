TESTS = qkd_tests

check_PROGRAMS = $(TESTS)

qkd_tests_SOURCES = \
	tests.h tests.c \
	suites/test_qkd_factory.c \
	suites/test_vendor_a.c	\
	suites/test_qss.c

qkd_tests_CFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libstrongswan/tests \
	-I$(top_srcdir)/src/libstrongswan/plugins/qkd \
	@COVERAGE_CFLAGS@

qkd_tests_LDFLAGS = @COVERAGE_LDFLAGS@
qkd_tests_LDADD = \
	../libqkd-vendor-a.la ../libqkd-qss.la \
	$(top_builddir)/src/libstrongswan/tests/libtest.la \
	$(top_builddir)/src/libstrongswan/libstrongswan.la
