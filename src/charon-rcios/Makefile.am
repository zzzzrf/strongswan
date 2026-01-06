sbin_PROGRAMS = charon-rcios

charon_rcios_SOURCES = \
	charon_rcios.c \
	rcios_dispatcher.c	rcios_socket.c	\
	rcios_client.c \
	rcios_config.c \
	rcios_cmds.c

charon_rcios.o :	$(top_builddir)/config.status

charon_rcios_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon \
	-DPLUGINS=\""${charon_plugins}\""

charon_rcios_LDADD = \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	$(top_builddir)/src/libcharon/libcharon.la \
	-lm $(PTHREADLIB) $(ATOMICLIB) $(DLLIB)
