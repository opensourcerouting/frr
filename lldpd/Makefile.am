## Process this file with automake to produce Makefile.in.

AM_CPPFLAGS = -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

AM_CFLAGS = $(PICFLAGS) -g
AM_LDFLAGS = $(PILDFLAGS)

noinst_LIBRARIES = liblldp.a
sbin_PROGRAMS = lldpd

liblldp_a_SOURCES = lldp_interface.c lldp_zebra.c lldp_db.c \
	lldpd.c lldp_neighbor.c lldp_write.c lldp_read.c lldp_packet.c lldp_socket.c 
#	priv.c privsep_fdpass.c agent.c agent_priv.c

noinst_HEADERS = \
	lldpd.h lldp_db.h lldp_neighbor.h lldp_interface.h lldp_packet.h lldp_socket.h

lldpd_SOURCES = lldp_main.c $(liblldp_a_SOURCES)

#lldpctl_SOURCES = lldpctl.c log.c ctl.c

lldpd_LDADD = ../lib/libzebra.la @LIBCAP@
#lldpctl_LDADD = ../lib/libzebra.la @LIBCAP@

