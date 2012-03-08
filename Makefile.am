AUTOMAKE_OPTIONS = foreign
include rpm.mk

pluginsdir = $(WIRESHARK_PLUGINS_DIR)
plugins_LTLIBRARIES=gluster.la

gluster_la_CFLAGS  = $(WIRESHARK_CFLAGS)
gluster_la_LDFLAGS = -rpath $(pluginsdir) -avoid-version -module
gluster_la_SOURCES = plugin.c
EXTRA_DIST = packet-gluster.patch
nodist_gluster_la_SOURCES = packet-gluster.c packet-gluster.h
BUILT_SOURCES = packet-gluster.c packet-gluster.h
CLEANFILES = packet-gluster.c packet-gluster.h
gluster_la_LIBADD = $(WIRESHARK_LIBS)

packet-gluster.patch: Makefile
	touch packet-gluster.patch
packet-gluster.c: packet-gluster.patch
	rm -f packet-gluster.c packet-gluster.h
	patch < $<
	ls -l
	sed -i -e 's,#include "packet-rpc.h",#include <dissectors/packet-rpc.h>,' -e 's,_U_,,' $@
packet-gluster.h: packet-gluster.c packet-gluster.patch
	:

EXTRA_DIST += gluster-wireshark-plugin.spec
