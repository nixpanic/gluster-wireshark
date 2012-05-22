AUTOMAKE_OPTIONS = foreign
include rpm.mk

BUILT_SOURCES = \
	packet-gluster.c \
	packet-gluster.h \
	packet-gluster_cli.c \
	packet-gluster_dump.c \
	packet-gluster_gd_mgmt.c \
	packet-gluster_hndsk.c \
	packet-gluster_pmap.c \
	packet-glusterfs.c

CLEANFILES = $(BUILT_SOURCES) explode-patch

pluginsdir = $(WIRESHARK_PLUGINS_DIR)
plugins_LTLIBRARIES=gluster.la

gluster_la_CFLAGS  = $(WIRESHARK_CFLAGS)
gluster_la_LDFLAGS = -rpath $(pluginsdir) -avoid-version -module
gluster_la_SOURCES = plugin.c
EXTRA_DIST = packet-gluster.patch
nodist_gluster_la_SOURCES = $(BUILT_SOURCES)

gluster_la_LIBADD = $(WIRESHARK_LIBS)

explode-patch: packet-gluster.patch
	rm -f $(BUILT_SOURCES)
	patch < $<
	echo "patch exploded" > explode-patch

$(BUILT_SOURCES): explode-patch
	sed -i -e 's,#include "packet-rpc.h",#include <dissectors/packet-rpc.h>,' -e 's,_U_,,' $@

EXTRA_DIST += wireshark-plugin-gluster.spec
