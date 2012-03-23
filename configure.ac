m4_define([pkg_name],    [wireshark-plugin-gluster])
m4_define([pkg_verison], [0.0.0])

AC_INIT(pkg_name, pkg_verison)
AM_INIT_AUTOMAKE([no-dist-gzip dist-bzip2])

AC_PROG_CC
AC_PROG_CC_STDC

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AM_PATH_WIRESHARK
WIRESHARK_PLUGINS_DIR=`pkg-config --variable=libdir wireshark`/wireshark/plugins/$WIRESHARK_VERSION
AC_SUBST(WIRESHARK_PLUGINS_DIR)

AC_OUTPUT([Makefile wireshark-plugin-gluster.spec])
