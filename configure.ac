AC_INIT(fd_cache.c)
AC_CONFIG_HEADER(config.h)
AC_PROG_INSTALL
AC_PROG_CC([gcc egcs kgcc])
AC_PROG_LEX
AC_PROG_YACC
AC_HEADER_STDC
AC_SYS_LARGEFILE
AC_SEARCH_LIBS(xdr_int, nsl)
AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(inet_aton, resolv)
AC_CHECK_HEADERS(mntent.h,,,[#include <stdio.h>])
AC_CHECK_HEADERS(rpc/svc_soc.h,,,[#include <rpc/types.h>
#include <rpc/rpc.h>])
AC_CHECK_HEADERS(linux/ext2_fs.h,,,[#include <unistd.h>])
AC_CHECK_TYPES(rpc_inline_t,,,[#include <rpc/types.h>])
AC_CHECK_MEMBERS([struct stat.st_gen],,,[#include <sys/stat.h>])
AC_CHECK_FUNCS(xdr_u_int64_t)
AC_CHECK_FUNCS(statvfs)
AC_ARG_ENABLE(cluster,[  --enable-cluster        include clustering extensions],[AC_DEFINE([WANT_CLUSTER], [], [Cluster extensions]) AC_SUBST([SUBDIRS],[Extras]) AC_SUBST([EXTRAOBJ],[Extras/lib.a])])
AC_OUTPUT(Makefile Config/Makefile Extras/Makefile)
