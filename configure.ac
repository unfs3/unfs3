AC_INIT(unfs3, 0.9.22) 
AC_CONFIG_HEADER(config.h)
AC_PROG_INSTALL
AC_PROG_CC([gcc egcs kgcc cc])
AC_PROG_LEX
AC_PROG_YACC
AC_HEADER_STDC
AC_SYS_LARGEFILE
AC_SEARCH_LIBS(xdr_int, nsl)
AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(inet_aton, resolv)
AC_CHECK_HEADERS(mntent.h,,,[#include <stdio.h>])
AC_CHECK_HEADERS(stdint.h,,,[#include <stdio.h>])
AC_CHECK_HEADERS(sys/mnttab.h,,,[#include <stdio.h>])
AC_CHECK_HEADERS(sys/mount.h,,,[#include <stdio.h>])
AC_CHECK_HEADERS(sys/vmount.h,,,[#include <stdio.h>])
AC_CHECK_HEADERS(rpc/svc_soc.h,,,[#include <rpc/rpc.h>])
AC_CHECK_HEADERS(linux/ext2_fs.h,,,[#include <unistd.h>])
AC_CHECK_TYPES(int32,,,[#include <sys/inttypes.h>])
AC_CHECK_TYPES(uint32,,,[#include <sys/inttypes.h>])
AC_CHECK_TYPES(int64,,,[#include <sys/inttypes.h>])
AC_CHECK_TYPES(uint64,,,[#include <sys/inttypes.h>])
AC_CHECK_MEMBERS([struct stat.st_gen],,,[#include <sys/stat.h>])
AC_CHECK_MEMBERS([struct __rpc_svcxprt.xp_fd],,,[#include <rpc/rpc.h>])
AC_CHECK_FUNCS(xdr_long xdr_int32 xdr_u_long xdr_uint32)
AC_CHECK_FUNCS(xdr_uint64 xdr_uint64_t xdr_u_int64_t)
AC_CHECK_FUNCS(statvfs)
AC_CHECK_FUNCS(seteuid setegid)
AC_CHECK_FUNCS(setresuid setresgid)
AC_CHECK_FUNCS(vsyslog)
AC_CHECK_FUNCS(lchown)
AC_CHECK_FUNCS(setgroups)
UNFS3_SOLARIS_RPC
UNFS3_PORTMAP_DEFINE
UNFS3_COMPILE_WARNINGS
AC_ARG_ENABLE(cluster,[  --enable-cluster        include clustering extensions],[AC_DEFINE([WANT_CLUSTER], [], [Cluster extensions]) AC_SUBST([SUBDIRS],[Extras]) AC_SUBST([EXTRAOBJ],[Extras/lib.a])])
AC_OUTPUT(Makefile Config/Makefile Extras/Makefile)
