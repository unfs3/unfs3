AC_INIT([unfs3],[0.10.0])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_HEADER(config.h)
AC_PROG_INSTALL
AC_PROG_CC([gcc egcs kgcc cc])
AC_CHECK_TOOL([AR], [ar])
AC_PROG_LEX
AS_IF([test "x$LEX" == "x:"], [
  AC_MSG_ERROR([flex or lex missing.])
])
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
AC_CHECK_FUNCS(statvfs)
AC_CHECK_FUNCS(seteuid setegid)
AC_CHECK_FUNCS(setresuid setresgid)
AC_CHECK_FUNCS(vsyslog)
AC_CHECK_FUNCS(lchown)
AC_CHECK_FUNCS(setgroups)
AC_CHECK_FUNCS(lutimes)
UNFS3_COMPILE_WARNINGS

PKG_CHECK_MODULES([TIRPC], [libtirpc])
AC_SUBST(TIRPC_CFLAGS)
AC_SUBST(TIRPC_LIBS)

saved_CPPFLAGS="$CPPFLAGS"
saved_LIBS="$LIBS"
CPPFLAGS="$CPPFLAGS $TIRPC_CFLAGS"
LIBS="$LIBS $TIRPC_LIBS"
AC_CHECK_FUNCS(svc_getreq_poll)
# Old libtirpc has not implement poll() fully
AC_CHECK_DECLS(svc_pollfd,,,[#include <rpc/rpc.h>])
CPPFLAGS="$saved_CPPFLAGS"
LIBS="$saved_LIBS"

AC_ARG_ENABLE(afs,
	AS_HELP_STRING([--enable-afs], [include better support for exporting from AFS]),
	[AC_DEFINE([AFS_SUPPORT], [], [Enable better support for exporting from AFS])])

AC_ARG_WITH(afs-prefix,
	AS_HELP_STRING([--with-afs-prefix=PFX], [use AFS libs installed under PFX]),
	[AFS_INCLUDES="-I$withval/include"
	 AFS_LIBS="-L$withval/lib/afs"],
	[AFS_INCLUDES=""
	 AFS_LIBS="-L/usr/lib/afs"])

AFS_LIBS="$AFS_LIBS -lsys -lrx -lafsutil -llwp"

if test "_$enable_afs" != _yes
then
	AFS_INCLUDES=
	AFS_LIBS=
fi

AC_SUBST([AFS_INCLUDES])
AC_SUBST([AFS_LIBS])

AC_ARG_ENABLE(cluster,
	AS_HELP_STRING([--enable-cluster], [include clustering extensions]),
	[AC_DEFINE([WANT_CLUSTER], [], [Cluster extensions])
	 SUBDIRS=Extras
	 EXTRAOBJ=Extras/lib.a],
	[SUBDIRS=
	 EXTRAOBJ=])

AC_SUBST([SUBDIRS])
AC_SUBST([EXTRAOBJ])

AC_CONFIG_FILES([Makefile Config/Makefile Extras/Makefile])
AC_OUTPUT
