AC_INIT(fd_cache.c)
AC_CONFIG_HEADER(config.h)
AC_PROG_INSTALL
AC_PROG_CC([gcc egcs kgcc cc])
AC_COMPILE_WARNINGS
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
AC_CHECK_HEADERS(rpc/svc_soc.h,,,[#include <rpc/types.h> #include <rpc/rpc.h>])
AC_CHECK_HEADERS(linux/ext2_fs.h,,,[#include <unistd.h>])
AC_CHECK_TYPES(int32,,,[#include <stdio.h> #include <sys/inttypes.h>])
AC_CHECK_TYPES(uint32,,,[#include <stdio.h> #include <sys/inttypes.h>])
AC_CHECK_TYPES(int64,,,[#include <stdio.h> #include <sys/inttypes.h>])
AC_CHECK_TYPES(uint64,,,[#include <stdio.h> #include <sys/inttypes.h>])
AC_CHECK_MEMBERS([struct stat.st_gen],,,[#include <sys/stat.h>])
AC_CHECK_FUNCS(xdr_long xdr_int32 xdr_u_long xdr_uint32)
AC_CHECK_FUNCS(xdr_int64 xdr_int64_t)
AC_CHECK_FUNCS(xdr_uint64 xdr_uint64_t xdr_u_int64_t)
AC_CHECK_FUNCS(statvfs)
AC_CHECK_FUNCS(seteuid setegid)
AC_CHECK_FUNCS(setresuid setresgid)
AC_CHECK_FUNCS(vsyslog)
AC_ARG_ENABLE(cluster,[  --enable-cluster        include clustering extensions],[AC_DEFINE([WANT_CLUSTER], [], [Cluster extensions]) AC_SUBST([SUBDIRS],[Extras]) AC_SUBST([EXTRAOBJ],[Extras/lib.a])])

AC_CHECK_FUNC(svc_tli_create, [
    # On Solaris, you must link with librpcsoc, or the binaries won't work. 
    LDFLAGS="-L/usr/ucblib -R/usr/ucblib $LDFLAGS"
    AC_CHECK_LIB(rpcsoc, svctcp_create, 
        [ LIBS="-lrpcsoc $LIBS" ],
        [ AC_MSG_ERROR([*** Cannot find librpcsoc. Install package SUNWscpu. ***]) ]
    )
])

AC_OUTPUT(Makefile Config/Makefile Extras/Makefile)
