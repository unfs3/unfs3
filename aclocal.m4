dnl Special rpc library for Solaris
dnl
AC_DEFUN([UNFS3_SOLARIS_RPC],[
  AC_CHECK_FUNC(svc_tli_create, [
    # On Solaris, you must link with librpcsoc, or the binaries won't work. 
    LDFLAGS="-L/usr/ucblib -R/usr/ucblib $LDFLAGS"
    AC_CHECK_LIB(rpcsoc, svctcp_create, 
        [ LIBS="-lrpcsoc $LIBS" ],
        [ AC_MSG_WARN([*** Cannot find librpcsoc. On Solaris, install package SUNWscpu. ***]) ]
    )
  ])
])
dnl PORTMAP define needed for Solaris
dnl
AC_DEFUN([UNFS3_PORTMAP_DEFINE],[
  AC_DEFINE([PORTMAP], [], [Define to an empty value if you use Solaris.])
])
dnl Set compiler warnings for gcc
dnl
AC_DEFUN([UNFS3_COMPILE_WARNINGS],[
  if test "$GCC" = "yes"
  then
    CFLAGS="$CFLAGS -Wall -W"
  fi
])
