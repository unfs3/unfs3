dnl Special rpc library for Solaris
dnl
AC_DEFUN([UNFS3_SOLARIS_RPC],[
  AC_CHECK_FUNC(svc_tli_create, [
    # On Solaris, you must link with librpcsoc, or the binaries won't work. 
    LDFLAGS="-L/usr/ucblib -R/usr/ucblib $LDFLAGS"
    AC_CHECK_LIB(rpcsoc, svctcp_create, 
        [ LIBS="-lrpcsoc $LIBS" ],
        [ AC_MSG_ERROR([*** Cannot find librpcsoc. Install package SUNWscpu. ***]) ]
    )
  ])
])
dnl PORTMAP define needed for Solaris
dnl
AC_DEFUN([UNFS3_PORTMAP_DEFINE],[
  AC_DEFINE([PORTMAP], [], [Define to an empty value if you use Solaris.])
])
dnl Available from the GNU Autoconf Macro Archive at:
dnl http://www.gnu.org/software/ac-archive/htmldoc/ac_compile_warnings.html
dnl
AC_DEFUN([AC_COMPILE_WARNINGS],
[AC_MSG_CHECKING(maximum warning verbosity option)
if test -n "$CXX"
then
  if test "$GXX" = "yes"
  then
    ac_compile_warnings_opt='-Wall'
  fi
  CXXFLAGS="$CXXFLAGS $ac_compile_warnings_opt"
  ac_compile_warnings_msg="$ac_compile_warnings_opt for C++"
fi

if test -n "$CC"
then
  if test "$GCC" = "yes"
  then
    ac_compile_warnings_opt='-Wall'
  fi
  CFLAGS="$CFLAGS $ac_compile_warnings_opt"
  ac_compile_warnings_msg="$ac_compile_warnings_msg $ac_compile_warnings_opt for C"
fi
AC_MSG_RESULT($ac_compile_warnings_msg)
unset ac_compile_warnings_msg
unset ac_compile_warnings_opt
])
