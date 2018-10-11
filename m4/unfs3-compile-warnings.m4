dnl Set compiler warnings for gcc
dnl
AC_DEFUN([UNFS3_COMPILE_WARNINGS],[
  if test "$GCC" = "yes"
  then
    CFLAGS="$CFLAGS -Wall -W"
  fi
])
