dnl Special rpc library for Solaris
dnl
AC_DEFUN([UNFS3_SOLARIS_RPC],[
  AC_CHECK_FUNC(svc_tli_create, [
    # On Solaris, you must link with librpcsoc, or the binaries won't work. 
    LDFLAGS="-L=/usr/ucblib -R/usr/ucblib $LDFLAGS"
    AC_CHECK_LIB(rpcsoc, svctcp_create, 
        [ LIBS="-lrpcsoc $LIBS" ],
        [ AC_MSG_WARN([*** Cannot find librpcsoc. On Solaris, install package SUNWscpu. ***]) ]
    )
  ])
])
