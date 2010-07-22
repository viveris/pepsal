#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59e)
AC_INIT(PEPSaL, 2.0.0)
AC_CONFIG_SRCDIR(src)
AC_CONFIG_HEADER(include/config.h)
AM_INIT_AUTOMAKE(-Wall -Werror foreign)
# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET                                                                                        
AC_PROG_RANLIB

AC_CHECK_LIB([netfilter_queue], [nfq_handle_packet],,check_nfqueue="no")
AC_CHECK_LIB([nfnetlink], [nfnl_open],,check_nfnetlink="no")
AC_CHECK_LIB([pthread], [pthread_create],,check_pthread="no")
AC_CHECK_LIB([rt], [timer_create],,check_rt="no")
AC_CHECK_LIB([m], [ceil],,check_m="no")

if test \
      x${check_nfqueue} = xno \
   -o x${check_nfnetlink} = xno \
   -o x${check_pthread} = xno \
   -o x${check_rt} = xno \
   -o x${check_m} = xno \
   ; then
   AC_MSG_RESULT([])
   if test x${check_nfqueue} = xno; then 
      AC_MSG_RESULT([ERROR: libnetfilter-queue required])
   fi
   if test x${check_nfnetlink} = xno; then
      AC_MSG_RESULT([ERROR: libnfnetlink required])
   fi
   if test x${check_pthread} = xno; then
      AC_MSG_RESULT([ERROR: libpthread required])
   fi
   if test x${check_rt} = xno; then
      AC_MSG_RESULT([ERROR: librt required])
   fi
   if test x${check_m} = xno; then
      AC_MSG_RESULT([ERROR: libm required])
   fi
   exit 1
fi

# Add required libraries to LDFLAGS
[ LDFLAGS="$LDFKAGS -lnfnetlink -lnetfilter_queue -lpthread -lrt -lm" ]

AC_ARG_ENABLE(debug,
        AC_HELP_STRING([--enable-debug], [enable debugging: yes|no (default=no)]),
        [enable_debug=$enableval],
        [enable_debug="no"])

if test x${enable_debug} = xno; then
   AC_DEFINE([NDEBUG], 1, "Disable assertions")
fi

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h time.h ])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gethostbyname memset socket timer_create timer_settime])

AC_CONFIG_FILES(Makefile 
                src/Makefile)
AC_OUTPUT
