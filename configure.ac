#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59e)
AC_INIT(PEPSaL, 1.2.2)
AC_CONFIG_SRCDIR(src)
AC_CONFIG_HEADER(include/config.h)
AM_INIT_AUTOMAKE(-Wall -Werror foreign)
# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET                                                                                        
AC_PROG_RANLIB

# Checks for libraries.
AC_CHECK_LIB([netfilter_queue], [nfq_handle_packet], ,AC_MSG_ERROR([   ***   Unable to find netfilter-queue library.]))
AC_CHECK_LIB([nfnetlink], [nfnl_open], , AC_MSG_ERROR([   ***   Unable to find nfnetlink library.]))
AC_CHECK_LIB([pthread], [pthread_create], , AC_MSG_ERROR([   ***   Unable to find pthread library.]))


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
