#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59e)
AC_INIT(PEPSaL, 1.2.2)
AC_CONFIG_SRCDIR([pep.c])
AC_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE()
# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([netfilter_queue], [nfq_handle_packet])
AC_CHECK_LIB([nfnetlink], [nfnl_open])

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gethostbyname memset socket])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
