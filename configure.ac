#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.50])
AC_INIT(pubcFS, 0.1, miro.mannino@gmail.com)
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR([src/fuse_operations.h])
AC_CONFIG_HEADERS([config.h])
AC_LANG_C
AC_PREFIX_DEFAULT(/usr/local)

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX	
AC_PROG_LIBTOOL
AM_PROG_CC_C_O
AC_PROG_INSTALL

CFLAGS="-D_FILE_OFFSET_BITS=64 -Wall -g"
LDFLAGS="-L/usr/lib -L/usr/local/lib"

# Checks for libraries.
AC_CHECK_LIB(fuse,fuse_main,
	[FUSE_LIBS="-lfuse"],
    [AC_MSG_ERROR([ fuse library not found: use -L in LDFLAGS for configure
    				the search path (for example: "export LDFLAGS=-L/usr/lib" ])],)
AC_SUBST(FUSE_LIBS)
AC_CHECK_LIB(m,ceil,
	[MATH_LIBS="-lm"],
    [AC_MSG_ERROR([ math library not found: use -L in LDFLAGS for configure
    				the search path (for example: "export LDFLAGS=-L/usr/lib" ])],)
AC_SUBST(MATH_LIBS)
AC_CHECK_LIB(crypto,EVP_EncryptInit_ex,
	[CRYPTO_LIBS="-lcrypto"],
    [AC_MSG_ERROR([ crypto library not found: use -L in LDFLAGS for configure
    				the search path (for example: "export LDFLAGS=-L/usr/lib" ])],)
AC_SUBST(CRYPTO_LIBS)


# Checks for header files.
AC_CHECK_HEADERS([ \
	fuse.h \ 
	sys/types.h \ 
	sys/stat.h \
	errno.h \
	unistd.h \
	fcntl.h \
	stdint.h \
	stdlib.h \
	string.h \
	openssl/evp.h \
	openssl/aes.h
])


# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_INT8_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset])

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])

AC_OUTPUT
