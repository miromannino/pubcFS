# Makefile.in generated by automake 1.11.1 from Makefile.am.
# src/Makefile.  Generated from Makefile.in by configure.

# Copyright (C) 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002,
# 2003, 2004, 2005, 2006, 2007, 2008, 2009  Free Software Foundation,
# Inc.
# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.





pkgdatadir = $(datadir)/pubcfs
pkgincludedir = $(includedir)/pubcfs
pkglibdir = $(libdir)/pubcfs
pkglibexecdir = $(libexecdir)/pubcfs
am__cd = CDPATH="$${ZSH_VERSION+.}$(PATH_SEPARATOR)" && cd
install_sh_DATA = $(install_sh) -c -m 644
install_sh_PROGRAM = $(install_sh) -c
install_sh_SCRIPT = $(install_sh) -c
INSTALL_HEADER = $(INSTALL_DATA)
transform = $(program_transform_name)
NORMAL_INSTALL = :
PRE_INSTALL = :
POST_INSTALL = :
NORMAL_UNINSTALL = :
PRE_UNINSTALL = :
POST_UNINSTALL = :
build_triplet = i686-pc-linux-gnu
host_triplet = i686-pc-linux-gnu
bin_PROGRAMS = pubcfs$(EXEEXT) pubcfs-config$(EXEEXT)
subdir = src
DIST_COMMON = $(srcdir)/Makefile.am $(srcdir)/Makefile.in
ACLOCAL_M4 = $(top_srcdir)/aclocal.m4
am__aclocal_m4_deps = $(top_srcdir)/configure.ac
am__configure_deps = $(am__aclocal_m4_deps) $(CONFIGURE_DEPENDENCIES) \
	$(ACLOCAL_M4)
mkinstalldirs = $(install_sh) -d
CONFIG_HEADER = $(top_builddir)/config.h
CONFIG_CLEAN_FILES =
CONFIG_CLEAN_VPATH_FILES =
LTLIBRARIES = $(noinst_LTLIBRARIES)
libbase64_la_LIBADD =
am_libbase64_la_OBJECTS = libbase64_la-base64.lo
libbase64_la_OBJECTS = $(am_libbase64_la_OBJECTS)
libbase64_la_LINK = $(LIBTOOL) --tag=CC $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=link $(CCLD) $(libbase64_la_CFLAGS) \
	$(CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@
am__DEPENDENCIES_1 =
libfuseoperations_la_DEPENDENCIES = $(am__DEPENDENCIES_1)
am_libfuseoperations_la_OBJECTS =  \
	libfuseoperations_la-fuse_operations.lo
libfuseoperations_la_OBJECTS = $(am_libfuseoperations_la_OBJECTS)
libfuseoperations_la_LINK = $(LIBTOOL) --tag=CC $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=link $(CCLD) \
	$(libfuseoperations_la_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) \
	$(LDFLAGS) -o $@
libmconfig_la_LIBADD =
am_libmconfig_la_OBJECTS = libmconfig_la-mConfig.lo
libmconfig_la_OBJECTS = $(am_libmconfig_la_OBJECTS)
libmconfig_la_LINK = $(LIBTOOL) --tag=CC $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=link $(CCLD) $(libmconfig_la_CFLAGS) \
	$(CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@
libpubcfsfunctions_la_DEPENDENCIES = libutil.la libbase64.la \
	$(am__DEPENDENCIES_1) $(am__DEPENDENCIES_1) \
	$(am__DEPENDENCIES_1)
am_libpubcfsfunctions_la_OBJECTS = libpubcfsfunctions_la-pubcfs.lo
libpubcfsfunctions_la_OBJECTS = $(am_libpubcfsfunctions_la_OBJECTS)
libpubcfsfunctions_la_LINK = $(LIBTOOL) --tag=CC $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=link $(CCLD) \
	$(libpubcfsfunctions_la_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) \
	$(LDFLAGS) -o $@
libutil_la_DEPENDENCIES = $(am__DEPENDENCIES_1) $(am__DEPENDENCIES_1)
am_libutil_la_OBJECTS = libutil_la-util.lo
libutil_la_OBJECTS = $(am_libutil_la_OBJECTS)
libutil_la_LINK = $(LIBTOOL) --tag=CC $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=link $(CCLD) $(libutil_la_CFLAGS) \
	$(CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@
am__installdirs = "$(DESTDIR)$(bindir)"
PROGRAMS = $(bin_PROGRAMS)
am_pubcfs_OBJECTS = pubcfs-main.$(OBJEXT)
pubcfs_OBJECTS = $(am_pubcfs_OBJECTS)
pubcfs_DEPENDENCIES = libfuseoperations.la libpubcfsfunctions.la \
	libutil.la libmconfig.la $(am__DEPENDENCIES_1) \
	$(am__DEPENDENCIES_1) $(am__DEPENDENCIES_1)
pubcfs_LINK = $(LIBTOOL) --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) \
	--mode=link $(CCLD) $(pubcfs_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) \
	$(LDFLAGS) -o $@
am_pubcfs_config_OBJECTS = pubcfs_config-pubcfs-config.$(OBJEXT)
pubcfs_config_OBJECTS = $(am_pubcfs_config_OBJECTS)
pubcfs_config_DEPENDENCIES = libpubcfsfunctions.la libutil.la \
	libmconfig.la $(am__DEPENDENCIES_1)
pubcfs_config_LINK = $(LIBTOOL) --tag=CC $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=link $(CCLD) $(pubcfs_config_CFLAGS) \
	$(CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@
DEFAULT_INCLUDES = -I. -I$(top_builddir)
depcomp = $(SHELL) $(top_srcdir)/config/depcomp
am__depfiles_maybe = depfiles
am__mv = mv -f
COMPILE = $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	$(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
LTCOMPILE = $(LIBTOOL) --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) \
	--mode=compile $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) \
	$(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
CCLD = $(CC)
LINK = $(LIBTOOL) --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) \
	--mode=link $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) \
	$(LDFLAGS) -o $@
SOURCES = $(libbase64_la_SOURCES) $(libfuseoperations_la_SOURCES) \
	$(libmconfig_la_SOURCES) $(libpubcfsfunctions_la_SOURCES) \
	$(libutil_la_SOURCES) $(pubcfs_SOURCES) \
	$(pubcfs_config_SOURCES)
DIST_SOURCES = $(libbase64_la_SOURCES) $(libfuseoperations_la_SOURCES) \
	$(libmconfig_la_SOURCES) $(libpubcfsfunctions_la_SOURCES) \
	$(libutil_la_SOURCES) $(pubcfs_SOURCES) \
	$(pubcfs_config_SOURCES)
ETAGS = etags
CTAGS = ctags
DISTFILES = $(DIST_COMMON) $(DIST_SOURCES) $(TEXINFOS) $(EXTRA_DIST)
ACLOCAL = ${SHELL} /home/miro/Università/TESI/pubcFS/config/missing --run aclocal-1.11
AMTAR = ${SHELL} /home/miro/Università/TESI/pubcFS/config/missing --run tar
AR = ar
AUTOCONF = ${SHELL} /home/miro/Università/TESI/pubcFS/config/missing --run autoconf
AUTOHEADER = ${SHELL} /home/miro/Università/TESI/pubcFS/config/missing --run autoheader
AUTOMAKE = ${SHELL} /home/miro/Università/TESI/pubcFS/config/missing --run automake-1.11
AWK = mawk
CC = gcc
CCDEPMODE = depmode=gcc3
CFLAGS = -D_FILE_OFFSET_BITS=64 -Wall -g
CPP = gcc -E
CPPFLAGS = 
CRYPTO_LIBS = -lcrypto
CXX = g++
CXXCPP = g++ -E
CXXDEPMODE = depmode=gcc3
CXXFLAGS = -g -O2
CYGPATH_W = echo
DEFS = -DHAVE_CONFIG_H
DEPDIR = .deps
DSYMUTIL = 
DUMPBIN = 
ECHO_C = 
ECHO_N = -n
ECHO_T = 
EGREP = /bin/grep -E
EXEEXT = 
FGREP = /bin/grep -F
FUSE_LIBS = -lfuse
GREP = /bin/grep
INSTALL = /usr/bin/install -c
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_PROGRAM = ${INSTALL}
INSTALL_SCRIPT = ${INSTALL}
INSTALL_STRIP_PROGRAM = $(install_sh) -c -s
LD = /usr/bin/ld
LDFLAGS = -L/usr/lib -L/usr/local/lib
LIBOBJS = 
LIBS = 
LIBTOOL = $(SHELL) $(top_builddir)/libtool
LIPO = 
LN_S = ln -s
LTLIBOBJS = 
MAKEINFO = ${SHELL} /home/miro/Università/TESI/pubcFS/config/missing --run makeinfo
MATH_LIBS = -lm
MKDIR_P = /bin/mkdir -p
NM = /usr/bin/nm -B
NMEDIT = 
OBJDUMP = objdump
OBJEXT = o
OTOOL = 
OTOOL64 = 
PACKAGE = pubcfs
PACKAGE_BUGREPORT = miro.mannino@gmail.com
PACKAGE_NAME = pubcFS
PACKAGE_STRING = pubcFS 0.1
PACKAGE_TARNAME = pubcfs
PACKAGE_URL = 
PACKAGE_VERSION = 0.1
PATH_SEPARATOR = :
RANLIB = ranlib
SED = /bin/sed
SET_MAKE = 
SHELL = /bin/bash
STRIP = strip
VERSION = 0.1
abs_builddir = /home/miro/Università/TESI/pubcFS/src
abs_srcdir = /home/miro/Università/TESI/pubcFS/src
abs_top_builddir = /home/miro/Università/TESI/pubcFS
abs_top_srcdir = /home/miro/Università/TESI/pubcFS
ac_ct_CC = gcc
ac_ct_CXX = g++
ac_ct_DUMPBIN = 
am__include = include
am__leading_dot = .
am__quote = 
am__tar = ${AMTAR} chof - "$$tardir"
am__untar = ${AMTAR} xf -
bindir = ${exec_prefix}/bin
build = i686-pc-linux-gnu
build_alias = 
build_cpu = i686
build_os = linux-gnu
build_vendor = pc
builddir = .
datadir = ${datarootdir}
datarootdir = ${prefix}/share
docdir = ${datarootdir}/doc/${PACKAGE_TARNAME}
dvidir = ${docdir}
exec_prefix = ${prefix}
host = i686-pc-linux-gnu
host_alias = 
host_cpu = i686
host_os = linux-gnu
host_vendor = pc
htmldir = ${docdir}
includedir = ${prefix}/include
infodir = ${datarootdir}/info
install_sh = ${SHELL} /home/miro/Università/TESI/pubcFS/config/install-sh
libdir = ${exec_prefix}/lib
libexecdir = ${exec_prefix}/libexec
localedir = ${datarootdir}/locale
localstatedir = ${prefix}/var
lt_ECHO = echo
mandir = ${datarootdir}/man
mkdir_p = /bin/mkdir -p
oldincludedir = /usr/include
pdfdir = ${docdir}
prefix = /usr/local
program_transform_name = s,x,x,
psdir = ${docdir}
sbindir = ${exec_prefix}/sbin
sharedstatedir = ${prefix}/com
srcdir = .
sysconfdir = ${prefix}/etc
target_alias = 
top_build_prefix = ../
top_builddir = ..
top_srcdir = ..
pubcfs_SOURCES = main.c
pubcfs_CFLAGS = \
	-DFUSE_USE_VERSION=26 \
	$(FUSE_CFLAGS) $(CRYPTO_CFLAGS) $(MATH_CFLAGS)

pubcfs_LDADD = \
	libfuseoperations.la \
	libpubcfsfunctions.la \
	libutil.la \
	libmconfig.la \
	$(FUSE_LIBS) $(CRYPTO_LIBS) $(MATH_LIBS)

pubcfs_config_SOURCES = pubcfs-config.c
pubcfs_config_CFLAGS = \
	$(CRYPTO_CFLAGS)

pubcfs_config_LDADD = \
	libpubcfsfunctions.la \
	libutil.la \
	libmconfig.la \
	$(CRYPTO_LIBS)

noinst_LTLIBRARIES = libfuseoperations.la libpubcfsfunctions.la libutil.la libmconfig.la libbase64.la

#base64 ---------------------------------------
libbase64_la_SOURCES = base64/base64.c base64/base64.h
libbase64_la_CFLAGS = \
	-I./base64 \
	$(MATH_CFLAGS)


#mconfig ---------------------------------------
libmconfig_la_SOURCES = mConfig/mConfig.c mConfig/mConfig.h
libmconfig_la_CFLAGS = \
	-I./mConfig


#util ---------------------------------------
libutil_la_SOURCES = util.c util.h
libutil_la_CFLAGS = \
	-DFUSE_USE_VERSION=26 \
	$(FUSE_CFLAGS) $(CRYPTO_CFLAGS)

libutil_la_LIBADD = \
	$(FUSE_LIBS) $(CRYPTO_LIBS)


#fuse_operations ----------------------------
libfuseoperations_la_SOURCES = fuse_operations.c fuse_operations.h
libfuseoperations_la_CFLAGS = \
	-DFUSE_USE_VERSION=26 \
	$(FUSE_CFLAGS)

libfuseoperations_la_LIBADD = \
	$(FUSE_LIBS)


#pubcfs_functions ---------------------------
libpubcfsfunctions_la_SOURCES = pubcfs.c pubcfs.h
libpubcfsfunctions_la_CFLAGS = \
	-DFUSE_USE_VERSION=26 \
	-lm \
	$(FUSE_CFLAGS) $(CRYPTO_CFLAGS) $(MATH_CFLAGS)

libpubcfsfunctions_la_LIBADD = \
	libutil.la \
	libbase64.la \
	$(FUSE_LIBS) $(CRYPTO_LIBS) $(MATH_LIBS)

all: all-am

.SUFFIXES:
.SUFFIXES: .c .lo .o .obj
$(srcdir)/Makefile.in:  $(srcdir)/Makefile.am  $(am__configure_deps)
	@for dep in $?; do \
	  case '$(am__configure_deps)' in \
	    *$$dep*) \
	      ( cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh ) \
	        && { if test -f $@; then exit 0; else break; fi; }; \
	      exit 1;; \
	  esac; \
	done; \
	echo ' cd $(top_srcdir) && $(AUTOMAKE) --gnu src/Makefile'; \
	$(am__cd) $(top_srcdir) && \
	  $(AUTOMAKE) --gnu src/Makefile
.PRECIOUS: Makefile
Makefile: $(srcdir)/Makefile.in $(top_builddir)/config.status
	@case '$?' in \
	  *config.status*) \
	    cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh;; \
	  *) \
	    echo ' cd $(top_builddir) && $(SHELL) ./config.status $(subdir)/$@ $(am__depfiles_maybe)'; \
	    cd $(top_builddir) && $(SHELL) ./config.status $(subdir)/$@ $(am__depfiles_maybe);; \
	esac;

$(top_builddir)/config.status: $(top_srcdir)/configure $(CONFIG_STATUS_DEPENDENCIES)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh

$(top_srcdir)/configure:  $(am__configure_deps)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh
$(ACLOCAL_M4):  $(am__aclocal_m4_deps)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh
$(am__aclocal_m4_deps):

clean-noinstLTLIBRARIES:
	-test -z "$(noinst_LTLIBRARIES)" || rm -f $(noinst_LTLIBRARIES)
	@list='$(noinst_LTLIBRARIES)'; for p in $$list; do \
	  dir="`echo $$p | sed -e 's|/[^/]*$$||'`"; \
	  test "$$dir" != "$$p" || dir=.; \
	  echo "rm -f \"$${dir}/so_locations\""; \
	  rm -f "$${dir}/so_locations"; \
	done
libbase64.la: $(libbase64_la_OBJECTS) $(libbase64_la_DEPENDENCIES) 
	$(libbase64_la_LINK)  $(libbase64_la_OBJECTS) $(libbase64_la_LIBADD) $(LIBS)
libfuseoperations.la: $(libfuseoperations_la_OBJECTS) $(libfuseoperations_la_DEPENDENCIES) 
	$(libfuseoperations_la_LINK)  $(libfuseoperations_la_OBJECTS) $(libfuseoperations_la_LIBADD) $(LIBS)
libmconfig.la: $(libmconfig_la_OBJECTS) $(libmconfig_la_DEPENDENCIES) 
	$(libmconfig_la_LINK)  $(libmconfig_la_OBJECTS) $(libmconfig_la_LIBADD) $(LIBS)
libpubcfsfunctions.la: $(libpubcfsfunctions_la_OBJECTS) $(libpubcfsfunctions_la_DEPENDENCIES) 
	$(libpubcfsfunctions_la_LINK)  $(libpubcfsfunctions_la_OBJECTS) $(libpubcfsfunctions_la_LIBADD) $(LIBS)
libutil.la: $(libutil_la_OBJECTS) $(libutil_la_DEPENDENCIES) 
	$(libutil_la_LINK)  $(libutil_la_OBJECTS) $(libutil_la_LIBADD) $(LIBS)
install-binPROGRAMS: $(bin_PROGRAMS)
	@$(NORMAL_INSTALL)
	test -z "$(bindir)" || $(MKDIR_P) "$(DESTDIR)$(bindir)"
	@list='$(bin_PROGRAMS)'; test -n "$(bindir)" || list=; \
	for p in $$list; do echo "$$p $$p"; done | \
	sed 's/$(EXEEXT)$$//' | \
	while read p p1; do if test -f $$p || test -f $$p1; \
	  then echo "$$p"; echo "$$p"; else :; fi; \
	done | \
	sed -e 'p;s,.*/,,;n;h' -e 's|.*|.|' \
	    -e 'p;x;s,.*/,,;s/$(EXEEXT)$$//;$(transform);s/$$/$(EXEEXT)/' | \
	sed 'N;N;N;s,\n, ,g' | \
	$(AWK) 'BEGIN { files["."] = ""; dirs["."] = 1 } \
	  { d=$$3; if (dirs[d] != 1) { print "d", d; dirs[d] = 1 } \
	    if ($$2 == $$4) files[d] = files[d] " " $$1; \
	    else { print "f", $$3 "/" $$4, $$1; } } \
	  END { for (d in files) print "f", d, files[d] }' | \
	while read type dir files; do \
	    if test "$$dir" = .; then dir=; else dir=/$$dir; fi; \
	    test -z "$$files" || { \
	    echo " $(INSTALL_PROGRAM_ENV) $(LIBTOOL) $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=install $(INSTALL_PROGRAM) $$files '$(DESTDIR)$(bindir)$$dir'"; \
	    $(INSTALL_PROGRAM_ENV) $(LIBTOOL) $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=install $(INSTALL_PROGRAM) $$files "$(DESTDIR)$(bindir)$$dir" || exit $$?; \
	    } \
	; done

uninstall-binPROGRAMS:
	@$(NORMAL_UNINSTALL)
	@list='$(bin_PROGRAMS)'; test -n "$(bindir)" || list=; \
	files=`for p in $$list; do echo "$$p"; done | \
	  sed -e 'h;s,^.*/,,;s/$(EXEEXT)$$//;$(transform)' \
	      -e 's/$$/$(EXEEXT)/' `; \
	test -n "$$list" || exit 0; \
	echo " ( cd '$(DESTDIR)$(bindir)' && rm -f" $$files ")"; \
	cd "$(DESTDIR)$(bindir)" && rm -f $$files

clean-binPROGRAMS:
	@list='$(bin_PROGRAMS)'; test -n "$$list" || exit 0; \
	echo " rm -f" $$list; \
	rm -f $$list || exit $$?; \
	test -n "$(EXEEXT)" || exit 0; \
	list=`for p in $$list; do echo "$$p"; done | sed 's/$(EXEEXT)$$//'`; \
	echo " rm -f" $$list; \
	rm -f $$list
pubcfs$(EXEEXT): $(pubcfs_OBJECTS) $(pubcfs_DEPENDENCIES) 
	@rm -f pubcfs$(EXEEXT)
	$(pubcfs_LINK) $(pubcfs_OBJECTS) $(pubcfs_LDADD) $(LIBS)
pubcfs-config$(EXEEXT): $(pubcfs_config_OBJECTS) $(pubcfs_config_DEPENDENCIES) 
	@rm -f pubcfs-config$(EXEEXT)
	$(pubcfs_config_LINK) $(pubcfs_config_OBJECTS) $(pubcfs_config_LDADD) $(LIBS)

mostlyclean-compile:
	-rm -f *.$(OBJEXT)

distclean-compile:
	-rm -f *.tab.c

include ./$(DEPDIR)/libbase64_la-base64.Plo
include ./$(DEPDIR)/libfuseoperations_la-fuse_operations.Plo
include ./$(DEPDIR)/libmconfig_la-mConfig.Plo
include ./$(DEPDIR)/libpubcfsfunctions_la-pubcfs.Plo
include ./$(DEPDIR)/libutil_la-util.Plo
include ./$(DEPDIR)/pubcfs-main.Po
include ./$(DEPDIR)/pubcfs_config-pubcfs-config.Po

.c.o:
	$(COMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ $<
	$(am__mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po
#	source='$<' object='$@' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(COMPILE) -c $<

.c.obj:
	$(COMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ `$(CYGPATH_W) '$<'`
	$(am__mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po
#	source='$<' object='$@' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(COMPILE) -c `$(CYGPATH_W) '$<'`

.c.lo:
	$(LTCOMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ $<
	$(am__mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Plo
#	source='$<' object='$@' libtool=yes \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(LTCOMPILE) -c -o $@ $<

libbase64_la-base64.lo: base64/base64.c
	$(LIBTOOL)  --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(libbase64_la_CFLAGS) $(CFLAGS) -MT libbase64_la-base64.lo -MD -MP -MF $(DEPDIR)/libbase64_la-base64.Tpo -c -o libbase64_la-base64.lo `test -f 'base64/base64.c' || echo '$(srcdir)/'`base64/base64.c
	$(am__mv) $(DEPDIR)/libbase64_la-base64.Tpo $(DEPDIR)/libbase64_la-base64.Plo
#	source='base64/base64.c' object='libbase64_la-base64.lo' libtool=yes \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(LIBTOOL)  --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(libbase64_la_CFLAGS) $(CFLAGS) -c -o libbase64_la-base64.lo `test -f 'base64/base64.c' || echo '$(srcdir)/'`base64/base64.c

libfuseoperations_la-fuse_operations.lo: fuse_operations.c
	$(LIBTOOL)  --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(libfuseoperations_la_CFLAGS) $(CFLAGS) -MT libfuseoperations_la-fuse_operations.lo -MD -MP -MF $(DEPDIR)/libfuseoperations_la-fuse_operations.Tpo -c -o libfuseoperations_la-fuse_operations.lo `test -f 'fuse_operations.c' || echo '$(srcdir)/'`fuse_operations.c
	$(am__mv) $(DEPDIR)/libfuseoperations_la-fuse_operations.Tpo $(DEPDIR)/libfuseoperations_la-fuse_operations.Plo
#	source='fuse_operations.c' object='libfuseoperations_la-fuse_operations.lo' libtool=yes \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(LIBTOOL)  --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(libfuseoperations_la_CFLAGS) $(CFLAGS) -c -o libfuseoperations_la-fuse_operations.lo `test -f 'fuse_operations.c' || echo '$(srcdir)/'`fuse_operations.c

libmconfig_la-mConfig.lo: mConfig/mConfig.c
	$(LIBTOOL)  --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(libmconfig_la_CFLAGS) $(CFLAGS) -MT libmconfig_la-mConfig.lo -MD -MP -MF $(DEPDIR)/libmconfig_la-mConfig.Tpo -c -o libmconfig_la-mConfig.lo `test -f 'mConfig/mConfig.c' || echo '$(srcdir)/'`mConfig/mConfig.c
	$(am__mv) $(DEPDIR)/libmconfig_la-mConfig.Tpo $(DEPDIR)/libmconfig_la-mConfig.Plo
#	source='mConfig/mConfig.c' object='libmconfig_la-mConfig.lo' libtool=yes \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(LIBTOOL)  --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(libmconfig_la_CFLAGS) $(CFLAGS) -c -o libmconfig_la-mConfig.lo `test -f 'mConfig/mConfig.c' || echo '$(srcdir)/'`mConfig/mConfig.c

libpubcfsfunctions_la-pubcfs.lo: pubcfs.c
	$(LIBTOOL)  --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(libpubcfsfunctions_la_CFLAGS) $(CFLAGS) -MT libpubcfsfunctions_la-pubcfs.lo -MD -MP -MF $(DEPDIR)/libpubcfsfunctions_la-pubcfs.Tpo -c -o libpubcfsfunctions_la-pubcfs.lo `test -f 'pubcfs.c' || echo '$(srcdir)/'`pubcfs.c
	$(am__mv) $(DEPDIR)/libpubcfsfunctions_la-pubcfs.Tpo $(DEPDIR)/libpubcfsfunctions_la-pubcfs.Plo
#	source='pubcfs.c' object='libpubcfsfunctions_la-pubcfs.lo' libtool=yes \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(LIBTOOL)  --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(libpubcfsfunctions_la_CFLAGS) $(CFLAGS) -c -o libpubcfsfunctions_la-pubcfs.lo `test -f 'pubcfs.c' || echo '$(srcdir)/'`pubcfs.c

libutil_la-util.lo: util.c
	$(LIBTOOL)  --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(libutil_la_CFLAGS) $(CFLAGS) -MT libutil_la-util.lo -MD -MP -MF $(DEPDIR)/libutil_la-util.Tpo -c -o libutil_la-util.lo `test -f 'util.c' || echo '$(srcdir)/'`util.c
	$(am__mv) $(DEPDIR)/libutil_la-util.Tpo $(DEPDIR)/libutil_la-util.Plo
#	source='util.c' object='libutil_la-util.lo' libtool=yes \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(LIBTOOL)  --tag=CC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(libutil_la_CFLAGS) $(CFLAGS) -c -o libutil_la-util.lo `test -f 'util.c' || echo '$(srcdir)/'`util.c

pubcfs-main.o: main.c
	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(pubcfs_CFLAGS) $(CFLAGS) -MT pubcfs-main.o -MD -MP -MF $(DEPDIR)/pubcfs-main.Tpo -c -o pubcfs-main.o `test -f 'main.c' || echo '$(srcdir)/'`main.c
	$(am__mv) $(DEPDIR)/pubcfs-main.Tpo $(DEPDIR)/pubcfs-main.Po
#	source='main.c' object='pubcfs-main.o' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(pubcfs_CFLAGS) $(CFLAGS) -c -o pubcfs-main.o `test -f 'main.c' || echo '$(srcdir)/'`main.c

pubcfs-main.obj: main.c
	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(pubcfs_CFLAGS) $(CFLAGS) -MT pubcfs-main.obj -MD -MP -MF $(DEPDIR)/pubcfs-main.Tpo -c -o pubcfs-main.obj `if test -f 'main.c'; then $(CYGPATH_W) 'main.c'; else $(CYGPATH_W) '$(srcdir)/main.c'; fi`
	$(am__mv) $(DEPDIR)/pubcfs-main.Tpo $(DEPDIR)/pubcfs-main.Po
#	source='main.c' object='pubcfs-main.obj' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(pubcfs_CFLAGS) $(CFLAGS) -c -o pubcfs-main.obj `if test -f 'main.c'; then $(CYGPATH_W) 'main.c'; else $(CYGPATH_W) '$(srcdir)/main.c'; fi`

pubcfs_config-pubcfs-config.o: pubcfs-config.c
	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(pubcfs_config_CFLAGS) $(CFLAGS) -MT pubcfs_config-pubcfs-config.o -MD -MP -MF $(DEPDIR)/pubcfs_config-pubcfs-config.Tpo -c -o pubcfs_config-pubcfs-config.o `test -f 'pubcfs-config.c' || echo '$(srcdir)/'`pubcfs-config.c
	$(am__mv) $(DEPDIR)/pubcfs_config-pubcfs-config.Tpo $(DEPDIR)/pubcfs_config-pubcfs-config.Po
#	source='pubcfs-config.c' object='pubcfs_config-pubcfs-config.o' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(pubcfs_config_CFLAGS) $(CFLAGS) -c -o pubcfs_config-pubcfs-config.o `test -f 'pubcfs-config.c' || echo '$(srcdir)/'`pubcfs-config.c

pubcfs_config-pubcfs-config.obj: pubcfs-config.c
	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(pubcfs_config_CFLAGS) $(CFLAGS) -MT pubcfs_config-pubcfs-config.obj -MD -MP -MF $(DEPDIR)/pubcfs_config-pubcfs-config.Tpo -c -o pubcfs_config-pubcfs-config.obj `if test -f 'pubcfs-config.c'; then $(CYGPATH_W) 'pubcfs-config.c'; else $(CYGPATH_W) '$(srcdir)/pubcfs-config.c'; fi`
	$(am__mv) $(DEPDIR)/pubcfs_config-pubcfs-config.Tpo $(DEPDIR)/pubcfs_config-pubcfs-config.Po
#	source='pubcfs-config.c' object='pubcfs_config-pubcfs-config.obj' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(pubcfs_config_CFLAGS) $(CFLAGS) -c -o pubcfs_config-pubcfs-config.obj `if test -f 'pubcfs-config.c'; then $(CYGPATH_W) 'pubcfs-config.c'; else $(CYGPATH_W) '$(srcdir)/pubcfs-config.c'; fi`

mostlyclean-libtool:
	-rm -f *.lo

clean-libtool:
	-rm -rf .libs _libs

ID: $(HEADERS) $(SOURCES) $(LISP) $(TAGS_FILES)
	list='$(SOURCES) $(HEADERS) $(LISP) $(TAGS_FILES)'; \
	unique=`for i in $$list; do \
	    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
	  done | \
	  $(AWK) '{ files[$$0] = 1; nonempty = 1; } \
	      END { if (nonempty) { for (i in files) print i; }; }'`; \
	mkid -fID $$unique
tags: TAGS

TAGS:  $(HEADERS) $(SOURCES)  $(TAGS_DEPENDENCIES) \
		$(TAGS_FILES) $(LISP)
	set x; \
	here=`pwd`; \
	list='$(SOURCES) $(HEADERS)  $(LISP) $(TAGS_FILES)'; \
	unique=`for i in $$list; do \
	    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
	  done | \
	  $(AWK) '{ files[$$0] = 1; nonempty = 1; } \
	      END { if (nonempty) { for (i in files) print i; }; }'`; \
	shift; \
	if test -z "$(ETAGS_ARGS)$$*$$unique"; then :; else \
	  test -n "$$unique" || unique=$$empty_fix; \
	  if test $$# -gt 0; then \
	    $(ETAGS) $(ETAGSFLAGS) $(AM_ETAGSFLAGS) $(ETAGS_ARGS) \
	      "$$@" $$unique; \
	  else \
	    $(ETAGS) $(ETAGSFLAGS) $(AM_ETAGSFLAGS) $(ETAGS_ARGS) \
	      $$unique; \
	  fi; \
	fi
ctags: CTAGS
CTAGS:  $(HEADERS) $(SOURCES)  $(TAGS_DEPENDENCIES) \
		$(TAGS_FILES) $(LISP)
	list='$(SOURCES) $(HEADERS)  $(LISP) $(TAGS_FILES)'; \
	unique=`for i in $$list; do \
	    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
	  done | \
	  $(AWK) '{ files[$$0] = 1; nonempty = 1; } \
	      END { if (nonempty) { for (i in files) print i; }; }'`; \
	test -z "$(CTAGS_ARGS)$$unique" \
	  || $(CTAGS) $(CTAGSFLAGS) $(AM_CTAGSFLAGS) $(CTAGS_ARGS) \
	     $$unique

GTAGS:
	here=`$(am__cd) $(top_builddir) && pwd` \
	  && $(am__cd) $(top_srcdir) \
	  && gtags -i $(GTAGS_ARGS) "$$here"

distclean-tags:
	-rm -f TAGS ID GTAGS GRTAGS GSYMS GPATH tags

distdir: $(DISTFILES)
	@srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	topsrcdirstrip=`echo "$(top_srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	list='$(DISTFILES)'; \
	  dist_files=`for file in $$list; do echo $$file; done | \
	  sed -e "s|^$$srcdirstrip/||;t" \
	      -e "s|^$$topsrcdirstrip/|$(top_builddir)/|;t"`; \
	case $$dist_files in \
	  */*) $(MKDIR_P) `echo "$$dist_files" | \
			   sed '/\//!d;s|^|$(distdir)/|;s,/[^/]*$$,,' | \
			   sort -u` ;; \
	esac; \
	for file in $$dist_files; do \
	  if test -f $$file || test -d $$file; then d=.; else d=$(srcdir); fi; \
	  if test -d $$d/$$file; then \
	    dir=`echo "/$$file" | sed -e 's,/[^/]*$$,,'`; \
	    if test -d "$(distdir)/$$file"; then \
	      find "$(distdir)/$$file" -type d ! -perm -700 -exec chmod u+rwx {} \;; \
	    fi; \
	    if test -d $(srcdir)/$$file && test $$d != $(srcdir); then \
	      cp -fpR $(srcdir)/$$file "$(distdir)$$dir" || exit 1; \
	      find "$(distdir)/$$file" -type d ! -perm -700 -exec chmod u+rwx {} \;; \
	    fi; \
	    cp -fpR $$d/$$file "$(distdir)$$dir" || exit 1; \
	  else \
	    test -f "$(distdir)/$$file" \
	    || cp -p $$d/$$file "$(distdir)/$$file" \
	    || exit 1; \
	  fi; \
	done
check-am: all-am
check: check-am
all-am: Makefile $(LTLIBRARIES) $(PROGRAMS)
installdirs:
	for dir in "$(DESTDIR)$(bindir)"; do \
	  test -z "$$dir" || $(MKDIR_P) "$$dir"; \
	done
install: install-am
install-exec: install-exec-am
install-data: install-data-am
uninstall: uninstall-am

install-am: all-am
	@$(MAKE) $(AM_MAKEFLAGS) install-exec-am install-data-am

installcheck: installcheck-am
install-strip:
	$(MAKE) $(AM_MAKEFLAGS) INSTALL_PROGRAM="$(INSTALL_STRIP_PROGRAM)" \
	  install_sh_PROGRAM="$(INSTALL_STRIP_PROGRAM)" INSTALL_STRIP_FLAG=-s \
	  `test -z '$(STRIP)' || \
	    echo "INSTALL_PROGRAM_ENV=STRIPPROG='$(STRIP)'"` install
mostlyclean-generic:

clean-generic:

distclean-generic:
	-test -z "$(CONFIG_CLEAN_FILES)" || rm -f $(CONFIG_CLEAN_FILES)
	-test . = "$(srcdir)" || test -z "$(CONFIG_CLEAN_VPATH_FILES)" || rm -f $(CONFIG_CLEAN_VPATH_FILES)

maintainer-clean-generic:
	@echo "This command is intended for maintainers to use"
	@echo "it deletes files that may require special tools to rebuild."
clean: clean-am

clean-am: clean-binPROGRAMS clean-generic clean-libtool \
	clean-noinstLTLIBRARIES mostlyclean-am

distclean: distclean-am
	-rm -rf ./$(DEPDIR)
	-rm -f Makefile
distclean-am: clean-am distclean-compile distclean-generic \
	distclean-tags

dvi: dvi-am

dvi-am:

html: html-am

html-am:

info: info-am

info-am:

install-data-am:

install-dvi: install-dvi-am

install-dvi-am:

install-exec-am: install-binPROGRAMS

install-html: install-html-am

install-html-am:

install-info: install-info-am

install-info-am:

install-man:

install-pdf: install-pdf-am

install-pdf-am:

install-ps: install-ps-am

install-ps-am:

installcheck-am:

maintainer-clean: maintainer-clean-am
	-rm -rf ./$(DEPDIR)
	-rm -f Makefile
maintainer-clean-am: distclean-am maintainer-clean-generic

mostlyclean: mostlyclean-am

mostlyclean-am: mostlyclean-compile mostlyclean-generic \
	mostlyclean-libtool

pdf: pdf-am

pdf-am:

ps: ps-am

ps-am:

uninstall-am: uninstall-binPROGRAMS

.MAKE: install-am install-strip

.PHONY: CTAGS GTAGS all all-am check check-am clean clean-binPROGRAMS \
	clean-generic clean-libtool clean-noinstLTLIBRARIES ctags \
	distclean distclean-compile distclean-generic \
	distclean-libtool distclean-tags distdir dvi dvi-am html \
	html-am info info-am install install-am install-binPROGRAMS \
	install-data install-data-am install-dvi install-dvi-am \
	install-exec install-exec-am install-html install-html-am \
	install-info install-info-am install-man install-pdf \
	install-pdf-am install-ps install-ps-am install-strip \
	installcheck installcheck-am installdirs maintainer-clean \
	maintainer-clean-generic mostlyclean mostlyclean-compile \
	mostlyclean-generic mostlyclean-libtool pdf pdf-am ps ps-am \
	tags uninstall uninstall-am uninstall-binPROGRAMS


# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
