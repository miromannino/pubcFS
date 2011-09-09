bin_PROGRAMS = pubcfs pubcfs-config

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