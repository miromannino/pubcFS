/*
 * Copyright 2010 Miro Mannino <miro.mannino@gmail.com>
 * This work is licensed under the Creative Commons Attribution 2.5
 * Italy License. To view a copy of this license, visit
 * http://creativecommons.org/licenses/by/2.5/it/ or send a letter
 * to Creative Commons, 171 Second Street, Suite 300, San Francisco,
 * California, 94105, USA.
 *
 */

#ifndef FUSEOPERATIONS_H

	#define FUSEOPERATIONS_H

	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>
	#include <errno.h>
	#include <fcntl.h>
	#include <dirent.h>
	#include <sys/stat.h>
	#include <unistd.h>
	#include <sys/xattr.h>
	#include <sys/types.h>

	#include <util.h>
	#include <pubcfs.h>


	#include <fuse.h>

	struct fuse_operations *getPubcFSOperations();

#endif
