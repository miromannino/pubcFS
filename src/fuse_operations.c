/*
 * Copyright 2010 Miro Mannino <miro.mannino@gmail.com>
 * This work is licensed under the Creative Commons Attribution 2.5
 * Italy License. To view a copy of this license, visit
 * http://creativecommons.org/licenses/by/2.5/it/ or send a letter
 * to Creative Commons, 171 Second Street, Suite 300, San Francisco,
 * California, 94105, USA.
 *
 */

#include <fuse_operations.h>

/** Get file attributes.
 *
 * Similar to stat().  The 'st_dev' and 'st_blksize' fields are
 * ignored.	 The 'st_ino' field is ignored except if the 'use_ino'
 * mount option is given.
 */
int pubcfs_getattr(const char *path, struct stat *statbuf){
	int ris;
	char* e_path;
	pubcfs_context* ctx;

	ctx = pubcfs_getCtx();
	e_path = pubcfs_encodePath(ctx, path, true);
	if(e_path == NULL) return -errno;

	ris = lstat(e_path, statbuf);
	free(e_path);

	if (ris != 0)
		return -errno;
	return 0;
}

/** Read the target of a symbolic link
 *
 * The buffer should be filled with a null terminated string. The
 * buffer size argument includes the space for the terminating
 * null character.	If the linkname is too long to fit in the
 * buffer, it should be truncated.	The return value should be 0
 * for success.
 */
int pubcfs_readlink(const char *path, char *link, size_t size)
{
	int cris;
	size_t buff_len, token_len;
	char *e_path, *e_link, *strtok_ctx, *check, *buff, *ris, *token;
	pubcfs_context* ctx;
	pubcfs_cryptoCtx* cctx;

	ctx = pubcfs_getCtx();
	cctx = pubcfs_getCryptoCtx(ctx);
	e_path = pubcfs_encodePath(ctx, path, true);
	if(e_path == NULL) return -errno;

	e_link = malloc(size);
	if(e_link == NULL){
		free(e_path);
		return -1;
	}

	cris = readlink(e_path, e_link, size - 1);
	if (cris < 0) return -errno;
	e_link[cris] = '\0';

	ris = malloc(1);
	ris[0] = '\0';
	token = strtok_r(e_link, "/", &strtok_ctx);
	while(token != NULL){
		check = strstr(token, PUBCFS_FILENAME_ENC);
		if(check == token){
			ris = strappend(ris, PUBCFS_FILENAME_ENC_WITH_S);
			token = token + PUBCFS_FILENAME_ENC_SIZE; //remove the PUBCFS_FILENAME_ENC prefix
			token_len = strlen(token);
			base64_decode((uchar*)token, (uchar**)(&buff), token_len, &buff_len, base64_OPT_FILENAMESAFE);
			char* buff2 = malloc(buff_len);
			if(buff2 == NULL){
				free(ris);
				return -1;
			}

			pubcfs_decrypt(&(cctx->de), (uchar*)buff, (uchar*)buff2, buff_len);
			buff2[buff_len] = '\0';

			ris = strappend(ris, buff2);
			free(buff2);
		}else{
			ris = strappend(ris, "/");
			ris = strappend(ris, token);
		}

		token = strtok_r(NULL, "/", &strtok_ctx);
	}

	free(e_path);
	strncpy(link, ris, size);
	return 0;
}

/** Create a file node
 *
 * This is called for creation of all non-directory, non-symlink
 * nodes.  If the filesystem defines a create() method, then for
 * regular files that will be called instead.
 */
int pubcfs_mknod(const char *path, mode_t mode, dev_t dev)
{
	int ris;
	char* e_path;
	pubcfs_context* ctx;

	ctx = pubcfs_getCtx();
	e_path = pubcfs_encodePath(ctx, path, true);
	if(e_path == NULL) return -errno;

	/* this is not portable because in other SO mknod is used only for create mkfifo and if
	 * mode != S_IFIFO the behavior is unspecified */
	ris = mknod(e_path, mode, dev);
	free(e_path);
	if (ris < 0) return -errno;

	return ris;
}

/** Create a directory
 *
 * Note that the mode argument may not have the type specification
 * bits set, i.e. S_ISDIR(mode) can be false.  To obtain the
 * correct directory type bits use  mode|S_IFDIR
 * */
int pubcfs_mkdir(const char *path, mode_t mode)
{
	int ris;
	char* e_path;
	pubcfs_context* ctx;

	ctx = pubcfs_getCtx();
	e_path = pubcfs_encodePath(ctx, path, true);
	if(e_path == NULL) return -errno;

	ris = mkdir(e_path, mode);
	free(e_path);
	if (ris < 0) return -errno;

	return ris;
}

/** Remove a file */
int pubcfs_unlink(const char *path)
{
	int ris;
	char* e_path;
	pubcfs_context* ctx;

	ctx = pubcfs_getCtx();
	e_path = pubcfs_encodePath(ctx, path, true);
	if(e_path == NULL) return -errno;

	ris = unlink(e_path);
	free(e_path);
	if (ris < 0) return -errno;

	return ris;
}

/** Remove a directory */
int pubcfs_rmdir(const char *path)
{
	int ris;
	char* e_path;
	pubcfs_context* ctx;

	ctx = pubcfs_getCtx();
	e_path = pubcfs_encodePath(ctx, path, true);
	if(e_path == NULL) return -errno;

	ris = rmdir(e_path);
	free(e_path);
	if (ris < 0) return -errno;

	return ris;
}

/** Create a symbolic link */
int pubcfs_symlink(const char *path1, const char *path2)
{
	int ris;
	char *e_path1, *e_path2;
	pubcfs_context* ctx;

	ctx = pubcfs_getCtx();

	e_path1 = pubcfs_encodePath(ctx, path1, false);
	if(e_path1 == NULL) return -errno;
	e_path2 = pubcfs_encodePath(ctx, path2, true);
	if(e_path2 == NULL) return -errno;

	ris = symlink(e_path1, e_path2);
	free(e_path2);
	free(e_path1);
	if(ris < 0) return -errno;

	return 0;
}

/** Rename a file */
int pubcfs_rename(const char *old, const char *new)
{
	int ris;
	char *e_old, *e_new;
	pubcfs_context* ctx;

	ctx = pubcfs_getCtx();
	e_old = pubcfs_encodePath(ctx, old, true);
	if(e_old == NULL) return -errno;
	e_new = pubcfs_encodePath(ctx, new, true);
	if(e_new == NULL) return -errno;
	ris = rename(e_old, e_new);
	free(e_old);
	free(e_new);
	if(ris < 0) return -errno;

	return 0;
}

/** Create a hard link to a file */
int pubcfs_link(const char *path1, const char *path2)
{
	int ris;
	char *e_path1, *e_path2;
	pubcfs_context* ctx;

	ctx = pubcfs_getCtx();
	e_path1 = pubcfs_encodePath(ctx, path1, true);
	if(e_path1 == NULL) return -errno;
	e_path2 = pubcfs_encodePath(ctx, path2, true);
	if(e_path2 == NULL) return -errno;
	ris = link(e_path1, e_path2);
	free(e_path2);
	free(e_path1);
	if(ris < 0) return -errno;

	return 0;
}

/** Change the permission bits of a file */
int pubcfs_chmod(const char *path, mode_t mode)
{
	int ris;
	char* e_path;
	pubcfs_context* ctx;

	ctx = pubcfs_getCtx();
	e_path = pubcfs_encodePath(ctx, path, true);
	if(e_path == NULL) return -errno;

	ris = chmod(e_path, mode);
	free(e_path);
	if (ris < 0) return -errno;

	return ris;
}

/** Change the owner and group of a file */
int pubcfs_chown(const char *path, uid_t uid, gid_t gid)
{
	int ris;
	char* e_path;
	pubcfs_context* ctx;

	ctx = pubcfs_getCtx();
	e_path = pubcfs_encodePath(ctx, path, true);
	if(e_path == NULL) return -errno;

	/*I use the lchown because if path is a link it will work too*/
	ris = lchown(e_path, uid, gid);
	free(e_path);
	if (ris < 0) return -errno;

	return ris;
}

/** Change the size of a file */
int pubcfs_truncate(const char *path, off_t newSize)
{
	int ris;
	char* e_path;
	pubcfs_context* ctx;

	ctx = pubcfs_getCtx();
	e_path = pubcfs_encodePath(ctx, path, true);
	if(e_path == NULL) return -errno;
	ris = truncate(e_path, newSize);
	free(e_path);
	if (ris < 0) return -errno;

	return ris;
}

/** Change the access and/or modification times of a file */
int pubcfs_utime(const char *path, struct utimbuf *times)
{
	int ris;
	char* e_path;
	pubcfs_context* ctx;

	ctx = pubcfs_getCtx();
	e_path = pubcfs_encodePath(ctx, path, true);
	if(e_path == NULL) return -errno;

	ris = utime(e_path, times);
	free(e_path);
	if (ris < 0) return -errno;

	return ris;
}

/** File open operation
 *
 * No creation (O_CREAT, O_EXCL) and by default also no
 * truncation (O_TRUNC) flags will be passed to open(). If an
 * application specifies O_TRUNC, fuse first calls truncate()
 * and then open(). Only if 'atomic_o_trunc' has been
 * specified and kernel version is 2.6.24 or later, O_TRUNC is
 * passed on to open.
 *
 * Unless the 'default_permissions' mount option is given,
 * open should check if the operation is permitted for the
 * given flags. Optionally open may also return an arbitrary
 * filehandle in the fuse_file_info structure, which will be
 * passed to all file operations.
 *
 * Changed in version 2.2
 */
int pubcfs_open(const char *path, struct fuse_file_info *fi)
{
	int fd;
	char* e_path;
	pubcfs_context* ctx;

	ctx = pubcfs_getCtx();
	e_path = pubcfs_encodePath(ctx, path, true);
	if(e_path == NULL) return -errno;

	fd = open(e_path, fi->flags);
	free(e_path);
	if (fd < 0) return -errno;
	fi->fh = fd;

	return 0;
}

/** Read data from an open file
 *
 * Read should return exactly the number of bytes requested except
 * on EOF or error, otherwise the rest of the data will be
 * substituted with zeroes.	 An exception to this is when the
 * 'direct_io' mount option is specified, in which case the return
 * value of the read system call will reflect the return value of
 * this operation.
 *
 * Changed in version 2.2
 */
int pubcfs_read(const char *path, char *buf, size_t count, off_t offset, struct fuse_file_info *fi)
{
	int ris;
	ulong block; //current block where we start to read
	size_t blockSize;
    off_t blockOffset; //offset relative to the start of the current block
    size_t blockRemainingSpace; //space to read until reach the end of the block or 'size'
    off_t endOffset;
    size_t writed, toCopy;
    ubyte* blockBuf;
    pubcfs_context* ctx;
    pubcfs_cryptoCtx* cctx;

    ctx = pubcfs_getCtx();
    cctx = pubcfs_getCryptoCtx(ctx);
    blockSize = ctx->blockSize;
    blockBuf = (ubyte*)malloc(blockSize);
    if(blockBuf == NULL) return -1;
    endOffset = offset + count;
    writed = 0;

    /* First of all with the 'offset' param it calculate the first block. Then the loop start
     * and finish when the current block contain the 'offset' + 'count' byte. For example if the
     * count is a little less then blockSize*2 the loop do two iterations for read the first and
     * the second block starting from the block that contain the 'offset' byte.
     *
     * numeric example
	 *
	 *	|----------|--^-------|-----------|... (blocksize=10; offset=12; count=12)
	 *	block=12/10=1; and with this we calculate that the first block is the second
	 *	then the loop continue with the third and then it finish because 30 >= 12+12
	 */

    block = offset / blockSize;
    while((block * blockSize) < endOffset){

		if (block * blockSize < offset){ //check that the start of the block is before the offset
			blockOffset = offset % blockSize;
		}else{
			/* in this case the offset is before the start of the current block and we need to
			 * read all the block starting from the first possition. */
			blockOffset = 0;
		}

		if (((block + 1) * blockSize) <= endOffset){
			/* in this case we need to read all the remaining space of the block because endOffset
			 * is after the end of the current block */
			blockRemainingSpace = blockSize - blockOffset;
		}else{
			/* in this case we need to read until endOffset
			 * (endOffset % blockSize) is the offset of endOffset relative to the start of the block
			 * like the blockOffset
			 */
			blockRemainingSpace = (endOffset % blockSize) - blockOffset;
		}

		//read the block and copy it into blockBuf
		ris = pubcfs_readBlock(ctx, cctx, fi->fh, block, blockBuf);
		if(ris == -1){ //error
			free(blockBuf);
			return -1;
		}if(ris <= blockOffset){ //it's like it don't read anything
			break;
		}

		toCopy = ris - blockOffset;
		//we read the entire block but we need only a part
		memcpy(buf + writed, blockBuf + blockOffset, toCopy);
		writed += toCopy;

		/* if readBlock read a number of bytes smaller than blockOffset + blockRemainingSpace it
		 * means that the read don't have other to read */
		if(ris < blockOffset + blockRemainingSpace) break;

		block++;
    }

    free(blockBuf);
    return writed;

}

/** Write data to an open file
 *
 * Write should return exactly the number of bytes requested
 * except on error.	 An exception to this is when the 'direct_io'
 * mount option is specified (see read operation).
 *
 * Changed in version 2.2
 */
int pubcfs_write(const char *path, const char *buf, size_t count, off_t offset,
		struct fuse_file_info *fi)
{
	int ris;
	ulong block; //current block where we start to read
	size_t blockSize;
	off_t blockOffset; //offset relative to the start of the current block
	size_t blockRemainingSpace; //space to read until reach the end of the block or 'size'
	off_t endOffset;
	size_t writed;
	ubyte* blockBuf;
	pubcfs_context* ctx;
	pubcfs_cryptoCtx* cctx;

	ctx = pubcfs_getCtx();
	cctx = pubcfs_getCryptoCtx(ctx);
	blockSize = ctx->blockSize;
	blockBuf = (ubyte*)malloc(blockSize);
	if(blockBuf == NULL) return -1;
	endOffset = offset + count;
	writed = 0;

	block = offset / blockSize;
	while((block * blockSize) < endOffset){

		if (block * blockSize < offset){ //check that the start of the block is before the offset
			blockOffset = offset % blockSize;
		}else{
			/* in this case the offset is before the start of the current block and we need to
			 * read all the block starting from the first possition. */
			blockOffset = 0;
		}

		if (((block + 1) * blockSize) <= endOffset){
			/* in this case we need to read all the remaining space of the block because endOffset
			 * is after the end of the current block */
			blockRemainingSpace = blockSize - blockOffset;
		}else{
			/* in this case we need to read until endOffset
			 * (endOffset % blockSize) is the offset of endOffset relative to the start of the block
			 * like the blockOffset
			 */
			blockRemainingSpace = (endOffset % blockSize) - blockOffset;
		}

		//We need to read the block and change it, then we need to rewrite into the file

		//check if we need to read a block
		if((blockOffset != 0) && (blockRemainingSpace != blockSize)){
			//read the block and copy it into blockBuf
			ris = pubcfs_readBlock(ctx, cctx, fi->fh, block, blockBuf);
			if(ris == -1){
				free(blockBuf);
				return -1;
			}
		}

		//change and write the block
		memcpy(blockBuf + blockOffset, buf + writed, blockRemainingSpace);
		if(pubcfs_writeBlock(ctx, cctx, fi->fh, block, blockBuf,
							 blockOffset + blockRemainingSpace) == -1){
			free(blockBuf);
			return -1;
		}

		writed += blockRemainingSpace;

		block++;
	}

	free(blockBuf);
	return writed;
}

/** Get file system statistics
 *
 * The 'f_frsize', 'f_favail', 'f_fsid' and 'f_flag' fields are ignored
 *
 * Replaced 'struct statfs' parameter with 'struct statvfs' in
 * version 2.5
 */
int pubcfs_statfs(const char *path, struct statvfs *statv)
{
	int ris;
	char* e_path;
	pubcfs_context* ctx;

	ctx = pubcfs_getCtx();
	e_path = pubcfs_encodePath(ctx, path, true);
	if(e_path == NULL) return -errno;

	ris = statvfs(e_path, statv);
	free(e_path);
	if(ris < 0) return -errno;

	return 0;
}

/** Possibly flush cached data
 *
 * BIG NOTE: This is not equivalent to fsync().  It's not a
 * request to sync dirty data.
 *
 * Flush is called on each close() of a file descriptor.  So if a
 * filesystem wants to return write errors in close() and the file
 * has cached dirty data, this is a good place to write back data
 * and return any errors.  Since many applications ignore close()
 * errors this is not always useful.
 *
 * NOTE: The flush() method may be called more than once for each
 * open().	This happens if more than one file descriptor refers
 * to an opened file due to dup(), dup2() or fork() calls.	It is
 * not possible to determine if a flush is final, so each flush
 * should be treated equally.  Multiple write-flush sequences are
 * relatively rare, so this shouldn't be a problem.
 *
 * Filesystems shouldn't assume that flush will always be called
 * after some writes, or that if will be called at all.
 *
 * Changed in version 2.2
 */
int pubcfs_flush(const char *path, struct fuse_file_info *fi)
{
	return 0;
}

/** Release an open file
 *
 * Release is called when there are no more references to an open
 * file: all file descriptors are closed and all memory mappings
 * are unmapped.
 *
 * For every open() call there will be exactly one release() call
 * with the same flags and file descriptor.	 It is possible to
 * have a file opened more than once, in which case only the last
 * release will mean, that no more reads/writes will happen on the
 * file.  The return value of release is ignored.
 *
 * Changed in version 2.2
 */
int pubcfs_release(const char *path, struct fuse_file_info *fi)
{
	int ris = 0;

	//Close the file and free all allocated resources.
	ris = close(fi->fh);

	return ris;
}

/** Synchronize file contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data.
 *
 * Changed in version 2.2
 */
int pubcfs_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
	int ris;

	if (datasync)
		ris = fdatasync(fi->fh);
	else
		ris = fsync(fi->fh);

	if(ris < 0) return -errno;

	return 0;
}

/** Set extended attributes */
int pubcfs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
	int ris;
	char* e_path;
	pubcfs_context* ctx;

	ctx = pubcfs_getCtx();
	e_path = pubcfs_encodePath(ctx, path, true);
	if(e_path == NULL) return -errno;

	ris = lsetxattr(e_path, name, value, size, flags);
	free(e_path);
	if(ris < 0) return -errno;

	return 0;
}

/** Get extended attributes */
int pubcfs_getxattr(const char *path, const char *name, char *value, size_t size)
{
	int ris;
	char* e_path;
	pubcfs_context* ctx;

	ctx = pubcfs_getCtx();
	e_path = pubcfs_encodePath(ctx, path, true);
	if(e_path == NULL) return -errno;

    ris = lgetxattr(e_path, name, value, size);
	free(e_path);
	if(ris < 0) return -errno;

	return 0;
}

/** List extended attributes */
int pubcfs_listxattr(const char *path, char *list, size_t size)
{
	int ris;
	char* e_path;
	pubcfs_context* ctx;

	ctx = pubcfs_getCtx();
	e_path = pubcfs_encodePath(ctx, path, true);
	if(e_path == NULL) return -errno;

    ris = llistxattr(e_path, list, size);
	free(e_path);
	if(ris < 0) return -errno;

	return 0;
}

/** Remove extended attributes */
int pubcfs_removexattr(const char *path, const char *name)
{
	int ris;
	char* e_path;
	pubcfs_context* ctx;

	ctx = pubcfs_getCtx();
	e_path = pubcfs_encodePath(ctx, path, true);
	if(e_path == NULL) return -errno;

    ris = lremovexattr(e_path, name);
	free(e_path);
	if(ris < 0) return -errno;

	return 0;
}

/** Open directory
 *
 * Unless the 'default_permissions' mount option is given,
 * this method should check if opendir is permitted for this
 * directory. Optionally opendir may also return an arbitrary
 * filehandle in the fuse_file_info structure, which will be
 * passed to readdir, closedir and fsyncdir.
 *
 * Introduced in version 2.3
 */
int pubcfs_opendir(const char *path, struct fuse_file_info *fi)
{
	DIR *dp;
	char* e_path;
	pubcfs_context* ctx;

	ctx = pubcfs_getCtx();
	e_path = pubcfs_encodePath(ctx, path, true);
	if(e_path == NULL) return -errno;

	dp = opendir(e_path);
	free(e_path);
	if (dp == NULL) return -errno;
	fi->fh = (ulong)dp;

	return 0;
}

/** Read directory
 *
 * This supersedes the old getdir() interface.  New applications
 * should use this.
 *
 * The filesystem may choose between two modes of operation:
 *
 * 1) The readdir implementation ignores the offset parameter, and
 * passes zero to the filler function's offset.  The filler
 * function will not return '1' (unless an error happens), so the
 * whole directory is read in a single readdir operation.  This
 * works just like the old getdir() method.
 *
 * 2) The readdir implementation keeps track of the offsets of the
 * directory entries.  It uses the offset parameter and always
 * passes non-zero offset to the filler function.  When the buffer
 * is full (or an error happens) the filler function will return
 * '1'.
 *
 * Introduced in version 2.3
 */
int pubcfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
		struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;
	char* de_name;
	pubcfs_context* ctx;

	ctx = pubcfs_getCtx();
	dp = (DIR *)(fi->fh);

	/* The first call of readdir can't return NULL because all directory have the . and .. entry */
	de = readdir(dp);
	if(de == NULL) return -errno;

	/* Copy all entry into the buffer */
	do{
		de_name = pubcfs_decryptName(ctx, de->d_name);
		if(de_name == NULL) return -errno;
		if(filler(buf, de_name, NULL, 0) != 0) return -ENOMEM;
		free(de_name);
	}while ((de = readdir(dp)) != NULL);

	return 0;
}

/** Release directory
 *
 * Introduced in version 2.3
 */
int pubcfs_releasedir(const char *path, struct fuse_file_info *fi)
{
	DIR *dp;

	dp = (DIR *)(fi->fh);
	closedir(dp);

	return 0;
}

/** Synchronize directory contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data
 *
 * Introduced in version 2.3
 */
int pubcfs_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi)
{
	return 0;
}

/**
 * Initialize filesystem
 *
 * The return value will passed in the private_data field of
 * fuse_context to all file operations and as a parameter to the
 * destroy() method.
 *
 * Introduced in version 2.3
 * Changed in version 2.6
 */
void *pubcfs_init(struct fuse_conn_info *conn)
{
	/* fuse_context is set up before this function is called and fuse_get_context()->private_data
	 * returns the user_data passed to fuse_main().
	 */
	return pubcfs_getCtx();
}

/**
 * Clean up filesystem
 *
 * Called on filesystem exit.
 *
 * Introduced in version 2.3
 */
void pubcfs_destroy(void *userdata)
{
	/*Void*/
}

/**
 * Check file access permissions
 *
 * This will be called for the access() system call.  If the
 * 'default_permissions' mount option is given, this method is not
 * called.
 *
 * This method is not called under Linux kernel versions 2.4.x
 *
 * Introduced in version 2.5
 */
int pubcfs_access(const char *path, int mask)
{
	int ris;
	char* e_path;
	pubcfs_context* ctx;

	ctx = pubcfs_getCtx();
	e_path = pubcfs_encodePath(ctx, path, true);
	if(e_path == NULL) return -errno;

	ris = access(e_path, mask);
	free(e_path);
	if(ris < 0) return -errno;

	return 0;
}

/**
 * Create and open a file
 *
 * If the file does not exist, first create it with the specified
 * mode, and then open it.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the mknod() and open() methods
 * will be called instead.
 *
 * Introduced in version 2.5
 */
int pubcfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	int fd;
	char* e_path;
	pubcfs_context* ctx;

	ctx = pubcfs_getCtx();
	e_path = pubcfs_encodePath(ctx, path, true);
	if(e_path == NULL) return -errno;

	fd = creat(e_path, mode);
	free(e_path);
	if(fd < 0) return -errno;

    fi->fh = fd;

	return 0;
}

/**
 * Change the size of an open file
 *
 * This method is called instead of the truncate() method if the
 * truncation was invoked from an ftruncate() system call.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the truncate() method will be
 * called instead.
 *
 * Introduced in version 2.5
 */
int pubcfs_ftruncate(const char *path, off_t offset, struct fuse_file_info *fi)
{
	int ris;

	ris = ftruncate(fi->fh, offset);
	if (ris < 0) return -errno;

	return ris;
}

/**
 * Get attributes from an open file
 *
 * This method is called instead of the getattr() method if the
 * file information is available.
 *
 * Currently this is only called after the create() method if that
 * is implemented (see above).  Later it may be called for
 * invocations of fstat() too.
 *
 * Introduced in version 2.5
 */
int pubcfs_fgetattr(const char *path, struct stat *statbuf, struct fuse_file_info *fi)
{
	int ris;

	ris = fstat(fi->fh, statbuf);
	if (ris < 0) return -errno;

	return ris;
}


/* ----------------------------------------------------------------------------------- */

private struct fuse_operations pubcfs_operations = {
	.getattr = pubcfs_getattr,
	.readlink = pubcfs_readlink,
	.getdir = NULL, //because deprecated
	.mknod = pubcfs_mknod,
	.mkdir = pubcfs_mkdir,
	.unlink = pubcfs_unlink,
	.rmdir = pubcfs_rmdir,
	.symlink = pubcfs_symlink,
	.rename = pubcfs_rename,
	.link = pubcfs_link,
	.chmod = pubcfs_chmod,
	.chown = pubcfs_chown,
	.truncate = pubcfs_truncate,
	.utime = pubcfs_utime,
	.open = pubcfs_open,
	.read = pubcfs_read,
	.write = pubcfs_write,
	.statfs = pubcfs_statfs,
	.flush = pubcfs_flush,
	.release = pubcfs_release,
	.fsync = pubcfs_fsync,
	.setxattr = pubcfs_setxattr,
	.getxattr = pubcfs_getxattr,
	.listxattr = pubcfs_listxattr,
	.removexattr = pubcfs_removexattr,
	.opendir = pubcfs_opendir,
	.readdir = pubcfs_readdir,
	.releasedir = pubcfs_releasedir,
	.fsyncdir = pubcfs_fsyncdir,
	.init = pubcfs_init,
	.destroy = pubcfs_destroy,
	.access = pubcfs_access,
	.create = pubcfs_create,
	.ftruncate = pubcfs_ftruncate,
	.fgetattr = pubcfs_fgetattr
};

/**
 * return the provided fuse operations
 * */
struct fuse_operations *getPubcFSOperations()
{
    return &pubcfs_operations;
}
