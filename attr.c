
/*
 * UNFS3 attribute handling
 * (C) 2004, Pascal Schmidt <der.eremit@email.de>
 * see file LICENSE for license details
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <rpc/rpc.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>
#include <errno.h>

#include "nfs.h"
#include "attr.h"
#include "error.h"
#include "fh.h"
#include "fh_cache.h"

/*
 * check whether stat_cache is for a regular file
 *
 * fh_decomp must be called before to fill the stat cache
 */
nfsstat3 is_reg(void)
{
    if (!st_cache_valid)
	return NFS3ERR_STALE;
    else if (S_ISREG(st_cache.st_mode))
	return NFS3_OK;
    else
	return NFS3ERR_INVAL;
}

/*
 * find stat bit corresponding to given NFS file type
 */
mode_t type_to_mode(ftype3 ftype)
{
    switch (ftype) {
	case NF3REG:
	    return S_IFREG;
	case NF3DIR:
	    return S_IFDIR;
	case NF3LNK:
	    return S_IFLNK;
	case NF3CHR:
	    return S_IFCHR;
	case NF3BLK:
	    return S_IFBLK;
	case NF3FIFO:
	    return S_IFIFO;
	case NF3SOCK:
	    return S_IFSOCK;
    }

    /* fix gcc warning */
    return 0;
}

/*
 * post_op_attr for error returns
 */
static inline post_op_attr error_attr(void)
{
    post_op_attr result;

    result.attributes_follow = FALSE;
    return result;
}

/*
 * return pre-operation attributes
 *
 * fh_decomp must be called before to fill the stat cache
 */
pre_op_attr get_pre_cached(void)
{
    pre_op_attr result;

    if (!st_cache_valid) {
	result.attributes_follow = FALSE;
	return result;
    }

    result.attributes_follow = TRUE;

    result.pre_op_attr_u.attributes.size = st_cache.st_size;
    result.pre_op_attr_u.attributes.mtime.seconds = st_cache.st_mtime;
    result.pre_op_attr_u.attributes.mtime.nseconds = 0;
    result.pre_op_attr_u.attributes.ctime.seconds = st_cache.st_ctime;
    result.pre_op_attr_u.attributes.ctime.nseconds = 0;

    return result;
}

/*
 * compute post-operation attributes given a stat buffer
 */
post_op_attr get_post_buf(struct stat buf)
{
    post_op_attr result;

    result.attributes_follow = TRUE;

    if (S_ISDIR(buf.st_mode))
	result.post_op_attr_u.attributes.type = NF3DIR;
    else if (S_ISBLK(buf.st_mode))
	result.post_op_attr_u.attributes.type = NF3BLK;
    else if (S_ISCHR(buf.st_mode))
	result.post_op_attr_u.attributes.type = NF3CHR;
    else if (S_ISLNK(buf.st_mode))
	result.post_op_attr_u.attributes.type = NF3LNK;
    else if (S_ISSOCK(buf.st_mode))
	result.post_op_attr_u.attributes.type = NF3SOCK;
    else if (S_ISFIFO(buf.st_mode))
	result.post_op_attr_u.attributes.type = NF3FIFO;
    else
	result.post_op_attr_u.attributes.type = NF3REG;

    result.post_op_attr_u.attributes.mode = buf.st_mode & 0xFFFF;
    result.post_op_attr_u.attributes.nlink = buf.st_nlink;
    result.post_op_attr_u.attributes.uid = buf.st_uid;
    result.post_op_attr_u.attributes.gid = buf.st_gid;
    result.post_op_attr_u.attributes.size = buf.st_size;
    result.post_op_attr_u.attributes.used = buf.st_blocks * 512;
    result.post_op_attr_u.attributes.rdev.specdata1 =
	(buf.st_rdev >> 8) & 0xFF;
    result.post_op_attr_u.attributes.rdev.specdata2 = buf.st_rdev & 0xFF;
    result.post_op_attr_u.attributes.fsid = buf.st_dev;
    result.post_op_attr_u.attributes.fileid =
	((uint64) buf.st_dev << 32) + buf.st_ino;
    result.post_op_attr_u.attributes.atime.seconds = buf.st_atime;
    result.post_op_attr_u.attributes.atime.nseconds = 0;
    result.post_op_attr_u.attributes.mtime.seconds = buf.st_mtime;
    result.post_op_attr_u.attributes.mtime.nseconds = 0;
    result.post_op_attr_u.attributes.ctime.seconds = buf.st_ctime;
    result.post_op_attr_u.attributes.ctime.nseconds = 0;

    return result;
}

/*
 * lowlevel routine for getting post-operation attributes
 */
static post_op_attr get_post_ll(const char *path, uint32 dev, uint32 ino)
{
    struct stat buf;
    int res;

    if (!path)
	return error_attr();

    res = lstat(path, &buf);
    if (res == -1)
	return error_attr();

    /* protect against local fs race */
    if (dev != buf.st_dev || ino != buf.st_ino)
	return error_attr();

    return get_post_buf(buf);
}

/*
 * return post-operation attributes, using fh for old dev/ino
 */
post_op_attr get_post_attr(const char *path, nfs_fh3 nfh)
{
    unfs3_fh_t *fh = (void *) nfh.data.data_val;

    return get_post_ll(path, fh->dev, fh->ino);
}

/*
 * return post-operation attributes, using stat cache for old dev/ino
 */
post_op_attr get_post_stat(const char *path)
{
    return get_post_ll(path, st_cache.st_dev, st_cache.st_ino);
}

/*
 * return post-operation attributes using stat cache
 *
 * fd_decomp must be called before to fill the stat cache
 */
post_op_attr get_post_cached(void)
{
    if (!st_cache_valid)
	return error_attr();

    return get_post_buf(st_cache);
}

/*
 * set attributes of an object
 */
nfsstat3 set_attr(const char *path, nfs_fh3 nfh, sattr3 new)
{
    unfs3_fh_t *fh = (void *) nfh.data.data_val;
    int res, fd;
    uid_t new_uid;
    gid_t new_gid;
    time_t new_atime, new_mtime;
    struct utimbuf utim;
    struct stat buf;

    /* 
     * deny clearing both the owner read and write bit since we need
     * to open() the file to set attributes
     */
    if (new.mode.set_it == TRUE &&
	(new.mode.set_mode3_u.mode & S_IRUSR) != S_IRUSR &&
	(new.mode.set_mode3_u.mode & S_IWUSR) != S_IWUSR)
	return NFS3ERR_INVAL;

    fd = open(path, O_WRONLY | O_NONBLOCK);
    if (fd == -1)
	fd = open(path, O_RDONLY | O_NONBLOCK);

    if (fd == -1)
	return NFS3ERR_INVAL;

    res = fstat(fd, &buf);
    if (res == -1) {
	close(fd);
	return NFS3ERR_STALE;
    }

    /* check local fs race */
    if (fh->dev != buf.st_dev || fh->ino != buf.st_ino ||
	fh->gen != get_gen(buf, fd, path)) {
	close(fd);
	return NFS3ERR_STALE;
    }

    /* set file size */
    if (new.size.set_it == TRUE) {
	res = ftruncate(fd, new.size.set_size3_u.size);
	if (res == -1) {
	    close(fd);
	    return setattr_err();
	}
    }

    /* set uid and gid */
    if (new.uid.set_it == TRUE || new.gid.set_it == TRUE) {
	if (new.uid.set_it == TRUE)
	    new_uid = new.uid.set_uid3_u.uid;
	else
	    new_uid = -1;
	if (new_uid == buf.st_uid)
	    new_uid = -1;

	if (new.gid.set_it == TRUE)
	    new_gid = new.gid.set_gid3_u.gid;
	else
	    new_gid = -1;

	res = fchown(fd, new_uid, new_gid);
	if (res == -1) {
	    close(fd);
	    return setattr_err();
	}
    }

    /* set mode */
    if (new.mode.set_it == TRUE) {
	res = fchmod(fd, new.mode.set_mode3_u.mode);
	if (res == -1) {
	    close(fd);
	    return setattr_err();
	}
    }

    res = close(fd);
    if (res == -1) {
	/* error on close probably means attributes didn't make it */
	return NFS3ERR_IO;
    }

    /* 
     * setting of times races with local filesystem
     *
     * we may set the time on the wrong file system object
     */

    if (new.atime.set_it != DONT_CHANGE || new.mtime.set_it != DONT_CHANGE) {

	/* compute atime to set */
	if (new.atime.set_it == SET_TO_SERVER_TIME)
	    new_atime = time(NULL);
	else if (new.atime.set_it == SET_TO_CLIENT_TIME)
	    new_atime = new.atime.set_atime_u.atime.seconds;
	else			       /* DONT_CHANGE */
	    new_atime = buf.st_atime;

	/* compute mtime to set */
	if (new.mtime.set_it == SET_TO_SERVER_TIME)
	    new_mtime = time(NULL);
	else if (new.mtime.set_it == SET_TO_CLIENT_TIME)
	    new_mtime = new.mtime.set_mtime_u.mtime.seconds;
	else			       /* DONT_CHANGE */
	    new_mtime = buf.st_mtime;

	utim.actime = new_atime;
	utim.modtime = new_mtime;

	/* set atime and mtime */
	res = utime(path, &utim);
	if (res == -1)
	    return setattr_err();
    }

    return NFS3_OK;
}

/*
 * deduce mode from given settable attributes
 * default to rwxrwxr-x if no mode given
 */
mode_t create_mode(sattr3 new)
{
    if (new.mode.set_it == TRUE)
	if ((new.mode.set_mode3_u.mode & S_IRUSR) != S_IRUSR &&
	    (new.mode.set_mode3_u.mode & S_IWUSR) != S_IWUSR)
	    /* 
	     * keep owner read access always on since
	     * other further chmod() would get impossible
	     */
	    return new.mode.set_mode3_u.mode | S_IRUSR;
	else
	    return new.mode.set_mode3_u.mode;
    else
	return S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP |
	    S_IROTH | S_IXOTH;
}

/*
 * check whether an sattr3 is settable atomically on a create op
 */
nfsstat3 atomic_attr(sattr3 attr)
{
    if (attr.uid.set_it == TRUE || attr.gid.set_it == TRUE ||
	attr.size.set_it == TRUE || attr.atime.set_it != DONT_CHANGE ||
	attr.mtime.set_it != DONT_CHANGE)
	return NFS3ERR_SERVERFAULT;
    else
	return NFS3_OK;
}
