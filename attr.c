
/*
 * UNFS3 attribute handling
 * (C) 2004, Pascal Schmidt
 * see file LICENSE for license details
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <rpc/rpc.h>
#include <fcntl.h>
#include <time.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <utime.h>
#include <errno.h>

#include "backend.h"
#include "nfs.h"
#include "attr.h"
#include "error.h"
#include "fh.h"
#include "fh_cache.h"
#include "daemon.h"
#include "user.h"
#include "Config/exports.h"

#ifndef HAVE_CLOCK_GETTIME
# include "clock_gettime.h"
#endif /* HAVE_CLOCK_GETTIME */

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
#ifdef __GNUC__
static post_op_attr error_attr = {.attributes_follow = FALSE };
#else
static post_op_attr error_attr = { FALSE };
#endif

struct timespec nfstime3_to_timespec(const nfstime3 nt) {
    struct timespec ts;
    ts.tv_sec = nt.seconds;
    ts.tv_nsec = nt.nseconds;
    return ts;
}

nfstime3 timespec_to_nfstime3(const struct timespec ts) {
    nfstime3 nt;
    nt.seconds = ts.tv_sec;
    nt.nseconds = ts.tv_nsec;
    return nt;
}

/*
 * Helper functions to extract nfstime3 structures from stat
 * structures, depending on what precision is available.
 */
nfstime3 get_stat_atime(const backend_statstruct statbuf)
{
    nfstime3 time;
#if defined(HAVE_STRUCT_STAT_ST_ATIMESPEC)
    time = timespec_to_nfstime3(statbuf.st_atimespec);
#elif defined(HAVE_STRUCT_STAT_ST_ATIM)
    time = timespec_to_nfstime3(statbuf.st_atim);
#else
    time.seconds = statbuf.st_atime;
    time.nseconds = 0;
#endif
    return time;
}

nfstime3 get_stat_mtime(const backend_statstruct statbuf)
{
    nfstime3 time;
#if defined(HAVE_STRUCT_STAT_ST_ATIMESPEC)
    time = timespec_to_nfstime3(statbuf.st_mtimespec);
#elif defined(HAVE_STRUCT_STAT_ST_ATIM)
    time = timespec_to_nfstime3(statbuf.st_mtim);
#else
    time.seconds = statbuf.st_mtime;
    time.nseconds = 0;
#endif
    return time;
}

nfstime3 get_stat_ctime(const backend_statstruct statbuf)
{
    nfstime3 time;
#if defined(HAVE_STRUCT_STAT_ST_ATIMESPEC)
    time = timespec_to_nfstime3(statbuf.st_ctimespec);
#elif defined(HAVE_STRUCT_STAT_ST_ATIM)
    time = timespec_to_nfstime3(statbuf.st_ctim);
#else
    time.seconds = statbuf.st_ctime;
    time.nseconds = 0;
#endif
    return time;
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
    result.pre_op_attr_u.attributes.mtime = get_stat_mtime(st_cache);
    result.pre_op_attr_u.attributes.ctime = get_stat_ctime(st_cache);

    return result;
}

/*
 * compute post-operation attributes given a stat buffer
 */
post_op_attr get_post_buf(backend_statstruct buf, struct svc_req * req)
{
    post_op_attr result;

    result.attributes_follow = TRUE;

    if (S_ISDIR(buf.st_mode))
	result.post_op_attr_u.attributes.type = NF3DIR;
    else if (S_ISBLK(buf.st_mode))
	result.post_op_attr_u.attributes.type = NF3BLK;
    else if (S_ISCHR(buf.st_mode))
	result.post_op_attr_u.attributes.type = NF3CHR;
#ifdef S_ISLNK
    else if (S_ISLNK(buf.st_mode))
	result.post_op_attr_u.attributes.type = NF3LNK;
#endif				       /* S_ISLNK */
#ifdef S_ISSOCK
    else if (S_ISSOCK(buf.st_mode))
	result.post_op_attr_u.attributes.type = NF3SOCK;
#endif				       /* S_ISSOCK */
    else if (S_ISFIFO(buf.st_mode))
	result.post_op_attr_u.attributes.type = NF3FIFO;
    else
	result.post_op_attr_u.attributes.type = NF3REG;

    /* adapt permissions for executable files */
    if (opt_readable_executables && S_ISREG(buf.st_mode)) {
	if (buf.st_mode & S_IXUSR)
	    buf.st_mode |= S_IRUSR;
	if (buf.st_mode & S_IXGRP)
	    buf.st_mode |= S_IRGRP;
	if (buf.st_mode & S_IXOTH)
	    buf.st_mode |= S_IROTH;
    }

    result.post_op_attr_u.attributes.mode = buf.st_mode & 0xFFFF;
    result.post_op_attr_u.attributes.nlink = buf.st_nlink;

    /* If -s, translate uids */
    if (opt_singleuser) {
	unsigned int req_uid = 0;
	unsigned int req_gid = 0;
	struct authunix_parms *auth = (struct authunix_parms *) req->rq_clntcred;
	uid_t ruid = backend_getuid();

	if (req->rq_cred.oa_flavor == AUTH_UNIX) {
	    req_uid = auth->aup_uid;
	    req_gid = auth->aup_gid;
	}

	if ((buf.st_uid == ruid) || (ruid == 0))
	    result.post_op_attr_u.attributes.uid = req_uid;
	else
	    result.post_op_attr_u.attributes.uid = 0;

	if ((buf.st_gid == backend_getgid()) || (ruid == 0))
	    result.post_op_attr_u.attributes.gid = req_gid;
	else
	    result.post_op_attr_u.attributes.gid = 0;
    } else {
	/* Normal case */
	result.post_op_attr_u.attributes.uid = buf.st_uid;
	result.post_op_attr_u.attributes.gid = buf.st_gid;
    }

    result.post_op_attr_u.attributes.size = buf.st_size;
    result.post_op_attr_u.attributes.used = buf.st_blocks * 512;
    result.post_op_attr_u.attributes.rdev.specdata1 =
	(buf.st_rdev >> 8) & 0xFF;
    result.post_op_attr_u.attributes.rdev.specdata2 = buf.st_rdev & 0xFF;
    result.post_op_attr_u.attributes.fsid = buf.st_dev;

    /* If this is a removable export point, we should return the preset fsid
       for all objects which resides in the same file system as the exported
       directory */
    if (exports_opts & OPT_REMOVABLE) {
	backend_statstruct epbuf;

	if (backend_lstat(export_path, &epbuf) != -1 &&
	    buf.st_dev == epbuf.st_dev) {
	    result.post_op_attr_u.attributes.fsid = export_fsid;
	}
    }

    /* Always truncate fsid to a 32-bit value, even though the fsid is
       defined as a uint64. We only use 32-bit variables for
       fsid/dev_t:s internally. This caused problems on systems where
       dev_t is signed, such as 32-bit OS X. */
    result.post_op_attr_u.attributes.fsid &= 0xFFFFFFFF;

#if defined(WIN32) || defined(AFS_SUPPORT)
    /* Recent Linux kernels (2.6.24 and newer) expose large fileids even to
       non-LFS 32-bit applications, unless kernel parameter
       nfs.enable_ino64=0. This means that applications will fail with
       EOVERFLOW. On Windows, we always have large st_ino:s. To avoid
       trouble, we truncate to 32 bits */
    result.post_op_attr_u.attributes.fileid =
	(buf.st_ino >> 32) ^ (buf.st_ino & 0xffffffff);
#else
    result.post_op_attr_u.attributes.fileid = buf.st_ino;
#endif

    result.post_op_attr_u.attributes.atime = get_stat_atime(buf);
    result.post_op_attr_u.attributes.mtime = get_stat_mtime(buf);
    result.post_op_attr_u.attributes.ctime = get_stat_ctime(buf);

    return result;
}

/*
 * lowlevel routine for getting post-operation attributes
 */
static post_op_attr get_post_ll(const char *path, uint32 dev, uint64 ino,
				struct svc_req *req)
{
    backend_statstruct buf;
    int res;

    if (!path)
	return error_attr;

    res = backend_lstat(path, &buf);
    if (res == -1)
	return error_attr;

    /* protect against local fs race */
    if (dev != buf.st_dev || ino != buf.st_ino)
	return error_attr;

    return get_post_buf(buf, req);
}

/*
 * return post-operation attributes, using fh for old dev/ino
 */
post_op_attr get_post_attr(const char *path, nfs_fh3 nfh,
			   struct svc_req * req)
{
    unfs3_fh_t fh = fh_decode(&nfh);

    return get_post_ll(path, fh.dev, fh.ino, req);
}

/*
 * return post-operation attributes, using stat cache for old dev/ino
 */
post_op_attr get_post_stat(const char *path, struct svc_req * req)
{
    return get_post_ll(path, st_cache.st_dev, st_cache.st_ino, req);
}

/*
 * return post-operation attributes using stat cache
 *
 * fd_decomp must be called before to fill the stat cache
 */
post_op_attr get_post_cached(struct svc_req * req)
{
    if (!st_cache_valid)
	return error_attr;

    return get_post_buf(st_cache, req);
}

/*
 * setting of time, races with local filesystem
 */
static nfsstat3 set_time(const char *path, backend_statstruct buf, sattr3 new)
{
    struct timespec new_atime, new_mtime;
#if defined(HAVE_UTIMENSAT)
    struct timespec ts[2];
#elif defined(HAVE_UTIMES)
    struct timeval tv[2];
#else
    struct utimbuf utim;
#endif
    int res;

    /* Do nothing if both are DONT_CHANGE */
    if (new.atime.set_it != DONT_CHANGE || new.mtime.set_it != DONT_CHANGE) {

        /* compute atime to set */
        if (new.atime.set_it == SET_TO_SERVER_TIME) {
            clock_gettime(CLOCK_REALTIME, &new_atime);
        }
        else if (new.atime.set_it == SET_TO_CLIENT_TIME)
            new_atime = nfstime3_to_timespec(new.atime.set_atime_u.atime);
        else {			       /* DONT_CHANGE */
            new_atime = nfstime3_to_timespec(get_stat_atime(buf));
        }

        /* compute mtime to set */
        if (new.mtime.set_it == SET_TO_SERVER_TIME) {
            clock_gettime(CLOCK_REALTIME, &new_mtime);
        }
        else if (new.mtime.set_it == SET_TO_CLIENT_TIME)
            new_mtime = nfstime3_to_timespec(new.mtime.set_mtime_u.mtime);
        else {			       /* DONT_CHANGE */
            new_mtime = nfstime3_to_timespec(get_stat_mtime(buf));
        }

#if defined(HAVE_UTIMENSAT)
        ts[0] = new_atime;
        ts[1] = new_mtime;

        res = backend_utimensat(-1, path, ts, 0);
#elif defined(HAVE_UTIMES)
        tv[0].tv_sec = new_atime.tv_sec;
        tv[0].tv_usec = new_atime.tv_nsec / 1000;
        tv[1].tv_sec = new_mtime.tv_sec;
        tv[1].tv_usec = new_mtime.tv_nsec / 1000;

        res = backend_utimes(path, tv);
#else /* !HAVE_UTIMENSAT && !HAVE_UTIMES */
        utim.actime = new_atime.tv_sec;
        utim.modtime = new_mtime.tv_sec;

        res = backend_utime(path, &utim);
#endif /* HAVE_UTIMENSAT */

        if (res == -1)
            return setattr_err();
    }
    return NFS3_OK;
}

/*
 * race unsafe setting of attributes
 */
static nfsstat3 set_attr_unsafe(const char *path, nfs_fh3 nfh, sattr3 new)
{
    unfs3_fh_t fh = fh_decode(&nfh);
    uid_t new_uid;
    gid_t new_gid;
    backend_statstruct buf;
    int res;

    res = backend_lstat(path, &buf);
    if (res != 0)
	return NFS3ERR_STALE;

    /* check local fs race */
    if (buf.st_dev != fh.dev || buf.st_ino != fh.ino)
	return NFS3ERR_STALE;

    /* set file size */
    if (new.size.set_it == TRUE) {
	res = backend_truncate(path, new.size.set_size3_u.size);
	if (res == -1)
	    return setattr_err();
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

	res = backend_lchown(path, new_uid, new_gid);
	if (res == -1)
	    return setattr_err();
    }

    /* set mode */
    if (new.mode.set_it == TRUE) {
	res = backend_chmod(path, new.mode.set_mode3_u.mode);
	if (res == -1)
	    return setattr_err();
    }

    return set_time(path, buf, new);
}

/*
 * set attributes of an object
 */
nfsstat3 set_attr(const char *path, nfs_fh3 nfh, sattr3 new)
{
    unfs3_fh_t fh = fh_decode(&nfh);
    int res, fd;
    uid_t new_uid;
    gid_t new_gid;
    backend_statstruct buf;

    res = backend_lstat(path, &buf);
    if (res != 0)
	return NFS3ERR_STALE;

    /* 
     * don't open(2) device nodes, it could trigger
     * module loading on the server
     */
    if (S_ISBLK(buf.st_mode) || S_ISCHR(buf.st_mode))
	return set_attr_unsafe(path, nfh, new);

#ifdef S_ISLNK
    /* 
     * opening a symlink would open the underlying file,
     * don't try to do that
     */
    if (S_ISLNK(buf.st_mode))
	return set_attr_unsafe(path, nfh, new);
#endif

    /* 
     * open object for atomic setting of attributes
     */
    fd = backend_open(path, O_WRONLY | O_NONBLOCK);
    if (fd == -1)
	fd = backend_open(path, O_RDONLY | O_NONBLOCK);

    if (fd == -1)
	return set_attr_unsafe(path, nfh, new);

    res = backend_fstat(fd, &buf);
    if (res == -1) {
	backend_close(fd);
	return NFS3ERR_STALE;
    }

    /* check local fs race */
    if (fh.dev != buf.st_dev || fh.ino != buf.st_ino ||
	fh.gen != backend_get_gen(buf, fd, path)) {
	backend_close(fd);
	return NFS3ERR_STALE;
    }

    /* set file size */
    if (new.size.set_it == TRUE) {
	res = backend_ftruncate(fd, new.size.set_size3_u.size);
	if (res == -1) {
	    backend_close(fd);
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

	res = backend_fchown(fd, new_uid, new_gid);
	if (res == -1) {
	    backend_close(fd);
	    return setattr_err();
	}
    }

    /* set mode */
    if (new.mode.set_it == TRUE) {
	res = backend_fchmod(fd, new.mode.set_mode3_u.mode);
	if (res == -1) {
	    backend_close(fd);
	    return setattr_err();
	}
    }

    res = backend_close(fd);
    if (res == -1) {
	/* error on close probably means attributes didn't make it */
	return NFS3ERR_IO;
    }

    /* finally, set times */
    return set_time(path, buf, new);
}

/*
 * deduce mode from given settable attributes
 * default to rwxrwxr-x if no mode given
 */
mode_t create_mode(sattr3 new)
{
    if (new.mode.set_it == TRUE)
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
    uid_t used_uid = mangle_uid(attr.uid.set_uid3_u.uid);
    gid_t used_gid = mangle_gid(attr.gid.set_gid3_u.gid);

    if ((attr.uid.set_it == TRUE && used_uid != backend_geteuid()) ||
	(attr.gid.set_it == TRUE && used_gid != backend_getegid()) ||
	(attr.size.set_it == TRUE && attr.size.set_size3_u.size != 0) ||
	attr.atime.set_it == SET_TO_CLIENT_TIME ||
	attr.mtime.set_it == SET_TO_CLIENT_TIME)
	return NFS3ERR_INVAL;
    else
	return NFS3_OK;
}
