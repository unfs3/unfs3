
/*
 * UNFS3 NFS protocol procedures
 * (C) 2004, Pascal Schmidt
 * Copyright 2014 Karl Mikaelsson <derfian@cendio.se> for Cendio AB
 * see file LICENSE for license details
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>		       /* needed for statfs() on NetBSD */
#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>		       /* dito */
#endif
#ifdef HAVE_SYS_VMOUNT_H
#include <sys/vmount.h>		       /* AIX */
#endif
#include <rpc/rpc.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utime.h>
#ifndef WIN32
#include <sys/socket.h>
#include <sys/un.h>
#endif				       /* WIN32 */

#if HAVE_STATVFS == 1
# include <sys/statvfs.h>
#else
# define statvfs statfs
#endif

#include "nfs.h"
#include "mount.h"
#include "fh.h"
#include "fh_cache.h"
#include "attr.h"
#include "readdir.h"
#include "user.h"
#include "error.h"
#include "fd_cache.h"
#include "daemon.h"
#include "backend.h"
#include "Config/exports.h"
#include "Extras/cluster.h"

/*
 * decompose filehandle and switch user if permitted access
 * otherwise zero result structure and return with error status
 */
#define PREP(p,f) do {						\
                      unfs3_fh_t fh = fh_decode(&f); \
                      switch_to_root();				\
                      p = fh_decomp(f);				\
                      if (exports_options(p, rqstp, NULL, NULL) == -1) { \
                          memset(&result, 0, sizeof(result));	\
                          if (p)				\
                              result.status = NFS3ERR_ACCES;	\
                          else					\
                              result.status = NFS3ERR_STALE;	\
                          return &result;			\
                      }						\
                      if (fh.pwhash != export_password_hash) { \
                          memset(&result, 0, sizeof(result));	\
                          result.status = NFS3ERR_STALE;        \
                          return &result;                       \
                      }                                         \
                      switch_user(rqstp);			\
                  } while (0)

/*
 * cat an object name onto a path, checking for illegal input
 */
nfsstat3 cat_name(const char *path, const char *name, char *result)
{
    char *last;

    if (!path)
	return NFS3ERR_STALE;

    if (!name)
	return NFS3ERR_ACCES;

    if (name[0] == 0 || strchr(name, '/') != NULL)
	return NFS3ERR_ACCES;

    if (strlen(path) + strlen(name) + 2 > NFS_MAXPATHLEN)
	return NFS3ERR_NAMETOOLONG;

    if (strcmp(name, ".") == 0) {
	strcpy(result, path);
	return NFS3_OK;
    }

    /* 
     * Irix clients do lookups for .. and then use the
     * resulting filehandle for more lookups, causing them
     * to get filehandles that fh_decomp_raw will refuse to
     * resolve. Export list handling will also get very
     * confused if we allow such filehandles.
     */
    if (strcmp(name, "..") == 0) {
	last = strrchr(path, '/');
	if (!last || last == path)
	    strcpy(result, "/");
	else {
	    *last = 0;
	    strcpy(result, path);
	    *last = '/';
	}
	return NFS3_OK;
    }

    sprintf(result, "%s/%s", path, name);
    return NFS3_OK;
}

void *nfsproc3_null_3_svc(U(void *argp), U(struct svc_req *rqstp))
{
    static void *result = NULL;

    return &result;
}

GETATTR3res *nfsproc3_getattr_3_svc(GETATTR3args * argp,
				    struct svc_req * rqstp)
{
    static GETATTR3res result;
    char *path;
    post_op_attr post;

    PREP(path, argp->object);
    post = get_post_cached(rqstp);

    result.status = NFS3_OK;
    result.GETATTR3res_u.resok.obj_attributes =
	post.post_op_attr_u.attributes;

    return &result;
}

/*
 * check ctime guard for SETATTR procedure
 */
static nfsstat3 in_sync(sattrguard3 guard, pre_op_attr pre)
{
    if (!pre.attributes_follow)
	return NFS3ERR_STALE;

    if (!guard.check)
	return NFS3_OK;

    if (guard.sattrguard3_u.obj_ctime.seconds !=
	pre.pre_op_attr_u.attributes.ctime.seconds)
	return NFS3ERR_NOT_SYNC;

    return NFS3_OK;
}

SETATTR3res *nfsproc3_setattr_3_svc(SETATTR3args * argp,
				    struct svc_req * rqstp)
{
    static SETATTR3res result;
    pre_op_attr pre;
    char *path;

    PREP(path, argp->object);
    pre = get_pre_cached();
    result.status = join(in_sync(argp->guard, pre), exports_rw());

    if (result.status == NFS3_OK)
	result.status = set_attr(path, argp->object, argp->new_attributes);

    /* overlaps with resfail */
    result.SETATTR3res_u.resok.obj_wcc.before = pre;
    result.SETATTR3res_u.resok.obj_wcc.after = get_post_stat(path, rqstp);

    return &result;
}

LOOKUP3res *nfsproc3_lookup_3_svc(LOOKUP3args * argp, struct svc_req * rqstp)
{
    static LOOKUP3res result;
    unfs3_fh_t *fh;
    static char fhbuf[FH_MAXBUF];
    char *path;
    char obj[NFS_MAXPATHLEN];
    backend_statstruct buf;
    int res;
    uint32 gen;

    PREP(path, argp->what.dir);
    result.status = cat_name(path, argp->what.name, obj);

    cluster_lookup(obj, rqstp, &result.status);

    if (result.status == NFS3_OK) {
	res = backend_lstat(obj, &buf);
	if (res == -1)
	    result.status = lookup_err();
	else {
	    if (strcmp(argp->what.name, ".") == 0 ||
		strcmp(argp->what.name, "..") == 0) {
		fh = fh_comp_ptr(obj, rqstp, 0);
	    } else {
		gen = backend_get_gen(buf, FD_NONE, obj);
		fh = fh_extend(argp->what.dir, buf.st_dev, buf.st_ino, gen);
		fh_cache_add(buf.st_dev, buf.st_ino, obj);
	    }

	    if (fh) {
		result.LOOKUP3res_u.resok.object = fh_encode(fh, fhbuf);
		fix_dir_times(obj, &buf);
		result.LOOKUP3res_u.resok.obj_attributes =
		    get_post_buf(buf, rqstp);
	    } else {
		/* path was too long */
		result.status = NFS3ERR_NAMETOOLONG;
	    }
	}
    }

    /* overlaps with resfail */
    result.LOOKUP3res_u.resok.dir_attributes = get_post_stat(path, rqstp);

    return &result;
}

ACCESS3res *nfsproc3_access_3_svc(ACCESS3args * argp, struct svc_req * rqstp)
{
    static ACCESS3res result;
    char *path;
    post_op_attr post;
    mode_t mode;
    int newaccess = 0;

    PREP(path, argp->object);
    post = get_post_cached(rqstp);
    mode = post.post_op_attr_u.attributes.mode;

    if (access(path, R_OK) != -1)
        newaccess |= ACCESS3_READ;

    if (access(path, W_OK) != -1)
        newaccess |= ACCESS3_MODIFY | ACCESS3_EXTEND;

    if (access(path, X_OK) != -1) {
        newaccess |= ACCESS3_EXECUTE;
        if (opt_readable_executables)
            newaccess |= ACCESS3_READ;
    }

    /* root is allowed everything */
    if (get_uid(rqstp) == 0)
	newaccess |= ACCESS3_READ | ACCESS3_MODIFY | ACCESS3_EXTEND;

    /* adjust if directory */
    if (post.post_op_attr_u.attributes.type == NF3DIR) {
	if (newaccess & (ACCESS3_READ | ACCESS3_EXECUTE))
	    newaccess |= ACCESS3_LOOKUP;
	if (newaccess & ACCESS3_MODIFY)
	    newaccess |= ACCESS3_DELETE;
	newaccess &= ~ACCESS3_EXECUTE;
    }

    result.status = NFS3_OK;
    result.ACCESS3res_u.resok.access = newaccess & argp->access;
    result.ACCESS3res_u.resok.obj_attributes = post;

    return &result;
}

READLINK3res *nfsproc3_readlink_3_svc(READLINK3args * argp,
				      struct svc_req * rqstp)
{
    static READLINK3res result;
    char *path;
    static char buf[NFS_MAXPATHLEN];
    int res;

    PREP(path, argp->symlink);

    res = backend_readlink(path, buf, NFS_MAXPATHLEN - 1);
    if (res == -1)
	result.status = readlink_err();
    else {
	/* readlink does not NULL-terminate */
	buf[res] = 0;

	result.status = NFS3_OK;
	result.READLINK3res_u.resok.data = buf;
    }

    /* overlaps with resfail */
    result.READLINK3res_u.resok.symlink_attributes =
	get_post_stat(path, rqstp);

    return &result;
}

READ3res *nfsproc3_read_3_svc(READ3args * argp, struct svc_req * rqstp)
{
    static READ3res result;
    char *path;
    int fd, res;
    static char buf[NFS_MAXDATA_TCP + 1];
    unsigned int maxdata;

    if (get_socket_type(rqstp) == SOCK_STREAM)
	maxdata = NFS_MAXDATA_TCP;
    else
	maxdata = NFS_MAXDATA_UDP;

    PREP(path, argp->file);
    result.status = is_reg();

    /* handle reading of executables */
    read_executable(rqstp, st_cache);

    /* handle read of owned files */
    read_by_owner(rqstp, st_cache);

    /* if bigger than rtmax, truncate length */
    if (argp->count > maxdata)
	argp->count = maxdata;

    if (result.status == NFS3_OK) {
	fd = fd_open(path, argp->file, UNFS3_FD_READ, TRUE);
	if (fd != -1) {
	    /* read one more to check for eof */
	    res = backend_pread(fd, buf, argp->count + 1, (off64_t)argp->offset);

	    /* eof if we could not read one more */
	    result.READ3res_u.resok.eof = (res <= (int64) argp->count);

	    /* close for real when hitting eof */
	    if (result.READ3res_u.resok.eof)
		fd_close(fd, UNFS3_FD_READ, FD_CLOSE_REAL);
	    else {
		fd_close(fd, UNFS3_FD_READ, FD_CLOSE_VIRT);
		res--;
	    }

	    if (res >= 0) {
		result.READ3res_u.resok.count = res;
		result.READ3res_u.resok.data.data_len = res;
		result.READ3res_u.resok.data.data_val = buf;
	    } else {
		/* error during read() */

		/* EINVAL means unreadable object */
		if (errno == EINVAL)
		    result.status = NFS3ERR_INVAL;
		else
		    result.status = NFS3ERR_IO;
	    }
	} else
	    /* opening for read failed */
	    result.status = read_err();
    }

    /* overlaps with resfail */
    result.READ3res_u.resok.file_attributes = get_post_stat(path, rqstp);

    return &result;
}

WRITE3res *nfsproc3_write_3_svc(WRITE3args * argp, struct svc_req * rqstp)
{
    static WRITE3res result;
    char *path;
    int fd, res, res_close;

    PREP(path, argp->file);
    result.status = join(is_reg(), exports_rw());

    /* handle write of owned files */
    write_by_owner(rqstp, st_cache);

    if (result.status == NFS3_OK) {
	/* We allow caching of the fd only for unstable writes. This is to
	   prevent generating a new write verifier for failed stable writes,
	   when the fd was not in the cache. Besides, for stable writes, the
	   fd will be removed from the cache by fd_close() below, so adding
	   it to and removing it from the cache is just a waste of CPU cycles 
	 */
	fd = fd_open(path, argp->file, UNFS3_FD_WRITE,
		     (argp->stable == UNSTABLE));
	if (fd != -1) {
	    res =
		backend_pwrite(fd, argp->data.data_val, argp->data.data_len,
			       (off64_t)argp->offset);

	    /* close for real if not UNSTABLE write */
	    if (argp->stable == UNSTABLE)
		res_close = fd_close(fd, UNFS3_FD_WRITE, FD_CLOSE_VIRT);
	    else
		res_close = fd_close(fd, UNFS3_FD_WRITE, FD_CLOSE_REAL);

	    /* we always do fsync(), never fdatasync() */
	    if (argp->stable == DATA_SYNC)
		argp->stable = FILE_SYNC;

	    if (res != -1 && res_close != -1) {
		result.WRITE3res_u.resok.count = res;
		result.WRITE3res_u.resok.committed = argp->stable;
		memcpy(result.WRITE3res_u.resok.verf, wverf,
		       NFS3_WRITEVERFSIZE);
	    } else {
		/* error during write or close */
		result.status = write_write_err();
	    }
	} else
	    /* could not open for writing */
	    result.status = write_open_err();
    }

    /* overlaps with resfail */
    result.WRITE3res_u.resok.file_wcc.before = get_pre_cached();
    result.WRITE3res_u.resok.file_wcc.after = get_post_stat(path, rqstp);

    return &result;
}

/* seconds between 1970-01-01 and 1980-01-01 */
static const unsigned FT80SEC = 315532800;

/*
 * store verifier in atime and mtime 
 */
static int store_create_verifier(char *obj, createverf3 verf)
{
    char hashbuf[9];
    uint32 hash;
    struct utimbuf ubuf;

    /* FAT has a very limited number of bits for file times, so we hash
       the verifier down to 32 bits to be able to fit it in. This
       increases the risk of collisions a bit, but we should hopefully
       not have the kind of load where this is a problem. */
    memcpy(hashbuf, verf, 8);
    hashbuf[8] = '\0';
    hash = fnv1a_32(hashbuf);

    /* FAT can only store dates in the interval 1980-01-01 to 2107-12-31.
       However, since the utime interface uses Epoch time, we are further
       limited to 1980-01-01 to 2038-01-19, assuming 32 bit signed time_t.
       math.log(2**31-1 - FT80SEC, 2) = 30.7, which means that we only have
       30 bits. WriteTime then only has a resolution of 2 seconds, meaning
       we lose yet another bit there. And finally AccessTime has the really
       poor resolution of 1 day. So we need to spread things out. */

    /* 29 bits in WriteTime */
    ubuf.modtime = ((hash & 0x1fffffff) * 2) + FT80SEC;
    /* And the remaining 3 bits in AccessTime. Things get hairy here as
       Windows stores time stamps in local time on FAT. But since we only
       have a resolution of a whole day, the conversion between UTC and
       local time might shift us over to the wrong day. To handle this
       we sacrifice a few bits and shift the value up enough that we can
       mask off any conversion noise when we compare later. */
    ubuf.actime = (((((hash >> 29) * 24) << 6) | 0x20) * 3600) + FT80SEC;

    return backend_utime(obj, &ubuf);
}

/*
 * check if a create verifier matches
 */
static int check_create_verifier(backend_statstruct * buf, createverf3 verf)
{
    char hashbuf[9];
    uint32 hash, expected;

    /* Compute the expected value, same as above */
    memcpy(hashbuf, verf, 8);
    hashbuf[8] = '\0';
    expected = fnv1a_32(hashbuf);

    /* Extract the hash from the file, strategically dropping bits where
       the file system might have messed things up for us (see above). */
    hash = (buf->st_mtime - FT80SEC) / 2;
    hash |= ((((buf->st_atime - FT80SEC) / 3600) >> 6) / 24) << 29;

    return hash == expected;
}

CREATE3res *nfsproc3_create_3_svc(CREATE3args * argp, struct svc_req * rqstp)
{
    static CREATE3res result;
    char *path;
    char obj[NFS_MAXPATHLEN];
    sattr3 new_attr;
    int fd = -1, res = -1;
    backend_statstruct buf;
    uint32 gen;
    int flags = O_RDWR | O_CREAT | O_TRUNC | O_NONBLOCK;

    PREP(path, argp->where.dir);
    result.status = join(cat_name(path, argp->where.name, obj), exports_rw());

    cluster_create(obj, rqstp, &result.status);

    /* GUARDED and EXCLUSIVE maps to Unix exclusive create */
    if (argp->how.mode != UNCHECKED)
	flags = flags | O_EXCL;

    if (argp->how.mode != EXCLUSIVE) {
	new_attr = argp->how.createhow3_u.obj_attributes;
	result.status = join(result.status, atomic_attr(new_attr));
    }

    /* Try to open the file */
    if (result.status == NFS3_OK) {
	if (argp->how.mode != EXCLUSIVE) {
	    fd = backend_open_create(obj, flags, create_mode(new_attr));
	} else {
	    fd = backend_open_create(obj, flags, create_mode(new_attr));
	}
    }

    if (fd != -1) {
	/* Successful open */
	res = backend_fstat(fd, &buf);
	if (res != -1) {
	    /* Successful stat */
	    if (argp->how.mode == EXCLUSIVE) {
		/* Save verifier in atime and mtime */
		res = store_create_verifier(obj, argp->how.createhow3_u.verf);
		/* Check that it was properly stored */
		if (res != -1) {
		    res = backend_stat(obj, &buf);
		}
		if (res != -1) {
		    if (!check_create_verifier(&buf, argp->how.createhow3_u.verf)) {
			res = -1;
		    }
		}
	    }
	}

	if (res != -1) {
	    /* So far, so good */
	    gen = backend_get_gen(buf, fd, obj);
	    fh_cache_add(buf.st_dev, buf.st_ino, obj);

	    result.CREATE3res_u.resok.obj =
		fh_extend_post(argp->where.dir, buf.st_dev, buf.st_ino, gen);
	    result.CREATE3res_u.resok.obj_attributes =
		get_post_buf(buf, rqstp);
	}

	if (res == -1) {
	    /* backend_fstat() or store_create_verifier() failed */
	    result.status = NFS3ERR_IO;
	}

	backend_close(fd);

    } else if (result.status == NFS3_OK) {
	/* open() failed */
	if (argp->how.mode == EXCLUSIVE && errno == EEXIST) {
	    /* Check if verifier matches */
	    fd = backend_open(obj, O_NONBLOCK);
	    if (fd != -1) {
		res = backend_fstat(fd, &buf);

		if (res != -1) {
		    if (check_create_verifier(&buf, argp->how.createhow3_u.verf)) {
			/* The verifier matched. Return success */
			gen = backend_get_gen(buf, fd, obj);
			fh_cache_add(buf.st_dev, buf.st_ino, obj);

			result.CREATE3res_u.resok.obj =
			    fh_extend_post(argp->where.dir, buf.st_dev,
					   buf.st_ino, gen);
			result.CREATE3res_u.resok.obj_attributes =
			    get_post_buf(buf, rqstp);
		    } else {
			/* The verifier doesn't match */
			result.status = NFS3ERR_EXIST;
		    }
		}

		backend_close(fd);
	    }
	}
	if (res == -1) {
	    result.status = create_err();
	}
    }

    /* overlaps with resfail */
    result.CREATE3res_u.resok.dir_wcc.before = get_pre_cached();
    result.CREATE3res_u.resok.dir_wcc.after = get_post_stat(path, rqstp);

    return &result;
}

MKDIR3res *nfsproc3_mkdir_3_svc(MKDIR3args * argp, struct svc_req * rqstp)
{
    static MKDIR3res result;
    char *path;
    pre_op_attr pre;
    post_op_attr post;
    char obj[NFS_MAXPATHLEN];
    int res;

    PREP(path, argp->where.dir);
    pre = get_pre_cached();
    result.status =
	join3(cat_name(path, argp->where.name, obj),
	      atomic_attr(argp->attributes), exports_rw());

    cluster_create(obj, rqstp, &result.status);

    if (result.status == NFS3_OK) {
	res = backend_mkdir(obj, create_mode(argp->attributes));
	if (res == -1)
	    result.status = mkdir_err();
	else {
	    result.MKDIR3res_u.resok.obj =
		fh_extend_type(argp->where.dir, obj, S_IFDIR);
	    result.MKDIR3res_u.resok.obj_attributes = get_post_cached(rqstp);
	}
    }

    post = get_post_attr(path, argp->where.dir, rqstp);

    /* overlaps with resfail */
    result.MKDIR3res_u.resok.dir_wcc.before = pre;
    result.MKDIR3res_u.resok.dir_wcc.after = post;

    return &result;
}

SYMLINK3res *nfsproc3_symlink_3_svc(SYMLINK3args * argp,
				    struct svc_req * rqstp)
{
    static SYMLINK3res result;
    char *path;
    pre_op_attr pre;
    post_op_attr post;
    char obj[NFS_MAXPATHLEN];
    int res;
    mode_t new_mode;

    PREP(path, argp->where.dir);
    pre = get_pre_cached();
    result.status =
	join3(cat_name(path, argp->where.name, obj),
	      atomic_attr(argp->symlink.symlink_attributes), exports_rw());

    cluster_create(obj, rqstp, &result.status);

    if (argp->symlink.symlink_attributes.mode.set_it == TRUE)
	new_mode = create_mode(argp->symlink.symlink_attributes);
    else {
	/* default rwxrwxrwx */
	new_mode =
	    S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP |
	    S_IROTH | S_IWOTH | S_IXOTH;
    }

    if (result.status == NFS3_OK) {
	umask(~new_mode);
	res = backend_symlink(argp->symlink.symlink_data, obj);
	umask(0);
	if (res == -1)
	    result.status = symlink_err();
	else {
	    result.SYMLINK3res_u.resok.obj =
		fh_extend_type(argp->where.dir, obj, S_IFLNK);
	    result.SYMLINK3res_u.resok.obj_attributes =
		get_post_cached(rqstp);
	}
    }

    post = get_post_attr(path, argp->where.dir, rqstp);

    /* overlaps with resfail */
    result.SYMLINK3res_u.resok.dir_wcc.before = pre;
    result.SYMLINK3res_u.resok.dir_wcc.after = post;

    return &result;
}

#ifndef WIN32
static char pathbuf_tmp[NFS_MAXPATHLEN + NFS_MAXNAMLEN + 1];

/*
 * create Unix socket
 */
static int mksocket(const char *path, mode_t mode)
{
    int res, sock;
    struct sockaddr_un addr;
    unsigned int len = strlen(path);

    sock = socket(PF_UNIX, SOCK_STREAM, 0);
    res = sock;
    if (res != -1) {
	addr.sun_family = AF_UNIX;
	if (len < sizeof(addr.sun_path) -1) {
	    strcpy(addr.sun_path, path);
	} else {
	    char *ptr;
	    res = -1;
	    if (len >= sizeof(path))
		goto out;
	    strcpy(pathbuf_tmp, path);
	    ptr = strrchr(pathbuf_tmp,'/');
	    if (ptr) {
		*ptr = '\0';
		ptr++;
		if (chdir(pathbuf_tmp))
		    goto out;
	    } else {
		ptr = pathbuf_tmp;
	    }
	    if (strlen(ptr) >= sizeof(addr.sun_path))
		goto out;
	    strcpy(addr.sun_path, ptr);
	}
	umask(~mode);
	res =
	    bind(sock, (struct sockaddr *) &addr,
		 sizeof(addr.sun_family) + strlen(addr.sun_path));
	umask(0);
out:
	if (chdir("/"))
	    fprintf(stderr, "Internal failure to chdir /\n");
	close(sock);
    }
    return res;
}

#endif				       /* WIN32 */

/*
 * check and process arguments to MKNOD procedure
 */
static nfsstat3 mknod_args(mknoddata3 what, const char *obj, mode_t * mode,
			   dev_t * dev)
{
    sattr3 attr;

    /* determine attributes */
    switch (what.type) {
	case NF3REG:
	case NF3DIR:
	case NF3LNK:
	    return NFS3ERR_INVAL;
	case NF3SOCK:
	    if (strlen(obj) + 1 > UNIX_PATH_MAX)
		return NFS3ERR_NAMETOOLONG;
	    /* fall thru */
	case NF3FIFO:
	    attr = what.mknoddata3_u.pipe_attributes;
	    break;
	case NF3BLK:
	case NF3CHR:
	    attr = what.mknoddata3_u.device.dev_attributes;
	    *dev = (what.mknoddata3_u.device.spec.specdata1 << 8)
		+ what.mknoddata3_u.device.spec.specdata2;
	    break;
    }

    *mode = create_mode(attr);

    /* adjust mode for creation of device special files */
    switch (what.type) {
	case NF3CHR:
	    *mode |= S_IFCHR;
	    break;
	case NF3BLK:
	    *mode |= S_IFBLK;
	    break;
	default:
	    break;
    }

    return atomic_attr(attr);
}

MKNOD3res *nfsproc3_mknod_3_svc(MKNOD3args * argp, struct svc_req * rqstp)
{
    static MKNOD3res result;
    char *path;
    pre_op_attr pre;
    post_op_attr post;
    char obj[NFS_MAXPATHLEN];
    int res;
    mode_t new_mode = 0;
    dev_t dev = 0;

    PREP(path, argp->where.dir);
    pre = get_pre_cached();
    result.status =
	join3(cat_name(path, argp->where.name, obj),
	      mknod_args(argp->what, obj, &new_mode, &dev), exports_rw());

    cluster_create(obj, rqstp, &result.status);

    if (result.status == NFS3_OK) {
	if (argp->what.type == NF3CHR || argp->what.type == NF3BLK)
	    res = backend_mknod(obj, new_mode, dev);	/* device */
	else if (argp->what.type == NF3FIFO)
	    res = backend_mkfifo(obj, new_mode);	/* FIFO */
	else
	    res = backend_mksocket(obj, new_mode);	/* socket */

	if (res == -1) {
	    result.status = mknod_err();
	} else {
	    result.MKNOD3res_u.resok.obj =
		fh_extend_type(argp->where.dir, obj,
			       type_to_mode(argp->what.type));
	    result.MKNOD3res_u.resok.obj_attributes = get_post_cached(rqstp);
	}
    }

    post = get_post_attr(path, argp->where.dir, rqstp);

    /* overlaps with resfail */
    result.MKNOD3res_u.resok.dir_wcc.before = pre;
    result.MKNOD3res_u.resok.dir_wcc.after = post;

    return &result;
}

REMOVE3res *nfsproc3_remove_3_svc(REMOVE3args * argp, struct svc_req * rqstp)
{
    static REMOVE3res result;
    char *path;
    char obj[NFS_MAXPATHLEN];
    int res;

    PREP(path, argp->object.dir);
    result.status =
	join(cat_name(path, argp->object.name, obj), exports_rw());

    cluster_lookup(obj, rqstp, &result.status);

    if (result.status == NFS3_OK) {
        change_readdir_cookie();
	res = backend_remove(obj);
	if (res == -1)
	    result.status = remove_err();
    }

    /* overlaps with resfail */
    result.REMOVE3res_u.resok.dir_wcc.before = get_pre_cached();
    result.REMOVE3res_u.resok.dir_wcc.after = get_post_stat(path, rqstp);

    return &result;
}

RMDIR3res *nfsproc3_rmdir_3_svc(RMDIR3args * argp, struct svc_req * rqstp)
{
    static RMDIR3res result;
    char *path;
    char obj[NFS_MAXPATHLEN];
    int res;

    PREP(path, argp->object.dir);
    result.status =
	join(cat_name(path, argp->object.name, obj), exports_rw());

    cluster_lookup(obj, rqstp, &result.status);

    if (result.status == NFS3_OK) {
        change_readdir_cookie();
	res = backend_rmdir(obj);
	if (res == -1)
	    result.status = rmdir_err();
    }

    /* overlaps with resfail */
    result.RMDIR3res_u.resok.dir_wcc.before = get_pre_cached();
    result.RMDIR3res_u.resok.dir_wcc.after = get_post_stat(path, rqstp);

    return &result;
}

RENAME3res *nfsproc3_rename_3_svc(RENAME3args * argp, struct svc_req * rqstp)
{
    static RENAME3res result;
    char *from;
    char *to;
    char from_obj[NFS_MAXPATHLEN];
    char to_obj[NFS_MAXPATHLEN];
    pre_op_attr pre;
    post_op_attr post;
    int res;

    PREP(from, argp->from.dir);
    pre = get_pre_cached();
    result.status =
	join(cat_name(from, argp->from.name, from_obj), exports_rw());

    cluster_lookup(from_obj, rqstp, &result.status);

    to = fh_decomp(argp->to.dir);

    if (result.status == NFS3_OK) {
	result.status =
	    join(cat_name(to, argp->to.name, to_obj),
		 exports_compat(to, rqstp));

	cluster_create(to_obj, rqstp, &result.status);

	if (result.status == NFS3_OK) {
	    change_readdir_cookie();
	    res = backend_rename(from_obj, to_obj);
	    if (res == -1)
		result.status = rename_err();
	    /* Update the fh_cache with moved inode value */
	    fh_cache_update(argp->to.dir, to_obj);
	}
    }

    post = get_post_attr(from, argp->from.dir, rqstp);

    /* overlaps with resfail */
    result.RENAME3res_u.resok.fromdir_wcc.before = pre;
    result.RENAME3res_u.resok.fromdir_wcc.after = post;
    result.RENAME3res_u.resok.todir_wcc.before = get_pre_cached();
    result.RENAME3res_u.resok.todir_wcc.after = get_post_stat(to, rqstp);

    return &result;
}

LINK3res *nfsproc3_link_3_svc(LINK3args * argp, struct svc_req * rqstp)
{
    static LINK3res result;
    char *path, *old;
    pre_op_attr pre;
    post_op_attr post;
    char obj[NFS_MAXPATHLEN];
    int res;

    PREP(path, argp->link.dir);
    pre = get_pre_cached();
    result.status = join(cat_name(path, argp->link.name, obj), exports_rw());

    cluster_create(obj, rqstp, &result.status);

    old = fh_decomp(argp->file);

    if (old && result.status == NFS3_OK) {
	result.status = exports_compat(old, rqstp);

	if (result.status == NFS3_OK) {
	    res = backend_link(old, obj);
	    if (res == -1)
		result.status = link_err();
	}
    } else if (!old)
	result.status = NFS3ERR_STALE;

    post = get_post_attr(path, argp->link.dir, rqstp);

    /* overlaps with resfail */
    result.LINK3res_u.resok.file_attributes = get_post_stat(old, rqstp);
    result.LINK3res_u.resok.linkdir_wcc.before = pre;
    result.LINK3res_u.resok.linkdir_wcc.after = post;

    return &result;
}

READDIR3res *nfsproc3_readdir_3_svc(READDIR3args * argp,
				    struct svc_req * rqstp)
{
    static READDIR3res result;
    char *path;

    PREP(path, argp->dir);

    result = read_dir(path, argp->cookie, argp->cookieverf, argp->count);
    result.READDIR3res_u.resok.dir_attributes = get_post_stat(path, rqstp);

    return &result;
}

READDIRPLUS3res *nfsproc3_readdirplus_3_svc(U(READDIRPLUS3args * argp),
					    U(struct svc_req * rqstp))
{
    static READDIRPLUS3res result;

    /* 
     * we don't do READDIRPLUS since it involves filehandle and
     * attribute getting which is impossible to do atomically
     * from user-space
     */
    result.status = NFS3ERR_NOTSUPP;
    result.READDIRPLUS3res_u.resfail.dir_attributes.attributes_follow = FALSE;

    return &result;
}

FSSTAT3res *nfsproc3_fsstat_3_svc(FSSTAT3args * argp, struct svc_req * rqstp)
{
    static FSSTAT3res result;
    char *path;
    backend_statvfsstruct buf;
    int res;

    PREP(path, argp->fsroot);

    /* overlaps with resfail */
    result.FSSTAT3res_u.resok.obj_attributes = get_post_cached(rqstp);

    res = backend_statvfs(path, &buf);
    if (res == -1) {
	/* statvfs fell on its nose */
	if ((exports_opts & OPT_REMOVABLE) && export_point(path)) {
	    /* Removable media export point; probably no media inserted.
	       Return dummy values. */
	    result.status = NFS3_OK;
	    result.FSSTAT3res_u.resok.tbytes = 0;
	    result.FSSTAT3res_u.resok.fbytes = 0;
	    result.FSSTAT3res_u.resok.abytes = 0;
	    result.FSSTAT3res_u.resok.tfiles = 0;
	    result.FSSTAT3res_u.resok.ffiles = 0;
	    result.FSSTAT3res_u.resok.afiles = 0;
	    result.FSSTAT3res_u.resok.invarsec = 0;
	} else {
	    result.status = NFS3ERR_IO;
	}
    } else {
	result.status = NFS3_OK;
	result.FSSTAT3res_u.resok.tbytes =
	    (uint64) buf.f_blocks * buf.f_frsize;
	result.FSSTAT3res_u.resok.fbytes = 
	    (uint64) buf.f_bfree * buf.f_frsize;
	result.FSSTAT3res_u.resok.abytes =
	    (uint64) buf.f_bavail * buf.f_frsize;
	result.FSSTAT3res_u.resok.tfiles = buf.f_files;
	result.FSSTAT3res_u.resok.ffiles = buf.f_ffree;
	result.FSSTAT3res_u.resok.afiles = buf.f_ffree;
	result.FSSTAT3res_u.resok.invarsec = 0;
    }

    return &result;
}

FSINFO3res *nfsproc3_fsinfo_3_svc(FSINFO3args * argp, struct svc_req * rqstp)
{
    static FSINFO3res result;
    char *path;
    unsigned int maxdata;

    if (get_socket_type(rqstp) == SOCK_STREAM)
	maxdata = NFS_MAXDATA_TCP;
    else
	maxdata = NFS_MAXDATA_UDP;

    PREP(path, argp->fsroot);

    result.FSINFO3res_u.resok.obj_attributes = get_post_cached(rqstp);

    result.status = NFS3_OK;
    result.FSINFO3res_u.resok.rtmax = maxdata;
    result.FSINFO3res_u.resok.rtpref = maxdata;
    result.FSINFO3res_u.resok.rtmult = 4096;
    result.FSINFO3res_u.resok.wtmax = maxdata;
    result.FSINFO3res_u.resok.wtpref = maxdata;
    result.FSINFO3res_u.resok.wtmult = 4096;
    result.FSINFO3res_u.resok.dtpref = 4096;
    result.FSINFO3res_u.resok.maxfilesize = ~0ULL;
    result.FSINFO3res_u.resok.time_delta.seconds = backend_time_delta_seconds;
    result.FSINFO3res_u.resok.time_delta.nseconds = 0;
    result.FSINFO3res_u.resok.properties = backend_fsinfo_properties;

    return &result;
}

PATHCONF3res *nfsproc3_pathconf_3_svc(PATHCONF3args * argp,
				      struct svc_req * rqstp)
{
    static PATHCONF3res result;
    char *path;

    PREP(path, argp->object);

    result.PATHCONF3res_u.resok.obj_attributes = get_post_cached(rqstp);

    result.status = NFS3_OK;
    result.PATHCONF3res_u.resok.linkmax = 0xFFFFFFFF;
    result.PATHCONF3res_u.resok.name_max = NFS_MAXPATHLEN;
    result.PATHCONF3res_u.resok.no_trunc = TRUE;
    result.PATHCONF3res_u.resok.chown_restricted = FALSE;
    result.PATHCONF3res_u.resok.case_insensitive =
	backend_pathconf_case_insensitive;
    result.PATHCONF3res_u.resok.case_preserving = TRUE;

    return &result;
}

COMMIT3res *nfsproc3_commit_3_svc(COMMIT3args * argp, struct svc_req * rqstp)
{
    static COMMIT3res result;
    char *path;
    int res;

    PREP(path, argp->file);
    result.status = join(is_reg(), exports_rw());

    if (result.status == NFS3_OK) {
	res = fd_sync(argp->file);
	if (res != -1)
	    memcpy(result.COMMIT3res_u.resok.verf, wverf, NFS3_WRITEVERFSIZE);
	else
	    /* error during fsync() or close() */
	    result.status = NFS3ERR_IO;
    }

    /* overlaps with resfail */
    result.COMMIT3res_u.resfail.file_wcc.before = get_pre_cached();
    result.COMMIT3res_u.resfail.file_wcc.after = get_post_stat(path, rqstp);

    return &result;
}
