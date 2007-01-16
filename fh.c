
/*
 * UNFS3 low-level filehandle routines
 * (C) 2004, Pascal Schmidt
 * see file LICENSE for license details
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#ifndef WIN32
#include <sys/ioctl.h>
#include <syslog.h>
#endif				       /* WIN32 */
#include <rpc/rpc.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if HAVE_LINUX_EXT2_FS_H == 1

/*
 * presence of linux/ext2_fs.h is a hint that we are on Linux, really
 * including that file doesn't work on Debian, so define the ioctl
 * number here
 */
#define EXT2_IOC_GETVERSION	0x80047601
#endif

#include "nfs.h"
#include "mount.h"
#include "daemon.h"
#include "fh.h"
#include "backend.h"
#include "Config/exports.h"

/*
 * hash function for inode numbers
 */
#define FH_HASH(n) ((n ^ (n >> 8) ^ (n >> 16) ^ (n >> 24) ^ (n >> 32) ^ (n >> 40) ^ (n >> 48) ^ (n >> 56)) & 0xFF)

/*
 * stat cache
 */
int st_cache_valid = FALSE;
backend_statstruct st_cache;

/*
 * --------------------------------
 * INODE GENERATION NUMBER HANDLING
 * --------------------------------
 */

/*
 * obtain inode generation number if possible
 *
 * obuf: filled out stat buffer (must be given!)
 * fd:   open fd to file or FD_NONE (-1) if no fd open
 * path: path to object in case we need to open it here
 *
 * returns 0 on failure
 */
uint32 get_gen(backend_statstruct obuf, U(int fd), U(const char *path))
{
#if HAVE_STRUCT_STAT_ST_GEN == 1
    return obuf.st_gen;
#endif

#if HAVE_STRUCT_STAT_ST_GEN == 0 && HAVE_LINUX_EXT2_FS_H == 1
    int newfd, res;
    uint32 gen;
    uid_t euid;
    gid_t egid;

    if (!S_ISREG(obuf.st_mode) && !S_ISDIR(obuf.st_mode))
	return 0;

    euid = backend_geteuid();
    egid = backend_getegid();
    backend_setegid(0);
    backend_seteuid(0);

    if (fd != FD_NONE) {
	res = ioctl(fd, EXT2_IOC_GETVERSION, &gen);
	if (res == -1)
	    gen = 0;
    } else {
	newfd = backend_open(path, O_RDONLY);
	if (newfd == -1)
	    gen = 0;
	else {
	    res = ioctl(newfd, EXT2_IOC_GETVERSION, &gen);
	    close(newfd);

	    if (res == -1)
		gen = 0;
	}
    }

    backend_setegid(egid);
    backend_seteuid(euid);

    if (backend_geteuid() != euid || backend_getegid() != egid) {
	logmsg(LOG_EMERG, "euid/egid switching failed, aborting");
	daemon_exit(CRISIS);
    }

    return gen;
#endif

#if HAVE_STRUCT_STAT_ST_GEN == 0 && HAVE_LINUX_EXT2_FS_H == 0
    return obuf.st_ino;
#endif
}

/*
 * --------------------------------
 * FILEHANDLE COMPOSITION FUNCTIONS
 * --------------------------------
 */

/*
 * check whether an NFS filehandle is valid
 */
int nfh_valid(nfs_fh3 fh)
{
    unfs3_fh_t *obj = (void *) fh.data.data_val;

    /* too small? */
    if (fh.data.data_len < FH_MINLEN)
	return FALSE;

    /* encoded length different from real length? */
    if (fh.data.data_len != fh_length(obj))
	return FALSE;

    return TRUE;
}

/*
 * check whether a filehandle is valid
 */
int fh_valid(unfs3_fh_t fh)
{
    /* invalid filehandles have zero device and inode */
    return (int) (fh.dev != 0 || fh.ino != 0);
}

/*
 * invalid fh for error returns
 */
#ifdef __GNUC__
static const unfs3_fh_t invalid_fh = {.dev = 0,.ino = 0,.gen = 0,.len =
	0,.inos = {0}
};
#else
static const unfs3_fh_t invalid_fh = { 0, 0, 0, 0, {0} };
#endif

/*
 * compose a filehandle for a given path
 * path:     path to compose fh for
 * rqstp:    If not NULL, generate special FHs for removables
 * need_dir: if not 0, path must point to a directory
 */
unfs3_fh_t fh_comp_raw(const char *path, struct svc_req *rqstp, int need_dir)
{
    char work[NFS_MAXPATHLEN];
    unfs3_fh_t fh;
    backend_statstruct buf;
    int res;
    char *last;
    int pos = 0;

    fh.len = 0;

    /* special case for removable device export point: return preset fsid and 
       inod 1. */
    if (rqstp && export_point(path)) {
	uint32 fsid;

	if (exports_options(path, rqstp, NULL, &fsid) == -1) {
	    /* Shouldn't happen, unless the exports file changed after the
	       call to export_point() */
	    return invalid_fh;
	}
	if (exports_opts & OPT_REMOVABLE) {
	    fh.dev = fsid;
	    /* There's a small risk that the file system contains other file
	       objects with st_ino = 1. This should be fairly uncommon,
	       though. The FreeBSD fs(5) man page says:

	       "The root inode is the root of the file system.  Inode 0
	       cannot be used for normal purposes and historically bad blocks 
	       were linked to inode 1, thus the root inode is 2 (inode 1 is
	       no longer used for this purpose, however numerous dump tapes
	       make this assumption, so we are stuck with it)."

	       In Windows, there's also a small risk that the hash ends up
	       being exactly 1. */
	    fh.ino = 0x1;
	    fh.gen = 0;
	    return fh;
	}
    }

    res = backend_lstat(path, &buf);
    if (res == -1)
	return invalid_fh;

    /* check for dir if need_dir is set */
    if (need_dir != 0 && !S_ISDIR(buf.st_mode))
	return invalid_fh;

    fh.dev = buf.st_dev;
    fh.ino = buf.st_ino;
    fh.gen = backend_get_gen(buf, FD_NONE, path);

    /* special case for root directory */
    if (strcmp(path, "/") == 0)
	return fh;

    strcpy(work, path);
    last = work;

    do {
	*last = '/';
	last = strchr(last + 1, '/');
	if (last != NULL)
	    *last = 0;

	res = backend_lstat(work, &buf);
	if (res == -1) {
	    return invalid_fh;
	}

	/* store 8 bit hash of the component's inode */
	fh.inos[pos] = FH_HASH(buf.st_ino);
	pos++;

    } while (last && pos < FH_MAXLEN);

    if (last)			       /* path too deep for filehandle */
	return invalid_fh;

    fh.len = pos;

    return fh;
}

/*
 * get real length of a filehandle
 */
u_int fh_length(const unfs3_fh_t * fh)
{
    return fh->len + sizeof(fh->len) + sizeof(fh->dev) + sizeof(fh->ino) +
	sizeof(fh->gen) + sizeof(fh->pwhash);
}

/*
 * extend a filehandle with a given device, inode, and generation number
 */
unfs3_fh_t *fh_extend(nfs_fh3 nfh, uint32 dev, uint64 ino, uint32 gen)
{
    static unfs3_fh_t new;
    unfs3_fh_t *fh = (void *) nfh.data.data_val;

    memcpy(&new, fh, fh_length(fh));

    if (new.len == 0) {
	char *path;

	path = export_point_from_fsid(new.dev, NULL, NULL);
	if (path != NULL) {
	    /* Our FH to extend refers to a removable device export point,
	       which lacks .inos. We need to construct a real FH to extend,
	       which can be done by passing rqstp=NULL to fh_comp_raw. */
	    new = fh_comp_raw(path, NULL, FH_ANY);
	    if (!fh_valid(new))
		return NULL;
	}
    }

    if (new.len == FH_MAXLEN)
	return NULL;

    new.dev = dev;
    new.ino = ino;
    new.gen = gen;
    new.pwhash = export_password_hash;
    new.inos[new.len] = FH_HASH(ino);
    new.len++;

    return &new;
}

/*
 * get post_op_fh3 extended by device, inode, and generation number
 */
post_op_fh3 fh_extend_post(nfs_fh3 fh, uint32 dev, uint64 ino, uint32 gen)
{
    post_op_fh3 post;
    unfs3_fh_t *new;

    new = fh_extend(fh, dev, ino, gen);

    if (new) {
	post.handle_follows = TRUE;
	post.post_op_fh3_u.handle.data.data_len = fh_length(new);
	post.post_op_fh3_u.handle.data.data_val = (char *) new;
    } else
	post.handle_follows = FALSE;

    return post;
}

/*
 * extend a filehandle given a path and needed type
 */
post_op_fh3 fh_extend_type(nfs_fh3 fh, const char *path, unsigned int type)
{
    post_op_fh3 result;
    backend_statstruct buf;
    int res;

    res = backend_lstat(path, &buf);
    if (res == -1 || (buf.st_mode & type) != type) {
	st_cache_valid = FALSE;
	result.handle_follows = FALSE;
	return result;
    }

    st_cache_valid = TRUE;
    st_cache = buf;

    return fh_extend_post(fh, buf.st_dev, buf.st_ino,
			  backend_get_gen(buf, FD_NONE, path));
}

/*
 * -------------------------------
 * FILEHANDLE RESOLUTION FUNCTIONS
 * -------------------------------
 */

/*
 * filehandles have the following fields:
 * dev:  device of the file system object fh points to
 * ino:  inode of the file system object fh points to
 * gen:  inode generation number, if available
 * len:  number of entries in following inos array
 * inos: array of max FH_MAXLEN directories needed to traverse to reach
 *       object, for each name, an 8 bit hash of the inode number is stored
 *
 * - search functions traverse directory structure from the root looking
 *   for directories matching the inode information stored
 * - if such a directory is found, we descend into it trying to locate the
 *   object
 */

/*
 * recursive directory search
 * fh:     filehandle being resolved
 * pos:    position in filehandles path inode array
 * lead:   current directory for search
 * result: where to store path if seach is complete
 */
static int fh_rec(const unfs3_fh_t * fh, int pos, const char *lead,
		  char *result)
{
    backend_dirstream *search;
    struct dirent *entry;
    backend_statstruct buf;
    int res, rec;
    char obj[NFS_MAXPATHLEN];

    /* There's a slight risk of multiple files with the same st_ino on
       Windows. Take extra care and make sure that there are no collisions */
    unsigned short matches = 0;

    /* went in too deep? */
    if (pos == fh->len)
	return FALSE;

    search = backend_opendir(lead);
    if (!search)
	return FALSE;

    entry = backend_readdir(search);

    while (entry) {
	if (strlen(lead) + strlen(entry->d_name) + 1 < NFS_MAXPATHLEN) {

	    sprintf(obj, "%s/%s", lead, entry->d_name);

	    res = backend_lstat(obj, &buf);
	    if (res == -1) {
		buf.st_dev = 0;
		buf.st_ino = 0;
	    }

	    if (buf.st_dev == fh->dev && buf.st_ino == fh->ino) {
		/* found the object */
		sprintf(result, "%s/%s", lead + 1, entry->d_name);
		/* update stat cache */
		st_cache_valid = TRUE;
		st_cache = buf;
		matches++;
#ifndef WIN32
		break;
#endif
	    }

	    if (strcmp(entry->d_name, "..") != 0 &&
		strcmp(entry->d_name, ".") != 0 &&
		FH_HASH(buf.st_ino) == fh->inos[pos]) {
		/* 
		 * might be directory we're looking for,
		 * try descending into it
		 */
		rec = fh_rec(fh, pos + 1, obj, result);
		if (rec) {
		    /* object was found in dir */
		    backend_closedir(search);
		    return TRUE;
		}
	    }
	}
	entry = backend_readdir(search);
    }

    backend_closedir(search);
    switch (matches) {
	case 0:
	    return FALSE;
	case 1:
	    return TRUE;
	default:
#ifdef WIN32
	    logmsg(LOG_CRIT, "Hash collision detected for file %s!", result);
#endif
	    return FALSE;
    }
}

/*
 * resolve a filehandle into a path
 */
char *fh_decomp_raw(const unfs3_fh_t * fh)
{
    int rec = 0;
    static char result[NFS_MAXPATHLEN];

    /* valid fh? */
    if (!fh)
	return NULL;

    /* special case for root directory */
    if (fh->len == 0)
	return "/";

    rec = fh_rec(fh, 0, "/", result);

    if (rec)
	return result;

    /* could not find object */
    return NULL;
}
