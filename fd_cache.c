
/*
 * UNFS3 file descriptor cache
 * (C) 2004, Pascal Schmidt
 * see file LICENSE for license details
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <rpc/rpc.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <syslog.h>
#include <unistd.h>

#include "nfs.h"
#include "mount.h"
#include "fh.h"
#include "daemon.h"
#include "Config/exports.h"
#include "fd_cache.h"
#include "backend.h"

/*
 * intention of the file descriptor cache
 *
 * for READ operations, the intent is to open() the file on the first
 * access and to close() it when we hit EOF
 *
 * for WRITE operations, the intent is to open() the file on the first
 * UNSTABLE access and to close() it when COMMIT is called
 */

/* number of entries in fd cache */
#define FD_ENTRIES	256

typedef struct {
    int fd;			/* open file descriptor */
    int kind;			/* read or write */
    time_t use;			/* last use */
    uint32 dev;			/* device */
    uint32 ino;			/* inode */
    uint32 gen;			/* inode generation */
} fd_cache_t;

static fd_cache_t fd_cache[FD_ENTRIES];

/* statistics */
int fd_cache_readers = 0;
int fd_cache_writers = 0;

/* counter for LRU */
static int fd_cache_time = 0;

/*
 * return next pseudo-time value for LRU counter
 */
static int fd_cache_next(void)
{
    return ++fd_cache_time;
}

/*
 * initialize the fd cache
 */
void fd_cache_init(void)
{
    int i;

    for (i = 0; i < FD_ENTRIES; i++) {
	fd_cache[i].fd = -1;
	fd_cache[i].kind = FD_READ;
	fd_cache[i].use = 0;
	fd_cache[i].dev = 0;
	fd_cache[i].ino = 0;
	fd_cache[i].gen = 0;
    }
}

/*
 * find cache index to use for new entry
 * returns an empty slot if found, else return the least recently used slot
 *
 * only returns a used WRITE slot if opt_expire_writers is set
 */
static int fd_cache_lru(void)
{
    int best = INT_MAX;
    int i;
    int idx = -1;

    for (i = 0; i < FD_ENTRIES; i++) {
	if (fd_cache[i].use == 0)
	    return i;
	if (fd_cache[i].use < best) {
	    if (opt_expire_writers) {
		best = fd_cache[i].use;
		idx = i;
	    } else if (fd_cache[i].kind == FD_READ) {
		best = fd_cache[i].use;
		idx = i;
	    }
	}
    }

    if (idx == -1)
	logmsg(LOG_WARNING, "fd cache full due to UNSTABLE writers");

    return idx;
}

/*
 * remove an entry from the cache
 */
static int fd_cache_del(int idx)
{
    int res1, res2;

    fd_cache[idx].use = 0;

    if (fd_cache[idx].fd != -1) {
	if (fd_cache[idx].kind == FD_WRITE) {
	    /* sync file data if writing descriptor */
	    fd_cache_writers--;
	    res1 = backend_fsync(fd_cache[idx].fd);
	} else {
	    fd_cache_readers--;
	    res1 = 0;
	}
	res2 = backend_close(fd_cache[idx].fd);

	/* return -1 if something went wrong during sync or close */
	if (res1 == -1 || res2 == -1)
	    res1 = -1;
	else
	    res1 = 0;
    } else
	res1 = 0;

    fd_cache[idx].fd = -1;
    fd_cache[idx].dev = 0;
    fd_cache[idx].ino = 0;
    fd_cache[idx].gen = 0;
    return res1;
}

/*
 * add an entry to the cache
 */
static void fd_cache_add(int fd, unfs3_fh_t * ufh, int kind)
{
    int idx, res;

    idx = fd_cache_lru();
    if (idx != -1) {
	if (fd_cache[idx].kind == FD_READ)
	    fd_cache_del(idx);
	else {
	    /* if expiring a WRITE fd, report errors to log */
	    res = fd_cache_del(idx);
	    if (res != 0)
		logmsg(LOG_CRIT,
		       "silent write failure for dev %li, inode %li",
		       fd_cache[idx].dev, fd_cache[idx].ino);
	}

	/* update statistics */
	if (kind == FD_READ)
	    fd_cache_readers++;
	else
	    fd_cache_writers++;

	fd_cache[idx].fd = fd;
	fd_cache[idx].kind = kind;
	fd_cache[idx].use = fd_cache_next();
	fd_cache[idx].dev = ufh->dev;
	fd_cache[idx].ino = ufh->ino;
	fd_cache[idx].gen = ufh->gen;
    }
}

/*
 * find entry by operating system fd number
 */
static int idx_by_fd(int fd, int kind)
{
    int i;
    int idx = -1;

    for (i = 0; i < FD_ENTRIES; i++)
	if (fd_cache[i].fd == fd && fd_cache[i].kind == kind) {
	    idx = i;
	    break;
	}
    return idx;
}

/*
 * find entry by fh (device, inode, and generation number)
 */
static int idx_by_fh(unfs3_fh_t * ufh, int kind)
{
    int i;
    int idx = -1;

    for (i = 0; i < FD_ENTRIES; i++)
	if (fd_cache[i].kind == kind) {
	    if (fd_cache[i].dev == ufh->dev && fd_cache[i].ino == ufh->ino &&
		fd_cache[i].gen == ufh->gen) {
		idx = i;
		break;
	    }
	}
    return idx;
}

/*
 * open a file descriptor
 * uses fd from cache if possible
 */
int fd_open(const char *path, nfs_fh3 nfh, int kind)
{
    int idx, res, fd;
    struct stat buf;
    unfs3_fh_t *fh = (void *) nfh.data.data_val;

    idx = idx_by_fh(fh, kind);

    if (idx != -1)
	return fd_cache[idx].fd;
    else {
	/* call open to obtain new fd */
	if (kind == FD_READ)
	    fd = backend_open(path, O_RDONLY);
	else
	    fd = backend_open(path, O_WRONLY);
	if (fd == -1)
	    return -1;

	/* check for local fs race */
	res = backend_fstat(fd, &buf);
	if ((res == -1) ||
	    (fh->dev != buf.st_dev || fh->ino != buf.st_ino ||
	     fh->gen != backend_get_gen(buf, fd, path))) {
	    /* 
	     * local fs changed meaning of path between
	     * calling NFS operation doing fh_decomp and
	     * arriving here
	     *
	     * set errno to ELOOP to make calling NFS
	     * operation return NFS3ERR_STALE
	     */
	    backend_close(fd);
	    errno = ELOOP;
	    return -1;
	}

	/* 
	 * success, add to cache for later use if not marked
	 * as removable medium
	 */
	if (!(exports_opts & OPT_REMOVABLE))
	    fd_cache_add(fd, fh, kind);
	return fd;
    }
}

/*
 * close a file descriptor
 * returns error number from real close() if applicable
 */
int fd_close(int fd, int kind, int really_close)
{
    int idx, res1 = 0, res2 = 0;

    idx = idx_by_fd(fd, kind);
    if (idx != -1) {
	/* update usage time of cache entry */
	fd_cache[idx].use = fd_cache_next();

	if (really_close == FD_CLOSE_REAL)
	    /* delete entry on real close, will close() fd */
	    return fd_cache_del(idx);
	else
	    return 0;
    } else {
	/* not in cache, sync and close directly */
	if (kind == FD_WRITE)
	    res1 = backend_fsync(fd);

	res2 = backend_close(fd);

	if (res1 != 0)
	    return res1;
	else
	    return res2;
    }
}

/*
 * sync file descriptor data to disk
 */
int fd_sync(nfs_fh3 nfh)
{
    int idx;
    unfs3_fh_t *fh = (void *) nfh.data.data_val;

    idx = idx_by_fh(fh, FD_WRITE);
    if (idx != -1)
	/* delete entry, will fsync() and close() the fd */
	return fd_cache_del(idx);
    else
	return 0;
}

/*
 * purge/shutdown the cache
 */
void fd_cache_purge(void)
{
    int i;

    /* close any open file descriptors we still have */
    for (i = 0; i < FD_ENTRIES; i++) {
	if (fd_cache[i].fd != -1)
	    fd_cache_del(i);
    }
}
