
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
#include <time.h>
#ifndef WIN32
#include <syslog.h>
#include <unistd.h>
#endif				       /* WIN32 */

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
 * access and to close() it when we hit EOF or after two seconds of
 * inactivity.
 *
 * for WRITE operations, the intent is to open() the file on the first
 * UNSTABLE access and to close() it when COMMIT is called or after
 * two seconds of inactivity. 
 * 
 * There are three states of an entry:
 * 1) Unused. use == 0. 
 * 2) Open fd. use != 0, fd != -1. 
 * 3) Pending fsync/close error, to be reported in next COMMIT or WRITE. use != 0, fd == -1. 
 *
 * Handling fsync/close errors 100% correctly is very difficult for a
 * user space server. Although rare, fsync/close might fail, for
 * example when out of quota or closing a file on a NFS file
 * system. The most correct way of handling these errors would be to
 * keep track of "dirty" and failed ranges. However, this would
 * require runtime memory allocation, with no known upper bound, which
 * in turn can lead to DOS attacks etc. Our solution returns a
 * fsync/close error in the first WRITE or COMMIT
 * response. Additionally, the write verifier is changed. Subsequent
 * COMMITs may succeed even though data has been lost, but since the
 * verifier is changed, clients will notice this and re-send their
 * data. Eventually, with some luck, all clients will get an IO error.
 */

/* number of entries in fd cache */
#define FD_ENTRIES	256

/* The number of seconds to wait before closing inactive fd */
#define INACTIVE_TIMEOUT 2

/* The number of seconds to keep pending errors */
#define PENDING_ERROR_TIMEOUT 7200     /* 2 hours */

typedef struct {
    int fd;			/* open file descriptor */
    int kind;			/* read or write */
    time_t use;			/* last use */
    uint32 dev;			/* device */
    uint64 ino;			/* inode */
    uint32 gen;			/* inode generation */
} fd_cache_t;

static fd_cache_t fd_cache[FD_ENTRIES];

/* statistics */
int fd_cache_readers = 0;
int fd_cache_writers = 0;

/*
 * initialize the fd cache
 */
void fd_cache_init(void)
{
    int i;

    for (i = 0; i < FD_ENTRIES; i++) {
	fd_cache[i].fd = -1;
	fd_cache[i].kind = UNFS3_FD_READ;
	fd_cache[i].use = 0;
	fd_cache[i].dev = 0;
	fd_cache[i].ino = 0;
	fd_cache[i].gen = 0;
    }
}

/*
 * find cache index to use for new entry
 * returns an empty slot if found, else return error
 */
static int fd_cache_unused(void)
{
    int i;
    static time_t last_warning = 0;

    for (i = 0; i < FD_ENTRIES; i++) {
	if (fd_cache[i].use == 0)
	    return i;
    }

    /* Do not print warning more than once per 10 second */
    if (time(NULL) > last_warning + 10) {
	last_warning = time(NULL);
	logmsg(LOG_INFO,
	       "fd cache full due to more than %d active files or pending IO errors",
	       FD_ENTRIES);
    }

    return -1;
}

/*

 * remove an entry from the cache. The keep_on_error variable
 * indicates if the entry should be kept in the cache upon
 * fsync/close failures. It should be set to TRUE when fd_cache_del is
 * called from a code path which cannot report an IO error back to the
 * client through WRITE or COMMIT. 
 */
static int fd_cache_del(int idx, int keep_on_error)
{
    int res1, res2;

    res1 = -1;

    if (fd_cache[idx].fd != -1) {
	if (fd_cache[idx].kind == UNFS3_FD_WRITE) {
	    /* sync file data if writing descriptor */
	    fd_cache_writers--;
	    res1 = backend_fsync(fd_cache[idx].fd);
	} else {
	    fd_cache_readers--;
	    res1 = 0;
	}
	res2 = backend_close(fd_cache[idx].fd);
	fd_cache[idx].fd = -1;

	/* return -1 if something went wrong during sync or close */
	if (res1 == -1 || res2 == -1) {
	    res1 = -1;
	}
    } else
	/* pending error */
	errno = EIO;

    if (res1 == -1 && !keep_on_error) {
	/* The verifier should not be changed until we actually report &
	   remove the error */
	regenerate_write_verifier();
    }

    if (res1 != -1 || !keep_on_error) {
	fd_cache[idx].fd = -1;
	fd_cache[idx].use = 0;
	fd_cache[idx].dev = 0;
	fd_cache[idx].ino = 0;
	fd_cache[idx].gen = 0;
    }

    return res1;
}

/*
 * add an entry to the cache
 */
static void fd_cache_add(int fd, unfs3_fh_t * ufh, int kind)
{
    int idx;

    idx = fd_cache_unused();
    if (idx != -1) {
	/* update statistics */
	if (kind == UNFS3_FD_READ)
	    fd_cache_readers++;
	else
	    fd_cache_writers++;

	fd_cache[idx].fd = fd;
	fd_cache[idx].kind = kind;
	fd_cache[idx].use = time(NULL);
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
int fd_open(const char *path, nfs_fh3 nfh, int kind, int allow_caching)
{
    int idx, res, fd;
    backend_statstruct buf;
    unfs3_fh_t *fh = (void *) nfh.data.data_val;

    idx = idx_by_fh(fh, kind);

    if (idx != -1) {
	if (fd_cache[idx].fd == -1) {
	    /* pending error, report to client and remove from cache */
	    fd_cache_del(idx, FALSE);
	    return -1;
	}
	return fd_cache[idx].fd;
    } else {
	/* call open to obtain new fd */
	if (kind == UNFS3_FD_READ)
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
	 * success, add to cache for later use
	 */
	if (allow_caching)
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
	fd_cache[idx].use = time(NULL);

	if (really_close == FD_CLOSE_REAL)
	    /* delete entry on real close, will close() fd */
	    return fd_cache_del(idx, FALSE);
	else
	    return 0;
    } else {
	/* not in cache, sync and close directly */
	if (kind == UNFS3_FD_WRITE)
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

    idx = idx_by_fh(fh, UNFS3_FD_WRITE);
    if (idx != -1)
	/* delete entry, will fsync() and close() the fd */
	return fd_cache_del(idx, FALSE);
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
	if (fd_cache[i].use != 0) {
	    if (fd_cache_del(i, TRUE) == -1)
		logmsg(LOG_CRIT,
		       "Error during shutdown fsync/close for dev %lu, inode %lu",
		       fd_cache[i].dev, fd_cache[i].ino);

	}
    }
}

/*
 * close inactive fds
 */
void fd_cache_close_inactive(void)
{
    time_t now;
    int i;
    int found_error = 0;
    int active_error = 0;

    now = time(NULL);
    for (i = 0; i < FD_ENTRIES; i++) {
	/* Check for inactive open fds */
	if (fd_cache[i].use && fd_cache[i].fd != -1 &&
	    fd_cache[i].use + INACTIVE_TIMEOUT < now) {
	    fd_cache_del(i, TRUE);
	}

	/* Check for inactive pending errors */
	if (fd_cache[i].use && fd_cache[i].fd == -1) {
	    found_error = 1;
	    if (fd_cache[i].use + PENDING_ERROR_TIMEOUT > now)
		active_error = 1;
	}
    }

    if (found_error && !active_error) {
	/* All pending errors are old. Delete them all from the table and
	   generate new verifier. This is done to prevent the table from
	   filling up with old pending errors, perhaps for files that never
	   will be written again. In this case, we throw away the errors, and 
	   change the server verifier. If clients has pending COMMITs, they
	   will notify the changed verifier and re-send. */
	for (i = 0; i < FD_ENTRIES; i++) {
	    if (fd_cache[i].use && fd_cache[i].fd == -1) {
		fd_cache_del(i, FALSE);
	    }
	}
	regenerate_write_verifier();
    }
}
