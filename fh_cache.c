
/*
 * UNFS3 filehandle cache
 * (C) 2004
 * see file LICENSE for license details
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <rpc/rpc.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "nfs.h"
#include "fh.h"
#include "locate.h"
#include "fh_cache.h"
#include "mount.h"
#include "daemon.h"
#include "Config/exports.h"
#include "readdir.h"
#include "backend.h"

/* number of entries in fh cache */
#define CACHE_ENTRIES	4096

typedef struct {
    uint32 dev;			/* device */
    uint64 ino;			/* inode */
    char path[NFS_MAXPATHLEN];	/* pathname */
    unsigned int use;		/* last use */
} unfs3_cache_t;

static unfs3_cache_t fh_cache[CACHE_ENTRIES];

/* statistics */
int fh_cache_max = 0;
int fh_cache_use = 0;
int fh_cache_hit = 0;

/* counter for LRU */
static unsigned int fh_cache_time = 0;

/*
 * last returned entry
 *
 * this entry must not be overwritten before the next lookup, because
 * operations such as CREATE may still be needing the path inside the
 * entry for getting directory attributes
 *
 * this is needed since fh_cache_time can roll around to 0, thus
 * making the entry evictable
 */
static int fh_last_entry = -1;

/*
 * return next pseudo-time value for LRU counter
 */
static unsigned int fh_cache_next(void)
{
    return ++fh_cache_time;
}

/*
 * initialize cache
 */
void fh_cache_init(void)
{
    memset(fh_cache, 0, sizeof(unfs3_cache_t) * CACHE_ENTRIES);
}

/*
 * find cache index to use for new entry
 * returns either an empty slot or the least recently used slot if no
 * empty slot is present
 */
static int fh_cache_lru(void)
{
    unsigned int best = UINT_MAX;
    int best_idx = 0;
    int i;

    /* if cache is not full, we simply hand out the next slot */
    if (fh_cache_max < CACHE_ENTRIES - 1)
	return fh_cache_max++;

    for (i = 0; i < CACHE_ENTRIES; i++) {
	if (i == fh_last_entry)
	    continue;
	if (fh_cache[i].use == 0)
	    return i;
	if (fh_cache[i].use < best) {
	    best = fh_cache[i].use;
	    best_idx = i;
	}
    }

    /* avoid stomping over last returned entry */
    if (best_idx == 0 && fh_last_entry == 0)
	best_idx = 1;

    return best_idx;
}

/*
 * invalidate (clear) a cache entry
 */
static void fh_cache_inval(int idx)
{
    fh_cache[idx].dev = 0;
    fh_cache[idx].ino = 0;
    fh_cache[idx].use = 0;
    fh_cache[idx].path[0] = 0;
}

/*
 * find index given device and inode number
 */
static int fh_cache_index(uint32 dev, uint64 ino)
{
    int i, res = -1;

    for (i = 0; i < fh_cache_max + 1; i++)
	if (fh_cache[i].dev == dev && fh_cache[i].ino == ino) {
	    res = i;
	    break;
	}

    return res;
}

/*
 * add an entry to the filehandle cache
 */
char *fh_cache_add(uint32 dev, uint64 ino, const char *path)
{
    int idx;

    /* if we already have a matching entry, overwrite that */
    idx = fh_cache_index(dev, ino);

    /* otherwise overwrite least recently used entry */
    if (idx == -1)
	idx = fh_cache_lru();

    fh_cache[idx].dev = dev;
    fh_cache[idx].ino = ino;
    fh_cache[idx].use = fh_cache_next();

    strcpy(fh_cache[idx].path, path);

    return fh_cache[idx].path;
}

/*
 * lookup an entry in the cache given a device, inode, and generation number
 */
static char *fh_cache_lookup(uint32 dev, uint64 ino)
{
    int i, res;
    backend_statstruct buf;

    i = fh_cache_index(dev, ino);

    if (i != -1) {
	/* check whether path to <dev,ino> relation still holds */
	res = backend_lstat(fh_cache[i].path, &buf);
	if (res == -1) {
	    /* object does not exist any more */
	    fh_cache_inval(i);
	    return NULL;
	}
	if (buf.st_dev == dev && buf.st_ino == ino) {
	    /* cache hit, update time on cache entry */
	    fh_cache[i].use = fh_cache_next();

	    /* update stat cache */
	    st_cache_valid = TRUE;
	    st_cache = buf;

	    /* prevent next fh_cache_add from overwriting entry */
	    fh_last_entry = i;

	    return fh_cache[i].path;
	} else {
	    /* path to <dev,ino> relation has changed */
	    fh_cache_inval(i);
	    return NULL;
	}
    }

    return NULL;
}

/*
 * resolve a filename into a path
 * cache-using wrapper for fh_decomp_raw
 */
char *fh_decomp(nfs_fh3 fh)
{
    char *result;
    unfs3_fh_t *obj = (void *) fh.data.data_val;
    time_t *last_mtime;
    uint32 *dir_hash, new_dir_hash;

    if (!nfh_valid(fh)) {
	st_cache_valid = FALSE;
	return NULL;
    }

    /* Does the fsid match some static fsid? */
    if ((result =
	 export_point_from_fsid(obj->dev, &last_mtime, &dir_hash)) != NULL) {
	if (obj->ino == 0x1) {
	    /* This FH refers to the export point itself */
	    /* Need to fill stat cache */
	    st_cache_valid = TRUE;

	    if (backend_lstat(result, &st_cache) == -1) {
		/* export point does not exist. This probably means that we
		   are using autofs and no media is inserted. Fill stat cache 
		   with dummy information */
		st_cache.st_mode = S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO;
		st_cache.st_nlink = 2;
		st_cache.st_uid = 0;
		st_cache.st_gid = 0;
		st_cache.st_rdev = 0;
		st_cache.st_size = 4096;
		st_cache.st_blksize = 512;
		st_cache.st_blocks = 8;
	    } else {
		/* Stat was OK, but make sure the values are sane. Supermount 
		   returns insane values when no media is inserted, for
		   example. */
		if (st_cache.st_nlink == 0)
		    st_cache.st_nlink = 1;
		if (st_cache.st_size == 0)
		    st_cache.st_size = 4096;
		if (st_cache.st_blksize == 0)
		    st_cache.st_blksize = 512;
		if (st_cache.st_blocks == 0)
		    st_cache.st_blocks = 8;
	    }

	    st_cache.st_dev = obj->dev;
	    st_cache.st_ino = 0x1;

	    /* It's very important that we get mtime correct, since it's used 
	       as verifier in READDIR. The generation of mtime is tricky,
	       because with some filesystems, such as the Linux 2.4 FAT fs,
	       the mtime value for the mount point is set to *zero* on each
	       mount. I consider this a bug, but we need to work around it
	       anyway.

	       We store the last mtime returned. When stat returns a smaller
	       value than this, we double-check by doing a hash of the names
	       in the directory. If this hash is different from what we had
	       earlier, return current time.

	       Note: Since dir_hash is stored in memory, we have introduced a 
	       little statefulness here. This means that if unfsd is
	       restarted during two READDIR calls, NFS3ERR_BAD_COOKIE will be 
	       returned, and the client has to retry the READDIR operation
	       with a zero cookie */

	    if (st_cache.st_mtime > *last_mtime) {
		/* stat says our directory has changed */
		*last_mtime = st_cache.st_mtime;
	    } else if (*dir_hash != (new_dir_hash = directory_hash(result))) {
		/* The names in the directory has changed. Return current
		   time. */
		st_cache.st_mtime = time(NULL);
		*last_mtime = st_cache.st_mtime;
		*dir_hash = new_dir_hash;
	    } else {
		/* Hash unchanged. Returned stored mtime. */
		st_cache.st_mtime = *last_mtime;
	    }

	    return result;
	}
    }

    /* try lookup in cache, increase cache usage counter */
    result = fh_cache_lookup(obj->dev, obj->ino);
    fh_cache_use++;

    if (!result) {
	/* not found, resolve the hard way */
	result = fh_decomp_raw(obj);

	/* if still not found, do full recursive search) */
	if (!result)
	    result = backend_locate_file(obj->dev, obj->ino);

	if (result)
	    /* add to cache for later use if resolution ok */
	    result = fh_cache_add(obj->dev, obj->ino, result);
	else
	    /* could not resolve in any way */
	    st_cache_valid = FALSE;
    } else
	/* found, update cache hit statistic */
	fh_cache_hit++;

    return result;
}

/*
 * compose a filehandle for a path
 * cache-using wrapper for fh_comp_raw
 * exports_options must be called before
 */
unfs3_fh_t fh_comp(const char *path, struct svc_req * rqstp, int need_dir)
{
    unfs3_fh_t res;

    res = fh_comp_raw(path, rqstp, need_dir);
    if (fh_valid(res))
	/* add to cache for later use */
	fh_cache_add(res.dev, res.ino, path);

    res.pwhash = export_password_hash;
    return res;
}

/*
 * return pointer to composed filehandle
 * wrapper for fh_comp
 */
unfs3_fh_t *fh_comp_ptr(const char *path, struct svc_req * rqstp,
			int need_dir)
{
    static unfs3_fh_t res;

    res = fh_comp(path, rqstp, need_dir);
    if (fh_valid(res))
	return &res;
    else
	return NULL;
}
