
/*
 * unfs3 AFS FID support layer
 * Copyright (c) 2008 Daniel Richard G. <skunk@iSKUNK.ORG>
 * see file LICENSE for license details
 */

#ifdef AFS_SUPPORT
#ifndef UNFS3_AFSSUPPORT_H
#define UNFS3_AFSSUPPORT_H

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "nfs.h"

/* Linux's /usr/include/bits/stat.h has this nonsense:
 *
 *	# define st_atime st_atim.tv_sec        /+ Backward compatibility.  +/
 *	# define st_mtime st_mtim.tv_sec
 *	# define st_ctime st_ctim.tv_sec
 */
#undef st_atime
#undef st_mtime
#undef st_ctime

struct stat_plus_afs {
    dev_t     st_dev;
    uint64    st_ino;	/* Must be unconditionally 64-bit */
    mode_t    st_mode;
    nlink_t   st_nlink;
    uid_t     st_uid;
    gid_t     st_gid;
    dev_t     st_rdev;
    off_t     st_size;
    size_t    st_blksize;
    blkcnt_t  st_blocks;
    time_t    st_atime;
    time_t    st_mtime;
    time_t    st_ctime;

    /* Following fields are valid only if this is non-zero
     */
    int       afs_valid;

    int32     afs_cell;
    uint32    afs_volume;
    uint32    afs_vnode;
    uint32    afs_unique;
};

uint32 afs_get_gen(struct stat_plus_afs obuf, int fd, const char *path);

int afs_stat(const char *file_name, struct stat_plus_afs *buf);

int afs_fstat(int fd, struct stat_plus_afs *buf);

int afs_lstat(const char *path, struct stat_plus_afs *buf);

#endif /* UNFS3_AFSSUPPORT_H */
#endif /* AFS_SUPPORT */
