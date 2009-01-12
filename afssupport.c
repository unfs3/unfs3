
/*
 * unfs3 AFS FID support layer
 * Copyright (c) 2008 Daniel Richard G. <skunk@iSKUNK.ORG>
 * see file LICENSE for license details
 */

/*
 * These routines allow UNFS3 to better support exporting files from an
 * AFS network filesystem.
 *
 * THE PROBLEM: The inode numbers presented by AFS to stat() et al. are
 * not unique, and AFS does not implement the notion of inode generation
 * numbers. This messes with UNFS3's filehandle cache, and leads to the
 * occasional bizarre result where reading file X yields the content of
 * file Y (where X and Y are usually in different AFS volumes).
 *
 * THE SOLUTION: We make direct[*] use of AFS file IDs (FIDs), which are
 * AFS's moral equivalent of the Unix device number + inode number pair
 * (inasmuch as they are meant to uniquely identify a file). The FID is
 * obtained via a special pioctl() call, and consists of four unsigned
 * 32-bit integers: a cell number, a volume number, a vnode number, and
 * a uniquifier. We wrap the three stat() functions, and have them
 * return a 64-bit inode number that is basically the concatenation of
 * the volume and vnode numbers, and provide a backend_get_gen()
 * implementation that returns the uniquifier as the inode generation
 * number.
 *
 * [*]: The inode numbers visible to stat() and friends are actually
 * composed using a portion of the volume and vnode numbers. So there,
 * we are indirectly using the AFS FIDs, but of course in a way that
 * doesn't work terribly well for UNFS3.
 *
 * CAVEAT: Currently, we don't (can't?) make use of a file's associated
 * AFS cell number, because there's basically no good place to put it.
 * So if UNFS3 is exporting files from more than one cell, there is a
 * small chance of the aforementioned file X vs. file Y problem cropping
 * up. In practice, a cell is usually quite big (even the largest AFS
 * installations have only a handful), and having UNFS3 export large
 * tracts of AFS-space is a rather nutty idea anyway!
 */

#include "config.h"

#ifdef AFS_SUPPORT

#include <stdio.h>
#include <errno.h>

#include <netinet/in.h>
#include <afs/venus.h>

#include "fh.h"
#include "afssupport.h"

/* This isn't declared in any AFS public header, so we declare it ourselves
 */
int pioctl(const char *path, int32 cmd, struct ViceIoctl *data, int32 follow);

/* These two structs are in the public headers, but good luck trying to
 * pull them in correctly */

struct AFSFid {
    afs_uint32 Volume;
    afs_uint32 Vnode;
    afs_uint32 Unique;
};

struct VenusFid {
    afs_int32 Cell;
    struct AFSFid Fid;
};

/* Get an AFS file ID for a specified file path or file descriptor. If
 * <path> is non-NULL and refers to a symlink, then the second argument
 * indicates whether it should be followed or not (0 = obtain FID for
 * symlink; 1 = obtain FID for symlink target). When specifying a file
 * descriptor, <path> must be NULL, and the descriptor is passed in as
 * the second argument.
 *
 * Returns zero on success, non-zero + errno otherwise.
 */
static int get_afs_fid(const char *path, int follow_or_fd, int32 *cell, uint32 *volume, uint32 *vnode, uint32 *unique)
{
    char fdname[32];
    int follow;
    struct ViceIoctl vioc;
    struct VenusFid vfid;
    int ret;

    if (path == NULL)
    {
#ifdef __linux__
	/*
	 * "Note that while there is no interface to obtain the FID of an
	 * open file descriptor, in Linux you can cheat by calling the
	 * pioctl on /proc/self/fd/N"  --Jeffrey Hutzelman
	 *
	 * http://www.openafs.org/pipermail/openafs-info/2005-December/020498.html
	 */
	sprintf(fdname, "/proc/self/fd/%d", follow_or_fd);
	path = fdname;
	follow = 1;	/* Necessary, or else the pioctl() returns EINVAL */
#else
	errno = ENOSYS	/* Function not implemented */
	return 1;
#endif
    }
    else
	follow = follow_or_fd;

    vioc.in_size = 0;
    vioc.out_size = sizeof(struct VenusFid);
    vioc.out = (char *) &vfid;

    ret = pioctl(path, VIOCGETFID, &vioc, follow);

    if (ret == 0)
    {
	if (cell)   *cell   = vfid.Cell;
	if (volume) *volume = vfid.Fid.Volume;
	if (vnode)  *vnode  = vfid.Fid.Vnode;
	if (unique) *unique = vfid.Fid.Unique;
    }

    return ret;
}

uint32 afs_get_gen(struct stat_plus_afs obuf, int fd, const char *path)
{
    if (obuf.afs_valid)
	return obuf.afs_unique;

    return get_gen(obuf, fd, path);
}

/* These are defined in afsgettimes.c
 */
time_t afs_get_system_st_atime(struct stat *buf);
time_t afs_get_system_st_mtime(struct stat *buf);
time_t afs_get_system_st_ctime(struct stat *buf);

/* "struct stat_plus_afs" may not have the same layout as "struct stat",
 * so we assign the fields individually instead of all at once
 */
#define ASSIGN_STAT_FIELDS(to_ptr, from_struct) \
    to_ptr->st_dev	= from_struct.st_dev; \
    to_ptr->st_ino	= from_struct.st_ino; \
    to_ptr->st_mode	= from_struct.st_mode; \
    to_ptr->st_nlink	= from_struct.st_nlink; \
    to_ptr->st_uid	= from_struct.st_uid; \
    to_ptr->st_gid	= from_struct.st_gid; \
    to_ptr->st_rdev	= from_struct.st_rdev; \
    to_ptr->st_size	= from_struct.st_size; \
    to_ptr->st_blksize	= from_struct.st_blksize; \
    to_ptr->st_blocks	= from_struct.st_blocks; \
    to_ptr->st_atime	= afs_get_system_st_atime(&from_struct); \
    to_ptr->st_mtime	= afs_get_system_st_mtime(&from_struct); \
    to_ptr->st_ctime	= afs_get_system_st_ctime(&from_struct)

#define MAKE_INODE_NUMBER(x,y)	( ((uint64) (x) << 32) | (uint64) (y) )

int afs_stat(const char *path, struct stat_plus_afs *buf)
{
    struct stat sys_buf;
    int ret;

    ret = stat(path, &sys_buf);

    if (ret != 0)
	return ret;

    ASSIGN_STAT_FIELDS(buf, sys_buf);

    buf->afs_valid = 0 == get_afs_fid(path, 1, &buf->afs_cell, &buf->afs_volume, &buf->afs_vnode, &buf->afs_unique);

    if (buf->afs_valid)
	buf->st_ino = MAKE_INODE_NUMBER(buf->afs_volume, buf->afs_vnode);

    return 0;
}

int afs_fstat(int fd, struct stat_plus_afs *buf)
{
    struct stat sys_buf;
    int ret;

    ret = fstat(fd, &sys_buf);

    if (ret != 0)
	return ret;

    ASSIGN_STAT_FIELDS(buf, sys_buf);

    buf->afs_valid = 0 == get_afs_fid(NULL, fd, &buf->afs_cell, &buf->afs_volume, &buf->afs_vnode, &buf->afs_unique);

    if (buf->afs_valid)
	buf->st_ino = MAKE_INODE_NUMBER(buf->afs_volume, buf->afs_vnode);

    return 0;
}

int afs_lstat(const char *path, struct stat_plus_afs *buf)
{
    struct stat sys_buf;
    int ret;

    ret = lstat(path, &sys_buf);

    if (ret != 0)
	return ret;

    ASSIGN_STAT_FIELDS(buf, sys_buf);

    buf->afs_valid = 0 == get_afs_fid(path, 0, &buf->afs_cell, &buf->afs_volume, &buf->afs_vnode, &buf->afs_unique);

    if (buf->afs_valid)
	buf->st_ino = MAKE_INODE_NUMBER(buf->afs_volume, buf->afs_vnode);

    return 0;
}

#endif /* AFS_SUPPORT */

/* ISO C forbids an empty source file */
typedef long walk;
