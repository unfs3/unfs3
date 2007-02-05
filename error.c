
/*
 * UNFS3 error translation
 * (C) 2004, Pascal Schmidt
 * see file LICENSE for license details
 */

/*
 * translations from Unix errno to NFS error numbers
 */

#include "config.h"

#include <rpc/rpc.h>
#include <errno.h>

#include "nfs.h"
#include "error.h"
#include "backend.h"

static int is_stale(void)
{
    if (errno == ENOTDIR || errno == ELOOP || errno == ENOENT ||
	errno == ENAMETOOLONG)
	return -1;
    else
	return 0;
}

nfsstat3 symlink_err(void)
{
    if (errno == EACCES || errno == EPERM)
	return NFS3ERR_ACCES;
    else if (is_stale())
	return NFS3ERR_STALE;
    else if (errno == EROFS)
	return NFS3ERR_ROFS;
    else if (errno == EEXIST)
	return NFS3ERR_EXIST;
    else if (errno == ENOSPC)
	return NFS3ERR_NOSPC;
#ifdef EDQUOT
    else if (errno == EDQUOT)
	return NFS3ERR_DQUOT;
#endif
    else if (errno == ENOSYS)
	return NFS3ERR_NOTSUPP;
    else if (errno == EINVAL)
	return NFS3ERR_INVAL;
    else
	return NFS3ERR_IO;
}

nfsstat3 mkdir_err(void)
{
    return symlink_err();
}

nfsstat3 mknod_err(void)
{
    return symlink_err();
}

nfsstat3 link_err(void)
{
    if (errno == EXDEV)
	return NFS3ERR_XDEV;
    else if (errno == EMLINK)
	return NFS3ERR_MLINK;
#ifdef EDQUOT
    else if (errno == EDQUOT)
	return NFS3ERR_DQUOT;
#endif
    else
	return symlink_err();
}

nfsstat3 lookup_err(void)
{
    if (errno == ENOENT)
	return NFS3ERR_NOENT;
#ifdef ENOMEDIUM
    else if (errno == ENOMEDIUM)
	return NFS3ERR_NOENT;
#endif
    else if (errno == EACCES)
	return NFS3ERR_ACCES;
    else if (errno == ENOTDIR || errno == ELOOP || errno == ENAMETOOLONG)
	return NFS3ERR_STALE;
    else if (errno == EINVAL)
	return NFS3ERR_INVAL;
    else
	return NFS3ERR_IO;
}

nfsstat3 readlink_err(void)
{
    if (errno == EINVAL)
	return NFS3ERR_INVAL;
    else if (errno == EACCES)
	return NFS3ERR_ACCES;
    else if (errno == ENOSYS)
	return NFS3ERR_NOTSUPP;
    else if (is_stale())
	return NFS3ERR_STALE;
    else
	return NFS3ERR_IO;
}

nfsstat3 read_err(void)
{
    if (errno == EINVAL)
	return NFS3ERR_INVAL;
    else if (is_stale())
	return NFS3ERR_STALE;
    else if (errno == EACCES)
	return NFS3ERR_ACCES;
    else if (errno == ENXIO || errno == ENODEV)
	return NFS3ERR_NXIO;
    else
	return NFS3ERR_IO;
}

nfsstat3 write_open_err(void)
{
    if (errno == EACCES)
	return NFS3ERR_ACCES;
    else if (is_stale())
	return NFS3ERR_STALE;
    else if (errno == EINVAL)
	return NFS3ERR_INVAL;
    else if (errno == EROFS)
	return NFS3ERR_ROFS;
    else
	return NFS3ERR_IO;
}

nfsstat3 write_write_err(void)
{
    if (errno == EINVAL)
	return NFS3ERR_INVAL;
    else if (errno == EFBIG)
	return NFS3ERR_FBIG;
    else if (errno == ENOSPC)
	return NFS3ERR_NOSPC;
#ifdef EDQUOT
    else if (errno == EDQUOT)
	return NFS3ERR_DQUOT;
#endif
    else
	return NFS3ERR_IO;
}

nfsstat3 create_err(void)
{
    if (errno == EACCES)
	return NFS3ERR_ACCES;
    else if (is_stale())
	return NFS3ERR_STALE;
    else if (errno == EROFS)
	return NFS3ERR_ROFS;
    else if (errno == ENOSPC)
	return NFS3ERR_NOSPC;
    else if (errno == EEXIST)
	return NFS3ERR_EXIST;
#ifdef EDQUOT
    else if (errno == EDQUOT)
	return NFS3ERR_DQUOT;
#endif
    else
	return NFS3ERR_IO;
}

nfsstat3 rename_err(void)
{
    if (errno == EISDIR)
	return NFS3ERR_ISDIR;
    else if (errno == EXDEV)
	return NFS3ERR_XDEV;
    else if (errno == EEXIST)
	return NFS3ERR_EXIST;
    else if (errno == ENOTEMPTY)
	return NFS3ERR_NOTEMPTY;
    else if (errno == EINVAL)
	return NFS3ERR_INVAL;
    else if (errno == ENOTDIR)
	return NFS3ERR_NOTDIR;
    else if (errno == EACCES || errno == EPERM)
	return NFS3ERR_ACCES;
    else if (errno == ENOENT)
	return NFS3ERR_NOENT;
    else if (errno == ELOOP || errno == ENAMETOOLONG)
	return NFS3ERR_STALE;
    else if (errno == EROFS)
	return NFS3ERR_ROFS;
    else if (errno == ENOSPC)
	return NFS3ERR_NOSPC;
#ifdef EDQUOT
    else if (errno == EDQUOT)
	return NFS3ERR_DQUOT;
#endif
    else
	return NFS3ERR_IO;
}

nfsstat3 remove_err(void)
{
    if (errno == EACCES || errno == EPERM)
	return NFS3ERR_ACCES;
    else if (errno == ENOENT)
	return ENOENT;
    else if (errno == ENOTDIR || errno == ELOOP || errno == ENAMETOOLONG)
	return NFS3ERR_STALE;
    else if (errno == EINVAL)
	return NFS3ERR_INVAL;
    else if (errno == EROFS)
	return NFS3ERR_ROFS;
    else
	return NFS3ERR_IO;
}

nfsstat3 rmdir_err(void)
{
    if (errno == ENOTEMPTY)
	return NFS3ERR_NOTEMPTY;
    else
	return remove_err();
}

nfsstat3 setattr_err(void)
{
    if (errno == EPERM)
	return NFS3ERR_PERM;
    else if (errno == EROFS)
	return NFS3ERR_ROFS;
    else if (is_stale())
	return NFS3ERR_STALE;
    else if (errno == EACCES)
	return NFS3ERR_ACCES;
#ifdef EDQUOT
    else if (errno == EDQUOT)
	return NFS3ERR_DQUOT;
#endif
    else if (errno == EINVAL)
	return NFS3ERR_INVAL;
    else
	return NFS3ERR_IO;
}

nfsstat3 readdir_err(void)
{
    if (errno == EPERM)
	return NFS3ERR_PERM;
    else if (errno == EACCES)
	return NFS3ERR_ACCES;
    else if (errno == ENOTDIR)
	return NFS3ERR_NOTDIR;
    else if (is_stale())
	return NFS3ERR_STALE;
    else if (errno == EINVAL)
	return NFS3ERR_INVAL;
    else
	return NFS3ERR_IO;
}

/*
 * combine two error values
 */
nfsstat3 join(nfsstat3 x, nfsstat3 y)
{
    return (x != NFS3_OK) ? x : y;
}

/*
 * combine three error values
 */
nfsstat3 join3(nfsstat3 x, nfsstat3 y, nfsstat3 z)
{
    return (x != NFS3_OK) ? x : join(y, z);
}
