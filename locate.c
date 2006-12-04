
/*
 * UNFS3 brute force file search
 * (C) 2004, Pascal Schmidt
 * see file LICENSE for license details
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <rpc/rpc.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if HAVE_MNTENT_H == 1
#include <mntent.h>
#endif

#if HAVE_SYS_MNTTAB_H == 1
#include <sys/mnttab.h>
#endif

#include "nfs.h"
#include "fh.h"
#include "daemon.h"

/*
 * these are the brute-force file searching routines that are used
 * when both the filehandle cache and the hashed path inside the
 * filehandle are unable to locate the file
 *
 * this can only happen if a file was rename(3)'d across directories
 *
 * these routines are slow, but better than returning ESTALE to
 * clients
 */

#if HAVE_MNTENT_H == 1 || HAVE_SYS_MNTTAB_H == 1

/*
 * locate file given prefix, device, and inode number
 */
static int locate_pfx(const char *pfx, uint32 dev, uint64 ino, char *result)
{
    char path[NFS_MAXPATHLEN];
    backend_dirstream *search;
    struct dirent *ent;
    struct stat buf;
    int res;

    search = opendir(pfx);
    if (!search)
	return FALSE;

    while ((ent = readdir(search))) {
	if (strlen(pfx) + strlen(ent->d_name) + 2 >= NFS_MAXPATHLEN)
	    continue;

	sprintf(path, "%s/%s", pfx, ent->d_name);

	res = lstat(path, &buf);
	if (res != 0)
	    continue;

	/* check for matching object */
	if (buf.st_dev == dev && buf.st_ino == ino) {
	    strcpy(result, path);
	    st_cache = buf;
	    st_cache_valid = TRUE;
	    closedir(search);
	    return TRUE;
	}

	/* descend into directories with same dev */
	if (buf.st_dev == dev && S_ISDIR(buf.st_mode) &&
	    strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0) {
	    res = locate_pfx(path, dev, ino, result);
	    if (res == TRUE) {
		closedir(search);
		return TRUE;
	    }
	}
    }

    closedir(search);
    return FALSE;
}
#endif

/*
 * locate file given device and inode number
 *
 * slow fallback in case other filehandle resolution functions fail
 */
char *locate_file(U(uint32 dev), U(uint64 ino))
{
#if HAVE_MNTENT_H == 1 || HAVE_SYS_MNTTAB_H == 1
    static char path[NFS_MAXPATHLEN];
    FILE *mtab;
    struct stat buf;
    int res;
#endif

#if HAVE_MNTENT_H == 1
    struct mntent *ent;
#endif

#if HAVE_SYS_MNTTAB_H == 1
    struct mnttab ent;
    int found = FALSE;
#endif

    if (!opt_brute_force)
	return NULL;

#if HAVE_MNTENT_H == 1
    mtab = setmntent("/etc/mtab", "r");
    if (!mtab)
	return NULL;

    /* 
     * look for mtab entry with matching device
     */
    while ((ent = getmntent(mtab))) {
	res = lstat(ent->mnt_dir, &buf);

	if (res == 0 && buf.st_dev == dev)
	    break;
    }
    endmntent(mtab);

    /* found matching entry? */
    if (ent) {
	res = locate_pfx(ent->mnt_dir, dev, ino, path);
	if (res == TRUE)
	    return path;
    }
#endif

#if HAVE_SYS_MNTTAB_H == 1
    mtab = fopen("/etc/mnttab", "r");
    if (!mtab)
	return NULL;

    /* 
     * look for mnttab entry with matching device
     */
    while (getmntent(mtab, &ent) == 0) {
	res = lstat(ent.mnt_mountp, &buf);

	if (res == 0 && buf.st_dev == dev) {
	    found = TRUE;
	    break;
	}
    }
    fclose(mtab);

    /* found matching entry? */
    if (found) {
	res = locate_pfx(ent.mnt_mountp, dev, ino, path);
	if (res == TRUE)
	    return path;
    }
#endif

    return NULL;
}
