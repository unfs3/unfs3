
/*
 * UNFS3 readdir routine
 * (C) 2004, Pascal Schmidt <der.eremit@email.de>
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
#include <time.h>
#include <unistd.h>

#include "nfs.h"
#include "mount.h"
#include "fh.h"
#include "readdir.h"
#include "Config/exports.h"

/*
 * maximum number of entries in readdir results
 *
 * this is 4096 / 28 (the minimum size of an entry3)
 */
#define MAX_ENTRIES 143

/*
 * static READDIR3resok size with XDR overhead
 *
 * 88 bytes attributes, 8 bytes verifier, 4 bytes value_follows for
 * first entry, 4 bytes eof flag
 */
#define RESOK_SIZE 104

/*
 * static entry3 size with XDR overhead
 *
 * 8 bytes fileid, 4 bytes name length, 8 bytes cookie, 4 byte value_follows
 */
#define ENTRY_SIZE 24

/*
 * size of a name with XDR overhead
 *
 * XDR pads to multiple of 4 bytes
 */
#define NAME_SIZE(x) (((strlen((x))+3)/4)*4)

/*
 * check if directory cookie is still valid
 */
static int cookie_check(time_t time, cookieverf3 verf)
{
    return (int) (time == *(time_t *) verf);
}

uint32 directory_hash(const char *path)
{
    DIR *search;
    struct dirent *this;
    uint32 hval = 0;

    search = opendir(path);
    if (!search) {
	return 0;
    }

    while ((this = readdir(search)) != NULL) {
	hval = fnv1a_32(this->d_name, hval);
    }

    closedir(search);
    return hval;
}

/*
 * perform a READDIR operation
 *
 * fh_decomp must be called directly before to fill the stat cache
 */
READDIR3res read_dir(const char *path, cookie3 cookie, cookieverf3 verf,
		     count3 count)
{
    READDIR3res result;
    READDIR3resok resok;
    static entry3 entry[MAX_ENTRIES];
    struct stat buf;
    int res;
    DIR *search;
    struct dirent *this;
    count3 i, real_count;
    static char obj[NFS_MAXPATHLEN * MAX_ENTRIES];
    char scratch[NFS_MAXPATHLEN];

    /* we refuse to return more than 4k from READDIR */
    if (count > 4096)
	count = 4096;

    /* account for size of information heading resok structure */
    real_count = RESOK_SIZE;

    /* check verifier against directory's modification time */
    if (cookie != 0 && !cookie_check(st_cache.st_mtime, verf)) {
	result.status = NFS3ERR_BAD_COOKIE;
	return result;
    }

    /* compute new cookie verifier */
    memset(verf, 0, NFS3_COOKIEVERFSIZE);
    *(time_t *) verf = st_cache.st_mtime;

    search = opendir(path);
    if (!search) {
	if ((exports_opts & OPT_REMOVABLE) && (export_point(path))) {
	    /* Removable media export point; probably no media inserted.
	       Return empty directory. */
	    memset(resok.cookieverf, 0, NFS3_COOKIEVERFSIZE);
	    resok.reply.entries = NULL;
	    resok.reply.eof = TRUE;
	    result.status = NFS3_OK;
	    result.READDIR3res_u.resok = resok;
	    return result;
	} else {
	    result.status = NFS3ERR_STALE;
	    return result;
	}
    }

    this = readdir(search);
    for (i = 0; i < cookie; i++)
	if (this)
	    this = readdir(search);

    i = 0;
    while (this && real_count < count && i < MAX_ENTRIES) {
	if (i > 0)
	    entry[i - 1].nextentry = &entry[i];

	if (strlen(path) + strlen(this->d_name) + 1 < NFS_MAXPATHLEN) {

	    sprintf(scratch, "%s/%s", path, this->d_name);

	    res = lstat(scratch, &buf);
	    if (res == -1) {
		result.status = NFS3ERR_IO;
		closedir(search);
		return result;
	    }

	    strcpy(&obj[i * NFS_MAXPATHLEN], this->d_name);

	    entry[i].fileid = ((uint64) buf.st_dev << 32)
		+ buf.st_ino;
	    entry[i].name = &obj[i * NFS_MAXPATHLEN];
	    entry[i].cookie = cookie + 1 + i;
	    entry[i].nextentry = NULL;

	    /* account for entry size */
	    real_count += ENTRY_SIZE + NAME_SIZE(this->d_name);

	    /* whoops, overflowed the maximum size */
	    if (real_count > count && i > 0)
		entry[i - 1].nextentry = NULL;
	    else {
		/* advance to next entry */
		this = readdir(search);
	    }

	    i++;
	} else {
	    result.status = NFS3ERR_IO;
	    closedir(search);
	    return result;
	}
    }
    closedir(search);

    resok.reply.entries = &entry[0];
    if (this)
	resok.reply.eof = FALSE;
    else
	resok.reply.eof = TRUE;

    memcpy(resok.cookieverf, verf, NFS3_COOKIEVERFSIZE);

    result.status = NFS3_OK;
    result.READDIR3res_u.resok = resok;

    return result;
}
