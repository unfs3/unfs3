
/*
 * UNFS3 readdir routine
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
#include <time.h>
#include <unistd.h>

#include "nfs.h"
#include "mount.h"
#include "fh.h"
#include "readdir.h"
#include "backend.h"
#include "Config/exports.h"
#include "daemon.h"
#include "error.h"

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

uint32 directory_hash(const char *path)
{
    backend_dirstream *search;
    struct dirent *this;
    uint32 hval = 0;

    search = backend_opendir(path);
    if (!search) {
	return 0;
    }

    while ((this = backend_readdir(search)) != NULL) {
	hval = fnv1a_32(this->d_name, hval);
    }

    backend_closedir(search);
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
    cookie3 upper;
    static entry3 entry[MAX_ENTRIES];
    backend_statstruct buf;
    int res;
    backend_dirstream *search;
    struct dirent *this;
    count3 i, real_count;
    static char obj[NFS_MAXPATHLEN * MAX_ENTRIES];
    char scratch[NFS_MAXPATHLEN];

    /* check upper part of cookie */
    upper = cookie & 0xFFFFFFFF00000000ULL;
    if (cookie != 0 && upper != rcookie) {
      /* ignore cookie if unexpected so we restart from the beginning */
      cookie = 0;
    }
    cookie &= 0xFFFFFFFFULL;

    /* we refuse to return more than 4k from READDIR */
    if (count > 4096)
	count = 4096;

    /* account for size of information heading resok structure */
    real_count = RESOK_SIZE;

    /* We are always returning zero as a cookie verifier. One reason for this 
       is that stat() on Windows seems to return cached st_mtime values,
       which gives spurious NFS3ERR_BAD_COOKIEs. Btw, here's what Peter
       Staubach has to say about cookie verifiers:

       "From my viewpoint, the cookieverifier was a failed experiment in NFS
       Version 3.  The semantics were never well understood nor supported by
       many local file systems.  The Solaris NFS server always returns zeros
       in the cookieverifier field." */
    memset(verf, 0, NFS3_COOKIEVERFSIZE);

    search = backend_opendir(path);
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
	    result.status = readdir_err();
	    return result;
	}
    }

    this = backend_readdir(search);
    /* We cannot use telldir()/seekdir(), since the value from telldir() is
       not valid after closedir(). */
    for (i = 0; i < cookie; i++)
	if (this)
	    this = backend_readdir(search);

    i = 0;
    entry[0].name = NULL;
    while (this && real_count < count && i < MAX_ENTRIES) {
	if (i > 0)
	    entry[i - 1].nextentry = &entry[i];

	if (strlen(path) + strlen(this->d_name) + 1 < NFS_MAXPATHLEN) {

	    if (strcmp(path, "/") == 0)
		sprintf(scratch, "/%s", this->d_name);
	    else
		sprintf(scratch, "%s/%s", path, this->d_name);

	    res = backend_lstat(scratch, &buf);
	    if (res == -1) {
		result.status = readdir_err();
		backend_closedir(search);
		return result;
	    }

	    strcpy(&obj[i * NFS_MAXPATHLEN], this->d_name);

#ifdef WIN32
	    /* See comment in attr.c:get_post_buf */
	    entry[i].fileid = (buf.st_ino >> 32) ^ (buf.st_ino & 0xffffffff);
#else
	    entry[i].fileid = buf.st_ino;
#endif
	    entry[i].name = &obj[i * NFS_MAXPATHLEN];
	    entry[i].cookie = (cookie + 1 + i) | rcookie;
	    entry[i].nextentry = NULL;

	    /* account for entry size */
	    real_count += ENTRY_SIZE + NAME_SIZE(this->d_name);

	    /* whoops, overflowed the maximum size */
	    if (real_count > count && i > 0)
		entry[i - 1].nextentry = NULL;
	    else {
		/* advance to next entry */
		this = backend_readdir(search);
	    }

	    i++;
	} else {
	    result.status = NFS3ERR_IO;
	    backend_closedir(search);
	    return result;
	}
    }
    backend_closedir(search);

    if (entry[0].name)
	resok.reply.entries = &entry[0];
    else
	resok.reply.entries = NULL;

    if (this)
	resok.reply.eof = FALSE;
    else
	resok.reply.eof = TRUE;

    memcpy(resok.cookieverf, verf, NFS3_COOKIEVERFSIZE);

    result.status = NFS3_OK;
    result.READDIR3res_u.resok = resok;

    return result;
}
