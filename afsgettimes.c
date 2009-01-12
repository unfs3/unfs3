
/*
 * unfs3 AFS FID support layer
 * Copyright (c) 2008 Daniel Richard G. <skunk@iSKUNK.ORG>
 * see file LICENSE for license details
 */

#include "config.h"

#ifdef AFS_SUPPORT

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

time_t afs_get_system_st_atime(struct stat *buf) { return buf->st_atime; }
time_t afs_get_system_st_mtime(struct stat *buf) { return buf->st_mtime; }
time_t afs_get_system_st_ctime(struct stat *buf) { return buf->st_ctime; }

#endif /* AFS_SUPPORT */

/* ISO C forbids an empty source file */
typedef long walk;
