/*
 * UNFS3 file descriptor cache
 * (C) 2004, Pascal Schmidt <der.eremit@email.de>
 * see file LICENSE for license details
 */

#ifndef UNFS3_FD_CACHE_H
#define UNFS3_FD_CACHE_H

#define FD_READ  0			/* fd for READ */
#define FD_WRITE 1			/* fd for WRITE */

#define FD_CLOSE_VIRT 0		/* virtually close the fd */
#define FD_CLOSE_REAL 1		/* really close the fd */

/* statistics */
extern int fd_cache_readers;
extern int fd_cache_writers;

void fd_cache_init(void);

int fd_open(const char *path, nfs_fh3 fh, int kind);
int fd_close(int fd, int kind, int really_close);
int fd_sync(nfs_fh3 fh);
void fd_cache_purge(void);

#endif
