/*
 * UNFS3 low-level filesystem calls for Unix
 * (C) 2004, Pascal Schmidt <der.eremit@email.de>
 * see file LICENSE for license details
 */

#ifndef UNFS3_BACKEND_UNIX_H
#define UNFS3_BACKEND_UNIX_H

/*
 * backend init and shutdown
 */
#define backend_init() 1
#define backend_shutdown() do { } while (0)

/*
 * unfs3 functions
 */
#define backend_get_gen get_gen
#define backend_mksocket mksocket
#define backend_locate_file locate_file

/*
 * system calls
 */
#define backend_chmod chmod
#define backend_chown chown
#define backend_close close
#define backend_closedir closedir
#define backend_fchmod fchmod
#define backend_fchown fchown
#define backend_fstat fstat
#define backend_fsync fsync
#define backend_ftruncate ftruncate
#define backend_link link
#define backend_lseek lseek
#define backend_lstat lstat
#define backend_mkdir mkdir
#define backend_mkfifo mkfifo
#define backend_mknod mknod
#define backend_open open
#define backend_opendir opendir
#define backend_read read
#define backend_readdir readdir
#define backend_readlink readlink
#define backend_realpath realpath
#define backend_remove remove
#define backend_rename rename
#define backend_rmdir rmdir
#define backend_stat stat
#define backend_statvfs statvfs
#define backend_symlink symlink
#define backend_truncate truncate
#define backend_utime utime
#define backend_write write

#endif
