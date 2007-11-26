/*
 * UNFS3 low-level filesystem calls for Win32
 * (C) 2006, Peter Åstrand
 * see file LICENSE for license details
 */

#ifndef UNFS3_BACKEND_WIN32_H
#define UNFS3_BACKEND_WIN32_H

#include "winsupport.h"

/*
 * backend init and shutdown
 */
#define backend_shutdown() do { } while (0)

/*
 * unfs3 functions
 */
#define backend_get_gen get_gen
#define backend_mksocket win_mkfifo
#define backend_locate_file locate_file

/*
 * system calls
 */
#define backend_chmod win_chmod
#define backend_chown win_chown
#define backend_close win_close
#define backend_closedir win_closedir
#define backend_fchmod win_fchmod
#define backend_fchown win_fchown
#define backend_fstat win_fstat
#define backend_fsync _commit
#define backend_ftruncate chsize
#define backend_getegid() 0
#define backend_geteuid() 0
#define backend_getgid() 0
#define backend_getuid() 0
#define backend_lchown win_chown
#define backend_link win_link
#define backend_lseek lseek
#define backend_lstat win_stat
#define backend_mkdir win_mkdir
#define backend_mkfifo win_mkfifo
#define backend_mknod win_mknod
#define backend_open win_open
#define backend_open_create win_open
#define backend_opendir win_opendir
#define backend_pread pread
#define backend_pwrite pwrite
#define backend_readdir win_readdir
#define backend_readlink win_readlink
#define backend_realpath win_realpath
#define backend_remove win_remove
#define backend_rename win_rename 
#define backend_rmdir win_rmdir
#define backend_setegid win_setegid
#define backend_seteuid win_seteuid
#define backend_setgroups(size, groups) 0
#define backend_stat win_stat
#define backend_statvfs win_statvfs
#define backend_symlink win_symlink
#define backend_truncate win_truncate
#define backend_utime win_utime
#define backend_init win_init
#define backend_dirstream UNFS3_WIN_DIR
#define backend_fsinfo_properties FSF3_HOMOGENEOUS | FSF3_CANSETTIME;
/*
  Note: FAT has different granularities for different times: 1 day for
  atime, 2 seconds for mtime and 10ms för CreationTime. time_delta
  only applies to atime/mtime. We are choosing 2 seconds.
*/
#define backend_time_delta_seconds 2
#define backend_pathconf_case_insensitive TRUE
#define backend_getpwnam(name) NULL
#define backend_gen_nonce win_gen_nonce
#define backend_flock flock(fd, op) (-1)
#define backend_getpid getpid
#define backend_store_create_verifier win_store_create_verifier
#define backend_check_create_verifier win_check_create_verifier

#endif
