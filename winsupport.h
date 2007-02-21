
/*
 * unfs3 Windows compatibility
 * Copyright 2006 Peter Åstrand <astrand@cendio.se> for Cendio AB
 * see file LICENSE for license details
 */

#ifdef WIN32
#ifndef UNFS3_WINSUPPORT_H
#define UNFS3_WINSUPPORT_H

#include <sys/stat.h>
#include <dirent.h>
#include <utime.h>
#include "nfs.h"

#define LOG_EMERG       0       /* system is unusable */
#define LOG_ALERT       1       /* action must be taken immediately */
#define LOG_CRIT        2       /* critical conditions */
#define LOG_ERR         3       /* error conditions */
#define LOG_WARNING     4       /* warning conditions */
#define LOG_NOTICE      5       /* normal but significant condition */
#define LOG_INFO        6       /* informational */
#define LOG_DEBUG       7       /* debug-level messages */
#define LOG_CONS        0
#define LOG_PID         0
#define LOG_DAEMON      0
#define closelog()      do { } while (0)

#define O_NONBLOCK      0
#define ELOOP           ENAMETOOLONG

#define S_IRWXG 0
#define S_IXGRP S_IRGRP
#define S_IRGRP 0
#define S_IWGRP 0

#define S_IRWXO 0
#define S_IXOTH S_IROTH 
#define S_IROTH 0
#define S_IWOTH 0

#define S_IFLNK 0
#define S_IFSOCK 0

typedef int socklen_t;
typedef uint32 uid_t;
typedef uint32 gid_t;

typedef struct _backend_statstruct
{
        uint32  st_dev;  
        uint64  st_ino;  
        _mode_t st_mode;
        short   st_nlink;
        uint32  st_uid;
        uint32  st_gid;
        _dev_t  st_rdev;
        _off_t  st_size;
        short   st_blksize;
        _off_t  st_blocks;
        time_t  st_atime;
        time_t  st_mtime;
        time_t  st_ctime;
} backend_statstruct;

typedef struct _backend_passwdstruct
{
    uid_t   pw_uid;
    gid_t   pw_gid;
} backend_passwdstruct;

/* Only includes fields actually used by unfs3 */
typedef struct _backend_statvfsstruct
{
        unsigned long  f_bsize;    /* file system block size */
        uint64         f_blocks;   /* size of fs in f_frsize units */
        uint64         f_bfree;    /* # free blocks */
        uint64         f_bavail;   /* # free blocks for non-root */
        uint64         f_files;    /* # inodes */
        uint64         f_ffree;    /* # free inodes */
} backend_statvfsstruct;

typedef struct _UNFS3_WIN_DIR
{
    _WDIR *stream; /* Windows DIR stream. NULL means root emulation */
    uint32 currentdrive; /* Next drive to check/return */
    struct dirent de;
    DWORD logdrives;
} UNFS3_WIN_DIR;

int inet_aton(const char *cp, struct in_addr *addr);
ssize_t pread(int fd, void *buf, size_t count, off_t offset);
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset);
void syslog(int priority, const char *format, ...);

int win_seteuid(uid_t euid);
int win_setegid(gid_t egid);
int win_truncate(const char *path, off_t length);
int win_chown(const char *path, uid_t owner, gid_t group);
int win_fchown(int fd, uid_t owner, gid_t group);
int win_fchmod(int fildes, mode_t mode);
int win_stat(const char *file_name, backend_statstruct *buf);
int win_fstat(int fd, backend_statstruct *buf);
int win_open(const char *pathname, int flags, ...);
int win_close(int fd);
UNFS3_WIN_DIR *win_opendir(const char *name);
struct dirent *win_readdir(UNFS3_WIN_DIR *dir);
int win_closedir(UNFS3_WIN_DIR *dir);
int win_init();
void openlog(const char *ident, int option, int facility);
char *win_realpath(const char *path, char *resolved_path);
int win_readlink(const char *path, char *buf, size_t bufsiz);
int win_mkdir(const char *pathname, mode_t mode);
int win_symlink(const char *oldpath, const char *newpath);
int win_mknod(const char *pathname, mode_t mode, dev_t dev);
int win_mkfifo(const char *pathname, mode_t mode);
int win_link(const char *oldpath, const char *newpath);
int win_statvfs(const char *path, backend_statvfsstruct *buf);
int win_remove(const char *pathname);
int win_chmod(const char *path, mode_t mode);
int win_utime(const char *path, const struct utimbuf *times);
int win_rmdir(const char *path);
int win_rename(const char *oldpath, const char *newpath);
int win_gen_nonce(char *nonce);
int win_utf8ncasecmp(const char *s1, const char *s2, size_t n);
int win_store_create_verifier(char *obj, createverf3 verf);
int win_check_create_verifier(backend_statstruct * buf, createverf3 verf);

#endif /* UNFS3_WINSUPPORT_H */
#endif /* WIN32 */
