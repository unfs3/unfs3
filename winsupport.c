
/*
 * unfs3 Windows compatibility layer
 * Copyright 2006 Peter Åstrand <astrand@cendio.se> for Cendio AB
 * see file LICENSE for license details
 */

#ifdef WIN32
#define _WIN32_WINDOWS 0x0410	       /* We require Windows 98 or later For
				          GetLongPathName */
#include <errno.h>
#include <stdio.h>
#include "winsupport.h"
#include "Config/exports.h"
#include "daemon.h"
#include <assert.h>
#include <windows.h>
#include <wincrypt.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>

#define MAX_NUM_DRIVES 26
#define FT70SEC 11644473600LL	       /* seconds between 1/1/1601 and
				          1/1/1970 */

typedef struct _fdname {
    int fd;
    char *name;
    struct _fdname *next;
} fdname;

static fdname *fdnames = NULL;

static char *get_fdname(int fd)
{
    fdname *fn;

    for (fn = fdnames; fn; fn = fn->next) {
	if (fn->fd == fd) {
	    return fn->name;
	    break;
	}
    }

    assert(0);
    return NULL;
}

static int add_fdname(int fd, const char *name)
{
    fdname *fn;

    fn = malloc(sizeof(fdname));
    if (!fn) {
	logmsg(LOG_CRIT, "add_mount: Unable to allocate memory");
	return -1;
    }

    fn->fd = fd;
    fn->name = strdup(name);
    fn->next = fdnames;
    fdnames = fn;

    return fd;
}

static void remove_fdname(int fd)
{
    fdname *fn, **prevnext = &fdnames;

    for (fn = fdnames; fn; fn = fn->next) {
	if (fn->fd == fd) {
	    *prevnext = fn->next;
	    free(fn->name);
	    free(fn);
	    break;
	}
	prevnext = &fn->next;
    }
}

/* Translate an internal representation of a path (like /c/home) to
   a Windows path (like c:\home) */
static char *intpath2winpath(const char *intpath)
{
    char *winpath;
    char *slash;
    const char *lastrootslash;
    char *lastslash;
    size_t intlen;

    /* Skip over multiple root slashes for paths like ///home/john */
    lastrootslash = intpath;
    while (*lastrootslash == '/')
	lastrootslash++;
    if (lastrootslash != intpath)
	lastrootslash--;

    intlen = strlen(lastrootslash);
    winpath = malloc(intlen + 1);      /* One extra for /c -> c:\ */
    if (!winpath) {
	logmsg(LOG_CRIT, "add_mount: Unable to allocate memory");
	return NULL;
    }

    strcpy(winpath, lastrootslash);

    /* If path ends with /.., chop of the last component. Eventually, we
       might want to eliminate all occurances of .. */
    lastslash = strrchr(winpath, '/');
    if (!strcmp(lastslash, "/..")) {
	*lastslash = '\0';
	lastslash = strrchr(winpath, '/');
	*lastslash = '\0';
    }

    /* Translate /x -> x:/ and /x/something -> x:/something */
    if ((winpath[0] == '/') && winpath[1]) {
	switch (winpath[2]) {
	    case '\0':
		winpath[2] = '/';
		winpath[3] = '\0';
		/* fall through */

	    case '/':
		winpath[0] = winpath[1];
		winpath[1] = ':';
		break;

	    default:
		break;
	}
    }

    while ((slash = strchr(winpath, '/')) != NULL) {
	*slash = '\\';
    }

    return winpath;
}

int win_seteuid(U(uid_t euid))
{
    return 0;
}

int win_setegid(U(gid_t egid))
{
    return 0;
}

int win_truncate(const char *path, off_t length)
{
    int fd, ret, saved_errno;

    fd = win_open(path, O_WRONLY);
    if (fd < 0)
	return -1;
    ret = chsize(fd, length);
    saved_errno = errno;
    win_close(fd);
    errno = saved_errno;

    return ret;
}

int win_chown(U(const char *path), U(uid_t owner), U(gid_t group))
{
    errno = EINVAL;
    return -1;
}

int win_fchown(U(int fd), U(uid_t owner), U(gid_t group))
{
    errno = EINVAL;
    return -1;
}

int win_fchmod(int fildes, mode_t mode)
{
    char *winpath;
    int ret;

    winpath = intpath2winpath(get_fdname(fildes));
    ret = chmod(winpath, mode);
    free(winpath);
    return ret;
}

int inet_aton(const char *cp, struct in_addr *addr)
{
    addr->s_addr = inet_addr(cp);
    return (addr->s_addr == INADDR_NONE) ? 0 : 1;
}

/* 
   If you need a good laugh, take a look at the "Suggested Interix
   replacement" at:
   http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dnucmg/html/UCMGch10.asp
*/
ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
    ssize_t size;
    off_t ret;

    if ((ret = lseek(fd, offset, SEEK_SET)) < 0)
	return -1;
    size = read(fd, buf, count);
    return size;
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset)
{
    ssize_t size;
    off_t ret;

    if ((ret = lseek(fd, offset, SEEK_SET)) < 0)
	return -1;
    size = write(fd, buf, count);
    return size;
}

void syslog(U(int priority), U(const char *format), ...)
{
    assert(0);
}

int win_init()
{
    WORD winsock_ver;
    WSADATA wsadata;

    /* Verify that -s is used */
    if (!opt_singleuser) {
	fprintf(stderr, "Single-user mode is required on this platform.\n");
	exit(1);
    }

    /* Verify that -d is used */
    if (opt_detach) {
	fprintf(stderr,
		"Foreground (debug) mode is required on this platform.\n");
	exit(1);
    }

    winsock_ver = MAKEWORD(1, 1);
    if (WSAStartup(winsock_ver, &wsadata)) {
	fprintf(stderr, "Unable to initialise WinSock\n");
	exit(1);
    }
    if (LOBYTE(wsadata.wVersion) != 1 || HIBYTE(wsadata.wVersion) != 1) {
	fprintf(stderr, "WinSock version is incompatible with 1.1\n");
	WSACleanup();
	exit(1);
    }
    return 0;
}

void win_shutdown()
{
    WSACleanup();
}

/* Wrapper for Windows stat function, which provides
   st_dev and st_ino. These are calculated as follows:

   st_dev is set to the drive number (0=A 1=B ...). Our virtual root
   "/" gets a st_dev of 0xff. 

   st_ino is hashed from the full file path. Each half produces a 32
   bit hash. These are concatenated to a 64 bit value. The risk that
   st_ino is the same for two files on the system is, if I'm not
   mistaken, b=pigeon(2**32, f)**2. For f=1000, b=1e-08. By using a 64
   bit hash function this risk can be lowered. Possible future
   enhancement.

   pigeon() can be calculated in Python with:
   
   def pigeon(m, n):
       res = 1.0
       for i in range(m - n + 1, m):
           res = res * i / m
       return 1 - res
*/
int win_stat(const char *file_name, backend_statstruct * buf)
{
    char *winpath;
    int ret;
    char pathbuf[4096];
    int retval;
    int namelen;
    char *splitpoint;
    char savedchar;
    struct stat win_statbuf;

    /* Special case: Our top-level virtual root, containing each drive
       represented as a directory. Compare with "My Computer" etc. This
       virtual root has a hardcoded hash value of 1, to simplify debugging
       etc. */
    if (!strcmp(file_name, "/")) {
	buf->st_mode = S_IFDIR | S_IRUSR | S_IWUSR;
	buf->st_nlink = MAX_NUM_DRIVES + 3;	/* 3 extra for: . .. / */
	buf->st_uid = 1;
	buf->st_gid = 1;
	buf->st_rdev = 0;
	buf->st_size = 4096;
	buf->st_atime = 0;
	buf->st_mtime = 0;
	buf->st_ctime = 0;
	buf->st_dev = 0xff;
	buf->st_ino = 1;
	return 0;
    }

    winpath = intpath2winpath(file_name);

    ret = stat(winpath, &win_statbuf);
    if (ret < 0) {
	free(winpath);
	return ret;
    }

    /* Copy values to our struct */
    buf->st_mode = win_statbuf.st_mode;
    buf->st_nlink = win_statbuf.st_nlink;
    buf->st_uid = win_statbuf.st_uid;
    buf->st_gid = win_statbuf.st_gid;
    buf->st_rdev = win_statbuf.st_rdev;
    buf->st_size = win_statbuf.st_size;
    buf->st_atime = win_statbuf.st_atime;
    buf->st_mtime = win_statbuf.st_mtime;
    buf->st_ctime = win_statbuf.st_ctime;
    buf->st_blocks = win_statbuf.st_size / 512;

    retval = GetFullPathName(winpath, sizeof(pathbuf), pathbuf, NULL);
    if (!retval) {
	errno = ENOENT;
	return -1;
    }

    /* Set st_dev to the drive number */
    buf->st_dev = tolower(pathbuf[0]) - 'a';

    /* GetLongPathName fails if called with only x:\, and drive x is not
       ready. So, only call it for other paths. */
    if (pathbuf[0] && strcmp(pathbuf + 1, ":\\")) {
	retval = GetLongPathName(pathbuf, pathbuf, sizeof(pathbuf));
	if (!retval || (unsigned) retval > sizeof(pathbuf)) {
	    /* Strangely enough, GetLongPathName returns
	       ERROR_SHARING_VIOLATION for locked files, such as hiberfil.sys 
	     */
	    if (GetLastError() != ERROR_SHARING_VIOLATION) {
		errno = ENAMETOOLONG;
		return -1;
	    }
	}
    }

    /* Hash st_ino, by splitting in two halves */
    namelen = strlen(pathbuf);
    splitpoint = &pathbuf[namelen / 2];
    savedchar = *splitpoint;
    *splitpoint = '\0';
    buf->st_ino = fnv1a_32(pathbuf, 0);
    assert(sizeof(buf->st_ino) == 8);
    buf->st_ino = buf->st_ino << 32;
    *splitpoint = savedchar;
    buf->st_ino |= fnv1a_32(splitpoint, 0);

#if 0
    fprintf(stderr,
	    "win_stat: file=%s, ret=%d, st_dev=0x%x, st_ino=0x%I64x\n",
	    file_name, ret, buf->st_dev, buf->st_ino);
#endif
    free(winpath);
    return ret;
}

int win_open(const char *pathname, int flags, ...)
{
    va_list args;
    mode_t mode;
    int fd;
    char *winpath;

    va_start(args, flags);
    mode = va_arg(args, int);

    va_end(args);

    winpath = intpath2winpath(pathname);
    fd = open(winpath, flags | O_BINARY, mode);
    free(winpath);
    if (fd < 0) {
	return fd;
    }

    return add_fdname(fd, pathname);

}

int win_close(int fd)
{
    remove_fdname(fd);
    return close(fd);
}

int win_fstat(int fd, backend_statstruct * buf)
{
    return win_stat(get_fdname(fd), buf);
}

/*
  opendir implementation which emulates a virtual root with the drive
  letters presented as directories. 
*/
UNFS3_WIN_DIR *win_opendir(const char *name)
{
    char *winpath;
    UNFS3_WIN_DIR *ret;

    ret = malloc(sizeof(UNFS3_WIN_DIR));
    if (!ret) {
	logmsg(LOG_CRIT, "win_opendir: Unable to allocate memory");
	return NULL;
    }

    if (!strcmp("/", name)) {
	/* Emulate root */
	ret->stream = NULL;
	ret->currentdrive = 0;
	ret->logdrives = GetLogicalDrives();
    } else {
	winpath = intpath2winpath(name);
	ret->stream = opendir(winpath);
	free(winpath);
	if (ret->stream == NULL) {
	    free(ret);
	    ret = NULL;
	}
    }

    return ret;
}

struct dirent *win_readdir(UNFS3_WIN_DIR * dir)
{
    if (dir->stream == NULL) {
	/* Emulate root */
	for (; dir->currentdrive < MAX_NUM_DRIVES; dir->currentdrive++) {
	    if (dir->logdrives & 1 << dir->currentdrive)
		break;
	}

	if (dir->currentdrive < MAX_NUM_DRIVES) {
	    dir->de.d_name[0] = 'a' + dir->currentdrive;
	    dir->de.d_name[1] = '\0';
	    dir->currentdrive++;
	    return &dir->de;
	} else {
	    return NULL;
	}
    } else {
	return readdir(dir->stream);
    }
}

int win_closedir(UNFS3_WIN_DIR * dir)
{
    if (dir->stream == NULL) {
	free(dir);
	return 0;
    } else {
	return closedir(dir->stream);
    }
}

void openlog(U(const char *ident), U(int option), U(int facility))
{

}

char *win_realpath(const char *path, char *resolved_path)
{
    return normpath(path, resolved_path);
}

int win_readlink(U(const char *path), U(char *buf), U(size_t bufsiz))
{
    errno = ENOSYS;
    return -1;
}

int win_mkdir(const char *pathname, U(mode_t mode))
{
    char *winpath;
    int ret;

    if (!strcmp("/", pathname)) {
	/* Emulate root */
	errno = EROFS;
	return -1;
    }

    winpath = intpath2winpath(pathname);
    /* FIXME: Use mode */
    ret = mkdir(winpath);
    free(winpath);
    return ret;
}

int win_symlink(U(const char *oldpath), U(const char *newpath))
{
    errno = ENOSYS;
    return -1;
}

int win_mknod(U(const char *pathname), U(mode_t mode), U(dev_t dev))
{
    errno = ENOSYS;
    return -1;
}

int win_mkfifo(U(const char *pathname), U(mode_t mode))
{
    errno = ENOSYS;
    return -1;
}

int win_link(U(const char *oldpath), U(const char *newpath))
{
    errno = ENOSYS;
    return -1;
}

int win_statvfs(const char *path, backend_statvfsstruct * buf)
{
    char *winpath;
    DWORD SectorsPerCluster;
    DWORD BytesPerSector;
    DWORD NumberOfFreeClusters;
    DWORD TotalNumberOfClusters;
    ULARGE_INTEGER FreeBytesAvailable;
    ULARGE_INTEGER TotalNumberOfBytes;
    ULARGE_INTEGER TotalNumberOfFreeBytes;

    if (!strcmp("/", path)) {
	/* Emulate root */
	buf->f_bsize = 1024;
	buf->f_blocks = 1024;
	buf->f_bfree = 0;
	buf->f_bavail = 0;
	buf->f_files = 1024;
	buf->f_ffree = 0;
	return 0;
    }

    winpath = intpath2winpath(path);
    winpath[3] = '\0';		       /* Cut off after x:\ */

    if (!GetDiskFreeSpace
	(winpath, &SectorsPerCluster, &BytesPerSector, &NumberOfFreeClusters,
	 &TotalNumberOfClusters)) {
	errno = EIO;
	return -1;
    }

    if (!GetDiskFreeSpaceEx
	(winpath, &FreeBytesAvailable, &TotalNumberOfBytes,
	 &TotalNumberOfFreeBytes)) {
	errno = EIO;
	return -1;
    }

    buf->f_bsize = BytesPerSector;
    buf->f_blocks = TotalNumberOfBytes.QuadPart / BytesPerSector;
    buf->f_bfree = TotalNumberOfFreeBytes.QuadPart / BytesPerSector;
    buf->f_bavail = FreeBytesAvailable.QuadPart / BytesPerSector;
    buf->f_files = buf->f_blocks / SectorsPerCluster;
    buf->f_ffree = buf->f_bfree / SectorsPerCluster;
    free(winpath);
    return 0;
}

int win_remove(const char *pathname)
{
    char *winpath;
    int ret;

    if (!strcmp("/", pathname)) {
	/* Emulate root */
	errno = EROFS;
	return -1;
    }

    winpath = intpath2winpath(pathname);
    ret = remove(winpath);
    free(winpath);
    return ret;
}

int win_chmod(const char *path, mode_t mode)
{
    char *winpath;
    int ret;

    if (!strcmp("/", path)) {
	/* Emulate root */
	errno = EROFS;
	return -1;
    }

    winpath = intpath2winpath(path);
    ret = chmod(winpath, mode);
    free(winpath);
    return ret;
}

int win_utime(const char *path, const struct utimbuf *times)
{
    char *winpath;
    int ret = 0;
    HANDLE h;
    ULARGE_INTEGER fti;
    FILETIME atime, mtime;

    if (!strcmp("/", path)) {
	/* Emulate root */
	errno = EROFS;
	return -1;
    }

    winpath = intpath2winpath(path);

    /* Unfortunately, we cannot use utime(), since it doesn't support
       directories. */
    fti.QuadPart = UInt32x32To64(times->actime + FT70SEC, 10000000);
    atime.dwHighDateTime = fti.HighPart;
    atime.dwLowDateTime = fti.LowPart;
    fti.QuadPart = UInt32x32To64(times->modtime + FT70SEC, 10000000);
    mtime.dwHighDateTime = fti.HighPart;
    mtime.dwLowDateTime = fti.LowPart;

    h = CreateFile(winpath, FILE_WRITE_ATTRIBUTES,
		   FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
		   FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, NULL);

    if (!SetFileTime(h, NULL, &atime, &mtime)) {
	errno = EACCES;
	ret = -1;
    }

    CloseHandle(h);
    free(winpath);
    return ret;
}

int win_rmdir(const char *path)
{
    char *winpath;
    int ret;

    if (!strcmp("/", path)) {
	/* Emulate root */
	errno = EROFS;
	return -1;
    }

    winpath = intpath2winpath(path);
    ret = rmdir(winpath);
    free(winpath);
    return ret;
}

int win_rename(const char *oldpath, const char *newpath)
{
    char *oldwinpath, *newwinpath;
    int ret;

    if (!strcmp("/", oldpath) && !strcmp("/", newpath)) {
	/* Emulate root */
	errno = EROFS;
	return -1;
    }

    oldwinpath = intpath2winpath(oldpath);
    newwinpath = intpath2winpath(newpath);

    ret = rename(oldwinpath, newwinpath);
    free(oldwinpath);
    free(newwinpath);
    return ret;
}

int win_gen_nonce(char *nonce)
{
    HCRYPTPROV hCryptProv;

    if (!CryptAcquireContext
	(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
	logmsg(LOG_ERR, "CryptAcquireContext failed with error 0x%lx",
	       GetLastError());
	return -1;
    }

    if (!CryptGenRandom(hCryptProv, 32, nonce)) {
	logmsg(LOG_ERR, "CryptGenRandom failed with error 0x%lx",
	       GetLastError());
	return -1;
    }

    if (!CryptReleaseContext(hCryptProv, 0)) {
	logmsg(LOG_ERR, "CryptReleaseContext failed with error 0x%lx",
	       GetLastError());
	return -1;
    }

    return 0;
}

#endif				       /* WIN32 */
