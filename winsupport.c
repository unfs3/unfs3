
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
#include <direct.h>
#include <dirent.h>
#include <locale.h>

#define MAX_NUM_DRIVES 26
#define FT70SEC 11644473600LL	       /* seconds between 1601-01-01 and
				          1970-01-01 */
#define FT80SEC 315529200	       /* seconds between 1970-01-01 and
				          1980-01-01 */

#define wsizeof(x) (sizeof(x)/sizeof(wchar_t))

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

/* 
 * The following UTF-8 validation is borrowed from
 * ftp://ftp.unicode.org/Public/PROGRAMS/CVTUTF/ConvertUTF.c.
 */

/*
 * Copyright 2001-2004 Unicode, Inc.
 * 
 * Disclaimer
 * 
 * This source code is provided as is by Unicode, Inc. No claims are
 * made as to fitness for any particular purpose. No warranties of any
 * kind are expressed or implied. The recipient agrees to determine
 * applicability of information provided. If this file has been
 * purchased on magnetic or optical media from Unicode, Inc., the
 * sole remedy for any claim will be exchange of defective media
 * within 90 days of receipt.
 * 
 * Limitations on Rights to Redistribute This Code
 * 
 * Unicode, Inc. hereby grants the right to freely use the information
 * supplied in this file in the creation of products supporting the
 * Unicode Standard, and to make copies of this file in any form
 * for internal or external distribution as long as this notice
 * remains attached.
 */

/*
 * Index into the table below with the first byte of a UTF-8 sequence to
 * get the number of trailing bytes that are supposed to follow it.
 * Note that *legal* UTF-8 values can't have 4 or 5-bytes. The table is
 * left as-is for anyone who may want to do such conversion, which was
 * allowed in earlier algorithms.
 */
static const char trailingBytesForUTF8[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5
};

/*
 * Utility routine to tell whether a sequence of bytes is legal UTF-8.
 * This must be called with the length pre-determined by the first byte.
 * If not calling this from ConvertUTF8to*, then the length can be set by:
 *  length = trailingBytesForUTF8[*source]+1;
 * and the sequence is illegal right away if there aren't that many bytes
 * available.
 * If presented with a length > 4, this returns 0.  The Unicode
 * definition of UTF-8 goes up to 4-byte sequences.
 */

static int isLegalUTF8(const unsigned char *source, int length)
{
    unsigned char a;
    const unsigned char *srcptr = source + length;

    switch (length) {
	default:
	    return 0;
	    /* Everything else falls through when "1"... */
	case 4:
	    if ((a = (*--srcptr)) < 0x80 || a > 0xBF)
		return 0;
	case 3:
	    if ((a = (*--srcptr)) < 0x80 || a > 0xBF)
		return 0;
	case 2:
	    if ((a = (*--srcptr)) > 0xBF)
		return 0;

	    switch (*source) {
		    /* no fall-through in this inner switch */
		case 0xE0:
		    if (a < 0xA0)
			return 0;
		    break;
		case 0xED:
		    if (a > 0x9F)
			return 0;
		    break;
		case 0xF0:
		    if (a < 0x90)
			return 0;
		    break;
		case 0xF4:
		    if (a > 0x8F)
			return 0;
		    break;
		default:
		    if (a < 0x80)
			return 0;
	    }

	case 1:
	    if (*source >= 0x80 && *source < 0xC2)
		return 0;
    }
    if (*source > 0xF4)
	return 0;
    return 1;
}

/* End of code borrowed from ConvertUTF.c */

int isLegalUTF8String(const unsigned char *source)
{
    const unsigned char *seq, *sourceend;
    int seqlen;

    sourceend = source + strlen(source);
    seq = source;

    while (seq < sourceend) {
	seqlen = trailingBytesForUTF8[*seq] + 1;
	if (!isLegalUTF8(seq, seqlen))
	    return 0;
	seq += seqlen;
    }

    return 1;
}

/* Translate an internal representation of a path (like /c/home) to
   a Windows path (like c:\home) */
static wchar_t *intpath2winpath(const char *intpath)
{
    wchar_t *winpath;
    int winpath_len;
    wchar_t *slash;
    const char *lastrootslash;
    wchar_t *lastslash;
    size_t intlen;

    /* Verify that input is valid UTF-8. We cannot use MB_ERR_INVALID_CHARS
       to MultiByteToWideChar, since it's only available in late versions of
       Windows. */
    if (!isLegalUTF8String(intpath)) {
	logmsg(LOG_CRIT, "intpath2winpath: Illegal UTF-8 string:%s", intpath);
	return NULL;
    }

    /* Skip over multiple root slashes for paths like ///home/john */
    lastrootslash = intpath;
    while (*lastrootslash == '/')
	lastrootslash++;
    if (lastrootslash != intpath)
	lastrootslash--;

    intlen = strlen(lastrootslash);
    /* One extra for /c -> c:\ */
    winpath_len = sizeof(wchar_t) * (intlen + 2);
    winpath = malloc(winpath_len);
    if (!winpath) {
	logmsg(LOG_CRIT, "intpath2winpath: Unable to allocate memory");
	return NULL;
    }

    if (!MultiByteToWideChar
	(CP_UTF8, 0, lastrootslash, -1, winpath, winpath_len)) {
	logmsg(LOG_CRIT, "intpath2winpath: MultiByteToWideChar failed");
	return NULL;
    }

    /* If path ends with /.., chop of the last component. Eventually, we
       might want to eliminate all occurances of .. */
    lastslash = wcsrchr(winpath, '/');
    if (!wcscmp(lastslash, L"/..")) {
	*lastslash = '\0';
	lastslash = wcsrchr(winpath, '/');
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

    while ((slash = wcschr(winpath, '/')) != NULL) {
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
    wchar_t *winpath;
    int ret;

    winpath = intpath2winpath(get_fdname(fildes));
    if (!winpath) {
	errno = EINVAL;
	return -1;
    }

    ret = _wchmod(winpath, mode);
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
    HANDLE h;
    FILETIME ft;
    SYSTEMTIME st;
    ULARGE_INTEGER fti;

    if ((ret = lseek(fd, offset, SEEK_SET)) < 0)
	return -1;
    size = write(fd, buf, count);

    /* Since we are using the CreationTime attribute as "ctime", we need to
       update it. From RFC1813: "Writing to the file changes the ctime in
       addition to the mtime." */
    h = (HANDLE) _get_osfhandle(fd);
    GetSystemTime(&st);
    SystemTimeToFileTime(&st, &ft);
    /* Ceil up to nearest even second */
    fti.LowPart = ft.dwLowDateTime;
    fti.HighPart = ft.dwHighDateTime;
    fti.QuadPart = ((fti.QuadPart + 20000000 - 1) / 20000000) * 20000000;
    ft.dwLowDateTime = fti.LowPart;
    ft.dwHighDateTime = fti.HighPart;
    if (!SetFileTime(h, &ft, NULL, NULL)) {
	fprintf(stderr,
		"warning: pwrite: SetFileTime failed with error %ld\n",
		GetLastError());
    }

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

    /* Set up locale, so that string compares works correctly */
    setlocale(LC_ALL, "");

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

    /* init winsock */
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

    /* disable error popups, for example from drives not ready */
    SetErrorMode(SEM_FAILCRITICALERRORS);

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
    wchar_t *winpath;
    int ret;
    wchar_t pathbuf[4096];
    int retval;
    size_t namelen;
    wchar_t *splitpoint;
    char savedchar;
    struct _stat win_statbuf;

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
    if (!winpath) {
	errno = EINVAL;
	return -1;
    }

    ret = _wstat(winpath, &win_statbuf);
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

    retval = GetFullPathNameW(winpath, wsizeof(pathbuf), pathbuf, NULL);
    if (!retval) {
	errno = ENOENT;
	return -1;
    }

    /* Set st_dev to the drive number */
    buf->st_dev = tolower(pathbuf[0]) - 'a';

    /* GetLongPathName fails if called with only x:\, and drive x is not
       ready. So, only call it for other paths. */
    if (pathbuf[0] && wcscmp(pathbuf + 1, L":\\")) {
	retval = GetLongPathNameW(pathbuf, pathbuf, wsizeof(pathbuf));
	if (!retval || (unsigned) retval > wsizeof(pathbuf)) {
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
    namelen = wcslen(pathbuf);
    splitpoint = &pathbuf[namelen / 2];
    savedchar = *splitpoint;
    *splitpoint = '\0';
    buf->st_ino = wfnv1a_32(pathbuf, 0);
    assert(sizeof(buf->st_ino) == 8);
    buf->st_ino = buf->st_ino << 32;
    *splitpoint = savedchar;
    buf->st_ino |= wfnv1a_32(splitpoint, 0);

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
    wchar_t *winpath;

    va_start(args, flags);
    mode = va_arg(args, int);

    va_end(args);

    winpath = intpath2winpath(pathname);
    if (!winpath) {
	errno = EINVAL;
	return -1;
    }

    fd = _wopen(winpath, flags | O_BINARY, mode);
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
    wchar_t *winpath;
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
	if (!winpath) {
	    free(ret);
	    errno = EINVAL;
	    return NULL;
	}

	ret->stream = _wopendir(winpath);
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
	struct _wdirent *de;

	de = _wreaddir(dir->stream);
	if (!de) {
	    return NULL;
	}

	if (!WideCharToMultiByte
	    (CP_UTF8, 0, de->d_name, -1, dir->de.d_name,
	     sizeof(dir->de.d_name), NULL, NULL)) {
	    logmsg(LOG_CRIT, "win_readdir: WideCharToMultiByte failed");
	    return NULL;
	}
	return &dir->de;
    }
}

int win_closedir(UNFS3_WIN_DIR * dir)
{
    if (dir->stream == NULL) {
	free(dir);
	return 0;
    } else {
	return _wclosedir(dir->stream);
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
    wchar_t *winpath;
    int ret;

    if (!strcmp("/", pathname)) {
	/* Emulate root */
	errno = EROFS;
	return -1;
    }

    winpath = intpath2winpath(pathname);
    if (!winpath) {
	errno = EINVAL;
	return -1;
    }

    /* FIXME: Use mode */
    ret = _wmkdir(winpath);
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
    wchar_t *winpath;
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
    if (!winpath) {
	errno = EINVAL;
	return -1;
    }

    winpath[3] = '\0';		       /* Cut off after x:\ */

    if (!GetDiskFreeSpaceW
	(winpath, &SectorsPerCluster, &BytesPerSector, &NumberOfFreeClusters,
	 &TotalNumberOfClusters)) {
	errno = EIO;
	return -1;
    }

    if (!GetDiskFreeSpaceExW
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
    wchar_t *winpath;
    int ret;

    if (!strcmp("/", pathname)) {
	/* Emulate root */
	errno = EROFS;
	return -1;
    }

    winpath = intpath2winpath(pathname);
    if (!winpath) {
	errno = EINVAL;
	return -1;
    }

    ret = _wremove(winpath);
    free(winpath);
    return ret;
}

int win_chmod(const char *path, mode_t mode)
{
    wchar_t *winpath;
    int ret;

    if (!strcmp("/", path)) {
	/* Emulate root */
	errno = EROFS;
	return -1;
    }

    winpath = intpath2winpath(path);
    if (!winpath) {
	errno = EINVAL;
	return -1;
    }

    ret = _wchmod(winpath, mode);
    free(winpath);
    return ret;
}

/* 
   If creation is false, the LastAccessTime will be set according to
   times->actime. Otherwise, CreationTime will be set. LastWriteTime
   is always set according to times->modtime.
*/
static int win_utime_creation(const char *path, const struct utimbuf *times,
			      int creation)
{
    wchar_t *winpath;
    int ret = 0;
    HANDLE h;
    ULARGE_INTEGER fti;
    FILETIME xtime, mtime;

    if (!strcmp("/", path)) {
	/* Emulate root */
	errno = EROFS;
	return -1;
    }

    winpath = intpath2winpath(path);
    if (!winpath) {
	errno = EINVAL;
	return -1;
    }

    /* Unfortunately, we cannot use utime(), since it doesn't support
       directories. */
    fti.QuadPart = UInt32x32To64(times->actime + FT70SEC, 10000000);
    xtime.dwHighDateTime = fti.HighPart;
    xtime.dwLowDateTime = fti.LowPart;
    fti.QuadPart = UInt32x32To64(times->modtime + FT70SEC, 10000000);
    mtime.dwHighDateTime = fti.HighPart;
    mtime.dwLowDateTime = fti.LowPart;

    h = CreateFileW(winpath, FILE_WRITE_ATTRIBUTES,
		    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
		    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, NULL);

    if (!SetFileTime
	(h, creation ? &xtime : NULL, creation ? NULL : &xtime, &mtime)) {
	errno = EACCES;
	ret = -1;
    }

    CloseHandle(h);
    free(winpath);
    return ret;
}

int win_utime(const char *path, const struct utimbuf *times)
{
    return win_utime_creation(path, times, FALSE);
}

int win_rmdir(const char *path)
{
    wchar_t *winpath;
    int ret;

    if (!strcmp("/", path)) {
	/* Emulate root */
	errno = EROFS;
	return -1;
    }

    winpath = intpath2winpath(path);
    if (!winpath) {
	errno = EINVAL;
	return -1;
    }

    ret = _wrmdir(winpath);
    free(winpath);
    return ret;
}

int win_rename(const char *oldpath, const char *newpath)
{
    wchar_t *oldwinpath, *newwinpath;
    int ret;

    if (!strcmp("/", oldpath) && !strcmp("/", newpath)) {
	/* Emulate root */
	errno = EROFS;
	return -1;
    }

    oldwinpath = intpath2winpath(oldpath);
    if (!oldwinpath) {
	errno = EINVAL;
	return -1;
    }
    newwinpath = intpath2winpath(newpath);
    if (!newwinpath) {
	free(oldwinpath);
	errno = EINVAL;
	return -1;
    }

    ret = _wrename(oldwinpath, newwinpath);
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

/* Just like strncasecmp, but compare two UTF8 strings. Limited to 4096 chars. */
int win_utf8ncasecmp(const char *s1, const char *s2, size_t n)
{
    wchar_t ws1[4096], ws2[4096];
    int converted;

    /* Make sure input is valid UTF-8 */
    if (!isLegalUTF8String(s1)) {
	logmsg(LOG_CRIT, "win_utf8ncasecmp: Illegal UTF-8 string:%s", s1);
	return -1;
    }
    if (!isLegalUTF8String(s2)) {
	logmsg(LOG_CRIT, "win_utf8ncasecmp: Illegal UTF-8 string:%s", s2);
	return -1;
    }

    /* Convert both strings to wide chars */
    converted = MultiByteToWideChar(CP_UTF8, 0, s1, n, ws1, wsizeof(ws1));
    if (!converted) {
	logmsg(LOG_CRIT, "win_utf8ncasecmp: MultiByteToWideChar failed");
	return -1;
    }
    ws1[converted] = '\0';
    converted = MultiByteToWideChar(CP_UTF8, 0, s2, n, ws2, wsizeof(ws2));
    if (!converted) {
	logmsg(LOG_CRIT, "win_utf8ncasecmp: MultiByteToWideChar failed");
	return 1;
    }
    ws2[converted] = '\0';

    /* compare */
    return _wcsicmp(ws1, ws2);
}

static void win_verf_to_ubuf(struct utimbuf *ubuf, createverf3 verf)
{
    ubuf->actime = verf[0] | verf[1] << 8 | verf[2] << 16 | verf[3] << 24;
    ubuf->modtime = verf[4] | verf[5] << 8 | verf[6] << 16 | verf[7] << 24;

    /* FAT can only store dates in the interval 1980-01-01 to 2107-12-31.
       However, since the utime interface uses Epoch time, we are further
       limited to 1980-01-01 to 2038-01-19, assuming 32 bit signed time_t.
       math.log(2**31-1 - FT80SEC, 2) = 30.7, which means that we can only
       use 30 bits. */
    ubuf->actime &= 0x3fffffff;
    ubuf->actime += FT80SEC;
    ubuf->modtime &= 0x3fffffff;
    ubuf->modtime += FT80SEC;
    /* While FAT CreationTime has a resolution of 10 ms, WriteTime only has a 
       resolution of 2 seconds. */
    ubuf->modtime &= ~1;
}

int win_store_create_verifier(char *obj, createverf3 verf)
{
    struct utimbuf ubuf;

    win_verf_to_ubuf(&ubuf, verf);
    return win_utime_creation(obj, &ubuf, TRUE);
}

int win_check_create_verifier(backend_statstruct * buf, createverf3 verf)
{
    struct utimbuf ubuf;

    win_verf_to_ubuf(&ubuf, verf);
    return (buf->st_ctime == ubuf.actime && buf->st_mtime == ubuf.modtime);
}

#endif				       /* WIN32 */
