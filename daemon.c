
/*
 * UNFS3 server framework
 * Originally generated using rpcgen
 * Portions (C) 2004, Pascal Schmidt
 * see file LICENSE for license details
 */

#include "config.h"

#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#else				       /* WIN32 */
#include <winsock.h>
#endif				       /* WIN32 */

#include <fcntl.h>
#include <memory.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#if HAVE_RPC_SVC_SOC_H == 1
# include <rpc/svc_soc.h>
#endif

#include "nfs.h"
#include "mount.h"
#include "xdr.h"
#include "fh.h"
#include "fh_cache.h"
#include "fd_cache.h"
#include "user.h"
#include "daemon.h"
#include "backend.h"
#include "Config/exports.h"

#ifndef SIG_PF
#define SIG_PF void(*)(int)
#endif

#define UNFS_NAME "UNFS3 unfsd " PACKAGE_VERSION " (C) 2006, Pascal Schmidt <unfs3-server@ewetel.net>\n"

/* write verifier */
writeverf3 wverf;

/* readdir cookie */
cookie3 rcookie = 0;

/* options and default values */
int opt_detach = TRUE;
char *opt_exports = "/etc/exports";
int opt_cluster = FALSE;
char *opt_cluster_path = "/";
int opt_tcponly = FALSE;
unsigned int opt_nfs_port = NFS_PORT;	/* 0 means RPC_ANYSOCK */
unsigned int opt_mount_port = NFS_PORT;
int opt_singleuser = FALSE;
int opt_brute_force = FALSE;
int opt_testconfig = FALSE;
struct in_addr opt_bind_addr;
int opt_readable_executables = FALSE;
char *opt_pid_file = NULL;

/* Register with portmapper? */
int opt_portmapper = TRUE;

/*
 * output message to syslog or stdout
 */
void logmsg(int prio, const char *fmt, ...)
{
    va_list ap;

#if HAVE_VSYSLOG == 0
    char mesg[1024];
#endif

    va_start(ap, fmt);
    if (opt_detach) {
#if HAVE_VSYSLOG == 1
	vsyslog(prio, fmt, ap);
#else
	vsnprintf(mesg, 1024, fmt, ap);
	syslog(prio, mesg, 1024);
#endif
    } else {
	vprintf(fmt, ap);
	putchar('\n');
    }
    va_end(ap);
}

/*
 * return remote address from svc_req structure
 */
struct in_addr get_remote(struct svc_req *rqstp)
{
    return (svc_getcaller(rqstp->rq_xprt))->sin_addr;
}

/*
 * return remote port from svc_req structure
 */
short get_port(struct svc_req *rqstp)
{
    return (svc_getcaller(rqstp->rq_xprt))->sin_port;
}

/*
 * return the socket type of the request (SOCK_STREAM or SOCK_DGRAM)
 */
int get_socket_type(struct svc_req *rqstp)
{
    int v, res;
    socklen_t l;

    l = sizeof(v);

#if HAVE_STRUCT___RPC_SVCXPRT_XP_FD == 1
    res = getsockopt(rqstp->rq_xprt->xp_fd, SOL_SOCKET, SO_TYPE, &v, &l);
#else
    res = getsockopt(rqstp->rq_xprt->xp_sock, SOL_SOCKET, SO_TYPE, &v, &l);
#endif

    if (res < 0) {
	logmsg(LOG_CRIT, "unable to determine socket type");
	return -1;
    }

    return v;
}

/*
 * write current pid to a file
 */
static void create_pid_file(void)
{
    char buf[16];
    int fd, res, len;

    if (!opt_pid_file)
	return;

    fd = backend_open_create(opt_pid_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
	logmsg(LOG_WARNING, "failed to create pid file `%s'", opt_pid_file);
	return;
    }
#if defined(LOCK_EX) && defined(LOCK_NB)
    res = backend_flock(fd, LOCK_EX | LOCK_NB);
    if (res == -1) {
	logmsg(LOG_WARNING, "failed to lock pid file `%s'", opt_pid_file);
	backend_close(fd);
	return;
    }
#endif

    sprintf(buf, "%i\n", backend_getpid());
    len = strlen(buf);

    res = backend_pwrite(fd, buf, len, 0);
    backend_close(fd);
    if (res != len) {
	logmsg(LOG_WARNING, "failed to write pid file `%s'", opt_pid_file);
    }
}

/*
 * remove pid file
 */
static void remove_pid_file(void)
{
    int res;

    if (!opt_pid_file)
	return;

    res = backend_remove(opt_pid_file);
    if (res == -1 && errno != ENOENT) {
	logmsg(LOG_WARNING, "failed to remove pid file `%s'", opt_pid_file);
    }
}

/*
 * parse command line options
 */
static void parse_options(int argc, char **argv)
{
    int opt = 0;
    char *optstring = "bcC:de:hl:m:n:prstTuwi:";

    while (opt != -1) {
	opt = getopt(argc, argv, optstring);
	switch (opt) {
	    case 'b':
		opt_brute_force = TRUE;
		break;
#ifdef WANT_CLUSTER
	    case 'c':
		opt_cluster = TRUE;
		break;
	    case 'C':
		opt_cluster_path = optarg;
		break;
#endif
	    case 'd':
		printf(UNFS_NAME);
		opt_detach = FALSE;
		break;
	    case 'e':
#ifndef WIN32
		if (optarg[0] != '/') {
		    /* A relative path won't work for re-reading the exports
		       file on SIGHUP, since we are changing directory */
		    fprintf(stderr, "Error: relative path to exports file\n");
		    exit(1);
		}
#endif
		opt_exports = optarg;
		break;
	    case 'h':
		printf(UNFS_NAME);
		printf("Usage: %s [options]\n", argv[0]);
		printf("\t-h          display this short option summary\n");
		printf("\t-u          use unprivileged port for services\n");
		printf("\t-d          do not detach from terminal\n");
		printf("\t-e <file>   file to use instead of /etc/exports\n");
		printf("\t-i <file>   write daemon pid to given file\n");
#ifdef WANT_CLUSTER
		printf("\t-c          enable cluster extensions\n");
		printf("\t-C <path>   set path for cluster extensions\n");
#endif
		printf("\t-n <port>   port to use for NFS service\n");
		printf("\t-m <port>   port to use for MOUNT service\n");
		printf
		    ("\t-t          TCP only, do not listen on UDP ports\n");
		printf("\t-p          do not register with the portmapper\n");
		printf("\t-s          single user mode\n");
		printf("\t-b          enable brute force file searching\n");
		printf
		    ("\t-l <addr>   bind to interface with specified address\n");
		printf
		    ("\t-r          report unreadable executables as readable\n");
		printf("\t-T          test exports file and exit\n");
		exit(0);
		break;
	    case 'l':
		opt_bind_addr.s_addr = inet_addr(optarg);
		if (opt_bind_addr.s_addr == (unsigned) -1) {
		    fprintf(stderr, "Invalid bind address\n");
		    exit(1);
		}
		break;
	    case 'm':
		opt_mount_port = strtol(optarg, NULL, 10);
		if (opt_mount_port == 0) {
		    fprintf(stderr, "Invalid port\n");
		    exit(1);
		}
		break;
	    case 'n':
		opt_nfs_port = strtol(optarg, NULL, 10);
		if (opt_nfs_port == 0) {
		    fprintf(stderr, "Invalid port\n");
		    exit(1);
		}
		break;
	    case 'p':
		opt_portmapper = FALSE;
		break;
	    case 'r':
		opt_readable_executables = TRUE;
		break;
	    case 's':
		opt_singleuser = TRUE;
#ifndef WIN32
		if (backend_getuid() == 0) {
		    logmsg(LOG_WARNING,
			   "Warning: running as root with -s is dangerous");
		    logmsg(LOG_WARNING,
			   "All clients will have root access to all exported files!");
		}
#endif
		break;
	    case 't':
		opt_tcponly = TRUE;
		break;
	    case 'T':
		opt_testconfig = TRUE;
		break;
	    case 'u':
		opt_nfs_port = 0;
		opt_mount_port = 0;
		break;
	    case 'i':
		opt_pid_file = optarg;
		break;
	    case '?':
		exit(1);
		break;
	}
    }
}

/*
 * signal handler and error exit function
 */
void daemon_exit(int error)
{
#ifndef WIN32
    if (error == SIGHUP) {
	get_squash_ids();
	exports_parse();
	return;
    }

    if (error == SIGUSR1) {
	if (fh_cache_use > 0)
	    logmsg(LOG_INFO, "fh entries %i access %i hit %i miss %i",
		   fh_cache_max, fh_cache_use, fh_cache_hit,
		   fh_cache_use - fh_cache_hit);
	else
	    logmsg(LOG_INFO, "fh cache unused");
	logmsg(LOG_INFO, "open file descriptors: read %i, write %i",
	       fd_cache_readers, fd_cache_writers);
	return;
    }
#endif				       /* WIN32 */

    if (opt_portmapper) {
	svc_unregister(MOUNTPROG, MOUNTVERS1);
	svc_unregister(MOUNTPROG, MOUNTVERS3);
    }

    if (opt_portmapper) {
	svc_unregister(NFS3_PROGRAM, NFS_V3);
    }

    if (error == SIGSEGV)
	logmsg(LOG_EMERG, "segmentation fault");

    fd_cache_purge();

    if (opt_detach)
	closelog();

    remove_pid_file();
    backend_shutdown();

    exit(1);
}

/*
 * NFS service dispatch function
 * generated by rpcgen
 */
static void nfs3_program_3(struct svc_req *rqstp, register SVCXPRT * transp)
{
    union {
	GETATTR3args nfsproc3_getattr_3_arg;
	SETATTR3args nfsproc3_setattr_3_arg;
	LOOKUP3args nfsproc3_lookup_3_arg;
	ACCESS3args nfsproc3_access_3_arg;
	READLINK3args nfsproc3_readlink_3_arg;
	READ3args nfsproc3_read_3_arg;
	WRITE3args nfsproc3_write_3_arg;
	CREATE3args nfsproc3_create_3_arg;
	MKDIR3args nfsproc3_mkdir_3_arg;
	SYMLINK3args nfsproc3_symlink_3_arg;
	MKNOD3args nfsproc3_mknod_3_arg;
	REMOVE3args nfsproc3_remove_3_arg;
	RMDIR3args nfsproc3_rmdir_3_arg;
	RENAME3args nfsproc3_rename_3_arg;
	LINK3args nfsproc3_link_3_arg;
	READDIR3args nfsproc3_readdir_3_arg;
	READDIRPLUS3args nfsproc3_readdirplus_3_arg;
	FSSTAT3args nfsproc3_fsstat_3_arg;
	FSINFO3args nfsproc3_fsinfo_3_arg;
	PATHCONF3args nfsproc3_pathconf_3_arg;
	COMMIT3args nfsproc3_commit_3_arg;
    } argument;
    char *result;
    xdrproc_t _xdr_argument, _xdr_result;
    char *(*local) (char *, struct svc_req *);

    switch (rqstp->rq_proc) {
	case NFSPROC3_NULL:
	    _xdr_argument = (xdrproc_t) xdr_void;
	    _xdr_result = (xdrproc_t) xdr_void;
	    local = (char *(*)(char *, struct svc_req *)) nfsproc3_null_3_svc;
	    break;

	case NFSPROC3_GETATTR:
	    _xdr_argument = (xdrproc_t) xdr_GETATTR3args;
	    _xdr_result = (xdrproc_t) xdr_GETATTR3res;
	    local =
		(char *(*)(char *, struct svc_req *)) nfsproc3_getattr_3_svc;
	    break;

	case NFSPROC3_SETATTR:
	    _xdr_argument = (xdrproc_t) xdr_SETATTR3args;
	    _xdr_result = (xdrproc_t) xdr_SETATTR3res;
	    local =
		(char *(*)(char *, struct svc_req *)) nfsproc3_setattr_3_svc;
	    break;

	case NFSPROC3_LOOKUP:
	    _xdr_argument = (xdrproc_t) xdr_LOOKUP3args;
	    _xdr_result = (xdrproc_t) xdr_LOOKUP3res;
	    local =
		(char *(*)(char *, struct svc_req *)) nfsproc3_lookup_3_svc;
	    break;

	case NFSPROC3_ACCESS:
	    _xdr_argument = (xdrproc_t) xdr_ACCESS3args;
	    _xdr_result = (xdrproc_t) xdr_ACCESS3res;
	    local =
		(char *(*)(char *, struct svc_req *)) nfsproc3_access_3_svc;
	    break;

	case NFSPROC3_READLINK:
	    _xdr_argument = (xdrproc_t) xdr_READLINK3args;
	    _xdr_result = (xdrproc_t) xdr_READLINK3res;
	    local =
		(char *(*)(char *, struct svc_req *)) nfsproc3_readlink_3_svc;
	    break;

	case NFSPROC3_READ:
	    _xdr_argument = (xdrproc_t) xdr_READ3args;
	    _xdr_result = (xdrproc_t) xdr_READ3res;
	    local = (char *(*)(char *, struct svc_req *)) nfsproc3_read_3_svc;
	    break;

	case NFSPROC3_WRITE:
	    _xdr_argument = (xdrproc_t) xdr_WRITE3args;
	    _xdr_result = (xdrproc_t) xdr_WRITE3res;
	    local =
		(char *(*)(char *, struct svc_req *)) nfsproc3_write_3_svc;
	    break;

	case NFSPROC3_CREATE:
	    _xdr_argument = (xdrproc_t) xdr_CREATE3args;
	    _xdr_result = (xdrproc_t) xdr_CREATE3res;
	    local =
		(char *(*)(char *, struct svc_req *)) nfsproc3_create_3_svc;
	    break;

	case NFSPROC3_MKDIR:
	    _xdr_argument = (xdrproc_t) xdr_MKDIR3args;
	    _xdr_result = (xdrproc_t) xdr_MKDIR3res;
	    local =
		(char *(*)(char *, struct svc_req *)) nfsproc3_mkdir_3_svc;
	    break;

	case NFSPROC3_SYMLINK:
	    _xdr_argument = (xdrproc_t) xdr_SYMLINK3args;
	    _xdr_result = (xdrproc_t) xdr_SYMLINK3res;
	    local =
		(char *(*)(char *, struct svc_req *)) nfsproc3_symlink_3_svc;
	    break;

	case NFSPROC3_MKNOD:
	    _xdr_argument = (xdrproc_t) xdr_MKNOD3args;
	    _xdr_result = (xdrproc_t) xdr_MKNOD3res;
	    local =
		(char *(*)(char *, struct svc_req *)) nfsproc3_mknod_3_svc;
	    break;

	case NFSPROC3_REMOVE:
	    _xdr_argument = (xdrproc_t) xdr_REMOVE3args;
	    _xdr_result = (xdrproc_t) xdr_REMOVE3res;
	    local =
		(char *(*)(char *, struct svc_req *)) nfsproc3_remove_3_svc;
	    break;

	case NFSPROC3_RMDIR:
	    _xdr_argument = (xdrproc_t) xdr_RMDIR3args;
	    _xdr_result = (xdrproc_t) xdr_RMDIR3res;
	    local =
		(char *(*)(char *, struct svc_req *)) nfsproc3_rmdir_3_svc;
	    break;

	case NFSPROC3_RENAME:
	    _xdr_argument = (xdrproc_t) xdr_RENAME3args;
	    _xdr_result = (xdrproc_t) xdr_RENAME3res;
	    local =
		(char *(*)(char *, struct svc_req *)) nfsproc3_rename_3_svc;
	    break;

	case NFSPROC3_LINK:
	    _xdr_argument = (xdrproc_t) xdr_LINK3args;
	    _xdr_result = (xdrproc_t) xdr_LINK3res;
	    local = (char *(*)(char *, struct svc_req *)) nfsproc3_link_3_svc;
	    break;

	case NFSPROC3_READDIR:
	    _xdr_argument = (xdrproc_t) xdr_READDIR3args;
	    _xdr_result = (xdrproc_t) xdr_READDIR3res;
	    local =
		(char *(*)(char *, struct svc_req *)) nfsproc3_readdir_3_svc;
	    break;

	case NFSPROC3_READDIRPLUS:
	    _xdr_argument = (xdrproc_t) xdr_READDIRPLUS3args;
	    _xdr_result = (xdrproc_t) xdr_READDIRPLUS3res;
	    local = (char *(*)(char *, struct svc_req *))
		nfsproc3_readdirplus_3_svc;
	    break;

	case NFSPROC3_FSSTAT:
	    _xdr_argument = (xdrproc_t) xdr_FSSTAT3args;
	    _xdr_result = (xdrproc_t) xdr_FSSTAT3res;
	    local =
		(char *(*)(char *, struct svc_req *)) nfsproc3_fsstat_3_svc;
	    break;

	case NFSPROC3_FSINFO:
	    _xdr_argument = (xdrproc_t) xdr_FSINFO3args;
	    _xdr_result = (xdrproc_t) xdr_FSINFO3res;
	    local =
		(char *(*)(char *, struct svc_req *)) nfsproc3_fsinfo_3_svc;
	    break;

	case NFSPROC3_PATHCONF:
	    _xdr_argument = (xdrproc_t) xdr_PATHCONF3args;
	    _xdr_result = (xdrproc_t) xdr_PATHCONF3res;
	    local =
		(char *(*)(char *, struct svc_req *)) nfsproc3_pathconf_3_svc;
	    break;

	case NFSPROC3_COMMIT:
	    _xdr_argument = (xdrproc_t) xdr_COMMIT3args;
	    _xdr_result = (xdrproc_t) xdr_COMMIT3res;
	    local =
		(char *(*)(char *, struct svc_req *)) nfsproc3_commit_3_svc;
	    break;

	default:
	    svcerr_noproc(transp);
	    return;
    }
    memset((char *) &argument, 0, sizeof(argument));
    if (!svc_getargs(transp, (xdrproc_t) _xdr_argument, (caddr_t) & argument)) {
	svcerr_decode(transp);
	return;
    }
    result = (*local) ((char *) &argument, rqstp);
    if (result != NULL &&
	!svc_sendreply(transp, (xdrproc_t) _xdr_result, result)) {
	svcerr_systemerr(transp);
	logmsg(LOG_CRIT, "unable to send RPC reply");
    }
    if (!svc_freeargs
	(transp, (xdrproc_t) _xdr_argument, (caddr_t) & argument)) {
	logmsg(LOG_CRIT, "unable to free XDR arguments");
    }
    return;
}

/*
 * mount protocol dispatcher
 * generated by rpcgen
 */
static void mountprog_3(struct svc_req *rqstp, register SVCXPRT * transp)
{
    union {
	dirpath mountproc_mnt_3_arg;
	dirpath mountproc_umnt_3_arg;
    } argument;
    char *result;
    xdrproc_t _xdr_argument, _xdr_result;
    char *(*local) (char *, struct svc_req *);

    switch (rqstp->rq_proc) {
	case MOUNTPROC_NULL:
	    _xdr_argument = (xdrproc_t) xdr_void;
	    _xdr_result = (xdrproc_t) xdr_void;
	    local =
		(char *(*)(char *, struct svc_req *)) mountproc_null_3_svc;
	    break;

	case MOUNTPROC_MNT:
	    _xdr_argument = (xdrproc_t) xdr_dirpath;
	    _xdr_result = (xdrproc_t) xdr_mountres3;
	    local = (char *(*)(char *, struct svc_req *)) mountproc_mnt_3_svc;
	    break;

	case MOUNTPROC_DUMP:
	    _xdr_argument = (xdrproc_t) xdr_void;
	    _xdr_result = (xdrproc_t) xdr_mountlist;
	    local =
		(char *(*)(char *, struct svc_req *)) mountproc_dump_3_svc;
	    break;

	case MOUNTPROC_UMNT:
	    _xdr_argument = (xdrproc_t) xdr_dirpath;
	    _xdr_result = (xdrproc_t) xdr_void;
	    local =
		(char *(*)(char *, struct svc_req *)) mountproc_umnt_3_svc;
	    break;

	case MOUNTPROC_UMNTALL:
	    _xdr_argument = (xdrproc_t) xdr_void;
	    _xdr_result = (xdrproc_t) xdr_void;
	    local =
		(char *(*)(char *, struct svc_req *)) mountproc_umntall_3_svc;
	    break;

	case MOUNTPROC_EXPORT:
	    _xdr_argument = (xdrproc_t) xdr_void;
	    _xdr_result = (xdrproc_t) xdr_exports;
	    local =
		(char *(*)(char *, struct svc_req *)) mountproc_export_3_svc;
	    break;

	default:
	    svcerr_noproc(transp);
	    return;
    }
    memset((char *) &argument, 0, sizeof(argument));
    if (!svc_getargs(transp, (xdrproc_t) _xdr_argument, (caddr_t) & argument)) {
	svcerr_decode(transp);
	return;
    }
    result = (*local) ((char *) &argument, rqstp);
    if (result != NULL &&
	!svc_sendreply(transp, (xdrproc_t) _xdr_result, result)) {
	svcerr_systemerr(transp);
	logmsg(LOG_CRIT, "unable to send RPC reply");
    }
    if (!svc_freeargs
	(transp, (xdrproc_t) _xdr_argument, (caddr_t) & argument)) {
	logmsg(LOG_CRIT, "unable to free XDR arguments");
    }
    return;
}

static void register_nfs_service(SVCXPRT * udptransp, SVCXPRT * tcptransp)
{
    if (opt_portmapper) {
	pmap_unset(NFS3_PROGRAM, NFS_V3);
    }

    if (udptransp != NULL) {
	/* Register NFS service for UDP */
	if (!svc_register
	    (udptransp, NFS3_PROGRAM, NFS_V3, nfs3_program_3,
	     opt_portmapper ? IPPROTO_UDP : 0)) {
	    fprintf(stderr, "%s\n",
		    "unable to register (NFS3_PROGRAM, NFS_V3, udp).");
	    daemon_exit(0);
	}
    }

    if (tcptransp != NULL) {
	/* Register NFS service for TCP */
	if (!svc_register
	    (tcptransp, NFS3_PROGRAM, NFS_V3, nfs3_program_3,
	     opt_portmapper ? IPPROTO_TCP : 0)) {
	    fprintf(stderr, "%s\n",
		    "unable to register (NFS3_PROGRAM, NFS_V3, tcp).");
	    daemon_exit(0);
	}
    }
}

static void register_mount_service(SVCXPRT * udptransp, SVCXPRT * tcptransp)
{
    if (opt_portmapper) {
	pmap_unset(MOUNTPROG, MOUNTVERS1);
	pmap_unset(MOUNTPROG, MOUNTVERS3);
    }

    if (udptransp != NULL) {
	/* Register MOUNT service (v1) for UDP */
	if (!svc_register
	    (udptransp, MOUNTPROG, MOUNTVERS1, mountprog_3,
	     opt_portmapper ? IPPROTO_UDP : 0)) {
	    fprintf(stderr, "%s\n",
		    "unable to register (MOUNTPROG, MOUNTVERS1, udp).");
	    daemon_exit(0);
	}

	/* Register MOUNT service (v3) for UDP */
	if (!svc_register
	    (udptransp, MOUNTPROG, MOUNTVERS3, mountprog_3,
	     opt_portmapper ? IPPROTO_UDP : 0)) {
	    fprintf(stderr, "%s\n",
		    "unable to register (MOUNTPROG, MOUNTVERS3, udp).");
	    daemon_exit(0);
	}
    }

    if (tcptransp != NULL) {
	/* Register MOUNT service (v1) for TCP */
	if (!svc_register
	    (tcptransp, MOUNTPROG, MOUNTVERS1, mountprog_3,
	     opt_portmapper ? IPPROTO_TCP : 0)) {
	    fprintf(stderr, "%s\n",
		    "unable to register (MOUNTPROG, MOUNTVERS1, tcp).");
	    daemon_exit(0);
	}

	/* Register MOUNT service (v3) for TCP */
	if (!svc_register
	    (tcptransp, MOUNTPROG, MOUNTVERS3, mountprog_3,
	     opt_portmapper ? IPPROTO_TCP : 0)) {
	    fprintf(stderr, "%s\n",
		    "unable to register (MOUNTPROG, MOUNTVERS3, tcp).");
	    daemon_exit(0);
	}
    }
}

static SVCXPRT *create_udp_transport(unsigned int port)
{
    SVCXPRT *transp = NULL;
    struct sockaddr_in sin;
    int sock;
    const int on = 1;

    if (port == 0)
	sock = RPC_ANYSOCK;
    else {
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = opt_bind_addr.s_addr;
	sock = socket(PF_INET, SOCK_DGRAM, 0);
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on));
	if (bind(sock, (struct sockaddr *) &sin, sizeof(struct sockaddr))) {
	    perror("bind");
	    fprintf(stderr, "Couldn't bind to udp port %d\n", port);
	    exit(1);
	}
    }

    transp = svcudp_bufcreate(sock, NFS_MAX_UDP_PACKET, NFS_MAX_UDP_PACKET);

    if (transp == NULL) {
	fprintf(stderr, "%s\n", "cannot create udp service.");
	daemon_exit(0);
    }

    return transp;
}

static SVCXPRT *create_tcp_transport(unsigned int port)
{
    SVCXPRT *transp = NULL;
    struct sockaddr_in sin;
    int sock;
    const int on = 1;

    if (port == 0)
	sock = RPC_ANYSOCK;
    else {
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = opt_bind_addr.s_addr;
	sock = socket(PF_INET, SOCK_STREAM, 0);
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on));
	if (bind(sock, (struct sockaddr *) &sin, sizeof(struct sockaddr))) {
	    perror("bind");
	    fprintf(stderr, "Couldn't bind to tcp port %d\n", port);
	    exit(1);
	}
    }

    transp = svctcp_create(sock, 0, 0);

    if (transp == NULL) {
	fprintf(stderr, "%s\n", "cannot create tcp service.");
	daemon_exit(0);
    }

    return transp;
}

/* Run RPC service. This is our own implementation of svc_run(), which
   allows us to handle other events as well. */
static void unfs3_svc_run()
{
    fd_set readfds;
    struct timeval tv;

    for (;;) {
	fd_cache_close_inactive();
	readfds = svc_fdset;
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	/* Note: On Windows, it's not possible to call select with all sets
	   empty; to use it as a sleep function. In our case, however,
	   readfds should never be empty, since we always have our listen
	   socket. Well, at least hope that our Windows RPC library works
	   like that. oncrpc-ms does. */
	switch (select(FD_SETSIZE, &readfds, NULL, NULL, &tv)) {
	    case -1:
		if (errno == EINTR) {
		    continue;
		}
		perror("unfs3_svc_run: select failed");
		return;
	    case 0:
		/* timeout */
		continue;
	    default:
		svc_getreqset(&readfds);
	}
    }
}

/*
 * Generate write verifier based on PID and current time
 */
void regenerate_write_verifier(void)
{
    *(wverf + 0) = (uint32) getpid();
    *(wverf + 0) ^= rand();
    *(wverf + 4) = (uint32) time(NULL);
}

/*
 * Change readdir cookie value
 */
void change_readdir_cookie(void)
{
    rcookie = rcookie >> 32;
    ++rcookie;
    rcookie = rcookie << 32;
}

/*
 * NFSD main function
 * originally generated by rpcgen
 * forking, logging, options, and signal handler stuff added
 */
int main(int argc, char **argv)
{
    register SVCXPRT *tcptransp = NULL, *udptransp = NULL;
    pid_t pid = 0;

#ifndef WIN32
    struct sigaction act;
    sigset_t actset;
#endif				       /* WIN32 */
    int res;

    opt_bind_addr.s_addr = INADDR_ANY;

    parse_options(argc, argv);
    if (optind < argc) {
	fprintf(stderr, "Error: extra arguments on command line\n");
	exit(1);
    }

    /* init write verifier */
    regenerate_write_verifier();

    res = backend_init();
    if (res == -1) {
	fprintf(stderr, "backend initialization failed\n");
	daemon_exit(0);
    }

    /* config test mode */
    if (opt_testconfig) {
	res = exports_parse();
	if (res) {
	    exit(0);
	} else {
	    fprintf(stderr, "Parse error in `%s'\n", opt_exports);
	    exit(1);
	}
    }

    if (opt_detach) {
	/* prepare syslog access */
	openlog("unfsd", LOG_CONS | LOG_PID, LOG_DAEMON);
    } else {
	/* flush stdout after each newline */
	setvbuf(stdout, NULL, _IOLBF, 0);
    }

    /* NFS transports */
    if (!opt_tcponly)
	udptransp = create_udp_transport(opt_nfs_port);
    tcptransp = create_tcp_transport(opt_nfs_port);

    register_nfs_service(udptransp, tcptransp);

    /* MOUNT transports. If ports are equal, then the MOUNT service can reuse 
       the NFS transports. */
    if (opt_mount_port != opt_nfs_port) {
	if (!opt_tcponly)
	    udptransp = create_udp_transport(opt_mount_port);
	tcptransp = create_tcp_transport(opt_mount_port);
    }

    register_mount_service(udptransp, tcptransp);

#ifndef WIN32
    if (opt_detach) {
	pid = fork();
	if (pid == -1) {
	    fprintf(stderr, "could not fork into background\n");
	    daemon_exit(0);
	}
    }
#endif				       /* WIN32 */

    if (!opt_detach || pid == 0) {
#ifndef WIN32
	sigemptyset(&actset);
	act.sa_handler = daemon_exit;
	act.sa_mask = actset;
	act.sa_flags = 0;
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGQUIT, &act, NULL);
	sigaction(SIGSEGV, &act, NULL);
	sigaction(SIGUSR1, &act, NULL);

	act.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &act, NULL);
	sigaction(SIGUSR2, &act, NULL);
	sigaction(SIGALRM, &act, NULL);

	/* don't make directory we started in busy */
	chdir("/");

	/* detach from terminal */
	if (opt_detach) {
	    setsid();
	    fclose(stdin);
	    fclose(stdout);
	    fclose(stderr);
	}
#endif				       /* WIN32 */

	/* no umask to not screw up create modes */
	umask(0);

	/* create pid file if wanted */
	create_pid_file();

	/* initialize internal stuff */
	fh_cache_init();
	fd_cache_init();
	get_squash_ids();
	exports_parse();

	unfs3_svc_run();
	exit(1);
	/* NOTREACHED */
    }

    return 0;
}
