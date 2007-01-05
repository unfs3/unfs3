
/*
 * UNFS3 mount protocol procedures
 * (C) 2004, Pascal Schmidt
 * see file LICENSE for license details
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <rpc/rpc.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <syslog.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif				       /* WIN32 */
#include <fcntl.h>

#include "nfs.h"
#include "mount.h"
#include "daemon.h"
#include "fh.h"
#include "fh_cache.h"
#include "fd_cache.h"
#include "Config/exports.h"
#include "password.h"
#include "backend.h"

#ifndef PATH_MAX
# define PATH_MAX	4096
#endif

#define IS_SECURE(port) ((port) < 1024)

/*
 * number of active mounts
 *
 * only a guess since clients can crash and/or not sent UMNT calls
 */
static int mount_cnt = 0;

/* list of currently mounted directories */
static mountlist mount_list = NULL;

static char nonce[32] = "";

/*
 * add entry to mount list
 */
static void add_mount(const char *path, struct svc_req *rqstp)
{
    mountlist new;
    mountlist iter;
    char *host;

    new = malloc(sizeof(struct mountbody));
    if (!new) {
	logmsg(LOG_CRIT, "add_mount: Unable to allocate memory");
	return;
    }

    host = inet_ntoa(get_remote(rqstp));
    new->ml_hostname = malloc(strlen(host) + 1);
    if (!new->ml_hostname) {
	logmsg(LOG_CRIT, "add_mount: Unable to allocate memory");
	free(new);
	return;
    }

    new->ml_directory = malloc(strlen(path) + 1);
    if (!new->ml_directory) {
	logmsg(LOG_CRIT, "add_mount: Unable to allocate memory");
	free(new->ml_hostname);
	free(new);
	return;
    }

    /* initialize the new entry */
    new->ml_next = NULL;
    strcpy(new->ml_hostname, host);
    strcpy(new->ml_directory, path);

    iter = mount_list;
    if (iter) {
	while (iter->ml_next)
	    iter = iter->ml_next;
	iter->ml_next = new;
    } else
	mount_list = new;

    mount_cnt++;
}

/*
 * remove entries from mount list
 */
static void remove_mount(const char *path, struct svc_req *rqstp)
{
    mountlist iter, next, prev = NULL;
    char *host;

    host = inet_ntoa(get_remote(rqstp));

    iter = mount_list;
    while (iter) {
	if (strcmp(iter->ml_hostname, host) == 0 &&
	    (!path || strcmp(iter->ml_directory, path) == 0)) {
	    if (prev)
		prev->ml_next = iter->ml_next;
	    else
		mount_list = iter->ml_next;

	    next = iter->ml_next;

	    free(iter->ml_hostname);
	    free(iter->ml_directory);
	    free(iter);

	    iter = next;

	    /* adjust mount count */
	    if (mount_cnt > 0)
		mount_cnt--;
	} else {
	    prev = iter;
	    iter = iter->ml_next;
	}
    }
}

void *mountproc_null_3_svc(U(void *argp), U(struct svc_req *rqstp))
{
    static void *result = NULL;

    return &result;
}

mountres3 *mountproc_mnt_3_svc(dirpath * argp, struct svc_req * rqstp)
{
    char buf[PATH_MAX];
    static unfs3_fh_t fh;
    static mountres3 result;
    static int auth = AUTH_UNIX;
    int authenticated = 0;
    char *password;

    /* We need to modify the *argp pointer. Make a copy. */
    char *dpath = *argp;

    /* error out if not version 3 */
    if (rqstp->rq_vers != 3) {
	logmsg(LOG_INFO,
	       "%s attempted mount with unsupported protocol version",
	       inet_ntoa(get_remote(rqstp)));
	result.fhs_status = MNT3ERR_INVAL;
	return &result;
    }

    /* Check for "mount commands" */
    if (strncmp(dpath, "@getnonce", sizeof("@getnonce") - 1) == 0) {
	if (backend_gen_nonce(nonce) < 0) {
	    result.fhs_status = MNT3ERR_IO;
	} else {
	    result.fhs_status = MNT3_OK;
	    result.mountres3_u.mountinfo.fhandle.fhandle3_len = 32;
	    result.mountres3_u.mountinfo.fhandle.fhandle3_val = nonce;
	    result.mountres3_u.mountinfo.auth_flavors.auth_flavors_len = 1;
	    result.mountres3_u.mountinfo.auth_flavors.auth_flavors_val =
		&auth;
	}
	return &result;
    } else if (strncmp(dpath, "@password:", sizeof("@password:") - 1) == 0) {
	char pw[PASSWORD_MAXLEN + 1];

	mnt_cmd_argument(&dpath, "@password:", pw, PASSWORD_MAXLEN);
	if (exports_options(dpath, rqstp, &password, NULL) != -1) {
	    authenticated = !strcmp(password, pw);
	}
	/* else leave authenticated unchanged */
    } else if (strncmp(dpath, "@otp:", sizeof("@otp:") - 1) == 0) {
	/* The otp from the client */
	char otp[PASSWORD_MAXLEN + 1];

	/* Our calculated otp */
	char hexdigest[32];

	mnt_cmd_argument(&dpath, "@otp:", otp, PASSWORD_MAXLEN);
	if (exports_options(dpath, rqstp, &password, NULL) != -1) {
	    otp_digest(nonce, password, hexdigest);

	    /* Compare our calculated digest with what the client submitted */
	    authenticated = !strncmp(hexdigest, otp, 32);

	    /* Change nonce */
	    backend_gen_nonce(nonce);
	}
	/* else leave authenticated unchanged */
    }

    if ((exports_opts & OPT_REMOVABLE) && export_point(dpath)) {
	/* Removable media export point. Do not call realpath; simply copy
	   path */
	strncpy(buf, dpath, PATH_MAX);
    } else if (!backend_realpath(dpath, buf)) {
	/* the given path does not exist */
	result.fhs_status = MNT3ERR_NOENT;
	return &result;
    }

    if (strlen(buf) + 1 > NFS_MAXPATHLEN) {
	logmsg(LOG_INFO, "%s attempted to mount jumbo path",
	       inet_ntoa(get_remote(rqstp)));
	result.fhs_status = MNT3ERR_NAMETOOLONG;
	return &result;
    }

    if ((exports_options(buf, rqstp, &password, NULL) == -1)
	|| (!authenticated && password[0])
	|| (!(exports_opts & OPT_INSECURE) &&
	    !IS_SECURE(ntohs(get_port(rqstp))))
	) {
	/* not exported to this host or at all, or a password defined and not 
	   authenticated */
	result.fhs_status = MNT3ERR_ACCES;
	return &result;
    }

    fh = fh_comp(buf, rqstp, FH_DIR);

    if (!fh_valid(fh)) {
	logmsg(LOG_INFO, "%s attempted to mount non-directory",
	       inet_ntoa(get_remote(rqstp)));
	result.fhs_status = MNT3ERR_NOTDIR;
	return &result;
    }

    add_mount(dpath, rqstp);

    result.fhs_status = MNT3_OK;
    result.mountres3_u.mountinfo.fhandle.fhandle3_len = fh_length(&fh);
    result.mountres3_u.mountinfo.fhandle.fhandle3_val = (char *) &fh;
    result.mountres3_u.mountinfo.auth_flavors.auth_flavors_len = 1;
    result.mountres3_u.mountinfo.auth_flavors.auth_flavors_val = &auth;

    return &result;
}

mountlist *mountproc_dump_3_svc(U(void *argp), U(struct svc_req *rqstp))
{
    return &mount_list;
}

void *mountproc_umnt_3_svc(dirpath * argp, struct svc_req *rqstp)
{
    /* RPC times out if we use a NULL pointer */
    static void *result = NULL;

    remove_mount(*argp, rqstp);

    /* if no more mounts are active, flush all open file descriptors */
    if (mount_cnt == 0)
	fd_cache_purge();

    return &result;
}

void *mountproc_umntall_3_svc(U(void *argp), struct svc_req *rqstp)
{
    /* RPC times out if we use a NULL pointer */
    static void *result = NULL;

    remove_mount(NULL, rqstp);

    /* if no more mounts are active, flush all open file descriptors */
    if (mount_cnt == 0)
	fd_cache_purge();

    return &result;
}

exports *mountproc_export_3_svc(U(void *argp), U(struct svc_req *rqstp))
{
    return &exports_nfslist;
}
