
/*
 * UNFS3 user and group id handling
 * (C) 2003, Pascal Schmidt <der.eremit@email.de>
 * see file LICENSE for license details
 */

#include "config.h"

#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <rpc/rpc.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include "nfs.h"
#include "mount.h"
#include "daemon.h"
#include "user.h"
#include "Config/exports.h"

/* user and group id we squash to */
static uid_t squash_uid = 65534;
static gid_t squash_gid = 65534;

/* whether we can use seteuid/setegid */
static int can_switch = TRUE;

/*
 * initialize group and user id used for squashing
 */
void get_squash_ids(void)
{
    struct passwd *passwd;

    if (can_switch) {
	passwd = getpwnam("nobody");
	if (passwd) {
	    squash_uid = passwd->pw_uid;
	    squash_gid = passwd->pw_gid;
	} else {
	    squash_uid = 65534;
	    squash_gid = 65534;
	}
    }
}

/*
 * mangle an id
 */
static int mangle(int id, int squash)
{
    if (!can_switch || (exports_opts & OPT_ALL_SQUASH))
	return squash;
    else if (exports_opts & OPT_NO_ROOT_SQUASH)
	return id;
    else if (id == 0)
	return squash;
    else
	return id;
}

/*
 * return user id of a request
 */
int get_uid(struct svc_req *req)
{
    struct authunix_parms *auth = (void *) req->rq_clntcred;

    if (req->rq_cred.oa_flavor == AUTH_UNIX)
	return mangle(auth->aup_uid, squash_uid);
    else
	return squash_uid;	       /* fallback if no uid given */
}

/*
 * return group id of a request
 */
static int get_gid(struct svc_req *req)
{
    struct authunix_parms *auth = (void *) req->rq_clntcred;

    if (req->rq_cred.oa_flavor == AUTH_UNIX)
	return mangle(auth->aup_gid, squash_gid);
    else
	return squash_gid;	       /* fallback if no gid given */
}

/*
 * check whether a request comes from a given user id
 */
int is_owner(int owner, struct svc_req *req)
{
    return (int) (owner == get_uid(req));
}

/*
 * check if a request comes from somebody who has a given group id
 */
int has_group(int group, struct svc_req *req)
{
    struct authunix_parms *auth = (void *) req->rq_clntcred;
    unsigned int i;

    if (req->rq_cred.oa_flavor == AUTH_UNIX) {
	if (mangle(auth->aup_gid, squash_gid) == group)
	    return TRUE;

	/* search groups */
	for (i = 0; i < auth->aup_len; i++)
	    if (mangle(auth->aup_gids[i], squash_gid) == group)
		return TRUE;
    }

    return FALSE;
}

/*
 * switch user and group id to values listed in request
 */
void switch_user(struct svc_req *req)
{
    int uid, gid;

    if (!can_switch)
	return;

    if (getuid() != 0) {
	/* 
	 * have uid/gid functions behave correctly by squashing
	 * all user and group ids to the current values
	 *
	 * otherwise ACCESS would malfunction
	 */
	squash_uid = getuid();
	squash_gid = getgid();

	can_switch = FALSE;
	return;
    }

    setegid(0);
    seteuid(0);
    gid = setegid(get_gid(req));
    uid = seteuid(get_uid(req));

    if (uid == -1 || gid == -1) {
	putmsg(LOG_EMERG, "euid/egid switching failed, aborting");
	daemon_exit(CRISIS);
    }
}

/*
 * re-switch to root for reading executable files
 */
void read_executable(struct svc_req *req, struct stat buf)
{
    int have_exec = 0;

    if (buf.st_mode & S_IXOTH)
	have_exec = 1;
    else if ((buf.st_mode & S_IXUSR) && is_owner(buf.st_uid, req))
	have_exec = 1;
    else if ((buf.st_mode & S_IXGRP) && has_group(buf.st_gid, req))
	have_exec = 1;

    if (have_exec) {
	setegid(0);
	seteuid(0);
    }
}
