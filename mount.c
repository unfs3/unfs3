/*
 * UNFS3 mount protocol procedures
 * (C) 2004, Pascal Schmidt <der.eremit@email.de>
 * see file LICENSE for license details
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <rpc/rpc.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>           /* gettimeofday */
#include <sys/times.h>          /* times */
#include <fcntl.h>

#include "nfs.h"
#include "mount.h"
#include "daemon.h"
#include "fh.h"
#include "fh_cache.h"
#include "fd_cache.h"
#include "Config/exports.h"
#include "md5.h"

#ifndef PATH_MAX
# define PATH_MAX	4096
#endif

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
static void
add_mount(const char *path, struct svc_req *rqstp)
{
    mountlist new;
    mountlist iter;
    char *host;

    new = malloc(sizeof(struct mountbody));
    if (!new)
        return;

    host = inet_ntoa(get_remote(rqstp));
    new->ml_hostname = malloc(strlen(host) + 1);
    new->ml_directory = malloc(strlen(path) + 1);

    if (!new->ml_hostname || !new->ml_directory) {
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
    }
    else
        mount_list = new;

    mount_cnt++;
}

/*
 * remove entries from mount list
 */
static void
remove_mount(const char *path, struct svc_req *rqstp)
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
        }
        else {
            prev = iter;
            iter = iter->ml_next;
        }
    }
}


static void
gen_nonce(char *nonce)
{
    struct stat st;
    struct tms tmsbuf;
    md5_state_t state;
    uint32 *arr;
    int bytes_read, fd;

    if (((fd = open("/dev/urandom", O_RDONLY)) != -1)
        || ((fd = open("/dev/random", O_RDONLY)) != -1)) {
        bytes_read = read(fd, nonce, 32);
        close(fd);
        if (bytes_read == 32)
            return;
    }

    /* No /dev/random; do it by hand */
    arr = (uint32 *) nonce;
    stat("/tmp", &st);
    arr[0] = st.st_mtime;
    arr[1] = st.st_atime;
    arr[2] = st.st_ctime;
    arr[3] = times(&tmsbuf);
    arr[4] = tmsbuf.tms_cutime;
    arr[5] = tmsbuf.tms_cstime;
    gettimeofday((struct timeval *) &arr[6], NULL);

    md5_init(&state);
    md5_append(&state, nonce, 32);
    md5_finish(&state, nonce);
}

static unsigned char
nibble_as_hexchar(unsigned char c)
{
    if (c <= 9)
        return c + '0';

    return c - 10 + 'a';
}

static void
hexify(unsigned char digest[16], unsigned char hexdigest[32])
{
    int i, j;

    for (i = j = 0; i < 16; i++) {
        char c;
        /* The first four bits */
        c = (digest[i] >> 4) & 0xf;
        hexdigest[j++] = nibble_as_hexchar(c);
        /* The next four bits */
        c = (digest[i] & 0xf);
        hexdigest[j++] = nibble_as_hexchar(c);
    }
}

void *
mountproc_null_3_svc(U(void *argp), U(struct svc_req *rqstp))
{
    static void *result = NULL;

    return &result;
}

mountres3 *
mountproc_mnt_3_svc(dirpath * argp, struct svc_req * rqstp)
{
    char buf[PATH_MAX];
    static unfs3_fh_t fh;
    static mountres3 result;
    static int auth = AUTH_UNIX;
    int authenticated = 1;
    /* We need to modify the *argp pointer. Make a copy. */
    char *dpath = *argp;

    /* error out if not version 3 */
    if (rqstp->rq_vers != 3) {
        putmsg(LOG_INFO,
               "%s attempted mount with unsupported protocol version",
               inet_ntoa(get_remote(rqstp)));
        result.fhs_status = MNT3ERR_INVAL;
        return &result;
    }

    if (password[0])
        /* If a password is defined, the user must authenticate */
        authenticated = 0;

    /* Check for "mount commands" */
    if (strncmp(dpath, "@getnonce", sizeof("@getnonce") - 1) == 0) {
        gen_nonce(nonce);
        result.fhs_status = MNT3_OK;
        result.mountres3_u.mountinfo.fhandle.fhandle3_len = 32;
        result.mountres3_u.mountinfo.fhandle.fhandle3_val = nonce;
        result.mountres3_u.mountinfo.auth_flavors.auth_flavors_len = 1;
        result.mountres3_u.mountinfo.auth_flavors.auth_flavors_val = &auth;
        return &result;
    }
    else if (strncmp(dpath, "@password:", sizeof("@password:") - 1) == 0) {
        char pw[PASSWORD_MAXLEN + 1];
        char *slash;

        dpath += sizeof("@password:") - 1;
        strncpy(pw, dpath, PASSWORD_MAXLEN);
        pw[PASSWORD_MAXLEN] = '\0';

        slash = strchr(pw, '/');
        if (slash != NULL)
            *slash = '\0';

        authenticated = !strcmp(password, pw);
        dpath += strlen(pw);
    }
    else if (strncmp(dpath, "@otp:", sizeof("@otp:") - 1) == 0) {
        md5_state_t state;
        char otp[PASSWORD_MAXLEN + 1];
        char *slash;
        unsigned char digest[16];
        unsigned char hexdigest[32];

        dpath += sizeof("@otp:") - 1;
        strncpy(otp, dpath, PASSWORD_MAXLEN);
        otp[PASSWORD_MAXLEN] = '\0';

        slash = strchr(otp, '/');
        if (slash != NULL)
            *slash = '\0';

        /* Calculate the digest, in the same way as the client did */
        md5_init(&state);
        md5_append(&state, nonce, 32);
        md5_append(&state, password, strlen(password));
        md5_finish(&state, digest);
        hexify(digest, hexdigest);

        /* Compare our calculated digest with what the client
           submitted */
        authenticated = !strncmp(hexdigest, otp, 32);

        dpath += strlen(otp);
        gen_nonce(nonce);
    }

    if (!realpath(dpath, buf)) {
        /* the given path does not exist */
        result.fhs_status = MNT3ERR_NOENT;
        return &result;
    }

    if (strlen(buf) + 1 > NFS_MAXPATHLEN) {
        putmsg(LOG_INFO, "%s attempted to mount jumbo path",
               inet_ntoa(get_remote(rqstp)));
        result.fhs_status = MNT3ERR_NAMETOOLONG;
        return &result;
    }

    if (!authenticated || exports_options(buf, rqstp) == -1) {
        /* not exported to this host or at all */
        result.fhs_status = MNT3ERR_ACCES;
        return &result;
    }

    fh = fh_comp(buf, FH_DIR);

    if (!fh_valid(fh)) {
        putmsg(LOG_INFO, "%s attempted to mount non-directory",
               inet_ntoa(get_remote(rqstp)));
        result.fhs_status = MNT3ERR_NOTDIR;
        return &result;
    }

    add_mount(dpath, rqstp);

    result.fhs_status = MNT3_OK;
    result.mountres3_u.mountinfo.fhandle.fhandle3_len = fh_len(&fh);
    result.mountres3_u.mountinfo.fhandle.fhandle3_val = (char *) &fh;
    result.mountres3_u.mountinfo.auth_flavors.auth_flavors_len = 1;
    result.mountres3_u.mountinfo.auth_flavors.auth_flavors_val = &auth;

    return &result;
}

mountlist *
mountproc_dump_3_svc(U(void *argp), U(struct svc_req *rqstp))
{
    return &mount_list;
}

void *
mountproc_umnt_3_svc(dirpath * argp, struct svc_req *rqstp)
{
    /* RPC times out if we use a NULL pointer */
    static void *result = NULL;

    remove_mount(*argp, rqstp);

    /* if no more mounts are active, flush all open file descriptors */
    if (mount_cnt == 0)
        fd_cache_purge();

    return &result;
}

void *
mountproc_umntall_3_svc(U(void *argp), struct svc_req *rqstp)
{
    /* RPC times out if we use a NULL pointer */
    static void *result = NULL;

    remove_mount(NULL, rqstp);

    /* if no more mounts are active, flush all open file descriptors */
    if (mount_cnt == 0)
        fd_cache_purge();

    return &result;
}

exports *
mountproc_export_3_svc(U(void *argp), U(struct svc_req *rqstp))
{
    return &exports_nfslist;
}
