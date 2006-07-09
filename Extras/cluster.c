
/*
 * UNFS3 cluster support
 * (C) 2004, Pascal Schmidt
 * see file LICENSE for license details
 */

#include "../config.h"

#ifdef WANT_CLUSTER

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <rpc/rpc.h>
#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../nfs.h"
#include "../daemon.h"
#include "../backend.h"
#include "cluster.h"

/* array of dirents prefixed with master file name */
static char **cluster_dirents = NULL;

/* number of dirents in above array */
static int cluster_count = -1;

/*
 * check whether given pathname is in clustering path
 */
int want_cluster(const char *path)
{
    char buf[NFS_MAXPATHLEN];
    char *last, *next;

    /* if path is too long, play it safe */
    if (strlen(opt_cluster_path) + 1 > NFS_MAXPATHLEN)
	return TRUE;

    strcpy(buf, opt_cluster_path);
    last = buf;

    /* iterate over colon-seperated list */
    do {
	next = strchr(last, ':');
	if (next)
	    *next = 0;

	if (strstr(path, last) == path)
	    return TRUE;

	if (next) {
	    last = next + 1;
	    if (strlen(last) == 0)
		last = NULL;
	} else {
	    last = NULL;
	}
    } while (last);

    return FALSE;
}

/*
 * get name of remote machine
 */
static char *get_host(struct in_addr remote)
{
    static char buf[NFS_MAXPATHLEN];
    struct hostent *entry;
    char *dot;

    entry = gethostbyaddr((char *) &remote, sizeof(struct in_addr), AF_INET);

    if (entry) {
	strcpy(buf, entry->h_name);

	/* have the name string end at the first dot */
	dot = strchr(buf, '.');
	if (dot)
	    *dot = 0;

	return buf;
    }

    return NULL;
}

/*
 * check whether name is already host tagged name
 */
int is_host(const char *name)
{
    return (int) (strstr(name, "$$HOST=") && name[strlen(name) - 1] == '$' &&
		  name[strlen(name) - 2] == '$');
}

/*
 * check whether a hostname matches a dirent
 */
char *match_host(const char *hname, const char *entry)
{
    char buf[NFS_MAXPATHLEN];
    static char *part;

    /* check for presence of hostname tag */
    if (!is_host(entry))
	return NULL;

    part = strstr(entry, "$$HOST=");

    /* copy hostname part of host tag */
    memcpy(buf, part + 7, strlen(part) - 8);
    buf[strlen(part) - 9] = 0;

    /* exact match? */
    if (strcmp(buf, hname) == 0)
	return part;

    /* wildcard pattern? */
    if (buf[strlen(buf) - 1] != '*')
	return NULL;

    /* if wildcard, check for matching prefix */
    buf[strlen(buf) - 1] = 0;
    if (strstr(hname, buf) == hname)
	return part;

    return NULL;
}

/*
 * better dirname providing internal buffer
 */
char *cluster_dirname(const char *path)
{
    static char buf[NFS_MAXPATHLEN];

    strcpy(buf, path);
    return dirname(buf);
}

/*
 * better basename providing internal buffer
 */
char *cluster_basename(const char *path)
{
    static char buf[NFS_MAXPATHLEN];

    strcpy(buf, path);
    return basename(buf);
}

/*
 * free dirent array
 */
void cluster_freedir(void)
{
    /* only if it was really allocated before */
    if (cluster_dirents) {
	while (cluster_count--)
	    free(cluster_dirents[cluster_count]);
	free(cluster_dirents);
	cluster_dirents = NULL;
    }
}

/*
 * compare function for qsort'ing the scandir list
 */
int compar(const void *x, const void *y)
{
    return strcmp(*(const char **) x, *(const char **) y);
}

/*
 * reset euid/egid to specific values
 */
static void reset_ids(uid_t euid, gid_t egid)
{
    if (backend_setegid(egid) || backend_seteuid(euid)) {
	logmsg(LOG_EMERG, "euid/egid switching failed, aborting");
	daemon_exit(CRISIS);
    }
}

/*
 * scan directory for filenames beginning with master name as prefix
 */
void cluster_scandir(const char *path)
{
    char prefix[NFS_MAXPATHLEN];
    DIR *scan;
    struct dirent *entry;
    char **new, *name;
    uid_t euid;
    gid_t egid;

    strcpy(prefix, cluster_basename(path));

    /* 
     * need to read directory as root, temporarily switch back
     */
    euid = backend_geteuid();
    egid = backend_getegid();
    backend_setegid(0);
    backend_seteuid(0);

    scan = backend_opendir(cluster_dirname(path));
    if (!scan) {
	cluster_count = -1;
	reset_ids(euid, egid);
	return;
    }

    cluster_count = 0;
    while ((entry = backend_readdir(scan))) {
	if (strstr(entry->d_name, prefix) != entry->d_name &&
	    strcmp(entry->d_name, "$$CREATE=IP$$") != 0 &&
	    strcmp(entry->d_name, "$$CREATE=CLIENT$$") != 0 &&
	    strcmp(entry->d_name, "$$ALWAYS=IP$$") != 0 &&
	    strcmp(entry->d_name, "$$ALWAYS=CLIENT$$") != 0)
	    continue;

	name = malloc(strlen(entry->d_name) + 1);
	new = realloc(cluster_dirents, (cluster_count + 1) * sizeof(char *));
	if (!new || !name) {
	    cluster_freedir();
	    cluster_count = -1;
	    free(new);
	    free(name);
	    backend_closedir(scan);
	    reset_ids(euid, egid);
	    return;
	}

	strcpy(name, entry->d_name);
	cluster_dirents = new;
	cluster_dirents[cluster_count] = name;
	cluster_count++;
    }

    backend_closedir(scan);
    reset_ids(euid, egid);

    /* list needs to be sorted for cluster_lookup_lowlevel to work */
    qsort(cluster_dirents, cluster_count, sizeof(char *), compar);
}

/*
 * check whether master name + suffix matches with a string
 */
int match_suffix(const char *master, const char *suffix, const char *entry)
{
    char obj[NFS_MAXPATHLEN];

    sprintf(obj, "%s%s", master, suffix);

    if (strcmp(entry, obj) == 0)
	return CLU_SLAVE;
    else
	return FALSE;
}

/*
 * create string version of a netmask
 * buf:    where to put string
 * remote: full IP address of remote machine
 * n:      number of dots to keep
 */
void cluster_netmask(char *buf, const char *remote, int n)
{
    int i;

    sprintf(buf, "$$IP=%s", remote);

    /* skip to desired dot position */
    for (i = 0; i < n; i++)
	buf = strchr(buf, '.') + 1;

    *buf-- = 0;

    /* append trailer of netmask string */
    switch (n) {
	case 3:
	    strcat(buf, "0_24$$");
	    break;
	case 2:
	    strcat(buf, "0.0_16$$");
	    break;
	case 1:
	    strcat(buf, "0.0.0_8$$");
	    break;
    }
}

/*
 * look up cluster name, defaulting to master name if no slave name found
 */
int cluster_lookup_lowlevel(char *path, struct svc_req *rqstp)
{
    struct in_addr raddr;
    char *remote, *hname, *master, *entry, *match;
    char buf[NFS_MAXPATHLEN];
    int i, res = CLU_MASTER;

    cluster_freedir();
    cluster_scandir(path);

    if (cluster_count == -1)
	return CLU_IO;
    else if (cluster_count == 0)
	return CLU_MASTER;

    raddr = get_remote(rqstp);	       /* remote IP address */
    master = cluster_basename(path);   /* master file name */
    remote = inet_ntoa(raddr);	       /* remote IP address string */
    hname = get_host(raddr);	       /* remote hostname */

    /* 
     * traversal in reverse alphanumerical order, so that 
     *  IP is encountered before HOST, HOST before CLIENT,
     *  CLIENT before ALWAYS, and also subnets are encountered
     *  in the right order
     */
    i = cluster_count;
    while (i--) {
	entry = cluster_dirents[i];

	/* match specific IP address */
	sprintf(buf, "$$IP=%s$$", remote);
	if ((res = match_suffix(master, buf, entry)))
	    break;

	/* always match IP file */
	if ((res = match_suffix(master, "$$ALWAYS=IP$$", entry)))
	    break;
	if (strcmp("$$ALWAYS=IP$$", entry) == 0) {
	    res = CLU_SLAVE;
	    break;
	}

	/* match all clients */
	strcpy(buf, "$$CLIENT$$");
	if ((res = match_suffix(master, buf, entry)))
	    break;

	/* always match CLIENT file */
	if ((res = match_suffix(master, "$$ALWAYS=CLIENT$$", entry)))
	    break;
	if (strcmp("$$ALWAYS=CLIENT$$", entry) == 0) {
	    res = CLU_SLAVE;
	    break;
	}

	/* match 24 bit network address */
	cluster_netmask(buf, remote, 3);
	if ((res = match_suffix(master, buf, entry)))
	    break;

	/* match 16 bit network address */
	cluster_netmask(buf, remote, 2);
	if ((res = match_suffix(master, buf, entry)))
	    break;

	/* match 8 bit network address */
	cluster_netmask(buf, remote, 1);
	if ((res = match_suffix(master, buf, entry)))
	    break;

	/* match hostname pattern */
	if (!is_host(master)) {
	    match = match_host(hname, entry);
	    if (match) {
		res = CLU_SLAVE;
		strcpy(buf, match);
		break;
	    }
	}
    }

    /* append suffix if possible */
    if (res == CLU_SLAVE) {
	if (strlen(path) + strlen(buf) + 1 < NFS_MAXPATHLEN)
	    strcat(path, buf);
	else
	    res = CLU_TOOLONG;
    } else {
	/* res will be 0 after above loop */
	res = CLU_MASTER;
    }

    /* 
     * dirent array not freed here since cluster_create may need
     * to look at it afterwards
     */

    return res;
}

/*
 * substitute slave filename if possible
 */
void cluster_lookup(char *path, struct svc_req *rqstp, nfsstat3 * nstat)
{
    int res;

    if (!opt_cluster)
	return;

    if (!path)
	return;

    if (*nstat != NFS3_OK)
	return;

    if (!want_cluster(path))
	return;

    res = strlen(path);
    if (strstr(path, "$$$$") == path + res - 4) {
	*(path + res - 4) = 0;
	return;
    }

    res = cluster_lookup_lowlevel(path, rqstp);
    if (res == CLU_TOOLONG)
	*nstat = NFS3ERR_NAMETOOLONG;
    else if (res == CLU_IO)
	*nstat = NFS3ERR_IO;
}

/*
 * substitute slave filename if possible, for create operations
 */
void cluster_create(char *path, struct svc_req *rqstp, nfsstat3 * nstat)
{
    int i, res;
    char buf[NFS_MAXPATHLEN];
    char *master, *entry;

    if (!opt_cluster)
	return;

    if (*nstat != NFS3_OK)
	return;

    if (!want_cluster(path))
	return;

    res = cluster_lookup_lowlevel(path, rqstp);

    if (res == CLU_TOOLONG) {
	*nstat = NFS3ERR_NAMETOOLONG;
	return;
    } else if (res == CLU_IO) {
	*nstat = NFS3ERR_IO;
	return;
    } else if (res == CLU_SLAVE)
	return;

    master = cluster_basename(path);

    /* look for create tag */
    i = cluster_count;
    while (i--) {
	entry = cluster_dirents[i];

	/* always create IP file */
	sprintf(buf, "$$IP=%s$$", inet_ntoa(get_remote(rqstp)));
	if ((res = match_suffix(master, "$$CREATE=IP$$", entry)) ||
	    (res = match_suffix(master, "$$ALWAYS=IP$$", entry)))
	    break;
	if ((strcmp("$$CREATE=IP$$", entry) == 0) ||
	    (strcmp("$$ALWAYS=IP$$", entry) == 0)) {
	    res = CLU_SLAVE;
	    break;
	}

	/* always create CLIENT file */
	sprintf(buf, "$$CLIENT$$");
	if ((res = match_suffix(master, "$$CREATE=CLIENT$$", entry)) ||
	    (res = match_suffix(master, "$$ALWAYS=CLIENT$$", entry)))
	    break;
	if ((strcmp("$$CREATE=CLIENT$$", entry) == 0) ||
	    (strcmp("$$ALWAYS=CLIENT$$", entry) == 0)) {
	    res = CLU_SLAVE;
	    break;
	}
    }

    if (res != CLU_SLAVE)
	return;

    /* append suffix if possible */
    if (strlen(path) + strlen(buf) + 1 < NFS_MAXPATHLEN)
	strcat(path, buf);
    else
	*nstat = NFS3ERR_NAMETOOLONG;
}

#endif
