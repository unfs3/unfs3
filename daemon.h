/*
 * UNFS3 server framework
 * (C) 2004, Pascal Schmidt <der.eremit@email.de>
 * see file LICENSE for license details
 */

#ifndef UNFS3_DAEMON_H
#define UNFS3_DAEMON_H

/* exit status for internal errors */
#define CRISIS	99

/* error handling */
void daemon_exit(int);
void putmsg(int, const char *, ...);

/* remote address */
struct in_addr get_remote(struct svc_req *);

/* write verifier */
extern writeverf3 wverf;

/* options */
extern int	opt_expire_writers;
extern int	opt_detach;
extern char	*opt_exports;
extern int	opt_cluster;
extern char	*opt_cluster_path;
extern int opt_singleuser;

#endif
