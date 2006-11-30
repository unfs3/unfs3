/*
 * UNFS3 server framework
 * (C) 2004, Pascal Schmidt
 * see file LICENSE for license details
 */

#ifndef UNFS3_DAEMON_H
#define UNFS3_DAEMON_H

/* exit status for internal errors */
#define CRISIS	99

/* HP-UX does not have seteuid() and setegid() */
#if HAVE_SETEUID == 0 && HAVE_SETRESUID == 1
#define seteuid(u) setresuid(-1, u, -1)
#endif
#if HAVE_SETEGID == 0 && HAVE_SETRESGID == 1
#define setegid(g) setresgid(-1, g, -1)
#endif

/* error handling */
void daemon_exit(int);
void logmsg(int, const char *, ...);

/* remote address */
struct in_addr get_remote(struct svc_req *);
short get_port(struct svc_req *);

/* write verifier */
extern writeverf3 wverf;

/* options */
extern int	opt_expire_writers;
extern int	opt_detach;
extern char	*opt_exports;
extern int	opt_cluster;
extern char	*opt_cluster_path;
extern int	opt_singleuser;
extern int	opt_brute_force;
extern int	opt_readable_executables;

#endif
