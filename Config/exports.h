/*
 * UNFS3 export controls
 * (C) 2003, Pascal Schmidt <der.eremit@email.de>
 * see file LICENSE for license details
 */

#ifndef UNFS3_EXPORTS_H
#define UNFS3_EXPORTS_H

#define OPT_NO_ROOT_SQUASH	1
#define OPT_ALL_SQUASH		2
#define OPT_RW			4
#define OPT_REMOVABLE		8

#define PASSWORD_MAXLEN   64

extern exports	exports_nfslist;
extern int	exports_opts;

extern unsigned char password[PASSWORD_MAXLEN+1];

void		exports_parse(void);
int		exports_options(const char *path, struct svc_req *rqstp, char **password);
nfsstat3	exports_compat(const char *path, struct svc_req *rqstp);
nfsstat3	exports_rw(void);

#endif
