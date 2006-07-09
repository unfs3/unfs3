/*
 * UNFS3 cluster extensions
 * (C) 2003, Pascal Schmidt
 * see file LICENSE for license details
 */

#ifndef UNFS3_CLUSTER_H
#define UNFS3_CLUSTER_H

#ifdef WANT_CLUSTER

#define CLU_TOOLONG		0	/* name got too long   */
#define CLU_SLAVE		1	/* slave file matched  */
#define CLU_MASTER		2	/* master file matched */
#define CLU_IO			3	/* I/O error */

void cluster_lookup(char *path, struct svc_req *rqstp, nfsstat3 *nstat);
void cluster_create(char *path, struct svc_req *rqstp, nfsstat3 *nstat);

#else

#define cluster_lookup(x,y,z)
#define cluster_create(x,y,z)

#endif

#endif
