/*
 * UNFS3 low-level filehandle routines
 * (C) 2004, Pascal Schmidt <der.eremit@email.de>
 * see file LICENSE for license details
 */

#ifndef UNFS3_FH_H
#define UNFS3_FH_H

/* minimum length of complete filehandle */
#define FH_MINLEN 13

/* maximum depth of pathname described by filehandle */
#define FH_MAXLEN 51

typedef struct {
	uint32			dev;
	uint32			ino;
	uint32			gen;
	unsigned char	len;
	unsigned char	inos[FH_MAXLEN];
} unfs3_fh_t __attribute__((packed));

#define FH_ANY 0
#define FH_DIR 1

#define FD_NONE (-1)			/* used for get_gen */

extern int st_cache_valid;		/* stat value is valid */
extern struct stat st_cache;	/* cached stat value */

uint32 get_gen(struct stat obuf, int fd, const char *path);

int nfh_valid(nfs_fh3 fh);
int fh_valid(unfs3_fh_t fh);

unfs3_fh_t fh_comp_raw(const char *path, int need_dir);
u_int fh_len(const unfs3_fh_t *fh);

unfs3_fh_t *fh_extend(nfs_fh3 fh, uint32 dev, uint32 ino, uint32 gen);
post_op_fh3 fh_extend_post(nfs_fh3 fh, uint32 dev, uint32 ino, uint32 gen);
post_op_fh3 fh_extend_type(nfs_fh3 fh, const char *path, unsigned int type);

char *fh_decomp_raw(const unfs3_fh_t *fh);

#endif
