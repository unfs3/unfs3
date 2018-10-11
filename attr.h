/*
 * UNFS3 attribute handling
 * (C) 2004, Pascal Schmidt
 * see file LICENSE for license details
 */

#ifndef NFS_ATTR_H
#define NFS_ATTR_H

nfsstat3 is_reg(void);

mode_t type_to_mode(ftype3 ftype);

struct timespec nfstime3_to_timespec(const nfstime3 nt);
nfstime3 timespec_to_nfstime3(const struct timespec ts);

nfstime3 get_stat_atime(const backend_statstruct statbuf);
nfstime3 get_stat_mtime(const backend_statstruct statbuf);
nfstime3 get_stat_ctime(const backend_statstruct statbuf);

post_op_attr get_post_attr(const char *path, nfs_fh3 fh, struct svc_req *req);
post_op_attr get_post_stat(const char *path, struct svc_req *req);
post_op_attr get_post_cached(struct svc_req *req);
post_op_attr get_post_buf(backend_statstruct buf, struct svc_req *req);
pre_op_attr  get_pre_cached(void);

nfsstat3 set_attr(const char *path, nfs_fh3 fh, sattr3 sattr);

mode_t create_mode(sattr3 sattr);

nfsstat3 atomic_attr(sattr3 sattr);

#endif
