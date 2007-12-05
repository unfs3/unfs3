/*
 * UNFS3 user and group id handling
 * (C) 2003, Pascal Schmidt
 * see file LICENSE for license details
 */

#ifndef UNFS3_USER_H
#define UNFS3_USER_H

#include "backend.h"

int get_uid(struct svc_req *req);

int mangle_uid(int id);
int mangle_gid(int id);

int is_owner(int owner, struct svc_req *req);
int has_group(int group, struct svc_req *req);

void get_squash_ids(void);

void switch_to_root();
void switch_user(struct svc_req *req);

void read_executable(struct svc_req *req, backend_statstruct buf);
void read_by_owner(struct svc_req *req, backend_statstruct buf);
void write_by_owner(struct svc_req *req, backend_statstruct buf);

#endif
