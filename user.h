/*
 * UNFS3 user and group id handling
 * (C) 2003, Pascal Schmidt <der.eremit@email.de>
 * see file LICENSE for license details
 */

#ifndef UNFS3_USER_H
#define UNFS3_USER_H

int get_uid(struct svc_req *req);

int is_owner(int owner, struct svc_req *req);
int has_group(int group, struct svc_req *req);

void get_squash_ids(void);

void switch_user(struct svc_req *req);

void execute_check(struct svc_req *req, struct stat buf);

#endif
