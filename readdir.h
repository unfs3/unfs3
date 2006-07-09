/*
 * UNFS3 readdir routine
 * (C) 2003, Pascal Schmidt
 * see file LICENSE for license details
 */

#ifndef UNFS3_READDIR_H
#define UNFS3_READDIR_H

READDIR3res
read_dir(const char *path, cookie3 cookie, cookieverf3 verf, count3 count);
uint32 directory_hash(const char *path);

#endif
