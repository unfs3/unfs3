/*
 * UNFS3 mount protocol definitions
 * Generated by rpcgen
 */

#ifndef _MOUNT_H_RPCGEN
#define _MOUNT_H_RPCGEN

#define MNTPATHLEN 1024
#define MNTNAMLEN 255
#define FHSIZE3 64

typedef struct {
        u_int fhandle3_len;
        char *fhandle3_val;
} fhandle3;

enum mountstat3 {
        MNT3_OK = 0,
        MNT3ERR_PERM = 1,
        MNT3ERR_NOENT = 2,
        MNT3ERR_IO = 5,
        MNT3ERR_ACCES = 13,
        MNT3ERR_NOTDIR = 20,
        MNT3ERR_INVAL = 22,
        MNT3ERR_NAMETOOLONG = 63,
        MNT3ERR_NOTSUPP = 10004,
        MNT3ERR_SERVERFAULT = 10006
};
typedef enum mountstat3 mountstat3;

struct mountres3_ok {
        fhandle3 fhandle;
        struct {
                u_int auth_flavors_len;
                int *auth_flavors_val;
        } auth_flavors;
};
typedef struct mountres3_ok mountres3_ok;

struct mountres3 {
        mountstat3 fhs_status;
        union {
                mountres3_ok mountinfo;
        } mountres3_u;
};
typedef struct mountres3 mountres3;

typedef char *dirpath;

typedef char *name;

typedef struct mountbody *mountlist;

struct mountbody {
        name ml_hostname;
        dirpath ml_directory;
        mountlist ml_next;
};
typedef struct mountbody mountbody;

typedef struct groupnode *groups;

struct groupnode {
        name gr_name;
        groups gr_next;
};
typedef struct groupnode groupnode;

typedef struct exportnode *exports;

struct exportnode {
        dirpath ex_dir;
        groups ex_groups;
        exports ex_next;
};
typedef struct exportnode exportnode;

#define MOUNTPROG 100005
#define MOUNTVERS1 1
#define MOUNTVERS3 3

#define MOUNTPROC_NULL 0
extern  void * mountproc_null_3_svc(void *, struct svc_req *);
#define MOUNTPROC_MNT 1
extern  mountres3 * mountproc_mnt_3_svc(dirpath *, struct svc_req *);
#define MOUNTPROC_DUMP 2
extern  mountlist * mountproc_dump_3_svc(void *, struct svc_req *);
#define MOUNTPROC_UMNT 3
extern  void * mountproc_umnt_3_svc(dirpath *, struct svc_req *);
#define MOUNTPROC_UMNTALL 4
extern  void * mountproc_umntall_3_svc(void *, struct svc_req *);
#define MOUNTPROC_EXPORT 5
extern  exports * mountproc_export_3_svc(void *, struct svc_req *);
extern int mountprog_3_freeresult (SVCXPRT *, xdrproc_t, caddr_t);

#endif /* !_MOUNT_H_RPCGEN */
