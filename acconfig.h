
/* for lack of a better place */
#ifdef __GNUC__
#define U(x) x __attribute__ ((unused))
#else
#define U(x) x
#endif

/* needed on Solaris before including rpc/rpc.h */
#define PORTMAP
