/* Fallback definition of clock_gettime */

#ifndef UNFS3_CLOCK_GETTIME_H
#define UNFS3_CLOCK_GETTIME_H

#ifndef HAVE_CLOCK_GETTIME

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 0
#endif /* CLOCK_REALTIME */

struct timespec;

int clock_gettime(int clock, struct timespec *timespec);

#endif /* HAVE_CLOCK_GETTIME */
#endif /* UNFS3_CLOCK_GETTIME_H */
