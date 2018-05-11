#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include "clock_gettime.h"

#ifndef HAVE_CLOCK_GETTIME

/* Compatibility definition of clock_gettime that uses gettimeofday to
   fill out timestamps to microsecond resolution. */

int clock_gettime(int clock, struct timespec *timespec) {
    struct timeval tv;

    if (clock != CLOCK_REALTIME) {
        errno = EINVAL;
        return -1;
    }

    gettimeofday(&tv, NULL);

    timespec->tv_sec = tv.tv_sec;
    timespec->tv_nsec = tv.tv_usec * 1000;

    return 0;
}
#endif /* HAVE_CLOCK_GETTIME */
