/*
 * UNFS3 low-level filesystem calls
 * (C) 2004, Pascal Schmidt
 * see file LICENSE for license details
 */

#ifndef UNFS3_BACKEND_H
#define UNFS3_BACKEND_H

#ifdef WIN32
#include "backend_win32.h"
#else
#include "backend_unix.h"
#endif /* WIN32 */

#endif
