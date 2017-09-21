#ifndef __RDESKTOP_H__
#define __RDESKTOP_H__

#include <cstdlib>
#include <cstdio>
#include <cstring>
#ifdef _WIN32
#define WINVER 0x0400
#include <windows.h>
#include <winsock.h>
//#include <WinSock2.h>
#include <ctime>
#include <iostream>

#define DIR int
#else
#include <dirent.h>
#include <sys/time.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#else
#include <sys/types.h>
#include <unistd.h>
#endif
#endif
#include <climits>

#define VERSION "0.0.1"

#ifdef WITH_DEBUG
#define DEBUG(args)	printf args;
#else
#define DEBUG(args)
#endif

#ifdef WITH_DEBUG_KBD
#define DEBUG_KBD(args) printf args;
#else
#define DEBUG_KBD(args)
#endif

#ifdef WITH_DEBUG_RDP5
#define DEBUG_RDP5(args) printf args;
#else
#define DEBUG_RDP5(args)
#endif

#ifdef WITH_DEBUG_CLIPBOARD
#define DEBUG_CLIPBOARD(args) printf args;
#else
#define DEBUG_CLIPBOARD(args)
#endif

#ifdef WITH_DEBUG_SOUND
#define DEBUG_SOUND(args) printf args;
#else
#define DEBUG_SOUND(args)
#endif

#ifdef WITH_DEBUG_CHANNEL
#define DEBUG_CHANNEL(args) printf args;
#else
#define DEBUG_CHANNEL(args)
#endif

#ifdef WITH_DEBUG_SCARD
#define DEBUG_SCARD(args) printf args;
#else
#define DEBUG_SCARD(args)
#endif

#define STRNCPY(dst,src,n)	{ strncpy_s(dst,n-1,src,n-1); dst[n-1] = 0; }

#ifndef MIN
#define MIN(x,y)		(((x) < (y)) ? (x) : (y))
#endif

#ifndef MAX
#define MAX(x,y)		(((x) > (y)) ? (x) : (y))
#endif

/* timeval macros */
#ifndef timerisset
#define timerisset(tvp)\
         ((tvp)->tv_sec || (tvp)->tv_usec)
#endif
#ifndef timercmp
#define timercmp(tvp, uvp, cmp)\
        ((tvp)->tv_sec cmp (uvp)->tv_sec ||\
        (tvp)->tv_sec == (uvp)->tv_sec &&\
        (tvp)->tv_usec cmp (uvp)->tv_usec)
#endif
#ifndef timerclear
#define timerclear(tvp)\
        ((tvp)->tv_sec = (tvp)->tv_usec = 0)
#endif

/* If configure does not define the endianess, try
   to find it out */
#if !defined(L_ENDIAN) && !defined(B_ENDIAN)
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define L_ENDIAN
#elif __BYTE_ORDER == __BIG_ENDIAN
#define B_ENDIAN
#else
#error Unknown endianness. Edit rdesktop.h.
#endif
#endif /* B_ENDIAN, L_ENDIAN from configure */

/* No need for alignment on x86 and amd64 */
#if !defined(NEED_ALIGN)
#if !(defined(__x86__) || defined(__x86_64__) || \
      defined(__AMD64__) || defined(_M_IX86) || \
      defined(__i386__))
#define NEED_ALIGN
#endif
#endif

#include "parse.h"
#include "constants.h"
#include "types.h"

#ifndef MAKE_PROTO
#include "proto.h"
#endif

typedef unsigned long dword;

#define PRINT_DEBUG 1

#endif
