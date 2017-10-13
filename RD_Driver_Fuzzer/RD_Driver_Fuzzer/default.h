#pragma once
#include <stdio.h>

/*
 * typedef
 */
typedef char               int8;
typedef short              int16;
typedef int                int32;
typedef long long          int64;
typedef unsigned char      uint8;
typedef unsigned short     uint16;
typedef unsigned int       uint32;
typedef unsigned long long uint64;

/*
 * Default defined
 */
#define True  1
#define False 0
#define Error -1

#define BUF_MAXSIZE 0x10000

 /*
 * GetLastError() ErrorHandler
 */
void PrintLastError(uint32 lasterror);

/*
* for debugging
*/
void hexdump(unsigned char *p, unsigned int len);
void fhexdump(FILE* fp, unsigned char *p, unsigned int len);
