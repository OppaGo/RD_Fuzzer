#pragma once
#include "default.h"

/*
* ioctl Code
*/
#define TVMonitor0 CTL_CODE(0x22, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TVMonitor1 CTL_CODE(0x22, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TVMonitor2 CTL_CODE(0x22, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TVMonitor3 CTL_CODE(0x22, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TVMonitor4 CTL_CODE(0x22, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TVMonitor5 CTL_CODE(0x22, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*
* ioctl mask for convert
*/
#define DEVICE_MASK   (0xffff0000)
#define ACCESS_MASK   (0xffffc000 - DEVICE_MASK)
#define FUNCTION_MASK (0xfffffffc - DEVICE_MASK - ACCESS_MASK)
#define METHOD_MASK   (0xffffffff - DEVICE_MASK - ACCESS_MASK - FUNCTION_MASK)

/*
* Convert from ioctl Code to specific values
*/
#define CTL_DEVICE(x) ((x & DEVICE_MASK) >> 16)
#define CTL_ACCESS(x) ((x & ACCESS_MASK) >> 14)
#define CTL_FUNCTION(x) ((x & FUNCTION_MASK) >> 2)
#define CTL_METHOD(x) (x & METHOD_MASK)

/*
* IOCTL Print Function
*/
void IOCTLPrintDevice(const int32 DeviceType);
void IOCTLPrintMethod(const int32 Method);
void IOCTLPrintAccess(const int32 Access);
void PrintIOCTLValue(int32 ioctl_code);
