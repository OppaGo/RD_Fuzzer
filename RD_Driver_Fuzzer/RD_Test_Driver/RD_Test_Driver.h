#pragma once
#include <ntddk.h>

#define LINK_NAME L"\\DosDevices\\Tribal"
#define DEVICE_NAME L"\\Device\\tribal"
#define IOCTL_TEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x4000, METHOD_BUFFERED, FILE_ANY_ACCESS)
