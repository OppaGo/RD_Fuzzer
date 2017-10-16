#pragma once

#include <stdio.h>
#include <Windows.h>
#include <conio.h>

#include "ioctl.h"
#include "logger.h"
#include "wingetopt.h"

HINSTANCE GetMutationFuncinDLL();
void CleanupMutationFunc(HINSTANCE hInstDLL);

uint32 CreateMutatedData(uint8* buf);
uint32 DriverFuzzing(LPWSTR DeviceName, uint32 ioctl_code, FILE* fp);

void Usage(char* exe);
uint32 GetIOCTLOpt(int argc, char** argv, LPWSTR *DeviceName, uint32 *ioctl_code_list);
