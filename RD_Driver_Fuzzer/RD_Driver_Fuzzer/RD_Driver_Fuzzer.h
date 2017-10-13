#pragma once

#include <stdio.h>
#include <Windows.h>
#include <conio.h>

#include "ioctl.h"
#include "logger.h"

HINSTANCE GetMutationFuncinDLL();
void CleanupMutationFunc(HINSTANCE hInstDLL);

uint32 CreateMutatedData(uint8* buf);
uint32 DriverFuzzing(uint32 ioctl_code, FILE* fp);
