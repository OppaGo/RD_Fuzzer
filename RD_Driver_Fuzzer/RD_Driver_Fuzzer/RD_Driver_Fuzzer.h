#pragma once

#include <stdio.h>
#include <Windows.h>
#include <conio.h>

#include "ioctl.h"
#include "logger.h"
#include "wingetopt.h"

//struct ThreadParam
//{
//	LPWSTR DeviceName;
//	uint32 ioctl_code;
//	FILE* fp;
//};

/* main argument */
void Usage(char* exe);
uint32 GetIOCTLOpt(int argc, char** argv, LPWSTR *DeviceName, uint32 *ioctl_code_list);// , DWORD *timeout, uint32 *threads_count);

/* MutationFunc */
extern uint32(*GenRandomValue)(uint32);
extern uint32(*Mutation)(char*, uint32);

HINSTANCE GetMutationFuncinDLL();
void CleanupMutationFunc(HINSTANCE hInstDLL);

/* for Fuzzing */
uint32 CreateMutatedData(uint8* buf);
uint32 InitDriverFuzzing(const LPCWSTR DeviceName, const int8* FileName, PHANDLE phDevice, FILE **pfp);
uint32 DriverFuzzing(HANDLE hDevice, uint32 ioctl_code, FILE* fp);
void CleanupDriverFuzzing(HANDLE hDevice, FILE* fp);
//DWORD WINAPI ThreadFunctionForFuzzing(LPVOID lpParam);
