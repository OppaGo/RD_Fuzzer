#include <cstdio>
#include <iostream>
#include <Windows.h>

#include "RD_Tester.h"

using namespace std;

/*
*	CallFileFuzzer()
*	File Fuzzer 호출
*/
bool CallFileFuzzer()
{
	HINSTANCE hInstDLL;
	void* Fuzzer_Handle;

	void* (*pOpenFunc)(const char*);
	bool(*pFuzzFunc)(void*);
	void(*pCloseFunc)(void*);

	hInstDLL = LoadLibrary("RD_File_Fuzzer.dll");
	if (hInstDLL == NULL)
	{
		fprintf(stderr, "LoadLibrary Error\n");
		printf("Error Code : %u\n", GetLastError());
		return(false);
	}

	pOpenFunc = (void* (*)(const char*))GetProcAddress(hInstDLL, "OpenFileFuzzer");
	pFuzzFunc = (bool(*)(void*))GetProcAddress(hInstDLL, "File_Fuzzer_Loop");
	pCloseFunc = (void(*)(void*))GetProcAddress(hInstDLL, "CloseFileFuzzer");

	if (pOpenFunc == NULL ||
		pFuzzFunc == NULL ||
		pCloseFunc == NULL)
	{
		goto Exit_Label;
	}

	Fuzzer_Handle = (*pOpenFunc)("./config.yaml");
	if (!pFuzzFunc(Fuzzer_Handle)) {
		fprintf(stderr, "[-] File Fuzzing Error\n");
	}
	(*pCloseFunc)(Fuzzer_Handle);

Exit_Label:
	FreeLibrary(hInstDLL);
	return(0);
}

/*
*	CallRDPFuzzer()
*	RDP Fuzzer 호출
*/
bool CallRDPFuzzer()
{
	HINSTANCE hInstDLL;
	void* Fuzzer_Handle;

	void* (*pOpenFunc)(const char*);
	int(*pFuzzFunc)(void*, DWORD);
	void(*pCloseFunc)(void*);

	hInstDLL = LoadLibrary("RD_RDP_Fuzzer.dll");
	if (hInstDLL == NULL)
	{
		fprintf(stderr, "LoadLibrary Error\n");
		printf("[-] Error Code : %u\n", GetLastError());
		return(false);
	}

	pOpenFunc = (void* (*)(const char*))GetProcAddress(hInstDLL, "OpenRDPFuzzer");
	pFuzzFunc = (int(*)(void*, DWORD))GetProcAddress(hInstDLL, "RDPFuzzing");
	pCloseFunc = (void(*)(void*))GetProcAddress(hInstDLL, "CloseRDPFuzzer");

	if (pOpenFunc == NULL ||
		pFuzzFunc == NULL ||
		pCloseFunc == NULL)
	{
		goto Exit_Label;
	}

	Fuzzer_Handle = (*pOpenFunc)("./config.yaml");
	if (!pFuzzFunc(Fuzzer_Handle, 1)) {
		fprintf(stderr, "[-] RDP Fuzzing Error\n");
	}
	(*pCloseFunc)(Fuzzer_Handle);

Exit_Label:
	FreeLibrary(hInstDLL);
	return(0);
}

/*
*	CallSniffer()
*	Sniffer 호출
*/
bool CallSniffer(const char* file_path)
{
	HINSTANCE hInstDLL;
	void* Fuzzer_Handle;

	void* (*pOpenFunc)();
	void (*pSniffFunc)(void*, const char*);
	void (*pCloseFunc)(void*);

	hInstDLL = LoadLibrary("RD_Sniffer.dll");
	if (hInstDLL == NULL)
	{
		fprintf(stderr, "LoadLibrary Error\n");
		printf("[-] Error Code : %u\n", GetLastError());
		return(false);
	}

	pOpenFunc = (void* (*)())GetProcAddress(hInstDLL, "OpenSniffer");
	pSniffFunc = (void (*)(void*, const char*))GetProcAddress(hInstDLL, "Sniffing");
	pCloseFunc = (void (*)(void*))GetProcAddress(hInstDLL, "CloseSniffer");

	if (pOpenFunc == NULL ||
		pSniffFunc == NULL ||
		pCloseFunc == NULL)
	{
		goto Exit_Label;
	}

	Fuzzer_Handle = (*pOpenFunc)();
	pSniffFunc(Fuzzer_Handle, file_path);
	(*pCloseFunc)(Fuzzer_Handle);

Exit_Label:
	FreeLibrary(hInstDLL);
	return(0);
}

