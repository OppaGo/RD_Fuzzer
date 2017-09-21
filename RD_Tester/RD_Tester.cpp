#include <cstdio>
#include <iostream>
#include <Windows.h>

using namespace std;

#define FileFormat 0
#define RDPNetwork 1
int main(int argc, char* argv[]) {
	HINSTANCE hInstDLL;
	void* Fuzzer_Handle;
	
	if (argc != 2) {
		fprintf(stderr, "Usage > %s [File Format Fuzzer(0) | RDP Fuzzer(1)]\n", argv[0]);
		return(-1);
	}

	unsigned int select = /* RDPNetwork; */atoi(argv[1]);
	if (select == FileFormat) {
		void* (*pOpenFunc)(const char*);
		bool(*pFuzzFunc)(void*);
		void(*pCloseFunc)(void*);

		hInstDLL = LoadLibrary("RD_File_Fuzzer.dll");
		if (hInstDLL == NULL)
		{
			fprintf(stderr, "LoadLibrary Error\n");
			printf("Error Code : %u\n", GetLastError());
			return(-1);
		}

		pOpenFunc = (void* (*)(const char*))GetProcAddress(hInstDLL, "OpenFileFuzzer");
		pFuzzFunc = (bool (*)(void*))GetProcAddress(hInstDLL, "File_Fuzzer_Loop");
		pCloseFunc = (void (*)(void*))GetProcAddress(hInstDLL, "CloseFileFuzzer");

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
	}
	else if (select == RDPNetwork)
	{
		void* (*pOpenFunc)(const char*);
		int(*pFuzzFunc)(void*, DWORD);
		void(*pCloseFunc)(void*);

		hInstDLL = LoadLibrary("RD_RDP_Fuzzer.dll");
		if (hInstDLL == NULL)
		{
			fprintf(stderr, "LoadLibrary Error\n");
			printf("[-] Error Code : %u\n", GetLastError());
			return(-1);
		}

		pOpenFunc = (void* (*)(const char*))GetProcAddress(hInstDLL, "OpenRDPFuzzer");
		pFuzzFunc = (int (*)(void*, DWORD))GetProcAddress(hInstDLL, "RDPFuzzing");
		pCloseFunc = (void (*)(void*))GetProcAddress(hInstDLL, "CloseRDPFuzzer");

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
	}
	else {
		fprintf(stderr, "[-] Not yet Supported.\n");
		return(-1);
	}

Exit_Label:
	FreeLibrary(hInstDLL);
	return(0);
}
