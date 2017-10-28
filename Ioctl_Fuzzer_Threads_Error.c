#include "RD_Driver_Fuzzer.h"

static uint32 (*GenRandomValue)(uint32);
static uint32(*Mutation)(char*, uint32);
static HANDLE ghSemaphore;

#define IOCTL_LIST_LENGTH (argc-3)
#define InitThreads(c, l, h, p) {										\
	l = (LPDWORD*) malloc(c * sizeof(LPDWORD));							\
	h = (HANDLE*) malloc(c * sizeof(HANDLE));							\
	p = (struct ThreadParam*) malloc(c * sizeof(struct ThreadParam));	\
}
#define SetParam(t, d, i, f) {					\
	((struct ThreadParam*)t)->DeviceName = d;	\
	((struct ThreadParam*)t)->ioctl_code = i;	\
	((struct ThreadParam*)t)->fp = f;			\
}
#define CleanThreads(l, h, p) {	\
	free(l);					\
	free(h);					\
	free(p);					\
}

int main(int argc, char* argv[])
{
	FILE* fp = NULL;
	HINSTANCE hInstDLL = NULL;
	uint32 count = 0;
	LPWSTR DeviceName = NULL;
	int8 filename[MAX_PATH] = { 0, };
	uint32* ioctl_code_list = NULL;
	uint32 ioctl_code;
	DWORD timeout = 3000;
	uint32 threads_count = 5;
	LPDWORD *lpThreadId = NULL;
	HANDLE *hThread = NULL;
	struct ThreadParam *tp = NULL;
	DWORD result;

	if (argc < 5) {
		Usage(argv[0]);

		return Error;
	}

	ioctl_code_list = (uint32*)malloc(IOCTL_LIST_LENGTH*sizeof(uint32));
	memset(ioctl_code_list, 0, IOCTL_LIST_LENGTH * sizeof(uint32));
	if (GetIOCTLOpt(argc, argv, &DeviceName, ioctl_code_list, &timeout, &threads_count) != True)
	{
		fprintf(stderr, "[-] getopt error\n");

		return Error;
	}

	wprintf(L"Device Name : %ws\n", DeviceName);
	for (int i = 0; ioctl_code_list[i] != 0; i++)
		printf("[%u] 0x%x\n", i, ioctl_code_list[i]);
	printf("timeout : %u\n", timeout);
	printf("threads_cout : %u\n", threads_count);

	hInstDLL = GetMutationFuncinDLL();
	if (hInstDLL == NULL) return Error;
	
	ghSemaphore = CreateSemaphore(
		NULL,
		threads_count,
		threads_count,
		NULL
	);
	if (ghSemaphore == NULL) {
		PrintLastError(GetLastError());
		return Error;
	}

	InitThreads(threads_count, lpThreadId, hThread, tp);
	while (1) {
		sprintf_s(filename, MAX_PATH, "RD_Driver_Fuzzer_.log");
		if ((fp = OpenLogger(filename)) == NULL) return Error;
		printf("[+] Start Index_%u Fuzzing\n", count);
		for (uint32 i = 0; i < threads_count; i++) {
			ioctl_code = ioctl_code_list[GenRandomValue(IOCTL_LIST_LENGTH - 1)];
			SetParam(&tp[i], DeviceName, ioctl_code, fp);
			hThread[i] = CreateThread(
								NULL,
								0,
								ThreadFunctionForFuzzing,
								&tp[i],
								0,
								lpThreadId[i]);
			if (hThread[i] == NULL)
				PrintLastError(GetLastError());
		}

		Sleep(timeout);
		WaitForMultipleObjects(threads_count, hThread, TRUE, INFINITE);
		printf("[+] Index_%u Fuzzing Done.\n", count++);

		for (uint32 i = 0; i < threads_count; i++) {
			GetExitCodeThread(hThread[i], &result);
			if (CloseHandle(hThread[i]) == 0)
				PrintLastError(GetLastError());
		}
		CloseLogger(fp);
	}
	CleanThreads(lpThreadId, hThread, tp);
	CloseHandle(ghSemaphore);

	CleanupMutationFunc(hInstDLL);
	free(DeviceName);
	free(ioctl_code_list);

	return 0;
}

HINSTANCE GetMutationFuncinDLL()
{
	HINSTANCE hInstDLL = LoadLibrary(L"RD_Mutation_Lib.dll");
	if (hInstDLL == NULL)
	{
		fprintf(stderr, "[-] LoadLibrary Error\n");
		PrintLastError(GetLastError());
		return NULL;
	}

	GenRandomValue = (uint32(*)(uint32))GetProcAddress(hInstDLL, "GenRandomValue");
	Mutation = (uint32(*)(char*, uint32))GetProcAddress(hInstDLL, "Mutation");
	if (GenRandomValue == NULL ||
		Mutation == NULL)
	{
		fprintf(stderr, "[-] GetProcAddress Error\n");
		PrintLastError(GetLastError());
		return NULL;
	}

	return hInstDLL;
}

void CleanupMutationFunc(HINSTANCE hInstDLL)
{
	FreeLibrary(hInstDLL);
}

uint32 CreateMutatedData(uint8* bufIn)
{
	uint32 bufIo_length = (*GenRandomValue)(BUF_MAXSIZE);

	memset(bufIn, 0, BUF_MAXSIZE);
	for (uint32 i = 0; i < bufIo_length; i++)
		bufIn[i] = (*GenRandomValue)(0x100);
	//memset(bufIn, 'A', bufIo_length);
	//(*Mutation)(bufIn, bufIo_length);

	return bufIo_length;
}

uint32 DriverFuzzing(LPWSTR DeviceName, uint32 ioctl_code, FILE* fp)
{
	HANDLE handle;
	LPWSTR deviceName = DeviceName; // L"\\\\Device\\MonitorFunction0";
	DWORD dwRet;
	uint32 bufIo_length = 0;
	uint8 bufIn[BUF_MAXSIZE];
	uint8 bufOut[BUF_MAXSIZE];

	handle = CreateFileW(
		deviceName,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);
	if (handle == INVALID_HANDLE_VALUE)
	{
		PrintLastError(GetLastError());
		return Error;
	}

	fprintf(fp, "==========================================\n");
	fprintf(fp, "[+] Thread %d\n", GetCurrentThreadId());
	fprintf(fp, "[+] DeviceName : %S\n", deviceName);
	if (!DeviceIoControl(
		handle,
		ioctl_code,
		NULL,
		0,
		NULL,
		0,
		&dwRet,
		NULL))
	{
		goto IoControlError;
	}
	fprintf(fp, "[+] IOCTL CODE : %u\n\n", ioctl_code);

	memset(bufOut, 0, BUF_MAXSIZE);
	bufIo_length = CreateMutatedData(bufIn);
	if (!DeviceIoControl(
		handle,
		ioctl_code,
		bufIn,
		bufIo_length,
		bufOut,
		bufIo_length,
		&dwRet,
		NULL))
	{
		goto IoControlError;
	}

	fprintf(fp, "[+] Random Length : %u\n", bufIo_length);
	fprintf(fp, "[+] Random Buffer\n");
	fhexdump(fp, bufIn, bufIo_length);

	CloseHandle(handle);

	return True;

IoControlError:
	fprintf(stderr, "[-] DeviceIoControl() Failed..\n");
	fprintf(fp, "[-] DeviceIoControl() Failed..\n");
	fprintf(fp, "============================================\n\n");

	CloseHandle(handle);

	return Error;
}

DWORD WINAPI ThreadFunctionForFuzzing(LPVOID lpParam)
{
	struct ThreadParam* tp = (struct ThreadParam*)lpParam;
	DWORD dwWaitResult;
	DWORD Continue = True;

	printf("[+] Thread %d\n", GetCurrentThreadId());
	while (Continue) {
		dwWaitResult = WaitForSingleObject(ghSemaphore, INFINITE);

		switch (dwWaitResult)
		{
		case WAIT_OBJECT_0:
			if (DriverFuzzing(tp->DeviceName, tp->ioctl_code, tp->fp) != True)
				Continue = False;
			break;
		case WAIT_FAILED:
			return Error;
		}
	}

	if (!ReleaseSemaphore(ghSemaphore, 1, NULL))
	{
		PrintLastError(GetLastError());
	}

	return True;
}

void Usage(char* exe)
{
	fprintf(stderr, "Usage: %s [-t|-T] -n [DeviceName] -c [ioctl_code ...]\n", exe);
	fprintf(stderr, "   -t: timeout(milliseconds)\n");
	fprintf(stderr, "   -T: Threads Count\n");
	fprintf(stderr, "   -n: DeviceName (without \"\\\\.\\\")\n");
	fprintf(stderr, "   -c: ioctl codes\n");
}

//#define DeviceNameLen(x) ((strlen("\\\\.\\") + strlen(x) + 1) * 2);
uint32 GetIOCTLOpt(int argc, char** argv, LPWSTR *DeviceName, uint32 *ioctl_code_list, DWORD *timeout, uint32 *threads_count)
{
	size_t DeviceNamelen = 0;
	uint32 index = 0;
	uint32 tmp;
	int c;

	while ((c = getopt(argc, argv, "n:c:t:T")) != -1)
	{
		switch (c)
		{
		case 'n':
			DeviceNamelen = ((MultiByteToWideChar(CP_ACP, 0, "\\\\.\\", -1, NULL, 0) - 1) * 2);
			DeviceNamelen += ((MultiByteToWideChar(CP_ACP, 0, optarg, -1, NULL, 0))* 2);
			if (0x100 < DeviceNamelen) return False;
			*DeviceName = (LPWSTR)malloc(DeviceNamelen);
			if (*DeviceName == NULL) return Error;
			memcpy(*DeviceName, L"\\\\.\\", sizeof(L"\\\\.\\"));
			MultiByteToWideChar(CP_ACP, 0, optarg, ((int)strlen(optarg) + 1), (*DeviceName + 4), (int)DeviceNamelen);
			break;
		case 'c':
			index = optind;
			while (argv[index] != NULL)
			{
				tmp = strtol(argv[index], NULL, 16);
				if (tmp == 0) return False;
				*ioctl_code_list = tmp;
				ioctl_code_list++;
				index++;
			}
			break;
		case 't':
			tmp = strtol(optarg, NULL, 10);
			*timeout = (DWORD)(tmp != 0) ? tmp : 3000;
			break;
		case 'T':
			tmp = strtol(optarg, NULL, 10);
			*threads_count = (tmp != 0) ? tmp : 5;
			break;
		default:
			puts("Error.");
			return False;
		}
	}

	return True;
}