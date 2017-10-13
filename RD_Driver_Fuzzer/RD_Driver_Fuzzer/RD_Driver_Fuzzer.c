#include "RD_Driver_Fuzzer.h"

//static uint32 ioctl_code = TVMonitor0;
static uint32 (*GenRandomValue)(uint32);
static uint32 (*Mutation)(char*, uint32);

int main(void)
{
	FILE* fp = NULL;
	HINSTANCE hInstDLL = NULL;
	uint32 count = 0;
	uint32 ioctl_code_list[] = {TVMonitor0, TVMonitor1, TVMonitor2, TVMonitor3, TVMonitor4, TVMonitor5};
	uint32 ioctl_code = ioctl_code_list[0];

	PrintIOCTLValue(ioctl_code);

	hInstDLL = GetMutationFuncinDLL();
	if (hInstDLL == NULL) return Error;
	
	if ((fp = OpenLogger()) == NULL) return Error;
	while (1) {
		ioctl_code = ioctl_code_list[GenRandomValue(sizeof(ioctl_code_list) / sizeof(uint32))];
		if (DriverFuzzing(ioctl_code, fp) != True)
			break;
		printf("Index[%u] Fuzzing...\n", count);
	}
	CloseLogger(fp);

	CleanupMutationFunc(hInstDLL);
	
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
	memset(bufIn, 'A', bufIo_length);
	(*Mutation)(bufIn, bufIo_length);

	return bufIo_length;
}

uint32 DriverFuzzing(uint32 ioctl_code, FILE* fp)
{
	HANDLE handle;
	WCHAR deviceName[] = L"\\\\.\\MonitorFunction0"; // L"\\\\Device\\MonitorFunction0";
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
