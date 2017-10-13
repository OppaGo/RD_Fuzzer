#include "RD_Driver_Fuzzer.h"

static DWORD ioctl_code = TVMonitor0;
static uint32 (*GenRandomValue)(uint32);
static uint32 (*Mutation)(char*, uint32);

int main(void)
{
	HANDLE handle;
	WCHAR deviceName[] = L"\\\\.\\MonitorFunction0"; // L"\\\\Device\\MonitorFunction0";
	DWORD dwRet;
	uint32 bufIo_length = 0;
	uint8 bufIn[BUF_MAXSIZE];
	uint8 bufOut[BUF_MAXSIZE];
	
	FILE* fp = NULL;
	errno_t err;

	HINSTANCE hInstDLL = LoadLibrary(L"RD_Mutation_Lib.dll");
	if (hInstDLL == NULL)
	{
		fprintf(stderr, "[-] LoadLibrary Error\n");
		PrintLastError(GetLastError());
		return Error;
	}

	GenRandomValue = (uint32(*)(uint32))GetProcAddress(hInstDLL, "GenRandomValue");
	Mutation = (uint32(*)(char*, uint32))GetProcAddress(hInstDLL, "Mutation");
	if (GenRandomValue == NULL ||
		Mutation == NULL)
	{
		fprintf(stderr, "[-] GetProcAddress Error\n");
		PrintLastError(GetLastError());
		return Error;
	}

	printf("DeviceType : 0x%x\n", CTL_DEVICE(ioctl_code));
	printf("Access : 0x%x\n", CTL_ACCESS(ioctl_code));
	printf("Function : 0x%x\n", CTL_FUNCTION(ioctl_code));
	printf("Method : 0x%x\n", CTL_METHOD(ioctl_code));
	
	if ((err = fopen_s(&fp, "RD_ioctl_fuzzer.log", "w")) != 0)
	{
		fprintf(stderr, "[-] fopen_s error.\n");
		return Error;
	}

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

	bufIo_length = (*GenRandomValue)(BUF_MAXSIZE);
	memset(bufOut, 0, BUF_MAXSIZE);
	memset(bufIn, 0, BUF_MAXSIZE);
	memset(bufIn, 'A', bufIo_length);
	(*Mutation)(bufIn, bufIo_length);
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
	fclose(fp);

	FreeLibrary(hInstDLL);
	return 0;

IoControlError:
	fprintf(stderr, "[-] DeviceIoControl() Failed..\n");
	fprintf(fp, "[-] DeviceIoControl() Failed..\n");
	fprintf(fp, "============================================\n\n");
	
	CloseHandle(handle);
	fclose(fp);

	return Error;
}
