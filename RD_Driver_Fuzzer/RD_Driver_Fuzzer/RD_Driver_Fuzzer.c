#include "RD_Driver_Fuzzer.h"

uint32(*GenRandomValue)(uint32);
uint32(*Mutation)(char*, uint32);

#define IOCTL_LIST_LENGTH (argc-3)
int main(int argc, char* argv[])
{
	FILE* fp = NULL;
	HINSTANCE hInstDLL = NULL;
	uint32 count = 0;
	LPWSTR DeviceName = NULL;
	int8 filename[MAX_PATH] = { 0, };
	uint32* ioctl_code_list = NULL;
	uint32 ioctl_code;
	HANDLE hDevice;

	if (argc < 5) {
		Usage(argv[0]);

		return Error;
	}

	ioctl_code_list = (uint32*)malloc(IOCTL_LIST_LENGTH * sizeof(uint32));
	memset(ioctl_code_list, 0, IOCTL_LIST_LENGTH * sizeof(uint32));
	if (GetIOCTLOpt(argc, argv, &DeviceName, ioctl_code_list) != True)
	{
		fprintf(stderr, "[-] getopt error\n");

		return Error;
	}

	wprintf(L"Device Name : %ws\n", DeviceName);
	for (int i = 0; ioctl_code_list[i] != 0; i++)
		printf("[%u] 0x%x\n", i, ioctl_code_list[i]);

	hInstDLL = GetMutationFuncinDLL();
	if (hInstDLL == NULL) return Error;

	sprintf_s(filename, MAX_PATH, "RD_Driver_Fuzzer_.log");
	while (1) {
		if (!InitDriverFuzzing(DeviceName, filename, &hDevice, &fp)) continue;
		printf("[+] Start Index_%u Fuzzing\n", count);
		while (1) {
			ioctl_code = ioctl_code_list[GenRandomValue(IOCTL_LIST_LENGTH - 1)];
			//PrintIOCTLValue(ioctl_code);
			if (DriverFuzzing(hDevice, ioctl_code, fp) != True)
				break;
			Sleep(500);
		}
		printf("[+] Index_%u Fuzzing Done.\n", count++);
		CleanupDriverFuzzing(hDevice, fp);
	}

	CleanupMutationFunc(hInstDLL);
	free(DeviceName);
	free(ioctl_code_list);

	return 0;
}

/* 
 * main argument 
 */
void Usage(char* exe)
{
	fprintf(stderr, "Usage: %s [options] -n [DeviceName] -c [ioctl_code ...]\n", exe);
	fprintf(stderr, "   -n: DeviceName (without \"\\\\.\\\")\n");
	fprintf(stderr, "   -c: ioctl codes\n");
}

uint32 GetIOCTLOpt(int argc, char** argv, LPWSTR *DeviceName, uint32 *ioctl_code_list)
{
	int c;
	size_t DeviceNamelen = 0;
	uint32 index = 0;
	uint32 tmp;

	while ((c = getopt(argc, argv, "n:c")) != -1)
	{
		switch (c)
		{
		case 'n':
			DeviceNamelen = ((MultiByteToWideChar(CP_ACP, 0, "\\\\.\\", -1, NULL, 0) - 1) * 2);
			DeviceNamelen += ((MultiByteToWideChar(CP_ACP, 0, optarg, -1, NULL, 0)) * 2);
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
		default:
			puts("Error.");
			return False;
		}
	}

	return True;
}

/* 
 * MutationFunc 
 */
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

/* 
 * for Fuzzing 
 */
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

uint32 InitDriverFuzzing(const LPCWSTR DeviceName, const int8* FileName, PHANDLE phDevice, FILE** pfp)
{
	if ((*pfp = OpenLogger((const int8*)FileName)) == NULL) return Error;

	*phDevice = CreateFileW(
		DeviceName,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);
	if (*phDevice == INVALID_HANDLE_VALUE)
	{
		PrintLastError(GetLastError());
		return False;
	}

	fprintf(*pfp, "==========================================\n");
	fprintf(*pfp, "[+] DeviceName : %S\n", DeviceName);

	return True;
}

uint32 DriverFuzzing(HANDLE hDevice, uint32 ioctl_code, FILE* fp)
{
	//LPWSTR deviceName = DeviceName;
	DWORD dwRet;
	uint32 bufIo_length = 0;
	uint8 bufIn[BUF_MAXSIZE];
	uint8 bufOut[BUF_MAXSIZE];

	/*if (!DeviceIoControl(
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
	}*/
	fprintf(fp, "[+] IOCTL CODE : %u\n\n", ioctl_code);

	memset(bufOut, 0, BUF_MAXSIZE);
	bufIo_length = CreateMutatedData(bufIn);
	if (!DeviceIoControl(
		hDevice,
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

	return True;

IoControlError:
	fprintf(stderr, "[-] DeviceIoControl() Failed..\n");
	fprintf(fp, "[-] DeviceIoControl() Failed..\n");
	fprintf(fp, "============================================\n\n");

	return Error;
}

void CleanupDriverFuzzing(HANDLE hDevice, FILE* fp)
{
	CloseHandle(hDevice);
	CloseLogger(fp);
}
