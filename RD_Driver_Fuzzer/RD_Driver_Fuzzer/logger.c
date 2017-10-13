#include "logger.h"

FILE* OpenLogger()
{
	FILE* fp = NULL;
	errno_t err;

	if ((err = fopen_s(&fp, "RD_Driver_Fuzzer.log", "a")) != 0)
	{
		fprintf(stderr, "[-] fopen_s error.\n");
		return NULL;
	}

	return fp;
}

void CloseLogger(FILE* fp)
{
	fclose(fp);
}
