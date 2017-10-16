#include "logger.h"

FILE* OpenLogger(const char* filename)
{
	FILE* fp = NULL;
	errno_t err;

	if ((err = fopen_s(&fp, filename, "a")) != 0)
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
