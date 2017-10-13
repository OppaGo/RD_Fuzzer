#include "default.h"
#include <stdio.h>

void hexdump(unsigned char *p, unsigned int len)
{
	unsigned char *line = p;
	unsigned int i, thisline, offset = 0;

	while (offset < len)
	{
		printf("%04x ", offset);
		thisline = len - offset;
		if (thisline > 16)
			thisline = 16;

		for (i = 0; i < thisline; i++)
			printf("%02x ", line[i]);

		for (; i < 16; i++)
			printf("   ");

		for (i = 0; i < thisline; i++)
			printf("%c", (line[i] >= 0x20 && line[i] < 0x7f) ? line[i] : '.');

		printf("\n");
		offset += thisline;
		line += thisline;
	}
}

void fhexdump(FILE* fp, unsigned char *p, unsigned int len)
{
	unsigned char *line = p;
	unsigned int i, thisline, offset = 0;

	while (offset < len)
	{
		fprintf(fp, "%04x ", offset);
		thisline = len - offset;
		if (thisline > 16)
			thisline = 16;

		for (i = 0; i < thisline; i++)
			fprintf(fp, "%02x ", line[i]);

		for (; i < 16; i++)
			fprintf(fp, "   ");

		for (i = 0; i < thisline; i++)
			fprintf(fp, "%c", (line[i] >= 0x20 && line[i] < 0x7f) ? line[i] : '.');

		fprintf(fp, "\n");
		offset += thisline;
		line += thisline;
	}
}