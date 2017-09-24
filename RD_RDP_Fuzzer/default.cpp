#include "rdesktop.h"


namespace RD_FUZZER
{
	/* malloc; exit if out of memory */
	void *
		xmalloc(int size)
	{
		void *mem = malloc(size);
		if (mem == NULL)
		{
			error("xmalloc %d\n", size);
			exit(1);
		}
		return mem;
	}

	/* realloc; exit if out of memory */
	void *
		xrealloc(void *oldmem, size_t size)
	{
		void *mem;

		if (size == 0)
			size = 1;
		mem = realloc(oldmem, size);
		if (mem == NULL)
		{
			error("xrealloc %ld\n", size);
			exit(1);
		}
		return mem;
	}

	/* free */
	void
		xfree(void *mem)
	{
		free(mem);
	}

	/* report an error */
	void
		error(char *format, ...)
	{
		va_list ap;

		fprintf(stderr, "[-] ERROR: ");

		va_start(ap, format);
		vfprintf(stderr, format, ap);
		va_end(ap);
	}

	/* report a warning */
	void
		warning(char *format, ...)
	{
		va_list ap;

		fprintf(stderr, "[-] WARNING: ");

		va_start(ap, format);
		vfprintf(stderr, format, ap);
		va_end(ap);
	}

	/* report an unimplemented protocol feature */
	void
		unimpl(char *format, ...)
	{
		va_list ap;

		fprintf(stderr, "NOT IMPLEMENTED: ");

		va_start(ap, format);
		vfprintf(stderr, format, ap);
		va_end(ap);
	}

	/* produce a hex dump */
	void
		hexdump(unsigned char *p, unsigned int len)
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

	void
		write_hexdump(unsigned char *p, unsigned int len, const char* filename)
	{
		unsigned char *line = p;
		unsigned int i, thisline, offset = 0;
		FILE* fp;
		fopen_s(&fp, filename, "wt");
		
		while (offset < len)
		{
			fprintf_s(fp, "%04x ", offset);
			thisline = len - offset;
			if (thisline > 16)
				thisline = 16;

			for (i = 0; i < thisline; i++)
				fprintf_s(fp, "%02x ", line[i]);

			for (; i < 16; i++)
				fprintf_s(fp, "   ");

			for (i = 0; i < thisline; i++)
				fprintf_s(fp, "%c", (line[i] >= 0x20 && line[i] < 0x7f) ? line[i] : '.');

			fprintf_s(fp, "\n");
			offset += thisline;
			line += thisline;
		}
	}
}
