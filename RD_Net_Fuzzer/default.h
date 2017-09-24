#ifndef __DEFAULT_H__
#define __DEFAULT_H__

/* *INDENT-OFF* */
#ifdef __cplusplus
extern "C" {
#endif
	namespace RD_FUZZER
	{
		/* default.cpp */
		void *xmalloc(int size);
		void *xrealloc(void *oldmem, size_t size);
		void xfree(void *mem);
		void error(char *format, ...);
		void warning(char *format, ...);
		void unimpl(char *format, ...);
		void hexdump(unsigned char *p, unsigned int len);
		void write_hexdump(unsigned char *p, unsigned int len, const char* filename);
		//void print_disconnect_reason(uint16 reason);
	}
/* *INDENT-OFF* */
#ifdef __cplusplus
}
#endif
/* *INDENT-ON* */

#endif
