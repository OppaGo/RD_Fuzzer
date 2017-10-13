#include "default.h"

void PrintLastError(uint32 lasterror)
{
	switch (lasterror)
	{
	case 0x1:
		fprintf(stderr, "[-] Error_Invalid_Function : 0x%x\n", lasterror);
		break;
	case 0x2:
		fprintf(stderr, "[-] Error_File_Not_Found : 0x%x\n", lasterror);
		break;
	case 0x5:
		fprintf(stderr, "[-] Error_Access_Denied : 0x%x\n", lasterror);
		break;
	case 0x35:
		fprintf(stderr, "[-] Error_Bad_Netpath : 0x%x\n", lasterror);
		break;
	case 0x37:
		fprintf(stderr, "[-] Error_Device_Not_Exist : 0x%x\n", lasterror);
		break;
	case 0x50:
		fprintf(stderr, "[-] Error_Not_Supported : 0x%x\n", lasterror);
		break;
	default:
		fprintf(stderr, "[-] Unknown Error : 0x%x\n", lasterror);
		break;
	}
}
