#include "RD_File_Fuzzer.h"


extern "C" RD_FILE_FUZZER_API PFileFuzzer OpenFileFuzzer(const char * config_file)
{
	RD_FUZZER::File_Fuzzer* file_fuzzer = new RD_FUZZER::File_Fuzzer(config_file);

	return (PFileFuzzer)file_fuzzer;
}

extern "C" RD_FILE_FUZZER_API bool File_Fuzzer_Loop(PFileFuzzer file_fuzzer)
{
	RD_FUZZER::File_Fuzzer* f = (RD_FUZZER::File_Fuzzer*)file_fuzzer;

	if (f->is_config() == false) return(false);

	if (!f->File_Fuzzer_Loop()) {
		fprintf(stderr, "[-] Please check .yaml file\n");
		return(false);
	}

	return(true);
}

extern "C" RD_FILE_FUZZER_API void CloseFileFuzzer(PFileFuzzer file_fuzzer)
{
	RD_FUZZER::File_Fuzzer* f = (RD_FUZZER::File_Fuzzer*)file_fuzzer;

	delete f;
}

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		printf("[+] DLL is attached process\n");
		break;
	case DLL_PROCESS_DETACH:
		printf("[+] DLL is dettached process\n");
		break;
	case DLL_THREAD_ATTACH:
		printf("[+] DLL is Attached thread\n");
		break;
	case DLL_THREAD_DETACH:
		printf("[+] DLL is dettached thread\n");
		break;
	}

	return TRUE;
}

