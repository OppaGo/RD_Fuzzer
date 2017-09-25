#include "RD_Net_Fuzzer.h"

RD_NET_FUZZER_API PNetFuzzer OpenNetFuzzer(const char* config_file)
{
	RD_FUZZER::NET_FUZZ *net_fuzz = new RD_FUZZER::NET_FUZZ();

	return net_fuzz;
}

RD_NET_FUZZER_API void CloseNetFuzzer(PNetFuzzer pnetfuzz)
{
	delete (RD_FUZZER::NET_FUZZ*)pnetfuzz;
}

RD_NET_FUZZER_API void NetworkFuzzing(PNetFuzzer pnetfuzz)
{
	RD_FUZZER::NET_FUZZ *net_fuzz = (RD_FUZZER::NET_FUZZ*)pnetfuzz;

	while(1) net_fuzz->NetFuzzing();
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
