#include <fstream>
#include <regex>
#include <string>
#include <cstring>
#include "RD_Net_Fuzzer.h"

#define BUF_SIZE 512
static bool GetServerInfofromFile(const char* config_file, char* server, short& port)
{
	std::ifstream ifs(config_file);
	char fdata[BUF_SIZE];
	if (ifs.is_open()) {
		while (!ifs.eof()) {
			memset(fdata, 0, BUF_SIZE);
			ifs.getline(fdata, BUF_SIZE);

			std::regex reg("^(\\w+?): ([\\w:\\\\ ().]+)");
			std::string fdata_str = fdata;
			std::smatch m;

			bool ismatched = std::regex_search(fdata_str, m, reg);

			if (ismatched) {
				char** dummy = NULL;
				if (!strcmp(m[1].str().c_str(), "server_ip")) strcpy_s(server, 32, m[2].str().c_str());
				else if (!strcmp(m[1].str().c_str(), "port")) port = (short)atoi(m[2].str().c_str());
			}
		}

		//cout << "[+] Server : " << server << endl;
		//cout << "[+] Port : " << port << endl;

		ifs.close();
	}
	else return(false);

	return(true);
}

RD_NET_FUZZER_API PNetFuzzer OpenNetFuzzer(const char* config_file)
{
	char server[32] = { 0, };
	short port = 80;

	RD_FUZZER::NET_FUZZ *net_fuzz = new RD_FUZZER::NET_FUZZ();

	if (GetServerInfofromFile(config_file, server, port))
	{
		net_fuzz->OpenNetFuzzer(server, port);
	}
	else 
	{
		fprintf(stderr, "OpenNetFuzzer Error\n");
		delete net_fuzz;
		return NULL;
	}

	return net_fuzz;
}

RD_NET_FUZZER_API void CloseNetFuzzer(PNetFuzzer pnetfuzz)
{
	RD_FUZZER::NET_FUZZ *net_fuzz = (RD_FUZZER::NET_FUZZ*)pnetfuzz;

	net_fuzz->CloseNetFuzzer();

	delete net_fuzz;
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
		//printf("[+] DLL is attached process\n");
		break;
	case DLL_PROCESS_DETACH:
		//printf("[+] DLL is dettached process\n");
		break;
	case DLL_THREAD_ATTACH:
		//printf("[+] DLL is Attached thread\n");
		break;
	case DLL_THREAD_DETACH:
		//printf("[+] DLL is dettached thread\n");
		break;
	}

	return TRUE;
}
