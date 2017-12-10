#include <fstream>
#include <string>
#include <regex>
#include "RD_Sniffer.h"
#include "packet_header.h"

#define RDP_PROTOCOL 3389
static DWORD64 filterfunc(const u_char* packet)
{
	DWORD64 offset = 0;
	const u_char* packet_ptr = packet;

	if (((pether_h)packet_ptr)->Type == TYPE_IP) {
		offset += ETHERNET_SIZE;
		packet_ptr += offset;
		if (((pip_h)packet_ptr)->protocol == TCP_PROTOCOL) {
			offset += (((pip_h)packet_ptr)->length * 4);
			packet_ptr += offset;
			if (((ptcp_h)packet_ptr)->source == htons(RDP_PROTOCOL)) {
				offset += (((ptcp_h)packet_ptr)->length * 4);
			}
			else offset = 0;
		}
		else offset = 0;
	}

	return offset;
}

RD_SNIFFER_API PSniffer OpenSniffer()
{
	RD_FUZZER::RD_SNIFFER *rd_sniffer = new RD_FUZZER::RD_SNIFFER();

	//rd_sniffer->OpenSniff(NULL, true);
	rd_sniffer->OpenSniff("VMnet8", false);
	return rd_sniffer;
}

RD_SNIFFER_API void CloseSniffer(PSniffer psniff)
{
	RD_FUZZER::RD_SNIFFER *rd_sniffer = (RD_FUZZER::RD_SNIFFER*) psniff;

	rd_sniffer->CloseSniff();
	delete rd_sniffer;
}

#define BUF_SIZE 512
#define MAX_FILTER_EXP 128
static bool GetFilterInfofromFile(const char* config_file, char* packet_store, char* filter_rule, uint32_t& netmask)
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
				if (!strcmp(m[1].str().c_str(), "packet_storage")) strcpy_s(packet_store, MAX_PATH, m[2].str().c_str());
				else if(!strcmp(m[1].str().c_str(), "filter_rule")) strcpy_s(filter_rule, 128, m[2].str().c_str());
				else if (!strcmp(m[1].str().c_str(), "netmask")) netmask = (short)atoi(m[2].str().c_str());
			}
		}

		//cout << "[+] Server : " << server << endl;
		//cout << "[+] Port : " << port << endl;

		ifs.close();
	}
	else return(false);

	return(true);
}

RD_SNIFFER_API void Sniffing(PSniffer psniff, const char* config_file)
{
	char file_path[MAX_PATH] = { 0, };
	char filter_exp[MAX_FILTER_EXP] = { 0, };
	bpf_u_int32 net = 0;

	RD_FUZZER::RD_SNIFFER *rd_sniffer = (RD_FUZZER::RD_SNIFFER*) psniff;

	if (GetFilterInfofromFile(config_file, file_path, filter_exp, net))
	{
		rd_sniffer->Sniffing_for_File(file_path, filter_exp, net, filterfunc);
	}
	else {
		fprintf(stderr, "[-] GetFilterInfofromFile Error\n");
		//delete rd_sniffer;
	}
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
