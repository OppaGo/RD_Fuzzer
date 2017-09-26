#include <cstdio>
#include <iostream>
#include <Windows.h>

#include "RD_Tester.h"

using namespace std;

void Usage(const char* argv0)
{
	fprintf(stderr, "Usage: %s [Fuzzer Num] [Config file]\n", argv0);
	fprintf(stderr, "     - Fuzzer Num: File Format Fuzzer(0)\n");
	fprintf(stderr, "                   RDP Fuzzer(1)\n");
	fprintf(stderr, "                   Sniffer(2)\n");
	fprintf(stderr, "                   Network Fuzzer(3)\n");
	fprintf(stderr, "     - Config file : ex) RD_File_Fuzzer.yaml etc...");
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		Usage(argv[0]);

		return(-1);
	}

	unsigned int select = /* RDPNetwork; */atoi(argv[1]);
	const char* config_file = (argc >= 3)?argv[2]:NULL;

	if (select == FileFormat)
	{
		(config_file == NULL) ? "RD_File_Fuzzer.yaml" : config_file;
		CallFileFuzzer(config_file);
	}
	else if (select == RDPNetwork)
	{
		(config_file == NULL) ? "RD_RDP_Fuzzer.yaml" : config_file;
		CallRDPFuzzer(config_file);
	}
	else if (select == SniffNetwork)
	{
		(config_file == NULL) ? "RD_Sniffer.yaml" : config_file;
		CallSniffer(config_file);
	}
	else if (select == NetFuzzer)
	{
		(config_file == NULL) ? "RD_Net_Fuzzer.yaml" : config_file;
		CallNetFuzzer(config_file);
	}
	else {
		fprintf(stderr, "[-] Not yet Supported.\n");
		return(-1);
	}
}
