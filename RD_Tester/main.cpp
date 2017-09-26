#include <cstdio>
#include <iostream>
#include <Windows.h>

#include "RD_Tester.h"

using namespace std;

void Usage(const char* argv0)
{
	fprintf(stderr, "Usage > %s [File Format Fuzzer(0) | RDP Fuzzer(1) | Sniffer(2) | Network Fuzzer(3)]\n", argv0);
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		Usage(argv[0]);
		return(-1);
	}

	unsigned int select = /* RDPNetwork; */atoi(argv[1]);
	if (select == FileFormat)
	{
		CallFileFuzzer();
	}
	else if (select == RDPNetwork)
	{
		CallRDPFuzzer();
	}
	else if (select == SniffNetwork)
	{
		CallSniffer();
	}
	else if (select == NetFuzzer)
	{
		CallNetFuzzer();
	}
	else {
		fprintf(stderr, "[-] Not yet Supported.\n");
		return(-1);
	}
}
