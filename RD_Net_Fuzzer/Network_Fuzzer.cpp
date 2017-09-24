#include "Network_Fuzzer.h"


RD_FUZZER::NET_FUZZ::NET_FUZZ()
{
}

RD_FUZZER::NET_FUZZ::~NET_FUZZ()
{
}

bool RD_FUZZER::NET_FUZZ::OpenNetFuzzer(const char* server, const uint16 port)
{
	if (!net_tcp.tcp_connect(server, port)) {
		fprintf(stderr, "[-] TCP connect Error\n");
		return(false);
	}

	return(true);
}

void RD_FUZZER::NET_FUZZ::CloseNetFuzzer()
{
	net_tcp.tcp_disconnect();
}

void RD_FUZZER::NET_FUZZ::NetFuzzing()
{
	char* data = NULL;
	dword data_len = 0;

	net_tcp.tcp_send(data, data_len);
}
