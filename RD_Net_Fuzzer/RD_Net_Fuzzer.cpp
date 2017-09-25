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
