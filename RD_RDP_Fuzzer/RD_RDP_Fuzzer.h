#pragma once

#ifdef RD_RDP_FUZZER_EXPORTS
#define RD_RDP_FUZZER_API __declspec(dllexport)
#else
#define RD_RDP_FUZZER_API __declspec(dllimport)
#endif

#include "rdp.h"

typedef void* PRDPFuzzer;

#define Before_Auth 0
#define After_Auth 1

void print_disconnect_reason(uint16 reason);

extern "C" RD_RDP_FUZZER_API PRDPFuzzer OpenRDPFuzzer(const char* config_file = "./config.yaml");
extern "C" RD_RDP_FUZZER_API void CloseRDPFuzzer(PRDPFuzzer prdp);
extern "C" RD_RDP_FUZZER_API RD_BOOL RDPFuzzing(PRDPFuzzer prdp, dword fuzztime);
