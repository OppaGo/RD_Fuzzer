#pragma once

#include "sniff.h"

#ifdef RD_SNIFF_NET_FUZZER_EXPORTS
#define RD_SNIFF_NET_FUZZER_API __declspec(dllexport)
#else
#define RD_SNIFF_NET_FUZZER_API __declspec(dllimport)
#endif

typedef void* PSNetFuzzer;
typedef void* PSniffer;

extern "C" RD_SNIFF_NET_FUZZER_API PSNetFuzzer OpenSNetFuzzer(const char* config_file = "./config.yaml");
extern "C" RD_SNIFF_NET_FUZZER_API void CloseSNetFuzzer(PSNetFuzzer prdp);
extern "C" RD_SNIFF_NET_FUZZER_API bool SNetFuzzing(PSNetFuzzer prdp);
