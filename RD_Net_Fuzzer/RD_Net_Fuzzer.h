#pragma once

#include "Network_Fuzzer.h"

#ifdef RD_NET_FUZZER_EXPORTS
#define RD_NET_FUZZER_API __declspec(dllexport)
#else
#define RD_NET_FUZZER_API __declspec(dllimport)
#endif

typedef void* PNetFuzzer;

extern "C" RD_NET_FUZZER_API PNetFuzzer OpenNetFuzzer(const char* config_file = "./config.yaml");
extern "C" RD_NET_FUZZER_API void CloseNetFuzzer(PNetFuzzer pnetfuzz);
extern "C" RD_NET_FUZZER_API void NetworkFuzzing(PNetFuzzer pnetfuzz);
