#pragma once


#ifdef RD_FILE_FUZZER_EXPORTS
#define RD_FILE_FUZZER_API __declspec(dllexport)
#else
#define RD_FILE_FUZZER_API __declspec(dllimport)
#endif

#include "file_fuzzer.h"

typedef void* PFileFuzzer;

extern "C" RD_FILE_FUZZER_API PFileFuzzer OpenFileFuzzer(const char* config_file = "./config.yaml");
extern "C" RD_FILE_FUZZER_API bool File_Fuzzer_Loop(PFileFuzzer file_fuzzer);
extern "C" RD_FILE_FUZZER_API void CloseFileFuzzer(PFileFuzzer file_fuzzer);
