#pragma once

#include "sniffer.h"

#ifdef RD_SNIFFER_EXPORTS
#define RD_SNIFFER_API __declspec(dllexport)
#else
#define RD_SNIFFER_API __declspec(dllimport)
#endif

typedef void* PSniffer;

extern "C" RD_SNIFFER_API PSniffer OpenSniffer();
extern "C" RD_SNIFFER_API void CloseSniffer(PSniffer psniff);
extern "C" RD_SNIFFER_API void Sniffing(PSniffer psniff, const char* file_path);
