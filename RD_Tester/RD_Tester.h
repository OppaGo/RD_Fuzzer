#pragma once

#define FileFormat 0
#define RDPNetwork 1
#define SniffNetwork 2

bool CallFileFuzzer();
bool CallRDPFuzzer();
bool CallSniffer(const char* file_path);
