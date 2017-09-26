#pragma once

#define FileFormat		0
#define RDPNetwork		1
#define SniffNetwork	2
#define NetFuzzer		3

bool CallFileFuzzer(const char* config_file);
bool CallRDPFuzzer(const char* config_file);
bool CallSniffer(const char* config_file);
bool CallNetFuzzer(const char* config_file);
