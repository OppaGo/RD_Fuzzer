#include "sniffer.h"
#include <stdio.h>

bool RD_FUZZER::RD_SNIFFER::OpenSniffer(const char * dev, bool finddev)
{
	if (!OpenSniff(dev, finddev)) {
		fprintf(stderr, "[-] Error : %s\n", GetError());
		return(false);
	}

	return(true);
}

void RD_FUZZER::RD_SNIFFER::CloseSniffer()
{
	CloseSniff();
}

void RD_FUZZER::RD_SNIFFER::WriteFile(const char* file_path, const char* data, const DWORD64 data_len)
{
	FILE* fp = NULL;
	char file_name[MAX_PATH] = { 0, };

	if (strlen(file_path) > 200) return;
	sprintf_s(file_name, "%s\\sample_%u", file_path, sniff_file_count);

	fopen_s(&fp, file_name, "wb");
	if (fp == NULL) {
		fprintf(stderr, "[-] fopen_s() error\n");
		return;
	}

	if (fwrite(data, 1, data_len, fp) != data_len) {
		fprintf(stderr, "[-] fwrite() error\n");
		return;
	}

	fclose(fp);
}

RD_FUZZER::RD_SNIFFER::RD_SNIFFER()
{
	sniff_file_count = 0;
}

void RD_FUZZER::RD_SNIFFER::Sniffing_for_File(const char* file_path, const char * filter_exp, bpf_u_int32 net, DWORD64(*filterfunc)(const u_char *packet))
{
	const u_char* packet_data;
	DWORD64 packet_data_len;

	if (!OpenSniffer(NULL, true)) {
		goto GetError;
	}

	if (!Set_Filter(filter_exp/* "port 3389" */, 0)) {
		goto GetError;
	}

	packet_data = GetPacketData(filterfunc);
	if (packet_data == NULL) {
		fprintf(stderr, "[-] packet_next_ex() error\n");
		return;
	}

	packet_data_len = GetPacketDataLen();
	WriteFile(file_path, (const char*)packet_data, packet_data_len);

	CloseSniffer();
	return;

GetError:
	fprintf(stderr, "[-] Error : %s\n", GetError());
	return;
}

