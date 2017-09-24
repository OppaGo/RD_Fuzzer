#include "fuzzer.h"
#include "packet_header.h"
#include <stdio.h>

#define RDP_PROTOCOL 3389
static DWORD64 filterfunc(const u_char* packet)
{
	DWORD64 offset = 0;
	const u_char* packet_ptr = packet;

	if (((pether_h)packet_ptr)->Type == TYPE_IP) {
		offset += ETHERNET_SIZE;
		packet_ptr += offset;
		if (((pip_h)packet_ptr)->protocol == TCP_PROTOCOL) {
			offset += (((pip_h)packet_ptr)->length * 4);
			packet_ptr += offset;
			if (((ptcp_h)packet_ptr)->source == htons(RDP_PROTOCOL)) {
				offset += (((ptcp_h)packet_ptr)->length * 4);
			}
			else offset = 0;
		}
		else offset = 0;
	}

	return offset;
}

bool RD_FUZZER::RD_NETFUZZER::OpenSniffer(const char * dev, bool finddev)
{
	if (!sniff.OpenSniff(dev, finddev)) {
		fprintf(stderr, "[-] Error : %s\n", sniff.GetError());
		return(false);
	}

	return(true);
}

void RD_FUZZER::RD_NETFUZZER::CloseSniffer()
{
	sniff.CloseSniff();
}

void RD_FUZZER::RD_NETFUZZER::WriteFile(const char* data, const DWORD64 data_len)
{
	FILE* fp = NULL;
	char file_name[64] = { 0, };

	sprintf_s(file_name, "sample_%u", sniff_file_count);

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

RD_FUZZER::RD_NETFUZZER::RD_NETFUZZER()
{
	sniff_file_count = 0;
}

void RD_FUZZER::RD_NETFUZZER::Sniffing_for_File(const char * filter_exp, bpf_u_int32 net, DWORD64(*filterfunc)(const u_char *packet))
{
	const u_char* packet_data;
	DWORD64 packet_data_len;

	if (!sniff.Set_Filter(filter_exp/* "port 3389" */, 0)) {
		fprintf(stderr, "[-] Error : %s\n", sniff.GetError());
		return;
	}

	packet_data = sniff.GetPacketData(filterfunc);
	if (packet_data == NULL) {
		fprintf(stderr, "[-] packet_next_ex() error\n");
		return;
	}

	packet_data_len = sniff.GetPacketDataLen();
	WriteFile((const char*)packet_data, packet_data_len);
}

