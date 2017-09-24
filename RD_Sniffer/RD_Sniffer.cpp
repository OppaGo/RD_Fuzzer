#include "RD_Sniffer.h"
#include "packet_header.h"

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

RD_SNIFFER_API PSniffer OpenSniffer()
{
	RD_FUZZER::RD_SNIFFER *rd_sniffer = new RD_FUZZER::RD_SNIFFER();

	return rd_sniffer;
}

RD_SNIFFER_API void CloseSniffer(PSniffer psniff)
{
	delete (RD_FUZZER::RD_SNIFFER*)psniff;
}

RD_SNIFFER_API void Sniffing(PSniffer psniff, const char* file_path)
{
	RD_FUZZER::RD_SNIFFER *rd_sniffer = (RD_FUZZER::RD_SNIFFER*) psniff;

	rd_sniffer->Sniffing_for_File(file_path, "port 3389", 0, filterfunc);
}
