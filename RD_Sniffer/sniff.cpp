#include "sniff.h"
#include "packet_header.h"

RD_FUZZER::SNIFF::SNIFF()
{
	handle = NULL;
	dev = NULL;
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	memset(&fp, 0, sizeof(struct bpf_program));
	memset(&header, 0, sizeof(struct pcap_pkthdr));
	packet = NULL;
	//packet_data = NULL;
	packet_data_len = 0;
}

char * RD_FUZZER::SNIFF::Find_Device()
{
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return NULL;
	}

	return dev;
}

bool RD_FUZZER::SNIFF::Set_Filter(const char * filter_exp, bpf_u_int32 net)
{
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) 
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(false);
	}
	if (pcap_setfilter(handle, &fp) == -1) 
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(false);
	}

	return(true);
}

bool RD_FUZZER::SNIFF::OpenSniff(const char * dev, bool finddev)
{
	handle = pcap_open_live((finddev)? Find_Device():dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(false);
	}

	return(true);
}

const u_char * RD_FUZZER::SNIFF::GetPacketData(DWORD64(*filterfunc)(const u_char *packet))
{
	int result = 0;
	DWORD64 offset = 0;

	while (1) {
		result = pcap_next_ex(handle, (struct pcap_pkthdr **)&header, &packet);

		if (result == 0) continue;
		else if (result == 1) {
			offset = (*filterfunc)(packet);
			
			if (offset != 0) {
				packet_data_len = ((pip_h)(packet + ETHERNET_SIZE))->total_len;
				break;
			}
		}
		else if (result == -1) {
			fprintf(stderr, "[-] Error : %s\n", pcap_geterr(handle));
			packet_data_len = 0;

			return NULL;
		}
		else {
			fprintf(stderr, "[-] Unknown Error\n");
			packet_data_len = 0;

			return NULL;
		}
	}

	return packet + offset;
}

DWORD64 RD_FUZZER::SNIFF::GetPacketDataLen()
{
	return packet_data_len;
}

void RD_FUZZER::SNIFF::CloseSniff()
{
	pcap_close(handle);
}

const char * RD_FUZZER::SNIFF::GetError()
{
	return((const char*)errbuf);
}
