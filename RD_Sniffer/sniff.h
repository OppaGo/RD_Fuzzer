#ifndef __SNIFF_H__
#define __SNIFF_H__

#include <pcap.h>

namespace RD_FUZZER
{
	class SNIFF
	{
	private:
		pcap_t *handle;					/* Session handle */
		char *dev;						/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];
		struct bpf_program fp;			/* The compiled filter */
		struct pcap_pkthdr header;		/* The header that pcap gives us */
		const u_char *packet;			/* The actual packet */
		DWORD64 packet_data_len;

		char* Find_Device();
	protected:

	public:
		SNIFF();
		bool Set_Filter(const char* filter_exp, bpf_u_int32 net);
		bool OpenSniff(const char* dev, bool finddev = true);
		const u_char* GetPacketData(DWORD64 (*filterfunc)(const u_char* packet));
		DWORD64 GetPacketDataLen();
		void CloseSniff();
		const char* GetError();
	};
}
#endif
