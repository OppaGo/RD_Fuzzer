#ifndef __FUZZER_H__
#define __FUZZER_H__

#include "sniff.h"

namespace RD_FUZZER
{
	class RD_SNIFFER:public SNIFF
	{
	private:
		//SNIFF sniff;
		DWORD sniff_file_count;

	private:
		bool OpenSniffer(const char * dev, bool finddev);
		void CloseSniffer();
		void WriteFile(const char* file_path, const char* data, const DWORD64 data_len);

	protected:
		
	public:
		RD_SNIFFER();
		void Sniffing_for_File(const char* file_path, const char* filter_exp, bpf_u_int32 net, DWORD64(*filterfunc)(const u_char* packet));
	};
}
#endif
