#pragma once

#include "tcp.h"
#include "mutator.h"

namespace RD_FUZZER
{
	class NET_FUZZ
	{
	private:
		std::string	 orig_path;
		std::string* orig_file_list;
		dword dummy_size_max;

		dword GetFileList();
		dword ReadPacketFile(char* data, dword list_select);

	protected:
		Mutator mutator;
		SNET_TCP net_tcp;

	public:
		NET_FUZZ();
		NET_FUZZ(const char* orig_path);
		~NET_FUZZ();
		void SetMaxDummySize(dword max);
		bool OpenNetFuzzer(const char* server, const uint16 port);
		void CloseNetFuzzer();
		void NetFuzzing();
	};
}
