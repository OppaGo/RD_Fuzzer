#pragma once

#include "tcp.h"
#include "mutator.h"

namespace RD_FUZZER
{
	class NET_FUZZ
	{
	private:

	protected:
		Mutator mutator;
		SNET_TCP net_tcp;

	public:
		NET_FUZZ();
		~NET_FUZZ();
		bool OpenNetFuzzer(const char* server, const uint16 port);
		void CloseNetFuzzer();
		void NetFuzzing();
	};
}
