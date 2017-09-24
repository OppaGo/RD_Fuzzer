#ifndef __RDP_TCP_H__
#define __RDP_TCP_H__

#include <WinSock2.h>
#include <cstdint>

#ifdef _WIN32
#define socklen_t int
#define TCP_CLOSE(_sck) closesocket(_sck)
#define TCP_STRERROR "tcp error"
#define TCP_BLOCKS (WSAGetLastError() == WSAEWOULDBLOCK)
#else
#define TCP_CLOSE(_sck) close(_sck)
#define TCP_STRERROR strerror(errno)
#define TCP_BLOCKS (errno == EWOULDBLOCK)
#endif

#ifndef INADDR_NONE
#define INADDR_NONE ((unsigned long) -1)
#endif


typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef int8_t int8;
typedef int16_t int16;
typedef int32_t int32;

typedef struct stream* STREAM;

namespace RD_FUZZER
{
	class SNET_TCP
	{
	private:
		SOCKET sock;
		
	protected:

	public:
		SNET_TCP();
		~SNET_TCP();
		/* Establish a connection on the TCP layer */
		bool tcp_connect(const char *server, const uint16 port);
		/* Disconnect on the TCP layer */
		void tcp_disconnect(void);
		/* Sending packets on the TCP layer*/
		void tcp_send(char* data, DWORD data_len);
	};
}

#endif
