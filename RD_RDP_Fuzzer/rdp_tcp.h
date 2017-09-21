#ifndef __RDP_TCP_H__
#define __RDP_TCP_H__

#ifndef _WIN32
#include <unistd.h>		/* select read write close */
#include <sys/socket.h>		/* socket connect setsockopt */
#include <sys/time.h>		/* timeval */
#include <netdb.h>		/* gethostbyname */
#include <netinet/in.h>		/* sockaddr_in */
#include <netinet/tcp.h>	/* TCP_NODELAY */
#include <arpa/inet.h>		/* inet_addr */
#include <errno.h>		/* errno */
#endif

#include "rdesktop.h"
#include "mutator.h"

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

#ifdef WITH_SCARD
#define STREAM_COUNT 8
#else
#define STREAM_COUNT 1
#endif

namespace RD_FUZZER
{
	class RDP_TCP
	{
	private:
		SOCKET sock;
		struct stream in_stream;
		struct stream out_stream[STREAM_COUNT];

	protected:
		char server[64];
		int tcp_port_rdp;
		Mutator mutator;

	public:
		RDP_TCP();
		~RDP_TCP();
		/* Establish a connection on the TCP layer */
		RD_BOOL tcp_connect(char *server);
		RD_BOOL tcp_connect(char *server, int port);
		/* Disconnect on the TCP layer */
		void tcp_disconnect(void);
		/* wait till socket is ready to write or timeout */
		RD_BOOL tcp_can_send(int sck, int millis);
		/* reset the state of the tcp layer, Support for Session Directory */
		void tcp_reset_state(void);
		/* Initialise TCP transport data packet */
		STREAM tcp_init(uint32 maxlen);
		/* Send TCP transport data packet */
		void tcp_send(STREAM s);
		/* Receive a message on the TCP layer */
		STREAM tcp_recv(STREAM s, uint32 length);
		char *tcp_get_address();
	};
}

#endif
