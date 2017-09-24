#include "tcp.h"
#include "default.h"

#include <cstdio>

namespace RD_FUZZER
{
	SNET_TCP::SNET_TCP()
	{
		sock = NULL;
	}

	SNET_TCP::~SNET_TCP()
	{
		tcp_disconnect();
	}

	bool SNET_TCP::tcp_connect(const char * server, const uint16 port)
	{
#ifdef IPv6

		int n;
		struct addrinfo hints, *res, *ressave;
		char tcp_port_s[10];

		snprintf(tcp_port_s, 10, "%d", tcp_port);

		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		if ((n = getaddrinfo(server, tcp_port_s, &hints, &res)))
		{
			error("getaddrinfo: %s\n", gai_strerror(n));
			return(false);
		}

		ressave = res;
		sock = -1;
		while (res)
		{
			sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
			if (!(sock < 0))
			{
				if (connect(sock, res->ai_addr, res->ai_addrlen) == 0)
					break;
				TCP_CLOSE(sock);
				sock = -1;
			}
			res = res->ai_next;
		}
		freeaddrinfo(ressave);

		if (sock == -1)
		{
			error("%s: unable to connect\n", server);
			return(false);
		}

#else /* no IPv6 support */

		WSADATA wsaData;
		struct hostent *nslookup;
		struct sockaddr_in servaddr;

		ZeroMemory(&servaddr, sizeof(struct sockaddr_in));
		if ((nslookup = gethostbyname(server)) != NULL)
		{
			memcpy(&servaddr.sin_addr, nslookup->h_addr, sizeof(servaddr.sin_addr));
		}
		else if ((servaddr.sin_addr.s_addr = inet_addr(server)) == INADDR_NONE)
		{
			error("%s: unable to resolve host\n", server);
			return(false);
		}

		if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
			fprintf(stderr, "WSAStartup Error\n");
			return(false);
		}

		if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
		{
			error("socket: %s\n", TCP_STRERROR);
			return(false);
		}

		servaddr.sin_family = AF_INET;
		servaddr.sin_port = htons((uint16)port);

		if (connect(
			sock,
			(struct sockaddr *) &servaddr,
			sizeof(struct sockaddr)) == SOCKET_ERROR)
		{
			error("connect: %s\n", TCP_STRERROR);
			TCP_CLOSE(sock);
			return(false);
		}

#endif /* IPv6 */

		return(true);
	}

	void SNET_TCP::tcp_disconnect(void)
	{
		TCP_CLOSE(sock);
	}

	/* Sending TCP packets */
	void SNET_TCP::tcp_send(char * data, DWORD data_len)
	{
		if (send(sock, data, data_len, 0) != data_len)
		{
			fprintf(stderr, "socket send() error!\n");
			return;
		}
	}
}
