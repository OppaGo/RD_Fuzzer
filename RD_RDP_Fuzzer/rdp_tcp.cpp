#include "rdp_tcp.h"


namespace RD_FUZZER
{
	RDP_TCP::RDP_TCP()
	{
		sock = NULL;
		memset(&in_stream, 0, sizeof(struct stream));
		for (dword i = 0; i < STREAM_COUNT; i++)
			memset(&out_stream[i], 0, sizeof(struct stream));
		tcp_port_rdp = TCP_PORT_RDP;
	}

	RDP_TCP::~RDP_TCP()
	{
		tcp_reset_state();
	}

	RD_BOOL RDP_TCP::tcp_can_send(int sck, int millis)
	{
		fd_set wfds;
		struct timeval time;
		int sel_count;

		time.tv_sec = millis / 1000;
		time.tv_usec = (millis * 1000) % 1000000;
		FD_ZERO(&wfds);
		FD_SET(sck, &wfds);
		sel_count = select(sck + 1, 0, &wfds, 0, &time);
		if (sel_count > 0)
		{
			return True;
		}
		return False;
	}

	void RDP_TCP::tcp_reset_state(void)
	{
		int i;

		sock = -1;		/* reset socket */

		/* Clear the incoming stream */
		if (in_stream.data != NULL)
			xfree(in_stream.data);
		in_stream.p = NULL;
		in_stream.end = NULL;
		in_stream.data = NULL;
		in_stream.size = 0;
		in_stream.iso_hdr = NULL;
		in_stream.mcs_hdr = NULL;
		in_stream.sec_hdr = NULL;
		in_stream.rdp_hdr = NULL;
		in_stream.channel_hdr = NULL;

		/* Clear the outgoing stream(s) */
		for (i = 0; i < STREAM_COUNT; i++)
		{
			if (out_stream[i].data != NULL)
				xfree(out_stream[i].data);
			out_stream[i].p = NULL;
			out_stream[i].end = NULL;
			out_stream[i].data = NULL;
			out_stream[i].size = 0;
			out_stream[i].iso_hdr = NULL;
			out_stream[i].mcs_hdr = NULL;
			out_stream[i].sec_hdr = NULL;
			out_stream[i].rdp_hdr = NULL;
			out_stream[i].channel_hdr = NULL;
		}
	}

	STREAM RDP_TCP::tcp_init(uint32 maxlen)
	{
		static int cur_stream_id = 0;
		STREAM result = NULL;

#ifdef WITH_SCARD
		scard_lock(SCARD_LOCK_TCP);
#endif
		result = &out_stream[cur_stream_id];
		cur_stream_id = (cur_stream_id + 1) % STREAM_COUNT;

		mutator.SetMaxDummySize(512);

		if (maxlen + mutator.GetMaxDummySize() > result->size)
		{
			result->data = (uint8 *)xrealloc(result->data, maxlen + mutator.GetMaxDummySize());
			result->size = maxlen  + mutator.GetMaxDummySize();
		}

		result->p = result->data;
		result->end = result->data + result->size;
#ifdef WITH_SCARD
		scard_unlock(SCARD_LOCK_TCP);
#endif
		return result;
	}

	void RDP_TCP::tcp_send(STREAM s)
	{
		int length = s->end - s->data;
		int sent, total = 0;

#ifdef WITH_SCARD
		scard_lock(SCARD_LOCK_TCP);
#endif
		while (total < length)
		{
			sent = send(sock, (const char*)s->data + total, length - total, 0);
			if (sent <= 0)
			{
				if (sent == -1 && TCP_BLOCKS)
				{
					tcp_can_send(sock, 100);
					sent = 0;
				}
				else
				{
					error("send: %s\n", TCP_STRERROR);
					return;
				}
			}
#ifdef PRINT_DEBUG
			hexdump(s->data + total, sent);
			printf("\n");
#endif
			total += sent;
		}
#ifdef WITH_SCARD
		scard_unlock(SCARD_LOCK_TCP);
#endif
	}

	STREAM RDP_TCP::tcp_recv(STREAM s, uint32 length)
	{
		uint32 new_length, end_offset, p_offset;
		int rcvd = 0;

		if (s == NULL)
		{
			/* read into "new" stream */
			if (length > in_stream.size)
			{
				in_stream.data = (uint8 *)xrealloc(in_stream.data, length);
				in_stream.size = length;
			}
			in_stream.end = in_stream.p = in_stream.data;
			s = &in_stream;
		}
		else
		{
			/* append to existing stream */
			new_length = (s->end - s->data) + length;
			if (new_length > s->size)
			{
				p_offset = s->p - s->data;
				end_offset = s->end - s->data;
				s->data = (uint8 *)xrealloc(s->data, new_length);
				s->size = new_length;
				s->p = s->data + p_offset;
				s->end = s->data + end_offset;
			}
		}

		while (length > 0)
		{
			//if (!ui_select(sock))
			//	/* User quit */
			//	return NULL;

			rcvd = recv(sock, (char*)s->end, length, 0);
			if (rcvd < 0)
			{
				if (rcvd == -1 && TCP_BLOCKS)
				{
					rcvd = 0;
				}
				else
				{
					error("recv: %s\n", TCP_STRERROR);
					return NULL;
				}
			}
			else if (rcvd == 0)
			{
				error("Connection closed\n");
				return NULL;
			}

			s->end += rcvd;
			length -= rcvd;
		}

		return s;
	}

	RD_BOOL RDP_TCP::tcp_connect(char * server)
	{
		socklen_t option_len;
		uint32 option_value;
		int i;

#ifdef IPv6

		int n;
		struct addrinfo hints, *res, *ressave;
		char tcp_port_rdp_s[10];

		snprintf(tcp_port_rdp_s, 10, "%d", tcp_port_rdp);

		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		if ((n = getaddrinfo(server, tcp_port_rdp_s, &hints, &res)))
		{
			error("getaddrinfo: %s\n", gai_strerror(n));
			return False;
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
			return False;
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
			return False;
		}

		if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
			fprintf(stderr, "WSAStartup Error\n");
			return False;
		}

		if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
		{
			error("socket: %s\n", TCP_STRERROR);
			return False;
		}

		servaddr.sin_family = AF_INET;
		servaddr.sin_port = htons((uint16)tcp_port_rdp);

		if (connect(
			sock,
			(struct sockaddr *) &servaddr,
			sizeof(struct sockaddr)) == SOCKET_ERROR)
		{
			error("connect: %s\n", TCP_STRERROR);
			TCP_CLOSE(sock);
			return False;
		}

#endif /* IPv6 */

		option_value = 1;
		option_len = sizeof(option_value);
		setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&option_value, option_len);
		/* receive buffer must be a least 16 K */
		if (getsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *)&option_value, &option_len) == 0)
		{
			if (option_value < (1024 * 16))
			{
				option_value = 1024 * 16;
				option_len = sizeof(option_value);
				setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char *)&option_value,
					option_len);
			}
		}

		in_stream.size = 4096;
		in_stream.data = (uint8 *)xmalloc(in_stream.size);

		for (i = 0; i < STREAM_COUNT; i++)
		{
			out_stream[i].size = 4096;
			out_stream[i].data = (uint8 *)xmalloc(out_stream[i].size);
		}

		return True;
	}

	RD_BOOL RDP_TCP::tcp_connect(char * server, int port)
	{
		socklen_t option_len;
		uint32 option_value;
		int i;

#ifdef IPv6

		int n;
		struct addrinfo hints, *res, *ressave;
		char tcp_port_rdp_s[10];

		snprintf(tcp_port_rdp_s, 10, "%d", tcp_port_rdp);

		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		if ((n = getaddrinfo(server, tcp_port_rdp_s, &hints, &res)))
		{
			error("getaddrinfo: %s\n", gai_strerror(n));
			return False;
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
			return False;
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
			return False;
		}

		if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
			fprintf(stderr, "WSAStartup Error\n");
			return False;
		}

		if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
		{
			error("socket: %s\n", TCP_STRERROR);
			return False;
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
			return False;
		}

#endif /* IPv6 */

		option_value = 1;
		option_len = sizeof(option_value);
		setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&option_value, option_len);
		/* receive buffer must be a least 16 K */
		if (getsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *)&option_value, &option_len) == 0)
		{
			if (option_value < (1024 * 16))
			{
				option_value = 1024 * 16;
				option_len = sizeof(option_value);
				setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char *)&option_value,
					option_len);
			}
		}

		in_stream.size = 4096;
		in_stream.data = (uint8 *)xmalloc(in_stream.size);

		for (i = 0; i < STREAM_COUNT; i++)
		{
			out_stream[i].size = 4096;
			out_stream[i].data = (uint8 *)xmalloc(out_stream[i].size);
		}

		return True;
	}

	void RDP_TCP::tcp_disconnect(void)
	{
		TCP_CLOSE(sock);
	}

	char * RDP_TCP::tcp_get_address()
	{
		static char ipaddr[32];
		struct sockaddr_in sockaddr;
		socklen_t len = sizeof(sockaddr);
		if (getsockname(sock, (struct sockaddr *) &sockaddr, &len) == 0)
		{
			uint8 *ip = (uint8 *)& sockaddr.sin_addr;
			sprintf_s(ipaddr, 32, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
		}
		else strcpy_s(ipaddr, 32, "127.0.0.1");

		return ipaddr;
	}
}
