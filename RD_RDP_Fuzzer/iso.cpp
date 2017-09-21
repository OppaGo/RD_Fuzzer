#include "mcs.h"

namespace RD_FUZZER
{
	RDP_ISO::RDP_ISO() : RDP_TCP()
	{
	}

	void RDP_ISO::iso_send_msg(uint8 code)
	{
		STREAM s;

		s = tcp_init(11);

		out_uint8(s, 3);	/* version */
		out_uint8(s, 0);	/* reserved */
		out_uint16_be(s, 11);	/* length */

		out_uint8(s, 6);	/* hdrlen */
		out_uint8(s, code);
		out_uint16(s, 0);	/* dst_ref */
		out_uint16(s, 0);	/* src_ref */
		out_uint8(s, 0);	/* class */

		s_mark_end(s);
		tcp_send(s);
	}

	void RDP_ISO::iso_send_connection_request(char * username)
	{
		STREAM s;
		int length = 30 + strlen(username);

		s = tcp_init(length);

		out_uint8(s, 3);	/* version */
		out_uint8(s, 0);	/* reserved */
		out_uint16_be(s, length);	/* length */

		out_uint8(s, length - 5);	/* hdrlen */
		out_uint8(s, ISO_PDU_CR);
		out_uint16(s, 0);	/* dst_ref */
		out_uint16(s, 0);	/* src_ref */
		out_uint8(s, 0);	/* class */

		out_uint8p(s, "Cookie: mstshash=", strlen("Cookie: mstshash="));
		out_uint8p(s, username, strlen(username));

		out_uint8(s, 0x0d);	/* Unknown */
		out_uint8(s, 0x0a);	/* Unknown */

		s_mark_end(s);
		tcp_send(s);
	}

	STREAM RDP_ISO::iso_recv_msg(uint8 * code, uint8 * rdpver)
	{
		STREAM s;
		uint16 length;
		uint8 version;

		s = tcp_recv(NULL, 4);
		if (s == NULL)
			return NULL;
		in_uint8(s, version);
		if (rdpver != NULL)
			*rdpver = version;
		if (version == 3)
		{
			in_uint8s(s, 1);	/* pad */
			in_uint16_be(s, length);
		}
		else
		{
			in_uint8(s, length);
			if (length & 0x80)
			{
				length &= ~0x80;
				next_be(s, length);
			}
		}
		if (length < 4)
		{
			error("Bad packet header\n");
			return NULL;
		}
		s = tcp_recv(s, length - 4);
		if (s == NULL)
			return NULL;
		if (version != 3)
			return s;
		in_uint8s(s, 1);	/* hdrlen */
		in_uint8(s, *code);
		if (*code == ISO_PDU_DT)
		{
			in_uint8s(s, 1);	/* eot */
			return s;
		}
		in_uint8s(s, 5);	/* dst_ref, src_ref, class */
		return s;
	}

	STREAM RDP_ISO::iso_init(int length)
	{
		STREAM s;

		s = tcp_init(length + 7);
		s_push_layer(s, iso_hdr, 7);

		return s;
	}

	void RDP_ISO::iso_send(STREAM s)
	{
		uint16 length;

		s_pop_layer(s, iso_hdr);
		length = s->end - s->p;

		out_uint8(s, 3);	/* version */
		out_uint8(s, 0);	/* reserved */
		out_uint16_be(s, length);

		out_uint8(s, 2);	/* hdrlen */
		out_uint8(s, ISO_PDU_DT);	/* code */
		out_uint8(s, 0x80);	/* eot */

		tcp_send(s);
	}

	STREAM RDP_ISO::iso_recv(uint8 * rdpver)
	{
		STREAM s;
		uint8 code = 0;

		s = iso_recv_msg(&code, rdpver);
		if (s == NULL)
			return NULL;
		if (rdpver != NULL)
			if (*rdpver != 3)
				return s;
		if (code != ISO_PDU_DT)
		{
			error("expected DT, got 0x%x\n", code);
			return NULL;
		}
		return s;
	}

	RD_BOOL RDP_ISO::iso_connect(char * server, char * username)
	{
		uint8 code = 0;

		if (!tcp_connect(server))
			return False;

		iso_send_connection_request(username);

		if (iso_recv_msg(&code, NULL) == NULL)
			return False;

		if (code != ISO_PDU_CC)
		{
			error("expected CC, got 0x%x\n", code);
			tcp_disconnect();
			return False;
		}

		return True;
	}

	RD_BOOL RDP_ISO::iso_connect(char * server, uint16 port, char * username)
	{
		uint8 code = 0;

		if (!tcp_connect(server, port))
			return False;

		iso_send_connection_request(username);

		if (iso_recv_msg(&code, NULL) == NULL)
			return False;

		if (code != ISO_PDU_CC)
		{
			error("expected CC, got 0x%x\n", code);
			tcp_disconnect();
			return False;
		}

		return True;
	}

	RD_BOOL RDP_ISO::iso_reconnect(char * server)
	{
		uint8 code = 0;

		if (!tcp_connect(server))
			return False;

		iso_send_msg(ISO_PDU_CR);

		if (iso_recv_msg(&code, NULL) == NULL)
			return False;

		if (code != ISO_PDU_CC)
		{
			error("expected CC, got 0x%x\n", code);
			tcp_disconnect();
			return False;
		}

		return True;
	}

	void RDP_ISO::iso_disconnect(void)
	{
		iso_send_msg(ISO_PDU_DR);
		tcp_disconnect();
	}

	void RDP_ISO::iso_reset_state(void)
	{
		tcp_reset_state();
	}
}
