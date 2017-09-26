#include "mcs.h"


namespace RD_FUZZER
{
	/*
	##############################################################
	*/

	RDP_MCS::RDP_MCS() : RDP_ISO()
	{
		mcs_userid = 0;
		memset(channels, 0, sizeof(channels));
		num_channels = 0;
	}

	RDP_MCS::~RDP_MCS()
	{
		mcs_reset_state();
	}

	bool RDP_MCS::mcs_Init_config_from_File(const char * config_file)
	{
		if (!iso_Init_config_from_File(config_file))
			return(false);

		return(true);
	}

	STREAM RDP_MCS::mcs_init(int length)
	{
		STREAM s;

		s = iso_init(length + 8);
		s_push_layer(s, mcs_hdr, 8);

		return s;
	}

	void RDP_MCS::mcs_send_to_channel(STREAM s, uint16 channel)
	{
		uint16 length;

		s_pop_layer(s, mcs_hdr);
		length = s->end - s->p - 8;
		length |= 0x8000;

		out_uint8(s, (MCS_SDRQ << 2));
		out_uint16_be(s, mcs_userid);
		out_uint16_be(s, channel);
		out_uint8(s, 0x70);	/* flags */
		out_uint16_be(s, length);

		iso_send(s);
	}

	void RDP_MCS::mcs_send(STREAM s)
	{
		mcs_send_to_channel(s, MCS_GLOBAL_CHANNEL);
	}

	STREAM RDP_MCS::mcs_recv(uint16 * channel, uint8 * rdpver)
	{
		uint8 opcode, appid, length;
		STREAM s;

		s = iso_recv(rdpver);
		if (s == NULL)
			return NULL;
		if (rdpver != NULL)
			if (*rdpver != 3)
				return s;
		in_uint8(s, opcode);
		appid = opcode >> 2;
		if (appid != MCS_SDIN)
		{
			if (appid != MCS_DPUM)
			{
				error("expected data, got %d\n", opcode);
			}
			return NULL;
		}
		in_uint8s(s, 2);	/* userid */
		in_uint16_be(s, *channel);
		in_uint8s(s, 1);	/* flags */
		in_uint8(s, length);
		if (length & 0x80)
			in_uint8s(s, 1);	/* second byte of length */
		return s;
	}

	STREAM RDP_MCS::mcs_connect(char * server, STREAM mcs_data, char * username)
	{
		if (!iso_connect(server, username))
			return mcs_data;

		mcs_send_connect_initial(mcs_data);

		return mcs_recv_connect_response(mcs_data);
	}

	STREAM RDP_MCS::mcs_connect(char * server, uint16 port, STREAM mcs_data, char * username)
	{
		if (!iso_connect(server, port, username))
			return mcs_data;

		mcs_send_connect_initial(mcs_data);

		return mcs_recv_connect_response(mcs_data);
	}

	RD_BOOL RDP_MCS::mcs_connect_final() {
		mcs_send_edrq();

		mcs_send_aurq();
		if (!mcs_recv_aucf(&mcs_userid))
			goto error;

		mcs_send_cjrq(mcs_userid + MCS_USERCHANNEL_BASE);

		if (!mcs_recv_cjcf())
			goto error;

		mcs_send_cjrq(MCS_GLOBAL_CHANNEL);
		if (!mcs_recv_cjcf())
			goto error;

		for (unsigned int i = 0; i < num_channels; i++)
		{
			mcs_send_cjrq(channels[i].mcs_id);
			if (!mcs_recv_cjcf())
				goto error;
		}
		return True;

	error:
		iso_disconnect();
		return False;
	}

	STREAM RDP_MCS::mcs_reconnect(char * server, STREAM mcs_data)
	{
		if (!iso_reconnect(server))
			return False;

		mcs_send_connect_initial(mcs_data);
		return mcs_recv_connect_response(mcs_data);
	}

	void RDP_MCS::mcs_disconnect(void)
	{
		iso_disconnect();
	}

	void RDP_MCS::mcs_reset_state(void)
	{
		mcs_userid = 0;
		iso_reset_state();
	}

	RD_BOOL RDP_MCS::ber_parse_header(STREAM s, int tagval, int * length)
	{
		int tag, len;

		if (tagval > 0xff)
		{
			in_uint16_be(s, tag);
		}
		else
		{
			in_uint8(s, tag);
		}

		if (tag != tagval)
		{
			error("expected tag %d, got %d\n", tagval, tag);
			return False;
		}

		in_uint8(s, len);

		if (len & 0x80)
		{
			len &= ~0x80;
			*length = 0;
			while (len--)
				next_be(s, *length);
		}
		else
			*length = len;

		return s_check(s);
	}

	void RDP_MCS::ber_out_header(STREAM s, int tagval, int length)
	{
		if (tagval > 0xff)
		{
			out_uint16_be(s, tagval);
		}
		else
		{
			out_uint8(s, tagval);
		}

		if (length >= 0x80)
		{
			out_uint8(s, 0x82);
			out_uint16_be(s, length);
		}
		else
			out_uint8(s, length);
	}

	void RDP_MCS::ber_out_integer(STREAM s, int value)
	{
		ber_out_header(s, BER_TAG_INTEGER, 2);
		out_uint16_be(s, value);
	}

	void RDP_MCS::mcs_out_domain_params(STREAM s, int max_channels, int max_users, int max_tokens, int max_pdusize)
	{
		ber_out_header(s, MCS_TAG_DOMAIN_PARAMS, 32);
		ber_out_integer(s, max_channels);
		ber_out_integer(s, max_users);
		ber_out_integer(s, max_tokens);
		ber_out_integer(s, 1);	/* num_priorities */
		ber_out_integer(s, 0);	/* min_throughput */
		ber_out_integer(s, 1);	/* max_height */
		ber_out_integer(s, max_pdusize);
		ber_out_integer(s, 2);	/* ver_protocol */
	}

	RD_BOOL RDP_MCS::mcs_parse_domain_params(STREAM s)
	{
		int length;

		ber_parse_header(s, MCS_TAG_DOMAIN_PARAMS, &length);
		in_uint8s(s, length);

		return s_check(s);
	}

	void RDP_MCS::mcs_send_connect_initial(STREAM mcs_data)
	{
		int datalen = mcs_data->end - mcs_data->data;
		int length = 9 + 3 * 34 + 4 + datalen;
		STREAM s;

		s = iso_init(length + 5);

		ber_out_header(s, MCS_CONNECT_INITIAL, length);
		ber_out_header(s, BER_TAG_OCTET_STRING, 1);	/* calling domain */
		out_uint8(s, 1);
		ber_out_header(s, BER_TAG_OCTET_STRING, 1);	/* called domain */
		out_uint8(s, 1);

		ber_out_header(s, BER_TAG_BOOLEAN, 1);
		out_uint8(s, 0xff);	/* upward flag */

		mcs_out_domain_params(s, 34, 2, 0, 0xffff);	/* target params */
		mcs_out_domain_params(s, 1, 1, 1, 0x420);	/* min params */
		mcs_out_domain_params(s, 0xffff, 0xfc17, 0xffff, 0xffff);	/* max params */

		ber_out_header(s, BER_TAG_OCTET_STRING, datalen);
		out_uint8p(s, mcs_data->data, datalen);

		s_mark_end(s);
		iso_send(s);
	}

	STREAM RDP_MCS::mcs_recv_connect_response(STREAM mcs_data)
	{
		uint8 result;
		int length;
		STREAM s;

		s = iso_recv(NULL);
		if (s == NULL)
			return False;

		ber_parse_header(s, MCS_CONNECT_RESPONSE, &length);

		ber_parse_header(s, BER_TAG_RESULT, &length);
		in_uint8(s, result);
		if (result != 0)
		{
			error("MCS connect: %d\n", result);
			return False;
		}

		ber_parse_header(s, BER_TAG_INTEGER, &length);
		in_uint8s(s, length);	/* connect id */
		mcs_parse_domain_params(s);

		ber_parse_header(s, BER_TAG_OCTET_STRING, &length);

		return s;
		//sec_process_mcs_data(s);
		/*
		if (length > mcs_data->size)
		{
		error("MCS data length %d, expected %d\n", length,
		mcs_data->size);
		length = mcs_data->size;
		}

		in_uint8a(s, mcs_data->data, length);
		mcs_data->p = mcs_data->data;
		mcs_data->end = mcs_data->data + length;
		*/
		//return s_check_end(s);
	}

	void RDP_MCS::mcs_send_edrq(void)
	{
		STREAM s;

		s = iso_init(5);

		out_uint8(s, (MCS_EDRQ << 2));
		out_uint16_be(s, 1);	/* height */
		out_uint16_be(s, 1);	/* interval */

		s_mark_end(s);
		iso_send(s);
	}

	void RDP_MCS::mcs_send_aurq(void)
	{
		STREAM s;

		s = iso_init(1);

		out_uint8(s, (MCS_AURQ << 2));

		s_mark_end(s);
		iso_send(s);
	}

	RD_BOOL RDP_MCS::mcs_recv_aucf(uint16 * mcs_userid)
	{
		uint8 opcode, result;
		STREAM s;

		s = iso_recv(NULL);
		if (s == NULL)
			return False;

		in_uint8(s, opcode);
		if ((opcode >> 2) != MCS_AUCF)
		{
			error("expected AUcf, got %d\n", opcode);
			return False;
		}

		in_uint8(s, result);
		if (result != 0)
		{
			error("AUrq: %d\n", result);
			return False;
		}

		if (opcode & 2)
			in_uint16_be(s, *mcs_userid);

		return s_check_end(s);
	}

	void RDP_MCS::mcs_send_cjrq(uint16 chanid)
	{
		STREAM s;

		DEBUG_RDP5(("Sending CJRQ for channel #%d\n", chanid));

		s = iso_init(5);

		out_uint8(s, (MCS_CJRQ << 2));
		out_uint16_be(s, mcs_userid);
		out_uint16_be(s, chanid);

		s_mark_end(s);
		iso_send(s);
	}

	RD_BOOL RDP_MCS::mcs_recv_cjcf(void)
	{
		uint8 opcode, result;
		STREAM s;

		s = iso_recv(NULL);
		if (s == NULL)
			return False;

		in_uint8(s, opcode);
		if ((opcode >> 2) != MCS_CJCF)
		{
			error("expected CJcf, got %d\n", opcode);
			return False;
		}

		in_uint8(s, result);
		if (result != 0)
		{
			error("CJrq: %d\n", result);
			return False;
		}

		in_uint8s(s, 4);	/* mcs_userid, req_chanid */
		if (opcode & 2)
			in_uint8s(s, 2);	/* join_chanid */

		return s_check_end(s);
	}
}
