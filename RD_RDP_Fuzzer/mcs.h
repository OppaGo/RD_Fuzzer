#ifndef __MCS_H__
#define __MCS_H__

#include "rdp_tcp.h"

namespace RD_FUZZER
{
	class RDP_ISO : protected RDP_TCP
	{
	protected:
		/* Send a self-contained ISO PDU */
		void iso_send_msg(uint8 code);
		void iso_send_connection_request(char *username);
		/* Receive a message on the ISO layer, return code */
		STREAM iso_recv_msg(uint8 * code, uint8 * rdpver);

	public:
		RDP_ISO();
		/* Initialise ISO transport data packet */
		STREAM iso_init(int length);
		/* Send an ISO data PDU */
		void iso_send(STREAM s);
		/* Receive ISO transport data packet */
		STREAM iso_recv(uint8 * rdpver);
		/* Establish a connection up to the ISO layer */
		RD_BOOL iso_connect(char *server, char *username);
		RD_BOOL iso_connect(char * server, uint16 port, char * username);
		/* Establish a reconnection up to the ISO layer */
		RD_BOOL iso_reconnect(char *server);
		/* Disconnect from the ISO layer */
		void iso_disconnect(void);
		/* reset the state to support reconnecting */
		void iso_reset_state(void);
	};

#define MAX_CHANNELS			6
	class RDP_MCS : protected RDP_ISO
	{
	protected:
		uint16 mcs_userid;
		VCHANNEL channels[MAX_CHANNELS];
		unsigned int num_channels;

	protected:
		/* Parse an ASN.1 BER header */
		RD_BOOL ber_parse_header(STREAM s, int tagval, int *length);
		/* Output an ASN.1 BER header */
		void ber_out_header(STREAM s, int tagval, int length);
		/* Output an ASN.1 BER integer */
		void ber_out_integer(STREAM s, int value);
		/* Output a DOMAIN_PARAMS structure (ASN.1 BER) */
		void mcs_out_domain_params(STREAM s, int max_channels, int max_users, int max_tokens, int max_pdusize);
		/* Parse a DOMAIN_PARAMS structure (ASN.1 BER) */
		RD_BOOL mcs_parse_domain_params(STREAM s);
		/* Send an MCS_CONNECT_INITIAL message (ASN.1 BER) */
		void mcs_send_connect_initial(STREAM mcs_data);
		/* Expect a MCS_CONNECT_RESPONSE message (ASN.1 BER) */
		STREAM mcs_recv_connect_response(STREAM mcs_data);
		/* Send an EDrq message (ASN.1 PER) */
		void mcs_send_edrq(void);
		/* Send an AUrq message (ASN.1 PER) */
		void mcs_send_aurq(void);
		/* Expect a AUcf message (ASN.1 PER) */
		RD_BOOL mcs_recv_aucf(uint16 * mcs_userid);
		/* Send a CJrq message (ASN.1 PER) */
		void mcs_send_cjrq(uint16 chanid);
		/* Expect a CJcf message (ASN.1 PER) */
		RD_BOOL mcs_recv_cjcf(void);

	public:
		RDP_MCS();
		~RDP_MCS();
		/* Initialise an MCS transport data packet */
		STREAM mcs_init(int length);
		/* Send an MCS transport data packet to a specific channel */
		void mcs_send_to_channel(STREAM s, uint16 channel);
		/* Send an MCS transport data packet to the global channel */
		void mcs_send(STREAM s);
		/* Receive an MCS transport data packet */
		STREAM mcs_recv(uint16 * channel, uint8 * rdpver);
		/* Establish a connection up to the MCS layer */
		STREAM mcs_connect(char *server, STREAM mcs_data, char *username);
		STREAM mcs_connect(char *server, uint16 port, STREAM mcs_data, char *username);
		RD_BOOL mcs_connect_final();
		/* Establish a connection up to the MCS layer */
		STREAM mcs_reconnect(char *server, STREAM mcs_data);
		/* Disconnect from the MCS layer */
		void mcs_disconnect(void);
		/* reset the state of the mcs layer */
		void mcs_reset_state(void);
	};
}

#endif
