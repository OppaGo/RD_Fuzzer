#ifndef __RDP_H__
#define __RDP_H__

#include <ctime>
#ifndef _WIN32
#include <errno.h>
#include <unistd.h>
#endif
#include "secure.h"

#ifdef HAVE_ICONV
#ifdef HAVE_ICONV_H
#include <iconv.h>
#endif

#ifndef ICONV_CONST
#define ICONV_CONST ""
#endif
#endif

namespace RD_FUZZER
{
	class RDP :protected RDP_SEC
	{
	private:
#if WITH_DEBUG
		uint32 g_packetno;
#endif

#ifdef HAVE_ICONV
		RD_BOOL g_iconv_works = True;
#endif

		uint8 caps_0x0d[84] = {
			0x01, 0x00, 0x00, 0x00, 0x09, 0x04, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00
		};

		uint8 caps_0x0c[4] = { 0x01, 0x00, 0x00, 0x00 };

		uint8 caps_0x0e[4] = { 0x01, 0x00, 0x00, 0x00 };

		uint8 caps_0x10[48] = {
			0xFE, 0x00, 0x04, 0x00, 0xFE, 0x00, 0x04, 0x00,
			0xFE, 0x00, 0x08, 0x00, 0xFE, 0x00, 0x08, 0x00,
			0xFE, 0x00, 0x10, 0x00, 0xFE, 0x00, 0x20, 0x00,
			0xFE, 0x00, 0x40, 0x00, 0xFE, 0x00, 0x80, 0x00,
			0xFE, 0x00, 0x00, 0x01, 0x40, 0x00, 0x00, 0x08,
			0x00, 0x01, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00
		};

		uint16 mcs_userid;
		char codepage[16];
		RD_BOOL bitmap_compression;
		RD_BOOL orders;
		RD_BOOL desktop_save;
		RD_BOOL polygon_ellipse_orders;
		uint32 rdp5_performanceflags;
		RD_BOOL use_rdp5;
		uint16 server_rdp_version = 4;
		RD_BOOL bitmap_cache;
		RD_BOOL bitmap_cache_persist_enable;
		RD_BOOL numlock_sync;

		RDPCOMP mppc_dict;

		uint8 *next_packet;
		uint32 rdp_shareid;

		/* Connection Information */
		//char server[64];
		uint32 flags = RDP_LOGON_NORMAL;
		char domain[16];
		char password[64];
		char command[256];
		char directory[256];
		/* END Connection Information */

		/* Session Directory support */
		RD_BOOL redirect;
		char redirect_server[64];
		char redirect_domain[16];
		char redirect_password[64];
		char redirect_username[64];
		char redirect_cookie[128];
		uint32 redirect_flags;
		/* END Session Directory support */

		bool isconfigured;

	protected:
		void rdp5_process(STREAM s);
		/* Receive an RDP packet */
		STREAM rdp_recv(uint8 * type);
		/* Initialise an RDP data packet */
		STREAM rdp_init_data(int maxlen);
		/* Send an RDP data packet */
		void rdp_send_data(STREAM s, uint8 data_pdu_type);
		/* Parse a logon info packet */
		void rdp_send_logon_info(uint32 flags, char *domain, char *user, char *password, char *program, char *directory);
		/* Send a control PDU */
		void rdp_send_control(uint16 action);
		/* Send a synchronisation PDU */
		void rdp_send_synchronise(void);
		/* Send persistent bitmap cache enumeration PDU's */
		void rdp_enum_bmpcache2(void);
		/* Send an (empty) font information PDU */
		void rdp_send_fonts(uint16 seq);
		/* Output general capability set */
		void rdp_out_general_caps(STREAM s);
		/* Output bitmap capability set */
		void rdp_out_bitmap_caps(STREAM s);
		/* Output bitmap cache capability set */
		void rdp_out_bmpcache_caps(STREAM s);
		/* Output bitmap cache v2 capability set */
		void rdp_out_bmpcache2_caps(STREAM s);
		/* Output control capability set */
		void rdp_out_control_caps(STREAM s);
		/* Output activation capability set */
		void rdp_out_activate_caps(STREAM s);
		/* Output pointer capability set */
		void rdp_out_pointer_caps(STREAM s);
		/* Output share capability set */
		void rdp_out_share_caps(STREAM s);
		/* Output colour cache capability set */
		void rdp_out_colcache_caps(STREAM s);
		/* Output unknown capability sets */
		void rdp_out_unknown_caps(STREAM s, uint16 id, uint16 length, uint8 * caps);
		/* Send a confirm active PDU */
		void rdp_send_confirm_active(void);
		/* Process a general capability set */
		void rdp_process_general_caps(STREAM s);
		/* Process a bitmap capability set */
		void rdp_process_bitmap_caps(STREAM s);
		/* Process server capabilities */
		void rdp_process_server_caps(STREAM s, uint16 length);
		/* Respond to a demand active PDU(Protocol Data Unit) */
		void process_demand_active(STREAM s);
		/* Process a pointer PDU */
		void process_pointer_pdu(STREAM s);
		/* Process an update PDU */
		void process_update_pdu(STREAM s);
		/* Process data PDU */
		RD_BOOL process_data_pdu(STREAM s, uint32 * ext_disc_reason);
		/* Process redirect PDU from Session Directory */
		RD_BOOL process_redirect_pdu(STREAM s /*, uint32 * ext_disc_reason */);
		int mppc_expand(uint8 * data, uint32 clen, uint8 ctype, uint32 * roff, uint32 * rlen);

	public:
		RDP();
		~RDP();
		/* Send a single input event */
		void rdp_send_input(uint32 time, uint16 message_type, uint16 device_flags, uint16 param1, uint16 param2);
		/* Send a client window information PDU */
		void rdp_send_client_window_status(int status);
		/* Output order capability set */
		void rdp_out_order_caps(STREAM s);
		/* Process a colour pointer PDU */
		void process_colour_pointer_pdu(STREAM s);
		/* Process a cached pointer PDU */
		void process_cached_pointer_pdu(STREAM s);
		/* Process a system pointer PDU */
		void process_system_pointer_pdu(STREAM s);
		/* Process bitmap updates */
		void process_bitmap_updates(STREAM s);
		/* Process a palette update */
		void process_palette(STREAM s);
		/* Process a disconnect PDU */
		void process_disconnect_pdu(STREAM s, uint32 * ext_disc_reason);
		/* Process incoming packets, nevers gets out of here till app is done */
		void rdp_main_loop(RD_BOOL * deactivated, uint32 * ext_disc_reason);
		/* used in uiports and rdp_main_loop, processes the rdp packets waiting */
		RD_BOOL rdp_loop(RD_BOOL * deactivated, uint32 * ext_disc_reason);
		/* Establish a connection up to the RDP layer */
		RD_BOOL rdp_connect();
		RD_BOOL rdp_connect(char *server, uint16 port, uint32 flags, char *domain, char * username, char *password, char *command, char *directory, uint16 server_rdp_version);
		/* Establish a reconnection up to the RDP layer */
		RD_BOOL rdp_reconnect();
		RD_BOOL rdp_reconnect(char *server, uint16 port, uint32 flags, char *domain, char * username, char *password, char *command, char *directory);
		/* Called during redirection to reset the state to support redirection */
		void rdp_reset_state(void);
		/* Disconnect from the RDP layer */
		void rdp_disconnect(void);
		RD_BOOL rdp_isenabled_encryption(void);
		void rdp_set_encrypt(RD_BOOL encrypt);
		RD_BOOL rdp_redirect(void);
		void rdp_support_redirect();//char *server, uint32* flags, char *domain, char* username, char *password);
		bool is_config(void);
		bool Init_config(const char* config_file);
		void reset_password(void);
	};
#define RDP5_FLAG 0x0030
}

#endif
