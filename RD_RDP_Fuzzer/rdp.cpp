#include "rdp.h"
#include <fstream>
#include <regex>
#include <string>


namespace RD_FUZZER
{
	RDP::RDP()
	{
		mcs_userid = 0;
		memset(username, 0, 64);
		memset(codepage, 0, 16);
		bitmap_compression = False;
		orders = False;
		encryption = True;
		desktop_save = False;
		polygon_ellipse_orders = False;
		rdp5_performanceflags = 0;
		server_depth = 0;
		width = 0;
		height = 0;
		bitmap_cache = False;
		bitmap_cache_persist_enable = False;
		numlock_sync = False;

		memset(&mppc_dict, 0, sizeof(RDPCOMP));

		next_packet = NULL;
		rdp_shareid = 0;

		redirect = True;
		memset(redirect_server, 0, 64);
		memset(redirect_domain, 0, 16);
		memset(redirect_password, 0, 64);
		memset(redirect_username, 0, 64);
		memset(redirect_cookie, 0, 128);
		redirect_flags = 0;

		session_count = 0;
	}

	RDP::~RDP()
	{
		rdp_reset_state();
	}

	void RDP::rdp5_process(STREAM s)
	{
		uint16 length, count, x, y;
		uint8 type, ctype;
		uint8 *next;

		uint32 roff, rlen;
		struct stream *ns = &(mppc_dict.ns);
		struct stream *ts;

	#if 0
		printf("RDP5 data:\n");
		hexdump(s->p, s->end - s->p);
	#endif

		while (s->p < s->end)
		{
			in_uint8(s, type);
			if (type & RDP5_COMPRESSED)
			{
				in_uint8(s, ctype);
				in_uint16_le(s, length);
				type ^= RDP5_COMPRESSED;
			}
			else
			{
				ctype = 0;
				in_uint16_le(s, length);
			}
			next_packet = next = s->p + length;

			if (ctype & RDP_MPPC_COMPRESSED)
			{
				if (mppc_expand(s->p, length, ctype, &roff, &rlen) == -1)
					error("error while decompressing packet\n");

				/* allocate memory and copy the uncompressed data into the temporary stream */
				ns->data = (uint8 *)xrealloc(ns->data, rlen);

				memcpy((ns->data), (unsigned char *)(mppc_dict.hist + roff), rlen);

				ns->size = rlen;
				ns->end = (ns->data + ns->size);
				ns->p = ns->data;
				ns->rdp_hdr = ns->p;

				ts = ns;
			}
			else
				ts = s;

			switch (type)
			{
			case 0:	/* update orders */
				in_uint16_le(ts, count);
				//process_orders(ts, count);
				break;
			case 1:	/* update bitmap */
				in_uint8s(ts, 2);	/* part length */
				process_bitmap_updates(ts);
				break;
			case 2:	/* update palette */
				in_uint8s(ts, 2);	/* uint16 = 2 */
				process_palette(ts);
				break;
			case 3:	/* update synchronize */
				break;
			case 5:	/* null pointer */
				break;
			case 6:	/* default pointer */
				break;
			case 8:	/* pointer position */
				in_uint16_le(ts, x);
				in_uint16_le(ts, y);
				break;
			case 9:	/* color pointer */
				process_colour_pointer_pdu(ts);
				break;
			case 10:	/* cached pointer */
				process_cached_pointer_pdu(ts);
				break;
			default:
				unimpl("RDP5 opcode %d\n", type);
			}

			s->p = next;
		}
	}

	STREAM RDP::rdp_recv(uint8 * type)
	{
		static STREAM rdp_s;
		uint16 length, pdu_type;
		uint8 rdpver;

		if ((rdp_s == NULL) || (next_packet >= rdp_s->end) || (next_packet == NULL))
		{
			rdp_s = sec_recv(&rdpver);
			if (rdp_s == NULL)
				return NULL;
			if (rdpver == 0xff)
			{
				next_packet = rdp_s->end;
				*type = 0;
				return rdp_s;
			}
			else if (rdpver != 3)
			{
				/* rdp5_process should move next_packet ok */
				rdp5_process(rdp_s);
				*type = 0;
				return rdp_s;
			}

			next_packet = rdp_s->p;
		}
		else
		{
			rdp_s->p = next_packet;
		}

		in_uint16_le(rdp_s, length);
		/* 32k packets are really 8, keepalive fix */
		if (length == 0x8000)
		{
			next_packet += 8;
			*type = 0;
			return rdp_s;
		}
		in_uint16_le(rdp_s, pdu_type);
		in_uint8s(rdp_s, 2);	/* userid */
		*type = pdu_type & 0xf;

	#if WITH_DEBUG
		DEBUG(("RDP packet #%d, (type %x)\n", ++g_packetno, *type));
		hexdump(next_packet, length);
	#endif /*  */

		next_packet += length;
		return rdp_s;
	}

	STREAM RDP::rdp_init_data(int maxlen)
	{
		STREAM s;

		s = sec_init(encryption ? SEC_ENCRYPT : 0, maxlen + 18);
		s_push_layer(s, rdp_hdr, 18);

		return s;
	}

	void RDP::rdp_send_data(STREAM s, uint8 data_pdu_type)
	{
		uint16 length;

		s_pop_layer(s, rdp_hdr);
		length = s->end - s->p;

		out_uint16_le(s, length);
		out_uint16_le(s, (RDP_PDU_DATA | 0x10));
		out_uint16_le(s, (mcs_userid + 1001));

		out_uint32_le(s, rdp_shareid);
		out_uint8(s, 0);	/* pad */
		out_uint8(s, 1);	/* streamid */
		out_uint16_le(s, (length - 14));
		out_uint8(s, data_pdu_type);
		out_uint8(s, 0);	/* compress_type */
		out_uint16(s, 0);	/* compress_len */

#ifdef RDP_FUZZ
		if (s->size != s->size + mutator.GetMaxDummySize()) {
			mutator.Mutation_in_max((char*)s->data, s->size, s->size + mutator.GetMaxDummySize());
		}
		else {
			mutator.ByteFlipMutation((char*)s->data, s->size);
		}
		printf("rdp_send_data\n");
		std::string filename = "rdp_fuzz_" + std::to_string(session_count);
		write_hexdump(s->data, s->size, filename.c_str());
		
#else
		printf("sending packets\n");
#endif

		sec_send(s, encryption ? SEC_ENCRYPT : 0);
	}

	void RDP::rdp_send_logon_info(uint32 flags, char * domain, char * user, char * password, char * program, char * directory)
	{
		char *ipaddr = tcp_get_address();
		int len_domain = 2 * strlen(domain);
		int len_user = 2 * strlen(user);
		int len_password = 2 * strlen(password);
		int len_program = 2 * strlen(program);
		int len_directory = 2 * strlen(directory);
		int len_ip = 2 * strlen(ipaddr);
		int len_dll = 2 * strlen("C:\\WINNT\\System32\\mstscax.dll");
		int packetlen = 0;
		uint32 sec_flags = encryption ? (SEC_LOGON_INFO | SEC_ENCRYPT) : SEC_LOGON_INFO;
		STREAM s;
		time_t t = time(NULL);
		time_t tzone;

		if (!use_rdp5 || 1 == server_rdp_version)
		{
			DEBUG_RDP5(("Sending RDP4-style Logon packet\n"));

			s = sec_init(sec_flags, 18 + len_domain + len_user + len_password
				+ len_program + len_directory + 10);
			// MaxLen + 각 hdrlen의 data를 가진 stream 반환(Mutator를 돌리기 위한 충분한 크기)

			out_uint32(s, 0);
			out_uint32_le(s, flags);
			out_uint16_le(s, len_domain);
			out_uint16_le(s, len_user);
			out_uint16_le(s, len_password);
			out_uint16_le(s, len_program);
			out_uint16_le(s, len_directory);
			rdp_out_unistr(s, domain, len_domain);
			rdp_out_unistr(s, user, len_user);
			rdp_out_unistr(s, password, len_password);
			rdp_out_unistr(s, program, len_program);
			rdp_out_unistr(s, directory, len_directory);
		}
		else
		{
			flags |= RDP_LOGON_BLOB;
			DEBUG_RDP5(("Sending RDP5-style Logon packet\n"));
			packetlen = 4 +	/* Unknown uint32 */
				4 +	/* flags */
				2 +	/* len_domain */
				2 +	/* len_user */
				(flags & RDP_LOGON_AUTO ? 2 : 0) +	/* len_password */
				(flags & RDP_LOGON_BLOB ? 2 : 0) +	/* Length of BLOB */
				2 +	/* len_program */
				2 +	/* len_directory */
				(0 < len_domain ? len_domain : 2) +	/* domain */
				len_user + (flags & RDP_LOGON_AUTO ? len_password : 0) + 0 +	/* We have no 512 byte BLOB. Perhaps we must? */
				(flags & RDP_LOGON_BLOB && !(flags & RDP_LOGON_AUTO) ? 2 : 0) +	/* After the BLOB is a unknown int16. If there is a BLOB, that is. */
				(0 < len_program ? len_program : 2) + (0 < len_directory ? len_directory : 2) + 2 +	/* Unknown (2) */
				2 +	/* Client ip length */
				len_ip +	/* Client ip */
				2 +	/* DLL string length */
				len_dll +	/* DLL string */
				2 +	/* Unknown */
				2 +	/* Unknown */
				64 +	/* Time zone #0 */
				2 +	/* Unknown */
				64 +	/* Time zone #1 */
				32;	/* Unknown */

			s = sec_init(sec_flags, packetlen);
			DEBUG_RDP5(("Called sec_init with packetlen %d\n", packetlen));

			out_uint32(s, 0);	/* Unknown */
			out_uint32_le(s, flags);
			out_uint16_le(s, len_domain);
			out_uint16_le(s, len_user);
			if (flags & RDP_LOGON_AUTO)
			{
				out_uint16_le(s, len_password);

			}
			if (flags & RDP_LOGON_BLOB && !(flags & RDP_LOGON_AUTO))
			{
				out_uint16_le(s, 0);
			}
			out_uint16_le(s, len_program);
			out_uint16_le(s, len_directory);
			if (0 < len_domain)
				rdp_out_unistr(s, domain, len_domain);
			else
				out_uint16_le(s, 0);
			rdp_out_unistr(s, user, len_user);
			if (flags & RDP_LOGON_AUTO)
			{
				rdp_out_unistr(s, password, len_password);
			}
			if (flags & RDP_LOGON_BLOB && !(flags & RDP_LOGON_AUTO))
			{
				out_uint16_le(s, 0);
			}
			if (0 < len_program)
			{
				rdp_out_unistr(s, program, len_program);

			}
			else
			{
				out_uint16_le(s, 0);
			}
			if (0 < len_directory)
			{
				rdp_out_unistr(s, directory, len_directory);
			}
			else
			{
				out_uint16_le(s, 0);
			}
			out_uint16_le(s, 2);
			out_uint16_le(s, len_ip + 2);	/* Length of client ip */
			rdp_out_unistr(s, ipaddr, len_ip);
			out_uint16_le(s, len_dll + 2);
			rdp_out_unistr(s, "C:\\WINNT\\System32\\mstscax.dll", len_dll);

			struct tm gmt, localt;
			gmtime_s(&gmt, &t);
			localtime_s(&localt, &t);
			tzone = (mktime(&gmt) - mktime(&localt)) / 60;
			out_uint32_le(s, (uint32)tzone);

			rdp_out_unistr(s, "GTB, normaltid", 2 * strlen("GTB, normaltid"));
			out_uint8s(s, 62 - 2 * strlen("GTB, normaltid"));

			out_uint32_le(s, 0x0a0000);
			out_uint32_le(s, 0x050000);
			out_uint32_le(s, 3);
			out_uint32_le(s, 0);
			out_uint32_le(s, 0);

			rdp_out_unistr(s, "GTB, sommartid", 2 * strlen("GTB, sommartid"));
			out_uint8s(s, 62 - 2 * strlen("GTB, sommartid"));

			out_uint32_le(s, 0x30000);
			out_uint32_le(s, 0x050000);
			out_uint32_le(s, 2);
			out_uint32(s, 0);
			out_uint32_le(s, 0xffffffc4);
			out_uint32_le(s, 0xfffffffe);
			out_uint32_le(s, rdp5_performanceflags);
			out_uint16(s, 0);
		}
		s_mark_end(s);
		
#ifdef RDP_FUZZ1
		//printf("Begin Address : %p\n", s->data);
		//printf("End Address : %p\n", s->end);
		//printf("End - Begin : %x, Size : %x\n", s->end - s->data, s->size);
		//hexdump(s->data, s->size);
		
		mutator.Mutation_in_max((char*)s->data, s->size - mutator.GetMaxDummySize(), s->size);	// Packet Mutator
		printf("RDP_Logon Fuzz\n");
		hexdump(s->data, s->size);
#endif
		sec_send(s, sec_flags);
	}

	void RDP::rdp_send_control(uint16 action)
	{
		STREAM s;

		s = rdp_init_data(8);

		out_uint16_le(s, action);
		out_uint16(s, 0);	/* userid */
		out_uint32(s, 0);	/* control id */

		s_mark_end(s);
		rdp_send_data(s, RDP_DATA_PDU_CONTROL);
	}

	void RDP::rdp_send_synchronise(void)
	{
		STREAM s;

		s = rdp_init_data(4);

		out_uint16_le(s, 1);	/* type */
		out_uint16_le(s, 1002);

		s_mark_end(s);
		rdp_send_data(s, RDP_DATA_PDU_SYNCHRONISE);
	}

	void RDP::rdp_enum_bmpcache2(void)
	{
		STREAM s;
		HASH_KEY keylist[BMPCACHE2_NUM_PSTCELLS];
		uint32 num_keys, offset, count, flags;

		offset = 0;
		//num_keys = pstcache_enumerate(2, keylist);
		num_keys = 0x123;	//////////////////////////////// max = BMPCACHE2_NUM_PSTCELLS;

		while (offset < num_keys)
		{
			count = MIN(num_keys - offset, 169);

			s = rdp_init_data(24 + count * sizeof(HASH_KEY));

			flags = 0;
			if (offset == 0)
				flags |= PDU_FLAG_FIRST;
			if (num_keys - offset <= 169)
				flags |= PDU_FLAG_LAST;

			/* header */
			out_uint32_le(s, 0);
			out_uint16_le(s, count);
			out_uint16_le(s, 0);
			out_uint16_le(s, 0);
			out_uint16_le(s, 0);
			out_uint16_le(s, 0);
			out_uint16_le(s, num_keys);
			out_uint32_le(s, 0);
			out_uint32_le(s, flags);

			/* list */
			out_uint8a(s, keylist[offset], count * sizeof(HASH_KEY));

			s_mark_end(s);
			rdp_send_data(s, 0x2b);

			offset += 169;
		}
	}

	void RDP::rdp_send_fonts(uint16 seq)
	{
		STREAM s;

		s = rdp_init_data(8);

		out_uint16(s, 0);	/* number of fonts */
		out_uint16_le(s, 0);	/* pad? */
		out_uint16_le(s, seq);	/* unknown */
		out_uint16_le(s, 0x32);	/* entry size */

		s_mark_end(s);
		rdp_send_data(s, RDP_DATA_PDU_FONT2);
	}

	void RDP::rdp_out_general_caps(STREAM s)
	{
		out_uint16_le(s, RDP_CAPSET_GENERAL);
		out_uint16_le(s, RDP_CAPLEN_GENERAL);

		out_uint16_le(s, 1);	/* OS major type */
		out_uint16_le(s, 3);	/* OS minor type */
		out_uint16_le(s, 0x200);	/* Protocol version */
		out_uint16(s, 0);	/* Pad */
		out_uint16(s, 0);	/* Compression types */
		out_uint16_le(s, use_rdp5 ? 0x40d : 0);
		/* Pad, according to T.128. 0x40d seems to
		trigger
		the server to start sending RDP5 packets.
		However, the value is 0x1d04 with W2KTSK and
		NT4MS. Hmm.. Anyway, thankyou, Microsoft,
		for sending such information in a padding
		field.. */
		out_uint16(s, 0);	/* Update capability */
		out_uint16(s, 0);	/* Remote unshare capability */
		out_uint16(s, 0);	/* Compression level */
		out_uint16(s, 0);	/* Pad */
	}

	void RDP::rdp_out_bitmap_caps(STREAM s)
	{
		out_uint16_le(s, RDP_CAPSET_BITMAP);
		out_uint16_le(s, RDP_CAPLEN_BITMAP);

		out_uint16_le(s, server_depth);	/* Preferred colour depth */
		out_uint16_le(s, 1);	/* Receive 1 BPP */
		out_uint16_le(s, 1);	/* Receive 4 BPP */
		out_uint16_le(s, 1);	/* Receive 8 BPP */
		out_uint16_le(s, 800);	/* Desktop width */
		out_uint16_le(s, 600);	/* Desktop height */
		out_uint16(s, 0);	/* Pad */
		out_uint16(s, 1);	/* Allow resize */
		out_uint16_le(s, bitmap_compression ? 1 : 0);	/* Support compression */
		out_uint16(s, 0);	/* Unknown */
		out_uint16_le(s, 1);	/* Unknown */
		out_uint16(s, 0);	/* Pad */
	}

	void RDP::rdp_out_bmpcache_caps(STREAM s)
	{
		int Bpp;
		out_uint16_le(s, RDP_CAPSET_BMPCACHE);
		out_uint16_le(s, RDP_CAPLEN_BMPCACHE);

		Bpp = (server_depth + 7) / 8;	/* bytes per pixel */
		out_uint8s(s, 24);	/* unused */
		out_uint16_le(s, 0x258);	/* entries */
		out_uint16_le(s, 0x100 * Bpp);	/* max cell size */
		out_uint16_le(s, 0x12c);	/* entries */
		out_uint16_le(s, 0x400 * Bpp);	/* max cell size */
		out_uint16_le(s, 0x106);	/* entries */
		out_uint16_le(s, 0x1000 * Bpp);	/* max cell size */
	}

	void RDP::rdp_out_bmpcache2_caps(STREAM s)
	{
		out_uint16_le(s, RDP_CAPSET_BMPCACHE2);
		out_uint16_le(s, RDP_CAPLEN_BMPCACHE2);

		out_uint16_le(s, bitmap_cache_persist_enable ? 2 : 0);	/* version */

		out_uint16_be(s, 3);	/* number of caches in this set */

								/* max cell size for cache 0 is 16x16, 1 = 32x32, 2 = 64x64, etc */
		out_uint32_le(s, BMPCACHE2_C0_CELLS);
		out_uint32_le(s, BMPCACHE2_C1_CELLS);
		//if (!pstcache_init(2))
		//{
		out_uint32_le(s, BMPCACHE2_NUM_PSTCELLS | BMPCACHE2_FLAG_PERSIST);
		//}
		//else
		//{
		//	out_uint32_le(s, BMPCACHE2_C2_CELLS);
		//}
		out_uint8s(s, 20);	/* other bitmap caches not used */
	}

	void RDP::rdp_out_control_caps(STREAM s)
	{
		out_uint16_le(s, RDP_CAPSET_CONTROL);
		out_uint16_le(s, RDP_CAPLEN_CONTROL);

		out_uint16(s, 0);	/* Control capabilities */
		out_uint16(s, 0);	/* Remote detach */
		out_uint16_le(s, 2);	/* Control interest */
		out_uint16_le(s, 2);	/* Detach interest */
	}

	void RDP::rdp_out_activate_caps(STREAM s)
	{
		out_uint16_le(s, RDP_CAPSET_ACTIVATE);
		out_uint16_le(s, RDP_CAPLEN_ACTIVATE);

		out_uint16(s, 0);	/* Help key */
		out_uint16(s, 0);	/* Help index key */
		out_uint16(s, 0);	/* Extended help key */
		out_uint16(s, 0);	/* Window activate */
	}

	void RDP::rdp_out_pointer_caps(STREAM s)
	{
		out_uint16_le(s, RDP_CAPSET_POINTER);
		out_uint16_le(s, RDP_CAPLEN_POINTER);

		out_uint16(s, 0);	/* Colour pointer */
		out_uint16_le(s, 20);	/* Cache size */
	}

	void RDP::rdp_out_share_caps(STREAM s)
	{
		out_uint16_le(s, RDP_CAPSET_SHARE);
		out_uint16_le(s, RDP_CAPLEN_SHARE);

		out_uint16(s, 0);	/* userid */
		out_uint16(s, 0);	/* pad */
	}

	void RDP::rdp_out_colcache_caps(STREAM s)
	{
		out_uint16_le(s, RDP_CAPSET_COLCACHE);
		out_uint16_le(s, RDP_CAPLEN_COLCACHE);

		out_uint16_le(s, 6);	/* cache size */
		out_uint16(s, 0);	/* pad */
	}

	void RDP::rdp_out_unknown_caps(STREAM s, uint16 id, uint16 length, uint8 * caps)
	{
		out_uint16_le(s, id);
		out_uint16_le(s, length);

		out_uint8p(s, caps, length - 4);
	}

	void RDP::rdp_send_confirm_active(void)
	{
		STREAM s;
		uint32 sec_flags = encryption ? (RDP5_FLAG | SEC_ENCRYPT) : RDP5_FLAG;
		uint16 caplen =
			RDP_CAPLEN_GENERAL + RDP_CAPLEN_BITMAP + RDP_CAPLEN_ORDER +
			RDP_CAPLEN_BMPCACHE + RDP_CAPLEN_COLCACHE +
			RDP_CAPLEN_ACTIVATE + RDP_CAPLEN_CONTROL +
			RDP_CAPLEN_POINTER + RDP_CAPLEN_SHARE +
			0x58 + 0x08 + 0x08 + 0x34 /* unknown caps */ +
			4 /* w2k fix, why? */;

		s = sec_init(sec_flags, 6 + 14 + caplen + sizeof(RDP_SOURCE));

		out_uint16_le(s, 2 + 14 + caplen + sizeof(RDP_SOURCE));
		out_uint16_le(s, (RDP_PDU_CONFIRM_ACTIVE | 0x10));	/* Version 1 */
		out_uint16_le(s, (mcs_userid + 1001));

		out_uint32_le(s, rdp_shareid);
		out_uint16_le(s, 0x3ea);	/* userid */
		out_uint16_le(s, sizeof(RDP_SOURCE));
		out_uint16_le(s, caplen);

		out_uint8p(s, RDP_SOURCE, sizeof(RDP_SOURCE));
		out_uint16_le(s, 0xd);	/* num_caps */
		out_uint8s(s, 2);	/* pad */

		rdp_out_general_caps(s);
		rdp_out_bitmap_caps(s);
		rdp_out_order_caps(s);
		use_rdp5 ? rdp_out_bmpcache2_caps(s) : rdp_out_bmpcache_caps(s);
		rdp_out_colcache_caps(s);
		rdp_out_activate_caps(s);
		rdp_out_control_caps(s);
		rdp_out_pointer_caps(s);
		rdp_out_share_caps(s);

		rdp_out_unknown_caps(s, 0x0d, 0x58, caps_0x0d);	/* international? */
		rdp_out_unknown_caps(s, 0x0c, 0x08, caps_0x0c);
		rdp_out_unknown_caps(s, 0x0e, 0x08, caps_0x0e);
		rdp_out_unknown_caps(s, 0x10, 0x34, caps_0x10);	/* glyph cache? */

		s_mark_end(s);
		sec_send(s, sec_flags);
	}

	void RDP::rdp_process_general_caps(STREAM s)
	{
		uint16 pad2octetsB;	/* rdp5 flags? */

		in_uint8s(s, 10);
		in_uint16_le(s, pad2octetsB);

		if (!pad2octetsB)
			use_rdp5 = False;
	}

	void RDP::rdp_process_bitmap_caps(STREAM s)
	{
		uint16 width, height, depth;

		in_uint16_le(s, depth);
		in_uint8s(s, 6);

		in_uint16_le(s, width);
		in_uint16_le(s, height);

		DEBUG(("setting desktop size and depth to: %dx%dx%d\n", width, height, depth));

		/*
		* The server may limit depth and change the size of the desktop (for
		* example when shadowing another session).
		*/
		if (server_depth != depth)
		{
			warning("Remote desktop does not support colour depth %d; falling back to %d\n",
				server_depth, depth);
			server_depth = depth;
		}
		if (width != width || height != height)
		{
			warning("Remote desktop changed from %dx%d to %dx%d.\n", width, height,
				width, height);
			width = width;
			height = height;
		}
	}

	void RDP::rdp_process_server_caps(STREAM s, uint16 length)
	{
		int n;
		uint8 *next, *start;
		uint16 ncapsets, capset_type, capset_length;

		start = s->p;

		in_uint16_le(s, ncapsets);
		in_uint8s(s, 2);	/* pad */

		for (n = 0; n < ncapsets; n++)
		{
			if (s->p > start + length)
				return;

			in_uint16_le(s, capset_type);
			in_uint16_le(s, capset_length);

			next = s->p + capset_length - 4;

			switch (capset_type)
			{
			case RDP_CAPSET_GENERAL:
				rdp_process_general_caps(s);
				break;

			case RDP_CAPSET_BITMAP:
				rdp_process_bitmap_caps(s);
				break;
			}

			s->p = next;
		}
	}

	void RDP::process_demand_active(STREAM s)
	{
		uint8 type;
		uint16 len_src_descriptor, len_combined_caps;

		in_uint32_le(s, rdp_shareid);
		in_uint16_le(s, len_src_descriptor);
		in_uint16_le(s, len_combined_caps);
		in_uint8s(s, len_src_descriptor);

		DEBUG(("DEMAND_ACTIVE(id=0x%x)\n", rdp_shareid));
		rdp_process_server_caps(s, len_combined_caps);

		rdp_send_confirm_active();
		rdp_send_synchronise();
		rdp_send_control(RDP_CTL_COOPERATE);
		rdp_send_control(RDP_CTL_REQUEST_CONTROL);
		rdp_recv(&type);	/* RDP_PDU_SYNCHRONIZE */
		rdp_recv(&type);	/* RDP_CTL_COOPERATE */
		rdp_recv(&type);	/* RDP_CTL_GRANT_CONTROL */
		rdp_send_input(0, RDP_INPUT_SYNCHRONIZE, 0, 0, 0);

		if (use_rdp5)
		{
			rdp_enum_bmpcache2();
			rdp_send_fonts(3);
		}
		else
		{
			rdp_send_fonts(1);
			rdp_send_fonts(2);
		}

		rdp_recv(&type);	/* RDP_PDU_UNKNOWN 0x28 (Fonts?) */
		//reset_order_state();
	}

	void RDP::process_pointer_pdu(STREAM s)
	{
		uint16 message_type;
		uint16 x, y;

		in_uint16_le(s, message_type);
		in_uint8s(s, 2);	/* pad */

		switch (message_type)
		{
		case RDP_POINTER_MOVE:
			in_uint16_le(s, x);
			in_uint16_le(s, y);
			//if (s_check(s))
			break;

		case RDP_POINTER_COLOR:
			process_colour_pointer_pdu(s);
			break;

		case RDP_POINTER_CACHED:
			process_cached_pointer_pdu(s);
			break;

		case RDP_POINTER_SYSTEM:
			process_system_pointer_pdu(s);
			break;

		default:
			unimpl("Pointer message 0x%x\n", message_type);
		}
	}

	void RDP::process_update_pdu(STREAM s)
	{
		uint16 update_type, count;

		in_uint16_le(s, update_type);

		switch (update_type)
		{
		case RDP_UPDATE_ORDERS:
			in_uint8s(s, 2);	/* pad */
			in_uint16_le(s, count);
			in_uint8s(s, 2);	/* pad */
			//process_orders(s, count);
			break;

		case RDP_UPDATE_BITMAP:
			process_bitmap_updates(s);
			break;

		case RDP_UPDATE_PALETTE:
			process_palette(s);
			break;

		case RDP_UPDATE_SYNCHRONIZE:
			break;

		default:
			unimpl("update %d\n", update_type);
		}
	}

	RD_BOOL RDP::process_data_pdu(STREAM s, uint32 * ext_disc_reason)
	{
		uint8 data_pdu_type;
		uint8 ctype;
		uint16 clen;
		uint32 len;

		uint32 roff, rlen;

		struct stream *ns = &(mppc_dict.ns);

		in_uint8s(s, 6);	/* shareid, pad, streamid */
		in_uint16_le(s, len);
		in_uint8(s, data_pdu_type);
		in_uint8(s, ctype);
		in_uint16_le(s, clen);
		clen -= 18;

		if (ctype & RDP_MPPC_COMPRESSED)
		{
			if (len > RDP_MPPC_DICT_SIZE)
				error("error decompressed packet size exceeds max\n");
			if (mppc_expand(s->p, clen, ctype, &roff, &rlen) == -1)
				error("error while decompressing packet\n");

			/* len -= 18; */

			/* allocate memory and copy the uncompressed data into the temporary stream */
			ns->data = (uint8 *)xrealloc(ns->data, rlen);

			memcpy((ns->data), (unsigned char *)(mppc_dict.hist + roff), rlen);

			ns->size = rlen;
			ns->end = (ns->data + ns->size);
			ns->p = ns->data;
			ns->rdp_hdr = ns->p;

			s = ns;
		}

		switch (data_pdu_type)
		{
		case RDP_DATA_PDU_UPDATE:
			process_update_pdu(s);
			break;

		case RDP_DATA_PDU_CONTROL:
			DEBUG(("Received Control PDU\n"));
			break;

		case RDP_DATA_PDU_SYNCHRONISE:
			DEBUG(("Received Sync PDU\n"));
			break;

		case RDP_DATA_PDU_POINTER:
			process_pointer_pdu(s);
			break;

		case RDP_DATA_PDU_BELL:
			break;

		case RDP_DATA_PDU_LOGON:
			DEBUG(("Received Logon PDU\n"));
			/* User logged on */
			break;

		case RDP_DATA_PDU_DISCONNECT:
			process_disconnect_pdu(s, ext_disc_reason);

			/* We used to return true and disconnect immediately here, but
			* Windows Vista sends a disconnect PDU with reason 0 when
			* reconnecting to a disconnected session, and MSTSC doesn't
			* drop the connection.  I think we should just save the status.
			*/
			break;

		default:
			unimpl("data PDU %d\n", data_pdu_type);
		}
		return False;
	}

	RD_BOOL RDP::process_redirect_pdu(STREAM s)
	{
		uint32 len;

		/* these 2 bytes are unknown, seem to be zeros */
		in_uint8s(s, 2);

		/* read connection flags */
		in_uint32_le(s, redirect_flags);

		/* read length of ip string */
		in_uint32_le(s, len);

		/* read ip string */
		rdp_in_unistr(s, redirect_server, sizeof(redirect_server), len);

		/* read length of cookie string */
		in_uint32_le(s, len);

		/* read cookie string (plain ASCII) */
		if (len > sizeof(redirect_cookie) - 1)
		{
			uint32 rem = len - (sizeof(redirect_cookie) - 1);
			len = sizeof(redirect_cookie) - 1;

			warning("Unexpectedly large redirection cookie\n");
			in_uint8a(s, redirect_cookie, len);
			in_uint8s(s, rem);
		}
		else
		{
			in_uint8a(s, redirect_cookie, len);
		}
		redirect_cookie[len] = 0;

		/* read length of username string */
		in_uint32_le(s, len);

		/* read username string */
		rdp_in_unistr(s, redirect_username, sizeof(redirect_username), len);

		/* read length of domain string */
		in_uint32_le(s, len);

		/* read domain string */
		rdp_in_unistr(s, redirect_domain, sizeof(redirect_domain), len);

		/* read length of password string */
		in_uint32_le(s, len);

		/* read password string */
		rdp_in_unistr(s, redirect_password, sizeof(redirect_password), len);

		redirect = True;

		return True;
	}

	void RDP::rdp_send_input(uint32 time, uint16 message_type, uint16 device_flags, uint16 param1, uint16 param2)
	{
		STREAM s;

		s = rdp_init_data(16);

		out_uint16_le(s, 1);	/* number of events */
		out_uint16(s, 0);	/* pad */

		out_uint32_le(s, time);
		out_uint16_le(s, message_type);
		out_uint16_le(s, device_flags);
		out_uint16_le(s, param1);
		out_uint16_le(s, param2);

		s_mark_end(s);
		rdp_send_data(s, RDP_DATA_PDU_INPUT);
	}

	void RDP::rdp_send_client_window_status(int status)
	{
		STREAM s;
		static int current_status = 1;

		if (current_status == status)
			return;

		s = rdp_init_data(12);

		out_uint32_le(s, status);

		switch (status)
		{
		case 0:	/* shut the server up */
			break;

		case 1:	/* receive data again */
			out_uint32_le(s, 0);	/* unknown */
			out_uint16_le(s, width);
			out_uint16_le(s, height);
			break;
		}

		s_mark_end(s);
		rdp_send_data(s, RDP_DATA_PDU_CLIENT_WINDOW_STATUS);
		current_status = status;
	}

	void RDP::rdp_out_order_caps(STREAM s)
	{
		uint8 order_caps[32];

		memset(order_caps, 0, 32);
		order_caps[0] = 1;	/* dest blt */
		order_caps[1] = 1;	/* pat blt */
		order_caps[2] = 1;	/* screen blt */
		order_caps[3] = (bitmap_cache ? 1 : 0);	/* memblt */
		order_caps[4] = 0;	/* triblt */
		order_caps[8] = 1;	/* line */
		order_caps[9] = 1;	/* line */
		order_caps[10] = 1;	/* rect */
		order_caps[11] = (desktop_save ? 1 : 0);	/* desksave */
		order_caps[13] = 1;	/* memblt */
		order_caps[14] = 1;	/* triblt */
		order_caps[20] = (polygon_ellipse_orders ? 1 : 0);	/* polygon */
		order_caps[21] = (polygon_ellipse_orders ? 1 : 0);	/* polygon2 */
		order_caps[22] = 1;	/* polyline */
		order_caps[25] = (polygon_ellipse_orders ? 1 : 0);	/* ellipse */
		order_caps[26] = (polygon_ellipse_orders ? 1 : 0);	/* ellipse2 */
		order_caps[27] = 1;	/* text2 */
		out_uint16_le(s, RDP_CAPSET_ORDER);
		out_uint16_le(s, RDP_CAPLEN_ORDER);

		out_uint8s(s, 20);	/* Terminal desc, pad */
		out_uint16_le(s, 1);	/* Cache X granularity */
		out_uint16_le(s, 20);	/* Cache Y granularity */
		out_uint16(s, 0);	/* Pad */
		out_uint16_le(s, 1);	/* Max order level */
		out_uint16_le(s, 0x147);	/* Number of fonts */
		out_uint16_le(s, 0x2a);	/* Capability flags */
		out_uint8p(s, order_caps, 32);	/* Orders supported */
		out_uint16_le(s, 0x6a1);	/* Text capability flags */
		out_uint8s(s, 6);	/* Pad */
		out_uint32_le(s, desktop_save == False ? 0 : 0x38400);	/* Desktop cache size */
		out_uint32(s, 0);	/* Unknown */
		out_uint32_le(s, 0x4e4);	/* Unknown */
	}

	void RDP::process_colour_pointer_pdu(STREAM s)
	{
		uint16 x, y, width, height, cache_idx, masklen, datalen;
		uint8 *mask, *data;

		in_uint16_le(s, cache_idx);
		in_uint16_le(s, x);
		in_uint16_le(s, y);
		in_uint16_le(s, width);
		in_uint16_le(s, height);
		in_uint16_le(s, masklen);
		in_uint16_le(s, datalen);
		in_uint8p(s, data, datalen);
		in_uint8p(s, mask, masklen);
	}

	void RDP::process_cached_pointer_pdu(STREAM s)
	{
		uint16 cache_idx;

		in_uint16_le(s, cache_idx);
	}

	void RDP::process_system_pointer_pdu(STREAM s)
	{
		uint16 system_pointer_type;

		in_uint16_le(s, system_pointer_type);
		switch (system_pointer_type)
		{
		case RDP_NULL_POINTER:
			break;

		default:
			unimpl("System pointer message 0x%x\n", system_pointer_type);
		}
	}

	void RDP::process_bitmap_updates(STREAM s)
	{
		uint16 num_updates;
		uint16 left, top, right, bottom, width, height;
		uint16 cx, cy, bpp, Bpp, compress, bufsize, size;
		uint8 *data, *bmpdata;
		int i;

		in_uint16_le(s, num_updates);

		for (i = 0; i < num_updates; i++)
		{
			in_uint16_le(s, left);
			in_uint16_le(s, top);
			in_uint16_le(s, right);
			in_uint16_le(s, bottom);
			in_uint16_le(s, width);
			in_uint16_le(s, height);
			in_uint16_le(s, bpp);
			Bpp = (bpp + 7) / 8;
			in_uint16_le(s, compress);
			in_uint16_le(s, bufsize);

			cx = right - left + 1;
			cy = bottom - top + 1;

			DEBUG(("BITMAP_UPDATE(l=%d,t=%d,r=%d,b=%d,w=%d,h=%d,Bpp=%d,cmp=%d)\n",
				left, top, right, bottom, width, height, Bpp, compress));

			if (!compress)
			{
				int y;
				bmpdata = (uint8 *)xmalloc(width * height * Bpp);
				for (y = 0; y < height; y++)
				{
					in_uint8a(s, &bmpdata[(height - y - 1) * (width * Bpp)],
						width * Bpp);
				}
				xfree(bmpdata);
				continue;
			}


			if (compress & 0x400)
			{
				size = bufsize;
			}
			else
			{
				in_uint8s(s, 2);	/* pad */
				in_uint16_le(s, size);
				in_uint8s(s, 4);	/* line_size, final_size */
			}
			in_uint8p(s, data, size);
			bmpdata = (uint8 *)xmalloc(width * height * Bpp);
			/*if (!bitmap_decompress(bmpdata, width, height, data, size, Bpp))
			{
				DEBUG_RDP5(("Failed to decompress data\n"));
			}*/

			xfree(bmpdata);
		}
	}

	void RDP::process_palette(STREAM s)
	{
		COLOURENTRY *entry;
		COLOURMAP map;
		int i;

		in_uint8s(s, 2);	/* pad */
		in_uint16_le(s, map.ncolours);
		in_uint8s(s, 2);	/* pad */

		map.colours = (COLOURENTRY *)xmalloc(sizeof(COLOURENTRY) * map.ncolours);

		DEBUG(("PALETTE(c=%d)\n", map.ncolours));

		for (i = 0; i < map.ncolours; i++)
		{
			entry = &map.colours[i];
			in_uint8(s, entry->red);
			in_uint8(s, entry->green);
			in_uint8(s, entry->blue);
		}

		xfree(map.colours);
	}

	void RDP::process_disconnect_pdu(STREAM s, uint32 * ext_disc_reason)
	{
		in_uint32_le(s, *ext_disc_reason);

		DEBUG(("Received disconnect PDU\n"));
	}

	void RDP::rdp_main_loop(RD_BOOL * deactivated, uint32 * ext_disc_reason)
	{
		while (rdp_loop(deactivated, ext_disc_reason));
	}

	RD_BOOL RDP::rdp_loop(RD_BOOL * deactivated, uint32 * ext_disc_reason)
	{
		uint8 type;
		RD_BOOL disc = False;	/* True when a disconnect PDU was received */
		RD_BOOL cont = True;
		STREAM s;

		while (cont)
		{
			s = rdp_recv(&type);
			if (s == NULL)
				return False;
			switch (type)
			{
			case RDP_PDU_DEMAND_ACTIVE:				// active
				process_demand_active(s);
				*deactivated = False;
				break;
			case RDP_PDU_DEACTIVATE:				// Stop
				DEBUG(("RDP_PDU_DEACTIVATE\n"));
				*deactivated = True;
				break;
			case RDP_PDU_REDIRECT:
				return process_redirect_pdu(s);
				break;
			case RDP_PDU_DATA:
				disc = process_data_pdu(s, ext_disc_reason);
				break;
			case 0:
				break;
			default:
				unimpl("PDU %d\n", type);
			}
			if (disc)
				return False;
			cont = next_packet < s->end;
		}
		return True;
	}

	RD_BOOL RDP::rdp_connect()
	{ 
		if (!sec_connect(server, tcp_port_rdp, username, server_rdp_version))
			return False;

		rdp_send_logon_info(flags, domain, username, password, command, directory);
		session_count++;
		return True;
	}

	RD_BOOL RDP::rdp_connect(
		char * server, 
		uint16 port, 
		uint32 flags, 
		char * domain, 
		char * username, 
		char * password, 
		char * command, 
		char * directory, 
		uint16 server_rdp_version)
	{
		STRNCPY(this->server, server, 64);
		this->tcp_port_rdp = port;
		this->flags = flags;
		STRNCPY(this->domain, domain, 16);
		STRNCPY(this->username, username, 64);
		STRNCPY(this->password, password, 64);
		STRNCPY(this->command, command, 256);
		STRNCPY(this->directory, directory, 256);
		this->server_rdp_version = server_rdp_version;

		if (!sec_connect(server, port, username, server_rdp_version))
			return False;

		rdp_send_logon_info(flags, domain, username, password, command, directory);
		return True;
	}

	RD_BOOL RDP::rdp_reconnect()
	{
		if (!sec_reconnect(server))
			return False;

		rdp_send_logon_info(flags, domain, username, password, command, directory);
		return True;
	}

	RD_BOOL RDP::rdp_reconnect(char * server, uint16 port, uint32 flags, char * domain, char * username, char * password, char * command, char * directory)
	{
		if (!sec_reconnect(server))
			return False;

		rdp_send_logon_info(flags, domain, username, password, command, directory);
		return True;
	}

	void RDP::rdp_reset_state(void)
	{
		next_packet = NULL;	/* reset the packet information */
		rdp_shareid = 0;
		sec_reset_state();
	}

	void RDP::rdp_disconnect(void)
	{
		sec_disconnect();
	}

	int RDP::mppc_expand(uint8 * data, uint32 clen, uint8 ctype, uint32 * roff, uint32 * rlen)
	{
		int k, walker_len = 0, walker;
		uint32 i = 0;
		int next_offset, match_off;
		int match_len;
		int old_offset, match_bits;
		RD_BOOL big = ctype & RDP_MPPC_BIG ? True : False;

		uint8 *dict = mppc_dict.hist;

		if ((ctype & RDP_MPPC_COMPRESSED) == 0)
		{
			*roff = 0;
			*rlen = clen;
			return 0;
		}

		if ((ctype & RDP_MPPC_RESET) != 0)
		{
			mppc_dict.roff = 0;
		}

		if ((ctype & RDP_MPPC_FLUSH) != 0)
		{
			memset(dict, 0, RDP_MPPC_DICT_SIZE);
			mppc_dict.roff = 0;
		}

		*roff = 0;
		*rlen = 0;

		walker = mppc_dict.roff;

		next_offset = walker;
		old_offset = next_offset;
		*roff = old_offset;
		if (clen == 0)
			return 0;
		clen += i;

		do
		{
			if (walker_len == 0)
			{
				if (i >= clen)
					break;
				walker = data[i++] << 24;
				walker_len = 8;
			}
			if (walker >= 0)
			{
				if (walker_len < 8)
				{
					if (i >= clen)
					{
						if (walker != 0)
							return -1;
						break;
					}
					walker |= (data[i++] & 0xff) << (24 - walker_len);
					walker_len += 8;
				}
				if (next_offset >= RDP_MPPC_DICT_SIZE)
					return -1;
				dict[next_offset++] = (((uint32)walker) >> ((uint32)24));
				walker <<= 8;
				walker_len -= 8;
				continue;
			}
			walker <<= 1;
			/* fetch next 8-bits */
			if (--walker_len == 0)
			{
				if (i >= clen)
					return -1;
				walker = data[i++] << 24;
				walker_len = 8;
			}
			/* literal decoding */
			if (walker >= 0)
			{
				if (walker_len < 8)
				{
					if (i >= clen)
						return -1;
					walker |= (data[i++] & 0xff) << (24 - walker_len);
					walker_len += 8;
				}
				if (next_offset >= RDP_MPPC_DICT_SIZE)
					return -1;
				dict[next_offset++] = (uint8)(walker >> 24 | 0x80);
				walker <<= 8;
				walker_len -= 8;
				continue;
			}

			/* decode offset  */
			/* length pair    */
			walker <<= 1;
			if (--walker_len < (big ? 3 : 2))
			{
				if (i >= clen)
					return -1;
				walker |= (data[i++] & 0xff) << (24 - walker_len);
				walker_len += 8;
			}

			if (big)
			{
				/* offset decoding where offset len is:
				-63: 11111 followed by the lower 6 bits of the value
				64-319: 11110 followed by the lower 8 bits of the value ( value - 64 )
				320-2367: 1110 followed by lower 11 bits of the value ( value - 320 )
				2368-65535: 110 followed by lower 16 bits of the value ( value - 2368 )
				*/
				switch (((uint32)walker) >> ((uint32)29))
				{
				case 7:	/* - 63 */
					for (; walker_len < 9; walker_len += 8)
					{
						if (i >= clen)
							return -1;
						walker |= (data[i++] & 0xff) << (24 - walker_len);
					}
					walker <<= 3;
					match_off = ((uint32)walker) >> ((uint32)26);
					walker <<= 6;
					walker_len -= 9;
					break;

				case 6:	/* 64 - 319 */
					for (; walker_len < 11; walker_len += 8)
					{
						if (i >= clen)
							return -1;
						walker |= (data[i++] & 0xff) << (24 - walker_len);
					}

					walker <<= 3;
					match_off = (((uint32)walker) >> ((uint32)24)) + 64;
					walker <<= 8;
					walker_len -= 11;
					break;

				case 5:
				case 4:	/* 320 - 2367 */
					for (; walker_len < 13; walker_len += 8)
					{
						if (i >= clen)
							return -1;
						walker |= (data[i++] & 0xff) << (24 - walker_len);
					}

					walker <<= 2;
					match_off = (((uint32)walker) >> ((uint32)21)) + 320;
					walker <<= 11;
					walker_len -= 13;
					break;

				default:	/* 2368 - 65535 */
					for (; walker_len < 17; walker_len += 8)
					{
						if (i >= clen)
							return -1;
						walker |= (data[i++] & 0xff) << (24 - walker_len);
					}

					walker <<= 1;
					match_off = (((uint32)walker) >> ((uint32)16)) + 2368;
					walker <<= 16;
					walker_len -= 17;
					break;
				}
			}
			else
			{
				/* offset decoding where offset len is:
				-63: 1111 followed by the lower 6 bits of the value
				64-319: 1110 followed by the lower 8 bits of the value ( value - 64 )
				320-8191: 110 followed by the lower 13 bits of the value ( value - 320 )
				*/
				switch (((uint32)walker) >> ((uint32)30))
				{
				case 3:	/* - 63 */
					if (walker_len < 8)
					{
						if (i >= clen)
							return -1;
						walker |= (data[i++] & 0xff) << (24 - walker_len);
						walker_len += 8;
					}
					walker <<= 2;
					match_off = ((uint32)walker) >> ((uint32)26);
					walker <<= 6;
					walker_len -= 8;
					break;

				case 2:	/* 64 - 319 */
					for (; walker_len < 10; walker_len += 8)
					{
						if (i >= clen)
							return -1;
						walker |= (data[i++] & 0xff) << (24 - walker_len);
					}

					walker <<= 2;
					match_off = (((uint32)walker) >> ((uint32)24)) + 64;
					walker <<= 8;
					walker_len -= 10;
					break;

				default:	/* 320 - 8191 */
					for (; walker_len < 14; walker_len += 8)
					{
						if (i >= clen)
							return -1;
						walker |= (data[i++] & 0xff) << (24 - walker_len);
					}

					match_off = (walker >> 18) + 320;
					walker <<= 14;
					walker_len -= 14;
					break;
				}
			}
			if (walker_len == 0)
			{
				if (i >= clen)
					return -1;
				walker = data[i++] << 24;
				walker_len = 8;
			}

			/* decode length of match */
			match_len = 0;
			if (walker >= 0)
			{		/* special case - length of 3 is in bit 0 */
				match_len = 3;
				walker <<= 1;
				walker_len--;
			}
			else
			{
				/* this is how it works len of:
				4-7: 10 followed by 2 bits of the value
				8-15: 110 followed by 3 bits of the value
				16-31: 1110 followed by 4 bits of the value
				32-63: .... and so forth
				64-127:
				128-255:
				256-511:
				512-1023:
				1024-2047:
				2048-4095:
				4096-8191:

				i.e. 4097 is encoded as: 111111111110 000000000001
				meaning 4096 + 1...
				*/
				match_bits = big ? 14 : 11;	/* 11 or 14 bits of value at most */
				do
				{
					walker <<= 1;
					if (--walker_len == 0)
					{
						if (i >= clen)
							return -1;
						walker = data[i++] << 24;
						walker_len = 8;
					}
					if (walker >= 0)
						break;
					if (--match_bits == 0)
					{
						return -1;
					}
				} while (1);
				match_len = (big ? 16 : 13) - match_bits;
				walker <<= 1;
				if (--walker_len < match_len)
				{
					for (; walker_len < match_len; walker_len += 8)
					{
						if (i >= clen)
						{
							return -1;
						}
						walker |= (data[i++] & 0xff) << (24 - walker_len);
					}
				}

				match_bits = match_len;
				match_len =
					((walker >> (32 - match_bits)) & (~(-1 << match_bits))) | (1 <<
						match_bits);
				walker <<= match_bits;
				walker_len -= match_bits;
			}
			if (next_offset + match_len >= RDP_MPPC_DICT_SIZE)
			{
				return -1;
			}
			/* memory areas can overlap - meaning we can't use memXXX functions */
			k = (next_offset - match_off) & (big ? 65535 : 8191);
			do
			{
				dict[next_offset++] = dict[k++];
			} while (--match_len != 0);
		} while (1);

		/* store history offset */
		mppc_dict.roff = next_offset;

		*roff = old_offset;
		*rlen = next_offset - old_offset;

		return 0;
	}

	RD_BOOL RDP::rdp_isenabled_encryption()
	{
		return isenabled_encryption();
	}

	void RDP::rdp_set_encrypt(RD_BOOL encrypt)
	{
		enable_encryption(encrypt);
	}

	RD_BOOL RDP::rdp_redirect(void)
	{
		return redirect;
	}

	void RDP::rdp_support_redirect()
	{
		//STRNCPY(server, redirect_server, sizeof(server));
		flags |= RDP_LOGON_AUTO;
		//STRNCPY(domain, redirect_domain, sizeof(domain));
		//STRNCPY(username, redirect_username, sizeof(username));
		//STRNCPY(password, redirect_password, sizeof(password));
	
		redirect = False;
	}

	bool RDP::is_config() {
		return isconfigured;
	}

	#define BUF_SIZE 512

	bool RDP::Init_config(const char* config_file) {
		std::ifstream ifs(config_file);
		char fdata[BUF_SIZE];
		if (ifs.is_open()) {
			while (!ifs.eof()) {
				memset(fdata, 0, BUF_SIZE);
				ifs.getline(fdata, BUF_SIZE);

				std::regex reg("^(\\w+?): ([\\w:\\\\ ().]+)");
				std::string fdata_str = fdata;
				std::smatch m;

				bool ismatched = regex_search(fdata_str, m, reg);

				if (ismatched) {
					//if (!strcmp(m[1].str().c_str(), "server_ip")) {
					//	STRNCPY(server, m[2].str().c_str(), 64);
					//}
					//else if (!strcmp(m[1].str().c_str(), "port")) {
					//	tcp_port_rdp = atoi(m[2].str().c_str());
					//}
					if (!strcmp(m[1].str().c_str(), "domain")) {
						STRNCPY(domain, m[2].str().c_str(), 16);
					}
					//else if (!strcmp(m[1].str().c_str(), "username")) {
					//	STRNCPY(username, m[2].str().c_str(), 64);
					//}
					else if (!strcmp(m[1].str().c_str(), "password")) {
						STRNCPY(password, m[2].str().c_str(), 64);
					}
					else if (!strcmp(m[1].str().c_str(), "command")) {
						STRNCPY(command, m[2].str().c_str(), 256);
					}
					else if (!strcmp(m[1].str().c_str(), "directory")) {
						STRNCPY(directory, m[2].str().c_str(), 256);
					}
					//else if (!strcmp(m[1].str().c_str(), "server_rdp_version")) {
					//	server_rdp_version = atoi(m[2].str().c_str());
					//}
				}
			}
			ifs.close();

			isconfigured = TRUE;
			//if (flag == SET_ALL) {
			//	Init_Debug_config(config_file);
			//	Init_Mutator_config(config_file);
			//}
		}
		else return(false);

		if (!sec_Init_config_from_File(config_file))
			return(false);

		isconfigured = true;

		return(true);
	}

	void RDP::reset_password(void)
	{
		memset(password, 0, 64);
	}
}
