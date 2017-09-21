#include "secure.h"
#include "ssl.h"

namespace RD_FUZZER
{
	RDP_SEC::RDP_SEC() : RDP_MCS()
	{
		rc4_key_len = 0;
		memset(&rc4_decrypt_key, 0, sizeof(SSL_RC4));
		memset(&rc4_encrypt_key, 0, sizeof(SSL_RC4));
		server_public_key_len = 0;

		memset(sec_sign_key, 0, 16);
		memset(sec_decrypt_key, 0, 16);
		memset(sec_encrypt_key, 0, 16);
		memset(sec_decrypt_update_key, 0, 16);
		memset(sec_encrypt_update_key, 0, 16);
		memset(sec_crypted_random, 0, SEC_MAX_MODULUS_SIZE);

		sec_encrypt_use_count = 0;
		sec_decrypt_use_count = 0;

		memset(pad_54, 54, 40);	//54
		memset(pad_92, 92, 48);	//92

		memset(licence_key, 0, 16);
		memset(licence_sign_key, 0, 16);

		server_rdp_version = 0;

		memset(hostname, 0, 16);
		keyboard_type = 0;
		keyboard_subtype = 0;
		keyboard_functionkeys = 0;
		encryption = True;
		licence_issued = False;
		console_session = False;
		keylayout = 0;
		server_depth = 0;
	}

	RDP_SEC::~RDP_SEC()
	{
		sec_reset_state();
	}

	void RDP_SEC::sec_make_40bit(uint8 * key)
	{
		key[0] = 0xd1;
		key[1] = 0x26;
		key[2] = 0x9e;
	}

	void RDP_SEC::sec_generate_keys(uint8 * client_random, uint8 * server_random, int rc4_key_size)
	{
		uint8 pre_master_secret[48];
		uint8 master_secret[48];
		uint8 key_block[48];

		/* Construct pre-master secret */
		memcpy(pre_master_secret, client_random, 24);
		memcpy(pre_master_secret + 24, server_random, 24);

		/* Generate master secret and then key material */
		sec_hash_48(master_secret, pre_master_secret, client_random, server_random, 'A');
		sec_hash_48(key_block, master_secret, client_random, server_random, 'X');

		/* First 16 bytes of key material is MAC secret */
		memcpy(sec_sign_key, key_block, 16);

		/* Generate export keys from next two blocks of 16 bytes */
		sec_hash_16(sec_decrypt_key, &key_block[16], client_random, server_random);
		sec_hash_16(sec_encrypt_key, &key_block[32], client_random, server_random);

		if (rc4_key_size == 1)
		{
			DEBUG(("40-bit encryption enabled\n"));
			sec_make_40bit(sec_sign_key);
			sec_make_40bit(sec_decrypt_key);
			sec_make_40bit(sec_encrypt_key);
			rc4_key_len = 8;
		}
		else
		{
			DEBUG(("rc_4_key_size == %d, 128-bit encryption enabled\n", rc4_key_size));
			rc4_key_len = 16;
		}

		/* Save initial RC4 keys as update keys */
		memcpy(sec_decrypt_update_key, sec_decrypt_key, 16);
		memcpy(sec_encrypt_update_key, sec_encrypt_key, 16);

		/* Initialise RC4 state arrays */
		ssl_rc4_set_key(&rc4_decrypt_key, sec_decrypt_key, rc4_key_len);
		ssl_rc4_set_key(&rc4_encrypt_key, sec_encrypt_key, rc4_key_len);
	}

	void RDP_SEC::sec_update(uint8 * key, uint8 * update_key)
	{
		uint8 shasig[20];
		SSL_SHA1 sha1;
		SSL_MD5 md5;
		SSL_RC4 update;

		ssl_sha1_init(&sha1);
		ssl_sha1_update(&sha1, update_key, rc4_key_len);
		ssl_sha1_update(&sha1, pad_54, 40);
		ssl_sha1_update(&sha1, key, rc4_key_len);
		ssl_sha1_final(&sha1, shasig);

		ssl_md5_init(&md5);
		ssl_md5_update(&md5, update_key, rc4_key_len);
		ssl_md5_update(&md5, pad_92, 48);
		ssl_md5_update(&md5, shasig, 20);
		ssl_md5_final(&md5, key);

		ssl_rc4_set_key(&update, key, rc4_key_len);
		ssl_rc4_crypt(&update, key, key, rc4_key_len);

		if (rc4_key_len == 8)
			sec_make_40bit(key);
	}

	void RDP_SEC::sec_encrypt(uint8 * data, int length)
	{
		if (sec_encrypt_use_count == 4096)
		{
			sec_update(sec_encrypt_key, sec_encrypt_update_key);
			ssl_rc4_set_key(&rc4_encrypt_key, sec_encrypt_key, rc4_key_len);
			sec_encrypt_use_count = 0;
		}

		ssl_rc4_crypt(&rc4_encrypt_key, data, data, length);
		sec_encrypt_use_count++;
	}

	void RDP_SEC::sec_rsa_encrypt(uint8 * out, uint8 * in, int len, uint32 modulus_size, uint8 * modulus, uint8 * exponent)
	{
		ssl_rsa_encrypt(out, in, len, modulus_size, modulus, exponent);
	}

	void RDP_SEC::sec_establish_key(void)
	{
		uint32 length = server_public_key_len + SEC_PADDING_SIZE;
		uint32 flags = SEC_CLIENT_RANDOM;
		STREAM s;

		s = sec_init(flags, length + 4);

		out_uint32_le(s, length);										// s->p = length; s->p += 2;
		out_uint8p(s, sec_crypted_random, server_public_key_len);		// s->p <= crypted_random
		out_uint8s(s, SEC_PADDING_SIZE);								// s->p <= padding

		s_mark_end(s);
		sec_send(s, flags);
	}

	void RDP_SEC::sec_out_mcs_data(STREAM s)
	{
		unsigned int hostlen = 2 * strlen(hostname);
		unsigned int length = 158 + 76 + 12 + 4;

		if (num_channels > 0)
			length += num_channels * 12 + 8;

		if (hostlen > 30)
			hostlen = 30;

		/* Generic Conference Control (T.124) ConferenceCreateRequest */
		out_uint16_be(s, 5);
		out_uint16_be(s, 0x14);
		out_uint8(s, 0x7c);
		out_uint16_be(s, 1);

		out_uint16_be(s, (length | 0x8000));	/* remaining length */

		out_uint16_be(s, 8);	/* length? */
		out_uint16_be(s, 16);
		out_uint8(s, 0);
		out_uint16_le(s, 0xc001);
		out_uint8(s, 0);

		out_uint32_le(s, 0x61637544);	/* OEM ID: "Duca", as in Ducati. */
		out_uint16_be(s, ((length - 14) | 0x8000));	/* remaining length */

		/* Client information */
		out_uint16_le(s, SEC_TAG_CLI_INFO);
		out_uint16_le(s, 212);	/* length */
		out_uint16_le(s, use_rdp5 ? 4 : 1);	/* RDP version. 1 == RDP4, 4 == RDP5. */
		out_uint16_le(s, 8);
		out_uint16_le(s, width);
		out_uint16_le(s, height);
		out_uint16_le(s, 0xca01);
		out_uint16_le(s, 0xaa03);
		out_uint32_le(s, keylayout);
		out_uint32_le(s, 2600);	/* Client build. We are now 2600 compatible :-) */

		/* Unicode name of client, padded to 32 bytes */
		rdp_out_unistr(s, hostname, hostlen);
		out_uint8s(s, 30 - hostlen);

		/* See
		http://msdn.microsoft.com/library/default.asp?url=/library/en-us/wceddk40/html/cxtsksupportingremotedesktopprotocol.asp */
		out_uint32_le(s, keyboard_type);
		out_uint32_le(s, keyboard_subtype);
		out_uint32_le(s, keyboard_functionkeys);
		out_uint8s(s, 64);	/* reserved? 4 + 12 doublewords */
		out_uint16_le(s, 0xca01);	/* colour depth? */
		out_uint16_le(s, 1);

		out_uint32(s, 0);
		out_uint8(s, server_depth);
		out_uint16_le(s, 0x0700);
		out_uint8(s, 0);
		out_uint32_le(s, 1);
		out_uint8s(s, 64);	/* End of client info */

		out_uint16_le(s, SEC_TAG_CLI_4);
		out_uint16_le(s, 12);
		out_uint32_le(s, console_session ? 0xb : 9);
		out_uint32(s, 0);

		/* Client encryption settings */
		out_uint16_le(s, SEC_TAG_CLI_CRYPT);
		out_uint16_le(s, 12);	/* length */
		out_uint32_le(s, encryption ? 0x3 : 0);	/* encryption supported, 128-bit supported */
		out_uint32(s, 0);	/* Unknown */

		DEBUG_RDP5(("num_channels is %d\n", num_channels));
		if (num_channels > 0)
		{
			out_uint16_le(s, SEC_TAG_CLI_CHANNELS);
			out_uint16_le(s, num_channels * 12 + 8);	/* length */
			out_uint32_le(s, num_channels);	/* number of virtual channels */
			for (unsigned int i = 0; i < num_channels; i++)
			{
				DEBUG_RDP5(("Requesting channel %s\n", channels[i].name));
				out_uint8a(s, channels[i].name, 8);
				out_uint32_be(s, channels[i].flags);
			}
		}

		s_mark_end(s);
	}

	RD_BOOL RDP_SEC::sec_parse_public_key(STREAM s, uint8 * modulus, uint8 * exponent)
	{
		uint32 magic, modulus_len;

		in_uint32_le(s, magic);
		if (magic != SEC_RSA_MAGIC)
		{
			error("RSA magic 0x%x\n", magic);
			return False;
		}

		in_uint32_le(s, modulus_len);
		modulus_len -= SEC_PADDING_SIZE;
		if ((modulus_len < SEC_MODULUS_SIZE) || (modulus_len > SEC_MAX_MODULUS_SIZE))
		{
			error("Bad server public key size (%u bits)\n", modulus_len * 8);
			return False;
		}

		in_uint8s(s, 8);	/* modulus_bits, unknown */
		in_uint8a(s, exponent, SEC_EXPONENT_SIZE);
		in_uint8a(s, modulus, modulus_len);
		in_uint8s(s, SEC_PADDING_SIZE);
		server_public_key_len = modulus_len;

		return s_check(s);
	}

	RD_BOOL RDP_SEC::sec_parse_public_sig(STREAM s, uint32 len, uint8 * modulus, uint8 * exponent)
	{
		uint8 signature[SEC_MAX_MODULUS_SIZE];
		uint32 sig_len;

		if (len != 72)
		{
			return True;
		}
		memset(signature, 0, sizeof(signature));
		sig_len = len - 8;
		in_uint8a(s, signature, sig_len);
		return ssl_sig_ok(exponent, SEC_EXPONENT_SIZE, modulus, server_public_key_len,
			signature, sig_len);
	}

	RD_BOOL RDP_SEC::sec_parse_crypt_info(STREAM s, uint32 * rc4_key_size, uint8 ** server_random, uint8 * modulus, uint8 * exponent)
	{
		uint32 crypt_level, random_len, rsa_info_len;
		uint32 cacert_len, cert_len, flags;
		SSL_CERT *cacert, *server_cert;
		SSL_RKEY *server_public_key;
		uint16 tag, length;
		uint8 *next_tag, *end;

		in_uint32_le(s, *rc4_key_size);	/* 1 = 40-bit, 2 = 128-bit */
		in_uint32_le(s, crypt_level);	/* 1 = low, 2 = medium, 3 = high */
		if (crypt_level == 0)	/* no encryption */
			return False;
		in_uint32_le(s, random_len);
		in_uint32_le(s, rsa_info_len);

		if (random_len != SEC_RANDOM_SIZE)
		{
			error("random len %d, expected %d\n", random_len, SEC_RANDOM_SIZE);
			return False;
		}

		in_uint8p(s, *server_random, random_len);

		/* RSA info */
		end = s->p + rsa_info_len;
		if (end > s->end)
			return False;

		in_uint32_le(s, flags);	/* 1 = RDP4-style, 0x80000002 = X.509 */
		if (flags & 1)
		{
			DEBUG_RDP5(("We're going for the RDP4-style encryption\n"));
			in_uint8s(s, 8);	/* unknown */

			while (s->p < end)
			{
				in_uint16_le(s, tag);
				in_uint16_le(s, length);

				next_tag = s->p + length;

				switch (tag)
				{
				case SEC_TAG_PUBKEY:
					if (!sec_parse_public_key(s, modulus, exponent))
						return False;
					DEBUG_RDP5(("Got Public key, RDP4-style\n"));

					break;

				case SEC_TAG_KEYSIG:
					if (!sec_parse_public_sig(s, length, modulus, exponent))
						return False;
					break;

				default:
					unimpl("crypt tag 0x%x\n", tag);
				}

				s->p = next_tag;
			}
		}
		else
		{
			uint32 certcount;

			DEBUG_RDP5(("We're going for the RDP5-style encryption\n"));
			in_uint32_le(s, certcount);	/* Number of certificates */
			if (certcount < 2)
			{
				error("Server didn't send enough X509 certificates\n");
				return False;
			}
			for (; certcount > 2; certcount--)
			{		/* ignore all the certificates between the root and the signing CA */
				uint32 ignorelen;
				SSL_CERT *ignorecert;

				DEBUG_RDP5(("Ignored certs left: %d\n", certcount));
				in_uint32_le(s, ignorelen);
				DEBUG_RDP5(("Ignored Certificate length is %d\n", ignorelen));
				ignorecert = ssl_cert_read(s->p, ignorelen);
				in_uint8s(s, ignorelen);
				if (ignorecert == NULL)
				{	/* XXX: error out? */
					DEBUG_RDP5(("got a bad cert: this will probably screw up the rest of the communication\n"));
				}

#ifdef WITH_DEBUG_RDP5
				DEBUG_RDP5(("cert #%d (ignored):\n", certcount));
				ssl_cert_print_fp(stdout, ignorecert);
#endif
			}
			/* Do da funky X.509 stuffy

			"How did I find out about this?  I looked up and saw a
			bright light and when I came to I had a scar on my forehead
			and knew about X.500"
			- Peter Gutman in a early version of
			http://www.cs.auckland.ac.nz/~pgut001/pubs/x509guide.txt
			*/
			in_uint32_le(s, cacert_len);
			DEBUG_RDP5(("CA Certificate length is %d\n", cacert_len));
			cacert = ssl_cert_read(s->p, cacert_len);
			in_uint8s(s, cacert_len);
			if (NULL == cacert)
			{
				error("Couldn't load CA Certificate from server\n");
				return False;
			}
			in_uint32_le(s, cert_len);
			DEBUG_RDP5(("Certificate length is %d\n", cert_len));
			server_cert = ssl_cert_read(s->p, cert_len);
			in_uint8s(s, cert_len);
			if (NULL == server_cert)
			{
				ssl_cert_free(cacert);
				error("Couldn't load Certificate from server\n");
				return False;
			}
			if (!ssl_certs_ok(server_cert, cacert))
			{
				ssl_cert_free(server_cert);
				ssl_cert_free(cacert);
				error("Security error CA Certificate invalid\n");
				return False;
			}
			ssl_cert_free(cacert);
			in_uint8s(s, 16);	/* Padding */
			server_public_key = ssl_cert_to_rkey(server_cert, &server_public_key_len);
			if (NULL == server_public_key)
			{
				DEBUG_RDP5(("Didn't parse X509 correctly\n"));
				ssl_cert_free(server_cert);
				return False;
			}
			ssl_cert_free(server_cert);
			if ((server_public_key_len < SEC_MODULUS_SIZE) ||
				(server_public_key_len > SEC_MAX_MODULUS_SIZE))
			{
				error("Bad server public key size (%u bits)\n",
					server_public_key_len * 8);
				ssl_rkey_free(server_public_key);
				return False;
			}
			if (ssl_rkey_get_exp_mod(server_public_key, exponent, SEC_EXPONENT_SIZE,
				modulus, SEC_MAX_MODULUS_SIZE) != 0)
			{
				error("Problem extracting RSA exponent, modulus");
				ssl_rkey_free(server_public_key);
				return False;
			}
			ssl_rkey_free(server_public_key);
			return True;	/* There's some garbage here we don't care about */
		}
		return s_check_end(s);
	}

	void RDP_SEC::sec_process_crypt_info(STREAM s)
	{
		uint8 *server_random = NULL;
		uint8 client_random[SEC_RANDOM_SIZE];
		uint8 modulus[SEC_MAX_MODULUS_SIZE];
		uint8 exponent[SEC_EXPONENT_SIZE];
		uint32 rc4_key_size;

		memset(modulus, 0, sizeof(modulus));
		memset(exponent, 0, sizeof(exponent));
		if (!sec_parse_crypt_info(s, &rc4_key_size, &server_random, modulus, exponent))
		{
			DEBUG(("Failed to parse crypt info\n"));
			return;
		}
		DEBUG(("Generating client random\n"));
		generate_random(client_random);
		sec_rsa_encrypt(sec_crypted_random, client_random, SEC_RANDOM_SIZE,
			server_public_key_len, modulus, exponent);
		sec_generate_keys(client_random, server_random, rc4_key_size);
	}

	void RDP_SEC::sec_process_srv_info(STREAM s)
	{
		in_uint16_le(s, server_rdp_version);
		DEBUG_RDP5(("Server RDP version is %d\n", server_rdp_version));
		if (1 == server_rdp_version)
		{
			use_rdp5 = 0;
			server_depth = 8;
		}
	}

	void RDP_SEC::sec_hash_48(uint8 * out, uint8 * in, uint8 * salt1, uint8 * salt2, uint8 salt)
	{
		uint8 shasig[20];
		uint8 pad[4];
		SSL_SHA1 sha1;
		SSL_MD5 md5;
		int i;

		for (i = 0; i < 3; i++)
		{
			memset(pad, salt + i, i + 1);

			ssl_sha1_init(&sha1);
			ssl_sha1_update(&sha1, pad, i + 1);
			ssl_sha1_update(&sha1, in, 48);
			ssl_sha1_update(&sha1, salt1, 32);
			ssl_sha1_update(&sha1, salt2, 32);
			ssl_sha1_final(&sha1, shasig);

			ssl_md5_init(&md5);
			ssl_md5_update(&md5, in, 48);
			ssl_md5_update(&md5, shasig, 20);
			ssl_md5_final(&md5, &out[i * 16]);
		}
	}

	void RDP_SEC::sec_hash_16(uint8 * out, uint8 * in, uint8 * salt1, uint8 * salt2)
	{
		SSL_MD5 md5;

		ssl_md5_init(&md5);
		ssl_md5_update(&md5, in, 16);
		ssl_md5_update(&md5, salt1, 32);
		ssl_md5_update(&md5, salt2, 32);
		ssl_md5_final(&md5, out);
	}

	void RDP_SEC::buf_out_uint32(uint8 * buffer, uint32 value)
	{
		buffer[0] = (value) & 0xff;
		buffer[1] = (value >> 8) & 0xff;
		buffer[2] = (value >> 16) & 0xff;
		buffer[3] = (value >> 24) & 0xff;
	}

	void RDP_SEC::sec_sign(uint8 * signature, int siglen, uint8 * session_key, int keylen, uint8 * data, int datalen)
	{
		uint8 shasig[20];
		uint8 md5sig[16];
		uint8 lenhdr[4];
		SSL_SHA1 sha1;
		SSL_MD5 md5;

		buf_out_uint32(lenhdr, datalen);

		ssl_sha1_init(&sha1);
		ssl_sha1_update(&sha1, session_key, keylen);
		ssl_sha1_update(&sha1, pad_54, 40);
		ssl_sha1_update(&sha1, lenhdr, 4);
		ssl_sha1_update(&sha1, data, datalen);
		ssl_sha1_final(&sha1, shasig);

		ssl_md5_init(&md5);
		ssl_md5_update(&md5, session_key, keylen);
		ssl_md5_update(&md5, pad_92, 48);
		ssl_md5_update(&md5, shasig, 20);
		ssl_md5_final(&md5, md5sig);

		memcpy(signature, md5sig, siglen);
	}

	void RDP_SEC::sec_decrypt(uint8 * data, int length)
	{
		if (sec_decrypt_use_count == 4096)
		{
			sec_update(sec_decrypt_key, sec_decrypt_update_key);
			ssl_rc4_set_key(&rc4_decrypt_key, sec_decrypt_key, rc4_key_len);
			sec_decrypt_use_count = 0;
		}

		ssl_rc4_crypt(&rc4_decrypt_key, data, data, length);
		sec_decrypt_use_count++;
	}

	STREAM RDP_SEC::sec_init(uint32 flags, int maxlen)
	{
		int hdrlen;
		STREAM s;

		if (!licence_issued)
			hdrlen = (flags & SEC_ENCRYPT) ? 12 : 4;
		else
			hdrlen = (flags & SEC_ENCRYPT) ? 12 : 0;
		s = mcs_init(maxlen + hdrlen);
		s_push_layer(s, sec_hdr, hdrlen);

		return s;
	}

	void RDP_SEC::sec_send_to_channel(STREAM s, uint32 flags, uint16 channel)
	{
		int datalen;

#ifdef WITH_SCARD
		scard_lock(SCARD_LOCK_SEC);
#endif

		s_pop_layer(s, sec_hdr);
		if (!licence_issued || (flags & SEC_ENCRYPT))
			out_uint32_le(s, flags);

		if (flags & SEC_ENCRYPT)
		{
			flags &= ~SEC_ENCRYPT;
			datalen = s->end - s->p - 8;

#if WITH_DEBUG
			DEBUG(("Sending encrypted packet:\n"));
			hexdump(s->p + 8, datalen);
#endif

			sec_sign(s->p, 8, sec_sign_key, rc4_key_len, s->p + 8, datalen);
			sec_encrypt(s->p + 8, datalen);
		}

		mcs_send_to_channel(s, channel);

#ifdef WITH_SCARD
		scard_unlock(SCARD_LOCK_SEC);
#endif
	}

	void RDP_SEC::sec_send(STREAM s, uint32 flags)
	{
		sec_send_to_channel(s, flags, MCS_GLOBAL_CHANNEL);
	}

	void RDP_SEC::sec_process_mcs_data(STREAM s)
	{
		uint16 tag, length;
		uint8 *next_tag;
		uint8 len;

		in_uint8s(s, 21);	/* header (T.124 ConferenceCreateResponse) */
		in_uint8(s, len);
		if (len & 0x80)
			in_uint8(s, len);

		while (s->p < s->end)
		{
			in_uint16_le(s, tag);
			in_uint16_le(s, length);

			if (length <= 4)
				return;

			next_tag = s->p + length - 4;

			switch (tag)
			{
			case SEC_TAG_SRV_INFO:
				sec_process_srv_info(s);
				break;

			case SEC_TAG_SRV_CRYPT:
				sec_process_crypt_info(s);
				break;

			case SEC_TAG_SRV_CHANNELS:
				/* FIXME: We should parse this information and
				use it to map RDP5 channels to MCS
				channels */
				break;

			default:
				unimpl("response tag 0x%x\n", tag);
			}

			s->p = next_tag;
		}
	}

	STREAM RDP_SEC::sec_recv(uint8 * rdpver)
	{
		uint32 sec_flags;
		uint16 channel;
		STREAM s;

		while ((s = mcs_recv(&channel, rdpver)) != NULL)
		{
			if (rdpver != NULL)
			{
				if (*rdpver != 3)
				{
					if (*rdpver & 0x80)
					{
						in_uint8s(s, 8);	/* signature */
						sec_decrypt(s->p, s->end - s->p);
					}
					return s;
				}
			}
			if (encryption || !licence_issued)
			{
				in_uint32_le(s, sec_flags);

				if (sec_flags & SEC_ENCRYPT)
				{
					in_uint8s(s, 8);	/* signature */
					sec_decrypt(s->p, s->end - s->p);
				}

				if (sec_flags & SEC_LICENCE_NEG)
				{
					//licence_process(s);
					continue;
				}

				if (sec_flags & 0x0400)	/* SEC_REDIRECT_ENCRYPT */
				{
					uint8 swapbyte;

					in_uint8s(s, 8);	/* signature */
					sec_decrypt(s->p, s->end - s->p);

					/* Check for a redirect packet, starts with 00 04 */
					if (s->p[0] == 0 && s->p[1] == 4)
					{
						/* for some reason the PDU and the length seem to be swapped.
						This isn't good, but we're going to do a byte for byte
						swap.  So the first foure value appear as: 00 04 XX YY,
						where XX YY is the little endian length. We're going to
						use 04 00 as the PDU type, so after our swap this will look
						like: XX YY 04 00 */
						swapbyte = s->p[0];
						s->p[0] = s->p[2];
						s->p[2] = swapbyte;

						swapbyte = s->p[1];
						s->p[1] = s->p[3];
						s->p[3] = swapbyte;

						swapbyte = s->p[2];
						s->p[2] = s->p[3];
						s->p[3] = swapbyte;
					}
#ifdef WITH_DEBUG
					/* warning!  this debug statement will show passwords in the clear! */
					hexdump(s->p, s->end - s->p);
#endif
				}

			}

			if (channel != MCS_GLOBAL_CHANNEL)
			{
				channel_process(s, channel);
				*rdpver = 0xff;
				return s;
			}

			return s;
		}

		return NULL;
	}

	RD_BOOL RDP_SEC::sec_connect(char * server, char * username, uint16 server_rdp_version)
	{
		struct stream mcs_data;
		int hostlen = strlen(username);
		STREAM s;

		this->server_rdp_version = server_rdp_version;
		use_rdp5 = (server_rdp_version == 5) ? True : False;

		/* We exchange some RDP data during the MCS-Connect */
		mcs_data.size = 512;
		mcs_data.p = mcs_data.data = (uint8 *)xmalloc(mcs_data.size);
		sec_out_mcs_data(&mcs_data);

		s = mcs_connect(server, &mcs_data, username);
		if (s == NULL)
			goto error;

		sec_process_mcs_data(s);
		if (!s_check_end(s))
			goto error;

		if (!mcs_connect_final())
			goto error;

		/* sec_process_mcs_data(&mcs_data); */
		//if (encryption)
		sec_establish_key();
		xfree(mcs_data.data);
		return True;

	error:
		iso_disconnect();
		return False;
	}

	RD_BOOL RDP_SEC::sec_connect(char * server, uint16 port, char * username, uint16 server_rdp_version)
	{
		struct stream mcs_data;
		int hostlen = strlen(username);
		STREAM s;

		this->server_rdp_version = server_rdp_version;
		use_rdp5 = (server_rdp_version == 5) ? True : False;

		/* We exchange some RDP data during the MCS-Connect */
		mcs_data.size = 512;
		mcs_data.p = mcs_data.data = (uint8 *)xmalloc(mcs_data.size);
		sec_out_mcs_data(&mcs_data);

		s = mcs_connect(server, port, &mcs_data, username);
		if (s == NULL)
			goto error;

		sec_process_mcs_data(s);
		if (!s_check_end(s))
			goto error;

		if (!mcs_connect_final())
			goto error;

		/* sec_process_mcs_data(&mcs_data); */
		//if (encryption)
		sec_establish_key();
		xfree(mcs_data.data);
		return True;

	error:
		iso_disconnect();
		return False;
	}

	RD_BOOL RDP_SEC::sec_reconnect(char * server)
	{
		struct stream mcs_data;
		STREAM s;

		/* We exchange some RDP data during the MCS-Connect */
		mcs_data.size = 512;
		mcs_data.p = mcs_data.data = (uint8 *)xmalloc(mcs_data.size);
		sec_out_mcs_data(&mcs_data);

		s = mcs_reconnect(server, &mcs_data);
		sec_process_mcs_data(s);			// please check
		if (!s_check_end(s))
			goto error;

		if (!mcs_connect_final())
			goto error;

		/*      sec_process_mcs_data(&mcs_data); */
		//if (encryption)
		sec_establish_key();
		xfree(mcs_data.data);
		return True;

	error:
		iso_disconnect();
		return False;
	}

	void RDP_SEC::sec_disconnect(void)
	{
		mcs_disconnect();
	}

	void RDP_SEC::sec_reset_state(void)
	{
		server_rdp_version = 0;
		sec_encrypt_use_count = 0;
		sec_decrypt_use_count = 0;
		mcs_reset_state();
	}

	RD_BOOL RDP_SEC::isenabled_encryption(void)
	{
		return encryption;
	}

	void RDP_SEC::enable_encryption(RD_BOOL encrypt)
	{
		encryption = encrypt;
	}

	/* Generate a 32-byte random for the secure transport code. */
	void RDP_SEC::generate_random(uint8 * random)
	{
		//struct stat st;
		SSL_MD5 md5;
		//uint32 *r;
		//int fd, n;

		/* If we have a kernel random device, try that first */
		//if (((fd = open("/dev/urandom", O_RDONLY)) != -1)
		//	|| ((fd = open("/dev/random", O_RDONLY)) != -1))
		//{
		//	n = read(fd, random, 32);
		//	close(fd);
		//	if (n == 32)		// error?
		//		return;
		//}

#ifdef EGD_SOCKET
	/* As a second preference use an EGD */
		if (generate_random_egd(random))
			return;
#endif

		///* Otherwise use whatever entropy we can gather - ideas welcome. */
		//r = (uint32 *)random;
		//r[0] = (getpid()) | (getppid() << 16);
		//r[1] = (getuid()) | (getgid() << 16);
		//r[2] = times(&tmsbuf);	/* system uptime (clocks) */
		//gettimeofday((struct timeval *) &r[3], NULL);	/* sec and usec */
		//stat("/tmp", &st);
		//r[5] = st.st_atime;
		//r[6] = st.st_mtime;
		//r[7] = st.st_ctime;

		/* Hash both halves with MD5 to obscure possible patterns */
		ssl_md5_init(&md5);
		ssl_md5_update(&md5, random, 16);
		ssl_md5_final(&md5, random);
		ssl_md5_update(&md5, random + 16, 16);
		ssl_md5_final(&md5, random + 16);
	}

	void RDP_SEC::rdp_out_unistr(STREAM s, char * string, int len)
	{
#ifdef HAVE_ICONV
		size_t ibl = strlen(string), obl = len + 2;
		static iconv_t iconv_h = (iconv_t)-1;
		char *pin = string, *pout = (char *)s->p;

		memset(pout, 0, len + 4);

		if (g_iconv_works)
		{
			if (iconv_h == (iconv_t)-1)
			{
				size_t i = 1, o = 4;
				if ((iconv_h = iconv_open(WINDOWS_CODEPAGE, g_codepage)) == (iconv_t)-1)
				{
					warning("rdp_out_unistr: iconv_open[%s -> %s] fail %p\n",
						g_codepage, WINDOWS_CODEPAGE, iconv_h);

					g_iconv_works = False;
					rdp_out_unistr(s, string, len);
					return;
				}
				if (iconv(iconv_h, (ICONV_CONST char **) &pin, &i, &pout, &o) ==
					(size_t)-1)
				{
					iconv_close(iconv_h);
					iconv_h = (iconv_t)-1;
					warning("rdp_out_unistr: iconv(1) fail, errno %d\n", errno);

					g_iconv_works = False;
					rdp_out_unistr(s, string, len);
					return;
				}
				pin = string;
				pout = (char *)s->p;
			}

			if (iconv(iconv_h, (ICONV_CONST char **) &pin, &ibl, &pout, &obl) == (size_t)-1)
			{
				iconv_close(iconv_h);
				iconv_h = (iconv_t)-1;
				warning("rdp_out_unistr: iconv(2) fail, errno %d\n", errno);

				g_iconv_works = False;
				rdp_out_unistr(s, string, len);
				return;
			}

			s->p += len + 2;

		}
		else
#endif
		{
			int i = 0, j = 0;

			len += 2;

			while (i < len)
			{
				s->p[i++] = string[j++];
				s->p[i++] = 0;
			}

			s->p += len;
		}
	}

	int RDP_SEC::rdp_in_unistr(STREAM s, char * string, int str_size, int in_len)
	{
#ifdef HAVE_ICONV
		size_t ibl = in_len, obl = str_size - 1;
		char *pin = (char *)s->p, *pout = string;
		static iconv_t iconv_h = (iconv_t)-1;

		if (g_iconv_works)
		{
			if (iconv_h == (iconv_t)-1)
			{
				if ((iconv_h = iconv_open(g_codepage, WINDOWS_CODEPAGE)) == (iconv_t)-1)
				{
					warning("rdp_in_unistr: iconv_open[%s -> %s] fail %p\n",
						WINDOWS_CODEPAGE, g_codepage, iconv_h);

					g_iconv_works = False;
					return rdp_in_unistr(s, string, str_size, in_len);
				}
			}

			if (iconv(iconv_h, (ICONV_CONST char **) &pin, &ibl, &pout, &obl) == (size_t)-1)
			{
				if (errno == E2BIG)
				{
					warning("server sent an unexpectedly long string, truncating\n");
				}
				else
				{
					iconv_close(iconv_h);
					iconv_h = (iconv_t)-1;
					warning("rdp_in_unistr: iconv fail, errno %d\n", errno);

					g_iconv_works = False;
					return rdp_in_unistr(s, string, str_size, in_len);
				}
			}

			/* we must update the location of the current STREAM for future reads of s->p */
			s->p += in_len;

			*pout = 0;
			return pout - string;
		}
		else
#endif
		{
			int i = 0;
			int len = in_len / 2;
			int rem = 0;

			if (len > str_size - 1)
			{
				warning("server sent an unexpectedly long string, truncating\n");
				len = str_size - 1;
				rem = in_len - 2 * len;
			}

			while (i < len)
			{
				in_uint8a(s, &string[i++], 1);
				in_uint8s(s, 1);
			}

			in_uint8s(s, rem);
			string[len] = 0;
			return len;
		}
	}
}
