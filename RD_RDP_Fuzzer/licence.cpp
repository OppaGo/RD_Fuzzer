#include "secure.h"


namespace RD_FUZZER
{
	void RDP_SEC::licence_generate_keys(uint8 * client_random, uint8 * server_random, uint8 * pre_master_secret)
	{
		uint8 master_secret[48];
		uint8 key_block[48];

		/* Generate master secret and then key material */
		sec_hash_48(master_secret, pre_master_secret, client_random, server_random, 'A');
		sec_hash_48(key_block, master_secret, server_random, client_random, 'A');

		/* Store first 16 bytes of session key as MAC secret */
		memcpy(licence_sign_key, key_block, 16);

		/* Generate RC4 key from next 16 bytes */
		sec_hash_16(licence_key, &key_block[16], client_random, server_random);
	}

	void RDP_SEC::licence_generate_hwid(uint8 * hwid)
	{
		buf_out_uint32(hwid, 2);
		strncpy_s((char *)(hwid + 4), LICENCE_HWID_SIZE - 4, hostname, LICENCE_HWID_SIZE - 4);
	}

	void RDP_SEC::licence_present(uint8 * client_random, uint8 * rsa_data, uint8 * licence_data, int licence_size, uint8 * hwid, uint8 * signature)
	{
		uint32 sec_flags = SEC_LICENCE_NEG;
		uint16 length =
			16 + SEC_RANDOM_SIZE + SEC_MODULUS_SIZE + SEC_PADDING_SIZE +
			licence_size + LICENCE_HWID_SIZE + LICENCE_SIGNATURE_SIZE;
		STREAM s;

		s = sec_init(sec_flags, length + 4);

		out_uint8(s, LICENCE_TAG_PRESENT);
		out_uint8(s, 2);	/* version */
		out_uint16_le(s, length);

		out_uint32_le(s, 1);
		out_uint16(s, 0);
		out_uint16_le(s, 0x0201);

		out_uint8p(s, client_random, SEC_RANDOM_SIZE);
		out_uint16(s, 0);
		out_uint16_le(s, (SEC_MODULUS_SIZE + SEC_PADDING_SIZE));
		out_uint8p(s, rsa_data, SEC_MODULUS_SIZE);
		out_uint8s(s, SEC_PADDING_SIZE);

		out_uint16_le(s, 1);
		out_uint16_le(s, licence_size);
		out_uint8p(s, licence_data, licence_size);

		out_uint16_le(s, 1);
		out_uint16_le(s, LICENCE_HWID_SIZE);
		out_uint8p(s, hwid, LICENCE_HWID_SIZE);

		out_uint8p(s, signature, LICENCE_SIGNATURE_SIZE);

		s_mark_end(s);
		sec_send(s, sec_flags);
	}

	void RDP_SEC::licence_send_request(uint8 * client_random, uint8 * rsa_data, char * user, char * host)
	{
		uint32 sec_flags = SEC_LICENCE_NEG;
		uint16 userlen = (uint16)strlen(user) + 1;
		uint16 hostlen = (uint16)strlen(host) + 1;
		uint16 length = 128 + userlen + hostlen;
		STREAM s;

		s = sec_init(sec_flags, length + 2);

		out_uint8(s, LICENCE_TAG_REQUEST);
		out_uint8(s, 2);	/* version */
		out_uint16_le(s, length);

		out_uint32_le(s, 1);
		out_uint16(s, 0);
		out_uint16_le(s, 0xff01);

		out_uint8p(s, client_random, SEC_RANDOM_SIZE);
		out_uint16(s, 0);
		out_uint16_le(s, (SEC_MODULUS_SIZE + SEC_PADDING_SIZE));
		out_uint8p(s, rsa_data, SEC_MODULUS_SIZE);
		out_uint8s(s, SEC_PADDING_SIZE);

		out_uint16_le(s, LICENCE_TAG_USER);
		out_uint16_le(s, userlen);
		out_uint8p(s, user, userlen);

		out_uint16_le(s, LICENCE_TAG_HOST);
		out_uint16_le(s, hostlen);
		out_uint8p(s, host, hostlen);

		s_mark_end(s);
		sec_send(s, sec_flags);
	}

	void RDP_SEC::licence_process_demand(STREAM s)
	{
		uint8 null_data[SEC_MODULUS_SIZE];
		uint8 *server_random;
		uint8 signature[LICENCE_SIGNATURE_SIZE];
		uint8 hwid[LICENCE_HWID_SIZE];
		uint8 *licence_data;
		int licence_size;
		SSL_RC4 crypt_key;

		/* Retrieve the server random from the incoming packet */
		in_uint8p(s, server_random, SEC_RANDOM_SIZE);

		/* We currently use null client keys. This is a bit naughty but, hey,
		the security of licence negotiation isn't exactly paramount. */
		memset(null_data, 0, sizeof(null_data));
		licence_generate_keys(null_data, server_random, null_data);

		licence_size = load_licence(&licence_data);
		if (licence_size > 0)
		{
			/* Generate a signature for the HWID buffer */
			licence_generate_hwid(hwid);
			sec_sign(signature, 16, licence_sign_key, 16, hwid, sizeof(hwid));

			/* Now encrypt the HWID */
			ssl_rc4_set_key(&crypt_key, licence_key, 16);
			ssl_rc4_crypt(&crypt_key, hwid, hwid, sizeof(hwid));

			licence_present(null_data, null_data, licence_data, licence_size, hwid, signature);
			xfree(licence_data);
			return;
		}

		licence_send_request(null_data, null_data, username, hostname);
	}

	void RDP_SEC::licence_send_authresp(uint8 * token, uint8 * crypt_hwid, uint8 * signature)
	{
		uint32 sec_flags = SEC_LICENCE_NEG;
		uint16 length = 58;
		STREAM s;

		s = sec_init(sec_flags, length + 2);

		out_uint8(s, LICENCE_TAG_AUTHRESP);
		out_uint8(s, 2);	/* version */
		out_uint16_le(s, length);

		out_uint16_le(s, 1);
		out_uint16_le(s, LICENCE_TOKEN_SIZE);
		out_uint8p(s, token, LICENCE_TOKEN_SIZE);

		out_uint16_le(s, 1);
		out_uint16_le(s, LICENCE_HWID_SIZE);
		out_uint8p(s, crypt_hwid, LICENCE_HWID_SIZE);

		out_uint8p(s, signature, LICENCE_SIGNATURE_SIZE);

		s_mark_end(s);
		sec_send(s, sec_flags);
	}

	RD_BOOL RDP_SEC::licence_parse_authreq(STREAM s, uint8 ** token, uint8 ** signature)
	{
		uint16 tokenlen;

		in_uint8s(s, 6);	/* unknown: f8 3d 15 00 04 f6 */

		in_uint16_le(s, tokenlen);
		if (tokenlen != LICENCE_TOKEN_SIZE)
		{
			error("token len %d\n", tokenlen);
			return False;
		}

		in_uint8p(s, *token, tokenlen);
		in_uint8p(s, *signature, LICENCE_SIGNATURE_SIZE);

		return s_check_end(s);
	}

	void RDP_SEC::licence_process_authreq(STREAM s)
	{
		uint8 *in_token = NULL, *in_sig;
		uint8 out_token[LICENCE_TOKEN_SIZE], decrypt_token[LICENCE_TOKEN_SIZE];
		uint8 hwid[LICENCE_HWID_SIZE], crypt_hwid[LICENCE_HWID_SIZE];
		uint8 sealed_buffer[LICENCE_TOKEN_SIZE + LICENCE_HWID_SIZE];
		uint8 out_sig[LICENCE_SIGNATURE_SIZE];
		SSL_RC4 crypt_key;

		/* Parse incoming packet and save the encrypted token */
		licence_parse_authreq(s, &in_token, &in_sig);
		memcpy(out_token, in_token, LICENCE_TOKEN_SIZE);

		/* Decrypt the token. It should read TEST in Unicode. */
		ssl_rc4_set_key(&crypt_key, licence_key, 16);
		ssl_rc4_crypt(&crypt_key, in_token, decrypt_token, LICENCE_TOKEN_SIZE);

		/* Generate a signature for a buffer of token and HWID */
		licence_generate_hwid(hwid);
		memcpy(sealed_buffer, decrypt_token, LICENCE_TOKEN_SIZE);
		memcpy(sealed_buffer + LICENCE_TOKEN_SIZE, hwid, LICENCE_HWID_SIZE);
		sec_sign(out_sig, 16, licence_sign_key, 16, sealed_buffer, sizeof(sealed_buffer));

		/* Now encrypt the HWID */
		ssl_rc4_set_key(&crypt_key, licence_key, 16);
		ssl_rc4_crypt(&crypt_key, hwid, crypt_hwid, LICENCE_HWID_SIZE);

		licence_send_authresp(out_token, crypt_hwid, out_sig);
	}

	void RDP_SEC::licence_process_issue(STREAM s)
	{
		SSL_RC4 crypt_key;
		uint32 length;
		uint16 check;
		int i;

		in_uint8s(s, 2);	/* 3d 45 - unknown */
		in_uint16_le(s, length);
		if (!s_check_rem(s, length))
			return;

		ssl_rc4_set_key(&crypt_key, licence_key, 16);
		ssl_rc4_crypt(&crypt_key, s->p, s->p, length);

		in_uint16(s, check);
		if (check != 0)
			return;

		licence_issued = True;

		in_uint8s(s, 2);	/* pad */

							/* advance to fourth string */
		length = 0;
		for (i = 0; i < 4; i++)
		{
			in_uint8s(s, length);
			in_uint32_le(s, length);
			if (!s_check_rem(s, length))
				return;
		}

		licence_issued = True;
		save_licence(s->p, length);
	}

	void RDP_SEC::licence_process(STREAM s)
	{
		uint8 tag;

		in_uint8(s, tag);
		in_uint8s(s, 3);	/* version, length */

		switch (tag)
		{
		case LICENCE_TAG_DEMAND:
			licence_process_demand(s);
			break;

		case LICENCE_TAG_AUTHREQ:
			licence_process_authreq(s);
			break;

		case LICENCE_TAG_ISSUE:
			licence_process_issue(s);
			break;

		case LICENCE_TAG_REISSUE:
		case LICENCE_TAG_RESULT:
			break;

		default:
			unimpl("licence tag 0x%x\n", tag);
		}
	}

	void RDP_SEC::save_licence(unsigned char *data, int length)
	{
		//char *home, *path, *tmppath;
		//int fd;

		//home = getenv("HOME");
		//if (home == NULL)
		//return;

		//path = (char *)xmalloc(strlen(home) + strlen(hostname) + sizeof("/.rdesktop/licence."));

		//sprintf(path, "%s/.rdesktop", home);
		//if ((mkdir(path, 0700) == -1) && errno != EEXIST)
		//{
		//perror(path);
		//return;
		//}

		///* write licence to licence.hostname.new, then atomically rename to licence.hostname */

		//sprintf(path, "%s/.rdesktop/licence.%s", home, hostname);
		//tmppath = (char *)xmalloc(strlen(path) + sizeof(".new"));
		//strcpy(tmppath, path);
		//strcat(tmppath, ".new");

		//fd = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		//if (fd == -1)
		//{
		//perror(tmppath);
		//return;
		//}

		//if (write(fd, data, length) != length)
		//{
		//perror(tmppath);
		//unlink(tmppath);
		//}
		//else if (rename(tmppath, path) == -1)
		//{
		//perror(path);
		//unlink(tmppath);
		//}

		//close(fd);
		//xfree(tmppath);
		//xfree(path);
	}
	int RDP_SEC::load_licence(unsigned char **data) {
		//char *home, *path;
		//struct stat st;
		//int fd, length;

		//home = getenv("HOME");
		//if (home == NULL)
		//	return -1;

		//path = (char *)xmalloc(strlen(home) + strlen(hostname) + sizeof("/.rdesktop/licence."));
		//sprintf(path, "%s/.rdesktop/licence.%s", home, hostname);

		//fd = open(path, O_RDONLY);
		//if (fd == -1)
		//	return -1;

		//if (fstat(fd, &st))
		//	return -1;

		//*data = (uint8 *)xmalloc(st.st_size);
		//length = read(fd, *data, st.st_size);
		//close(fd);
		//xfree(path);
		//return length;
	}
}
