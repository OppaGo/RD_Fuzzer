#ifndef __SECURE_H__
#define __SECURE_H__

#include "mcs.h"
#include "ssl.h"

#define CHANNEL_CHUNK_LENGTH		1600
#define CHANNEL_FLAG_FIRST			0x01
#define CHANNEL_FLAG_LAST			0x02
#define CHANNEL_FLAG_SHOW_PROTOCOL	0x10

namespace RD_FUZZER
{
	class RDP_SEC :protected RDP_MCS, protected RDP_SSL
	{
	private:
		int rc4_key_len;
		SSL_RC4 rc4_decrypt_key;
		SSL_RC4 rc4_encrypt_key;
		uint32 server_public_key_len;

		uint8 sec_sign_key[16];
		uint8 sec_decrypt_key[16];
		uint8 sec_encrypt_key[16];
		uint8 sec_decrypt_update_key[16];
		uint8 sec_encrypt_update_key[16];
		uint8 sec_crypted_random[SEC_MAX_MODULUS_SIZE];

		/* These values must be available to reset state - Session Directory */
		int sec_encrypt_use_count;
		int sec_decrypt_use_count;

		uint8 pad_54[40];	//54
		uint8 pad_92[48];	//92

		// for licence
		RD_BOOL licence_issued = False;
		uint8 licence_key[16];
		uint8 licence_sign_key[16];

		RD_BOOL console_session;

		int keyboard_type;
		int keyboard_subtype;
		int keyboard_functionkeys;
		unsigned int keylayout;

		RD_BOOL use_rdp5;
		uint16 server_rdp_version;

	protected:
		RD_BOOL encryption;
		int server_depth;

		char hostname[16];
		char username[64];
		int width;
		int height;

	protected:
		/* Reduce key entropy from 64 to 40 bits */
		void sec_make_40bit(uint8 * key);
		/* Generate encryption keys given client and server randoms */
		void sec_generate_keys(uint8 * client_random, uint8 * server_random, int rc4_key_size);
		/* Update an encryption key */
		void sec_update(uint8 * key, uint8 * update_key);
		/* Encrypt data using RC4 */
		void sec_encrypt(uint8 * data, int length);
		/* Perform an RSA public key encryption operation */
		void sec_rsa_encrypt(uint8 * out, uint8 * in, int len, uint32 modulus_size, uint8 * modulus, uint8 * exponent);
		/* Transfer the client random to the server */
		void sec_establish_key(void);
		/* Output connect initial data blob */
		void sec_out_mcs_data(STREAM s);
		/* Parse a public key structure */
		RD_BOOL sec_parse_public_key(STREAM s, uint8 * modulus, uint8 * exponent);
		/* Parse a public signature structure */
		RD_BOOL sec_parse_public_sig(STREAM s, uint32 len, uint8 * modulus, uint8 * exponent);
		/* Parse a crypto information structure */
		RD_BOOL sec_parse_crypt_info(STREAM s, uint32 * rc4_key_size, uint8 ** server_random, uint8 * modulus, uint8 * exponent);
		/* Process crypto information blob */
		void sec_process_crypt_info(STREAM s);
		/* Process SRV_INFO, find RDP version supported by server */
		void sec_process_srv_info(STREAM s);
		/* Generate a 32-byte random for the secure transport code. */
		void generate_random(uint8 * random);

		// RDP_CHANNER function
		VCHANNEL* channel_register(char *name, uint32 flags, void(*callback) (STREAM));
		STREAM channel_init(VCHANNEL * channel, uint32 length);
		void channel_send(STREAM s, VCHANNEL * channel);
		void channel_process(STREAM s, uint16 mcs_channel);

		// RDP_LICENCE function
		/* Generate a session key and RC4 keys, given client and server randoms */
		void licence_generate_keys(uint8 * client_random, uint8 * server_random, uint8 * pre_master_secret);
		void licence_generate_hwid(uint8 * hwid);
		/* Present an existing licence to the server */
		void licence_present(uint8 * client_random, uint8 * rsa_data, uint8 * licence_data, int licence_size, uint8 * hwid, uint8 * signature);
		/* Send a licence request packet */
		void licence_send_request(uint8 * client_random, uint8 * rsa_data, char *user, char *host);
		/* Process a licence demand packet */
		void licence_process_demand(STREAM s);
		/* Send an authentication response packet */
		void licence_send_authresp(uint8 * token, uint8 * crypt_hwid, uint8 * signature);
		/* Parse an authentication request packet */
		RD_BOOL licence_parse_authreq(STREAM s, uint8 ** token, uint8 ** signature);
		/* Process an authentication request packet */
		void licence_process_authreq(STREAM s);
		/* Process an licence issue packet */
		void licence_process_issue(STREAM s);

	public:
		RDP_SEC();
		~RDP_SEC();
		bool sec_Init_config_from_File(const char* config_file = "./RD_RDP_Fuzzer.yaml");
		/* 48-byte transformation used to generate master secret (6.1) and key material (6.2.2).
		 * Both SHA1 and MD5 algorithms are used. */
		void sec_hash_48(uint8 * out, uint8 * in, uint8 * salt1, uint8 * salt2, uint8 salt);
		/* 16-byte transformation used to generate export keys (6.2.2). */
		void sec_hash_16(uint8 * out, uint8 * in, uint8 * salt1, uint8 * salt2);
		/* Output a uint32 into a buffer (little-endian) */
		void buf_out_uint32(uint8 * buffer, uint32 value);
		/* Generate a MAC hash (5.2.3.1), using a combination of SHA1 and MD5 */
		void sec_sign(uint8 * signature, int siglen, uint8 * session_key, int keylen, uint8 * data, int datalen);
		/* Decrypt data using RC4 */
		void sec_decrypt(uint8 * data, int length);
		/* Initialise secure transport packet */
		STREAM sec_init(uint32 flags, int maxlen);
		/* Transmit secure transport packet over specified channel */
		void sec_send_to_channel(STREAM s, uint32 flags, uint16 channel);
		/* Transmit ssecure transport packet */
		void sec_send(STREAM s, uint32 flags);
		/* Process connect response data blob */
		void sec_process_mcs_data(STREAM s);
		/* Receive secure transport packet */
		STREAM sec_recv(uint8 * rdpver);
		/* Establish a secure connection */
		RD_BOOL sec_connect(char * server, char * username, uint16 server_rdp_version);
		RD_BOOL sec_connect(char * server, uint16 port, char * username, uint16 server_rdp_version);
		/* Establish a secure connection */
		RD_BOOL sec_reconnect(char *server);
		/* Disconnect a connection */
		void sec_disconnect(void);
		/* reset the state of the sec layer */
		void sec_reset_state(void);
		RD_BOOL isenabled_encryption(void);
		void enable_encryption(RD_BOOL encrypt);

		// RDP_LICENCE function
		/* Process a licence packet */
		void licence_process(STREAM s);
		void save_licence(unsigned char *data, int length);
		int load_licence(unsigned char **data);

		//RDP Unicode
		/* Output a string in Unicode */
		void rdp_out_unistr(STREAM s, char *string, int len);
		/* Input a string in Unicode, Returns str_len of string */
		int rdp_in_unistr(STREAM s, char *string, int str_size, int in_len);
	};
}

#endif
