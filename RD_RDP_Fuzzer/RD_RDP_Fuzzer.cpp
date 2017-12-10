#include "RD_RDP_Fuzzer.h"



void print_disconnect_reason(uint16 reason)	// 연결 해제 이유
{
	char *text;

	switch (reason)
	{
	case exDiscReasonNoInfo:
		text = "[+] No information available";
		break;

	case exDiscReasonAPIInitiatedDisconnect:
		text = "[+] Server initiated disconnect";
		break;

	case exDiscReasonAPIInitiatedLogoff:
		text = "[+] Server initiated logoff";
		break;

	case exDiscReasonServerIdleTimeout:
		text = "[-] Server idle timeout reached";
		break;

	case exDiscReasonServerLogonTimeout:
		text = "[-] Server logon timeout reached";
		break;

	case exDiscReasonReplacedByOtherConnection:
		text = "[-] The session was replaced";
		break;

	case exDiscReasonOutOfMemory:
		text = "[-] The server is out of memory";
		break;

	case exDiscReasonServerDeniedConnection:
		text = "[-] The server denied the connection";
		break;

	case exDiscReasonServerDeniedConnectionFips:
		text = "[-] The server denied the connection for security reason";
		break;

	case exDiscReasonLicenseInternal:
		text = "[-] Internal licensing error";
		break;

	case exDiscReasonLicenseNoLicenseServer:
		text = "[-] No license server available";
		break;

	case exDiscReasonLicenseNoLicense:
		text = "[-] No valid license available";
		break;

	case exDiscReasonLicenseErrClientMsg:
		text = "[-] Invalid licensing message";
		break;

	case exDiscReasonLicenseHwidDoesntMatchLicense:
		text = "[-] Hardware id doesn't match software license";
		break;

	case exDiscReasonLicenseErrClientLicense:
		text = "[-] Client license error";
		break;

	case exDiscReasonLicenseCantFinishProtocol:
		text = "[-] Network error during licensing protocol";
		break;

	case exDiscReasonLicenseClientEndedProtocol:
		text = "[-] Licensing protocol was not completed";
		break;

	case exDiscReasonLicenseErrClientEncryption:
		text = "[-] Incorrect client license enryption";
		break;

	case exDiscReasonLicenseCantUpgradeLicense:
		text = "[-] Can't upgrade license";
		break;

	case exDiscReasonLicenseNoRemoteConnections:
		text = "[-] The server is not licensed to accept remote connections";
		break;

	default:
		if (reason > 0x1000 && reason < 0x7fff)
		{
			text = "[-] Internal protocol error";
		}
		else
		{
			text = "[-] Unknown reason";
		}
	}
	fprintf(stderr, "[+] disconnect: \n%s.\n", text);
}

extern "C" RD_RDP_FUZZER_API PRDPFuzzer OpenRDPFuzzer(const char * config_file)
{
	RD_FUZZER::RDP* rdp = new RD_FUZZER::RDP();

	rdp->Init_config(config_file);

	return (PRDPFuzzer)rdp;
}

extern "C" RD_RDP_FUZZER_API void CloseRDPFuzzer(PRDPFuzzer prdp)
{
	RD_FUZZER::RDP* rdp = (RD_FUZZER::RDP*) prdp;

	delete rdp;
}

extern "C" RD_RDP_FUZZER_API RD_BOOL RDPFuzzing(PRDPFuzzer prdp, dword fuzztime)
{
	RD_FUZZER::RDP* rdp = (RD_FUZZER::RDP*) prdp;

	if (rdp->is_config() == false) return(false);

	RD_BOOL continue_connect = True;
	uint32 run_count = 0;
	RD_BOOL deactivated;
	uint32 ext_disc_reason = 0;

	while (/* run_count < 2 && */continue_connect)	/* add support for Session Directory; only reconnect once */
	{
		if (run_count == 0)
		{
			//if (!rdp.rdp_connect(server, flags, domain, username, passwd, cmd, directory))	// RDP Connect
			if (!rdp->rdp_connect())
				return(False);
		}
		//else if (!rdp.rdp_reconnect(server, flags, domain, username, passwd, cmd, directory))	// 실행횟수 1 이상
		else if (!rdp->rdp_reconnect())
			return(False);

		/* By setting encryption to False here, we have an encrypted login
		packet but unencrypted transfer of other packets */
		if (false)//!packet_encryption)
			rdp->rdp_set_encrypt(False);

		printf("[+] Connection successful.\n");
		//DEBUG(("Connection successful.\n"));
		rdp->reset_password();

		if (continue_connect)
			rdp->rdp_main_loop(&deactivated, &ext_disc_reason);							// main loop

		printf("[+] Disconnecting.\n");
		//DEBUG(("Disconnecting...\n"));
		rdp->rdp_disconnect();

		if ((rdp->rdp_redirect() == True) && (run_count == 0))	/* Support for Session Directory */
		{
			/* reset state of major globals */
			rdp->rdp_reset_state();
			rdp->rdp_support_redirect();
		}
		/*
		else
		{
			continue_connect = False;
			break;
		}*/

		run_count++;
	}

	//if (ext_disc_reason >= 2)
	print_disconnect_reason(ext_disc_reason);

	if (deactivated)
	{
		/* clean disconnect */
		return(True);
	}
	else
	{
		if (ext_disc_reason == exDiscReasonAPIInitiatedDisconnect
			|| ext_disc_reason == exDiscReasonAPIInitiatedLogoff)
		{
			/* not so clean disconnect, but nothing to worry about */
			return(True);
		}
		else
		{
			/* return error */
			return(False);
		}
	}
}

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		//printf("[+] DLL is attached process\n");
		break;
	case DLL_PROCESS_DETACH:
		//printf("[+] DLL is dettached process\n");
		break;
	case DLL_THREAD_ATTACH:
		//printf("[+] DLL is Attached thread\n");
		break;
	case DLL_THREAD_DETACH:
		//printf("[+] DLL is dettached thread\n");
		break;
	}

	return TRUE;
}
