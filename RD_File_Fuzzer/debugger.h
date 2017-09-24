#ifndef __DEBUGGER_H__
#define __DEBUGGER_H__

#include <Windows.h>
#include <string>


typedef unsigned long dword;

namespace RD_FUZZER
{
	class Debugger {
	private:
#ifdef _WIN32
#ifdef _WIN64
		BOOL isWow64Process;
#endif
#else
#endif
		BOOL isattached;
		bool isconfiged;

	protected:
		STARTUPINFO ProcessWindowInfo;
		PROCESS_INFORMATION TargetProcessInfo;
		DEBUG_EVENT DebugEvent;
		CONTEXT context;
		std::string target_program;
		std::string program_option;

	protected:
		bool Open_Process(
			const LPCSTR ApplicationName,
			const LPSTR CmdLine);
		virtual void ProcessView();
		bool Attach_Process(const dword pi);
		bool CloseProcess();
		bool SetSingleStep();
		bool DelSingleStep();
		virtual dword DebugStart(void);

	public:
		Debugger();
		Debugger(const char* config_file);
		bool Init_Debug_config(const char* config_file);
		bool is_debug_config();
		~Debugger();
	};
}

#endif
