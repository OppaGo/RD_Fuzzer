#ifndef __FUZZER_H__
#define __FUZZER_H__

#include <Windows.h>
#include "debugger.h"
#include "mutator.h"


namespace RD_FUZZER
{
	class File_Fuzzer : public Debugger, Mutator
	{
	private:
		dword crash;
		dword timeout;		// ms
		dword test_count;
		bool isconfigured;

		bool FileFuzzing(const std::string &mutated_full_path, const std::string &mutated_file);	//for Thread
		virtual bool Store_Crash(const std::string &mutated_full_path, const std::string &mutated_file);

	protected:
		std::string result_path;

		virtual dword DebugStart();

	public:
		File_Fuzzer();
		File_Fuzzer(const char* config_file);
		bool is_config();
#define SET_ALL		  1
#define SET_ONLY_THIS 0
		bool Init_config(const char* config_file = "./RD_File_Fuzzer.yaml", bool flag = SET_ALL);
		bool File_Fuzzer_Loop();
		//static void CALLBACK TimeProc(HWND hwnd, UINT uMsg, UINT nIDEvent, DWORD dwTime);
	};
}

#endif
