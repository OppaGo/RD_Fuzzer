#include <cstdio>
#include <cstring>
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <regex>
#include <future>
#include <chrono>
#include "file_fuzzer.h"

using namespace std;

#define BUF_SIZE 512


namespace RD_FUZZER
{
	/*
	 *	File_Fuzzer::File_Fuzzer()
	 *	설정 파일을 읽어들여, 초기화 수행
	 */
	File_Fuzzer::File_Fuzzer() : Mutator(), Debugger() {
		isconfigured = Init_config("./RD_File_Fuzzer.yaml", SET_ONLY_THIS) ? true : false;
	}

	/*
	*	File_Fuzzer::File_Fuzzer(const char* config_file)
	*	설정 파일을 읽어들여, 초기화 수행
	*/
	File_Fuzzer::File_Fuzzer(const char* config_file) : Mutator(config_file), Debugger(config_file) {
		isconfigured = Init_config(config_file, SET_ONLY_THIS) ? true : false;
	}

	/*
	*	is_config()
	*	isconfiged 반환
	*/
	bool File_Fuzzer::is_config() {
		return isconfigured && is_mutator_config() && is_debug_config();
	}

	/*
	*	Init_config()
	*	config 파일로부터 설정 초기화
	*/
	bool File_Fuzzer::Init_config(const char* config_file, bool flag) {
		ifstream ifs(config_file);
		char fdata[BUF_SIZE];
		if (ifs.is_open()) {
			while (!ifs.eof()) {
				memset(fdata, 0, BUF_SIZE);
				ifs.getline(fdata, BUF_SIZE);

				regex reg("^(\\w+?): ([\\w:\\\\ ()]+)");
				string fdata_str = fdata;
				smatch m;

				bool ismatched = regex_search(fdata_str, m, reg);

				if (ismatched) {
					char** dummy = NULL;
					if (!strcmp(m[1].str().c_str(), "result_path")) result_path = m[2].str();
					else if (!strcmp(m[1].str().c_str(), "timeout")) timeout = (dword)(strtof(m[2].str().c_str(), dummy));
					else if (!strcmp(m[1].str().c_str(), "test_count")) test_count = strtoul(m[2].str().c_str(), dummy, 10);
				}
			}
			ifs.close();
			if (flag == SET_ALL) {
				Init_Debug_config(config_file);
				Init_Mutator_config(config_file);
			}
		}
		else return(false);

		return(true);
	}

	/*
	 *	File_File_Fuzzer()
	 *	파일 퍼징 수행
	 *	정상 종료 : true, 비정상 종료 : false
	 */
#define Err_Wait 0xfffffff
#define Sucess_Debug 0x0
#define Access_Violation 0x1
#define Stack_Overflow 0x2
	bool File_Fuzzer::File_Fuzzer_Loop() {
		bool isstop = false;
		string mutated_file;
		string mutated_full_path;
		dword file_count = 0;

		cout << "[+] Target Program : " << target_program << endl;
		while (!isstop) {
			file_count = CreateMutatedFile();
			if (file_count == 0) {
				fprintf(stderr, "[-] Failed to create mutated files\n");
				return(false);
			}
			mutated_file = mutated_file_list[GenRandomValue(file_count)];
			mutated_full_path = /* target_program + */program_option + " \"" + mutated_path + "\\" + mutated_file + "\"";
			cout << "[+] Selected mutated File Name : " << mutated_file << endl;
			//cout << "[+] CMD : " << target_program << " " << mutated_file << endl;

			for (dword i = 0; i < test_count; i++) {
				thread t(&File_Fuzzer::FileFuzzing, this, mutated_full_path, mutated_file);

				t.join();
			}
		}

		return(true);
	}

	/*
	*	FileFuzzing()
	*	스레드가 실행할 파일 퍼징 함수
	*/
	bool File_Fuzzer::FileFuzzing(const string &mutated_full_path, const string &mutated_file) {
		
		if (!Open_Process(target_program.c_str(), (LPSTR)mutated_full_path.c_str()))
			return(false);

		//auto fut = std::async(std::launch::async, &File_Fuzzer::DebugStart, this);

		//std::chrono::milliseconds span(timeout);
		//while (fut.wait_for(span) == std::future_status::timeout);
		//status = fut.get();
		//if (status == Access_Violation) {
		//	cout << "[+] Access Violation!" << endl;
		//	Store_Crash(mutated_full_path, mutated_file);
		//}

		dword t = GetTickCount();
		while (1)
		{
			if ((GetTickCount() - t) > timeout)
				break;
			if (DebugStart() == Access_Violation) {
				cout << "[+] Access Violation!" << endl;
				Store_Crash(mutated_full_path, mutated_file);
				break;
			}
		}
		CloseProcess();
		
		return(true);
	}

	bool File_Fuzzer::Store_Crash(const string &mutated_full_path, const string &mutated_file) {
		ifstream ifs(mutated_full_path, ifstream::binary | ifstream::in);
		if (ifs.is_open()) {
			unsigned int fsize = 0;
			char* fdata = NULL;
			if (ifs.is_open()) {
				ifs.seekg(0, ios::end);
				fsize = (unsigned int)ifs.tellg();
				ifs.seekg(0, ios::beg);

				fdata = new char[fsize];
				memset(fdata, 0, fsize);
				ifs.read(fdata, fsize);
				ifs.close();

				string result_full_path = result_path + "\\" + to_string(crash) + "_" + mutated_file;
				cout << "[+] Result Path : " << result_full_path << endl;
				ofstream ofs(result_full_path, ofstream::binary | ofstream::out);
				if (ofs.is_open()) {
					ofs.write(fdata, fsize);
					ofs.close();
				}
				delete[] fdata;
			}
			else return(false);
		}

		return(true);
	}
	
	/*
	 *	DebugStart()
	 *	실행된 또는 Attached Process Debug 수행
	 *	Error 반환
	 */
	dword File_Fuzzer::DebugStart() {
		ContinueDebugEvent(
			DebugEvent.dwProcessId,
			DebugEvent.dwThreadId,
			DBG_CONTINUE);

		if (WaitForDebugEvent(&DebugEvent, timeout) == NULL)
			return Err_Wait;

		//printf("%d\n", DebugEvent.dwDebugEventCode);
		switch (DebugEvent.dwDebugEventCode) {
		case CREATE_PROCESS_DEBUG_EVENT:
			TargetProcessInfo.hProcess = DebugEvent.u.CreateProcessInfo.hProcess;
			TargetProcessInfo.hThread = DebugEvent.u.CreateProcessInfo.hThread;
			context.ContextFlags = CONTEXT_FULL;
			SetSingleStep();
			break;
		case EXCEPTION_DEBUG_EVENT:
			switch (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode) {
			case EXCEPTION_ACCESS_VIOLATION:
				GetThreadContext(TargetProcessInfo.hThread, &context);
				crash++;
				return Access_Violation;
			case EXCEPTION_STACK_OVERFLOW:
				GetThreadContext(TargetProcessInfo.hThread, &context);
				crash++;
				return Stack_Overflow;
			case EXCEPTION_INT_OVERFLOW:
				GetThreadContext(TargetProcessInfo.hThread, &context);
				break;
			case EXCEPTION_ILLEGAL_INSTRUCTION:
				GetThreadContext(TargetProcessInfo.hThread, &context);
				break;
			}
		}

		return Sucess_Debug;
	}
}
