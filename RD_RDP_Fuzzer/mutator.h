#ifndef __MUTATOR_H__
#define __MUTATOR_H__

#include <Windows.h>
#include <string>

typedef unsigned long dword;

namespace RD_FUZZER
{
	class Logger
	{
	private:
		dword lognum;
		std::string filename;
		FILE* fp;
		std::string logpath;

	public:
		std::string SetFileName(std::string& fname);
		std::string SetLogPath(std::string& path);
		bool OpenLogFile();
		dword WriteLog(const char* log, dword log_len);
		void CloseLogFile();
		static bool Logging(std::string& path, const char* log, dword log_len);
	};

	class Mutator
	{
	private:
		bool isconfiged;

	private:
		void Byte_flipping(char* data, const dword dsize);
		void Byte_flipping_in_range(char* data, const dword begin, const dword end);
		void Dummy_injection(char* data, const dword dsize);

	protected:
		std::string	 orig_path;
		std::string* orig_file_list;
		std::string* mutated_file_list;
		std::string	 mutated_path;
		dword dummy_size_max;

	protected:
		virtual dword CreateMutatedFile();
		virtual bool CreateMutatedFile(char* FileName);
		virtual dword GetFileList();

	public:
		Logger logger;

		//Mutator();
		//Mutator(const char* config_file);
		~Mutator();
		bool Init_Mutator_config(const char* config_file="./RD_RDP_Fuzzer.yaml");
		bool Init_Mutator_config(const std::string& orig_path, const std::string& mutated_path, dword dummy_size_max);
		bool is_mutator_config();
		dword GenRandomValue(dword max);
		static dword GenRandomValue_extern(dword max);
		dword Mutation(char* data, const dword dsize);
		dword Mutation_in_max(char* data, const dword dsize, const dword maxsize);
		dword Mutation_in_range(char* data, const dword begin, const dword end);
		dword ByteFlipMutation(char * data, const dword dsize);
		void SetMaxDummySize(dword max);
		dword GetMaxDummySize(void);
	};

	void InitWELLRNG512a(unsigned int *init);
	double WELLRNG512a();
}

#endif
