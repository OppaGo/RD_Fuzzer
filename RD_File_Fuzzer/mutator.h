#ifndef __MUTATOR_H__
#define __MUTATOR_H__

#include <Windows.h>
#include <string>

typedef unsigned long dword;

namespace RD_FUZZER
{
	class Mutator
	{
	private:
		bool isconfiged;

	protected:
		std::string	 orig_path;
		std::string* orig_file_list;
		std::string* mutated_file_list;
		std::string	 mutated_path;
		dword dummy_size_max;

	public:
		Mutator();
		Mutator(const char* config_file);
		bool Init_Mutator_config(const char* config_file);
		bool Init_Mutator_config(const std::string& orig_path, const std::string& mutated_path, dword dummy_size_max);
		bool is_mutator_config();
		virtual dword GetFileList();
		dword GenRandomValue(dword dsize);
		static dword GenRandomValue_extern(dword max);
		void Byte_flipping(char* data, const dword dsize);
		void Dummy_injection(char* data, const dword dsize);
		dword Mutation(char* data, const dword dsize);
		virtual dword CreateMutatedFile();
		virtual bool CreateMutatedFile(char* FileName);
		~Mutator();
	};

	void InitWELLRNG512a(unsigned int *init);
	double WELLRNG512a();
}

#endif
