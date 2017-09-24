#include <cstdio>
#include <cstring>
#include <iostream>
#include <regex>
#include <fstream>
#include <io.h>
#include <conio.h>
#include <ctime>
#include <random>
#include <functional>
#include "mutator.h"
#include "cryptohash.h"

using namespace std;


#define BUF_SIZE 512

namespace RD_FUZZER
{
	/*
	 *	Mutator::Mutator()
	 *	생성자, 설정 파일을 읽어들임
	 */
	Mutator::Mutator() {
		isconfiged = Init_Mutator_config("./config.yaml") ? true : false;
	}

	Mutator::Mutator(const char* config_file) {
		isconfiged = Init_Mutator_config(config_file) ? true : false;
	}

	/*
	*	Init_Mutator_config()
	*	config 파일로부터 설정 초기화
	*/
	bool Mutator::Init_Mutator_config(const char* config_file) {
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
					if (!strcmp(m[1].str().c_str(), "orig_path")) orig_path = m[2].str();
					else if (!strcmp(m[1].str().c_str(), "mutated_path")) mutated_path = m[2].str();
					else if (!strcmp(m[1].str().c_str(), "dummy_size")) dummy_size_max = strtoul(m[2].str().c_str(), dummy, 10);
				}
			}

			orig_file_list = NULL;
			cout << "[+] Original_Path : " << orig_path << endl;
			cout << "[+] Mutated_Path : " << mutated_path << endl;

			ifs.close();
		}
		else return(false);

		return(true);
	}

	bool Mutator::Init_Mutator_config(const std::string & orig_path, const std::string & mutated_path, dword dummy_size_max)
	{
		this->orig_path = orig_path;
		this->mutated_path = mutated_path;
		this->dummy_size_max = dummy_size_max;
	}

	/*
	*	is_mutator_config()
	*	is_config 반환
	*/
	bool Mutator::is_mutator_config() {
		return isconfiged;
	}

	/*
	 *	Mutator::~Mutator()
	 *	소멸자
	 */
	Mutator::~Mutator() {
		if (orig_file_list != NULL)
			delete[] orig_file_list;
		orig_file_list = NULL;
	}

	/*
	 *	GetFileList()
	 *	Original Path에서 Seed 파일의 목록을 읽어들임
	 *	읽어들인 파일의 갯수를 반환
	 */
#define EXIST		1
#define NOT_EXIST	-1
	dword Mutator::GetFileList() {
		dword fcount = 0;
		_finddata_t fd;
		long fd_handle;
		int isexisted = EXIST;

		string orig_file_path = orig_path + "\\*.*";
		fd_handle = _findfirst(orig_file_path.c_str(), &fd);
		if (fd_handle == -1) {
			fprintf(stderr, "[-] Original file is not found...\n");
			goto ret_count;
		}

		while (isexisted != NOT_EXIST) {
			//cout << "[+] File Name : " << fd.name << endl;
			isexisted = _findnext(fd_handle, &fd);
			fcount++;
		}
		_findclose(fd_handle);

		orig_file_list = new string[(fcount - 2)];
		mutated_file_list = new string[(fcount - 2)];

		fd_handle = _findfirst(orig_file_path.c_str(), &fd);
		isexisted = _findnext(fd_handle, &fd);
		isexisted = _findnext(fd_handle, &fd);
		isexisted = EXIST;
		for (fcount = 0; isexisted != NOT_EXIST; fcount++) {
			orig_file_list[fcount] = fd.name;
			isexisted = _findnext(fd_handle, &fd);
		}
		_findclose(fd_handle);
	ret_count:
		return(fcount);
	}

	/*
	 *	GenRandomValue()
	 *	랜덤 값 생성
	 */
#define WELLRANDOMLONG(x) (dword)((double)WELLRNG512a() * 1000000000) % x
#define WELLRANDOMLONG2(x) (dword)((double)WELLRNG512a() * 1000000000)
	dword Mutator::GenRandomValue(dword max) {
		random_device rd;
		mt19937 engine(rd());
		uniform_int_distribution<int> distribution(0, max);
		auto generator = bind(distribution, engine);
		unsigned int init[16];
		for (int i = 0; i < 16; i++)
			init[i] = generator();
		InitWELLRNG512a(init);
		try {
			return WELLRANDOMLONG(max);
		}
		catch (const std::exception e) {
			return WELLRANDOMLONG2(max);
		}
	}

	dword Mutator::GenRandomValue_extern(dword max)
	{
		random_device rd;
		mt19937 engine(rd());
		uniform_int_distribution<int> distribution(0, max);
		auto generator = bind(distribution, engine);
		unsigned int init[16];
		for (int i = 0; i < 16; i++)
			init[i] = generator();
		InitWELLRNG512a(init);
		try {
			return WELLRANDOMLONG(max);
		}
		catch (const std::exception e) {
			return WELLRANDOMLONG2(max);
		}
	}

	/*
	*	Byte_flipping()
	*	byte flipping 수행
	*/
	void Mutator::Byte_flipping(char* data, const dword dsize) {
		dword offset = GenRandomValue(dsize);
		BYTE  reverse_case = (BYTE)GenRandomValue(0x100);
		data[offset] ^= reverse_case;
	}

	void Mutator::Byte_flipping_in_range(char * data, const dword begin, const dword end)
	{
		dword offset = begin + GenRandomValue(end - begin);
		BYTE  reverse_case = (BYTE)GenRandomValue(0x100);
		data[offset] ^= reverse_case;
	}

	/*
	*	Dummy_injection()
	*	data 내부에 Dummy 1바이트 삽입
	*/
	void Mutator::Dummy_injection(char* data, const dword dsize) {
		dword offset = GenRandomValue(dsize);
		BYTE* tmp_mem = new BYTE[dsize - offset];
		BYTE dummy = (BYTE)GenRandomValue(0x100);
		memcpy(tmp_mem, &data[offset], dsize - offset);
		data[offset] = dummy;
		memcpy(&data[offset + 1], tmp_mem, dsize - offset);

		delete tmp_mem;
	}

	/*
	 *	Mutation()
	 *	Mutation을 수행후, 저장
	 *	Mutation된 data 길이 반환
	 */
	dword Mutator::Mutation(char* data, const dword dsize) {
		bool mutation_switch;	// true, false
		dword mutation_count = GenRandomValue(dummy_size_max);
		dword dummy_total_len = 0;
		for (dword i = 0; i < mutation_count; i++) {
			mutation_switch = ((BYTE)GenRandomValue(2) == 1) ? true : false;
			if (mutation_switch) {
				Byte_flipping(data, dsize + dummy_total_len);
			}
			else {
				Dummy_injection(data, dsize + dummy_total_len);
				dummy_total_len++;
			}
		}

		return(dsize + dummy_total_len);
	}

	dword Mutator::Mutation_in_max(char * data, const dword dsize, const dword maxsize)
	{
		bool mutation_switch;	// true, false
		dword mutation_count = GenRandomValue(maxsize - dsize);
		dword dummy_total_len = 0;
		for (dword i = 0; i < mutation_count; i++) {
			mutation_switch = ((BYTE)GenRandomValue(2) == 1) ? true : false;
			if (mutation_switch) {
				Byte_flipping(data, dsize + dummy_total_len);
			}
			else {
				Dummy_injection(data, dsize + dummy_total_len);
				dummy_total_len++;
			}
		}

		return(dsize + dummy_total_len);
	}

	dword Mutator::Mutation_in_range(char * data, const dword begin, const dword end)
	{
		dword mutation_count = GenRandomValue(end - begin);
		for (dword i = 0; i < mutation_count; i++) {
			Byte_flipping_in_range(data, begin, end);
		}

		return(mutation_count);
	}

	void Mutator::SetMaxDummySize(dword max)
	{
		dummy_size_max = max;
	}

	dword Mutator::GetMaxDummySize(void)
	{
		return dummy_size_max;
	}

	/*
	*	CreateMutatedFile()
	*	Original File List로 부터 Mutation을 통해 MutatedFile 생성
	*	파일 생성 여부 확인
	*/
	dword Mutator::CreateMutatedFile() {
		string mutated_full_path;
		string orig_full_path;
		string file_name;
		string file_ext;

		dword file_count = GetFileList();
		if (file_count == 0) goto Return_File_Count;
		for (dword i = 0; i < file_count; i++) {
			regex reg("(\\w+).([\\w]+)$");
			string orig_file_str = orig_file_list[i];
			smatch m;

			bool ismatched = regex_search(orig_file_str, m, reg);

			if (ismatched) {
				file_name = m[1];
				file_ext = m[2];
				//cout << "file name : " << file_name << endl;
				//cout << "file ext : " << file_ext << endl;
			}

			orig_full_path = ((string)orig_path) + "\\" + orig_file_list[i];
			cout << "[+] Original Full Path[i] : " << orig_full_path << endl;

			crypto::sha1_helper_t hash_helper;
			mutated_file_list[i] = hash_helper.hexdigesttext(file_name, TRUE) + "." + file_ext; // Get Mutated File Name
			//cout << "[+] Mutated Path size : " << mutated_path << mutated_path.size() << endl;
			//cout << "[+] File ext size : " << file_ext << file_ext.size() << endl;
			mutated_full_path = mutated_path + "\\" + mutated_file_list[i];
			cout << "[+] Mutated Full Path[" << i << "] : " << mutated_full_path << endl;

			ifstream ifs(orig_full_path, ifstream::binary | ifstream::in);
			unsigned int fsize = 0;
			char* fdata = NULL;
			if (ifs.is_open()) {
				ifs.seekg(0, ios::end);
				fsize = (unsigned int)ifs.tellg();
				ifs.seekg(0, ios::beg);

				fdata = new char[fsize + dummy_size_max];
				memset(fdata, 0, fsize + dummy_size_max);
				ifs.read(fdata, fsize);
				ifs.close();

				Mutation(fdata, fsize);
				ofstream ofs(mutated_full_path, ofstream::binary | ofstream::out | ofstream::trunc);
				if (ofs.is_open()) {
					ofs.write(fdata, fsize);
					ofs.close();
				}
				delete[] fdata;
			}
		}
	Return_File_Count:

		return(file_count);
	}

	/*
	*	CreateMutatedFile(char* filename)
	*	Original File List로 부터 Mutation을 통해 MutatedFile 생성
	*	파일 생성 여부 확인
	*/
	bool Mutator::CreateMutatedFile(char* filename) {
		string mutated_full_path;
		string orig_full_path;
		string file_name;
		string file_ext;

		regex reg("(\\w+).([\\w]+)$");
		string orig_file_str = filename;
		smatch m;

		bool ismatched = regex_search(orig_file_str, m, reg);

		if (ismatched) {
			file_name = m[1];
			file_ext = m[2];
			//cout << "file name : " << file_name << endl;
			//cout << "file ext : " << file_ext << endl;
		}

		orig_full_path = ((string)orig_path) + "\\" + filename;
		cout << "[+] Original Full Path[i] : " << orig_full_path << endl;

		crypto::sha1_helper_t hash_helper;
		mutated_file_list[0] = hash_helper.hexdigesttext(file_name, TRUE) + "." + file_ext; // Get Mutated File Name
		//cout << "[+] Mutated Path size : " << mutated_path << mutated_path.size() << endl;
		//cout << "[+] File ext size : " << file_ext << file_ext.size() << endl;
		mutated_full_path = mutated_path + "\\" + mutated_file_list[0];
		cout << "[+] Mutated Full Path[" << 0 << "] : " << mutated_full_path << endl;

		ifstream ifs(orig_full_path, ifstream::binary | ifstream::in);
		unsigned int fsize = 0;
		char* fdata = NULL;
		if (ifs.is_open()) {
			ifs.seekg(0, ios::end);
			fsize = (unsigned int)ifs.tellg();
			ifs.seekg(0, ios::beg);

			fdata = new char[fsize + dummy_size_max];
			memset(fdata, 0, fsize + dummy_size_max);
			ifs.read(fdata, fsize);
			ifs.close();

			Mutation(fdata, fsize);
			ofstream ofs(mutated_full_path, ofstream::binary | ofstream::out | ofstream::trunc);
			if (ofs.is_open()) {
				ofs.write(fdata, fsize);
				ofs.close();
			}
			delete[] fdata;
		}

//	Return_File_Count:
		return(1);
	}
}
