#include <string>
#include <io.h>
#include <conio.h>
#include <cstdio>
#include "Network_Fuzzer.h"
#include "default.h"

using namespace std;

/*
*	GetFileList()
*	Original Path에서 Seed 파일의 목록을 읽어들임
*	읽어들인 파일의 갯수를 반환
*/
#define EXIST		1
#define NOT_EXIST	-1
dword RD_FUZZER::NET_FUZZ::GetFileList() {
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
	
	fd_handle = _findfirst(orig_file_path.c_str(), &fd);
	_findnext(fd_handle, &fd);			// .
	_findnext(fd_handle, &fd);			// ..
	isexisted = EXIST;
	for (fcount = 0; isexisted != NOT_EXIST; fcount++) {
		orig_file_list[fcount] = fd.name;
		isexisted = _findnext(fd_handle, &fd);
	}
	_findclose(fd_handle);

ret_count:
	return(fcount);
}

dword RD_FUZZER::NET_FUZZ::ReadPacketFile(char * data, dword list_select)
{
	FILE* fp;
	dword data_len = 0;

	fopen_s(&fp, orig_file_list[list_select].c_str(), "rb");
	if (fp == NULL) {
		fprintf(stderr, "[-] for Fuzzing fopen_s() Error\n");
		return 0;
	}

	fseek(fp, 0, SEEK_END);
	data_len = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	data = new char[data_len + dummy_size_max];
	if (fread_s(data, data_len + dummy_size_max, 1, data_len, fp) != data_len)
	{
		fprintf(stderr, "[-] packet data read error\n");

		delete data;
		data = NULL;
		
		return 0;
	}
	fclose(fp);

	return data_len;
}

RD_FUZZER::NET_FUZZ::NET_FUZZ()
{
	this->orig_path = "Net_Fuzzer_Packets";
	orig_file_list = NULL;
	dummy_size_max = 512;
}

RD_FUZZER::NET_FUZZ::NET_FUZZ(const char* orig_path)
{
	this->orig_path = orig_path;
	orig_file_list = NULL;
	dummy_size_max = 512;
}

RD_FUZZER::NET_FUZZ::~NET_FUZZ()
{
	if (orig_file_list != NULL)
	{
		delete orig_file_list;
		orig_file_list = NULL;
	}
}

void RD_FUZZER::NET_FUZZ::SetMaxDummySize(dword max)
{
	dummy_size_max = max;
}

bool RD_FUZZER::NET_FUZZ::OpenNetFuzzer(const char* server, const uint16 port)
{
	if (!net_tcp.tcp_connect(server, port)) {
		fprintf(stderr, "[-] TCP connect Error\n");
		return(false);
	}

	return(true);
}

void RD_FUZZER::NET_FUZZ::CloseNetFuzzer()
{
	net_tcp.tcp_disconnect();
}

void RD_FUZZER::NET_FUZZ::NetFuzzing()
{
	char* data = NULL;
	dword data_len = 0;
	dword file_count = 0;

	if (orig_file_list == NULL)
		file_count = GetFileList();

	data_len = ReadPacketFile(data, mutator.GenRandomValue_extern(file_count));
	if (data_len == 0) return;

	printf("[+] Original Packet\n");
	hexdump((unsigned char*)data, data_len);

	dword mutated_len = mutator.Mutation_in_max(data, data_len, data_len + dummy_size_max);
	
	printf("[+] Mutated Packet\n");
	hexdump((unsigned char*)data, mutated_len);

	printf("[+] Complete mutate, Sending packets\n");
	net_tcp.tcp_send(data, mutated_len);
	
	delete data;
}
