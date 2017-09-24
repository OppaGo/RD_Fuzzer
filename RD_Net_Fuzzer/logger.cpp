#include "mutator.h"

namespace RD_FUZZER
{
	std::string Logger::SetFileName(std::string& fname)
	{
		filename = fname + std::to_string(lognum);

		return filename;
	}

	std::string Logger::SetLogPath(std::string& path)
	{
		logpath = path;

		return logpath;
	}

	bool Logger::OpenLogFile()
	{
		fopen_s(&fp, filename.c_str(), "wt");
		if (fp == NULL)
		{
			return(false);
		}
	}

	dword Logger::WriteLog(const char* log, dword log_len)
	{
		if (fwrite(log, 1, log_len, fp) != log_len)
		{
			return(0);
		}

		return log_len;
	}

	void Logger::CloseLogFile()
	{
		fclose(fp);
	}

	bool Logging(std::string& path, const char* log, dword log_len)
	{
		FILE* fp;

		fopen_s(&fp, path.c_str(), "wt");
		if (fp == NULL)
		{
			fprintf(stderr, "fopen_s() error\n");
			return(false);
		}

		if (fwrite(log, 1, log_len, fp) != log_len)
		{
			fprintf(stderr, "fwrite() error\n");
			return(false);
		}
		
		if (fclose(fp) != 0)
		{
			fprintf(stderr, "fclose() error\n");
			return(false);
		}

		return(true);
	}
}
