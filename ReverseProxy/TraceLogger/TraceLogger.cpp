#include <vector>
#include <iostream>
#include "TraceLogger.h"

#ifdef TRACE_LOGGER

static CRITICAL_SECTION s_mutex;

TraceLogger* TraceLogger::s_instance = 0;	//Singleton 

TraceLogger::TraceLogger(LOG_OPTION option_, LOG_LEVEL level_)
{
	level = level_;
	option = option_;
	WCHAR absolutePath[MAX_PATH] = { 0 };
	if (GetModuleFileNameW(NULL, absolutePath, MAX_PATH) == 0)
	{
		std::wcout << L"GetModuleFileNameW returned error: " << GetLastError() << std::endl;
	}
	std::wstring path(absolutePath);
	log_file_path = path.substr(0, path.find_last_of(L"\\/")) + L"\\log.txt";

	InitializeCriticalSection(&s_mutex);
}

void TraceLogger::EnableLog(BOOL enable)
{
	enable_log = enable;
}

void TraceLogger::EnableTrace(BOOL enable)
{
	enable_trace = enable;
}

void TraceLogger::SetLogOut(LOG_OPTION opt)
{
	if (opt == LOG_OPTION::WRITE_TO_FILE)
	{
		hFile = CreateFileW(log_file_path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED);
			std::wcerr << L"CreateFileW returned error: " << GetLastError() << std::endl;
		}
		else
		{
			std::wcout << L"Log file path: " << log_file_path << std::endl;
		}
	}
	option = opt;
}

void TraceLogger::SetLogLevel(LOG_LEVEL lv)
{
	level = lv;
}

void TraceLogger::SetLogFilePath(std::wstring path)
{
	log_file_path = path;
}

void TraceLogger::CloseLogFileHandle()
{
	if (hFile != NULL)
	{
		CloseHandle(hFile);
		hFile = NULL;
	}
}

BOOL TraceLogger::W_LOG(const CHAR* buffer, DWORD size)
{
	if (hFile == NULL || buffer == NULL || size == 0)
	{
		return FALSE; 
	}
	DWORD dwNumberOfBytesWrite = 0;
	if (!WriteFile(hFile, buffer, size, &dwNumberOfBytesWrite, NULL) || dwNumberOfBytesWrite != size)
	{
		CloseHandle(hFile);
		hFile = NULL;
		return FALSE;
	}
	return TRUE;
}

void TraceLogger::L_OUT_A(const std::string& ss, WORD color = WHITE)
{
	switch (option)
	{
		case LOG_OPTION::WRITE_TO_FILE:
		{
			if (W_LOG(ss.c_str(), static_cast<DWORD>(ss.length())) == FALSE)
			{
				SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED);
				std::cerr << "Write to file failed! Error code: " << GetLastError() << std::endl;
			}
		}
		break;
		case LOG_OPTION::OUTPUT_DEBUG:
		{
			OutputDebugStringA(ss.c_str());		
		}
		break;
		case LOG_OPTION::SHOW_MESSAGE:
		case LOG_OPTION::SHOW_CONSOLE:
		default:
		{
			if (!SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color))
			{
				std::cerr << "SetConsoleTextAttribute returned error: " << GetLastError() << std::endl;
			}
			else
			{
				std::cout << ss;
			}
		}
		break;
	}
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), WHITE);
}

void TraceLogger::L_OUT_W(const std::wstring& ss, WORD color = WHITE)
{
	switch (option)
	{
		case LOG_OPTION::WRITE_TO_FILE:
		{
			if (W_LOG(WSTR2STR(ss).c_str(), static_cast<DWORD>(ss.length())) == FALSE)
			{
				SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED);
				std::wcerr << L"Write to file failed! Error code: " << GetLastError() << std::endl;
			}
		}
		break;
		case LOG_OPTION::OUTPUT_DEBUG:
		{
			OutputDebugStringA(WSTR2STR(ss).c_str());
		}
		break;
		case LOG_OPTION::SHOW_MESSAGE:
		case LOG_OPTION::SHOW_CONSOLE:
		default:
		{
			if (!SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color))
			{
				std::wcerr << L"SetConsoleTextAttribute returned error: " << GetLastError() << std::endl;
			}
			else
			{
				std::wcout << ss;
			}
		}
		break;
	}
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), WHITE);
}

#pragma region LOGGER
void TraceLogger::LogA(ULONG line, const CHAR* format, ...) 
{
	EnterCriticalSection(&s_mutex);
	CHAR* buf = NULL;
	ULONG size = 0;
	if (level >= LOG_NONCE && enable_log)
	{
		va_list args;
		va_start(args, format);
		size = _vscprintf(format, args) + 1;
		buf = new CHAR[size];
		if (buf != NULL)
		{
			vsprintf_s(buf, size, format, args);
			if (option == OUTPUT_DEBUG || option == WRITE_TO_FILE)
			{
				L_OUT_A(GetTimeA()
					+ "[LOG][Line: " + std::to_string(line) + ']'
					+ std::string(buf) + "\r\n");
			}
			else if (option == SHOW_MESSAGE)
			{
				L_OUT_A(std::string(buf) + "\r\n");
			}
			else
			{
				L_OUT_A(GetTimeA(), WHITE);
				L_OUT_A("[", WHITE);
				L_OUT_A("LOG", WHITE);
				L_OUT_A("]", WHITE);
				L_OUT_A("[Line: " + std::to_string(line) + ']' + std::string(buf) + "\r\n", WHITE);
			}
			delete[] buf;
		}
		va_end(args);
	}
	LeaveCriticalSection(&s_mutex);
}

void TraceLogger::DebugA(const CHAR* func, ULONG line, const CHAR* format, ...) 
{
	EnterCriticalSection(&s_mutex);
	DWORD thread_id = GetCurrentThreadId();
	CHAR* buf = NULL;
	ULONG size = 0;
	if (level >= LOG_DEBUG && enable_log)
	{
		va_list args;
		va_start(args, format);
		size = _vscprintf(format, args) + 1;
		buf = new CHAR[size];
		if (buf != NULL)
		{
			vsprintf_s(buf, size, format, args);
			if (option == OUTPUT_DEBUG || option == WRITE_TO_FILE)
			{
				L_OUT_A(GetTimeA()
					+ "[DEBUG]"
					+ "[Thread_id: " + std::to_string(thread_id) + ']'
					+ "[Line: " + std::to_string(line) + ']'
					+ "[Function: " + std::string(func) + ']'
					+ std::string(buf) + "\r\n");
			}
			else if (option == SHOW_MESSAGE)
			{
				L_OUT_A(std::string(buf) + "\r\n");
			}
			else
			{
				L_OUT_A(GetTimeA(), WHITE);
				L_OUT_A("[", WHITE);
				L_OUT_A("DEBUG", DARK_BLUE);
				L_OUT_A("]", WHITE);
				L_OUT_A("[Thread_id: " + std::to_string(thread_id) + ']', WHITE);
				L_OUT_A("[Line: " + std::to_string(line) + ']', WHITE);
				L_OUT_A("[Function: " + std::string(func) + ']', WHITE);
				L_OUT_A(std::string(buf) + "\r\n");
			}
			delete[] buf;
		}
		va_end(args);
	}
	LeaveCriticalSection(&s_mutex);
}

void TraceLogger::InfoA(const CHAR* func, ULONG line, const CHAR* format, ...) 
{
	EnterCriticalSection(&s_mutex);
	DWORD thread_id = GetCurrentThreadId();
	CHAR* buf = NULL;
	ULONG size = 0;
	if (level >= LOG_INFO && enable_log)
	{
		va_list args;
		va_start(args, format);
		size = _vscprintf(format, args) + 1;
		buf = new CHAR[size];
		if (buf != NULL)
		{
			vsprintf_s(buf, size, format, args);
			if (option == OUTPUT_DEBUG || option == WRITE_TO_FILE)
			{
				L_OUT_A(GetTimeA()
					+ "[INFO]"
					+ "[Thread_id: " + std::to_string(thread_id) + ']'
					+ "[Line: " + std::to_string(line) + ']'
					+ "[Function: " + std::string(func) + ']'
					+ std::string(buf) + "\r\n");
			}
			else if (option == SHOW_MESSAGE)
			{
				L_OUT_A(std::string(buf) + "\r\n");
			}
			else
			{
				L_OUT_A(GetTimeA(), WHITE);
				L_OUT_A("[", WHITE);
				L_OUT_A("INFO", CYAN);
				L_OUT_A("]", WHITE);
				L_OUT_A("[Thread_id: " + std::to_string(thread_id) + ']', WHITE);
				L_OUT_A("[Line: " + std::to_string(line) + ']', WHITE);
				L_OUT_A("[Function: " + std::string(func) + ']', WHITE);
				L_OUT_A(std::string(buf) + "\r\n");
			}
			delete[] buf;
		}
		va_end(args);
	}
	LeaveCriticalSection(&s_mutex);
}

void TraceLogger::WarningA(const CHAR* func, ULONG line, const CHAR* format, ...) 
{
	EnterCriticalSection(&s_mutex);
	DWORD thread_id = GetCurrentThreadId();
	CHAR* buf = NULL;
	ULONG size = 0;
	if (level >= LOG_WARNING && enable_log)
	{
		va_list args;
		va_start(args, format);
		size = _vscprintf(format, args) + 1;
		buf = new CHAR[size];
		if (buf != NULL)
		{
			vsprintf_s(buf, size, format, args);
			if (option == OUTPUT_DEBUG || option == WRITE_TO_FILE)
			{
				L_OUT_A(GetTimeA()
					+ "[WARNING]"
					+ "[Thread_id: " + std::to_string(thread_id) + ']'
					+ "[Line: " + std::to_string(line) + ']'
					+ "[Function: " + std::string(func) + ']'
					+ std::string(buf) + "\r\n");
			}
			else if (option == SHOW_MESSAGE)
			{
				L_OUT_A(std::string(buf) + "\r\n");
			}
			else
			{
				L_OUT_A(GetTimeA(), WHITE);
				L_OUT_A("[", WHITE);
				L_OUT_A("WARNING", YELLOW);
				L_OUT_A("]", WHITE);
				L_OUT_A("[Thread_id: " + std::to_string(thread_id) + ']', WHITE);
				L_OUT_A("[Line: " + std::to_string(line) + ']', WHITE);
				L_OUT_A("[Function: " + std::string(func) + ']', WHITE);
				L_OUT_A(std::string(buf) + "\r\n");
			}
			delete[] buf;
		}
		va_end(args);
	}
	LeaveCriticalSection(&s_mutex);
}

void TraceLogger::ErrorA(const CHAR* func, ULONG line, const CHAR* file, const CHAR* format, ...) 
{
	EnterCriticalSection(&s_mutex);
	DWORD thread_id = GetCurrentThreadId();
	CHAR* buf = NULL;
	ULONG size = 0;
	if (level >= LOG_ERROR && enable_log)
	{
		va_list args;
		va_start(args, format);
		size = _vscprintf(format, args) + 1;
		buf = new CHAR[size];
		if (buf != NULL)
		{
			vsprintf_s(buf, size, format, args);
			if (option == OUTPUT_DEBUG || option == WRITE_TO_FILE)
			{
				L_OUT_A(GetTimeA()
					+ "[ERROR]"
					+ "[Thread_id: " + std::to_string(thread_id) + ']'
					+ "[Line:" + std::to_string(line) + ']'
					+ "[File:" + std::string(file) + ']'
					+ "[Function: " + std::string(func) + ']'
					+ std::string(buf) + "\r\n");
			}
			else if (option == SHOW_MESSAGE)
			{
				L_OUT_A(std::string(buf) + "\r\n");
			}
			else
			{
				L_OUT_A(GetTimeA(), WHITE);
				L_OUT_A("[", WHITE);
				L_OUT_A("ERROR", RED);
				L_OUT_A("]", WHITE);
				L_OUT_A("[Thread_id: " + std::to_string(thread_id) + ']', WHITE);
				L_OUT_A("[Line: " + std::to_string(line) + ']', WHITE);
				L_OUT_A("[File: " + std::string(file) + ']', WHITE);
				L_OUT_A("[Function: " + std::string(func) + ']', WHITE);
				L_OUT_A(std::string(buf) + "\r\n");
			}
			delete[] buf;
		}
		va_end(args);
	}
	LeaveCriticalSection(&s_mutex);
}

void TraceLogger::SuccessA(const CHAR* func, ULONG line, const CHAR* file, const CHAR* format, ...) 
{
	EnterCriticalSection(&s_mutex);
	DWORD thread_id = GetCurrentThreadId();
	CHAR* buf = NULL;
	ULONG size = 0;
	if (level >= LOG_SUCCESS && enable_log)
	{
		va_list args;
		va_start(args, format);
		size = _vscprintf(format, args) + 1;
		buf = new CHAR[size];
		if (buf != NULL)
		{
			vsprintf_s(buf, size, format, args);
			if (option == OUTPUT_DEBUG || option == WRITE_TO_FILE)
			{
				L_OUT_A(GetTimeA()
					+ "[SUCCESS]"
					+ "[Thread_id: " + std::to_string(thread_id) + ']'
					+ "[Line: " + std::to_string(line) + ']'
					+ "[File:" + std::string(file) + ']'
					+ "[Function: " + std::string(func) + ']'
					+ std::string(buf) + "\r\n");
			}
			else if (option == SHOW_MESSAGE)
			{
				L_OUT_A(std::string(buf) + "\r\n");
			}
			else
			{
				L_OUT_A(GetTimeA(), WHITE);
				L_OUT_A("[", WHITE);
				L_OUT_A("SUCCESS", FOREGROUND_GREEN);
				L_OUT_A("]", WHITE);
				L_OUT_A("[Thread_id: " + std::to_string(thread_id) + ']', WHITE);
				L_OUT_A("[Line: " + std::to_string(line) + ']', WHITE);
				L_OUT_A("[File: " + std::string(file) + ']', WHITE);
				L_OUT_A("[Function: " + std::string(func) + ']', WHITE);
				L_OUT_A(std::string(buf) + "\r\n");
			}
			delete[] buf;
		}
		va_end(args);
	}
	LeaveCriticalSection(&s_mutex);
}

void TraceLogger::CriticalA(const CHAR* func, ULONG line, const CHAR* file, const CHAR* format, ...) 
{
	EnterCriticalSection(&s_mutex);
	DWORD thread_id = GetCurrentThreadId();
	CHAR* buf = NULL;
	ULONG size = 0;
	if (level >= LOG_CRITICAL && enable_log)
	{
		va_list args;
		va_start(args, format);
		size = _vscprintf(format, args) + 1;
		buf = new CHAR[size];
		if (buf != NULL)
		{
			vsprintf_s(buf, size, format, args);
			if (option == OUTPUT_DEBUG || option == WRITE_TO_FILE)
			{
				L_OUT_A(GetTimeA()
					+ "[CRITICAL]"
					+ "[Thread_id: " + std::to_string(thread_id) + ']'
					+ "[Line: " + std::to_string(line) + ']'
					+ "[File:" + std::string(file) + ']'
					+ "[Function: " + std::string(func) + ']'
					+ std::string(buf) + "\r\n");
			}
			else if (option == SHOW_MESSAGE)
			{
				L_OUT_A(std::string(buf) + "\r\n");
			}
			else
			{
				L_OUT_A(GetTimeA(), WHITE);
				L_OUT_A("[", WHITE);
				L_OUT_A("CRITICAL", BACKGROUND_RED_2 | WHITE);
				L_OUT_A("]", WHITE);
				L_OUT_A("[Thread_id: " + std::to_string(thread_id) + ']', WHITE);
				L_OUT_A("[Line: " + std::to_string(line) + ']', WHITE);
				L_OUT_A("[File: " + std::string(file) + ']', WHITE);
				L_OUT_A("[Function: " + std::string(func) + ']', WHITE);
				L_OUT_A(std::string(buf) + "\r\n");
			}
			delete[] buf;
		}
		va_end(args);
	}
	LeaveCriticalSection(&s_mutex);
}

void TraceLogger::LogW(ULONG line, const WCHAR* format, ...) 
{
	EnterCriticalSection(&s_mutex);
	WCHAR* buf = NULL;
	ULONG size = 0;
	if (level >= LOG_NONCE && enable_log)
	{
		va_list args;
		va_start(args, format);
		size = _vscwprintf(format, args) + 1;
		buf = new WCHAR[size];
		if (buf != NULL)
		{
			vswprintf_s(buf, size, format, args);
			if (option == OUTPUT_DEBUG || option == WRITE_TO_FILE)
			{
				L_OUT_W(GetTimeW()
					+ L"[LOG][Line: " + std::to_wstring(line) + L']'
					+ std::wstring(buf) + L"\r\n");
			}
			else if (option == SHOW_MESSAGE)
			{
				L_OUT_W(std::wstring(buf) + L"\r\n");
			}
			else
			{
				L_OUT_W(GetTimeW(), WHITE);
				L_OUT_W(L"[", WHITE);
				L_OUT_W(L"LOG", WHITE);
				L_OUT_W(L"]", WHITE);
				L_OUT_W(L"[Line: " + std::to_wstring(line) + L']', WHITE);
				L_OUT_W(std::wstring(buf) + L"\r\n");
			}
			delete[] buf;
		}
		va_end(args);
	}
	LeaveCriticalSection(&s_mutex);
}

void TraceLogger::DebugW(const CHAR* func, ULONG line, const WCHAR* format, ...) 
{
	EnterCriticalSection(&s_mutex);
	DWORD thread_id = GetCurrentThreadId();
	WCHAR* buf = NULL;
	ULONG size = 0;
	if (level >= LOG_DEBUG && enable_log)
	{
		va_list args;
		va_start(args, format);
		size = _vscwprintf(format, args) + 1;
		buf = new WCHAR[size];
		if (buf != NULL)
		{
			vswprintf_s(buf, size, format, args);
			if (option == OUTPUT_DEBUG || option == WRITE_TO_FILE)
			{
				L_OUT_W(GetTimeW()
					+ L"[DEBUG]"
					+ L"[Thread_id: " + std::to_wstring(thread_id) + L']'
					+ L"[Line:" + std::to_wstring(line) + L']'
					+ L"[Function: " + STR2WSTR(func) + L']'
					+ std::wstring(buf) + L"\r\n");
			}
			else if (option == SHOW_MESSAGE)
			{
				L_OUT_W(std::wstring(buf) + L"\r\n");
			}
			else
			{
				L_OUT_W(GetTimeW(), WHITE);
				L_OUT_W(L"[", WHITE);
				L_OUT_W(L"DEBUG", DARK_BLUE);
				L_OUT_W(L"]", WHITE);
				L_OUT_W(L"[Thread_id: " + std::to_wstring(thread_id) + L']', WHITE);
				L_OUT_W(L"[Line: " + std::to_wstring(line) + L']', WHITE);
				L_OUT_W(L"[Function: " + STR2WSTR(func) + L']', WHITE);
				L_OUT_W(std::wstring(buf) + L"\r\n");
			}
			delete[] buf;
		}
		va_end(args);
	}
	LeaveCriticalSection(&s_mutex);
}

void TraceLogger::InfoW(const CHAR* func, ULONG line, const WCHAR* format, ...) 
{
	EnterCriticalSection(&s_mutex);
	DWORD thread_id = GetCurrentThreadId();
	WCHAR* buf = NULL;
	ULONG size = 0;
	if (level >= LOG_INFO && enable_log)
	{
		va_list args;
		va_start(args, format);
		size = _vscwprintf(format, args) + 1;
		buf = new WCHAR[size];
		if (buf != NULL)
		{
			vswprintf_s(buf, size, format, args);
			if (option == OUTPUT_DEBUG || option == WRITE_TO_FILE)
			{
				L_OUT_W(GetTimeW()
					+ L"[INFO]"
					+ L"[Thread_id: " + std::to_wstring(thread_id) + L']'
					+ L"[Line: " + std::to_wstring(line) + L']'
					+ L"[Function: " + STR2WSTR(func) + L']'
					+ std::wstring(buf) + L"\r\n");
			}
			else if (option == SHOW_MESSAGE)
			{
				L_OUT_W(std::wstring(buf) + L"\r\n");
			}
			else
			{
				L_OUT_W(GetTimeW(), WHITE);
				L_OUT_W(L"[", WHITE);
				L_OUT_W(L"INFO", CYAN);
				L_OUT_W(L"]", WHITE);
				L_OUT_W(L"[Thread_id: " + std::to_wstring(thread_id) + L']', WHITE);
				L_OUT_W(L"[Line: " + std::to_wstring(line) + L']', WHITE);
				L_OUT_W(L"[Function: " + STR2WSTR(func) + L']', WHITE);
				L_OUT_W(std::wstring(buf) + L"\r\n", WHITE);
			}
			delete[] buf;
		}
		va_end(args);
	}
	LeaveCriticalSection(&s_mutex);
}

void TraceLogger::WarningW(const CHAR* func, ULONG line, const WCHAR* format, ...) 
{
	EnterCriticalSection(&s_mutex);
	DWORD thread_id = GetCurrentThreadId();
	WCHAR* buf = NULL;
	ULONG size = 0;
	if (level >= LOG_WARNING && enable_log)
	{
		va_list args;
		va_start(args, format);
		size = _vscwprintf(format, args) + 1;
		buf = new WCHAR[size];
		if (buf != NULL)
		{
			vswprintf_s(buf, size, format, args);
			if (option == OUTPUT_DEBUG || option == WRITE_TO_FILE)
			{
				L_OUT_W(GetTimeW()
					+ L"[WARNING]"
					+ L"[Thread_id: " + std::to_wstring(thread_id) + L']'
					+ L"[Line: " + std::to_wstring(line) + L']'
					+ L"[Function: " + STR2WSTR(func) + L']'
					+ std::wstring(buf) + L"\r\n");
			}
			else if (option == SHOW_MESSAGE)
			{
				L_OUT_W(std::wstring(buf) + L"\r\n");
			}
			else
			{
				L_OUT_W(GetTimeW(), WHITE);
				L_OUT_W(L"[", WHITE);
				L_OUT_W(L"WARNING", YELLOW);
				L_OUT_W(L"]", WHITE);
				L_OUT_W(L"[Thread_id: " + std::to_wstring(thread_id) + L']', WHITE);
				L_OUT_W(L"[Line: " + std::to_wstring(line) + L']', WHITE);
				L_OUT_W(L"[Function: " + STR2WSTR(func) + L']', WHITE);
				L_OUT_W(std::wstring(buf) + L"\r\n", WHITE);
			}
			delete[] buf;
		}
		va_end(args);
	}
	LeaveCriticalSection(&s_mutex);
}

void TraceLogger::ErrorW(const CHAR* func, ULONG line, const CHAR* file, const WCHAR* format, ...) 
{
	EnterCriticalSection(&s_mutex);
	DWORD thread_id = GetCurrentThreadId();
	WCHAR* buf = NULL;
	ULONG size = 0;
	if (level >= LOG_ERROR && enable_log)
	{
		va_list args;
		va_start(args, format);
		size = _vscwprintf(format, args) + 1;
		buf = new WCHAR[size];
		if (buf != NULL)
		{
			vswprintf_s(buf, size, format, args);
			if (option == OUTPUT_DEBUG || option == WRITE_TO_FILE)
			{
				L_OUT_W(GetTimeW()
					+ L"[ERROR]"
					+ L"[Thread_id: " + std::to_wstring(thread_id) + L']'
					+ L"[Line: " + std::to_wstring(line) + L']'
					+ L"[File: " + STR2WSTR(file) + L']'
					+ L"[Function: " + STR2WSTR(func) + L']'
					+ std::wstring(buf) + L"\r\n");
			}
			else if (option == SHOW_MESSAGE)
			{
				L_OUT_W(std::wstring(buf) + L"\r\n");
			}
			else
			{
				L_OUT_W(GetTimeW(), WHITE);
				L_OUT_W(L"[", WHITE);
				L_OUT_W(L"ERROR", RED);
				L_OUT_W(L"]", WHITE);
				L_OUT_W(L"[Thread_id: " + std::to_wstring(thread_id) + L']', WHITE);
				L_OUT_W(L"[Line: " + std::to_wstring(line) + L']', WHITE);
				L_OUT_W(L"[File: " + STR2WSTR(file) + L']', WHITE);
				L_OUT_W(L"[Function: " + STR2WSTR(func) + L']', WHITE);
				L_OUT_W(std::wstring(buf) + L"\r\n", WHITE);
			}
			delete[] buf;
		}
		va_end(args);
	}
	LeaveCriticalSection(&s_mutex);
}

void TraceLogger::SuccessW(const CHAR* func, ULONG line, const CHAR* file, const WCHAR* format, ...) 
{
	EnterCriticalSection(&s_mutex);
	DWORD thread_id = GetCurrentThreadId();
	WCHAR* buf = NULL;
	ULONG size = 0;
	if (level >= LOG_SUCCESS && enable_log)
	{
		va_list args;
		va_start(args, format);
		size = _vscwprintf(format, args) + 1;
		buf = new WCHAR[size];
		if (buf != NULL)
		{
			vswprintf_s(buf, size, format, args);
			if (option == OUTPUT_DEBUG || option == WRITE_TO_FILE)
			{
				L_OUT_W(GetTimeW()
					+ L"[SUCCESS]"
					+ L"[Thread_id: " + std::to_wstring(thread_id) + L']'
					+ L"[Line: " + std::to_wstring(line) + L']'
					+ L"[File: " + STR2WSTR(file) + L']'
					+ L"[Function: " + STR2WSTR(func) + L']'
					+ std::wstring(buf) + L"\r\n");
			}
			else if (option == SHOW_MESSAGE)
			{
				L_OUT_W(std::wstring(buf) + L"\r\n");
			}
			else
			{
				L_OUT_W(GetTimeW(), WHITE);
				L_OUT_W(L"[", WHITE);
				L_OUT_W(L"SUCCESS", FOREGROUND_GREEN);
				L_OUT_W(L"]", WHITE);
				L_OUT_W(L"[Thread_id: " + std::to_wstring(thread_id) + L']', WHITE);
				L_OUT_W(L"[Line: " + std::to_wstring(line) + L']', WHITE);
				L_OUT_W(L"[File: " + STR2WSTR(file) + L']', WHITE);
				L_OUT_W(L"[Function: " + STR2WSTR(func) + L']', WHITE);
				L_OUT_W(std::wstring(buf) + L"\r\n", WHITE);
			}
			delete[] buf;
		}
		va_end(args);
	}
	LeaveCriticalSection(&s_mutex);
}

void TraceLogger::CriticalW(const CHAR* func, ULONG line, const CHAR* file, const WCHAR* format, ...) 
{
	EnterCriticalSection(&s_mutex);
	DWORD thread_id = GetCurrentThreadId();
	WCHAR* buf = NULL;
	ULONG size = 0;
	if (level >= LOG_CRITICAL && enable_log)
	{
		va_list args;
		va_start(args, format);
		size = _vscwprintf(format, args) + 1;
		buf = new WCHAR[size];
		if (buf != NULL)
		{
			vswprintf_s(buf, size, format, args);
			if (option == OUTPUT_DEBUG || option == WRITE_TO_FILE)
			{
				L_OUT_W(GetTimeW()
					+ L"[CRITICAL]"
					+ L"[Thread_id: " + std::to_wstring(thread_id) + L']'
					+ L"[Line: " + std::to_wstring(line) + L']'
					+ L"[File: " + STR2WSTR(file) + L']'
					+ L"[Function: " + STR2WSTR(func) + L']'
					+ std::wstring(buf) + L"\r\n");
			}
			else if (option == SHOW_MESSAGE)
			{
				L_OUT_W(std::wstring(buf) + L"\r\n");
			}
			else
			{
				L_OUT_W(GetTimeW(), WHITE);
				L_OUT_W(L"[", WHITE);
				L_OUT_W(L"CRITICAL", BACKGROUND_RED_2 | WHITE);
				L_OUT_W(L"]", WHITE);
				L_OUT_W(L"[Thread_id: " + std::to_wstring(thread_id) + L']', WHITE);
				L_OUT_W(L"[Line: " + std::to_wstring(line) + L']', WHITE);
				L_OUT_W(L"[File: " + STR2WSTR(file) + L']', WHITE);
				L_OUT_W(L"[Function: " + STR2WSTR(func) + L']', WHITE);
				L_OUT_W(std::wstring(buf) + L"\r\n", WHITE);
			}
			delete[] buf;
		}
		va_end(args);
	}
	LeaveCriticalSection(&s_mutex);
}
#pragma endregion

#pragma region TRACER
void TraceLogger::TraceA(const CHAR* format, ...) 
{
	EnterCriticalSection(&s_mutex);
	CHAR* buf = NULL;
	ULONG size = 0;
	if (enable_trace)
	{
		va_list args;
		va_start(args, format);
		size = _vscprintf(format, args) + 1;
		buf = new CHAR[size];
		if (buf != NULL)
		{
			vsprintf_s(buf, size, format, args);
			if (option == OUTPUT_DEBUG || option == WRITE_TO_FILE)
			{
				L_OUT_A(GetTimeA() + "[TRACING]" + buf + "\r\n");
			}
			else if (option == SHOW_MESSAGE)
			{
				L_OUT_A(std::string(buf) + "\r\n");
			}
			else
			{
				L_OUT_A(GetTimeA(), WHITE);
				L_OUT_A("[", WHITE);
				L_OUT_A("TRACING", DARK_BLUE);
				L_OUT_A("]" + std::string(buf) + "\r\n", WHITE);
			}
			delete[] buf;
		}
		va_end(args);
	}
	LeaveCriticalSection(&s_mutex);
}

void TraceLogger::TraceInA(const CHAR* func, ULONG line, const CHAR* format, ...) 
{
	EnterCriticalSection(&s_mutex);
	DWORD thread_id = GetCurrentThreadId();
	CHAR* buf = NULL;
	ULONG size = 0;
	if (enable_trace)
	{
		va_list args;
		va_start(args, format);
		size = _vscprintf(format, args) + 1;
		buf = new CHAR[size];
		if (buf != NULL)
		{
			vsprintf_s(buf, size, format, args);
			if (option == OUTPUT_DEBUG || option == WRITE_TO_FILE)
			{
				L_OUT_A(GetTimeA()
					+ "[TRACE_IN]"
					+ "[Thread_id: " + std::to_string(thread_id) + ']'
					+ "[Line: " + std::to_string(line) + ']'
					+ "[Function: " + std::string(func) + ']'
					+ std::string(buf) + "\r\n");
			}
			else if (option == SHOW_MESSAGE)
			{
				L_OUT_A(std::string(buf) + "\r\n");
			}
			else
			{
				L_OUT_A(GetTimeA(), WHITE);
				L_OUT_A("[", WHITE);
				L_OUT_A("TRACE_IN", BLUE);
				L_OUT_A("]", WHITE);
				L_OUT_A("[Thread_id: " + std::to_string(thread_id) + ']', WHITE);
				L_OUT_A("[Line: " + std::to_string(line) + ']', WHITE);
				L_OUT_A("[Function: " + std::string(func) + ']', WHITE);
				L_OUT_A(std::string(buf) + "\r\n", WHITE);
			}
			delete[] buf;
		}
		va_end(args);
	}
	LeaveCriticalSection(&s_mutex);
}

void TraceLogger::TraceOutA(const CHAR* func, ULONG line, const CHAR* format, ...) 
{
	EnterCriticalSection(&s_mutex);
	DWORD thread_id = GetCurrentThreadId();
	CHAR* buf = NULL;
	ULONG size = 0;
	if (enable_trace)
	{
		va_list args;
		va_start(args, format);
		size = _vscprintf(format, args) + 1;
		buf = new CHAR[size];
		if (buf != NULL)
		{
			vsprintf_s(buf, size, format, args);
			if (option == OUTPUT_DEBUG || option == WRITE_TO_FILE)
			{
				L_OUT_A(GetTimeA()
					+ "[TRACE_OUT]"
					+ "[Thread_id: " + std::to_string(thread_id) + ']'
					+ "[Line: " + std::to_string(line) + ']'
					+ "[Function: " + std::string(func) + ']'
					+ std::string(buf) + "\r\n");
			}
			else if (option == SHOW_MESSAGE)
			{
				L_OUT_A(std::string(buf) + "\r\n");
			}
			else
			{
				L_OUT_A(GetTimeA(), WHITE);
				L_OUT_A("[", WHITE);
				L_OUT_A("TRACE_OUT", BLUE);
				L_OUT_A("]", WHITE);
				L_OUT_A("[Thread_id: " + std::to_string(thread_id) + ']', WHITE);
				L_OUT_A("[Line: " + std::to_string(line) + ']', WHITE);
				L_OUT_A("[Function: " + std::string(func) + ']', WHITE);
				L_OUT_A(std::string(buf) + "\r\n", WHITE);
			}
			delete[] buf;
		}
		va_end(args);
	}
	LeaveCriticalSection(&s_mutex);
}

void TraceLogger::TraceW(const WCHAR* format, ...)
{
	EnterCriticalSection(&s_mutex);
	WCHAR* buf = NULL;
	ULONG size = 0;
	if (enable_trace)
	{
		va_list args;
		va_start(args, format);
		size = _vscwprintf(format, args) + 1;
		buf = new WCHAR[size];
		if (buf != NULL)
		{
			vswprintf_s(buf, size, format, args);
			if (option == OUTPUT_DEBUG || option == WRITE_TO_FILE)
			{
				L_OUT_W(GetTimeW() + L"[TRACING]" + std::wstring(buf) + L"\r\n");
			}
			else if (option == SHOW_MESSAGE)
			{
				L_OUT_W(std::wstring(buf) + L"\r\n");
			}
			else
			{
				L_OUT_W(GetTimeW(), WHITE);
				L_OUT_W(L"[", WHITE);
				L_OUT_W(L"TRACING", DARK_BLUE);
				L_OUT_W(L"]" + std::wstring(buf) + L"\r\n", WHITE);
			}
			delete[] buf;
		}
		va_end(args);
	}
	LeaveCriticalSection(&s_mutex);
}

void TraceLogger::TraceInW(const CHAR* func, ULONG line, const WCHAR* format, ...)
{
	EnterCriticalSection(&s_mutex);
	DWORD thread_id = GetCurrentThreadId();
	WCHAR* buf = NULL;
	ULONG size = 0;
	if (enable_trace)
	{
		va_list args;
		va_start(args, format);
		size = _vscwprintf(format, args) + 1;
		buf = new WCHAR[size];
		if (buf != NULL)
		{
			vswprintf_s(buf, size, format, args);
			if (option == OUTPUT_DEBUG || option == WRITE_TO_FILE)
			{
				L_OUT_W(GetTimeW()
					+ L"[TRACE_IN]"
					+ L"[Thread_id: " + std::to_wstring(thread_id) + L']'
					+ L"[Line:" + std::to_wstring(line) + L']'
					+ L"[Function: " + STR2WSTR(func) + L']'
					+ std::wstring(buf) + L"\r\n");
			}
			else if (option == SHOW_MESSAGE)
			{
				L_OUT_W(std::wstring(buf) + L"\r\n");
			}
			else
			{
				L_OUT_W(GetTimeW(), WHITE);
				L_OUT_W(L"[", WHITE);
				L_OUT_W(L"TRACE_IN", BLUE);
				L_OUT_W(L"]", WHITE);
				L_OUT_W(L"[Thread_id: " + std::to_wstring(thread_id) + L']', WHITE);
				L_OUT_W(L"[Line: " + std::to_wstring(line) + L']', WHITE);
				L_OUT_W(L"[Function: " + STR2WSTR(func) + L']', WHITE);
				L_OUT_W(std::wstring(buf) + L"\r\n", WHITE);
			}
			delete[] buf;
		}
		va_end(args);
	}
	LeaveCriticalSection(&s_mutex);
}

void TraceLogger::TraceOutW(const CHAR* func, ULONG line, const WCHAR* format, ...)
{
	EnterCriticalSection(&s_mutex);
	DWORD thread_id = GetCurrentThreadId();
	WCHAR* buf = NULL;
	ULONG size = 0;
	if (enable_trace)
	{
		va_list args;
		va_start(args, format);
		size = _vscwprintf(format, args) + 1;
		buf = new WCHAR[size];
		if (buf != NULL)
		{
			vswprintf_s(buf, size, format, args);
			if (option == OUTPUT_DEBUG || option == WRITE_TO_FILE)
			{
				L_OUT_W(GetTimeW()
					+ L"[TRACE_OUT]"
					+ L"[Thread_id: " + std::to_wstring(thread_id) + L']'
					+ L"[Line:" + std::to_wstring(line) + L']'
					+ L"[Function: " + STR2WSTR(func) + L']'
					+ std::wstring(buf) + L"\r\n");
			}
			else if (option == SHOW_MESSAGE)
			{
				L_OUT_W(std::wstring(buf) + L"\r\n");
			}
			else
			{
				L_OUT_W(GetTimeW(), WHITE);
				L_OUT_W(L"[", WHITE);
				L_OUT_W(L"TRACE_OUT", BLUE);
				L_OUT_W(L"]", WHITE);
				L_OUT_W(L"[Thread_id: " + std::to_wstring(thread_id) + L']', WHITE);
				L_OUT_W(L"[Line: " + std::to_wstring(line) + L']', WHITE);
				L_OUT_W(L"[Function: " + STR2WSTR(func) + L']', WHITE);
				L_OUT_W(std::wstring(buf) + L"\r\n", WHITE);
			}
			delete[] buf;
		}
		va_end(args);
	}
	LeaveCriticalSection(&s_mutex);
}
#pragma endregion

std::string TraceLogger::GetTimeA() 
{
	SYSTEMTIME sys;
	GetLocalTime(&sys);
	char tmp[64] = { '\0' };
	sprintf_s(tmp, "[%04d-%02d-%02d|%02d:%02d:%02d.%03d]", sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond, sys.wMilliseconds);
	return tmp;
}
std::wstring TraceLogger::GetTimeW() 
{
	SYSTEMTIME sys;
	GetLocalTime(&sys);
	wchar_t tmp[64] = { L'\0' };
	swprintf_s(tmp, L"[%04d-%02d-%02d|%02d:%02d:%02d.%03d]", sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond, sys.wMilliseconds);
	return tmp;
}

std::wstring TraceLogger::STR2WSTR(const std::string& str)
{
	int wchar_num = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
	if (wchar_num == 0) return L"";
	std::wstring wstr(wchar_num, 0);
	MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], wchar_num);
	wstr.pop_back();	// delete end null
	return wstr;
}
std::string TraceLogger::WSTR2STR(const std::wstring& wstr)
{
	int char_num = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
	if (char_num == 0) return "";
	std::string str(char_num, 0);
	WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], char_num, NULL, NULL);
	str.pop_back();		// delete end null
	return str;
}

#endif