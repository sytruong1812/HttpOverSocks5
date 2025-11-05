#pragma once
#ifndef TRACE_LOGGER
#define TRACE_LOGGER
#endif

#if defined TRACE_LOGGER
#ifndef __FUNCTION_NAME__
#ifdef WIN32   //WINDOWS
#define __FUNCTION_NAME__   __FUNCTION__  
#else          //*NIX
#define __FUNCTION_NAME__   __func__ 
#endif
#endif
#if defined(_WIN32) || defined(_WIN64)
#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#else
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif /* defined(_WIN32) || defined(_WIN64) */

#include <string>
#include <sstream>
#include <wtypes.h>

//Color
#define BLACK				0
#define DARK_BLUE			1
#define DARK_GREEN			2
#define CYAN				3
#define DARK_RED			4
#define PURPLE				5
#define ORANGE				6
#define GRAY				7
#define DARK_GRAY			8
#define BLUE				9
#define GREEN				10
#define AQUA				11
#define	RED					12
#define PINK				13
#define YELLOW				14
#define WHITE				15
#define BACKGROUND_RED_2	0xc4

enum LOG_LEVEL
{
	LOG_NONCE	 = 10,
	LOG_DEBUG	 = 20,
	LOG_INFO	 = 30,
	LOG_WARNING	 = 40,
	LOG_ERROR	 = 50,
	LOG_SUCCESS	 = 60,
	LOG_CRITICAL = 70
};

enum LOG_OPTION
{
	SHOW_MESSAGE,
	SHOW_CONSOLE,
	OUTPUT_DEBUG,
	WRITE_TO_FILE
};

class TraceLogger 
{
private:
	LOG_LEVEL level;
	LOG_OPTION option;
	BOOL enable_log = FALSE;
	BOOL enable_trace = FALSE;
	std::wstring log_file_path;
private:
	HANDLE hFile = NULL;
	BOOL W_LOG(const CHAR* buffer, DWORD size);
	void L_OUT_A(const std::string& ss, WORD color);
	void L_OUT_W(const std::wstring& ss, WORD color);
private:
	static TraceLogger* s_instance; 	//Singleton 
	TraceLogger(LOG_OPTION option_ = LOG_OPTION::SHOW_CONSOLE, LOG_LEVEL level_ = LOG_LEVEL::LOG_NONCE);
	std::string static GetTimeA();
	std::wstring static GetTimeW();
	std::wstring static STR2WSTR(const std::string& str);
	std::string static WSTR2STR(const std::wstring& wstr);
	template <typename Args> void static PrintArgsA(std::stringstream& ss, Args args) { ss << "{" << args << "}"; }
	template <typename Args> void static PrintArgsW(std::wstringstream& ss, Args args) { ss << L"{" << args << L"}"; }
public:
	static TraceLogger* instance()
	{	
		//Singleton 
		if (!s_instance)
		{
			s_instance = new TraceLogger;
		}
		return s_instance;
	}
	void EnableLog(BOOL enable);
	void EnableTrace(BOOL enable);
	void SetLogOut(LOG_OPTION opt);
	void SetLogLevel(LOG_LEVEL lv);
	void SetLogFilePath(std::wstring path);
	void CloseLogFileHandle();
public:
#pragma region LOGGER
	void LogA(ULONG line, const CHAR* format, ...);
	void DebugA(const CHAR* func, ULONG line, const CHAR* format, ...);
	void InfoA(const CHAR* func, ULONG line, const CHAR* format, ...);
	void WarningA(const CHAR* func, ULONG line, const CHAR* format, ...);
	void ErrorA(const CHAR* func, ULONG line, const CHAR* file, const CHAR* format, ...);
	void SuccessA(const CHAR* func, ULONG line, const CHAR* file, const CHAR* format, ...);
	void CriticalA(const CHAR* func, ULONG line, const CHAR* file, const CHAR* format, ...);
	/*=========================[UNICODE]==============================*/
	void LogW(ULONG line, const WCHAR* format, ...);
	void DebugW(const CHAR* func, ULONG line, const WCHAR* format, ...);
	void InfoW(const CHAR* func, ULONG line, const WCHAR* format, ...);
	void WarningW(const CHAR* func, ULONG line, const WCHAR* format, ...);
	void ErrorW(const CHAR* func, ULONG line, const CHAR* file, const WCHAR* format, ...);
	void SuccessW(const CHAR* func, ULONG line, const CHAR* file, const WCHAR* format, ...);
	void CriticalW(const CHAR* func, ULONG line, const CHAR* file, const WCHAR* format, ...);
#pragma endregion
public:
#pragma region TRACER
	void TraceA(const CHAR* format, ...);
	void TraceInA(const CHAR* func, ULONG line, const CHAR* format, ...);
	void TraceOutA(const CHAR* func, ULONG line, const CHAR* format, ...);
	template <typename Func, typename... Args>
	void TraceCallA(const CHAR* name, ULONG line, const CHAR* file, const Func& func, Args... args)
	{
		std::stringstream ss;
		if (enable_trace)
		{
			int dummy[] = { 0, ((void)PrintArgsA(ss, std::forward<Args>(args)),0)... };
			if (option == OUTPUT_DEBUG || option == WRITE_TO_FILE)
			{
				L_OUT_A(GetTimeA() 
					+ "[TRACE_CALL][Line: " + std::to_string(line) + ']' 
					+ "[Function call: " + std::string(name) + ']' 
					+ "[Param: " + ss.str() + ']' 
					+ "[File: " + std::string(file) + "]\r\n", WHITE);
			}
			else
			{
				L_OUT_A(GetTimeA(), WHITE);
				L_OUT_A("[", WHITE);
				L_OUT_A("TRACE_CALL", PURPLE);
				L_OUT_A("]", WHITE);
				L_OUT_A("[Line: " + std::to_string(line) + ']', WHITE);
				L_OUT_A("[Function call: " + std::string(name) + ']', WHITE);
				L_OUT_A("[Param: " + ss.str() + "]", WHITE);
				L_OUT_A("[File: " + std::string(file) + "]\r\n", WHITE);
			}
		}
		func(args...);
	}
	/*=========================[UNICODE]==============================*/
	void TraceW(const WCHAR* format, ...);
	void TraceInW(const CHAR* func, ULONG line, const WCHAR* format, ...);
	void TraceOutW(const CHAR* func, ULONG line, const WCHAR* format, ...);
	template <typename Func, typename... Args>
	void TraceCallW(const CHAR* name, ULONG line, const CHAR* file, const Func& func, Args... args)
	{
		std::wstringstream ss;
		if (enable_trace)
		{
			int dummy[] = { 0, ((void)PrintArgsW(ss, std::forward<Args>(args)),0)... };
			if (option == OUTPUT_DEBUG || option == WRITE_TO_FILE)
			{
				L_OUT_W(GetTimeW() 
					+ L"[TRACE_CALL][Line: " + std::to_wstring(line) + L']'
					+ L"[Function call: " + STR2WSTR(name) + L']' 
					+ L"[Param: " + ss.str() + L']' 
					+ L"[File: " + STR2WSTR(file) + L"]\r\n", WHITE);
			}
			else
			{
				L_OUT_W(GetTimeW(), WHITE);
				L_OUT_W(L"[", WHITE);
				L_OUT_W(L"TRACE_CALL", PURPLE);
				L_OUT_W(L"]", WHITE);
				L_OUT_W(L"[Line: " + std::to_wstring(line) + L']', WHITE);
				L_OUT_W(L"[Function call: " + STR2WSTR(name) + L']', WHITE);
				L_OUT_W(L"[Param: " + ss.str() + L"]", WHITE);
				L_OUT_W(L"[File: " + STR2WSTR(file) + L"]\r\n", WHITE);
			}
		}
		func(args...);
	}
#pragma endregion
};

#define ENABLE_LOG(e)		TraceLogger::instance()->EnableLog(e)
#define ENABLE_TRACE(e)		TraceLogger::instance()->EnableTrace(e)
#define SET_LOG_OUT(opt)	TraceLogger::instance()->SetLogOut(opt)
#define SET_LOG_LEVEL(lv)	TraceLogger::instance()->SetLogLevel(lv)
#define SET_FILE_PATH(p)	TraceLogger::instance()->SetLogFilePath(p)
#define CLOSE_FILE_HANDLE()	TraceLogger::instance()->CloseLogFileHandle()

#define LOG_A(...)			TraceLogger::instance()->LogA(__LINE__,__VA_ARGS__)
#define LOG_DEBUG_A(...)	TraceLogger::instance()->DebugA(__FUNCTION_NAME__,__LINE__,__VA_ARGS__)
#define LOG_INFO_A(...)		TraceLogger::instance()->InfoA(__FUNCTION_NAME__,__LINE__,__VA_ARGS__)
#define LOG_WARNING_A(...)	TraceLogger::instance()->WarningA(__FUNCTION_NAME__,__LINE__,__VA_ARGS__)
#define LOG_ERROR_A(...)	TraceLogger::instance()->ErrorA(__FUNCTION_NAME__,__LINE__,__FILENAME__,__VA_ARGS__)
#define LOG_SUCCESS_A(...)  TraceLogger::instance()->SuccessA(__FUNCTION_NAME__,__LINE__,__FILENAME__,__VA_ARGS__)
#define LOG_CRITICAL_A(...) TraceLogger::instance()->CriticalA(__FUNCTION_NAME__,__LINE__,__FILENAME__,__VA_ARGS__)

#define TRACE_A(...)		TraceLogger::instance()->TraceA(__VA_ARGS__)
#define TRACE_IN_A(...)		TraceLogger::instance()->TraceInA(__FUNCTION_NAME__,__LINE__,__VA_ARGS__)
#define TRACE_OUT_A(...)	TraceLogger::instance()->TraceOutA(__FUNCTION_NAME__,__LINE__,__VA_ARGS__)
#define TRACE_CALL_A(...)	TraceLogger::instance()->TraceCallA(__FUNCTION_NAME__,__LINE__,__FILENAME__,__VA_ARGS__)

#define LOG_W(...)			TraceLogger::instance()->LogW(__LINE__,__VA_ARGS__)
#define LOG_DEBUG_W(...)	TraceLogger::instance()->DebugW(__FUNCTION_NAME__,__LINE__,__VA_ARGS__)
#define LOG_INFO_W(...)		TraceLogger::instance()->InfoW(__FUNCTION_NAME__,__LINE__,__VA_ARGS__)
#define LOG_WARNING_W(...)	TraceLogger::instance()->WarningW(__FUNCTION_NAME__,__LINE__,__VA_ARGS__)
#define LOG_ERROR_W(...)	TraceLogger::instance()->ErrorW(__FUNCTION_NAME__,__LINE__,__FILENAME__,__VA_ARGS__)
#define LOG_SUCCESS_W(...)  TraceLogger::instance()->SuccessW(__FUNCTION_NAME__,__LINE__,__FILENAME__,__VA_ARGS__)
#define LOG_CRITICAL_W(...) TraceLogger::instance()->CriticalW(__FUNCTION_NAME__,__LINE__,__FILENAME__,__VA_ARGS__)

#define TRACE_W(...)		TraceLogger::instance()->TraceW(__VA_ARGS__)
#define TRACE_IN_W(...)		TraceLogger::instance()->TraceInW(__FUNCTION_NAME__,__LINE__,__VA_ARGS__)
#define TRACE_OUT_W(...)	TraceLogger::instance()->TraceOutW(__FUNCTION_NAME__,__LINE__,__VA_ARGS__)
#define TRACE_CALL_W(...)	TraceLogger::instance()->TraceCallW(__FUNCTION_NAME__,__LINE__,__FILENAME__,__VA_ARGS__)

#else

#define ENABLE_LOG(...)
#define ENABLE_TRACE(...)
#define SET_LOG_OUT(...)
#define SET_LOG_LEVEL(...)
#define SET_FILE_PATH(...)
#define CLOSE_FILE_HANDLE()

#define LOG_A(...)
#define LOG_DEBUG_A(...)
#define LOG_INFO_A(...)
#define LOG_WARNING_A(...)
#define LOG_ERROR_A(...)
#define LOG_SUCCESS_A(...)
#define LOG_CRITICAL_A(...)

#define TRACE_A(...)
#define TRACE_IN_A(...)
#define TRACE_OUT_A(...)
#define TRACE_CALL_A(...)

#define LOG_W(...)
#define LOG_DEBUG_W(...)
#define LOG_INFO_W(...)
#define LOG_WARNING_W(...)
#define LOG_ERROR_W(...)
#define LOG_SUCCESS_W(...)
#define LOG_CRITICAL_W(...)

#define TRACE_W(...)
#define TRACE_IN_W(...)
#define TRACE_OUT_W(...)
#define TRACE_CALL_W(...)

#endif /* TRACE_LOGGER */

