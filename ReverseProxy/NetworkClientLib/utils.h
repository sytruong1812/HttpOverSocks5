#pragma once
#include <map>
#include <string>
#include <vector>
#include <sstream>
#include <wtypes.h>
#include <iostream>
#include <algorithm>
#include <functional>

#define KB	1024
#define MB	(KB * KB)  // 1 MB = 1024 * 1024 = 1,048,576
#define GB	(MB * KB)  // 1 GB = 1,024 * 1,024 * 1,024 = 1,073,741,824
#define TB	(GB * KB)  // 1 TB = 1,024 * 1,024 * 1,024 * 1,024 = 1,099,511,627,776

namespace Helper 
{
    std::string CreateUUIDString();

    class DeferFunctionRAII
    {
    public:
        DeferFunctionRAII(std::function<void()> func) : deferred_func_(func) {}
        ~DeferFunctionRAII() { if (deferred_func_) deferred_func_(); }
    private:
        std::function<void()> deferred_func_;
    };

    class StringHelper 
    {
    public:
		static int convertHexToNumber(const std::string& s);
		static std::string convertNumberToHex(size_t n);
        static std::string convertWideStringToString(const std::wstring& wstr);
        static std::wstring convertStringToWideString(const std::string& str);
    };

    class PathHelper
    {
    public:
        static BOOL isFilePath(const std::wstring& path);
        static BOOL isFolderPath(const std::wstring& path);
        static BOOL isValidFilePath(const std::wstring& path);
        static std::wstring getCurrentDirectory();
        static std::wstring extractFileNameFromFilePath(const std::wstring& path);
        static std::wstring extractExtensionWithoutFileName(const std::wstring& path);
        static std::wstring extractFileNameWithoutExtension(const std::wstring& path);
        static std::wstring extractParentNameFromPath(const std::wstring& path);
        static std::wstring extractParentPathFromPath(const std::wstring& path);
        static std::wstring getPathFromEnvironmentVariable(const std::wstring& env);
        static std::wstring replaceFileNameFromPath(const std::wstring& path, const std::wstring& name);
        static std::wstring replaceFileExtensionFromPath(const std::wstring& path, const std::wstring& extension);
        static std::wstring combinePathComponent(const std::wstring& basePath, const std::wstring& component);
        static std::wstring combinePathComponent(const std::wstring& basePath, const std::wstring& component1, const std::wstring& component2);
    };

    class FileHelper 
    {
    public:
        static BOOL IsFileExists(const std::wstring& path);
        static BOOL ReadFileData(const std::wstring& path, BYTE*& pData, DWORD& szData);
        static BOOL WriteFileData(const std::wstring& path, const BYTE* pData, const DWORD& szData);
    };
}