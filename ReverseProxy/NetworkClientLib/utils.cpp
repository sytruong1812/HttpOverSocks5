#include <regex>
#include <random>
#include <chrono>
#include <iomanip>
#include <strsafe.h>
#include <Windows.h>
#include <Shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

#include "utils.h"

namespace Helper 
{
    std::string CreateUUIDString()
    {
        GUID guid;
        if (CoCreateGuid(&guid) != S_OK)
        {
            throw std::runtime_error("Failed to create GUID!");
        }
        char guid_string[37]; // 32 hex chars + 4 hyphens + null terminator
        snprintf(guid_string, sizeof(guid_string),
            "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            guid.Data1, guid.Data2, guid.Data3,
            guid.Data4[0], guid.Data4[1], guid.Data4[2],
            guid.Data4[3], guid.Data4[4], guid.Data4[5],
            guid.Data4[6], guid.Data4[7]);
        return guid_string;
    }

    int StringHelper::convertHexToNumber(const std::string& s)
    {
        int val = 0;
        int cnt = (int)s.size();
        for (int i = 0; cnt; i++, cnt--)
        {
            if (!s[i]) { return false; }
            auto v = 0;
            if (0x20 <= s[i] && isdigit(s[i]))
            {
                v = s[i] - '0';
                val = val * 16 + v;
            }
            else if ('A' <= s[i] && s[i] <= 'F')
            {
                v = s[i] - 'A' + 10;
                val = val * 16 + v;
            }
            else if ('a' <= s[i] && s[i] <= 'f')
            {
                v = s[i] - 'a' + 10;
                val = val * 16 + v;
            }
            else
            {
                return -1;
            }
        }
        return val;
    }

    std::string StringHelper::convertNumberToHex(size_t n)
    {
        static const auto charset = "0123456789abcdef";
        std::string ret;
        do
        {
            ret = charset[n & 15] + ret;
            n >>= 4;
        } while (n > 0);
        return ret;
    }

    std::wstring StringHelper::convertStringToWideString(const std::string& str)
    {
        int wchar_num = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
        if (wchar_num == 0) return L"";

        std::wstring wstr(wchar_num, 0);
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], wchar_num);

        // delete end null
        wstr.pop_back();
        return wstr;
    }

    std::string StringHelper::convertWideStringToString(const std::wstring& wstr)
    {
        int char_num = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
        if (char_num == 0) return "";

        std::string str(char_num, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], char_num, NULL, NULL);

        // delete end null
        str.pop_back();
        return str;
    }

    BOOL PathHelper::isFilePath(const std::wstring& path)
    {
        DWORD attrs = GetFileAttributesW(path.c_str());
        return (attrs != INVALID_FILE_ATTRIBUTES) && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
    }

    BOOL PathHelper::isFolderPath(const std::wstring& path)
    {
        DWORD attrs = GetFileAttributesW(path.c_str());
        return (attrs != INVALID_FILE_ATTRIBUTES) && (attrs & FILE_ATTRIBUTE_DIRECTORY);
    }

    BOOL PathHelper::isValidFilePath(const std::wstring& path)
    {
        if (path.empty())
        {
            return FALSE;
        }
        if (path.length() > 260)
        {
            return FALSE;
        }
        for (wchar_t c : path)
        {
            if (c == L'<' || c == L'>' || c == L'"' || c == L'/' ||
                c == L'|' || c == L'?' || c == L'*' || c == L'`')
            {
                return FALSE;
            }
        }
        size_t dotPosition = path.rfind(L'.');
        size_t slashPosition = path.find_last_of(L"/\\");
        return (dotPosition != std::wstring::npos) && (dotPosition > slashPosition);
    }

    std::wstring PathHelper::getCurrentDirectory()
    {
        wchar_t absolutePath[MAX_PATH];
        DWORD result = GetCurrentDirectoryW(MAX_PATH, absolutePath);
        if (result == 0)
        {
            return L"";
        }
        return std::wstring(absolutePath);
    }

    std::wstring PathHelper::extractParentPathFromPath(const std::wstring& path)
    {
        size_t lastSlashPos = path.find_last_of(L"/\\");
        if (lastSlashPos != std::wstring::npos && lastSlashPos > 1)
        {
            return path.substr(0, lastSlashPos);
        }
        return path;
    }

    std::wstring PathHelper::extractFileNameFromFilePath(const std::wstring& path)
    {
        std::wstring file_name;
        size_t lastSlashPos = path.find_last_of(L"/\\");
        if (lastSlashPos != std::wstring::npos && lastSlashPos > 1)
        {
            file_name = path.substr(lastSlashPos + 1);
        }
        return file_name;
    }

    std::wstring PathHelper::extractParentNameFromPath(const std::wstring& path)
    {
        std::wstring folder_name;
        size_t lastSlashPos = path.find_last_of(L"/\\");
        if (lastSlashPos != std::wstring::npos && lastSlashPos > 1)
        {
            std::wstring folder_path = path.substr(0, lastSlashPos);
            size_t lastSlashPos2 = folder_path.find_last_of(L"/\\");
            if (lastSlashPos2 != std::wstring::npos && lastSlashPos2 > 1)
            {
                folder_name = folder_path.substr(lastSlashPos2 + 1);
            }
        }
        return folder_name;
    }

    std::wstring PathHelper::extractExtensionWithoutFileName(const std::wstring& path)
    {
        std::wstring file_extension = L"";
        size_t lastSlashPos = path.find_last_of(L"/\\");
        if (lastSlashPos != std::wstring::npos && lastSlashPos > 1)
        {
            std::wstring file_name = path.substr(lastSlashPos + 1);
            size_t lastDotPos = file_name.find_last_of(L".");
            if (lastDotPos != std::wstring::npos && lastDotPos > 1)
            {
                file_extension = file_name.substr(lastDotPos);
            }
        }
        return file_extension;
    }

    std::wstring PathHelper::extractFileNameWithoutExtension(const std::wstring& path)
    {
        size_t lastSlashPos = path.find_last_of(L"/\\");
        std::wstring fileName = path;
        if (lastSlashPos != std::wstring::npos)
        {
            fileName = path.substr(lastSlashPos + 1);
        }
        size_t extensionPos = fileName.find_last_of(L".");
        if (extensionPos != std::wstring::npos)
        {
            return fileName.substr(0, extensionPos);
        }
        return fileName;
    }

    std::wstring PathHelper::getPathFromEnvironmentVariable(const std::wstring& env)
    {
        wchar_t envPath[MAX_PATH];
        int pathLength = ExpandEnvironmentStringsW(env.c_str(), envPath, MAX_PATH);
        return (pathLength != 0 && pathLength < MAX_PATH) ? envPath : env;
    }

    std::wstring PathHelper::replaceFileNameFromPath(const std::wstring& path, const std::wstring& name)
    {
        std::wstring file_path = path;
        std::wstring file_name = extractFileNameFromFilePath(path);
        file_path.replace(file_path.find(file_name), file_name.length(), name);
        return file_path;
    }

    std::wstring PathHelper::replaceFileExtensionFromPath(const std::wstring& path, const std::wstring& extension)
    {
        std::wstring file_path = path;
        std::wstring file_extension = extractExtensionWithoutFileName(path);
        file_path.replace(file_path.find(file_extension), file_extension.length(), extension);
        return file_path;
    }

    std::wstring PathHelper::combinePathComponent(const std::wstring& basePath, const std::wstring& component)
    {

        if (!basePath.empty() && basePath.back() != L'\\')
        {
            return basePath + L'\\' + component;
        }
        return basePath + component;
    }

    std::wstring PathHelper::combinePathComponent(const std::wstring& basePath, const std::wstring& component1, const std::wstring& component2)
    {
        if (!basePath.empty() && basePath.back() != L'\\')
        {
            return basePath + L'\\' + component1 + L"\\" + component2;
        }
        return basePath + component1 + L"\\" + component2;
    }

    BOOL FileHelper::IsFileExists(const std::wstring& path)
    {
        if (!PathFileExistsW(path.c_str()))
        {
            return FALSE;
        }
        DWORD dwAttrib = GetFileAttributesW(path.c_str());
        return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
    }

    BOOL FileHelper::ReadFileData(const std::wstring& path, BYTE*& pData, DWORD& szData)
    {
        DWORD bytesRead, totalBytesRead = 0;
        HANDLE hInputFile = CreateFileW(path.c_str(),
            GENERIC_READ,
            0,		// open with exclusive access
            NULL,	// no security attributes
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
        if (hInputFile == INVALID_HANDLE_VALUE)
        {
            return FALSE;
        }
        DeferFunctionRAII closeFileHandle([&hInputFile]() { CloseHandle(hInputFile); });

        DWORD fileSize = GetFileSize(hInputFile, NULL);
        pData = new BYTE[fileSize];
        if (pData == NULL)
        {
            return FALSE;
        }
        DWORD nBufferSize = min(fileSize, 10 * MB);
        BYTE* nBuffer = new BYTE[nBufferSize];
        if (nBuffer == NULL)
        {
            return FALSE;
        }
        while (ReadFile(hInputFile, nBuffer, nBufferSize, &bytesRead, NULL) && bytesRead > 0)
        {
            memcpy(pData + totalBytesRead, nBuffer, bytesRead);
            totalBytesRead += bytesRead;
        }
        szData = totalBytesRead;
        if (nBuffer != NULL)
        {
            delete[] nBuffer;
            nBuffer = NULL;
        }
        return TRUE;
    }

    BOOL FileHelper::WriteFileData(const std::wstring& path, const BYTE* pData, const DWORD& szData)
    {
        DWORD bytesWrite = 0;
        HANDLE hOutputFile = CreateFileW(path.c_str(),
            GENERIC_WRITE,
            0,		// open with exclusive access
            NULL,	// no security attributes
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
        if (hOutputFile == INVALID_HANDLE_VALUE)
        {
            return FALSE;
        }
        DeferFunctionRAII closeFileHandle([&hOutputFile]() { CloseHandle(hOutputFile); });

        if (!WriteFile(hOutputFile, pData, szData, &bytesWrite, NULL) || bytesWrite != szData)
        {
            return FALSE;
        }
        return TRUE;
    }
}