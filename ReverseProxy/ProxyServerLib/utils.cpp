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

    void HexDump(const PBYTE pBuffer, DWORD szBuffer)
    {
        static const CHAR hexChars[] = "0123456789ABCDEF";
        DWORD j = 0;
        for (DWORD i = 0; i < szBuffer; ++i)
        {
            if (i != 0 && i % 16 == 0)
            {
                std::cout << " | ";
                for (DWORD j = i - 16; j < i; ++j)
                {
                    if (isprint(pBuffer[j]))
                    {
                        std::cout << pBuffer[j];
                    }
                    else
                    {
                        std::cout << ".";
                    }
                }
                std::cout << std::endl;
                j = i;
            }
            std::cout << hexChars[(pBuffer[i] >> 0x04)]
                      << hexChars[(pBuffer[i] & 0x0F)]
                      << " ";
        }
        // print the remaining bytes
        std::cout << " | ";
        while (j < szBuffer)
        {
            if (isprint(pBuffer[j]))
            {
                std::cout << pBuffer[j];
            }
            else
            {
                std::cout << ".";
            }
            ++j;
        }
        std::cout << std::endl << std::endl;
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

    BOOL FileHelper::IsFileExists(const std::wstring& path)
    {
        if (!PathFileExistsW(path.c_str()))
        {
            return FALSE;
        }
        DWORD dwAttrib = GetFileAttributesW(path.c_str());
        return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
    }

    BOOL FileHelper::ReadFileData(const std::wstring& path, PBYTE& pData, DWORD& szData)
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

    BOOL FileHelper::WriteFileData(const std::wstring& path, const PBYTE pData, const DWORD& szData)
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
