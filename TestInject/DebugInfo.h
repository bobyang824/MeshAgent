#ifndef WstDebugInfo_h
#define WstDebugInfo_h

#include <windows.h>
#include <stdlib.h>
#include <strsafe.h>
#include <fstream>
#include <ctime>

#ifdef UNICODE
#define DbgPrintf DbgPrintfW
#else
#define DbgPrintf DbgPrintfA
#endif


inline void writeLog(const std::string& message) {
    std::ofstream logFile;
    logFile.open("log.txt", std::ios_base::app);

    std::time_t currentTime = std::time(nullptr);
    char timeString[26];
    std::strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", std::localtime(&currentTime));

    logFile << timeString << " - " << message << std::endl;

    logFile.close();
}

inline void writeLog(const std::wstring& message) {
    std::wofstream logFile;
    logFile.open("log.txt", std::ios_base::app);

    std::time_t currentTime = std::time(nullptr);
    wchar_t timeString[26];
    std::wcsftime(timeString, sizeof(timeString), L"%Y-%m-%d %H:%M:%S", std::localtime(&currentTime));

    logFile << timeString << L" - " << message << std::endl;

    logFile.close();
}


inline void __cdecl DbgPrintfW(LPCWSTR format, ...) 
{
    va_list	args;
    va_start(args, format);
    size_t nBufLen = _vscwprintf(format, args);

    if (nBufLen > 0) 
    {
        nBufLen = sizeof(WCHAR) * (nBufLen + 1);

        LPWSTR buf = (LPWSTR) malloc(nBufLen);

        if (buf) 
        {
            HRESULT hr = StringCbVPrintfW(buf, nBufLen, format, args);

            if (SUCCEEDED(hr)) 
            {
                OutputDebugStringW(buf);
            }
            free(buf);
        }
        va_end(args);
    }
}

inline void __cdecl DbgPrintfA(LPCSTR format, ...) 
{
    va_list	args;
    va_start(args, format);
    size_t nBufLen = _vscprintf(format, args);

    if (nBufLen > 0) 
    {
        nBufLen = sizeof(CHAR) * (nBufLen + 1);

        LPSTR buf = (LPSTR) malloc(nBufLen);

        if (buf) 
        {
            HRESULT hr = StringCbVPrintfA(buf, nBufLen, format, args);

            if (SUCCEEDED(hr)) 
            {
                OutputDebugStringA(buf);
            }
            free(buf);
        }
        va_end(args);
    }
}
#endif