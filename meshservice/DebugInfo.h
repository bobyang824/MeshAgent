#ifndef WstDebugInfo_h
#define WstDebugInfo_h

#include <windows.h>
#include <stdlib.h>
#include <strsafe.h>

#ifdef UNICODE
#define DbgPrintf DbgPrintfW
#else
#define DbgPrintf DbgPrintfA
#endif

inline void writeLog(const char* message) {
    HANDLE hFile = NULL;
    DWORD dwBytesWritten = 0;

    char szPath[MAX_PATH] = { 0 };
    GetTempPathA(sizeof(szPath), szPath);
    strcat_s(szPath, sizeof(szPath), "agent.log");

    hFile = CreateFile(szPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        SetFilePointer(hFile, 0, NULL, FILE_END);

        time_t current_time;
        char formatted_time[80];
        struct tm* time_info;

        time(&current_time);
        time_info = localtime(&current_time);
        strftime(formatted_time, 80, "%Y-%m-%d %H:%M:%S ", time_info);
        WriteFile(hFile, formatted_time, strlen(formatted_time), &dwBytesWritten, NULL);
        
        WriteFile(hFile, message, strlen(message), &dwBytesWritten, NULL);
        WriteFile(hFile, "\r\n", 2, &dwBytesWritten, NULL);
        CloseHandle(hFile);
    }
}

inline void writeLogW(const wchar_t* message) {
    HANDLE hFile = NULL;
    DWORD dwBytesWritten = 0;

    char szPath[MAX_PATH] = { 0 };
    GetTempPathA(sizeof(szPath), szPath);
    strcat_s(szPath, sizeof(szPath), "agent.log");

    hFile = CreateFile(szPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        SetFilePointer(hFile, 0, NULL, FILE_END);
        time_t current_time;
        wchar_t formatted_time[80];
        struct tm* time_info;

        time(&current_time);
        time_info = localtime(&current_time);
        wcsftime(formatted_time, 80, L"%Y-%m-%d %H:%M:%S ", time_info);
        WriteFile(hFile, formatted_time, wcslen(formatted_time), &dwBytesWritten, NULL);
        WriteFile(hFile, message, wcslen(message), &dwBytesWritten, NULL);
        WriteFile(hFile, L"\r\n", 4, &dwBytesWritten, NULL);
        CloseHandle(hFile);
    }
}
inline void __cdecl DbgPrintfW(LPCWSTR format, ...) 
{
    va_list	args;
    va_start(args, format);
    DWORD nBufLen = _vscwprintf(format, args);

    if (nBufLen > 0) 
    {
        nBufLen = sizeof(WCHAR) * (nBufLen + 1);

        LPWSTR buf = (LPWSTR) malloc(nBufLen);

        if (buf) 
        {
            HRESULT hr = StringCbVPrintfW(buf, nBufLen, format, args);

            if (SUCCEEDED(hr)) 
            {
                writeLogW(buf);
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
    DWORD nBufLen = _vscprintf(format, args);

    if (nBufLen > 0) 
    {
        nBufLen = sizeof(CHAR) * (nBufLen + 1);

        LPSTR buf = (LPSTR) malloc(nBufLen);

        if (buf) 
        {
            HRESULT hr = StringCbVPrintfA(buf, nBufLen, format, args);

            if (SUCCEEDED(hr)) 
            {
                writeLog(buf);
                OutputDebugStringA(buf);
            }
            free(buf);
        }
        va_end(args);
    }
}
#endif