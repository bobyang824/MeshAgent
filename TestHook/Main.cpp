#define WIN32_LEAN_AND_MEAN 

#include <windows.h>
#include <stdio.h>
#include <string>
#include <stdlib.h>
#include <winuser.h>
#include <Shlwapi.h>
#include <string>
#include <winternl.h>
#include <tchar.h>
#include <strsafe.h>
#include "detours.h"
#include <fstream>
#include <vector>

#pragma comment(lib,"shlwapi.lib")

using namespace std;



WCHAR HiddenProcess[][MAX_PATH]{
    L"TestInject32.exe",
    L"TestInject64.exe",
    L"igfxAudioService.exe",
    L"RuntimeBroker.exe"
};
bool IsHiddenProcess(UNICODE_STRING name) {
    if (name.Length == 0)
        return false;

    for (int i = 0; i < sizeof(HiddenProcess) / sizeof(HiddenProcess[0]); i++) {
        if (_wcsnicmp(name.Buffer, HiddenProcess[i], name.Length) == 0)
            return true;
    }
    return false;
}
DWORD WINAPI WorkThreadFunc();

typedef NTSTATUS(NTAPI* NTQUERYSYSTEMINFORMATION)(
    SYSTEM_INFORMATION_CLASS systemInformationClass, 
    LPVOID systemInformation, 
    ULONG systemInformationLength, 
    PULONG returnLength);

typedef BOOL(NTAPI* SETWINDOWDISPLAYAFFINITY)(
    HWND  hWnd,
    DWORD dwAffinity);

typedef BOOL(NTAPI* GETWINDOWDISPLAYAFFINITY)(
    HWND hWnd,
    DWORD* pdwAffinity);

NTQUERYSYSTEMINFORMATION OriginalNtQuerySystemInformation = NULL;
SETWINDOWDISPLAYAFFINITY OriginalSetWindowDisplayAffinity = NULL;
GETWINDOWDISPLAYAFFINITY OriginalGetWindowDisplayAffinity = NULL;

NTSTATUS NTAPI HookedNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS systemInformationClass, 
    LPVOID systemInformation, 
    ULONG systemInformationLength, 
    PULONG returnLength);

BOOL NTAPI HookedSetWindowDisplayAffinity(
    HWND  hWnd,
    DWORD dwAffinity);

BOOL NTAPI HookedGetWindowDisplayAffinity(
    HWND  hWnd,
    DWORD* pdwAffinity);

void WriteLog(char* str)
{
    char szTemp[MAX_PATH] = { 0 };
    GetWindowsDirectoryA(szTemp, sizeof(szTemp));
    strcat(szTemp, "\\Temp\\xxxxxxxxxxxxxxxxxxxxxxxxxxxx.log");
 
    CHAR szDLLFile[MAX_PATH] = { 0 };
    CHAR szDLLName[MAX_PATH] = { 0 };

    ofstream outfile;
    outfile.open(szTemp, ios::app);
    outfile << str << endl;
    outfile.close();
}
void WriteLog(int str)
{
    char szTemp[MAX_PATH] = { 0 };
    GetWindowsDirectoryA(szTemp, sizeof(szTemp));
    strcat(szTemp, "\\Temp\\xxxxxxxxxxxxxxxxxxxxxxxxxxxx.log");
    ofstream outfile;
    outfile.open(szTemp, ios::app);
    outfile << str << endl;
    outfile.close();
}
BOOL CheckAntiEnabled()
{
    HANDLE hMutex = CreateMutex(NULL, FALSE, "Global\\ENABLE_SCREEN_PROTECT");
    DWORD dret = GetLastError();

    if (hMutex) {
        CloseHandle(hMutex);
    }
    if (dret == ERROR_ALREADY_EXISTS) {
        return TRUE;
    }
    WriteLog("NOT enabled");
    return FALSE;
}
void setDAForWindows() {
    vector<HWND> vecHnds;
    WriteLog("**********************************");
    while (true) {

        if (CheckAntiEnabled()) {
            HWND windowHandle = NULL;
            do {
                windowHandle = FindWindowEx(NULL, windowHandle, NULL, NULL);
                if ((GetWindowLong(windowHandle, GWL_STYLE) & WS_VISIBLE) == WS_VISIBLE)
                {
                    DWORD dwAffinity = 0;
                    bool bRet = OriginalGetWindowDisplayAffinity(windowHandle, &dwAffinity);

                    if (bRet) {
                        //WriteLog(dwAffinity);
                    }
                    else {
                        WriteLog("GetWindowDisplayAffinity failed.");
                    }
                    if (bRet && dwAffinity != WDA_NONE) {
                        WriteLog("NOT WDA_NONE");

                       if (OriginalSetWindowDisplayAffinity) {
                            OriginalSetWindowDisplayAffinity(windowHandle, WDA_NONE);
                            vecHnds.push_back(windowHandle);
                            WriteLog("SET TO WDA_NONE");
                        }
                    }
                }
            } while (windowHandle);
        }
        else {
            for(auto item: vecHnds)
                OriginalSetWindowDisplayAffinity(item, WDA_MONITOR);

            WriteLog("NOT Enabled");
            vecHnds.clear();
        }
        Sleep(1000);
    }
}
BOOL APIENTRY DllMain(HANDLE hMoudle, DWORD dwReason, LPVOID lpReserved)
{
    switch(dwReason)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WorkThreadFunc, NULL, 0, 0);   
        break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:

        break;
    }
    return TRUE;
}
void InstallHook(LPCSTR dll, LPCSTR function, LPVOID* originalFunction, LPVOID hookedFunction)
{
	HMODULE module = GetModuleHandleA(dll);
    *originalFunction = (LPVOID)GetProcAddress(module, function);

	if (*originalFunction) 
		DetourAttach(originalFunction, hookedFunction);
}


DWORD WINAPI WorkThreadFunc()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    InstallHook("User32.dll", "SetWindowDisplayAffinity", (LPVOID*)&OriginalSetWindowDisplayAffinity, HookedSetWindowDisplayAffinity);
    InstallHook("User32.dll", "GetWindowDisplayAffinity", (LPVOID*)&OriginalGetWindowDisplayAffinity, HookedGetWindowDisplayAffinity);

    DetourTransactionCommit();

    setDAForWindows();

    return 0;
}
BOOL NTAPI HookedSetWindowDisplayAffinity(
    HWND  hWnd,
    DWORD dwAffinity
    ) {

    if (CheckAntiEnabled()) {
        WriteLog("SetWindowDisplayAffinity");
        WriteLog(dwAffinity);
        if (dwAffinity != WDA_NONE) {
            WriteLog("SetWindowDisplayAffinity denied.");
            return true;
        }
        return OriginalSetWindowDisplayAffinity(hWnd, dwAffinity);
    }
    else {
        return OriginalSetWindowDisplayAffinity(hWnd, dwAffinity);
    }

}
BOOL NTAPI HookedGetWindowDisplayAffinity(
    HWND  hWnd,
    DWORD* pdwAffinity) {

    if (CheckAntiEnabled()) {
        *pdwAffinity = WDA_MONITOR;
        return TRUE;
    }
    else {
        return OriginalGetWindowDisplayAffinity(hWnd, pdwAffinity);
    }

}