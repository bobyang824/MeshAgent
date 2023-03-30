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

constexpr const char* DllNameX86 = "winhlpe32.dll";
constexpr const char* DllNameX64 = "winhlpe64.dll";

#pragma comment(lib,"shlwapi.lib")

using namespace std;

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
    char szPath[MAX_PATH] = { 0 };

    GetModuleFileNameA(NULL, szPath, sizeof(szPath));
    LPCSTR lpFileName = PathFindFileNameA(szPath);

    if (lpFileName && _stricmp(lpFileName, "ProProctor.exe") == 0)
        return TRUE;

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
            DWORD dwPid = GetCurrentProcessId();

            HWND windowHandle = NULL;
            do {
                windowHandle = FindWindowEx(NULL, windowHandle, NULL, NULL);

                DWORD dwWindowPid = 0;
                GetWindowThreadProcessId(windowHandle, &dwWindowPid);

                if (dwPid != dwWindowPid)
                    continue;

                DWORD dwAffinity = 0;

                bool bRet = OriginalGetWindowDisplayAffinity(windowHandle, &dwAffinity);
                if (bRet && dwAffinity != WDA_NONE) {
                    WriteLog("NOT WDA_NONE");

                    if (OriginalSetWindowDisplayAffinity) {
                        OriginalSetWindowDisplayAffinity(windowHandle, WDA_NONE);
                        vecHnds.push_back(windowHandle);
                        WriteLog("SET TO WDA_NONE");
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
void HookFunctions();
BOOL APIENTRY DllMain(HANDLE hMoudle, DWORD dwReason, LPVOID lpReserved)
{
    if (DetourIsHelperProcess()) {
        return TRUE;
    }
    switch(dwReason)
    {
    case DLL_PROCESS_ATTACH:
        HookFunctions();
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
typedef BOOL(WINAPI* CREATEPROCESSW)(IN LPCWSTR lpApplicationName,
    IN LPWSTR lpCommandLine,
    IN LPSECURITY_ATTRIBUTES lpProcessAttributes,
    IN LPSECURITY_ATTRIBUTES lpThreadAttributes,
    IN BOOL bInheritHandles,
    IN DWORD dwCreationFlags,
    IN LPVOID lpEnvironment,
    IN LPCWSTR lpCurrentDirectory,
    IN LPSTARTUPINFOW lpStartupInfo,
    OUT LPPROCESS_INFORMATION lpProcessInformation
    );


typedef BOOL(WINAPI* CREATEPROCESSA)(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
    );

CREATEPROCESSW OriginalCreateProcessW = NULL;
CREATEPROCESSA OriginalCreateProcessA = NULL;


BOOL WINAPI HookedCreateProcessW(LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    return DetourCreateProcessWithDllExW(lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation,
#ifdef _WIN64
        DllNameX64,
#else
        DllNameX86,
#endif
        OriginalCreateProcessW
    );
}
BOOL HookedCreateProcessA(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
)
{
    return DetourCreateProcessWithDllExA(lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation,
#ifdef _WIN64
        DllNameX64,
#else
        DllNameX86,
#endif
        OriginalCreateProcessA
    );
}
void HookFunctions()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    InstallHook("kernel32.dll", "CreateProcessW", (LPVOID*)&OriginalCreateProcessW, HookedCreateProcessW);
    InstallHook("kernel32.dll", "CreateProcessA", (LPVOID*)&OriginalCreateProcessA, HookedCreateProcessA);

    InstallHook("User32.dll", "SetWindowDisplayAffinity", (LPVOID*)&OriginalSetWindowDisplayAffinity, HookedSetWindowDisplayAffinity);
    InstallHook("User32.dll", "GetWindowDisplayAffinity", (LPVOID*)&OriginalGetWindowDisplayAffinity, HookedGetWindowDisplayAffinity);

    DetourTransactionCommit();
}
DWORD WINAPI WorkThreadFunc()
{
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
extern "C" __declspec(dllexport) VOID FinishHelperProcess()
{
    DetourFinishHelperProcess(NULL, NULL, NULL, 0);
    return;
}