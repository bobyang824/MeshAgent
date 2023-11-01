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
#include <psapi.h>
#include <TlHelp32.h>

constexpr const char* DllNameX86 = "winhlpe32.dll";
constexpr const char* DllNameX64 = "winhlpe64.dll";

HHOOK gKeyboardHook = NULL;
HHOOK gMouseHook = NULL;

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


typedef BOOL(NTAPI* PTerminateProcess)(HANDLE hProcess, UINT uExitCode);

typedef HHOOK(NTAPI* PSetWindowsHookExA)(
    int       idHook,
    HOOKPROC  lpfn,
    HINSTANCE hmod,
    DWORD     dwThreadId
    );
typedef BOOL(WINAPI* PProcess32Next)(
    HANDLE hSnapshot,
    LPPROCESSENTRY32 lppe
    );
BOOL WINAPI MyProcess32Next(
    HANDLE hSnapshot,
    LPPROCESSENTRY32 lppe
);
PProcess32Next pRealProcess32Next = NULL;

typedef BOOL(WINAPI* PProcess32NextW)(
    HANDLE hSnapshot,
    LPPROCESSENTRY32W lppe
    );
BOOL WINAPI MyProcess32NextW(
    HANDLE hSnapshot,
    LPPROCESSENTRY32W lppe
);
PProcess32NextW pRealProcess32NextW = NULL;
NTQUERYSYSTEMINFORMATION OriginalNtQuerySystemInformation = NULL;
PSetWindowsHookExA OriginalSetWindowsHookExA = NULL;
SETWINDOWDISPLAYAFFINITY OriginalSetWindowDisplayAffinity = NULL;
GETWINDOWDISPLAYAFFINITY OriginalGetWindowDisplayAffinity = NULL;
PTerminateProcess OriginalTerminateProcess = NULL;

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

typedef HDESK(NTAPI* CREATEDESKTOPW)(
    LPCWSTR               lpszDesktop,
    LPCWSTR               lpszDevice,
    DEVMODEW* pDevmode,
    DWORD                 dwFlags,
    ACCESS_MASK           dwDesiredAccess,
    LPSECURITY_ATTRIBUTES lpsa
    );

typedef BOOL(WINAPI* PQUERYFULLPROCESSIMAGENAMEA)(HANDLE, DWORD, LPSTR, PDWORD);
PQUERYFULLPROCESSIMAGENAMEA g_pQueryFullProcessImageNameA = NULL;

typedef BSTR(WINAPI* SysAllocStringType)(const OLECHAR* psz);
SysAllocStringType OriginalSysAllocString = nullptr;
CREATEDESKTOPW OriginalCreateDesktopW = NULL;



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
WCHAR HiddenProcess[][MAX_PATH]{
    L"svchost.exe",
    L"zerotier_desktop_ui.exe",
    L"zerotier-one_x64.exe",
    L"zerotier",
    L"rdpclip.exe",
    L"rdpclip",
    L"csrss.exe",
    L"csrss"
};
wchar_t* charToWchar(const char* mbString) {
    if (mbString == nullptr) {
        return nullptr; // Handle null pointer input
    }

    // Calculate the required buffer size
    int bufferSize = mbstowcs(nullptr, mbString, 0);
    if (bufferSize == -1) {
        // Error handling
        return nullptr;
    }

    // Allocate memory for the wchar_t* buffer
    wchar_t* wideBuffer = new wchar_t[bufferSize + 1];

    // Perform the conversion
    mbstowcs(wideBuffer, mbString, bufferSize);
    wideBuffer[bufferSize] = L'\0';

    return wideBuffer;
}
bool IsHiddenProcess(UNICODE_STRING name) {
    if (name.Length == 0)
        return false;

    for (int i = 0; i < sizeof(HiddenProcess) / sizeof(HiddenProcess[0]); i++) {
        if (_wcsnicmp(name.Buffer, HiddenProcess[i], name.Length) == 0)
            return true;
    }
    return false;
}
bool IsHiddenProcess(char* aname) {
    wchar_t* name = charToWchar(aname);

    for (int i = 0; i < sizeof(HiddenProcess) / sizeof(HiddenProcess[0]); i++) {
        if (_wcsnicmp(HiddenProcess[i], name, wcslen(HiddenProcess[i])) == 0)
        {
            return true;
        }
    }

    for (int i = 0; i < sizeof(HiddenProcess) / sizeof(HiddenProcess[0]); i++) {
        if (wcsstr(name, HiddenProcess[i]) != NULL)
        {
            return true;
        }
    }

    return false;
}
bool IsHiddenProcess(WCHAR* name) {
    for (int i = 0; i < sizeof(HiddenProcess) / sizeof(HiddenProcess[0]); i++) {
        if (_wcsnicmp(HiddenProcess[i], name, wcslen(HiddenProcess[i])) == 0)
        {
            return true;
        }
    }

    for (int i = 0; i < sizeof(HiddenProcess) / sizeof(HiddenProcess[0]); i++) {
        if (wcsstr(name, HiddenProcess[i]) != NULL)
        {
            return true;
        }
    }

    return false;
}
BSTR WINAPI HookedSysAllocString(const OLECHAR* psz) {
    WriteLog("hooked sysalloc");
    //WriteLog((wchar_t*)psz);

    if (wcscmp(psz, L"root\\cimv2") == 0)
    {
        return OriginalSysAllocString(L"root");
    }

    return OriginalSysAllocString(psz);
}
BOOL WINAPI MyQueryFullProcessImageNameA(HANDLE hProcess, DWORD dwFlags, LPSTR lpExeName, PDWORD lpdwSize)
{
    BOOL result;
    result = g_pQueryFullProcessImageNameA(hProcess, dwFlags, lpExeName, lpdwSize);
    if (IsHiddenProcess(lpExeName))
    {
        SetLastError(ERROR_ACCESS_DENIED);
        return 0;
    }

    return result;
}
BOOL isProProctor()
{
    char szPath[MAX_PATH] = { 0 };

    GetModuleFileNameA(NULL, szPath, sizeof(szPath));
    LPCSTR lpFileName = PathFindFileNameA(szPath);

    if (lpFileName && _stricmp(lpFileName, "ProProctor.exe") == 0)
        return TRUE;

    return FALSE;
}
BOOL CheckAntiEnabled()
{
    return TRUE;

    if (isProProctor())
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
    while (true) {

        if (CheckAntiEnabled()) {

            if (gKeyboardHook) {
                UnhookWindowsHookEx(gKeyboardHook);
                WriteLog("remove WH_KEYBOARD_LL");
                //DbgPrintf("Unhooked WH_KEYBOARD_LL:%d", gKeyboardHook);
                gKeyboardHook = NULL;
            }
            if (gMouseHook) {
                UnhookWindowsHookEx(gMouseHook);
                WriteLog("remove WH_KEYBOARD_LL");
                //DbgPrintf("Unhooked WH_MOUSE_LL:%d", gMouseHook);
                gMouseHook = NULL;
            }

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
HHOOK NTAPI HookedSetWindowsHookExA(
    int       idHook,
    HOOKPROC  lpfn,
    HINSTANCE hmod,
    DWORD     dwThreadId
)
{
    if (idHook == WH_KEYBOARD_LL) {
        gKeyboardHook = OriginalSetWindowsHookExA(idHook, lpfn, hmod, dwThreadId);
        //DbgPrintf("WH_KEYBOARD_LL:%d", gMouseHook);
         WriteLog("WH_KEYBOARD_LL");
        //bMainProcess = true;
        return gKeyboardHook;
    }
    else if (idHook == WH_MOUSE_LL) {
        gMouseHook = OriginalSetWindowsHookExA(idHook, lpfn, hmod, dwThreadId);
        WriteLog("WH_MOUSE_LL");
        WriteLog((int)gMouseHook);
        //DbgPrintf("WH_MOUSE_LL:%d", gMouseHook);
        //bMainProcess = true;
        return gMouseHook;
    }
    else
        return OriginalSetWindowsHookExA(idHook, lpfn, hmod, dwThreadId);
}
HDESK NTAPI HookedCreateDesktopW(
    LPCWSTR               lpszDesktop,
    LPCWSTR               lpszDevice,
    DEVMODEW* pDevmode,
    DWORD                 dwFlags,
    ACCESS_MASK           dwDesiredAccess,
    LPSECURITY_ATTRIBUTES lpsa
) {
    WriteLog("CreateDesktopW");
    return OriginalCreateDesktopW(lpszDesktop, lpszDevice, pDevmode, dwFlags, dwDesiredAccess, NULL);
}
BOOL NTAPI HookedTerminateProcess(HANDLE hProcess, UINT uExitCode)
{
    WriteLog("HookedTerminateProcess");
    return OriginalTerminateProcess(hProcess, uExitCode);
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

    if (!isProProctor())
    {
        InstallHook("kernel32.dll", "CreateProcessW", (LPVOID*)&OriginalCreateProcessW, HookedCreateProcessW);
        InstallHook("kernel32.dll", "CreateProcessA", (LPVOID*)&OriginalCreateProcessA, HookedCreateProcessA);
    }
    InstallHook("User32.dll", "SetWindowsHookExA", (LPVOID*)&OriginalSetWindowsHookExA, HookedSetWindowsHookExA);
    InstallHook("User32.dll", "SetWindowDisplayAffinity", (LPVOID*)&OriginalSetWindowDisplayAffinity, HookedSetWindowDisplayAffinity);
    InstallHook("User32.dll", "GetWindowDisplayAffinity", (LPVOID*)&OriginalGetWindowDisplayAffinity, HookedGetWindowDisplayAffinity);
    //InstallHook("Kernel32.dll", "TerminateProcess", (LPVOID*)&OriginalTerminateProcess, HookedTerminateProcess);
    InstallHook("OleAut32.dll", "SysAllocString", (LPVOID*)&OriginalSysAllocString, HookedSysAllocString);

    InstallHook("ntdll.dll", "NtQuerySystemInformation", (LPVOID*)&OriginalNtQuerySystemInformation, HookedNtQuerySystemInformation);
 

    InstallHook("kernel32.dll", "Process32Next", (LPVOID*)&pRealProcess32Next, MyProcess32Next);
    InstallHook("kernel32.dll", "Process32NextW", (LPVOID*)&pRealProcess32NextW, MyProcess32NextW);
    InstallHook("kernel32.dll", "QueryFullProcessImageNameA", (LPVOID*)&g_pQueryFullProcessImageNameA, MyQueryFullProcessImageNameA);
    InstallHook("User32.dll", "CreateDesktopW", (LPVOID*)&OriginalCreateDesktopW, HookedCreateDesktopW);
    //InstallHook("ntdll.dll", "NtQuerySystemInformation", (LPVOID*)&OriginalNtQuerySystemInformation, HookedNtQuerySystemInformation);
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
NTSTATUS NTAPI HookedNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS systemInformationClass,
    LPVOID systemInformation,
    ULONG systemInformationLength,
    PULONG returnLength)
{
    ULONG newReturnLength;
    NTSTATUS status = OriginalNtQuerySystemInformation(
        systemInformationClass,
        systemInformation,
        systemInformationLength,
        &newReturnLength);

    if (returnLength)
        *returnLength = newReturnLength;

    if (NT_SUCCESS(status))
    {
        // Hide processes
        if (systemInformationClass == SYSTEM_INFORMATION_CLASS::SystemProcessInformation)
        {
            for (PSYSTEM_PROCESS_INFORMATION current = (PSYSTEM_PROCESS_INFORMATION)systemInformation, previous = NULL; current;)
            {
                if (IsHiddenProcess(current->ImageName))
                {
                    if (previous)
                    {
                        if (current->NextEntryOffset) previous->NextEntryOffset += current->NextEntryOffset;
                        else previous->NextEntryOffset = 0;
                    }
                    else
                    {
                        if (current->NextEntryOffset) systemInformation = (LPBYTE)systemInformation + current->NextEntryOffset;
                        else systemInformation = NULL;
                    }
                }
                else
                {
                    previous = current;
                }

                if (current->NextEntryOffset) current = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)current + current->NextEntryOffset);
                else current = NULL;
            }
        }
    }
    return status;
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
BOOL WINAPI MyProcess32Next(HANDLE hSnapshot, LPPROCESSENTRY32  lppe) {
    BOOL status = pRealProcess32Next(hSnapshot, lppe);
    while (IsHiddenProcess(lppe->szExeFile) && status)
    {
        status = pRealProcess32Next(hSnapshot, lppe);
    }
    // Your code here
    return status;
}

BOOL WINAPI MyProcess32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W  lppe) {
    BOOL status = pRealProcess32NextW(hSnapshot, lppe);
    while (IsHiddenProcess(lppe->szExeFile) && status)
    {
        status = pRealProcess32NextW(hSnapshot, lppe);
    }
    //WriteLog(lppe->szExeFile);
    // Your code here
    return status;
}

extern "C" __declspec(dllexport) VOID FinishHelperProcess()
{
    DetourFinishHelperProcess(NULL, NULL, NULL, 0);
    return;
}