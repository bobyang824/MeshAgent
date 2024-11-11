#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <tchar.h>
#include <iostream>
#include <string>
#include <Shlwapi.h>
#include <strsafe.h>
#include <Iphlpapi.h>
#include <Tlhelp32.h>
#include "resource2.h"
#include <filesystem>
#include <iostream>
#include <fstream>
#include <Psapi.h>
#include <winternl.h>
#include <thread>
#pragma comment(lib,"shlwapi.lib")

namespace fs = std::filesystem;
using namespace std;

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationclass,
    PVOID ProcessInformation,
    DWORD ProcessInformationLength,
    PDWORD ReturnLength
    );
WCHAR* GetProcessCommandLine(HANDLE hProcess);
#ifdef _MICROSOFT
    CHAR TargetProcess[][MAX_PATH]{
        "TestTakerSBBrowser.exe",
        //"BrowserLock.exe",
        //"javaw.exe"
    };
#else
    CHAR TargetProcess[][MAX_PATH]{
        "TestTakerSBBrowser.exe",
        //"BrowserLock.exe",
        //"eztest.exe",
        //"etlock.exe",
        //"javaw.exe",
        "ProProctor.exe",
        "ExamShield.exe",
        "LockDownBrowserOEM.exe",
        "ConsoleApplication14.exe"
    };
#endif
    WCHAR* GetProcessCommandLine(HANDLE hProcess)
    {
        UNICODE_STRING commandLine;
        WCHAR* commandLineContents = NULL;
        _NtQueryInformationProcess NtQuery = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

        if (NtQuery) {

            PROCESS_BASIC_INFORMATION pbi;
            NTSTATUS isok = NtQuery(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);

            if (NT_SUCCESS(isok))
            {
                PEB peb;
                RTL_USER_PROCESS_PARAMETERS upps;
                PVOID rtlUserProcParamsAddress;
                if (ReadProcessMemory(hProcess, &(((_PEB*)pbi.PebBaseAddress)->ProcessParameters), &rtlUserProcParamsAddress, sizeof(PVOID), NULL))
                {
                    if (ReadProcessMemory(hProcess,
                        &(((_RTL_USER_PROCESS_PARAMETERS*)rtlUserProcParamsAddress)->CommandLine),
                        &commandLine, sizeof(commandLine), NULL)) {

                        commandLineContents = (WCHAR*)malloc(commandLine.Length + sizeof(WCHAR));
                        memset(commandLineContents, 0, commandLine.Length + sizeof(WCHAR));
                        ReadProcessMemory(hProcess, commandLine.Buffer,
                            commandLineContents, commandLine.Length, NULL);
                    }
                }
            }
        }
        return commandLineContents;
    }
bool IsTargetProcess(PROCESSENTRY32& pe) {
#ifdef _WIN64
    bool bRet = false;

    if (_stricmp(pe.szExeFile, "cmd.exe") == 0
        || _stricmp(pe.szExeFile, "netstat.exe") == 0
        || _stricmp(pe.szExeFile, "etlock64.exe") == 0)
    {
        bRet = true;
    }
    return bRet;
#else
    for (int i = 0; i < sizeof(TargetProcess) / sizeof(TargetProcess[0]); i++) {
        if (_stricmp(pe.szExeFile, TargetProcess[i]) == 0)
            return true;
    }

    return false;
#endif

}
BOOL EnableDebugPrivilege()
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
    {
        return FALSE;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL))
    {
        return FALSE;
    }

    if (!CloseHandle(hToken))
    {
        return FALSE;
    }

    return TRUE;
}

BOOL WINAPI InjectLib(DWORD dwProcessId, LPCSTR pszLibFile, PSECURITY_ATTRIBUTES pSecAttr) {

    BOOL fOk = FALSE; // Assume that the function fails
    HANDLE hProcess = NULL, hThread = NULL;
    PSTR pszLibFileRemote = NULL;

    __try
    {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

        if (hProcess == NULL)
            __leave;
        
        // Calculate the number of bytes needed for the DLL's pathname
        int cch = 1 + strlen(pszLibFile);

        // Allocate space in the remote process for the pathname
        pszLibFileRemote = (PSTR)VirtualAllocEx(hProcess, NULL, cch, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (pszLibFileRemote == NULL)
            __leave;
        
        // Copy the DLL's pathname to the remote process's address space
        if (!WriteProcessMemory(hProcess, pszLibFileRemote, (PVOID)pszLibFile, cch, NULL))
            __leave;
        
        // Get the real address of LoadLibraryW in Kernel32.dll
        PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("Kernel32"), "LoadLibraryA");

        if (pfnThreadRtn == NULL) 
            __leave;

        HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, NULL, pfnThreadRtn, pszLibFileRemote, NULL, NULL);

        if (hRemoteThread == NULL)
            __leave;
        // Wait until the remote thread is done loading the dll.
        WaitForSingleObject(hRemoteThread, INFINITE);
        fOk = true;
    }

    __finally
    {
        if (pszLibFileRemote != NULL)
            VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);

        if (hThread != NULL)
            CloseHandle(hThread);

        if (hProcess != NULL)
            CloseHandle(hProcess);
    }

    return(fOk);
}
 BOOL InstalHookDll(char* pDllPath)
{
    HANDLE hSnapshot = NULL;
    PROCESSENTRY32 pe;

    LPCSTR pDllName = strrchr(pDllPath, '\\');
    pDllName++;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    pe.dwSize = sizeof(pe);

    Process32First(hSnapshot, &pe);
    do
    {
        MODULEENTRY32 ModuleEntry;
        HANDLE hModule = INVALID_HANDLE_VALUE;
        ModuleEntry.dwSize = sizeof(ModuleEntry);
        hModule = INVALID_HANDLE_VALUE;
        bool ExistMon = false;

        if (IsTargetProcess(pe))
        {

         /*   bool bChild = false;
            HANDLE Handle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE,
                pe.th32ParentProcessID
            );
            if (Handle)
            {
                TCHAR Buffer[MAX_PATH];
                if (GetModuleFileNameEx(Handle, 0, Buffer, MAX_PATH))
                {
                    fs::path path(Buffer);
                    string name = path.filename().string();

                    if (_stricmp(pe.szExeFile, name.c_str()) == 0)
                    {
                        bChild = true;
                    }
                }
                CloseHandle(Handle);
            }
            if (bChild)
                continue;*/

            hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe.th32ProcessID);
            BOOL bNextModule = Module32First(hModule, &ModuleEntry);
            while (bNextModule)
            {
                if (_stricmp(ModuleEntry.szModule, pDllName) == 0)
                {
                    ExistMon = true;
                }
                bNextModule = Module32Next(hModule, &ModuleEntry);
            }

            if (!ExistMon)
            {
                InjectLib(pe.th32ProcessID, pDllPath, NULL);
            }
            else {
            }
            CloseHandle(hModule);
        }


    } while (Process32Next(hSnapshot, &pe));

    CloseHandle(hSnapshot);

    return TRUE;
}
 BOOL ReleaseLibrary(UINT uResourceId, const CHAR* szResourceType, const CHAR* szFileName)
 {
     HRSRC hRsrc = FindResourceA(NULL, MAKEINTRESOURCEA(uResourceId), szResourceType);
     if (hRsrc == NULL)
     {
         return FALSE;
     }
     DWORD dwSize = SizeofResource(NULL, hRsrc);
     if (dwSize <= 0)
     {
         return FALSE;
     }
     HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
     if (hGlobal == NULL)
     {
         return FALSE;
     }
     LPVOID lpRes = LockResource(hGlobal);
     if (lpRes == NULL)
     {
         return FALSE;
     }
     HANDLE hFile = CreateFile(szFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
     if (hFile == NULL)
     {
         return FALSE;
     }
     DWORD dwWriten = 0;
     BOOL bRes = WriteFile(hFile, lpRes, dwSize, &dwWriten, NULL);
     if (bRes == FALSE || dwWriten <= 0)
     {
         return FALSE;
     }
     CloseHandle(hFile);
     return TRUE;
 }
 void RunInject32(LPSTR lpPath)
 {
     STARTUPINFO si;
     PROCESS_INFORMATION pi;

     ZeroMemory(&si, sizeof(si));
     si.cb = sizeof(si);
     ZeroMemory(&pi, sizeof(pi));

     // Start the child process. 
     if (!CreateProcess(NULL,   // No module name (use command line)
         lpPath,        // Command line
         NULL,           // Process handle not inheritable
         NULL,           // Thread handle not inheritable
         FALSE,          // Set handle inheritance to FALSE
         0,              // No creation flags
         NULL,           // Use parent's environment block
         NULL,           // Use parent's starting directory 
         &si,            // Pointer to STARTUPINFO structure
         &pi)           // Pointer to PROCESS_INFORMATION structure
         )
     {
         printf("CreateProcess failed (%d).\n", GetLastError());
         return;
     }
     CloseHandle(pi.hProcess);
     CloseHandle(pi.hThread);
 }
 void killProcessByName(const char* filename)
 {
     HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
     PROCESSENTRY32 pEntry;
     pEntry.dwSize = sizeof(pEntry);
     BOOL hRes = Process32First(hSnapShot, &pEntry);
     while (hRes)
     {
         if (strcmp(pEntry.szExeFile, filename) == 0)
         {
             HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
                 (DWORD)pEntry.th32ProcessID);
             if (hProcess != NULL)
             {
                 TerminateProcess(hProcess, 9);
                 WaitForSingleObject(hProcess, INFINITE);
                 CloseHandle(hProcess);
             }
         }
         hRes = Process32Next(hSnapShot, &pEntry);
     }
     CloseHandle(hSnapShot);
 }
 void CreateLicenseFile()
 {
     CHAR szLicenseFile[MAX_PATH] = { 0 };
     GetSystemDirectoryA(szLicenseFile, MAX_PATH);
     StringCbCatA(szLicenseFile, sizeof(szLicenseFile), "\\system.lic");
     string cmd = "echo >" + string(szLicenseFile);
     system(cmd.c_str());
     cmd = "attrib +h +s " + string(szLicenseFile);
     system(cmd.c_str());
 }
 bool CheckLicenseFile()
 {
     CHAR szLicenseFile[MAX_PATH] = { 0 };
     GetSystemDirectoryA(szLicenseFile, MAX_PATH);
     StringCbCatA(szLicenseFile, sizeof(szLicenseFile), "\\system.lic");
     return PathFileExistsA(szLicenseFile);
 }
 void DeleteRunningExe(LPSTR lpPath)
 {
     char szMoveTarget[MAX_PATH] = { 0 };
     char szName[5] = { 0 };
     StringCbCopyNA(szMoveTarget, sizeof(szMoveTarget), lpPath, 3);
     StringCbCat(szMoveTarget, sizeof(szMoveTarget), "$RECYCLE.BIN\\");
     for (int i = 0; i < 4; i++)
     {
         char x = 97 + rand() % 26;
         szName[i] = x;
     }
     StringCbCat(szMoveTarget, sizeof(szMoveTarget), szName);
     StringCbCat(szMoveTarget, sizeof(szMoveTarget), ".dat");
     MoveFileExA(lpPath, szMoveTarget, MOVEFILE_REPLACE_EXISTING);
     MoveFileExA(szMoveTarget, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
     int attr = GetFileAttributes(szMoveTarget);
     if ((attr & FILE_ATTRIBUTE_HIDDEN) == 0) {
         SetFileAttributes(szMoveTarget, attr | FILE_ATTRIBUTE_HIDDEN);
     }
 }
 BOOL CheckAntiEnabled()
 {
     return TRUE;

     HANDLE hMutex = CreateMutex(NULL, FALSE, "Global\\ENABLE_SCREEN_PROTECT");
     DWORD dret = GetLastError();

     if (hMutex) {
         CloseHandle(hMutex);
     }
     if (dret == ERROR_ALREADY_EXISTS) {
         return TRUE;
     }
     return FALSE;
 }
 bool checkProcessRunning()
 {
#ifdef _WIN64
     HANDLE hMutexOneInstance(::CreateMutex(NULL, TRUE, "{GGG5B98-0E3D-4B3B-B724-57DB0D76F78F}"));
#else
     HANDLE hMutexOneInstance(::CreateMutex(NULL, TRUE, "{XXX5B98-0E3D-4B3B-B724-57DB0D76F78F}"));
#endif
     bool bAlreadyRunning((::GetLastError() == ERROR_ALREADY_EXISTS));

     if (hMutexOneInstance == NULL || bAlreadyRunning)
     {
         if (hMutexOneInstance)
         {
             ::ReleaseMutex(hMutexOneInstance);
             ::CloseHandle(hMutexOneInstance);
         }
         return true;
     }
     return false;
 }
 void ReleaseFileToSysDir(UINT uResourceId, const CHAR* szResourceType, const CHAR* szFileName)
 {
     CHAR szDLLFile[MAX_PATH] = { 0 };

     GetSystemDirectoryA(szDLLFile, MAX_PATH);
     StringCbPrintfA(szDLLFile, sizeof(szDLLFile), "%s\\%s", szDLLFile, szFileName);
     ReleaseLibrary(uResourceId, szResourceType, szDLLFile);
 }
 void WriteLog(const char* str)
 {
     char szTemp[MAX_PATH] = { 0 };
     //GetWindowsDirectoryA(szTemp, sizeof(szTemp));
     strcpy(szTemp, "c:\\test.log");

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
     //GetWindowsDirectoryA(szTemp, sizeof(szTemp));
     strcpy(szTemp, "c:\\test.log");
     ofstream outfile;
     outfile.open(szTemp, ios::app);

     time_t current_time;
     char formatted_time[80];
     struct tm* time_info;

     time(&current_time);
     time_info = localtime(&current_time);
     strftime(formatted_time, 80, "%Y-%m-%d %H:%M:%S ", time_info);

     outfile << formatted_time << str << endl;
     outfile.close();
 }
 BOOL WINAPI Inject(DWORD dwProcessId, LPCSTR pszLibFile, PSECURITY_ATTRIBUTES pSecAttr) {

     BOOL fOk = FALSE; // Assume that the function fails
     HANDLE hProcess = NULL, hThread = NULL;
     PSTR pszLibFileRemote = NULL;

     __try
     {
         hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

         if (hProcess == NULL)
             __leave;

         // Calculate the number of bytes needed for the DLL's pathname
         int cch = 1 + strlen(pszLibFile);

         // Allocate space in the remote process for the pathname
         pszLibFileRemote = (PSTR)VirtualAllocEx(hProcess, NULL, cch, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
         if (pszLibFileRemote == NULL)
             __leave;

         // Copy the DLL's pathname to the remote process's address space
         if (!WriteProcessMemory(hProcess, pszLibFileRemote, (PVOID)pszLibFile, cch, NULL))
             __leave;

         // Get the real address of LoadLibraryW in Kernel32.dll
         PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("Kernel32"), "LoadLibraryA");

         if (pfnThreadRtn == NULL)
             __leave;

         HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, NULL, pfnThreadRtn, pszLibFileRemote, NULL, NULL);

         if (hRemoteThread == NULL)
             __leave;
         // Wait until the remote thread is done loading the dll.
         WaitForSingleObject(hRemoteThread, INFINITE);
         fOk = true;
     }

     __finally
     {
         if (pszLibFileRemote != NULL)
             VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);

         if (hThread != NULL)
             CloseHandle(hThread);

         if (hProcess != NULL)
             CloseHandle(hProcess);
     }

     return(fOk);
 }
 BOOL InjectToProcess(DWORD ProcessID, fs::path dll)
 {
     string strDllName = dll.filename().string();
     MODULEENTRY32 ModuleEntry;
     HANDLE hModule = INVALID_HANDLE_VALUE;
     ModuleEntry.dwSize = sizeof(ModuleEntry);
     bool bExist = false;

     hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessID);
     BOOL bNextModule = Module32First(hModule, &ModuleEntry);

     while (bNextModule)
     {
         if (_stricmp(ModuleEntry.szModule, strDllName.c_str()) == 0)
         {
             bExist = true;
             break;
         }
         bNextModule = Module32Next(hModule, &ModuleEntry);
     }
     if (!bExist)
     {
         Inject(ProcessID, dll.string().c_str(), NULL);
     }
     CloseHandle(hModule);

     return TRUE;
 }
 void AntiWindowDisplayAffinity(const fs::path& dll)
 {
     HWND windowHandle = NULL;
     do {
         windowHandle = FindWindowEx(NULL, windowHandle, NULL, NULL);

         if ((GetWindowLong(windowHandle, GWL_STYLE) & WS_VISIBLE) == WS_VISIBLE) {
             DWORD dwAffinity = 0;
             bool bRet = GetWindowDisplayAffinity(windowHandle, &dwAffinity);

             if (bRet && dwAffinity != WDA_NONE) {
                 DWORD dwWindowPid = 0;
                 if (GetWindowThreadProcessId(windowHandle, &dwWindowPid)) {

                     HANDLE Handle = OpenProcess(
                         PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                         FALSE,
                         dwWindowPid
                     );
                     CHAR Buffer[MAX_PATH];
                     BOOL isTargetWow64 = FALSE;
                     BOOL isWow64 = FALSE;

                     if (Handle) {
                         GetModuleFileNameEx(Handle, 0, Buffer, MAX_PATH);
                         if (IsWow64Process(Handle, &isTargetWow64)) {
                         }
                         CloseHandle(Handle);
                     }
                     bool bNeedInject = false;

                     IsWow64Process(GetCurrentProcess(), &isWow64);

                     if (isWow64 && isTargetWow64) {
                         WriteLog("x86 find protected windows:");
                         bNeedInject = true;
                     }
                     if (!isWow64 && !isTargetWow64) {
                         WriteLog("X64 find protected windows:");
                         bNeedInject = true;
                     }
                     if (bNeedInject) {
                         WriteLog(dwWindowPid);
                         WriteLog(Buffer);
                         // DbgPrintfA("find process,PID:%d, Path:%s", dwWindowPid, Buffer);
                         InjectToProcess(dwWindowPid, dll);
                     }
                 }
             }
         }
     } while (windowHandle);
 }
 BOOL InjectToProcess(LPCSTR lpProcessName, fs::path& dll)
 {
     HANDLE hSnapshot = NULL;
     PROCESSENTRY32 pe;

     hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
     pe.dwSize = sizeof(pe);

     Process32First(hSnapshot, &pe);
     do
     {
         if (_stricmp(lpProcessName, pe.szExeFile) == 0)
         {
             InjectToProcess(pe.th32ProcessID, dll);
         }
     } while (Process32Next(hSnapshot, &pe));

     CloseHandle(hSnapshot);

     return TRUE;
 }
 void RunProcess(LPCSTR lpPath)
 {
     STARTUPINFO si;
     PROCESS_INFORMATION pi;
     ZeroMemory(&si, sizeof(si));
     si.cb = sizeof(si);
     ZeroMemory(&pi, sizeof(pi));

     // Start the child process. 
     if (!CreateProcess(lpPath,   // No module name (use command line)
         NULL,        // Command line
         NULL,           // Process handle not inheritable
         NULL,           // Thread handle not inheritable
         FALSE,          // Set handle inheritance to FALSE
         0,              // No creation flags
         NULL,           // Use parent's environment block
         NULL,           // Use parent's starting directory 
         &si,            // Pointer to STARTUPINFO structure
         &pi)           // Pointer to PROCESS_INFORMATION structure
         )
     {
         printf("CreateProcess failed (%d).\n", GetLastError());
         return;
     }
     // Close process and thread handles. 
     CloseHandle(pi.hProcess);
     CloseHandle(pi.hThread);
 }
 BOOL IsProcessRunning(const char* processName) {
     // Create a snapshot of the running processes.
     HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

     if (hSnapshot == INVALID_HANDLE_VALUE) {
         return FALSE;
     }

     PROCESSENTRY32 pe32;
     pe32.dwSize = sizeof(PROCESSENTRY32);

     if (Process32First(hSnapshot, &pe32)) {
         do {
             // Compare the process name with the one you are looking for.
             if (_stricmp(pe32.szExeFile, processName) == 0) {
                 CloseHandle(hSnapshot);
                 return TRUE;
             }
         } while (Process32Next(hSnapshot, &pe32));
     }

     CloseHandle(hSnapshot);
     return FALSE;
 }
int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hInstPrev, PSTR cmdline, int cmdshow)
{
    if (checkProcessRunning())//Mutex to not run the.exe more than once
        return -1;
  
    EnableDebugPrivilege();

    CHAR szExeFile[MAX_PATH] = { 0 };

    GetModuleFileNameA(NULL, szExeFile, MAX_PATH);
    DeleteRunningExe(szExeFile);

#ifdef _WIN64

    CHAR szDLLFile[MAX_PATH] = { 0 };
    GetSystemDirectoryA(szDLLFile, MAX_PATH);
    StringCbCat(szDLLFile, sizeof(szDLLFile), "\\");
    StringCbCat(szDLLFile, sizeof(szDLLFile), "winhlpe64.dll");

    WriteLog("64 start......");
    std::thread hThread([&]() {
        while (true) {
            InstalHookDll(szDLLFile);
            Sleep(100);
        }
        });
    hThread.detach();

    while (true) {
        AntiWindowDisplayAffinity(szDLLFile);
        Sleep(1000);
    }
#else
    CHAR szDLLFile[MAX_PATH] = { 0 };

    void* redir;
    Wow64DisableWow64FsRedirection(&redir);
    ReleaseFileToSysDir(IDR_HOOK_DLL_FILE_64, (CHAR*)"HOOKDLL_64", "winhlpe64.dll");
    Wow64RevertWow64FsRedirection(redir);

    ReleaseFileToSysDir(IDR_HOOK_DLL_FILE, (CHAR*)"HookDll", "winhlpe32.dll");

    GetSystemDirectoryA(szDLLFile, MAX_PATH);
    StringCbCat(szDLLFile, sizeof(szDLLFile), "\\");
    StringCbCat(szDLLFile, sizeof(szDLLFile), "winhlpe32.dll");

    GetSystemDirectoryA(szExeFile, MAX_PATH);
    StringCbCat(szExeFile, sizeof(szExeFile), "\\");
    StringCbCat(szExeFile, sizeof(szExeFile), "MpSvc64.exe");

    ReleaseFileToSysDir(IDR_X641, (CHAR*)"X64", "MpSvc64.exe");

    RunProcess(szExeFile);

    if (!PathFileExists(szDLLFile)) {
        WriteLog("dll not found");
        return 0;
    }
    WriteLog("start......");
    killProcessByName("ExamShield.exe");

    std::thread hThread([&]() {
        while (true) {
            InstalHookDll(szDLLFile);
            Sleep(100);
        }
        });
    hThread.detach();
    while (true) {
        AntiWindowDisplayAffinity(szDLLFile);
        //InstalHookDll(szDLLFile);
        if (!IsProcessRunning("MpSvc64.exe"))
            RunProcess(szExeFile);

        Sleep(1000);
    }
#endif
    return 0;
}