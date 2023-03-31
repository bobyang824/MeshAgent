﻿#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <tchar.h>
#include <iostream>
#include <string>
#include <Shlwapi.h>
#include <strsafe.h>
#include <Iphlpapi.h>
#include <Tlhelp32.h>
#include "resource2.h"

#pragma comment(lib,"shlwapi.lib")

using namespace std;

#ifdef _MICROSOFT
    CHAR TargetProcess[][MAX_PATH]{
        "TestTakerSBBrowser.exe"
    };
#else
    CHAR TargetProcess[][MAX_PATH]{
        "TestTakerSBBrowser.exe",
        "BrowserLock.exe",
        "eztest.exe",
        "javaw.exe",
        "ProProctor.exe",
        "ExamShield.exe"
    };
#endif

bool IsTargetProcess(CHAR* pszName) {
    for (int i = 0; i < sizeof(TargetProcess) / sizeof(TargetProcess[0]); i++) {
        if (_stricmp(pszName, TargetProcess[i]) == 0)
            return true;
    }

    return false;
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

        if (IsTargetProcess(pe.szExeFile))
        {
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
     // Close process and thread handles. 
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
     HANDLE hMutexOneInstance(::CreateMutex(NULL, TRUE, "{GGG5B98-0E3D-4B3B-B724-57DB0D76F78F}"));
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
int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hInstPrev, PSTR cmdline, int cmdshow)
{
    if (checkProcessRunning())//Mutex to not run the.exe more than once
        return -1;

    ///****************license check*************/
    //if (CheckLicenseFile()) {
    //    return 0;
    //}
    //SYSTEMTIME st;
    //GetLocalTime(&st);
    //if (st.wMonth > 3) {
    //    CreateLicenseFile();
    //    return 0;
    //}
    ///****************license check*************/
  
    if (!CheckAntiEnabled())
    {
        OutputDebugStringA("NOT Enabled");
        return 0;
    }
    EnableDebugPrivilege();
    CHAR szDLLFile[MAX_PATH] = { 0 };
    CHAR szExeFile[MAX_PATH] = { 0 };

    GetModuleFileNameA(NULL, szExeFile, MAX_PATH);
    DeleteRunningExe(szExeFile);
    
    void* redir;
    Wow64DisableWow64FsRedirection(&redir);
    ReleaseFileToSysDir(IDR_HOOK_DLL_FILE_64, (CHAR*)"HOOKDLL_64", "winhlpe64.dll");
    Wow64RevertWow64FsRedirection(redir);

    ReleaseFileToSysDir(IDR_HOOK_DLL_FILE, (CHAR*)"HookDll", "winhlpe32.dll");

    GetSystemDirectoryA(szDLLFile, MAX_PATH);
    StringCbCat(szDLLFile, sizeof(szDLLFile), "\\");
    StringCbCat(szDLLFile, sizeof(szDLLFile), "winhlpe32.dll");
    
    if (!PathFileExists(szDLLFile)) {
        return 0;
    }
    while (true) {
        InstalHookDll(szDLLFile);
        Sleep(5000);
    }
    return 0;
}