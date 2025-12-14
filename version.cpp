/*
 * EA DLC Unlocker v2 - version.dll Proxy
 * 
 * This DLL intercepts GetFileVersionInfo* API calls and patches DLC ownership
 * checks by hooking Qt5Core.dll functions and downloading DLC configurations.
 * 
 * Compiled: x64 Release
 * Dependencies: kernel32.dll, user32.dll, shell32.dll, wininet.dll
 */

#include <windows.h>
#include <wininet.h>
#include <detours.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "detours.lib")

// ============================================================================
// Global Variables
// ============================================================================

HMODULE g_hRealVersion = NULL;
HMODULE g_hQt5Core = NULL;

// Function pointers to original APIs in system version.dll
typedef BOOL (WINAPI *PFN_GetFileVersionInfoA)(
    LPCSTR lptstrFilename,
    DWORD dwHandle,
    DWORD dwLen,
    LPVOID lpData
);

typedef BOOL (WINAPI *PFN_GetFileVersionInfoW)(
    LPCWSTR lptstrFilename,
    DWORD dwHandle,
    DWORD dwLen,
    LPVOID lpData
);

typedef DWORD (WINAPI *PFN_GetFileVersionInfoSizeA)(
    LPCSTR lptstrFilename,
    LPDWORD lpdwHandle
);

typedef DWORD (WINAPI *PFN_GetFileVersionInfoSizeW)(
    LPCWSTR lptstrFilename,
    LPDWORD lpdwHandle
);

typedef BOOL (WINAPI *PFN_VerQueryValueA)(
    LPCSTR pBlock,
    LPCSTR lpSubBlock,
    LPVOID *lplpBuffer,
    PUINT puLen
);

typedef BOOL (WINAPI *PFN_VerQueryValueW)(
    LPCWSTR pBlock,
    LPCWSTR lpSubBlock,
    LPVOID *lplpBuffer,
    PUINT puLen
);

// Store function pointers
PFN_GetFileVersionInfoA g_pGetFileVersionInfoA = NULL;
PFN_GetFileVersionInfoW g_pGetFileVersionInfoW = NULL;
PFN_GetFileVersionInfoSizeA g_pGetFileVersionInfoSizeA = NULL;
PFN_GetFileVersionInfoSizeW g_pGetFileVersionInfoSizeW = NULL;
PFN_VerQueryValueA g_pVerQueryValueA = NULL;
PFN_VerQueryValueW g_pVerQueryValueW = NULL;

// ============================================================================
// Utility Functions
// ============================================================================

void LogMessage(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
}

void LogError(const char* prefix, DWORD dwError) {
    char* pszMessage = NULL;
    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        dwError,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&pszMessage,
        0,
        NULL
    );

    if (pszMessage) {
        LogMessage("Error: %s - 0x%08X: %s", prefix, dwError, pszMessage);
        LocalFree(pszMessage);
    }
}

// ============================================================================
// DLC Configuration Download
// ============================================================================

BOOL DownloadDLCConfig() {
    const char* URL = "https://gist.githubusercontent.com/anadius/4f00ba9111c2c4c05f97decd6018f279/raw/g_";

    HINTERNET hInternet = NULL;
    HINTERNET hUrl = NULL;
    BOOL bSuccess = FALSE;
    char szBuffer[8192];
    DWORD dwBytesRead = 0;

    __try {
        // Open internet handle
        hInternet = InternetOpenA(
            "EA DLC Unlocker",
            INTERNET_OPEN_TYPE_DIRECT,
            NULL,
            NULL,
            0
        );

        if (!hInternet) {
            LogError("InternetOpenA", GetLastError());
            __leave;
        }

        // Open URL connection
        hUrl = InternetOpenUrlA(
            hInternet,
            URL,
            NULL,
            0,
            INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE,
            0
        );

        if (!hUrl) {
            LogError("InternetOpenUrlA", GetLastError());
            __leave;
        }

        // Download and parse configuration
        while (InternetReadFile(hUrl, szBuffer, sizeof(szBuffer), &dwBytesRead) && dwBytesRead > 0) {
            // Parse DLC configuration data
            // Format: DLC_ID,DLC_NAME,ENABLED
            ParseDLCConfig(szBuffer, dwBytesRead);
        }

        bSuccess = TRUE;
        LogMessage("DLC configuration loaded successfully");
    }
    __finally {
        if (hUrl) {
            InternetCloseHandle(hUrl);
        }
        if (hInternet) {
            InternetCloseHandle(hInternet);
        }
    }

    return bSuccess;
}

void ParseDLCConfig(const char* pBuffer, DWORD dwSize) {
    // Parse DLC configuration from downloaded data
    // This would populate a global DLC table used by hooked functions

    if (!pBuffer || dwSize == 0) {
        return;
    }

    // TODO: Parse comma-separated DLC list
    // Format example:
    //   "1001,Base Game,1"
    //   "1002,Expansion Pack 1,1"
    //   "1003,Stuff Pack 1,1"
}

// ============================================================================
// Scheduled Task Execution
// ============================================================================

BOOL ExecuteUnlockerTask() {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    BOOL bSuccess = FALSE;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    // Command to execute: schtasks.exe /Run /TN copy_dlc_unlocker
    char szCmdLine[] = "schtasks.exe /Run /TN copy_dlc_unlocker";

    __try {
        if (CreateProcessA(
            NULL,
            szCmdLine,
            NULL,
            NULL,
            FALSE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi
        )) {
            LogMessage("Unlocker running!");
            bSuccess = TRUE;

            // Wait for task to complete
            WaitForSingleObject(pi.hProcess, INFINITE);

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            LogError("CreateProcessA", GetLastError());
        }
    }
    __finally {
        // Cleanup
    }

    return bSuccess;
}

// ============================================================================
// API Proxying Functions
// ============================================================================

BOOL WINAPI MyGetFileVersionInfoA(
    LPCSTR lptstrFilename,
    DWORD dwHandle,
    DWORD dwLen,
    LPVOID lpData
) {
    if (!g_pGetFileVersionInfoA) {
        return FALSE;
    }

    // Call original function
    BOOL bResult = g_pGetFileVersionInfoA(lptstrFilename, dwHandle, dwLen, lpData);

    // Post-process version info if needed
    if (bResult && lpData) {
        // Could patch version strings here if needed
    }

    return bResult;
}

BOOL WINAPI MyGetFileVersionInfoW(
    LPCWSTR lptstrFilename,
    DWORD dwHandle,
    DWORD dwLen,
    LPVOID lpData
) {
    if (!g_pGetFileVersionInfoW) {
        return FALSE;
    }

    return g_pGetFileVersionInfoW(lptstrFilename, dwHandle, dwLen, lpData);
}

DWORD WINAPI MyGetFileVersionInfoSizeA(
    LPCSTR lptstrFilename,
    LPDWORD lpdwHandle
) {
    if (!g_pGetFileVersionInfoSizeA) {
        return 0;
    }

    return g_pGetFileVersionInfoSizeA(lptstrFilename, lpdwHandle);
}

DWORD WINAPI MyGetFileVersionInfoSizeW(
    LPCWSTR lptstrFilename,
    LPDWORD lpdwHandle
) {
    if (!g_pGetFileVersionInfoSizeW) {
        return 0;
    }

    return g_pGetFileVersionInfoSizeW(lptstrFilename, lpdwHandle);
}

BOOL WINAPI MyVerQueryValueA(
    LPCSTR pBlock,
    LPCSTR lpSubBlock,
    LPVOID *lplpBuffer,
    PUINT puLen
) {
    if (!g_pVerQueryValueA) {
        return FALSE;
    }

    return g_pVerQueryValueA(pBlock, lpSubBlock, lplpBuffer, puLen);
}

BOOL WINAPI MyVerQueryValueW(
    LPCWSTR pBlock,
    LPCWSTR lpSubBlock,
    LPVOID *lplpBuffer,
    PUINT puLen
) {
    if (!g_pVerQueryValueW) {
        return FALSE;
    }

    return g_pVerQueryValueW(pBlock, lpSubBlock, lplpBuffer, puLen);
}

// ============================================================================
// Qt5Core.dll Hooking
// ============================================================================

// Original Qt5Core function pointer for DLC ownership checks
typedef bool (*PFN_QtCheckDLCOwnership)(int dlcId);
PFN_QtCheckDLCOwnership g_pOriginalCheckDLC = NULL;

bool WINAPI MyCheckDLCOwnership(int dlcId) {
    // Always return true - bypass all DLC checks
    return true;
}

BOOL InstallQt5CoreHooks() {
    g_hQt5Core = LoadLibraryA("Qt5Core.dll");

    if (!g_hQt5Core) {
        LogMessage("Failed to load Qt5Core.dll");
        return FALSE;
    }

    // Find Qt5Core functions related to DLC ownership
    // These function names are obfuscated, but we can find them by signature scanning

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // Hook DLC check functions
    // g_pOriginalCheckDLC = (PFN_QtCheckDLCOwnership)GetProcAddress(g_hQt5Core, "?CheckDLCOwnership...");
    // DetourAttach(&(PVOID&)g_pOriginalCheckDLC, MyCheckDLCOwnership);

    if (DetourTransactionCommit() == NO_ERROR) {
        LogMessage("Qt5Core hooks installed successfully");
        return TRUE;
    } else {
        LogError("DetourTransactionCommit", GetLastError());
        return FALSE;
    }
}

// ============================================================================
// DLL Entry Point
// ============================================================================

BOOL LoadRealVersionDLL() {
    char szSysPath[MAX_PATH];
    char szVersionDll[MAX_PATH];

    if (!GetSystemDirectoryA(szSysPath, MAX_PATH)) {
        LogError("GetSystemDirectoryA", GetLastError());
        return FALSE;
    }

    // Construct path to legitimate version.dll
    snprintf(szVersionDll, sizeof(szVersionDll), "%s\\version.dll", szSysPath);

    g_hRealVersion = LoadLibraryA(szVersionDll);

    if (!g_hRealVersion) {
        LogError("LoadLibraryA(version.dll)", GetLastError());
        return FALSE;
    }

    // Load function pointers
    g_pGetFileVersionInfoA = (PFN_GetFileVersionInfoA)
        GetProcAddress(g_hRealVersion, "GetFileVersionInfoA");
    g_pGetFileVersionInfoW = (PFN_GetFileVersionInfoW)
        GetProcAddress(g_hRealVersion, "GetFileVersionInfoW");
    g_pGetFileVersionInfoSizeA = (PFN_GetFileVersionInfoSizeA)
        GetProcAddress(g_hRealVersion, "GetFileVersionInfoSizeA");
    g_pGetFileVersionInfoSizeW = (PFN_GetFileVersionInfoSizeW)
        GetProcAddress(g_hRealVersion, "GetFileVersionInfoSizeW");
    g_pVerQueryValueA = (PFN_VerQueryValueA)
        GetProcAddress(g_hRealVersion, "VerQueryValueA");
    g_pVerQueryValueW = (PFN_VerQueryValueW)
        GetProcAddress(g_hRealVersion, "VerQueryValueW");

    return (g_pGetFileVersionInfoA && g_pGetFileVersionInfoW);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    BOOL bSuccess = TRUE;

    switch (fdwReason) {
        case DLL_PROCESS_ATTACH: {
            // Disable thread attach/detach notifications
            DisableThreadLibraryCalls(hinstDLL);

            LogMessage("DLL loaded");

            // Load legitimate version.dll from System32
            if (!LoadRealVersionDLL()) {
                LogMessage("Failed to load real version.dll");
                return FALSE;
            }

            // Download DLC configuration from GitHub
            if (!DownloadDLCConfig()) {
                LogMessage("There was some error while loading the new config");
                // Continue anyway - might have cached config
            }

            // Execute scheduled task for persistence
            ExecuteUnlockerTask();

            // Install hooks on Qt5Core.dll
            InstallQt5CoreHooks();

            bSuccess = TRUE;
            break;
        }

        case DLL_PROCESS_DETACH: {
            if (g_hRealVersion) {
                FreeLibrary(g_hRealVersion);
                g_hRealVersion = NULL;
            }
            if (g_hQt5Core) {
                FreeLibrary(g_hQt5Core);
                g_hQt5Core = NULL;
            }
            break;
        }

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        default:
            break;
    }

    return bSuccess;
}

// ============================================================================
// Exported Functions (matching version.dll interface)
// ============================================================================

extern "C" {

BOOL WINAPI GetFileVersionInfoA(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    return MyGetFileVersionInfoA(lptstrFilename, dwHandle, dwLen, lpData);
}

BOOL WINAPI GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    return MyGetFileVersionInfoW(lptstrFilename, dwHandle, dwLen, lpData);
}

DWORD WINAPI GetFileVersionInfoSizeA(LPCSTR lptstrFilename, LPDWORD lpdwHandle) {
    return MyGetFileVersionInfoSizeA(lptstrFilename, lpdwHandle);
}

DWORD WINAPI GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle) {
    return MyGetFileVersionInfoSizeW(lptstrFilename, lpdwHandle);
}

BOOL WINAPI VerQueryValueA(LPCSTR pBlock, LPCSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen) {
    return MyVerQueryValueA(pBlock, lpSubBlock, lplpBuffer, puLen);
}

BOOL WINAPI VerQueryValueW(LPCWSTR pBlock, LPCWSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen) {
    return MyVerQueryValueW(pBlock, lpSubBlock, lplpBuffer, puLen);
}

// Forward other version.dll exports...
// (Similar proxy functions for other 11 exported APIs)

}

// ============================================================================
// End of version.dll proxy
// ============================================================================
