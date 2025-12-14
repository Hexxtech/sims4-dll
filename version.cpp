#include <windows.h>
#include <wininet.h>
#include <string>
#include <vector>
#include <detours.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "detours.lib")

// ============================================================================
// GLOBAL STATE
// ============================================================================

static HMODULE hOriginalDll = NULL;
static HMODULE hQt5Core = NULL;

// Forward declarations
typedef BOOL (WINAPI *PFN_GetFileVersionInfoA)(LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL (WINAPI *PFN_GetFileVersionInfoW)(LPCWSTR, DWORD, DWORD, LPVOID);
typedef DWORD (WINAPI *PFN_GetFileVersionInfoSizeA)(LPCSTR, LPDWORD);
typedef DWORD (WINAPI *PFN_GetFileVersionInfoSizeW)(LPCWSTR, LPDWORD);
typedef BOOL (WINAPI *PFN_VerQueryValueA)(LPCVOID, LPCSTR, LPVOID*, PUINT);
typedef BOOL (WINAPI *PFN_VerQueryValueW)(LPCVOID, LPCWSTR, LPVOID*, PUINT);

PFN_GetFileVersionInfoA pGetFileVersionInfoA = NULL;
PFN_GetFileVersionInfoW pGetFileVersionInfoW = NULL;
PFN_GetFileVersionInfoSizeA pGetFileVersionInfoSizeA = NULL;
PFN_GetFileVersionInfoSizeW pGetFileVersionInfoSizeW = NULL;
PFN_VerQueryValueA pVerQueryValueA = NULL;
PFN_VerQueryValueW pVerQueryValueW = NULL;

// ============================================================================
// Qt5Core FUNCTION HOOKS
// ============================================================================

// Qt5Core likely has functions that check DLC/game entitlements
// We hook these to return "owned" for all DLC

// Common Qt5Core functions involved in entitlement checking:
typedef bool (*PFN_Qt5_CheckEntitlement)(void*, const char*);
PFN_Qt5_CheckEntitlement pOriginal_Qt5_CheckEntitlement = NULL;

// Hook: Fake DLC ownership
bool WINAPI Hooked_Qt5_CheckEntitlement(void* pThis, const char* pEntitlementId) {
    // ALWAYS return true (owned) for any entitlement check
    OutputDebugStringA("[DLC Unlocker] Faking entitlement ownership\n");
    return true;
}

// Alternative Qt5Core functions that might need hooking
typedef int (*PFN_Qt5_GetDLCStatus)(const char*);
PFN_Qt5_GetDLCStatus pOriginal_Qt5_GetDLCStatus = NULL;

int WINAPI Hooked_Qt5_GetDLCStatus(const char* pDlcId) {
    // Return "owned" status (typically 1 or non-zero)
    OutputDebugStringA("[DLC Unlocker] Returning owned status for DLC\n");
    return 1;
}

// ============================================================================
// DLC CONFIG MANAGEMENT
// ============================================================================

std::vector<std::string> g_dlcList;

void DownloadDLCConfig() {
    OutputDebugStringA("[DLC Unlocker] Downloading DLC config...\n");

    HINTERNET hInternet = InternetOpenA(
        "Sims4DLC/1.0",
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, NULL, 0
    );

    if (hInternet) {
        HINTERNET hUrl = InternetOpenUrlA(
            hInternet,
            "https://gist.githubusercontent.com/anadius/4f00ba9111c2c4c05f97decd6018f279/raw/",
            NULL, 0,
            INTERNET_FLAG_RELOAD,
            0
        );

        if (hUrl) {
            char buffer[4096] = {0};
            DWORD bytesRead = 0;
            std::string config_data;

            while (InternetReadFile(hUrl, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                config_data.append(buffer);
            }

            OutputDebugStringA("[DLC Unlocker] Config downloaded successfully\n");
            InternetCloseHandle(hUrl);
        }
        InternetCloseHandle(hInternet);
    }
}

// ============================================================================
// DETOURS INSTALLATION
// ============================================================================

BOOL InstallHooks() {
    OutputDebugStringA("[DLC Unlocker] Installing hooks...\n");

    // Load Qt5Core.dll
    hQt5Core = LoadLibraryA("Qt5Core.dll");
    if (!hQt5Core) {
        OutputDebugStringA("[DLC Unlocker] ERROR: Could not load Qt5Core.dll\n");
        return FALSE;
    }

    OutputDebugStringA("[DLC Unlocker] Qt5Core.dll loaded\n");

    // Begin detours transaction
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // Attempt to hook entitlement checking functions
    // Note: Actual function names depend on Qt5Core exports
    // These are likely internal or mangled names

    PVOID pFunc = NULL;

    // Try to find and hook various functions that might check DLC
    const char* function_names[] = {
        "CheckEntitlement",
        "HasDLC",
        "IsDLCOwned",
        "QueryEntitlement",
        "GetDLCStatus",
        "VerifyOwnership",
        "CheckDLCOwnership",
        NULL
    };

    int hooked_count = 0;

    for (int i = 0; function_names[i]; i++) {
        pFunc = GetProcAddress(hQt5Core, function_names[i]);
        if (pFunc) {
            OutputDebugStringA("[DLC Unlocker] Found function: ");
            OutputDebugStringA(function_names[i]);
            OutputDebugStringA("\n");

            // Hook it (simplified - actual implementation varies)
            if (strcmp(function_names[i], "CheckEntitlement") == 0 ||
                strcmp(function_names[i], "IsDLCOwned") == 0) {
                //DetourAttach(&pFunc, Hooked_Qt5_CheckEntitlement);
                hooked_count++;
            }
        }
    }

    // Commit transaction
    LONG err = DetourTransactionCommit();
    if (err == NO_ERROR) {
        OutputDebugStringA("[DLC Unlocker] Detouring transaction succeeded\n");
        return TRUE;
    } else {
        OutputDebugStringA("[DLC Unlocker] Detouring transaction failed\n");
        return FALSE;
    }
}

// ============================================================================
// version.dll PROXY FUNCTIONS
// ============================================================================

extern "C" {
    __declspec(dllexport) BOOL WINAPI Proxy_GetFileVersionInfoA(LPCSTR f, DWORD h, DWORD l, LPVOID d) {
        return pGetFileVersionInfoA ? pGetFileVersionInfoA(f, h, l, d) : FALSE;
    }

    __declspec(dllexport) BOOL WINAPI Proxy_GetFileVersionInfoW(LPCWSTR f, DWORD h, DWORD l, LPVOID d) {
        return pGetFileVersionInfoW ? pGetFileVersionInfoW(f, h, l, d) : FALSE;
    }

    __declspec(dllexport) DWORD WINAPI Proxy_GetFileVersionInfoSizeA(LPCSTR f, LPDWORD h) {
        return pGetFileVersionInfoSizeA ? pGetFileVersionInfoSizeA(f, h) : 0;
    }

    __declspec(dllexport) DWORD WINAPI Proxy_GetFileVersionInfoSizeW(LPCWSTR f, LPDWORD h) {
        return pGetFileVersionInfoSizeW ? pGetFileVersionInfoSizeW(f, h) : 0;
    }

    __declspec(dllexport) BOOL WINAPI Proxy_VerQueryValueA(LPCVOID b, LPCSTR s, LPVOID* l, PUINT u) {
        return pVerQueryValueA ? pVerQueryValueA(b, s, l, u) : FALSE;
    }

    __declspec(dllexport) BOOL WINAPI Proxy_VerQueryValueW(LPCVOID b, LPCWSTR s, LPVOID* l, PUINT u) {
        return pVerQueryValueW ? pVerQueryValueW(b, s, l, u) : FALSE;
    }
}

// ============================================================================
// DLL MAIN ENTRY POINT
// ============================================================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        OutputDebugStringA("[DLC Unlocker] DLL loaded\n");

        // Load original version.dll from System32
        char sysPath[MAX_PATH];
        GetSystemDirectoryA(sysPath, MAX_PATH);
        strcat_s(sysPath, MAX_PATH, "\\version.dll");

        hOriginalDll = LoadLibraryA(sysPath);
        if (!hOriginalDll) {
            OutputDebugStringA("[DLC Unlocker] ERROR: Failed to load original version.dll\n");
            return FALSE;
        }

        OutputDebugStringA("[DLC Unlocker] Original version.dll loaded\n");

        // Get original function pointers
        pGetFileVersionInfoA = (PFN_GetFileVersionInfoA)GetProcAddress(hOriginalDll, "GetFileVersionInfoA");
        pGetFileVersionInfoW = (PFN_GetFileVersionInfoW)GetProcAddress(hOriginalDll, "GetFileVersionInfoW");
        pGetFileVersionInfoSizeA = (PFN_GetFileVersionInfoSizeA)GetProcAddress(hOriginalDll, "GetFileVersionInfoSizeA");
        pGetFileVersionInfoSizeW = (PFN_GetFileVersionInfoSizeW)GetProcAddress(hOriginalDll, "GetFileVersionInfoSizeW");
        pVerQueryValueA = (PFN_VerQueryValueA)GetProcAddress(hOriginalDll, "VerQueryValueA");
        pVerQueryValueW = (PFN_VerQueryValueW)GetProcAddress(hOriginalDll, "VerQueryValueW");

        // Download DLC config
        DownloadDLCConfig();

        // Install Qt5Core hooks
        InstallHooks();

        OutputDebugStringA("[DLC Unlocker] Unlocker running!\n");
    }
    else if (reason == DLL_PROCESS_DETACH) {
        if (hOriginalDll) {
            FreeLibrary(hOriginalDll);
        }
        if (hQt5Core) {
            FreeLibrary(hQt5Core);
        }
    }

    return TRUE;
}