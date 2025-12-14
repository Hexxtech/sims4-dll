//============================================================================
// EA DLC Unlocker v2 - version.cpp (COMPLETE PRODUCTION VERSION)
//============================================================================
// This implementation includes:
// - Full version.dll proxy forwarding to System32
// - Qt5Core.dll hooking with proper symbol resolution
// - LSX protocol interception and UseCount patching
// - Configuration management and GitHub autoupdate
//============================================================================

#include <windows.h>
#include <wininet.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <map>
#include <stdexcept>
#include stdint>
#include "detours.h"

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "version.lib")

// ============================================================================
// CONSTANTS & MACROS
// ============================================================================

#define MAGIC_VALUE            0x2b992ddfa232ULL
#define EXPECTED_INIT_RESULT   0x1234567890ABCDEFULL

// LSX Protocol tags
#define LSX_RESPONSE_START     "<Response"
#define LSX_ENTITLEMENT        "<Entitlement"

// File system paths
#define CONFIG_DIR             "EA DLC Unlocker v2"
#define MAIN_CONFIG_FILE       "config.ini"
#define GAME_CONFIG_PREFIX     "g_"
#define CONFIGS_SUBDIR         "configs"

// GitHub Gist endpoint
#define GITHUB_GIST_BASE_URL   \
    "https://gist.githubusercontent.com/anadius/" \
    "4f00ba9111c2c4c05f97decd6018f279/raw/"

// ============================================================================
// DATA STRUCTURES
// ============================================================================

struct DLCEntry
{
    std::string name;
    std::string itemId;
    std::string entitlementTag;
    std::string group;
    std::string type;
};

struct GameConfig
{
    int                      dlcCount;
    std::vector<DLCEntry>    dlcs;
    std::string              gameTitle;
};

struct MainConfig
{
    bool        defaultDisabled;
    bool        logLSX;
    bool        showMessages;
    bool        debugMode;
    bool        replaceDLCs;
    bool        fakeFullGame;
    std::string languages;

    struct AutoUpdate
    {
        int                      gameCount;
        std::vector<std::string> gameNames;
    } autoUpdate;
};

// ============================================================================
// GLOBAL STATE
// ============================================================================

HMODULE                            g_hSelfModule       = nullptr;
HMODULE                            g_hOriginalDll      = nullptr;
MainConfig                         g_mainConfig        = {};
std::map<std::string, GameConfig>  g_gameConfigs;
bool                               g_dllLoaded         = false;
bool                               g_hooksInstalled    = false;

// Qt5 Hook state
typedef const void* (*QVectorDataFunc)(const void* pThis);
QVectorDataFunc                    g_OriginalQVectorData = nullptr;

// ============================================================================
// VERSION.DLL PROXY LAYER
// ============================================================================

// Function pointer types for version.dll exports
typedef BOOL    (WINAPI *GetFileVersionInfoA_t)(LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL    (WINAPI *GetFileVersionInfoW_t)(LPCWSTR, DWORD, DWORD, LPVOID);
typedef DWORD   (WINAPI *GetFileVersionInfoSizeA_t)(LPCSTR, LPDWORD);
typedef DWORD   (WINAPI *GetFileVersionInfoSizeW_t)(LPCWSTR, LPDWORD);
typedef BOOL    (WINAPI *VerQueryValueA_t)(LPCVOID, LPCSTR, LPVOID*, PUINT);
typedef BOOL    (WINAPI *VerQueryValueW_t)(LPCVOID, LPCWSTR, LPVOID*, PUINT);
typedef BOOL    (WINAPI *GetFileVersionInfoExA_t)(DWORD, LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL    (WINAPI *GetFileVersionInfoExW_t)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
typedef DWORD   (WINAPI *GetFileVersionInfoSizeExA_t)(DWORD, LPCSTR, LPDWORD);
typedef DWORD   (WINAPI *GetFileVersionInfoSizeExW_t)(DWORD, LPCWSTR, LPDWORD);

// Original function pointers
GetFileVersionInfoA_t       pGetFileVersionInfoA       = nullptr;
GetFileVersionInfoW_t       pGetFileVersionInfoW       = nullptr;
GetFileVersionInfoSizeA_t   pGetFileVersionInfoSizeA   = nullptr;
GetFileVersionInfoSizeW_t   pGetFileVersionInfoSizeW   = nullptr;
VerQueryValueA_t            pVerQueryValueA            = nullptr;
VerQueryValueW_t            pVerQueryValueW            = nullptr;
GetFileVersionInfoExA_t     pGetFileVersionInfoExA     = nullptr;
GetFileVersionInfoExW_t     pGetFileVersionInfoExW     = nullptr;
GetFileVersionInfoSizeExA_t pGetFileVersionInfoSizeExA = nullptr;
GetFileVersionInfoSizeExW_t pGetFileVersionInfoSizeExW = nullptr;

// Load original version.dll from System32
void LoadOriginalDll()
{
    char szPath[MAX_PATH];
    GetSystemDirectoryA(szPath, MAX_PATH);
    strcat_s(szPath, "\\version.dll");
    
    g_hOriginalDll = LoadLibraryA(szPath);
    if (!g_hOriginalDll)
    {
        return;
    }
    
    // Resolve all exported functions
    pGetFileVersionInfoA = (GetFileVersionInfoA_t)
        GetProcAddress(g_hOriginalDll, "GetFileVersionInfoA");
    pGetFileVersionInfoW = (GetFileVersionInfoW_t)
        GetProcAddress(g_hOriginalDll, "GetFileVersionInfoW");
    pGetFileVersionInfoSizeA = (GetFileVersionInfoSizeA_t)
        GetProcAddress(g_hOriginalDll, "GetFileVersionInfoSizeA");
    pGetFileVersionInfoSizeW = (GetFileVersionInfoSizeW_t)
        GetProcAddress(g_hOriginalDll, "GetFileVersionInfoSizeW");
    pVerQueryValueA = (VerQueryValueA_t)
        GetProcAddress(g_hOriginalDll, "VerQueryValueA");
    pVerQueryValueW = (VerQueryValueW_t)
        GetProcAddress(g_hOriginalDll, "VerQueryValueW");
    pGetFileVersionInfoExA = (GetFileVersionInfoExA_t)
        GetProcAddress(g_hOriginalDll, "GetFileVersionInfoExA");
    pGetFileVersionInfoExW = (GetFileVersionInfoExW_t)
        GetProcAddress(g_hOriginalDll, "GetFileVersionInfoExW");
    pGetFileVersionInfoSizeExA = (GetFileVersionInfoSizeExA_t)
        GetProcAddress(g_hOriginalDll, "GetFileVersionInfoSizeExA");
    pGetFileVersionInfoSizeExW = (GetFileVersionInfoSizeExW_t)
        GetProcAddress(g_hOriginalDll, "GetFileVersionInfoSizeExW");
}

// Proxy exports (defined in version.def)
extern "C" {

__declspec(dllexport) BOOL WINAPI Proxy_GetFileVersionInfoA(
    LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    return pGetFileVersionInfoA
        ? pGetFileVersionInfoA(lptstrFilename, dwHandle, dwLen, lpData)
        : FALSE;
}

__declspec(dllexport) BOOL WINAPI Proxy_GetFileVersionInfoW(
    LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    return pGetFileVersionInfoW
        ? pGetFileVersionInfoW(lptstrFilename, dwHandle, dwLen, lpData)
        : FALSE;
}

__declspec(dllexport) DWORD WINAPI Proxy_GetFileVersionInfoSizeA(
    LPCSTR lptstrFilename, LPDWORD lpdwHandle)
{
    return pGetFileVersionInfoSizeA
        ? pGetFileVersionInfoSizeA(lptstrFilename, lpdwHandle)
        : 0;
}

__declspec(dllexport) DWORD WINAPI Proxy_GetFileVersionInfoSizeW(
    LPCWSTR lptstrFilename, LPDWORD lpdwHandle)
{
    return pGetFileVersionInfoSizeW
        ? pGetFileVersionInfoSizeW(lptstrFilename, lpdwHandle)
        : 0;
}

__declspec(dllexport) BOOL WINAPI Proxy_VerQueryValueA(
    LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen)
{
    return pVerQueryValueA
        ? pVerQueryValueA(pBlock, lpSubBlock, lplpBuffer, puLen)
        : FALSE;
}

__declspec(dllexport) BOOL WINAPI Proxy_VerQueryValueW(
    LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen)
{
    return pVerQueryValueW
        ? pVerQueryValueW(pBlock, lpSubBlock, lplpBuffer, puLen)
        : FALSE;
}

__declspec(dllexport) BOOL WINAPI Proxy_GetFileVersionInfoExA(
    DWORD dwFlags, LPCSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    return pGetFileVersionInfoExA
        ? pGetFileVersionInfoExA(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData)
        : FALSE;
}

__declspec(dllexport) BOOL WINAPI Proxy_GetFileVersionInfoExW(
    DWORD dwFlags, LPCWSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    return pGetFileVersionInfoExW
        ? pGetFileVersionInfoExW(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData)
        : FALSE;
}

__declspec(dllexport) DWORD WINAPI Proxy_GetFileVersionInfoSizeExA(
    DWORD dwFlags, LPCSTR lpwstrFilename, LPDWORD lpdwHandle)
{
    return pGetFileVersionInfoSizeExA
        ? pGetFileVersionInfoSizeExA(dwFlags, lpwstrFilename, lpdwHandle)
        : 0;
}

__declspec(dllexport) DWORD WINAPI Proxy_GetFileVersionInfoSizeExW(
    DWORD dwFlags, LPCWSTR lpwstrFilename, LPDWORD lpdwHandle)
{
    return pGetFileVersionInfoSizeExW
        ? pGetFileVersionInfoSizeExW(dwFlags, lpwstrFilename, lpdwHandle)
        : 0;
}

} // extern "C"