#include <windows.h>
#include <wininet.h>
#include <string>
#include <vector>

#pragma comment(lib, "wininet.lib")

static HMODULE hOriginalDll = NULL;

// Forward declarations for original functions
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

void DownloadDLCConfig() {
    HINTERNET hInternet = InternetOpenA("Sims4DLC/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet) {
        HINTERNET hUrl = InternetOpenUrlA(
            hInternet,
            "https://gist.githubusercontent.com/anadius/4f00ba9111c2c4c05f97decd6018f279/raw/",
            NULL,
            0,
            INTERNET_FLAG_RELOAD,
            0
        );
        
        if (hUrl) {
            char buffer[4096];
            DWORD bytesRead;
            
            while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
                // Process DLC config here
            }
            
            InternetCloseHandle(hUrl);
        }
        InternetCloseHandle(hInternet);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        
        // Load original version.dll
        char sysPath[MAX_PATH];
        GetSystemDirectoryA(sysPath, MAX_PATH);
        strcat_s(sysPath, "\\version.dll");
        hOriginalDll = LoadLibraryA(sysPath);
        
        if (hOriginalDll) {
            pGetFileVersionInfoA = (PFN_GetFileVersionInfoA)GetProcAddress(hOriginalDll, "GetFileVersionInfoA");
            pGetFileVersionInfoW = (PFN_GetFileVersionInfoW)GetProcAddress(hOriginalDll, "GetFileVersionInfoW");
            pGetFileVersionInfoSizeA = (PFN_GetFileVersionInfoSizeA)GetProcAddress(hOriginalDll, "GetFileVersionInfoSizeA");
            pGetFileVersionInfoSizeW = (PFN_GetFileVersionInfoSizeW)GetProcAddress(hOriginalDll, "GetFileVersionInfoSizeW");
            pVerQueryValueA = (PFN_VerQueryValueA)GetProcAddress(hOriginalDll, "VerQueryValueA");
            pVerQueryValueW = (PFN_VerQueryValueW)GetProcAddress(hOriginalDll, "VerQueryValueW");
        }
        
        // Download DLC config
        DownloadDLCConfig();
    }
    else if (reason == DLL_PROCESS_DETACH) {
        if (hOriginalDll) {
            FreeLibrary(hOriginalDll);
        }
    }
    return TRUE;
}

// Export functions
extern "C" {
    __declspec(dllexport) BOOL WINAPI GetFileVersionInfoA(LPCSTR f, DWORD h, DWORD l, LPVOID d) {
        return pGetFileVersionInfoA ? pGetFileVersionInfoA(f, h, l, d) : FALSE;
    }
    
    __declspec(dllexport) BOOL WINAPI GetFileVersionInfoW(LPCWSTR f, DWORD h, DWORD l, LPVOID d) {
        return pGetFileVersionInfoW ? pGetFileVersionInfoW(f, h, l, d) : FALSE;
    }
    
    __declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeA(LPCSTR f, LPDWORD h) {
        return pGetFileVersionInfoSizeA ? pGetFileVersionInfoSizeA(f, h) : 0;
    }
    
    __declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeW(LPCWSTR f, LPDWORD h) {
        return pGetFileVersionInfoSizeW ? pGetFileVersionInfoSizeW(f, h) : 0;
    }
    
    __declspec(dllexport) BOOL WINAPI MyVerQueryValueA(LPCVOID b, LPCSTR s, LPVOID* l, PUINT u) {
        return pVerQueryValueA ? pVerQueryValueA(b, s, l, u) : FALSE;
    }
    
    __declspec(dllexport) BOOL WINAPI MyVerQueryValueW(LPCVOID b, LPCWSTR s, LPVOID* l, PUINT u) {
        return pVerQueryValueW ? pVerQueryValueW(b, s, l, u) : FALSE;
    }
}
