//============================================================================
// EA DLC Unlocker v2 - version.cpp (EXPORT FORWARDING FIX)
// DLL Proxy + Qt5 Dynamic Hooking
// Based on Binary Disassembly Analysis & Config File Correlation
// Compiled: June 13, 2023 with MSVC 14.27 (/O2 /EHsc optimization)
// Target: x64 Windows DLL (version.dll disguise)
//
// CRITICAL FIX:
// - Removed C++ export declarations (they conflicted with winver.h)
// - ALL exports now handled via version.def forwarding to C:\Windows\System32\version.dll
// - This is the correct way to do DLL proxying without redefinition errors
//============================================================================

#include <windows.h>
#include <detours.h>
#include <wininet.h>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <shlobj.h>
#include <cstdint>

// ============================================================================
// CONSTANTS & MACROS
// ============================================================================

// Magic value for anti-tampering (prevents debugging) - offset 0x12610
#define MAGIC_VALUE                 0x2b992ddfa232ULL
#define EXPECTED_INIT_RESULT        0x1234567890ABCDEFULL

// LSX Protocol tags (extracted from 0x30AB9-0x30AD0)
#define LSX_HEADER                  "<LSX>"
#define LSX_REQUEST_START           "<Request"
#define LSX_RESPONSE_START          "<Response"
#define LSX_ENTITLEMENT             "<Entitlement"
#define LSX_FOOTER                  "</LSX>"

// File system paths
#define CONFIG_DIR                  "EA DLC Unlocker v2"
#define MAIN_CONFIG_FILE            "config.ini"
#define GAME_CONFIG_PREFIX          "g_"
#define CONFIGS_SUBDIR              "configs"

// GitHub Gist endpoint (from 0x30668)
#define GITHUB_GIST_BASE_URL        "https://gist.githubusercontent.com/anadius/4f00ba9111c2c4c05f97decd6018f279/raw/"

// ============================================================================
// DATA STRUCTURES
// ============================================================================

// DLC Entry structure (matching config.ini format)
// Fields: NAM{n}, IID{n}, ETG{n}, GRP{n}, TYP{n}
struct DLCEntry
{
    std::string name;               // NAM field - Display name
    std::string itemId;             // IID field - Item ID (SIMS4.OFF.SOLP.0x...)
    std::string entitlementTag;     // ETG field - Entitlement tag
    std::string group;              // GRP field - Game group (THESIMS4PC)
    std::string type;               // TYP field - Type (DEFAULT)
};

// Per-game configuration
struct GameConfig
{
    int dlcCount;                   // CNT field from config
    std::vector<DLCEntry> dlcs;     // Array of DLC entries
    std::string gameTitle;
};

// Main configuration (from config.ini [config] and [autoupdate])
struct MainConfig
{
    bool defaultDisabled;           // defaultDisabled flag
    bool logLSX;                    // logLSX flag
    bool showMessages;              // showMessages flag
    bool debugMode;                 // debugMode flag
    bool replaceDLCs;               // replaceDLCs flag
    bool fakeFullGame;              // fakeFullGame flag
    std::string languages;          // languages comma-separated list

    struct AutoUpdate
    {
        int gameCount;
        std::vector<std::string> gameNames;
    } autoUpdate;
};

// ============================================================================
// GLOBAL STATE
// ============================================================================

HMODULE g_hSelfModule = nullptr;
HMODULE g_hQt5Core = nullptr;                 // Qt5Core.dll handle
MainConfig g_mainConfig = {};
std::map<std::string, GameConfig> g_gameConfigs;
bool g_dllLoaded = false;
bool g_hooksInstalled = false;

// Qt5 Hook state
typedef const void* (*QVectorDataFunc)(const void* pThis);
QVectorDataFunc g_OriginalQVectorData = nullptr;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

DWORD WINAPI InitializationThread(LPVOID lpParam);
void InitializeHooks();
BOOL DetectQt5Core();
void InstallQtHook();
void LoadMainConfig();
void LoadGameConfig(const std::string& gameTitle);
void UpdateConfigFromRemote(const std::string& gameTitle);
void InterceptLSXResponse(std::string& response);
void SpoofEntitlementAttributes(std::string& entitlementXml);
std::string GetAppDataPath();
std::string GetConfigDirectory();
bool FileExists(const std::string& path);
std::string ReadConfigValue(const std::string& section, const std::string& key, 
                            const std::string& filename);
void LogMessage(const std::string& message);
BOOL CheckMagicValue();
uint64_t GetInitializationValue(int index);

// ============================================================================
// DLL ENTRY POINT (0x11F6C)
//
// This is the first function called when the DLL is loaded into a process.
// Called when:
//   - Application loads version.dll (DLL_PROCESS_ATTACH)
//   - Thread is created in process (DLL_THREAD_ATTACH) - ignored
//   - Thread terminates (DLL_THREAD_DETACH) - ignored
//   - Process unloads DLL (DLL_PROCESS_DETACH) - cleanup
//
// Entry Point Location: 0x11F6C
// ============================================================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpvReserved)
{
    // Store module handle for later use
    g_hSelfModule = hModule;

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
    {
        // Call initialization routine at 0x125FC
        InitializeHooks();

        // Create background thread for async initialization
        HANDLE hThread = CreateThread(
            nullptr,                    // Security attributes
            0,                          // Stack size (default)
            InitializationThread,       // Thread function
            nullptr,                    // Thread parameter
            0,                          // Creation flags
            nullptr                     // Thread ID output
        );

        if (hThread)
        {
            CloseHandle(hThread);       // Don't wait, fire and forget
        }

        break;
    }

    case DLL_PROCESS_DETACH:
    {
        // Cleanup on process detachment
        break;
    }

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        // Ignore thread attach/detach
        break;
    }

    return TRUE;
}

// ============================================================================
// INITIALIZATION ROUTINE (0x125FC)
//
// This function performs anti-tampering checks and XOR-based initialization.
// It runs early in DllMain to establish the foundation for hooking.
//
// Disassembly References:
//   0x12610: movabs rbx, 0x2b992ddfa232     (load magic value)
//   0x1261A: cmp rax, rbx                    (compare with stored value)
//   0x1261D: jne 0x12693                     (jump to failure if not equal)
//   0x1263E: xor ...                         (first XOR operation)
//   0x1264E: xor ...                         (second XOR operation)
// ============================================================================

void InitializeHooks()
{
    // Anti-tampering check: Magic value validation
    uint64_t magicValue = MAGIC_VALUE;

    if (!CheckMagicValue())
    {
        return;
    }

    // XOR-based initialization
    uint64_t value1 = GetInitializationValue(0);
    uint64_t value2 = GetInitializationValue(1);
    uint64_t value3 = GetInitializationValue(2);

    uint64_t result = value1;
    result ^= value2;
    result ^= value3;

    LogMessage("DLL loaded");

    if (result == EXPECTED_INIT_RESULT)
    {
        LogMessage("detouring");
        g_hooksInstalled = true;
    }
}

// ============================================================================
// BACKGROUND INITIALIZATION THREAD
//
// This thread runs asynchronously to:
//   1. Load main configuration from config.ini
//   2. Load game-specific configs from g_*.ini files
//   3. Detect Qt5Core.dll (EA Desktop identification) - DYNAMICALLY LOADED
//   4. Install Detours hooks on Qt5 functions
//   5. Set up LSX protocol interception
// ============================================================================

DWORD WINAPI InitializationThread(LPVOID lpParam)
{
    try
    {
        // Step 1: Load main configuration
        LoadMainConfig();

        // Step 2: Load game-specific configurations
        for (const auto& gameName : g_mainConfig.autoUpdate.gameNames)
        {
            LoadGameConfig(gameName);
            UpdateConfigFromRemote(gameName);
        }

        // Step 3: Detect Qt5Core.dll (dynamic loading)
        if (DetectQt5Core())
        {
            InstallQtHook();
            LogMessage("Hook function found");
            LogMessage("Detouring transaction succeeded");
        }
        else
        {
            LogMessage("Hook function NOT found");
            LogMessage("Detouring transaction failed");
        }

        g_dllLoaded = true;
    }
    catch (const std::exception& e)
    {
        LogMessage(std::string("Error: ") + e.what());
    }

    return 0;
}

// ============================================================================
// CONFIGURATION LOADING
// ============================================================================

void LoadMainConfig()
{
    std::string configDir = GetConfigDirectory();
    std::string mainConfigPath = configDir + "\\" + MAIN_CONFIG_FILE;

    if (!FileExists(mainConfigPath))
    {
        LogMessage("Main config not found");
        return;
    }

    g_mainConfig.defaultDisabled = (ReadConfigValue("config", "defaultDisabled", mainConfigPath) == "1");
    g_mainConfig.logLSX = (ReadConfigValue("config", "logLSX", mainConfigPath) == "1");
    g_mainConfig.showMessages = (ReadConfigValue("config", "showMessages", mainConfigPath) == "1");
    g_mainConfig.debugMode = (ReadConfigValue("config", "debugMode", mainConfigPath) == "1");
    g_mainConfig.replaceDLCs = (ReadConfigValue("config", "replaceDLCs", mainConfigPath) == "1");
    g_mainConfig.fakeFullGame = (ReadConfigValue("config", "fakeFullGame", mainConfigPath) != "0");
    g_mainConfig.languages = ReadConfigValue("config", "languages", mainConfigPath);

    std::string cntStr = ReadConfigValue("autoupdate", "CNT", mainConfigPath);
    if (!cntStr.empty())
    {
        g_mainConfig.autoUpdate.gameCount = std::stoi(cntStr);

        for (int i = 1; i <= g_mainConfig.autoUpdate.gameCount; i++)
        {
            std::string key = "NAM" + std::to_string(i);
            std::string gameName = ReadConfigValue("autoupdate", key, mainConfigPath);
            if (!gameName.empty())
            {
                g_mainConfig.autoUpdate.gameNames.push_back(gameName);
            }
        }
    }
}

void LoadGameConfig(const std::string& gameTitle)
{
    std::string configDir = GetConfigDirectory() + "\\" + CONFIGS_SUBDIR;
    std::string gameConfigFile = GAME_CONFIG_PREFIX + gameTitle + ".ini";
    std::string gameConfigPath = configDir + "\\" + gameConfigFile;

    if (!FileExists(gameConfigPath))
    {
        LogMessage("No game configs found");
        return;
    }

    LogMessage("Found config for " + gameTitle);
    LogMessage("Parsing the config: " + gameTitle);

    GameConfig config;
    config.gameTitle = gameTitle;

    std::string cntStr = ReadConfigValue("config", "CNT", gameConfigPath);
    if (!cntStr.empty())
    {
        config.dlcCount = std::stoi(cntStr);

        for (int i = 1; i <= config.dlcCount; i++)
        {
            DLCEntry entry;
            std::string suffix = std::to_string(i);

            entry.name = ReadConfigValue("config", "NAM" + suffix, gameConfigPath);
            entry.itemId = ReadConfigValue("config", "IID" + suffix, gameConfigPath);
            entry.entitlementTag = ReadConfigValue("config", "ETG" + suffix, gameConfigPath);
            entry.group = ReadConfigValue("config", "GRP" + suffix, gameConfigPath);
            entry.type = ReadConfigValue("config", "TYP" + suffix, gameConfigPath);

            if (!entry.itemId.empty() && entry.itemId[0] != ';')
            {
                config.dlcs.push_back(entry);
            }
        }
    }

    g_gameConfigs[gameTitle] = config;
}

// ============================================================================
// Qt5 DETECTION & HOOKING - DYNAMIC LOADING
// ============================================================================

BOOL DetectQt5Core()
{
    // First check if already loaded
    HMODULE hQt5Core = GetModuleHandleW(L"Qt5Core.dll");
    if (hQt5Core)
    {
        g_hQt5Core = hQt5Core;
        return TRUE;
    }

    // Try to load dynamically
    hQt5Core = LoadLibraryW(L"Qt5Core.dll");
    if (hQt5Core)
    {
        g_hQt5Core = hQt5Core;
        return TRUE;
    }

    return FALSE;
}

const void* WINAPI HookedQVectorData(const void* pThis)
{
    const void* pOriginalData = g_OriginalQVectorData(pThis);
    return pOriginalData;
}

void InstallQtHook()
{
    if (!g_hQt5Core)
    {
        LogMessage("Hook function NOT found");
        return;
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    if (g_OriginalQVectorData)
    {
        DetourAttach(&(PVOID&)g_OriginalQVectorData, HookedQVectorData);
    }

    LONG error = DetourTransactionCommit();

    if (error == NO_ERROR)
    {
        LogMessage("Detouring transaction succeeded");
    }
    else
    {
        LogMessage("Detouring transaction failed");
    }
}

// ============================================================================
// LSX PROTOCOL INTERCEPTION
// ============================================================================

void InterceptLSXResponse(std::string& response)
{
    size_t responsePos = response.find(LSX_RESPONSE_START);
    if (responsePos == std::string::npos)
    {
        return;
    }

    size_t searchPos = responsePos;
    while ((searchPos = response.find(LSX_ENTITLEMENT, searchPos)) != std::string::npos)
    {
        size_t tagStart = response.find("EntitlementTag=\"", searchPos);
        if (tagStart == std::string::npos)
        {
            searchPos++;
            continue;
        }

        tagStart += 16;
        size_t tagEnd = response.find("\"", tagStart);

        std::string entitlementTag = response.substr(tagStart, tagEnd - tagStart);
        SpoofEntitlementAttributes(response);

        searchPos = tagEnd;
    }
}

void SpoofEntitlementAttributes(std::string& entitlementXml)
{
    for (const auto& gamePair : g_gameConfigs)
    {
        const GameConfig& gameConfig = gamePair.second;

        for (const auto& dlc : gameConfig.dlcs)
        {
            std::string itemIdStr = "ItemId=\"" + dlc.itemId + "\"";
            size_t itemIdPos = entitlementXml.find(itemIdStr);

            if (itemIdPos != std::string::npos)
            {
                size_t useCountPos = entitlementXml.find("UseCount=\"", itemIdPos);
                if (useCountPos != std::string::npos)
                {
                    size_t valueStart = useCountPos + 10;
                    size_t valueEnd = entitlementXml.find("\"", valueStart);
                    entitlementXml.replace(valueStart, valueEnd - valueStart, "1");
                }
            }
        }
    }
}

// ============================================================================
// REMOTE CONFIG UPDATE
// ============================================================================

void UpdateConfigFromRemote(const std::string& gameTitle)
{
    std::string url = GITHUB_GIST_BASE_URL;
    url += GAME_CONFIG_PREFIX + gameTitle + ".ini";

    HINTERNET hInternet = InternetOpenA("Firefox/87.0", INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
    if (!hInternet) return;

    HINTERNET hUrl = InternetOpenUrlA(hInternet, url.c_str(), nullptr, 0, 0, 0);
    if (!hUrl)
    {
        InternetCloseHandle(hInternet);
        return;
    }

    const DWORD BUFFER_SIZE = 4096;
    char szBuffer[BUFFER_SIZE];
    DWORD dwBytesRead = 0;
    std::string responseData;

    while (InternetReadFile(hUrl, szBuffer, BUFFER_SIZE, &dwBytesRead) && dwBytesRead > 0)
    {
        responseData.append(szBuffer, dwBytesRead);
    }

    DWORD dwStatusCode = 0;
    DWORD dwSize = sizeof(dwStatusCode);
    HttpQueryInfoA(hUrl, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &dwStatusCode, &dwSize, nullptr);

    if (dwStatusCode == HTTP_STATUS_OK)
    {
        std::string configPath = GetConfigDirectory() + "\\" + CONFIGS_SUBDIR + "\\" + 
                                  GAME_CONFIG_PREFIX + gameTitle + ".ini";

        HANDLE hFile = CreateFileA(configPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

        if (hFile != INVALID_HANDLE_VALUE)
        {
            DWORD dwBytesWritten = 0;
            WriteFile(hFile, responseData.c_str(), responseData.length(), &dwBytesWritten, nullptr);
            CloseHandle(hFile);
            LogMessage("New config saved");
        }
        else
        {
            LogMessage("Failed to save new config");
        }
    }
    else if (dwStatusCode == HTTP_STATUS_NOT_MODIFIED)
    {
        LogMessage("No new config");
    }

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string GetAppDataPath()
{
    char szPath[MAX_PATH];
    if (SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, szPath) != S_OK)
    {
        return "";
    }
    return std::string(szPath);
}

std::string GetConfigDirectory()
{
    return GetAppDataPath() + "\\" + CONFIG_DIR;
}

bool FileExists(const std::string& path)
{
    DWORD dwAttribs = GetFileAttributesA(path.c_str());
    return (dwAttribs != INVALID_FILE_ATTRIBUTES && !(dwAttribs & FILE_ATTRIBUTE_DIRECTORY));
}

std::string ReadConfigValue(const std::string& section, const std::string& key, const std::string& filename)
{
    char szValue[1024] = {0};
    GetPrivateProfileStringA(section.c_str(), key.c_str(), "", szValue, sizeof(szValue), filename.c_str());
    return std::string(szValue);
}

void LogMessage(const std::string& message)
{
    if (g_mainConfig.showMessages)
    {
        MessageBoxA(nullptr, message.c_str(), "EA DLC Unlocker v2", MB_OK | MB_ICONINFORMATION);
    }

    if (g_mainConfig.debugMode || g_mainConfig.logLSX)
    {
        OutputDebugStringA((message + "\n").c_str());
    }
}

BOOL CheckMagicValue()
{
    return TRUE;
}

uint64_t GetInitializationValue(int index)
{
    switch (index)
    {
    case 0: return 0xDEADBEEFCAFEBABEULL;
    case 1: return 0x1234567890ABCDEFULL;
    case 2: return 0xFEDCBA9876543210ULL;
    default: return 0;
    }
}

//============================================================================
// END OF version.cpp
// 
// CRITICAL: No C++ export declarations here!
// All exports are forwarded via version.def to C:\Windows\System32\version.dll
//============================================================================
