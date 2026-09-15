#include "scanner/BypassScanner.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winevt.h>
#include <winioctl.h>

#include <cwchar>

namespace scanner {

namespace {

bool ReadDwordValue(HKEY root, const wchar_t* subKey, const wchar_t* value, DWORD& out) {
    HKEY key{};
    if (RegOpenKeyExW(root, subKey, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
        return false;
    DWORD data = 0;
    DWORD size = sizeof(data);
    DWORD type = 0;
    LONG res = RegQueryValueExW(key, value, nullptr, &type, reinterpret_cast<LPBYTE>(&data), &size);
    RegCloseKey(key);
    if (res != ERROR_SUCCESS || type != REG_DWORD) return false;
    out = data;
    return true;
}

// A value that exists and is explicitly 0 is a much stronger tamper signal
// than a value that is simply absent - absent usually just means "never
// configured", which is the default state on most machines.
bool IsExplicitlyDisabled(HKEY root, const wchar_t* subKey, const wchar_t* value) {
    DWORD data = 0;
    return ReadDwordValue(root, subKey, value, data) && data == 0;
}

bool IsServiceDisabled(SC_HANDLE scManager, const char* serviceName) {
    SC_HANDLE svc = OpenServiceA(scManager, serviceName, SERVICE_QUERY_CONFIG);
    if (!svc) return false;

    BYTE buffer[8192];
    DWORD bytesNeeded = 0;
    bool disabled = false;
    if (QueryServiceConfigA(svc, reinterpret_cast<LPQUERY_SERVICE_CONFIGA>(buffer), sizeof(buffer), &bytesNeeded)) {
        auto* cfg = reinterpret_cast<LPQUERY_SERVICE_CONFIGA>(buffer);
        disabled = (cfg->dwStartType == SERVICE_DISABLED);
    }
    CloseServiceHandle(svc);
    return disabled;
}

void CheckDisabledServices(std::vector<BypassFinding>& out) {
    SC_HANDLE scManager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scManager) return;

    struct ServiceCheck {
        const char* serviceName;
        const char* label;
    };
    static const ServiceCheck kChecks[] = {
        {"SysMain",    "SysMain (Superfetch)"},
        {"DPS",        "DPS (Diagnostic Policy Service)"},
        {"bam",        "BAM (Background Activity Moderator)"},
        {"DcomLaunch", "DCOM Server Process Launcher"},
        {"DBPSvc",     "DBPSvc"},
        {"EventLog",   "Windows Event Log service"},
    };

    for (const auto& check : kChecks) {
        if (IsServiceDisabled(scManager, check.serviceName)) {
            out.push_back({std::string(check.label) + " disabled", "Service start type is set to Disabled"});
        }
    }

    CloseServiceHandle(scManager);
}

void CheckActivitiesCache(std::vector<BypassFinding>& out) {
    if (IsExplicitlyDisabled(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Policies\\Microsoft\\Windows\\System", L"EnableActivityFeed")) {
        out.push_back({"Activities Cache disabled", "EnableActivityFeed policy value is set to 0"});
    }
}

void CheckPowerShellLogging(std::vector<BypassFinding>& out) {
    struct Check {
        const wchar_t* subKey;
        const wchar_t* value;
        const char* label;
    };
    static const Check kChecks[] = {
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
         L"EnableScriptBlockLogging", "PowerShell ScriptBlock logging"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging",
         L"EnableModuleLogging", "PowerShell Module logging"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription",
         L"EnableTranscripting", "PowerShell Transcription"},
    };

    for (const auto& c : kChecks) {
        if (IsExplicitlyDisabled(HKEY_LOCAL_MACHINE, c.subKey, c.value)) {
            out.push_back({std::string(c.label) + " disabled", "Policy value is explicitly set to 0"});
        }
    }
}

void CheckPrefetch(std::vector<BypassFinding>& out) {
    if (IsExplicitlyDisabled(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters",
            L"EnablePrefetcher")) {
        out.push_back({"Prefetch disabled", "EnablePrefetcher registry value is set to 0"});
    }
}

void CheckUsnJournal(std::vector<BypassFinding>& out) {
    HANDLE vol = CreateFileW(L"\\\\.\\C:", GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (vol == INVALID_HANDLE_VALUE) return;

    USN_JOURNAL_DATA_V0 data{};
    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(vol, FSCTL_QUERY_USN_JOURNAL, nullptr, 0, &data, sizeof(data), &bytesReturned, nullptr);
    DWORD err = ok ? 0 : GetLastError();
    CloseHandle(vol);

    if (!ok && (err == ERROR_JOURNAL_NOT_ACTIVE || err == ERROR_INVALID_FUNCTION)) {
        out.push_back({"USN Journal not active", "C: volume has no active change journal"});
    }
}

void CheckAmcache(std::vector<BypassFinding>& out) {
    wchar_t winDir[MAX_PATH]{};
    if (GetWindowsDirectoryW(winDir, MAX_PATH) == 0) return;

    std::wstring path = std::wstring(winDir) + L"\\AppCompat\\Programs\\Amcache.hve";
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        out.push_back({"Amcache missing", "Amcache.hve not found at the expected path"});
    }
}

// Reading the Security channel requires SeSecurityPrivilege to be enabled
// on the token, not just present - administrators have it present-but-
// disabled by default.
void EnableSecurityPrivilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return;

    LUID luid{};
    if (LookupPrivilegeValueW(nullptr, L"SeSecurityPrivilege", &luid)) {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    }
    CloseHandle(token);
}

void CheckEventLogCleared(std::vector<BypassFinding>& out) {
    EnableSecurityPrivilege();

    struct LogCheck {
        const wchar_t* channel;
        DWORD eventId;
        const char* label;
    };
    static const LogCheck kChecks[] = {
        {L"System",   104,  "System event log"},
        {L"Security", 1102, "Security event log"},
    };

    constexpr long long kWithinMs = 24LL * 60 * 60 * 1000;

    for (const auto& c : kChecks) {
        wchar_t query[300];
        swprintf_s(query, L"*[System[(EventID=%lu) and TimeCreated[timediff(@SystemTime) <= %lld]]]",
            c.eventId, kWithinMs);

        EVT_HANDLE results = EvtQuery(nullptr, c.channel, query, EvtQueryChannelPath);
        if (!results) continue;

        EVT_HANDLE evt = nullptr;
        DWORD returned = 0;
        if (EvtNext(results, 1, &evt, 0, 0, &returned) && returned > 0) {
            out.push_back({std::string(c.label) + " cleared", "A log-cleared event was recorded within the last 24 hours"});
        }
        if (evt) EvtClose(evt);
        EvtClose(results);
    }
}

void CheckRecycleBinRecentActivity(std::vector<BypassFinding>& out) {
    FILETIME nowFt{};
    GetSystemTimeAsFileTime(&nowFt);
    ULARGE_INTEGER now{};
    now.LowPart = nowFt.dwLowDateTime;
    now.HighPart = nowFt.dwHighDateTime;
    constexpr ULONGLONG kFifteenMinutes100ns = 15ULL * 60 * 10'000'000ULL;

    WIN32_FIND_DATAW sidEntry{};
    HANDLE sidHandle = FindFirstFileW(L"C:\\$Recycle.Bin\\*", &sidEntry);
    if (sidHandle == INVALID_HANDLE_VALUE) return;

    bool recent = false;
    do {
        if (!(sidEntry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (wcscmp(sidEntry.cFileName, L".") == 0 || wcscmp(sidEntry.cFileName, L"..") == 0) continue;

        std::wstring sidDir = L"C:\\$Recycle.Bin\\" + std::wstring(sidEntry.cFileName) + L"\\*";
        WIN32_FIND_DATAW fileEntry{};
        HANDLE fileHandle = FindFirstFileW(sidDir.c_str(), &fileEntry);
        if (fileHandle == INVALID_HANDLE_VALUE) continue;

        do {
            ULARGE_INTEGER modified{};
            modified.LowPart = fileEntry.ftLastWriteTime.dwLowDateTime;
            modified.HighPart = fileEntry.ftLastWriteTime.dwHighDateTime;
            if (now.QuadPart >= modified.QuadPart &&
                (now.QuadPart - modified.QuadPart) <= kFifteenMinutes100ns) {
                recent = true;
                break;
            }
        } while (FindNextFileW(fileHandle, &fileEntry));
        FindClose(fileHandle);
    } while (!recent && FindNextFileW(sidHandle, &sidEntry));
    FindClose(sidHandle);

    if (recent) {
        out.push_back({"Recycle Bin recently modified", "An entry was modified within the last 15 minutes"});
    }
}

} // namespace

std::vector<BypassFinding> ScanForBypassMethods() {
    std::vector<BypassFinding> findings;
    CheckDisabledServices(findings);
    CheckActivitiesCache(findings);
    CheckPowerShellLogging(findings);
    CheckPrefetch(findings);
    CheckUsnJournal(findings);
    CheckAmcache(findings);
    CheckEventLogCleared(findings);
    CheckRecycleBinRecentActivity(findings);
    return findings;
}

} // namespace scanner
