#include "scanner/ModuleTrustScanner.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <TlHelp32.h>
#include <Softpub.h>
#include <wintrust.h>

#include <algorithm>
#include <cwctype>

namespace scanner {

namespace {

std::wstring ToLowerW(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return s;
}

std::string NarrowAscii(const std::wstring& w) {
    std::string out;
    out.reserve(w.size());
    for (wchar_t c : w) out += (c > 0 && c < 128) ? static_cast<char>(c) : '?';
    return out;
}

enum class TrustResult { Trusted, NotPositivelyTrusted, Invalid };

// Runs Authenticode verification on a file on disk. Revocation checking
// is disabled (WTD_REVOKE_NONE) so this never makes a network call and
// stays fast/offline.
TrustResult VerifyFileTrust(const std::wstring& path) {
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.pFile = &fileInfo;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &action, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &trustData);

    if (status == ERROR_SUCCESS) return TrustResult::Trusted;

    const DWORD code = static_cast<DWORD>(status);
    if (code == TRUST_E_NOSIGNATURE || code == CRYPT_E_FILE_ERROR ||
        code == TRUST_E_SUBJECT_FORM_UNKNOWN || code == TRUST_E_PROVIDER_UNKNOWN) {
        // No signature at all, or the verifier couldn't process the file
        // (e.g. locked by another process) - not a positive trust
        // confirmation, but not evidence of tampering either.
        return TrustResult::NotPositivelyTrusted;
    }
    // A signature was present but is invalid, expired, from an
    // untrusted root, or explicitly distrusted - the file claims to be
    // signed but isn't legitimately so.
    return TrustResult::Invalid;
}

const std::vector<std::wstring>& KnownGoodPathMarkers() {
    static const std::vector<std::wstring> markers = {
        L"\\.minecraft\\", L"\\prismlauncher\\", L"\\polymc\\", L"\\multimc\\",
        L"\\atlauncher\\", L"\\the feed the beast\\", L"\\.technic\\",
        L"\\curseforge\\minecraft\\", L"\\gdlauncher_next\\", L"\\tlauncher\\",
        L"\\.lunarclient\\", L"\\.badlion\\", L"\\modrinth\\", L"\\overwolf\\minecraft\\",
    };
    return markers;
}

bool IsInKnownGoodLocation(const std::wstring& lowerPath, const std::wstring& lowerProcessDir) {
    if (!lowerProcessDir.empty() && lowerPath.rfind(lowerProcessDir, 0) == 0) return true;
    for (const auto& marker : KnownGoodPathMarkers()) {
        if (lowerPath.find(marker) != std::wstring::npos) return true;
    }
    return false;
}

struct SystemDirs {
    std::wstring lowerSysDir;
    std::wstring lowerSysDirX86;
};

SystemDirs QuerySystemDirs() {
    wchar_t sysDir[MAX_PATH]{};
    wchar_t sysDirX86[MAX_PATH]{};
    GetSystemDirectoryW(sysDir, MAX_PATH);
    GetSystemWow64DirectoryW(sysDirX86, MAX_PATH); // fails harmlessly on non-WOW64 hosts
    return {ToLowerW(sysDir), ToLowerW(sysDirX86)};
}

bool IsInWindowsSystemDirectory(const std::wstring& lowerPath, const SystemDirs& sysDirs) {
    if (!sysDirs.lowerSysDir.empty() && lowerPath.rfind(sysDirs.lowerSysDir, 0) == 0) return true;
    if (!sysDirs.lowerSysDirX86.empty() && lowerPath.rfind(sysDirs.lowerSysDirX86, 0) == 0) return true;
    return false;
}

} // namespace

std::vector<ModuleTrustFinding> ScanModuleTrust(uint32_t pid) {
    std::vector<ModuleTrustFinding> findings;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return findings;

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (!Module32FirstW(snap, &entry)) {
        CloseHandle(snap);
        return findings;
    }

    // The first module in the snapshot is always the process's own main
    // executable; its directory is the expected home for every native
    // library the JRE/launcher ships alongside it.
    std::wstring processDir;
    {
        const std::wstring exePath = entry.szExePath;
        const size_t lastSlash = exePath.find_last_of(L"\\/");
        if (lastSlash != std::wstring::npos) {
            processDir = ToLowerW(exePath.substr(0, lastSlash + 1));
        }
    }

    const SystemDirs sysDirs = QuerySystemDirs();

    do {
        const std::string moduleName = NarrowAscii(entry.szModule);
        const std::wstring modulePath = entry.szExePath;
        const std::wstring lowerPath = ToLowerW(modulePath);

        if (IsInWindowsSystemDirectory(lowerPath, sysDirs)) {
            continue; // out of scope: OS-level DLL tampering, not this tool's purpose
        }

        const bool knownLocation = IsInKnownGoodLocation(lowerPath, processDir);
        const TrustResult trust = VerifyFileTrust(modulePath);

        if (trust == TrustResult::Invalid) {
            findings.push_back({moduleName,
                "Signature present but invalid/untrusted: " + NarrowAscii(modulePath),
                Severity::Detect});
            continue;
        }

        if (!knownLocation) {
            if (trust == TrustResult::Trusted) {
                findings.push_back({moduleName,
                    "Loaded from an unexpected location (signed): " + NarrowAscii(modulePath),
                    Severity::Warning});
            } else {
                findings.push_back({moduleName,
                    "Loaded from an unexpected location and not verifiably signed: " + NarrowAscii(modulePath),
                    Severity::Detect});
            }
        }
        // known location + unsigned/trusted -> not flagged; this is the
        // normal case for most legitimate JVM native libraries.
    } while (Module32NextW(snap, &entry));

    CloseHandle(snap);
    return findings;
}

} // namespace scanner
