#include "scanner/ClasspathScanner.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <shellapi.h>

#include <algorithm>
#include <cwctype>
#include <fstream>

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

struct RemoteUStr {
    USHORT Length;
    USHORT MaximumLength;
    PVOID Buffer;
};

std::wstring ReadRemoteUnicodeStringW(HANDLE process, PVOID ustrAddr) {
    RemoteUStr us{};
    SIZE_T br = 0;
    if (!ReadProcessMemory(process, ustrAddr, &us, sizeof(us), &br) || !us.Buffer || us.Length == 0)
        return {};
    std::wstring w(static_cast<size_t>(us.Length / sizeof(wchar_t)), L'\0');
    if (!ReadProcessMemory(process, us.Buffer, w.data(), us.Length, &br))
        return {};
    return w;
}

// Walks the target process's PEB to read its raw command line (no environment
// block mixed in), matching the layout MemoryScanner already relies on.
std::wstring ReadRemoteCommandLine(HANDLE process) {
    using NtQIP_t = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static auto NtQIP = reinterpret_cast<NtQIP_t>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));
    if (!NtQIP) return {};

    struct PBI {
        PVOID ExitStatus;
        PVOID PebBaseAddress;
        PVOID AffinityMask;
        PVOID BasePriority;
        PVOID UniqueProcessId;
        PVOID InheritedFromUniqueProcessId;
    };
    PBI pbi{};
    ULONG retLen = 0;
    if (NtQIP(process, 0, &pbi, sizeof(pbi), &retLen) != 0 || !pbi.PebBaseAddress)
        return {};

    PVOID procParams = nullptr;
    SIZE_T br = 0;
    if (!ReadProcessMemory(process,
            reinterpret_cast<BYTE*>(pbi.PebBaseAddress) + 0x20,
            &procParams, sizeof(procParams), &br) || !procParams)
        return {};

    return ReadRemoteUnicodeStringW(process, reinterpret_cast<BYTE*>(procParams) + 0x70);
}

// Directory fragments that are normal, launcher-managed locations for a
// Minecraft game instance's classpath entries. Anything outside these is
// flagged, since legitimate libraries/mods are always loaded from here.
const std::vector<std::wstring>& KnownLauncherMarkers() {
    static const std::vector<std::wstring> markers = {
        L"\\.minecraft\\libraries\\",
        L"\\.minecraft\\versions\\",
        L"\\.minecraft\\mods\\",
        L"\\prismlauncher\\",
        L"\\polymc\\",
        L"\\multimc\\",
        L"\\atlauncher\\",
        L"\\the feed the beast\\",
        L"\\.technic\\",
        L"\\curseforge\\minecraft\\",
        L"\\gdlauncher_next\\",
        L"\\tlauncher\\",
        L"\\.lunarclient\\",
        L"\\.badlion\\",
        L"\\modrinth\\",
        L"\\overwolf\\minecraft\\",
    };
    return markers;
}

bool IsKnownGameLocation(const std::wstring& lowerPath) {
    for (const auto& marker : KnownLauncherMarkers()) {
        if (lowerPath.find(marker) != std::wstring::npos) return true;
    }
    return false;
}

std::vector<std::wstring> SplitClasspath(const std::wstring& cp) {
    std::vector<std::wstring> parts;
    std::wstring cur;
    for (wchar_t c : cp) {
        if (c == L';') {
            if (!cur.empty()) parts.push_back(cur);
            cur.clear();
        } else {
            cur += c;
        }
    }
    if (!cur.empty()) parts.push_back(cur);
    return parts;
}

std::wstring ExtractClasspathValue(const std::vector<std::wstring>& tokens) {
    const std::wstring prefix = L"-Djava.class.path=";
    for (size_t i = 0; i < tokens.size(); ++i) {
        const std::wstring& t = tokens[i];
        if ((t == L"-cp" || t == L"-classpath") && i + 1 < tokens.size()) {
            return tokens[i + 1];
        }
        if (t.rfind(prefix, 0) == 0) {
            return t.substr(prefix.size());
        }
    }
    return {};
}

std::wstring Trim(std::wstring s) {
    size_t start = s.find_first_not_of(L" \t\r\n");
    if (start == std::wstring::npos) return {};
    size_t end = s.find_last_not_of(L" \t\r\n");
    return s.substr(start, end - start + 1);
}

// Some launchers (Forge/modpacks especially) put the full argument list in an
// @argfile because the classpath would otherwise exceed the command line
// length limit. One argument per line, optionally quoted.
std::vector<std::wstring> ReadArgfileTokens(const std::wstring& path) {
    std::vector<std::wstring> tokens;
    std::wifstream in(path);
    if (!in.is_open()) return tokens;
    std::wstring line;
    while (std::getline(in, line)) {
        line = Trim(line);
        if (line.empty()) continue;
        if (line.size() >= 2 && line.front() == L'"' && line.back() == L'"') {
            line = line.substr(1, line.size() - 2);
        }
        tokens.push_back(line);
    }
    return tokens;
}

} // namespace

std::vector<ClasspathFinding> ScanClasspath(uint32_t pid) {
    std::vector<ClasspathFinding> findings;

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!process) return findings;

    std::wstring cmdLine = ReadRemoteCommandLine(process);
    CloseHandle(process);
    if (cmdLine.empty()) return findings;

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(cmdLine.c_str(), &argc);
    if (!argv) return findings;

    std::vector<std::wstring> tokens(argv, argv + argc);
    LocalFree(argv);

    for (const auto& t : tokens) {
        if (!t.empty() && t.front() == L'@') {
            std::vector<std::wstring> fileTokens = ReadArgfileTokens(t.substr(1));
            tokens.insert(tokens.end(), fileTokens.begin(), fileTokens.end());
        }
    }

    std::wstring classpath = ExtractClasspathValue(tokens);
    if (classpath.empty()) return findings;

    for (const auto& entry : SplitClasspath(classpath)) {
        std::wstring lower = ToLowerW(entry);
        if (IsKnownGameLocation(lower)) continue;

        const bool isJar = lower.size() >= 4 && lower.compare(lower.size() - 4, 4, L".jar") == 0;

        ClasspathFinding f;
        f.path = NarrowAscii(entry);
        f.reason = isJar
            ? "Classpath jar outside any known Minecraft/launcher directory"
            : "Non-standard classpath entry";
        findings.push_back(std::move(f));
    }

    return findings;
}

} // namespace scanner
