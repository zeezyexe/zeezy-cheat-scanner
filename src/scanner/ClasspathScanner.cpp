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

// Java accepts (and several real-world launchers, PrismLauncher included,
// actually emit) forward slashes in the classpath even on Windows. The
// location markers below are all backslash-delimited, so without this every
// classpath entry from such a launcher would fail every marker check and
// get flagged as "unknown location" - not because it's suspicious, but
// because of a separator mismatch.
std::wstring NormalizeSeparators(std::wstring s) {
    for (auto& c : s) if (c == L'/') c = L'\\';
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

// The LAST -cp/-classpath/-Djava.class.path= wins if more than one is
// present, matching how the real `java` launcher resolves repeated
// options - a wrapper script or launcher that appends its own flags after
// the base command line would otherwise be silently ignored.
std::wstring ExtractClasspathValue(const std::vector<std::wstring>& tokens) {
    const std::wstring prefix = L"-Djava.class.path=";
    std::wstring result;
    for (size_t i = 0; i < tokens.size(); ++i) {
        const std::wstring& t = tokens[i];
        if ((t == L"-cp" || t == L"-classpath") && i + 1 < tokens.size()) {
            result = tokens[i + 1];
        } else if (t.rfind(prefix, 0) == 0) {
            result = t.substr(prefix.size());
        }
    }
    return result;
}

// Some launchers (Forge/modpacks especially) put the full argument list in
// an @argfile because the classpath would otherwise exceed the command
// line length limit. Per the real @argfile format: arguments are
// separated by whitespace (including newlines) rather than one-per-line,
// single/double-quoted sections preserve internal whitespace and support
// backslash-escaping the quote character, and '#' starts a comment that
// runs to end of line.
std::vector<std::wstring> ReadArgfileTokens(const std::wstring& path) {
    std::vector<std::wstring> tokens;
    std::wifstream in(path, std::ios::binary);
    if (!in.is_open()) return tokens;

    std::wstring content((std::istreambuf_iterator<wchar_t>(in)), std::istreambuf_iterator<wchar_t>());
    constexpr size_t kMaxArgfileChars = 8 * 1024 * 1024;
    if (content.size() > kMaxArgfileChars) content.resize(kMaxArgfileChars);

    std::wstring current;
    bool inToken = false;
    bool inQuote = false;
    wchar_t quoteChar = 0;

    size_t i = 0;
    while (i < content.size()) {
        const wchar_t c = content[i];

        if (!inQuote && c == L'#') {
            while (i < content.size() && content[i] != L'\n') ++i;
            continue;
        }

        if (inQuote) {
            if (c == L'\\' && i + 1 < content.size() &&
                (content[i + 1] == quoteChar || content[i + 1] == L'\\')) {
                current += content[i + 1];
                i += 2;
                continue;
            }
            if (c == quoteChar) {
                inQuote = false;
                ++i;
                continue;
            }
            current += c;
            ++i;
            continue;
        }

        if (c == L'"' || c == L'\'') {
            inQuote = true;
            quoteChar = c;
            inToken = true;
            ++i;
            continue;
        }

        if (std::iswspace(c)) {
            if (inToken) {
                tokens.push_back(current);
                current.clear();
                inToken = false;
            }
            ++i;
            continue;
        }

        current += c;
        inToken = true;
        ++i;
    }

    if (inToken) tokens.push_back(current);
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

    // Index-based on purpose: growing `tokens` mid-loop (to expand a
    // nested @argfile reference found inside another argfile) would be
    // undefined behavior with a range-based for, since insert() can
    // reallocate and invalidate the loop's cached iterators. The expansion
    // cap guards against a self-referencing or maliciously crafted argfile
    // causing unbounded growth.
    constexpr size_t kMaxArgfileExpansions = 64;
    size_t argfileExpansions = 0;
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (!tokens[i].empty() && tokens[i].front() == L'@') {
            if (++argfileExpansions > kMaxArgfileExpansions) break;
            std::vector<std::wstring> fileTokens = ReadArgfileTokens(tokens[i].substr(1));
            tokens.insert(tokens.begin() + static_cast<ptrdiff_t>(i) + 1,
                fileTokens.begin(), fileTokens.end());
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
