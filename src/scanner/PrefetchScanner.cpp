#include "scanner/PrefetchScanner.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <cwctype>

namespace scanner {

namespace {

std::string NarrowAscii(const std::wstring& w) {
    std::string out;
    out.reserve(w.size());
    for (wchar_t c : w) out += (c > 0 && c < 128) ? static_cast<char>(c) : '?';
    return out;
}

std::string UpperAscii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return s;
}

// Starter list of external tool executable names seeded from what's
// explicitly known to be relevant here. Windows uppercases prefetch
// filenames, so these are compared case-insensitively regardless.
// Extend this list with any additional tool names you want covered -
// exact filenames vary by tool build, so treat this as a baseline.
const std::vector<std::string>& KnownToolNames() {
    static const std::vector<std::string> names = {
        "198MACROS",
        "PRESTIGEINJECTOR",
        "VAPE INJECTOR", "VAPEINJECTOR",
        "VIRGIN INJECTOR", "VIRGININJECTOR",
    };
    return names;
}

} // namespace

std::vector<PrefetchFinding> ScanPrefetchForKnownTools() {
    std::vector<PrefetchFinding> findings;

    wchar_t winDir[MAX_PATH]{};
    if (GetWindowsDirectoryW(winDir, MAX_PATH) == 0) return findings;

    const std::wstring pattern = std::wstring(winDir) + L"\\Prefetch\\*.pf";

    WIN32_FIND_DATAW entry{};
    HANDLE find = FindFirstFileW(pattern.c_str(), &entry);
    if (find == INVALID_HANDLE_VALUE) return findings;

    do {
        std::wstring fileName = entry.cFileName;

        // Prefetch entries are named "EXENAME-HASH.pf"; take the part
        // before the last hyphen as the executable name.
        std::wstring exeName = fileName;
        const size_t dash = fileName.rfind(L'-');
        if (dash != std::wstring::npos) {
            exeName = fileName.substr(0, dash);
        }

        const std::string upperExeName = UpperAscii(NarrowAscii(exeName));

        for (const auto& known : KnownToolNames()) {
            if (upperExeName.find(known) != std::string::npos) {
                findings.push_back({NarrowAscii(fileName), known});
                break;
            }
        }
    } while (FindNextFileW(find, &entry));

    FindClose(find);
    return findings;
}

} // namespace scanner
