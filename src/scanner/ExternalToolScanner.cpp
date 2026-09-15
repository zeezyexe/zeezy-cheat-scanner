#include "scanner/ExternalToolScanner.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <TlHelp32.h>

#include <algorithm>

namespace scanner {

namespace {

std::string NarrowAscii(const wchar_t* w) {
    std::string out;
    for (const wchar_t* p = w; *p; ++p)
        out += (*p > 0 && *p < 128) ? static_cast<char>(*p) : '?';
    return out;
}

std::string UpperAscii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return s;
}

struct ToolEntry {
    const char* name;
    Severity severity;
};

// High confidence: dedicated injector/macro tools that essentially have
// no legitimate unrelated use case. Low confidence: general-purpose
// automation/scripting runtimes that are *sometimes* used to build
// external macros but also have many ordinary uses on their own - worth
// a human look, not proof by themselves.
const std::vector<ToolEntry>& KnownTools() {
    static const std::vector<ToolEntry> tools = {
        {"198MACROS.EXE", Severity::Detect},
        {"PRESTIGEINJECTOR.EXE", Severity::Detect},
        {"VAPE INJECTOR.EXE", Severity::Detect},
        {"VAPEINJECTOR.EXE", Severity::Detect},
        {"VIRGIN INJECTOR.EXE", Severity::Detect},
        {"VIRGININJECTOR.EXE", Severity::Detect},

        {"AUTOHOTKEY.EXE", Severity::Warning},
        {"AUTOHOTKEYU64.EXE", Severity::Warning},
        {"AUTOHOTKEYU32.EXE", Severity::Warning},
        {"AUTOHOTKEY32.EXE", Severity::Warning},
        {"AUTOHOTKEY64.EXE", Severity::Warning},
        {"AUTOIT3.EXE", Severity::Warning},
        {"PYTHON.EXE", Severity::Warning},
        {"PYTHONW.EXE", Severity::Warning},
    };
    return tools;
}

} // namespace

std::vector<ExternalToolFinding> ScanForExternalTools() {
    std::vector<ExternalToolFinding> findings;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return findings;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snap, &entry)) {
        do {
            const std::string upperName = UpperAscii(NarrowAscii(entry.szExeFile));

            for (const auto& tool : KnownTools()) {
                if (upperName == tool.name) {
                    findings.push_back({NarrowAscii(entry.szExeFile), entry.th32ProcessID, tool.severity});
                    break;
                }
            }
        } while (Process32NextW(snap, &entry));
    }

    CloseHandle(snap);
    return findings;
}

} // namespace scanner
