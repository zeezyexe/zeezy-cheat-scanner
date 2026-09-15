#include "scanner/PEIntegrityScanner.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <TlHelp32.h>

namespace scanner {

namespace {

// Real PE files never need e_lfanew this large; anything bigger means the
// DOS header field itself has been corrupted rather than legitimately
// pointing at an NT header.
constexpr LONG kMaxLfanew = 0x1000;

std::string NarrowAscii(const wchar_t* w) {
    std::string out;
    for (const wchar_t* p = w; *p; ++p)
        out += (*p > 0 && *p < 128) ? static_cast<char>(*p) : '?';
    return out;
}

} // namespace

std::vector<PEIntegrityFinding> ScanForErasedPEHeaders(uint32_t pid) {
    std::vector<PEIntegrityFinding> findings;

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!process) return findings;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        CloseHandle(process);
        return findings;
    }

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (Module32FirstW(snap, &entry)) {
        do {
            const std::string moduleName = NarrowAscii(entry.szModule);

            IMAGE_DOS_HEADER dosHeader{};
            SIZE_T bytesRead = 0;
            if (!ReadProcessMemory(process, entry.modBaseAddr, &dosHeader, sizeof(dosHeader), &bytesRead) ||
                bytesRead != sizeof(dosHeader)) {
                findings.push_back({moduleName,
                    "Module base memory could not be read (unmapped or protected)",
                    Severity::Warning});
                continue;
            }

            if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
                findings.push_back({moduleName,
                    "DOS header ('MZ') missing or erased at module base",
                    Severity::Detect});
                continue;
            }

            if (dosHeader.e_lfanew <= 0 || dosHeader.e_lfanew > kMaxLfanew) {
                findings.push_back({moduleName,
                    "DOS header e_lfanew field is out of range (corrupted header)",
                    Severity::Detect});
                continue;
            }

            DWORD ntSignature = 0;
            if (!ReadProcessMemory(process,
                    reinterpret_cast<BYTE*>(entry.modBaseAddr) + dosHeader.e_lfanew,
                    &ntSignature, sizeof(ntSignature), &bytesRead) ||
                bytesRead != sizeof(ntSignature)) {
                findings.push_back({moduleName,
                    "NT header region could not be read (unmapped or protected)",
                    Severity::Warning});
                continue;
            }

            if (ntSignature != IMAGE_NT_SIGNATURE) {
                findings.push_back({moduleName,
                    "NT header ('PE') missing or erased",
                    Severity::Detect});
                continue;
            }
        } while (Module32NextW(snap, &entry));
    }

    CloseHandle(snap);
    CloseHandle(process);
    return findings;
}

} // namespace scanner
