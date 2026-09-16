#include "scanner/HiddenPayloadScanner.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <TlHelp32.h>

#include <algorithm>
#include <cstdint>

namespace scanner {

namespace {

std::string NarrowAscii(const wchar_t* w) {
    std::string out;
    for (const wchar_t* p = w; *p; ++p)
        out += (*p > 0 && *p < 128) ? static_cast<char>(*p) : '?';
    return out;
}

bool ReadAt(HANDLE file, LONGLONG offset, void* buf, DWORD size) {
    LARGE_INTEGER li{};
    li.QuadPart = offset;
    if (!SetFilePointerEx(file, li, nullptr, FILE_BEGIN)) return false;
    DWORD read = 0;
    return ReadFile(file, buf, size, &read, nullptr) && read == size;
}

// Computes where a PE file's declared content should end: the furthest
// point covered by a section's raw data, or the end of the Authenticode
// certificate table if the file is signed (that table is one of the few
// legitimate cases where real data sits past every section - its file
// offset comes from IMAGE_DIRECTORY_ENTRY_SECURITY, which uniquely among
// data directories is a raw file offset rather than an RVA). Anything
// past that point in the file on disk is overlay data the linker didn't
// put there.
bool ComputeExpectedFileEnd(HANDLE file, uint64_t& expectedEnd) {
    IMAGE_DOS_HEADER dos{};
    if (!ReadAt(file, 0, &dos, sizeof(dos))) return false;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (dos.e_lfanew <= 0 || dos.e_lfanew > 0x1000) return false;

    DWORD ntSignature = 0;
    if (!ReadAt(file, dos.e_lfanew, &ntSignature, sizeof(ntSignature))) return false;
    if (ntSignature != IMAGE_NT_SIGNATURE) return false;

    IMAGE_FILE_HEADER fileHeader{};
    const LONGLONG fileHeaderOffset = dos.e_lfanew + static_cast<LONGLONG>(sizeof(DWORD));
    if (!ReadAt(file, fileHeaderOffset, &fileHeader, sizeof(fileHeader))) return false;

    const LONGLONG optionalHeaderOffset = fileHeaderOffset + static_cast<LONGLONG>(sizeof(IMAGE_FILE_HEADER));
    if (fileHeader.SizeOfOptionalHeader < sizeof(WORD)) return false;

    WORD magic = 0;
    if (!ReadAt(file, optionalHeaderOffset, &magic, sizeof(magic))) return false;

    uint64_t certTableEnd = 0;
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32 opt{};
        if (fileHeader.SizeOfOptionalHeader >= sizeof(opt) &&
            ReadAt(file, optionalHeaderOffset, &opt, sizeof(opt))) {
            const auto& dir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
            if (dir.Size > 0) certTableEnd = static_cast<uint64_t>(dir.VirtualAddress) + dir.Size;
        }
    } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64 opt{};
        if (fileHeader.SizeOfOptionalHeader >= sizeof(opt) &&
            ReadAt(file, optionalHeaderOffset, &opt, sizeof(opt))) {
            const auto& dir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
            if (dir.Size > 0) certTableEnd = static_cast<uint64_t>(dir.VirtualAddress) + dir.Size;
        }
    } else {
        return false; // not a recognizable PE32/PE32+ optional header
    }

    const LONGLONG sectionTableOffset = optionalHeaderOffset + fileHeader.SizeOfOptionalHeader;
    uint64_t sectionsEnd = 0;
    for (WORD i = 0; i < fileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER section{};
        const LONGLONG entryOffset = sectionTableOffset + static_cast<LONGLONG>(i) * sizeof(section);
        if (!ReadAt(file, entryOffset, &section, sizeof(section))) break;
        if (section.SizeOfRawData > 0) {
            const uint64_t end = static_cast<uint64_t>(section.PointerToRawData) + section.SizeOfRawData;
            sectionsEnd = std::max(sectionsEnd, end);
        }
    }

    expectedEnd = std::max(sectionsEnd, certTableEnd);
    return expectedEnd > 0;
}

} // namespace

std::vector<HiddenPayloadFinding> ScanForHiddenPayloads(uint32_t pid) {
    std::vector<HiddenPayloadFinding> findings;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return findings;

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (Module32FirstW(snap, &entry)) {
        do {
            const std::string moduleName = NarrowAscii(entry.szModule);

            HANDLE file = CreateFileW(entry.szExePath, GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE) continue;

            LARGE_INTEGER fileSize{};
            uint64_t expectedEnd = 0;
            if (GetFileSizeEx(file, &fileSize) && ComputeExpectedFileEnd(file, expectedEnd)) {
                const uint64_t actualSize = static_cast<uint64_t>(fileSize.QuadPart);
                // Linkers routinely pad the file to its FileAlignment, so
                // allow a page's worth of slack before treating the gap
                // as meaningful - a real bound/hidden payload is
                // overwhelmingly larger than that.
                constexpr uint64_t kSlack = 4096;
                if (actualSize > expectedEnd + kSlack) {
                    const uint64_t extra = actualSize - expectedEnd;
                    findings.push_back({moduleName,
                        std::to_string(extra) + " bytes appended after the end of this file's "
                        "declared PE content (possible bound/hidden payload)",
                        Severity::Suspicious});
                }
            }

            CloseHandle(file);
        } while (Module32NextW(snap, &entry));
    }

    CloseHandle(snap);
    return findings;
}

} // namespace scanner
