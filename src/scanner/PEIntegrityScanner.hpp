#pragma once

#include "scanner/MemoryScanner.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace scanner {

struct PEIntegrityFinding {
    std::string moduleName;
    std::string detail;
    Severity severity;
};

// Enumerates the target process's normally-loaded modules (via Toolhelp32,
// same as a legitimate LoadLibrary/PEB module list walk) and checks whether
// each module's PE header (DOS "MZ" + NT "PE\0\0" signatures) is still
// intact at its base address. A module that IS in the loader's module list
// but no longer has a valid header in memory has almost certainly had its
// header erased on purpose - a common technique to defeat tools that dump
// or verify modules by walking that same list.
std::vector<PEIntegrityFinding> ScanForErasedPEHeaders(uint32_t pid);

}
