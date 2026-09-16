#pragma once

#include "scanner/MemoryScanner.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace scanner {

struct HiddenPayloadFinding {
    std::string moduleName;
    std::string detail;
    Severity severity;
};

// Checks every DLL loaded in the target process for data appended after
// where its own PE section table says the file should end ("overlay
// data"). This is the standard technique behind binders/crypters/
// "fakers" that hide a second payload inside an otherwise-legitimate
// host file: the host loads and runs normally, and a small stub
// extracts/loads the extra data appended past its real end.
//
// A module's declared image size in memory isn't a reliable signal here
// (the loader only maps what the section table describes either way);
// this specifically compares the file's actual size ON DISK against
// where its last section's raw data ends.
std::vector<HiddenPayloadFinding> ScanForHiddenPayloads(uint32_t pid);

}
