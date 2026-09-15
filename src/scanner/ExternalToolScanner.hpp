#pragma once

#include "scanner/MemoryScanner.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace scanner {

struct ExternalToolFinding {
    std::string processName;
    uint32_t pid;
    Severity severity;
};

// Enumerates every running process on the system (not just javaw.exe) and
// flags any whose image name matches a known external injector/macro
// tool - covers things that run alongside the game as their own process
// rather than as an in-game mod: standalone DLL injectors, external
// macro/automation engines, and Python interpreters that could be driving
// input or bridging into the game.
std::vector<ExternalToolFinding> ScanForExternalTools();

}
