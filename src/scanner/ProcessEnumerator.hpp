#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace scanner {

struct ProcessInfo {
    uint32_t pid{0};
    std::size_t memoryBytes{0};
    std::string startTime;
};

// Matches both javaw.exe and java.exe - some launchers/bundled JREs run
// the console variant instead of the windowed one, so limiting this to
// javaw.exe alone silently misses those instances entirely.
std::vector<ProcessInfo> EnumerateMinecraftJavaProcesses();

}
