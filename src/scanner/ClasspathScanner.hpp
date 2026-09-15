#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace scanner {

struct ClasspathFinding {
    std::string path;
    std::string reason;
};

// Reads the target javaw.exe process's JVM classpath (from its command line,
// following an @argfile if the launcher used one) and returns every entry
// that does not live under a recognized Minecraft/launcher directory.
std::vector<ClasspathFinding> ScanClasspath(uint32_t pid);

}
