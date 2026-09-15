#pragma once

#include <string>
#include <vector>

namespace scanner {

struct BypassFinding {
    std::string name;
    std::string detail;
};

// System-wide checks (independent of the target javaw.exe process) for
// common anti-forensic "bypass" techniques: disabling or clearing the
// Windows artifacts that would normally record what ran on the machine
// and when.
std::vector<BypassFinding> ScanForBypassMethods();

}
