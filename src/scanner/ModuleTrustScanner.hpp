#pragma once

#include "scanner/MemoryScanner.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace scanner {

struct ModuleTrustFinding {
    std::string moduleName;
    std::string detail;
    Severity severity;
};

// Walks every DLL loaded inside the target process and checks two things
// for each: whether it lives somewhere a legitimate game/JVM library
// would (the game's own directory tree, a known launcher directory, or
// the JRE's own directory), and whether it carries a valid Authenticode
// signature.
//
// A DLL that is both outside any expected location AND unsigned/
// invalidly-signed is the strongest signal of an injected payload; a
// signature that is actively invalid/tampered is flagged regardless of
// location. An unsigned DLL that DOES live somewhere expected is not
// flagged at all - most legitimate JVM native libraries (LWJGL, JNA,
// etc.) are routinely unsigned, so flagging on that alone would be
// noise, not signal.
//
// Windows system directories (System32/SysWOW64) are skipped entirely:
// compromised OS-level DLLs are a different threat model than an
// injected game cheat, and are out of scope for this tool.
std::vector<ModuleTrustFinding> ScanModuleTrust(uint32_t pid);

}
