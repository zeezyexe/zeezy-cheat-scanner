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
// invalidly-signed is the strongest signal of an injected payload
// (Severity::Detect); a signature that is actively invalid/tampered is
// flagged the same way regardless of location. A validly-signed DLL is
// never flagged for its location alone (a real Authenticode signature is
// a genuine identity-verified barrier a cheat author is unlikely to
// cross, and legitimate gaming overlays/capture tools/Defender's own
// hooks routinely inject signed DLLs from locations this tool can't
// enumerate in advance) - only an UNsigned DLL outside any expected
// location is flagged. An unsigned DLL that DOES live somewhere expected
// is still reported, just at a lower severity (Severity::Suspicious) -
// most legitimate JVM native libraries (LWJGL, JNA, etc.) are routinely
// unsigned, but a directory isn't trusted outright just because it's the
// game's own folder, since an unsigned cheat dropped there looks
// identical from location alone. The one exception is the JRE's own
// bin/lib directory specifically (not the whole game/launcher tree):
// anything there is definitionally part of the JVM that's currently
// running, so it's never flagged even when unsigned (common for several
// OpenJDK redistributions).
//
// Windows system directories (System32, SysWOW64, and WinSxS) are
// skipped entirely: compromised OS-level DLLs are a different threat
// model than an injected game cheat, and are out of scope for this tool.
std::vector<ModuleTrustFinding> ScanModuleTrust(uint32_t pid);

}
