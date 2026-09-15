#pragma once

#include <string>
#include <vector>

namespace scanner {

struct PrefetchFinding {
    std::string prefetchFile;
    std::string matchedTool;
};

// Scans %WINDIR%\Prefetch for entries whose executable name matches a
// known injector/macro/cheat-tool name. Prefetch records that a program
// was executed on this machine even if it has since been deleted, so this
// catches evidence of past use, not just currently-running tools.
//
// This only inspects the prefetch FILENAME (Windows names each entry
// "EXENAME-HASH.pf"). It does not parse the compressed internal contents
// of the .pf file itself (its embedded list of referenced DLLs, run
// timestamps, etc.) - modern Windows prefetch files use version-specific
// MAM/Xpress-Huffman compression, and reliably decompressing that is out
// of scope here.
std::vector<PrefetchFinding> ScanPrefetchForKnownTools();

}
