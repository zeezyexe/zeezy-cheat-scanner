# Daxy Cheat Scanner

A screenshare tool that scans a `java.exe`/`javaw.exe` process's memory (ASCII and UTF-16,
private/mapped/image regions) for known and unknown cheat strings, cross-checks its JVM
classpath and loaded modules, checks the local PC for anti-forensic "bypass" techniques, and
looks for external injectors, macro tools, and payload-hiding tricks. Findings correlate
across independent categories rather than resting on any single signal — see "Evidence
Summary" in the generated report.

**Ground rule:** this is meant to be run by the person whose PC is being checked, with them
watching the same screen (a screenshare verification), not run covertly against someone
without their knowledge.

Showcase: https://streamable.com/oqqkj8

DC Server: https://discord.gg/GkD535S2qh

Discord: .daxy

## Download

Prebuilt binaries are published automatically on the [Releases](../../releases) page whenever
a version tag is pushed — no build tools required, just download and run.

## Features

- **Memory scan** — searches the target process's readable memory (private allocations, mapped
  file views, and loaded images — not just private memory) for known cheat/mod signatures, in
  both raw ASCII and UTF-16LE (how Java actually stores `String` objects — on Java 8, required
  by many Minecraft versions, *every* string is UTF-16 regardless of content). Matches spanning
  a chunk-read boundary are caught via a carried-over overlap buffer, and reported addresses
  point at the real match location rather than the containing chunk's start
  (`src/scanner/MemoryScanner.cpp`). The signature lists ship empty by design — fill in
  `kRedDetections`, `kYellowDetections`, etc. with your own strings.
- **Classpath scan** — reads the JVM's actual `-cp`/`-classpath` (following one or more nested
  `@argfile`s, with real quoting/escaping/comment support per the documented argfile format;
  the last `-cp` wins if more than one is present, matching real `java` semantics) and flags
  entries outside any known launcher-managed directory (`src/scanner/ClasspathScanner.cpp`).
- **PC Bypass Methods** — checks the local machine for signs someone disabled or cleared the
  artifacts that would normally record what ran (SysMain/DPS/BAM/DCOM/EventLog service state,
  PowerShell logging policy, Prefetch, the USN journal, Amcache, Activities Cache, and recent
  Recycle Bin activity) (`src/scanner/BypassScanner.cpp`).
- **PE header integrity** — verifies every module normally loaded in the target process still
  has an intact DOS/NT header in memory; an erased header on a loaded module is a common
  self-hiding technique (`src/scanner/PEIntegrityScanner.cpp`).
- **Module trust** — checks every DLL loaded in the target process for both its location (game/
  launcher directory vs. somewhere unexpected) and its Authenticode signature. An unsigned DLL
  outside any expected location, or an actively tampered signature anywhere, is the strongest
  signal; an unsigned DLL that IS in an expected game/launcher directory is still reported (at
  lower severity) rather than silently trusted — only a validly-signed module in an expected
  location goes unflagged (`src/scanner/ModuleTrustScanner.cpp`).
- **Hidden payload ("faker") scan** — checks every loaded DLL's file on disk for data appended
  past where its own PE section table says it should end (the classic binder/crypter technique
  for hiding a second payload inside an otherwise-legitimate host file)
  (`src/scanner/HiddenPayloadScanner.cpp`).
- **Prefetch scan** — checks `%WINDIR%\Prefetch` for evidence a known injector/macro tool was
  run on this machine, even if it's since been deleted. This only matches on filename; it does
  not parse the compressed internal contents of `.pf` files (`src/scanner/PrefetchScanner.cpp`).
- **External tool scan** — enumerates *every* running process (not just the game) for known
  standalone injectors and macro/automation tools (`src/scanner/ExternalToolScanner.cpp`). The
  seeded list is a starting point, not exhaustive — extend `KnownTools()` with any additional
  executable names you want covered.
- **Java agent detection** — flags any `-javaagent:` JVM flag found on the command line
  (`src/scanner/MemoryScanner.cpp`); a legitimate mechanism (profilers, APM tools) an injected
  client can equally use to bootstrap itself.
- **Evidence correlation & scan transparency** — the report's Evidence Summary shows how many
  *independent* categories fired rather than treating any single generic string/stopped
  service/missing log/recent deletion as a verdict, and a Scan Notes section lists memory that
  couldn't be read and any rule category with nothing loaded, so gaps are visible instead of
  silently read as "clean."
- **Report redaction** — the Windows account name in any path shown in the report is replaced
  with `<redacted>` before it's written, since reports get shared/screenshotted.
- **Distinctive Clients** — a separate, high-confidence tab for signatures verified against real
  cheat-client sample jars. Several known clients ship as trojanized copies of real, popular
  mods (matching the real mod's manifest/id/description exactly, with combat-cheat modules
  injected directly into the real mod's own package namespace), so these signatures
  deliberately key on the recurring module class names and injected sub-paths that are
  consistent across every disguise seen so far, rather than on outer package names — several of
  which belong to genuine mods and would otherwise false-flag real, clean installs. A match
  here is the strongest signal this scan produces, but still confirm it yourself: these clients
  are specifically built to look legitimate, so no automated tool should be the last word before
  a ban.
- Generates a single self-contained HTML report (`detection-results.html`) and opens it in the
  default browser when the scan finishes.

## Known limitations (deliberately out of scope for now)

- **JAR/mod scanning** (manifests, mixin configs, nested jars, content hashes) isn't
  implemented — it needs a real ZIP/deflate reader, which deserves its own focused pass rather
  than being bolted on alongside everything else here.
- **Prefetch matching is filename-only.** The actual embedded file-reference list and
  timestamps inside a `.pf` file require decompressing Windows' MAM/Xpress-Huffman format,
  which is version-specific and easy to get subtly wrong without a large sample corpus to test
  against.
- **Amcache.hve** is checked for existence only — actually parsing program-run records out of
  it means implementing enough of the registry hive binary format to walk it, which is a
  substantial separate effort.
- **No loaded-class/classloader introspection.** That requires attaching into the running JVM
  (the Attach API / JVMTI), a fundamentally different technique from external memory scanning.
- **No automated test suite yet.** The algorithmic pieces (matching, argfile parsing, PE
  parsing, redaction) are unit-testable without a live target and are a natural next addition;
  testing against real cheat/mod samples needs a curated corpus this repo doesn't ship.
- **Releases are unsigned** (no Authenticode certificate) but are hash-verified and carry a
  [SLSA build provenance attestation](../../attestations) — verify with
  `gh attestation verify "Daxy Cheat Scanner.exe" --repo <owner>/<repo>`.

## Prerequisites

- Windows 10/11 (x64)
- [Visual Studio](https://visualstudio.microsoft.com/) with the "Desktop development with C++"
  workload
- [CMake](https://cmake.org/download/) 3.22+
- [vcpkg](https://github.com/microsoft/vcpkg) — the bundled preset expects it cloned into a
  `vcpkg/` folder at the repo root:

  ```bash
  git clone https://github.com/microsoft/vcpkg
  .\vcpkg\bootstrap-vcpkg.bat
  ```

## Building

```bash
cmake --preset release-static
cmake --build --preset release-static
```

The first configure will take a while — vcpkg builds `glfw3` and `imgui` from source for the
static triplet. The resulting binary is `build-static/Release/Daxy Cheat Scanner.exe`.

> The bundled preset targets the `Visual Studio 18 2026` generator. If your installed Visual
> Studio version uses a different generator name, edit `"generator"` in `CMakePresets.json`
> (e.g. `Visual Studio 17 2022` for VS 2022) before configuring.

## Running

The app requests elevation on launch (it needs `PROCESS_VM_READ` on another process and
queries service/registry state that requires admin). Select a detected `java.exe`/`javaw.exe`
process and press **Start Scan**; when it finishes, the report opens automatically in your
browser.

## License

[GPL-3.0](LICENSE).
