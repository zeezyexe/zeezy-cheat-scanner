# Zeezy Cheat Scanner

A screenshare tool that scans a `javaw.exe` process's memory for known and unknown cheat
strings, cross-checks its JVM classpath for entries outside any known Minecraft/launcher
directory, and separately checks the local PC for common anti-forensic "bypass" techniques
(disabled logging, cleared journals, recently-touched Recycle Bin, etc).

**Ground rule:** this is meant to be run by the person whose PC is being checked, with them
watching the same screen (a screenshare verification), not run covertly against someone
without their knowledge.

Showcase: https://streamable.com/oqqkj8

DC Server: https://discord.gg/GkD535S2qh

Discord: .zeezy

## Download

Prebuilt binaries are published automatically on the [Releases](../../releases) page whenever
a version tag is pushed — no build tools required, just download and run.

## Features

- **Memory scan** — searches the target `javaw.exe` process's readable private memory for
  known cheat/mod signatures (`src/scanner/MemoryScanner.cpp`). The signature lists ship empty
  by design — fill in `kRedDetections`, `kYellowDetections`, etc. with your own strings.
- **Classpath scan** — reads the JVM's actual `-cp`/`-classpath` (following an `@argfile` if the
  launcher used one) and flags any entry that isn't under a recognized launcher-managed
  directory (`src/scanner/ClasspathScanner.cpp`).
- **PC Bypass Methods** — checks the local machine for signs someone disabled or cleared the
  artifacts that would normally record what ran (SysMain/DPS/BAM/DCOM/EventLog service state,
  PowerShell logging policy, Prefetch, the USN journal, Amcache, Activities Cache, and recent
  Recycle Bin activity) (`src/scanner/BypassScanner.cpp`).
- **PE header integrity** — verifies every module normally loaded in the target process still
  has an intact DOS/NT header in memory; an erased header on a loaded module is a common
  self-hiding technique (`src/scanner/PEIntegrityScanner.cpp`).
- **Module trust** — checks every DLL loaded in the target process for both its location (game/
  launcher directory vs. somewhere unexpected) and its Authenticode signature. Only flags a DLL
  that's both outside any expected location *and* unsigned/invalidly signed, or one with an
  actively tampered signature anywhere — a plain unsigned DLL in an expected location (the
  normal case for LWJGL/JNA natives) is not flagged (`src/scanner/ModuleTrustScanner.cpp`).
- **Prefetch scan** — checks `%WINDIR%\Prefetch` for evidence a known injector/macro tool was
  run on this machine, even if it's since been deleted. This only matches on filename; it does
  not parse the compressed internal contents of `.pf` files
  (`src/scanner/PrefetchScanner.cpp`).
- **External tool scan** — enumerates *every* running process (not just javaw.exe) for known
  standalone injectors and macro/automation tools (`src/scanner/ExternalToolScanner.cpp`). The
  seeded list is a starting point, not exhaustive — extend `KnownTools()`/`KnownToolNames()`
  with any additional executable names you want covered.
- Generates a single self-contained HTML report (`detection-results.html`) and opens it in the
  default browser when the scan finishes.

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

The first configure will take a while — vcpkg builds `glfw3`, `imgui`, `curl`, and
`nlohmann-json` from source for the static triplet. The resulting binary is
`build-static/Release/Zeezy Cheat Scanner.exe`.

> The bundled preset targets the `Visual Studio 18 2026` generator. If your installed Visual
> Studio version uses a different generator name, edit `"generator"` in `CMakePresets.json`
> (e.g. `Visual Studio 17 2022` for VS 2022) before configuring.

## Running

The app requests elevation on launch (it needs `PROCESS_VM_READ` on another process and
queries service/registry state that requires admin). Select a detected `javaw.exe` process
and press **Start Scan**; when it finishes, the report opens automatically in your browser.

## License

[GPL-3.0](LICENSE).
