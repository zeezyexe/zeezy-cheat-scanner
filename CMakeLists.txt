cmake_minimum_required(VERSION 3.22)
project(DaxyCheatScanner VERSION 1.0.4 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(glfw3 CONFIG REQUIRED)
find_package(imgui CONFIG REQUIRED)
find_package(OpenGL REQUIRED)

# Single source of truth for the version string shown in the app's own UI -
# generated from this file's project(... VERSION ...) so the two can never
# silently drift apart.
configure_file(src/version.hpp.in ${CMAKE_CURRENT_BINARY_DIR}/generated/version.hpp @ONLY)

add_executable(daxy WIN32
    src/main.cpp
    src/gui/App.cpp
    src/gui/Theme.cpp
    src/gui/Starfield.cpp
    src/scanner/ProcessEnumerator.cpp
    src/scanner/MemoryScanner.cpp
    src/scanner/ClasspathScanner.cpp
    src/scanner/BypassScanner.cpp
    src/scanner/PEIntegrityScanner.cpp
    src/scanner/ModuleTrustScanner.cpp
    src/scanner/PrefetchScanner.cpp
    src/scanner/ExternalToolScanner.cpp
    src/scanner/HiddenPayloadScanner.cpp
    src/report/ReportGenerator.cpp
)

target_include_directories(daxy PRIVATE src ${CMAKE_CURRENT_BINARY_DIR}/generated)
set_target_properties(daxy PROPERTIES OUTPUT_NAME "Daxy Cheat Scanner")

target_link_libraries(daxy PRIVATE
    glfw
    imgui::imgui
    OpenGL::GL
    psapi
    dwmapi
    shell32
    wevtapi
    wintrust
    crypt32
)

if(MSVC)
    target_link_options(daxy PRIVATE
        "/MANIFEST:EMBED"
        "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'"
    )
endif()
