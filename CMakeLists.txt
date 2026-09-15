cmake_minimum_required(VERSION 3.22)
project(ZeezyCheatScanner VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(glfw3 CONFIG REQUIRED)
find_package(imgui CONFIG REQUIRED)
find_package(OpenGL REQUIRED)
find_package(CURL CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

add_executable(zeezy WIN32
    src/main.cpp
    src/gui/App.cpp
    src/gui/Theme.cpp
    src/gui/Starfield.cpp
    src/scanner/ProcessEnumerator.cpp
    src/scanner/MemoryScanner.cpp
    src/scanner/ClasspathScanner.cpp
    src/scanner/BypassScanner.cpp
    src/scanner/PEIntegrityScanner.cpp
    src/report/ReportGenerator.cpp
)

target_include_directories(zeezy PRIVATE src)
set_target_properties(zeezy PROPERTIES OUTPUT_NAME "Zeezy Cheat Scanner")

target_link_libraries(zeezy PRIVATE
    glfw
    imgui::imgui
    OpenGL::GL
    CURL::libcurl
    nlohmann_json::nlohmann_json
    psapi
    dwmapi
    shell32
    shlwapi
    wevtapi
)

if(MSVC)
    target_link_options(zeezy PRIVATE
        "/MANIFEST:EMBED"
        "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'"
    )
endif()
