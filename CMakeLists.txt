cmake_minimum_required(VERSION 3.16)
project(EA_DLC_Unlocker_v2 VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Detours
find_package(Detours REQUIRED)

# Add the DLL
add_library(version SHARED
    src/version_complete_working.cpp
)

# Set properties
set_target_properties(version PROPERTIES
    PREFIX ""
    SUFFIX ".dll"
    MSVC_RUNTIME_LIBRARY "MultiThreadedDLL"
)

# Link libraries
target_link_libraries(version PRIVATE
    kernel32
    user32
    shell32
    wininet
    Detours::Detours
)

# Include directories
target_include_directories(version PRIVATE
    ${Detours_INCLUDE_DIRS}
)

# Add DEF file
if(MSVC)
    set_target_properties(version PROPERTIES
        LINK_FLAGS "/DEF:${CMAKE_SOURCE_DIR}/src/version.def"
    )
endif()

# Optional: Add tests
if(BUILD_TESTING)
    enable_testing()
    # Add test executables here
endif()

# Installation
install(TARGETS version
    LIBRARY DESTINATION bin
    RUNTIME DESTINATION bin
)
install(FILES src/version.def DESTINATION bin)