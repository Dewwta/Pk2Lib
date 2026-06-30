cmake_minimum_required(VERSION 3.20)
project(Pk2Lib VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build as a static library instead of a DLL
option(PK2_LIB_STATIC "Build Pk2Lib as a static library" OFF)

set(SRCS
    src/Blowfish.cpp
    src/Pk2Archive.cpp
)

if(PK2_LIB_STATIC)
    add_library(Pk2Lib STATIC ${SRCS})
    target_compile_definitions(Pk2Lib PUBLIC PK2_LIB_STATIC)
else()
    add_library(Pk2Lib SHARED ${SRCS})
    target_compile_definitions(Pk2Lib PRIVATE PK2_LIB_EXPORTS)
endif()

target_include_directories(Pk2Lib
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(MSVC)
    # Static CRT so the DLL runs without the VC++ redistributable.
    set_target_properties(Pk2Lib PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    )

    target_compile_options(Pk2Lib PRIVATE /arch:SSE2)

    target_compile_definitions(Pk2Lib PRIVATE
        $<$<NOT:$<CONFIG:Debug>>:_ITERATOR_DEBUG_LEVEL=1>
    )

    # Warn early if the toolset will produce a DLL that won't load on Win7.
    if(MSVC_VERSION GREATER 1938 AND NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
        message(WARNING
            "MSVC toolset ${MSVC_VERSION} > 14.38: the built binary may NOT load on "
            "Windows 7. Build with -vcvars_ver=14.38 for Win7 compatibility.")
    endif()

    target_link_options(Pk2Lib PRIVATE /MACHINE:X86)
endif()

set_target_properties(Pk2Lib PROPERTIES OUTPUT_NAME "Pk2Lib")
