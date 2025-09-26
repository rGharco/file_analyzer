# Set minimum CMake version
cmake_minimum_required(VERSION 3.28.3...4.0)

# Setup project name and language
project(gorgot
        VERSION 1.0     
        LANGUAGES C
        )

# Setup C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Windows Build
if (WIN32) 
    # Add executable 
    add_executable(gorgot windows/main.c)

    # Add general libraries
    find_package(OpenSSL REQUIRED)  

    # Add subdirectories
    add_subdirectory(common/src)
    add_subdirectory(windows/src)

    # Add libraries
    target_link_libraries(gorgot PRIVATE
        allLibraries
        windowsLibrary
        OpenSSL::Crypto
        m
    )
endif()

# Set compiler flags
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O3 -march=native")
