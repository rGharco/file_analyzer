# Set minimum CMake version
cmake_minimum_required(VERSION 3.28.3)

# Setup project name and language
project(gorgot C)

# Setup C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

#Add subdirectories
add_subdirectory(src)

# Add executable 
add_executable(gorgot main.c)

# Add libraries
find_package(OpenSSL REQUIRED)
target_link_libraries(allLibraries PRIVATE OpenSSL::Crypto m)
target_link_libraries(gorgot PRIVATE allLibraries)

# Include headers
target_include_directories(gorgot PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Set compiler flags
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O3")
