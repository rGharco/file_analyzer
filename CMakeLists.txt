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
target_link_libraries(gorgot PRIVATE allLibraries m)

# Include headers
target_include_directories(gorgot PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
