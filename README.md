# file_analyzer

C-based program that parses the PE (Portable Executable) header of a file and prints detailed information about it.  

**Status:** In development  

---

## Features & Roadmap

Currently, the tool can read and analyze PE headers. Future enhancements include:  

- **Section analysis**: Flagging unusual section characteristics (e.g., any section besides `.text` marked as executable).  ✅
- **Entropy calculation**: Section-based entropy to detect packed or obfuscated content. ✅  
- **Hash computation**: MD5 and SHA256 hashes stored in a local database with classification flags (Suspicious, Malicious, Clean). 
- **YARA rules**: String and byte pattern matching for malware detection.  
- **CTI sharing**: Reporting findings in TLP-compliant, shareable formats.  
- **Cross-platform support**: Currently tested on Windows and Ubuntu, with ongoing work to improve compatibility.  

**Long-term goal:** Develop this into a lightweight antivirus in C that uses its own rules and techniques to classify files (not just a Python script that's written in C), offering analysts detailed insights. Advanced AV features like memory scanning will be added over time.  

---

## Prerequisites

- **CMake** (minimum version 3.28.3)  
- **GCC** (GNU Compiler Collection) or compatible C compiler  
- **OpenSSL library** 

---

## Installation on Windows

### MSYS2 

- Download the installer and follow the tutorial on their web page to install GCC: https://www.msys2.org/  (remember where you installed it)

- add to PATH the binary folder (example: E:\MYSYS2\ucrt64\bin) 

### CMAKE

- use the following PowerShell command
```powershell
winget install Kitware.CMake
```
### OPENSSL

- install vcpkg using the following series of commands where you wanna install it 

```powershell
cd C:\
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
```

- navigate to vcpkg folder, and run

```powershell
.\vcpkg.exe install openssl:x64-mingw-static
```

- **after this you can go to Compilation**

## Installation on Linux

Just run the `setup_linux.sh` script and it will install everything for you (only works on **Debian-based** linux distros such as Ubuntu, Kali, etc.)

## Compilation

```bash

# On Windows

mkdir build 
cd build 
cmake .. -G "MinGW Makefiles" -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-mingw-static
cmake --build .

# On Linux 

mkdir build
cd build
cmake ..
make
```

# Usage
```bash
./file_analyzer sample.exe -e
```

# Examples

![Screenshot](images/image.png)
![Screenshot](images/image-1.png)
![Screenshot](images/image-2.png)
