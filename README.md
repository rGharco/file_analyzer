# file_analyzer
C based program that performs file analysis for malicious patterns and flags potential unwanted files.

# HOW TO COMPILE

```bash
gcc src/main.c src/pattern.c src/file_context.c src/pe_utils.c src/constants.c src/print_helper.c -Iinclude -o bin/main.exe
``` 
