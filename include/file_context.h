#ifndef FILE_CONTEXT_H
#define FILE_CONTEXT_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "../include/coff_header.h"
#include "../include/optional_header.h"
#include "../include/section_header.h"

typedef struct {
    FILE* file;
    char* path;
    char* mode;
    uint64_t size;
    uint8_t* buffer;
    bool has_ms_dos_signature;
    uint32_t pe_signature_start_byte;
    bool is_pe;
    COFF_Header* coff_header;
    Optional_Header* optional_header;
    Section_Header* sections;
} File_Context;

File_Context* create_file_context(const char* path, const char* mode);
uint64_t get_file_size(const File_Context* file_context);
uint64_t get_file_size_win(const char* path);
void free_file_context(File_Context* file_context);

#endif