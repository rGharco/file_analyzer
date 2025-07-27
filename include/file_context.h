#ifndef FILE_CONTEXT_H
#define FILE_CONTEXT_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    FILE* file;
    char* path;
    char* mode;
    size_t size;
    uint8_t* buffer;
    bool has_ms_dos_signature;
    uint32_t pe_signature_start_byte;
    bool is_pe;
    uint32_t time_date_stamp;
} File_Context;

File_Context* create_file_context(const char* path, const char* mode);
void set_pe_flag(File_Context* file_context);
size_t get_file_size(const File_Context* file_context);
void free_file_context(File_Context* file_context);

#endif