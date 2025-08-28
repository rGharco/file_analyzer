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
    bool has_ms_dos_signature;
    uint32_t pe_signature_start_byte;
    bool is_pe;
    COFF_Header* coff_header;
    Optional_Header* optional_header;
    Section_Header* sections;
} File_Context;

typedef enum {
    FILE_CONTEXT_SUCCESS,
    FILE_CONTEXT_ERR_ALLOC, 
    FILE_CONTEXT_ERR_FOPEN,
    FILE_CONTEXT_ERR_FREAD,
    FILE_CONTEXT_ERR_NO_PATH_OR_MODE,
} Fc_Status;

Fc_Status create_file_context(const char* path, const char* mode, File_Context** ctx);
static uint64_t get_file_size(const File_Context* file_context);
static uint64_t get_file_size_win(const char* path);
void free_file_context(File_Context* file_context);
const char* fc_status_str(Fc_Status status);

#endif
