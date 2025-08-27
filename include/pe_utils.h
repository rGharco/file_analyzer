#ifndef PE_UTILS_H
#define PE_UTILS_H
#include "../include/file_context.h"
#include "../include/pattern.h"

typedef enum {
    PE_PARSE_SUCCESS,
    PE_PARSE_ERR_FREAD,
    PE_PARSE_ERR_FSEEK,
    PE_PARSE_ERR_ALLOC,
    PE_PARSE_ERR_MS_DOS_SIG,
    PE_PARSE_ERR_PE_HEADER_OFFSET,
    PE_PARSE_ERR_PE_SIG,
    PE_PARSE_ERR_COFF_HEADER,
    PE_PARSE_ERR_OPTIONAL_HEADER,
    PE_PARSE_ERR_SECTION_HEADER
} Pe_Parse_Status;

Pe_Parse_Status matches_ms_dos_signature(File_Context* file_context, const Pattern* ms_dos);
Pe_Parse_Status set_pe_header_offset(File_Context* file_context);
Pe_Parse_Status has_pe_signature(File_Context* file_context, const Pattern* pe_signature);
Pe_Parse_Status is_executable(File_Context* file_context, const Pattern* ms_dos, const Pattern* pe_signature);

Pe_Parse_Status parse_coff_header(File_Context* file_context);

const char* get_machine_type_name(uint16_t machine_type);

Pe_Parse_Status get_magic_number(File_Context* file_context, Optional_Header* optional_header);
Pe_Parse_Status parse_optional_header(File_Context* file_context);

Pe_Parse_Status parse_section_header(File_Context* file_context);

#endif