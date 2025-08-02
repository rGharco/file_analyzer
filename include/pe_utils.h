#ifndef PE_UTILS_H
#define PE_UTILS_H
#include "../include/file_context.h"
#include "../include/pattern.h"

bool matches_ms_dos_signature(File_Context* file_context, const Pattern* ms_dos);
uint32_t get_pe_header_offset(File_Context* file_context);
bool has_pe_signature(File_Context* file_context, const Pattern* pe_signature);
bool is_executable(File_Context* file_context, const Pattern* ms_dos, const Pattern* pe_signature);

bool parse_coff_header(File_Context* file_context);
void print_coff_header(const File_Context* file_context);
const char* get_machine_type_name(uint16_t machine_type);

bool get_magic_number(File_Context* file_context);
bool parse_optional_header(File_Context* file_context);
void print_optional_header_info(const Optional_Header* optional_header);


#endif