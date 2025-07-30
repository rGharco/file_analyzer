#ifndef PE_UTILS_H
#define PE_UTILS_H
#include "../include/file_context.h"
#include "../include/pattern.h"

bool matches_ms_dos_signature(File_Context* file_context, const Pattern* ms_dos);
uint32_t get_pe_header_offset(File_Context* file_context);
bool has_pe_signature(File_Context* file_context, const Pattern* pe_signature);
bool is_executable(File_Context* file_context, const Pattern* ms_dos, const Pattern* pe_signature);
void parse_coff_header(File_Context** file_context);
void print_coff_header(const File_Context* file_context);
void print_action(const char* message);
const char* get_machine_type_name(uint16_t machine_type);
void parse_optional_header(File_Context** file_context);

#endif