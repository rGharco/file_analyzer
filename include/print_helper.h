#ifndef PRINT_HELPER_H
#define PRINT_HELPER_H
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "../include/file_context.h"

void print_banner();
void print_usage(const char* main_exe);
void print_action(const char* message);
void print_error(const char* message);
void print_success(const char* message);
void print_checkpoint(const char* message);
void print_warning(const char* messsage);

void print_coff_header(const File_Context* file_context);
void print_optional_header(const File_Context* file_context);
void print_section_headers(const File_Context* fc);

#endif