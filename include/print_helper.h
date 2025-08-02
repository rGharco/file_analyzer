#ifndef PRINT_HELPER_H
#define PRINT_HELPER_H
#include <stdint.h>
#include <string.h>
#include <stdio.h>

void print_usage(const char* main_exe);
void print_action(const char* message);
void print_error(const char* message);
void print_warning(const char* messsage);

#endif