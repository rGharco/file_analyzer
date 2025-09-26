#ifndef PRINT_HELPER_H
#define PRINT_HELPER_H
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdarg.h>

#if _WIN32
#include <windows.h>
#endif

void print_banner();
void print_usage(const char* main_exe);
void print_legend();
void print_action(const char* message);
void print_error(const char* message);
void print_success(const char* message);
void print_checkpoint(const char* message);
void print_warning(const char* messsage);

int checkArgs(const int count, ...);

#endif
