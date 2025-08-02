#include "../include/print_helper.h"

void print_usage(const char* main_exe) {
    printf("\nUsage: %s <filename> -<flag>\n\n"
           "Flags:\n"
           "  -b  -> scans for a binary file and matches patterns\n"
           "  -e  -> scans for an executable file and finds information\n\n",
           main_exe);
}


void print_action(const char* message) {
	const uint8_t message_length = 100;
	const char* tag = "[ACTION]";
	const uint8_t tag_len = 8; 
    const uint8_t tag_space = 1; 
    const uint8_t padding_space = 2; 
	const uint8_t padding = ((message_length - strlen(message) - tag_space - tag_space - padding_space) / 2);

	printf("\n%s ", tag);
	for(register int i = 0; i < padding; i++) {
		putchar('=');
	}
	printf(" %s ", message);
	for(register int i = 0; i < padding; i++) {
		putchar('=');
	}
	printf(" %s\n\n", tag);
}

void print_error(const char* message) {
	printf("[-] %s\n", message);
}

void print_warning(const char* message) {
	printf("[!] Warning: %s\n", message);
}