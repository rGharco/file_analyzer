#include <stdlib.h>
#include <string.h>
#include "../include/pattern.h"
#include "../include/file_context.h"
#include "../include/pe_utils.h"
#include "../include/constants.h"
#include "../include/print_helper.h"
#include <time.h>

#define BINARY_READ "rb"
#define BINARY_WRITE "wb"
#define BUFFER_SIZE 255

void find_patterns(const uint8_t* buffer, const Pattern* array, size_t bytes_read) {
	for (register int i = 0; i < bytes_read - 1; i++) {
		uint8_t tmp[2];
		memcpy(tmp, &buffer[i], 2);

		if (memcmp(&( *(array[0].bytes) ), &tmp, 2) == 0) {
			printf("[+] Match found: %s at offset 0x%X\n", array[0].pattern_name, i);
		}
		else if (memcmp(&( *(array[1].bytes) ), &tmp, 2) == 0) {
			printf("[+] Match found: %s at offset 0x%X\n", array[1].pattern_name, i);
		}
	}
}

int main(int argc, char* argv[]) {

	if(argc < 2) {
		print_usage(argv[0]);
    	exit(EXIT_FAILURE);
	}

	File_Context* file_context = create_file_context(argv[1], BINARY_READ);

	size_t file_size = get_file_size(file_context);

	uint8_t byte_array[2] = {0xE8, 0x00};
	Pattern mal_1 = create_pattern("Malicious Pattern 1", 2, byte_array);

	uint8_t byte_array2[2] = {0x00, 0x5D};
	Pattern mal_2 = create_pattern("Malicious Pattern 2", 2, byte_array2);

	const Pattern pattern_array[] = { mal_1, mal_2 };

	if (strcmp(argv[2], "-b") == 0) {
		size_t bytes_read = fread(&file_context->buffer, sizeof(uint8_t), file_context->size, file_context->file);
		
		find_patterns(file_context->buffer, pattern_array, bytes_read);
	}

	//PE File Checking
	uint8_t ms_dos_bytes[2] = {0x4D, 0x5A};
	Pattern ms_dos = create_pattern("MS_DOS File Pattern", 2, ms_dos_bytes);

	uint8_t pe_signature_bytes[4] = {0x50, 0x45, 0x00, 0x00};
	Pattern pe_signature = create_pattern("PE file format signature", 4, pe_signature_bytes);

	if(strcmp(argv[2], "-e") == 0) {
		if(is_executable(file_context,&ms_dos,&pe_signature)) {
			set_pe_flag(file_context);
			
			if (!parse_coff_header(file_context)) {
				print_error("Failed to parse COFF header! parse_coff_header() failed!");
			}
			
			parse_optional_header(file_context);


			printf("\nFILE SIZE: %lfMB", (double)file_size / 1000000);
		}
	}
	
	free_file_context(file_context);

	return 0;
}