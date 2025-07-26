#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../include/pattern.h"

#define BINARY_READ "rb"
#define BINARY_WRITE "wb"
#define BUFFER_SIZE 255
#define PE_SIGNATURE_BYTES 4
#define PE_HEADER_POINTER_OFFSET 0x3C

bool matches_ms_dos_signature(FILE* image_file, uint8_t* buffer, const Pattern ms_dos) {
    if (fread(buffer, sizeof(uint8_t), ms_dos.number_of_bytes, image_file) != ms_dos.number_of_bytes) {
        printf("[-] Could not read the bytes necessary to match MS-DOS signature!\n");
        return false;
    }

    printf("[+] Successfully read bytes to check MS-DOS stub\n");

    if (memcmp(buffer, ms_dos.bytes, ms_dos.number_of_bytes) != 0) {
        printf("[-] Could not match the MS-DOS signature!\n");
        return false;
    }

    printf("[+] Successfully identified the MS-DOS stub\n");
    return true;
}

uint32_t get_pe_header_offset(FILE* image_file) {
	uint32_t pe_signature_byte_start;

	if(fseek(image_file, PE_HEADER_POINTER_OFFSET,SEEK_SET) != 0) {
		printf("[-] Could not go to PE header offset!\n");
		return UINT32_MAX;
	}

	if (fread(&pe_signature_byte_start, sizeof(uint32_t), 1, image_file) != 1) {
		printf("[-] Could not read PE header byte at offset!\n");
		return UINT32_MAX;
	}

	return pe_signature_byte_start;
}

bool has_pe_signature(FILE* image_file, const uint8_t pe_signature_byte_start, const Pattern pe_signature) {
	uint8_t pe_signature_bytes_read[PE_SIGNATURE_BYTES];

	if(fseek(image_file,pe_signature_byte_start,SEEK_SET) != 0 ) {
		printf("[-] Could not go to offset indicated by PE header byte!\n");
		return false;
	}

	printf("[+] Successfully found the PE signature offset!\n");

	if (fread(pe_signature_bytes_read, sizeof(uint8_t), 
		pe_signature.number_of_bytes, image_file) != pe_signature.number_of_bytes) {
		printf("[-] Could not read number of bytes at PE signature offset!\n");
		return false;
	}

	return memcmp(pe_signature_bytes_read, pe_signature.bytes, pe_signature.number_of_bytes) == 0;
}

bool is_executable(FILE* image_file, uint8_t* buffer, const Pattern ms_dos, const Pattern pe_signature) {
	if(!matches_ms_dos_signature(image_file,buffer,ms_dos)) {
		printf("[-] Abort: Failed to match MS_DOS stub!\n");
		return false;
	}

	uint32_t pe_signature_byte_start = get_pe_header_offset(image_file);

	if(pe_signature_byte_start == UINT32_MAX) {
		printf("[-] Abort: Failed to get PE header offset!\n");
		return false;
	}

	if(!has_pe_signature(image_file,pe_signature_byte_start,pe_signature)) {
		printf("[-] Abort: Failed to get PE signature!\n");
		return false;
	}

	printf("[+] Successfully read the PE signature!\n");
	printf("[+] File is an executable!\n");
	return true;
}

void check_file_open(FILE* file) {
	if (file == NULL) {
		perror("Failed to open file");
		exit(EXIT_FAILURE);
	}
}

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
		printf("Usage: %s <filename>\n", argv[0]);
    	exit(EXIT_FAILURE);
	}

	FILE* bin_file = fopen(argv[1], BINARY_READ);

	check_file_open(bin_file);

	uint8_t byte_array[2] = {0xE8, 0x00};
	Pattern mal_1 = create_pattern("Malicious Pattern 1", 2, byte_array);

	uint8_t byte_array2[2] = {0x00, 0x5D};
	Pattern mal_2 = create_pattern("Malicious Pattern 2", 2, byte_array2);

	const Pattern pattern_array[] = { mal_1,mal_2 };

	uint8_t buffer[BUFFER_SIZE];

	if (strcmp(argv[2], "-b") == 0) {
		size_t bytes_read = fread(&buffer, sizeof(uint8_t), BUFFER_SIZE, bin_file);
		find_patterns(buffer, pattern_array, bytes_read);
	}

	fclose(bin_file);

	//PE File Checking
	FILE* image_file = fopen(argv[1], BINARY_READ);

	check_file_open(image_file);

	uint8_t ms_dos_bytes[2] = {0x4D, 0x5A};
	Pattern ms_dos = create_pattern("MS_DOS File Pattern", 2, ms_dos_bytes);

	uint8_t pe_signature_bytes[4] = {0x50, 0x45, 0x00, 0x00};
	Pattern pe_signature = create_pattern("PE file format signature", 4, pe_signature_bytes);

	if(strcmp(argv[2], "-e") == 0) {
		memset(buffer,0,BUFFER_SIZE);
		is_executable(image_file,buffer,ms_dos,pe_signature);
	}
	
	fclose(image_file);

	return 0;
}