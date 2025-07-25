#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define BINARY_READ "rb"
#define BINARY_WRITE "wb"
#define BUFFER_SIZE 255

typedef struct {
	char* pattern_name;
	uint8_t bytes[2];
	uint8_t number_of_bytes;
} Pattern;

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

	if (bin_file == NULL) {
		perror("Failed to open file");
		exit(EXIT_FAILURE);
	}

	Pattern pattern1 = {
	.pattern_name = "Malicious Pattern 1",
	.bytes = { 0xE8, 0x00 },
	.number_of_bytes = 2
	};

	Pattern pattern2 = {
	.pattern_name = "Malicious Pattern 2",
	.bytes = {0x5D, 0xC3},
	.number_of_bytes = 2
	};

	const Pattern pattern_array[] = { pattern1,pattern2 };

	uint8_t buffer[BUFFER_SIZE];

	size_t bytes_read = fread(&buffer, sizeof(uint8_t), BUFFER_SIZE, bin_file);
	find_patterns(buffer, pattern_array, bytes_read);
	

	fclose(bin_file);

	return 0;
}