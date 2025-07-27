#include "../include/pe_utils.h"
#include <string.h>
#include "../include/constants.h"

bool matches_ms_dos_signature(File_Context* file_context, const Pattern* ms_dos) {
    if (fread(file_context->buffer, sizeof(uint8_t), ms_dos->number_of_bytes, file_context->file) != ms_dos->number_of_bytes) {
        printf("[-] Could not read the bytes necessary to match MS-DOS signature!\n");
        return false;
    }

    printf("[+] Successfully read bytes to check MS-DOS stub\n");

    if (memcmp(file_context->buffer, ms_dos->bytes, ms_dos->number_of_bytes) != 0) {
        printf("[-] Could not match the MS-DOS signature!\n");
        return false;
    }

    printf("[+] Successfully identified the MS-DOS stub\n");
	file_context->has_ms_dos_signature = true;
    return true;
}

uint32_t get_pe_header_offset(File_Context* file_context) {
	uint32_t pe_signature_start_byte;

	if(fseek(file_context->file, PE_HEADER_OFFSET,SEEK_SET) != 0) {
		printf("[-] Could not go to PE header offset!\n");
		return UINT32_MAX;
	}

	if (fread(&pe_signature_start_byte, sizeof(uint32_t), 1, file_context->file) != 1) {
		printf("[-] Could not read PE header byte at offset!\n");
		return UINT32_MAX;
	}

	file_context->pe_signature_start_byte = pe_signature_start_byte;

	return pe_signature_start_byte;
}

bool has_pe_signature(File_Context* file_context, const Pattern* pe_signature) {
	uint8_t pe_signature_bytes_read[PE_SIGNATURE_BYTES];

	if(fseek(file_context->file,file_context->pe_signature_start_byte,SEEK_SET) != 0 ) {
		printf("[-] Could not go to offset indicated by PE header byte!\n");
		return false;
	}

	printf("[+] Successfully found the PE signature offset!\n");

	if (fread(pe_signature_bytes_read, sizeof(uint8_t), PE_SIGNATURE_BYTES, file_context->file) != pe_signature->number_of_bytes) {
		printf("[-] Could not read number of bytes at PE signature offset!\n");
		return false;
	}

	return memcmp(pe_signature_bytes_read, pe_signature->bytes, pe_signature->number_of_bytes) == 0;
}

bool is_executable(File_Context* file_context, const Pattern* ms_dos, const Pattern* pe_signature) {
	if(!matches_ms_dos_signature(file_context,ms_dos)) {
		printf("[-] Abort: Failed to match MS_DOS stub!\n");
		return false;
	}

	uint32_t pe_signature_start_byte = get_pe_header_offset(file_context);

	if(pe_signature_start_byte == UINT32_MAX) {
		printf("[-] Abort: Failed to get PE header offset!\n");
		return false;
	}

	if(!has_pe_signature(file_context, pe_signature)) {
		printf("[-] Abort: Failed to get PE signature!\n");
		return false;
	}

	printf("[+] Successfully read the PE signature!\n");
	printf("[+] File is an executable!\n");
	return true;
}