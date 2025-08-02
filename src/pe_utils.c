#include "../include/pe_utils.h"
#include <string.h>
#include <stdlib.h>
#include "../include/constants.h"
#include <time.h>
#include "../include/print_helper.h"

#define PE32 0x10b
#define PE32_PLUS 0x20b
#define MAGIC_NUMBER_SIZE 2 

bool matches_ms_dos_signature(File_Context* file_context, const Pattern* ms_dos);
uint32_t get_pe_header_offset(File_Context* file_context);
bool has_pe_signature(File_Context* file_context, const Pattern* pe_signature);
bool is_executable(File_Context* file_context, const Pattern* ms_dos, const Pattern* pe_signature);

void print_coff_header(const File_Context* file_context);
void print_coff_header(const File_Context* file_context);

const char* get_machine_type_name(uint16_t machine_type);

bool get_magic_number(File_Context* file_context);
bool parse_optional_header(File_Context* file_context);
void print_optional_header_info(const Optional_Header* optional_header);

bool matches_ms_dos_signature(File_Context* file_context, const Pattern* ms_dos) {
    if (fread(file_context->buffer, sizeof(uint8_t), ms_dos->number_of_bytes, file_context->file) != ms_dos->number_of_bytes) {
        print_error("Could not read the bytes necessary to match MS-DOS signature!");
        return false;
    }

    printf("[+] Successfully read bytes to check MS-DOS stub\n");

    if (memcmp(file_context->buffer, ms_dos->bytes, ms_dos->number_of_bytes) != 0) {
        print_error("Could not match the MS-DOS signature!");
        return false;
    }

    printf("[+] Successfully identified the MS-DOS stub\n");
	file_context->has_ms_dos_signature = true;
    return true;
}

uint32_t get_pe_header_offset(File_Context* file_context) {
	uint32_t pe_signature_start_byte;

	if(fseek(file_context->file, PE_HEADER_OFFSET,SEEK_SET) != 0) {
		print_error("Could not go to PE header offset!");
		return UINT32_MAX;
	}

	if (fread(&pe_signature_start_byte, sizeof(uint32_t), 1, file_context->file) != 1) {
		print_error("Could not read PE header byte at offset!");
		return UINT32_MAX;
	}

	file_context->pe_signature_start_byte = pe_signature_start_byte;

	return pe_signature_start_byte;
}

bool has_pe_signature(File_Context* file_context, const Pattern* pe_signature) {
	uint8_t pe_signature_bytes_read[PE_SIGNATURE_LENGTH];

	if(fseek(file_context->file,file_context->pe_signature_start_byte,SEEK_SET) != 0 ) {
		print_error("Could not go to offset indicated by PE header byte!");
		return false;
	}

	printf("[+] Successfully found the PE signature offset!\n");

	if (fread(pe_signature_bytes_read, sizeof(uint8_t), PE_SIGNATURE_LENGTH, file_context->file) != pe_signature->number_of_bytes) {
		print_error("Could not read number of bytes at PE signature offset!");
		return false;
	}

	return memcmp(pe_signature_bytes_read, pe_signature->bytes, pe_signature->number_of_bytes) == 0;
}

bool is_executable(File_Context* file_context, const Pattern* ms_dos, const Pattern* pe_signature) {
	print_action("CHECKING IF FILE IS EXECUTABLE");

	if(!matches_ms_dos_signature(file_context,ms_dos)) {
		print_error("Abort: Failed to match MS_DOS stub!");
		return false;
	}

	uint32_t pe_signature_start_byte = get_pe_header_offset(file_context);

	if(pe_signature_start_byte == UINT32_MAX) {
		print_error("Abort: Failed to get PE header offset!");
        return false;
	}

	if(!has_pe_signature(file_context, pe_signature)) {
		print_error("Abort: Failed to get PE signature!");
		return false;
	}

	printf("[+] Successfully read the PE signature!\n");
	printf("[+] File is an executable!\n\n");

	print_action("CHECKING IF FILE IS EXECUTABLE");

	return true;
}

bool parse_coff_header(File_Context* file_context) {
    print_action("PARSING COFF HEADER");

    if (file_context == NULL) {
        print_error("Failed to parse COFF header! file_context is NULL!");
        return false;
    }

    if (fseek(file_context->file, file_context->pe_signature_start_byte + PE_SIGNATURE_LENGTH, SEEK_SET) != 0) {
        print_error("Failed to go to COFF header. fseek() failed!");
        return false;
    }

    COFF_Header* coff_header = (COFF_Header*)malloc(sizeof(COFF_Header));
    if (coff_header == NULL) {
        print_error("Failed to allocate memory for COFF header! parse_coff_header() failed!");
        return false;
    }

    if (fread(coff_header, sizeof(COFF_Header), 1, file_context->file) != 1) {
        print_error("Could not read bytes for COFF header! fread() failed!");
        free(coff_header);
        return false;
    }

    file_context->coff_header = coff_header;

    printf("[+] Successfully parsed COFF header! -> printing information: \n");

    print_coff_header(file_context);

    print_action("PARSING COFF HEADER");

    return true;
}

void print_coff_header(const File_Context* file_context) {
	if(file_context->coff_header == NULL) {
		print_error("Failed to read COFF header. COFF header is NULL!");
		exit(EXIT_FAILURE);
	}

	printf("\t[INFO] Machine Type: %s\n", get_machine_type_name(file_context->coff_header->machine));
	printf("\t[INFO] Number of sections: 0x%X\n", file_context->coff_header->number_of_sections);

	uint32_t timestamp = file_context->coff_header->time_date_stamp;
	time_t time = (time_t)timestamp;

	printf("\t[INFO] TimeDateStamp: %s", asctime(localtime(&time)));
	printf("\t[INFO] PointerToSymbolTable: 0x%X\n", file_context->coff_header->pointer_to_symbol_table);
	printf("\t[INFO] NumberOfSymbols: 0x%X\n", file_context->coff_header->number_of_symbols);
	printf("\t[INFO] SizeOfOptionalHeader: 0x%X\n", file_context->coff_header->size_of_optional_header);
	printf("\t[INFO] Characteristics: 0x%X\n", file_context->coff_header->characteristics);
}

const char* get_machine_type_name(uint16_t machine_type) {
    switch(machine_type) {
        case 0x0000: return "IMAGE_FILE_MACHINE_UNKNOWN";
        case 0x0184: return "IMAGE_FILE_MACHINE_ALPHA";
        case 0x0284: return "IMAGE_FILE_MACHINE_ALPHA64 / AXP64";
        case 0x01D3: return "IMAGE_FILE_MACHINE_AM33";
        case 0x8664: return "IMAGE_FILE_MACHINE_AMD64 (x64)";
        case 0x01C0: return "IMAGE_FILE_MACHINE_ARM (ARM Little Endian)";
        case 0xAA64: return "IMAGE_FILE_MACHINE_ARM64 (ARM64 Little Endian)";
        case 0xA641: return "IMAGE_FILE_MACHINE_ARM64EC (ARM64 + x64 interop)";
        case 0xA64E: return "IMAGE_FILE_MACHINE_ARM64X (Mixed ARM64 & ARM64EC)";
        case 0x01C4: return "IMAGE_FILE_MACHINE_ARMNT (Thumb-2 Little Endian)";
        case 0x0EBC: return "IMAGE_FILE_MACHINE_EBC (EFI Byte Code)";
        case 0x014C: return "IMAGE_FILE_MACHINE_I386 (x86)";
        case 0x0200: return "IMAGE_FILE_MACHINE_IA64 (Itanium)";
        case 0x6232: return "IMAGE_FILE_MACHINE_LOONGARCH32";
        case 0x6264: return "IMAGE_FILE_MACHINE_LOONGARCH64";
        case 0x9041: return "IMAGE_FILE_MACHINE_M32R (Mitsubishi M32R)";
        case 0x0266: return "IMAGE_FILE_MACHINE_MIPS16";
        case 0x0366: return "IMAGE_FILE_MACHINE_MIPSFPU";
        case 0x0466: return "IMAGE_FILE_MACHINE_MIPSFPU16";
        case 0x01F0: return "IMAGE_FILE_MACHINE_POWERPC (Little Endian)";
        case 0x01F1: return "IMAGE_FILE_MACHINE_POWERPCFP (w/ Floating Point)";
        case 0x0160: return "IMAGE_FILE_MACHINE_R3000BE (MIPS Big Endian)";
        case 0x0162: return "IMAGE_FILE_MACHINE_R3000 (MIPS Little Endian)";
        case 0x0166: return "IMAGE_FILE_MACHINE_R4000 (MIPS III 64-bit)";
        case 0x0168: return "IMAGE_FILE_MACHINE_R10000 (MIPS IV 64-bit)";
        case 0x5032: return "IMAGE_FILE_MACHINE_RISCV32";
        case 0x5064: return "IMAGE_FILE_MACHINE_RISCV64";
        case 0x5128: return "IMAGE_FILE_MACHINE_RISCV128";
        case 0x01A2: return "IMAGE_FILE_MACHINE_SH3";
        case 0x01A3: return "IMAGE_FILE_MACHINE_SH3DSP";
        case 0x01A6: return "IMAGE_FILE_MACHINE_SH4";
        case 0x01A8: return "IMAGE_FILE_MACHINE_SH5";
        case 0x01C2: return "IMAGE_FILE_MACHINE_THUMB";
        case 0x0169: return "IMAGE_FILE_MACHINE_WCEMIPSV2";
        default:     return "Unknown or unsupported machine type";
    }
}

bool get_magic_number(File_Context* file_context) {
    if (file_context == NULL) {
        print_error("file_context is NULL! get_magic_number() failed!");
        return false;
    }

    if(fread(&file_context->optional_header->magic_number, MAGIC_NUMBER_SIZE,1, file_context->file) == 0) {
        print_error("Failed to read Magic Number from optional header! get_magic_number() failed!");
        return false;
    }

    return true;
}

bool parse_optional_header(File_Context* file_context) {
    if (file_context == NULL) {
        print_error("file_context is NULL! parse_optional_header() failed!");
        return false;
    }

    uint32_t optional_header_offset = file_context->pe_signature_start_byte + PE_SIGNATURE_LENGTH + COFF_HEADER_BYTES;
    Optional_Header* optional_header = (Optional_Header*)malloc(sizeof(Optional_Header));

    if (optional_header == NULL) {
        print_error("Memory allocation failed! parse_optional_header() failed!");
        return false;
    }

    file_context->optional_header = optional_header;

    if (fseek(file_context->file, optional_header_offset, SEEK_SET) != 0) {
        print_error("Failed to seek to optional header offset!");
        goto cleanup;
    }

    if (!get_magic_number(file_context)) {
        print_error("Failed to read magic number!");
        goto cleanup;
    }

    switch(file_context->optional_header->magic_number) {
        case PE32:
            if(fread(&file_context->optional_header->variant.pe32, OPTIONAL_HEADER_PE32_SIZE, 1,file_context->file) == 0) {
                print_error("Failed to read bytes for Optional header! parse_optional_header() failed!");
                goto cleanup;
            }

            break;
        case PE32_PLUS:
            if(fread(&file_context->optional_header->variant.pe32, OPTIONAL_HEADER_PE32_PLUS_SIZE, 1,file_context->file) == 0) {
                print_error("Failed to read bytes for Optional header! parse_optional_header() failed!");
                goto cleanup;
            }
            
            break;
    }

    printf("[+] Successfully parsed Optional header!\n");
    print_optional_header_info(file_context->optional_header);
    return true;

cleanup:
    free(optional_header);
    return false;
}
