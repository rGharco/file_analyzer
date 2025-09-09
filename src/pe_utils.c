#include "../include/pe_utils.h"
#include "../include/constants.h"
#include "../include/print_helper.h"

#define MAGIC_NUMBER_SIZE 2 
#define MS_DOS_BUFFER 2

/****************************** FUNCTION PROTOTYPES *******************************/

Pe_Parse_Status matches_ms_dos_signature(File_Context* file_context, const Pattern* ms_dos);
Pe_Parse_Status set_pe_header_offset(File_Context* file_context);
Pe_Parse_Status has_pe_signature(File_Context* file_context, const Pattern* pe_signature);
Pe_Parse_Status is_executable(File_Context* file_context, const Pattern* ms_dos, const Pattern* pe_signature);

Pe_Parse_Status parse_coff_header(File_Context* file_context);
const char* get_machine_type_name(uint16_t machine_type);

Pe_Parse_Status get_magic_number(File_Context* file_context, Optional_Header* optional_header);
Pe_Parse_Status parse_optional_header(File_Context* file_context);
Pe_Parse_Status parse_section_header(File_Context* file_context);

/****************************** FUNCTION PROTOTYPES *******************************/

Pe_Parse_Status matches_ms_dos_signature(File_Context* file_context, const Pattern* ms_dos) {
    uint8_t buffer[MS_DOS_BUFFER];

    if (fread(buffer, sizeof(uint8_t), ms_dos->number_of_bytes, file_context->file) != ms_dos->number_of_bytes) {
        print_error("Could not read the bytes necessary to match MS-DOS signature!");
        return PE_PARSE_ERR_FREAD;
    }

    print_success("Successfully read bytes to check MS-DOS stub");

    if (memcmp(buffer, ms_dos->bytes, ms_dos->number_of_bytes) != 0) {
        print_error("Could not match the MS-DOS signature!");
        return PE_PARSE_ERR_MS_DOS_SIG;
    }

    print_success("Successfully identified the MS-DOS stub");
	file_context->has_ms_dos_signature = true;

    return PE_PARSE_SUCCESS;
}

Pe_Parse_Status set_pe_header_offset(File_Context* file_context) {
	if(fseek(file_context->file, PE_HEADER_OFFSET,SEEK_SET) != 0) {
		print_error("Could not go to PE header offset!");
		return PE_PARSE_ERR_FSEEK;
	}

	if (fread(&file_context->pe_signature_start_byte, sizeof(uint32_t), 1, file_context->file) != 1) {
		print_error("Could not read PE header byte at offset!");
		return PE_PARSE_ERR_FREAD;
	}

	return PE_PARSE_SUCCESS;
}

Pe_Parse_Status has_pe_signature(File_Context* file_context, const Pattern* pe_signature) {
	uint8_t pe_signature_bytes_read[PE_SIGNATURE_LENGTH];

	if(fseek(file_context->file,file_context->pe_signature_start_byte,SEEK_SET) != 0 ) {
		print_error("Could not go to offset indicated by PE header byte!");
		return PE_PARSE_ERR_FSEEK;
	}

	print_success("Successfully found the PE signature offset!");

	if (fread(pe_signature_bytes_read, sizeof(uint8_t), PE_SIGNATURE_LENGTH, file_context->file) != pe_signature->number_of_bytes) {
		print_error("Could not read number of bytes at PE signature offset!");
		return PE_PARSE_ERR_FREAD;
	}

	if(memcmp(pe_signature_bytes_read, pe_signature->bytes, pe_signature->number_of_bytes) != 0){
        return PE_PARSE_ERR_PE_SIG;
    }

    return PE_PARSE_SUCCESS;
}

Pe_Parse_Status is_executable(File_Context* file_context, const Pattern* ms_dos, const Pattern* pe_signature) {
	print_action("CHECKING IF FILE IS EXECUTABLE");

	if(matches_ms_dos_signature(file_context,ms_dos) != PE_PARSE_SUCCESS) {
		print_error("Failed to match MS_DOS stub!");
		return PE_PARSE_ERR_MS_DOS_SIG;
	}

	if(set_pe_header_offset(file_context) != PE_PARSE_SUCCESS) {
		print_error("Failed to get PE header offset!");
        return PE_PARSE_ERR_PE_HEADER_OFFSET;
	}

	if(has_pe_signature(file_context, pe_signature) != PE_PARSE_SUCCESS) {
		print_error("Failed to get PE signature!");
		return PE_PARSE_ERR_PE_SIG;
	}

	print_success("Successfully read the PE signature!");
	print_checkpoint("FILE IS EXECUTABLE!");

    file_context->is_pe = true;

	return PE_PARSE_SUCCESS;
}

Pe_Parse_Status parse_coff_header(File_Context* file_context) {
    print_action("PARSING COFF HEADER");

    COFF_Header* coff_header = (COFF_Header*)malloc(sizeof(COFF_Header));

    if (coff_header == NULL) {
        print_error("Failed to allocate memory for COFF header! parse_coff_header() failed!");
        return PE_PARSE_ERR_COFF_HEADER;
    }

    if (fread(coff_header, sizeof(COFF_Header), 1, file_context->file) != 1) {
        print_error("Could not read bytes for COFF header! fread() failed!");
        free(coff_header);
        return PE_PARSE_ERR_FREAD;
    }

    file_context->coff_header = coff_header;

    print_success("Successfully parsed COFF header! -> printing information: ");

    return PE_PARSE_SUCCESS;
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

Pe_Parse_Status get_magic_number(File_Context* file_context, Optional_Header* optional_header) {
    if(fread(&optional_header->magic_number, MAGIC_NUMBER_SIZE,1, file_context->file) != 1) {
        print_error("Failed to read Magic Number from optional header! get_magic_number() failed!");
        return PE_PARSE_ERR_FREAD;
    }

    return PE_PARSE_SUCCESS;
}

Pe_Parse_Status parse_optional_header(File_Context* file_context) {
    print_action("PARSING OPTIONAL HEADER");

    Optional_Header* optional_header = (Optional_Header*)malloc(sizeof(Optional_Header));

    if (optional_header == NULL) {
        print_error("Memory allocation failed! parse_optional_header() failed!");
        return PE_PARSE_ERR_OPTIONAL_HEADER;
    }

    if (get_magic_number(file_context, optional_header) != PE_PARSE_SUCCESS) {
        print_error("Failed to read magic number!");
        goto optional_header_cleanup;
    }

    print_success("Successfully read magic number bytes!");

    uint32_t optional_header_size = file_context->coff_header->size_of_optional_header-MAGIC_NUMBER_SIZE;

    if (optional_header->magic_number == PE32) {
        if (fread(&optional_header->variant.pe32, optional_header_size, 1, file_context->file) != 1) {
            print_error("Failed to read PE32 optional header!");
            goto optional_header_cleanup;
        }
        print_success("Successfully identified PE32 format!");
    } 
    else if (optional_header->magic_number == PE32_PLUS) {
        if (fread(&optional_header->variant.pe32_plus, optional_header_size, 1, file_context->file) != 1) {
            print_error("Failed to read PE32+ optional header!");
            goto optional_header_cleanup;
        }
        print_success("Successfully identified PE32+ format!");
    } 
    else {
        print_error("Unknown optional header format!");
        goto optional_header_cleanup;
    }

    file_context->optional_header = optional_header;

    print_success("Successfully parsed Optional header!");
    print_checkpoint("PARSE OPTIONAL HEADER");

    return PE_PARSE_SUCCESS;

optional_header_cleanup:
    free(optional_header);
    return PE_PARSE_ERR_OPTIONAL_HEADER;
}

Pe_Parse_Status parse_section_header(File_Context* file_context) {
    print_action("PARSING SECTION HEADER");

    Section_Header* sections = (Section_Header*)malloc(file_context->coff_header->number_of_sections * sizeof(Section_Header));

    if(sections == NULL) {
        print_error("Failed to allocate memory for section headers! parse_section_header() failed!");
        return PE_PARSE_ERR_SECTION_HEADER;
    }

    uint16_t n = file_context->coff_header->number_of_sections;

    if(fread(sections,sizeof(Section_Header),n,file_context->file) != n) {
        print_error("Failed to read all section headers! parse_section_header() failed!");
        free(sections);
        return PE_PARSE_ERR_FREAD;
    }

    file_context->sections = sections;

    print_success("Successfully parsed section header!");
    print_checkpoint("PARSED SECTION HEADER");

    return PE_PARSE_SUCCESS;
}

