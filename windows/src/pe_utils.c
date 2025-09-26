#include "../lib/pe_utils.h"

#define MS_DOS_SIGNATURE 0X5A4D
#define PE_SIGNATURE 0x00004550
#define PE_SIGNATURE_LENGTH 4 //in bytes

#define PE32_MAGIC_NUMBER 0x10b
#define PE32_PLUS_MAGIC_NUMBER 0x20b

//----------------------------------------------------------------------------------
// Function prototypes
//----------------------------------------------------------------------------------

PE_PARSE_STATUS peSignatureCheck(LPVOID baseAddress, PFILE_CONTEXT fileContext);
PE_PARSE_STATUS parseHeaders(LPVOID baseAddress, PFILE_CONTEXT fileContext);

//----------------------------------------------------------------------------------
// Public API implementations
//----------------------------------------------------------------------------------

PE_PARSE_STATUS peSignatureCheck(const LPVOID baseAddress, PFILE_CONTEXT fileContext) {
    print_action("CHECKING PE SIGNATURE");

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)baseAddress;
    setPeOffset(fileContext, dosHeader->e_lfanew);

    if(dosHeader->e_magic == MS_DOS_SIGNATURE) {
        print_success("Successfully identified MS DOS signature!");
        IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)baseAddress + dosHeader->e_lfanew);
        
        if(ntHeaders->Signature == PE_SIGNATURE) {
            print_success("Successfully matched PE signature. File is a PE!");
            return PE_PARSE_SUCCESS;
        }
        else {
            print_error("Could not match PE signature! peSignatureCheck() failed!");
            return PE_PARSE_ERR_PE_SIG;
        }
    }
    else {
        print_error("Could not match MS DOS signature! peSignatureCheck() failed!");
        return PE_PARSE_ERR_MS_DOS_SIG;
    }
}

PE_PARSE_STATUS parseHeaders(const LPVOID baseAddress, PFILE_CONTEXT fileContext) {
    print_action("PARSING FILE HEADERS");

    BYTE* filePointer = (BYTE*)baseAddress + getPeOffset(fileContext) + PE_SIGNATURE_LENGTH;
    
    IMAGE_FILE_HEADER* coffHeader = (IMAGE_FILE_HEADER*)filePointer;
    setCoffHeader(fileContext,coffHeader);

    filePointer += sizeof(IMAGE_FILE_HEADER);

    WORD magicNumber = *(WORD*)filePointer;
    
    if(magicNumber == PE32_PLUS_MAGIC_NUMBER) {
        IMAGE_OPTIONAL_HEADER64* optionalHeader = (IMAGE_OPTIONAL_HEADER64*)filePointer;
        setOptionalHeaderPe32Plus(fileContext, optionalHeader);
    }
    else if(magicNumber == PE32_MAGIC_NUMBER) {
        IMAGE_OPTIONAL_HEADER32* optionalHeader = (IMAGE_OPTIONAL_HEADER32*)filePointer;
        setOptionalHeaderPe32(fileContext, optionalHeader);
    }
    else {
        print_error("Could not identify PE file format from magic number! parseHeaders() failed!");
        return PE_PARSE_ERR_OPTIONAL_HEADER;
    }

    filePointer += coffHeader->SizeOfOptionalHeader;
    IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)filePointer;
    setSectionHeader(fileContext, sectionHeader);

    print_success("Successfully parsed PE header information!");

    return PE_PARSE_SUCCESS;
}
