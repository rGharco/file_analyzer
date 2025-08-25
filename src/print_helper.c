#define BOLD_CYAN "\e[1;36m"
#define BOLD_RED "\e[1;31m"
#define BOLD_GREEN   "\e[1;32m"
#define BOLD_YELLOW  "\e[1;33m"
#define BOLD_BLUE    "\e[1;34m"
#define RESET   "\033[0m"
#include "../include/print_helper.h"
#include "../include/pe_utils.h"
#include "../include/constants.h"
#include <time.h>

#if _WIN32
#include <windows.h>
#endif

#define PRINT_STRING_ROW(field, value) printf("\t║ "BOLD_RED"%-30s"RESET" │ "BOLD_CYAN"%-45s"RESET" ║\n", field, value)
#define PRINT_HEXA_ROW(field, value) printf("\t║ "BOLD_RED"%-30s"RESET" │ "BOLD_CYAN"0x%-43X"RESET" ║\n", field, value);
#define PRINT_NUMBER_ROW(field, value) printf("\t║ "BOLD_RED"%-30s"RESET" │ "BOLD_CYAN"%-45d"RESET" ║\n", field, value);

void print_banner() {

    #if _WIN32
    SetConsoleOutputCP(CP_UTF8);
    #endif

    	printf(
                BOLD_GREEN"                                                               "RESET"  \n"
                BOLD_GREEN"                               :7?^                            "RESET"   \n"
                BOLD_GREEN"                              :@@@@J                           "RESET"   \n"
                BOLD_GREEN"                               5@@#.                           "RESET"   \n"
                BOLD_GREEN"                            .^^^B#~                            "RESET"   \n"
                BOLD_GREEN"                         .5&@#&&&&&&BY:                       "RESET"    ██████╗  ██████╗ ██████╗  ██████╗  ██████╗ ████████╗\n"
                BOLD_GREEN"                          :^::..G#!~5@@!                      "RESET"   ██╔════╝ ██╔═══██╗██╔══██╗██╔════╝ ██╔═══██╗╚══██╔══╝\n"
                BOLD_GREEN"                                B@..Y@@~                      "RESET"   ██║  ███╗██║   ██║██████╔╝██║  ███╗██║   ██║   ██║   \n"
                BOLD_GREEN"                               .B&5@&5:                         "RESET" ██║   ██║██║   ██║██╔══██╗██║   ██║██║   ██║   ██║   \n"
                BOLD_GREEN"                             Y&BG&^:                            "RESET" ╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝╚██████╔╝   ██║   \n"
                BOLD_GREEN"                            G@G P&                              "RESET"  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   \n"
                BOLD_GREEN"                            Y@#:5#                              "RESET"  \n"
                BOLD_GREEN"                             ^P&&#Y:                            "RESET" ___________________________________________________\n"
                BOLD_GREEN"                                JBP&#:                          "RESET"/                                                   \\ \n"
                BOLD_GREEN"                                J# J@J                          "RESET"|  Cross-platform PE file analyzer                  |\n"
                BOLD_GREEN"                                J#5&Y                           "RESET"|  Windows PE headers                               |\n"
                BOLD_GREEN"                              !G5B:.                            "RESET"|  both on Linux and Windows                        |\n"
                BOLD_GREEN"                             :@57G                              "RESET"|                                                   |\n"
                BOLD_GREEN"                              !GBG~                             "RESET"|                                                   |\n"
                BOLD_GREEN"                                ~PG&.                           "RESET"\\___________________________________________________/\n"
                BOLD_GREEN"                               .?GJ!                            "RESET"\n"
                BOLD_GREEN"                              .&PJ                              "RESET"\n"
                BOLD_GREEN"                               .?5!                             "RESET"Developed by: Alexandru-Gabriel Radulescu\n"
                BOLD_GREEN"                                 .                              "RESET"version 1.0\n"
"\n═════════════════════════════════════════════════════ GORGOT AV ══════════════════════════════════════════════════════\n\n"
    );
}

void print_usage(const char* main_exe) {
    
    #if _WIN32
    SetConsoleOutputCP(CP_UTF8);
    #endif

    printf("\n"
        "═════════════[ "BOLD_YELLOW"USAGE GUIDE "RESET"\n"
        "\n"
        "\t\t%s <filename> [options]\n"
        "\n"
        "\t\tOptions:\n"
        "  \t\t\t-b    🔎  Scan a binary file for known patterns\n"
        "  \t\t\t-e    ⚙️  Analyze an executable and display header info\n"
        "\n"
        "\t\tExamples:\n"
        "  \t\t\t%s sample.bin -b\n"
        "  \t\t\t%s program.exe -e\n"
        "\n",
        main_exe, main_exe, main_exe);

}

void print_action(const char* message) {
	printf(BOLD_BLUE"\n═════════[ %s\n\n"RESET, message);
}

void print_error(const char* message) {
    fprintf(stderr, "[-] %s\n", message);
    fflush(stderr); 
}

void print_success(const char* message) {
    printf(BOLD_GREEN"\t[+] %s\n"RESET, message);
}

void print_checkpoint(const char* message) {
    printf(BOLD_YELLOW"\n\t[CHECKPOINT] %s\n"RESET, message);
}

void print_warning(const char* message) {
	fprintf(stderr, "[!] Warning: %s\n", message);
	fflush(stderr); 
}

void print_coff_header(const File_Context* file_context) {
    if(file_context->coff_header == NULL) {
        print_error("Failed to read COFF header. COFF header is NULL!");
        return;
    }

    uint32_t timestamp = file_context->coff_header->time_date_stamp;
    time_t time_val = (time_t)timestamp;
    char* time_str = asctime(localtime(&time_val));
    time_str[strcspn(time_str, "\n")] = '\0';

    printf("\t╔════════════════════════════════════════════════════════════════════════════════╗\n");
    PRINT_STRING_ROW("Field", "Value");
    printf("\t╠════════════════════════════════════════════════════════════════════════════════╣\n");
    PRINT_STRING_ROW("Machine Type", get_machine_type_name(file_context->coff_header->machine));
    PRINT_NUMBER_ROW("NumberOfSections", file_context->coff_header->number_of_sections);
    PRINT_STRING_ROW("TimeStamp", time_str);
    PRINT_HEXA_ROW("PointerToSymbolTable", file_context->coff_header->pointer_to_symbol_table);
    PRINT_HEXA_ROW("NumberOfSymbols", file_context->coff_header->number_of_symbols);
    PRINT_NUMBER_ROW("SizeOfOptionalHeader (bytes)", file_context->coff_header->size_of_optional_header);
    PRINT_HEXA_ROW("Characteristics", file_context->coff_header->characteristics);
    printf("\t╚════════════════════════════════════════════════════════════════════════════════╝\n");

    print_checkpoint("PARSED COFF HEADER!");
}

void print_optional_header_info(const Optional_Header* optional_header) {
    if (optional_header == NULL) {
        print_error("Optional Header is NULL!\n");
        return;
    }

    printf("\t╔════════════════════════════════════════════════════════════════════════════════╗\n");
    PRINT_STRING_ROW("Field", "Value");
    printf("\t╠════════════════════════════════════════════════════════════════════════════════╣\n");

    if (optional_header->magic_number == PE32) {
        PRINT_STRING_ROW("Header Type", "PE32");

        PRINT_NUMBER_ROW("Major Linker Version", optional_header->variant.pe32.MajorLinkerVersion);
        PRINT_NUMBER_ROW("Minor Linker Version", optional_header->variant.pe32.MinorLinkerVersion);
        PRINT_HEXA_ROW("Size of Code", optional_header->variant.pe32.SizeOfCode);
        PRINT_HEXA_ROW("Size of Initialized Data", optional_header->variant.pe32.SizeOfInitializedData);
        PRINT_HEXA_ROW("Size of Uninitialized Data", optional_header->variant.pe32.SizeOfUninitializedData);
        PRINT_HEXA_ROW("Address of Entry Point", optional_header->variant.pe32.AddressOfEntryPoint);
        PRINT_HEXA_ROW("Base of Code", optional_header->variant.pe32.BaseOfCode);
        PRINT_HEXA_ROW("Base of Data", optional_header->variant.pe32.BaseOfData);
        PRINT_HEXA_ROW("Image Base", optional_header->variant.pe32.ImageBase);
        PRINT_HEXA_ROW("Section Alignment", optional_header->variant.pe32.SectionAlignment);
        PRINT_HEXA_ROW("File Alignment", optional_header->variant.pe32.FileAlignment);

        PRINT_NUMBER_ROW("Major OS Version", optional_header->variant.pe32.MajorOperatingSystemVersion);
        PRINT_NUMBER_ROW("Minor OS Version", optional_header->variant.pe32.MinorOperatingSystemVersion);
        PRINT_NUMBER_ROW("Major Image Version", optional_header->variant.pe32.MajorImageVersion);
        PRINT_NUMBER_ROW("Minor Image Version", optional_header->variant.pe32.MinorImageVersion);
        PRINT_NUMBER_ROW("Major Subsystem Version", optional_header->variant.pe32.MajorSubsystemVersion);
        PRINT_NUMBER_ROW("Minor Subsystem Version", optional_header->variant.pe32.MinorSubsystemVersion);

        PRINT_HEXA_ROW("Win32 Version Value", optional_header->variant.pe32.Win32VersionValue);
        PRINT_HEXA_ROW("Size of Image", optional_header->variant.pe32.SizeOfImage);
        PRINT_HEXA_ROW("Size of Headers", optional_header->variant.pe32.SizeOfHeaders);
        PRINT_HEXA_ROW("CheckSum", optional_header->variant.pe32.CheckSum);
        PRINT_HEXA_ROW("Subsystem", optional_header->variant.pe32.Subsystem);
        PRINT_HEXA_ROW("Dll Characteristics", optional_header->variant.pe32.DllCharacteristics);
        PRINT_HEXA_ROW("Size of Stack Reserve", optional_header->variant.pe32.SizeOfStackReserve);
        PRINT_HEXA_ROW("Size of Stack Commit", optional_header->variant.pe32.SizeOfStackCommit);
        PRINT_HEXA_ROW("Size of Heap Reserve", optional_header->variant.pe32.SizeOfHeapReserve);
        PRINT_HEXA_ROW("Size of Heap Commit", optional_header->variant.pe32.SizeOfHeapCommit);
        PRINT_HEXA_ROW("Loader Flags", optional_header->variant.pe32.LoaderFlags);
        PRINT_HEXA_ROW("Number of RVA and Sizes", optional_header->variant.pe32.NumberOfRvaAndSizes);
    }
    else if (optional_header->magic_number == PE32_PLUS) {
        PRINT_STRING_ROW("Header Type", "PE32+");

        PRINT_NUMBER_ROW("Major Linker Version", optional_header->variant.pe32_plus.MajorLinkerVersion);
        PRINT_NUMBER_ROW("Minor Linker Version", optional_header->variant.pe32_plus.MinorLinkerVersion);
        PRINT_HEXA_ROW("Size of Code", optional_header->variant.pe32_plus.SizeOfCode);
        PRINT_HEXA_ROW("Size of Initialized Data", optional_header->variant.pe32_plus.SizeOfInitializedData);
        PRINT_HEXA_ROW("Size of Uninitialized Data", optional_header->variant.pe32_plus.SizeOfUninitializedData);
        PRINT_HEXA_ROW("Address of Entry Point", optional_header->variant.pe32_plus.AddressOfEntryPoint);
        PRINT_HEXA_ROW("Base of Code", optional_header->variant.pe32_plus.BaseOfCode);
        PRINT_HEXA_ROW("Image Base", optional_header->variant.pe32_plus.ImageBase);
        PRINT_HEXA_ROW("Section Alignment", optional_header->variant.pe32_plus.SectionAlignment);
        PRINT_HEXA_ROW("File Alignment", optional_header->variant.pe32_plus.FileAlignment);

        PRINT_NUMBER_ROW("Major OS Version", optional_header->variant.pe32_plus.MajorOperatingSystemVersion);
        PRINT_NUMBER_ROW("Minor OS Version", optional_header->variant.pe32_plus.MinorOperatingSystemVersion);
        PRINT_NUMBER_ROW("Major Image Version", optional_header->variant.pe32_plus.MajorImageVersion);
        PRINT_NUMBER_ROW("Minor Image Version", optional_header->variant.pe32_plus.MinorImageVersion);
        PRINT_NUMBER_ROW("Major Subsystem Version", optional_header->variant.pe32_plus.MajorSubsystemVersion);
        PRINT_NUMBER_ROW("Minor Subsystem Version", optional_header->variant.pe32_plus.MinorSubsystemVersion);

        PRINT_HEXA_ROW("Win32 Version Value", optional_header->variant.pe32_plus.Win32VersionValue);
        PRINT_HEXA_ROW("Size of Image", optional_header->variant.pe32_plus.SizeOfImage);
        PRINT_HEXA_ROW("Size of Headers", optional_header->variant.pe32_plus.SizeOfHeaders);
        PRINT_HEXA_ROW("CheckSum", optional_header->variant.pe32_plus.CheckSum);
        PRINT_HEXA_ROW("Subsystem", optional_header->variant.pe32_plus.Subsystem);
        PRINT_HEXA_ROW("Dll Characteristics", optional_header->variant.pe32_plus.DllCharacteristics);
        PRINT_HEXA_ROW("Size of Stack Reserve", optional_header->variant.pe32_plus.SizeOfStackReserve);
        PRINT_HEXA_ROW("Size of Stack Commit", optional_header->variant.pe32_plus.SizeOfStackCommit);
        PRINT_HEXA_ROW("Size of Heap Reserve", optional_header->variant.pe32_plus.SizeOfHeapReserve);
        PRINT_HEXA_ROW("Size of Heap Commit", optional_header->variant.pe32_plus.SizeOfHeapCommit);
        PRINT_HEXA_ROW("Loader Flags", optional_header->variant.pe32_plus.LoaderFlags);
        PRINT_HEXA_ROW("Number of RVA and Sizes", optional_header->variant.pe32_plus.NumberOfRvaAndSizes);
    }

    printf("\t╚════════════════════════════════════════════════════════════════════════════════╝\n");
}


