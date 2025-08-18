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
    printf("\t║ "BOLD_RED"%-30s"RESET" │ "BOLD_CYAN"%-45s"RESET" ║\n", "Field", "Value");
    printf("\t╠════════════════════════════════════════════════════════════════════════════════╣\n");
    printf("\t║ "BOLD_RED"%-30s"RESET" │ "BOLD_CYAN"%-45s"RESET" ║\n", "Machine Type", get_machine_type_name(file_context->coff_header->machine));
    printf("\t║ "BOLD_RED"%-30s"RESET" │ "BOLD_CYAN"%-45d"RESET" ║\n", "Number of Sections", file_context->coff_header->number_of_sections);
    printf("\t║ "BOLD_RED"%-30s"RESET" │ "BOLD_CYAN"%-45s"RESET" ║\n", "TimeDateStamp", time_str);
    printf("\t║ "BOLD_RED"%-30s"RESET" │ "BOLD_CYAN"0x%-43X"RESET" ║\n", "PointerToSymbolTable", file_context->coff_header->pointer_to_symbol_table);
    printf("\t║ "BOLD_RED"%-30s"RESET" │ "BOLD_CYAN"0x%-43X"RESET" ║\n", "NumberOfSymbols", file_context->coff_header->number_of_symbols);
    printf("\t║ "BOLD_RED"%-30s"RESET" │ "BOLD_CYAN"%-45d"RESET" ║\n", "SizeOfOptionalHeader (bytes)", file_context->coff_header->size_of_optional_header);
    printf("\t║ "BOLD_RED"%-30s"RESET" │ "BOLD_CYAN"0x%-43X"RESET" ║\n", "Characteristics", file_context->coff_header->characteristics);
    printf("\t╚════════════════════════════════════════════════════════════════════════════════╝\n");

    print_checkpoint("PARSED COFF HEADER!");
}

void print_optional_header_info(const Optional_Header* optional_header) {
    if (optional_header == NULL) {
        print_error("Optional Header is NULL!\n");
        return;
    }

    printf("\t╔════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("\t║ %s%-30s%s │ %s%-45s%s ║\n", BOLD_RED, "Field", RESET, BOLD_CYAN, "Value", RESET);
    printf("\t╠════════════════════════════════════════════════════════════════════════════════╣\n");

    if (optional_header->magic_number == PE32) {
        #define PE32_PRINT(field, value) printf("\t║ %s%-30s%s │ %s%-45X%s ║\n", BOLD_RED, field, RESET, BOLD_CYAN, value, RESET)
        #define PE32_PRINT_U(field, value) printf("\t║ %s%-30s%s │ %s%-45u%s ║\n", BOLD_RED, field, RESET, BOLD_CYAN, value, RESET)

        printf("\t║ %s%-30s%s │ %s%-45%s ║\n", BOLD_RED, "Header Type", RESET, BOLD_CYAN, "PE32", RESET);
        PE32_PRINT("Major Linker Version", optional_header->variant.pe32.MajorLinkerVersion);
        PE32_PRINT("Minor Linker Version", optional_header->variant.pe32.MinorLinkerVersion);
        PE32_PRINT("Size of Code", optional_header->variant.pe32.SizeOfCode);
        PE32_PRINT("Size of Initialized Data", optional_header->variant.pe32.SizeOfInitializedData);
        PE32_PRINT("Size of Uninitialized Data", optional_header->variant.pe32.SizeOfUninitializedData);
        PE32_PRINT("Address of Entry Point", optional_header->variant.pe32.AddressOfEntryPoint);
        PE32_PRINT("Base of Code", optional_header->variant.pe32.BaseOfCode);
        PE32_PRINT("Base of Data", optional_header->variant.pe32.BaseOfData);
        PE32_PRINT("Image Base", optional_header->variant.pe32.ImageBase);
        PE32_PRINT("Section Alignment", optional_header->variant.pe32.SectionAlignment);
        PE32_PRINT("File Alignment", optional_header->variant.pe32.FileAlignment);
        PE32_PRINT_U("Major OS Version", optional_header->variant.pe32.MajorOperatingSystemVersion);
        PE32_PRINT_U("Minor OS Version", optional_header->variant.pe32.MinorOperatingSystemVersion);
        PE32_PRINT_U("Major Image Version", optional_header->variant.pe32.MajorImageVersion);
        PE32_PRINT_U("Minor Image Version", optional_header->variant.pe32.MinorImageVersion);
        PE32_PRINT_U("Major Subsystem Version", optional_header->variant.pe32.MajorSubsystemVersion);
        PE32_PRINT_U("Minor Subsystem Version", optional_header->variant.pe32.MinorSubsystemVersion);
        PE32_PRINT("Win32 Version Value", optional_header->variant.pe32.Win32VersionValue);
        PE32_PRINT("Size of Image", optional_header->variant.pe32.SizeOfImage);
        PE32_PRINT("Size of Headers", optional_header->variant.pe32.SizeOfHeaders);
        PE32_PRINT("CheckSum", optional_header->variant.pe32.CheckSum);
        PE32_PRINT("Subsystem", optional_header->variant.pe32.Subsystem);
        PE32_PRINT("Dll Characteristics", optional_header->variant.pe32.DllCharacteristics);
        PE32_PRINT("Size of Stack Reserve", optional_header->variant.pe32.SizeOfStackReserve);
        PE32_PRINT("Size of Stack Commit", optional_header->variant.pe32.SizeOfStackCommit);
        PE32_PRINT("Size of Heap Reserve", optional_header->variant.pe32.SizeOfHeapReserve);
        PE32_PRINT("Size of Heap Commit", optional_header->variant.pe32.SizeOfHeapCommit);
        PE32_PRINT("Loader Flags", optional_header->variant.pe32.LoaderFlags);
        PE32_PRINT("Number of RVA and Sizes", optional_header->variant.pe32.NumberOfRvaAndSizes);
    } 
    else if (optional_header->magic_number == PE32_PLUS) {
        #define PE32_PLUS_PRINT(field, value) printf("\t║ %s%-30s%s │ %s%-45llX%s ║\n", BOLD_RED, field, RESET, BOLD_CYAN, (unsigned long long)value, RESET)
        #define PE32_PLUS_PRINT_U(field, value) printf("\t║ %s%-30s%s │ %s%-45u%s ║\n", BOLD_RED, field, RESET, BOLD_CYAN, value, RESET)

        printf("\t║ %s%-30s%s │ %s%-45s%s ║\n", BOLD_RED, "Header Type", RESET, BOLD_CYAN, "PE32+", RESET);
        PE32_PLUS_PRINT("Major Linker Version", optional_header->variant.pe32_plus.MajorLinkerVersion);
        PE32_PLUS_PRINT("Minor Linker Version", optional_header->variant.pe32_plus.MinorLinkerVersion);
        PE32_PLUS_PRINT("Size of Code", optional_header->variant.pe32_plus.SizeOfCode);
        PE32_PLUS_PRINT("Size of Initialized Data", optional_header->variant.pe32_plus.SizeOfInitializedData);
        PE32_PLUS_PRINT("Size of Uninitialized Data", optional_header->variant.pe32_plus.SizeOfUninitializedData);
        PE32_PLUS_PRINT("Address of Entry Point", optional_header->variant.pe32_plus.AddressOfEntryPoint);
        PE32_PLUS_PRINT("Base of Code", optional_header->variant.pe32_plus.BaseOfCode);
        PE32_PLUS_PRINT("Image Base", optional_header->variant.pe32_plus.ImageBase);
        PE32_PLUS_PRINT("Section Alignment", optional_header->variant.pe32_plus.SectionAlignment);
        PE32_PLUS_PRINT("File Alignment", optional_header->variant.pe32_plus.FileAlignment);
        PE32_PLUS_PRINT_U("Major OS Version", optional_header->variant.pe32_plus.MajorOperatingSystemVersion);
        PE32_PLUS_PRINT_U("Minor OS Version", optional_header->variant.pe32_plus.MinorOperatingSystemVersion);
        PE32_PLUS_PRINT_U("Major Image Version", optional_header->variant.pe32_plus.MajorImageVersion);
        PE32_PLUS_PRINT_U("Minor Image Version", optional_header->variant.pe32_plus.MinorImageVersion);
        PE32_PLUS_PRINT_U("Major Subsystem Version", optional_header->variant.pe32_plus.MajorSubsystemVersion);
        PE32_PLUS_PRINT_U("Minor Subsystem Version", optional_header->variant.pe32_plus.MinorSubsystemVersion);
        PE32_PLUS_PRINT("Win32 Version Value", optional_header->variant.pe32_plus.Win32VersionValue);
        PE32_PLUS_PRINT("Size of Image", optional_header->variant.pe32_plus.SizeOfImage);
        PE32_PLUS_PRINT("Size of Headers", optional_header->variant.pe32_plus.SizeOfHeaders);
        PE32_PLUS_PRINT("CheckSum", optional_header->variant.pe32_plus.CheckSum);
        PE32_PLUS_PRINT("Subsystem", optional_header->variant.pe32_plus.Subsystem);
        PE32_PLUS_PRINT("Dll Characteristics", optional_header->variant.pe32_plus.DllCharacteristics);
        PE32_PLUS_PRINT("Size of Stack Reserve", optional_header->variant.pe32_plus.SizeOfStackReserve);
        PE32_PLUS_PRINT("Size of Stack Commit", optional_header->variant.pe32_plus.SizeOfStackCommit);
        PE32_PLUS_PRINT("Size of Heap Reserve", optional_header->variant.pe32_plus.SizeOfHeapReserve);
        PE32_PLUS_PRINT("Size of Heap Commit", optional_header->variant.pe32_plus.SizeOfHeapCommit);
        PE32_PLUS_PRINT("Loader Flags", optional_header->variant.pe32_plus.LoaderFlags);
        PE32_PLUS_PRINT("Number of RVA and Sizes", optional_header->variant.pe32_plus.NumberOfRvaAndSizes);
    }

    printf("\t╚════════════════════════════════════════════════════════════════════════════════╝\n");
}


