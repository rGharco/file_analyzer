#define BOLD_CYAN "\e[1;36m"
#define BOLD_RED "\e[1;31m"
#define BOLD_GREEN   "\e[1;32m"
#define BOLD_YELLOW  "\e[1;33m"
#define YELLOW "\e[0;33m"
#define BOLD_BLUE    "\e[1;34m"
#define RESET   "\033[0m"
#include "../include/print_helper.h"
#include "../include/pe_utils.h"
#include "../include/constants.h"

#define PRINT_STRING_ROW(field, value) printf("\t║ "BOLD_RED"%-30s"RESET" │ "BOLD_CYAN"%-45s"RESET" ║\n", field, value)
#define PRINT_HEXA_ROW(field, value) printf("\t║ "BOLD_RED"%-30s"RESET" │ "BOLD_CYAN"0x%-43X"RESET" ║\n", field, value);
#define PRINT_NUMBER_ROW(field, value) printf("\t║ "BOLD_RED"%-30s"RESET" │ "BOLD_CYAN"%-45d"RESET" ║\n", field, value);

#define PRINT_SECTION(name,sec) printf("\t║"BOLD_CYAN" %-8s │ 0x%-14X │ 0x%-14X │ 0x%-14X │ 0x%-14X │ 0x%-8X "RESET"║\n", \
               name, \
               sec->VirtualAddress, \
               sec->VirtualSize, \
               sec->PointerToRawData, \
               sec->SizeOfRawData, \
               sec->Characteristics )

/****************************** FUNCTION PROTOTYPES *******************************/

void print_banner();
void print_usage(const char* main_exe);
void print_legend();
void print_action(const char* message);
void print_error(const char* message);
void print_success(const char* message);
void print_checkpoint(const char* message);
void print_warning(const char* message);
void print_coff_header(const File_Context* file_context);
void print_optional_header(const File_Context* file_context);
void print_section_headers(const File_Context* fc);

/****************************** FUNCTION PROTOTYPES *******************************/

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

void print_legend() {
	print_action("LEGEND");
	printf(""BOLD_GREEN"BOLD GREEN: Represent SUSPICIOUS activity, it is not a clear indicator of wheather or not something is malicious but indicates an outlier."RESET"\n");
	printf(""BOLD_YELLOW"BOLD YELLOW: Represents HIGHLY-SUSPICIOUS activity, much higher confidence level and indicator of an anomaly, unlikely to be a coincidence."RESET"\n");
	printf(""BOLD_RED"BOLD RED: Represents MALICIOUS activity, a clear indicator of malicious intent and not an accident or misconfiguration."RESET"\n");
}

void print_action(const char* message) {
	printf(BOLD_BLUE"\n═════════[ %s\n\n"RESET, message);
}

void print_error(const char* message) {
    fprintf(stderr, ""BOLD_RED"[-] %s"RESET"\n", message);
    fflush(stderr); 
}

void print_success(const char* message) {
    printf(BOLD_GREEN"\t[+] %s\n"RESET, message);
}

void print_checkpoint(const char* message) {
    printf(BOLD_YELLOW"\n\t[CHECKPOINT] %s\n"RESET, message);
}

void print_warning(const char* message) {
	fprintf(stderr, ""YELLOW"[!] Warning: %s"RESET"\n", message);
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

void print_optional_header(const File_Context* file_context) {
    if (file_context->optional_header == NULL) {
        print_error("Optional Header is NULL!\n");
        return;
    }

    printf("\t╔════════════════════════════════════════════════════════════════════════════════╗\n");
    PRINT_STRING_ROW("Field", "Value");
    printf("\t╠════════════════════════════════════════════════════════════════════════════════╣\n");

    if(file_context->optional_header->magic_number == PE32) {
        PRINT_STRING_ROW("Header Type", "PE32");
    }
    else {
        PRINT_STRING_ROW("Header Type", "PE32+");
    }

    PRINT_NUMBER_ROW("Major Linker Version", file_context->optional_header->variant.pe32.MajorLinkerVersion);
    PRINT_NUMBER_ROW("Minor Linker Version", file_context->optional_header->variant.pe32.MinorLinkerVersion);
    PRINT_HEXA_ROW("Size of Code", file_context->optional_header->variant.pe32.SizeOfCode);
    PRINT_HEXA_ROW("Size of Initialized Data", file_context->optional_header->variant.pe32.SizeOfInitializedData);
    PRINT_HEXA_ROW("Size of Uninitialized Data", file_context->optional_header->variant.pe32.SizeOfUninitializedData);
    PRINT_HEXA_ROW("Address of Entry Point", file_context->optional_header->variant.pe32.AddressOfEntryPoint);
    PRINT_HEXA_ROW("Base of Code", file_context->optional_header->variant.pe32.BaseOfCode);

    if(file_context->optional_header->magic_number == PE32) {
        PRINT_HEXA_ROW("Base of Data", file_context->optional_header->variant.pe32.BaseOfData);
    }

    PRINT_HEXA_ROW("Image Base", file_context->optional_header->variant.pe32.ImageBase);
    PRINT_HEXA_ROW("Section Alignment", file_context->optional_header->variant.pe32.SectionAlignment);
    PRINT_HEXA_ROW("File Alignment", file_context->optional_header->variant.pe32.FileAlignment);

    PRINT_NUMBER_ROW("Major OS Version", file_context->optional_header->variant.pe32.MajorOperatingSystemVersion);
    PRINT_NUMBER_ROW("Minor OS Version", file_context->optional_header->variant.pe32.MinorOperatingSystemVersion);
    PRINT_NUMBER_ROW("Major Image Version", file_context->optional_header->variant.pe32.MajorImageVersion);
    PRINT_NUMBER_ROW("Minor Image Version", file_context->optional_header->variant.pe32.MinorImageVersion);
    PRINT_NUMBER_ROW("Major Subsystem Version", file_context->optional_header->variant.pe32.MajorSubsystemVersion);
    PRINT_NUMBER_ROW("Minor Subsystem Version", file_context->optional_header->variant.pe32.MinorSubsystemVersion);

    PRINT_HEXA_ROW("Win32 Version Value", file_context->optional_header->variant.pe32.Win32VersionValue);
    PRINT_HEXA_ROW("Size of Image", file_context->optional_header->variant.pe32.SizeOfImage);
    PRINT_HEXA_ROW("Size of Headers", file_context->optional_header->variant.pe32.SizeOfHeaders);
    PRINT_HEXA_ROW("CheckSum", file_context->optional_header->variant.pe32.CheckSum);
    PRINT_HEXA_ROW("Subsystem", file_context->optional_header->variant.pe32.Subsystem);
    PRINT_HEXA_ROW("Dll Characteristics", file_context->optional_header->variant.pe32.DllCharacteristics);
    PRINT_HEXA_ROW("Size of Stack Reserve", file_context->optional_header->variant.pe32.SizeOfStackReserve);
    PRINT_HEXA_ROW("Size of Stack Commit", file_context->optional_header->variant.pe32.SizeOfStackCommit);
    PRINT_HEXA_ROW("Size of Heap Reserve", file_context->optional_header->variant.pe32.SizeOfHeapReserve);
    PRINT_HEXA_ROW("Size of Heap Commit", file_context->optional_header->variant.pe32.SizeOfHeapCommit);
    PRINT_HEXA_ROW("Loader Flags", file_context->optional_header->variant.pe32.LoaderFlags);
    PRINT_HEXA_ROW("Number of RVA and Sizes", file_context->optional_header->variant.pe32.NumberOfRvaAndSizes);
    
    printf("\t╚════════════════════════════════════════════════════════════════════════════════╝\n");
}

void print_section_headers(const File_Context* fc) {
    if (!fc || !fc->sections || !fc->coff_header) return;

    uint16_t n = fc->coff_header->number_of_sections;

    printf("\n\t╔═══════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("\t║ " BOLD_RED"%-8s │ %-16s │ %-16s │ %-16s │ %-16s │ %-10s"RESET" ║\n",
           "Name", "Virtual Addr", "Virtual Size", "Raw Ptr", "Raw Size", "Flags");
    printf("\t╠═══════════════════════════════════════════════════════════════════════════════════════════════════╣\n");

    for (uint16_t i = 0; i < n; i++) {
        const Section_Header* sec = &fc->sections[i];

        char name[9];
        memcpy(name, sec->Name, 8);
        name[8] = '\0';

        PRINT_SECTION(name,sec);
    }

    printf("\t╚═══════════════════════════════════════════════════════════════════════════════════════════════════╝\n\n");
}

