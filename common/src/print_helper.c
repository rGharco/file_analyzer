#define BOLD_CYAN "\e[1;36m"
#define BOLD_RED "\e[1;31m"
#define BOLD_GREEN   "\e[1;32m"
#define BOLD_YELLOW  "\e[1;33m"
#define YELLOW "\e[0;33m"
#define BOLD_BLUE    "\e[1;34m"
#define RESET   "\033[0m"
#include "../include/print_helper.h"

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

int checkArgs(const int count, ...);

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

int checkArgs(const int count, ...) {
    va_list args;
    va_start(args, count);

    for(int i = 0; i < count; i++) {
        const void* arg = va_arg(args, const void*);
        if(arg == NULL) {
            va_end(args);
            return -1;
        }
    }

    va_end(args);
    return 0;
}