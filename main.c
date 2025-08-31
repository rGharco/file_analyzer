#include <stdlib.h>
#include <string.h>
#include "../include/pattern.h"
#include "../include/file_context.h"
#include "../include/pe_utils.h"
#include "../include/constants.h"
#include "../include/print_helper.h"
#include <time.h>
#include "../include/heuristics.h"

#define BINARY_READ "rb"
#define BINARY_WRITE "wb"
#define BUFFER_SIZE 255

int main(int argc, char* argv[]) {

	if(argc < 2) {
		print_banner();
		print_usage(argv[0]);
    	exit(EXIT_FAILURE);
	}

	File_Context* file_context = NULL;
	Fc_Status ctx_status = create_file_context(argv[1], BINARY_READ, &file_context);

	//This should be temporary as in the future we will analyze batches of files 
	if(ctx_status != FILE_CONTEXT_SUCCESS) {
		fprintf(stderr,"Couldn't initiate file context for file: %s\n", argv[1]);
		fprintf(stderr,"EXIT STATUS: %s", fc_status_str(ctx_status));
		fflush(stderr);
		exit(EXIT_FAILURE);
	}

	//PE File Checking
	uint8_t ms_dos_bytes[2] = {0x4D, 0x5A};
	Pattern ms_dos = create_pattern("MS_DOS File Pattern", 2, ms_dos_bytes);

	uint8_t pe_signature_bytes[4] = {0x50, 0x45, 0x00, 0x00};
	Pattern pe_signature = create_pattern("PE file format signature", 4, pe_signature_bytes);

	if(strcmp(argv[2], "-e") == 0) {
		print_banner();
		if(is_executable(file_context,&ms_dos,&pe_signature) == PE_PARSE_SUCCESS) {
			
			parse_coff_header(file_context);
			parse_optional_header(file_context);
			parse_section_header(file_context);


			Heuristics* heuristics = create_heuristics(file_context);
			
			printf("\nFILE SIZE: %.2lfMB\n", (double)file_context->size / 1048576);
			printf("Entropy: %lf\n", get_file_entropy(heuristics));

			analyze_file_entropy(heuristics);
			printf("Malicious Score: %lf\n", get_malicious_score(heuristics));
			printf("Raised Flags: %u\n", get_raised_flags(heuristics));

			free_heuristics(heuristics);
		}
	}
	
	free_file_context(file_context);

	return 0;
}
