#include <stdlib.h>
#include <string.h>
#include "../windows/lib/file_context.h"
#include "../include/print_helper.h"
#include "../windows/lib/heuristics.h"
#include "../windows/lib/pe_utils.h"
#include "../windows/lib/logs.h"

int main(int argc, char* argv[]) {

	if(argc < 2) {
		print_banner();
		print_usage(argv[0]);
    	exit(EXIT_FAILURE);
	}

	print_banner();

//----------------------------------------------------------------------------------
// Setting up the file context
//----------------------------------------------------------------------------------

	FILE_CONTEXT_STATUS status;
	PFILE_CONTEXT fileContext = createFileContext((LPCSTR)argv[1], &status);
	
	logStatusFc(status);

	if(fileContext == NULL) {
		exit(EXIT_FAILURE);
	}

	LPVOID baseAddress = NULL;
	baseAddress = getBaseAddress(fileContext);

	peSignatureCheck(baseAddress, fileContext);
	parseHeaders(baseAddress, fileContext);

//----------------------------------------------------------------------------------
// Obtain heuristics
//----------------------------------------------------------------------------------

	PHEURISTICS heuristics = NULL;
	heuristics = createHeuristics(fileContext);

	setFileSize(heuristics, fileContext);

	print_action("OBTAINING HEURISTICS");
	calculateFileHash(heuristics, fileContext);
	printf("\n");
	analyzeFileEntropy(heuristics, fileContext);
	printf("\n");
	analyzeSectionEntropy(heuristics, fileContext);
	analyzeSectionFlag(heuristics,fileContext);
	printf("\nFILE SIZE: %.2lf MB\n", (double)getSize(heuristics) / 1000000);

	printf("MALICIOUS SCORE: %.2lf\n", getMaliciousScore(heuristics));
	printf("SUSPICIOUS FLAGS RAISED: %u\n", getRaisedFlags(heuristics));

	freeFileContext(fileContext);

	return 0;
}
