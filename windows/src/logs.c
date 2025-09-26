#include "../lib/logs.h"
#include "../lib/file_context.h"

void logStatusFc(FILE_CONTEXT_STATUS status) {
    if(status == FC_SUCCESS) {
        return;
    }
    else {
        fprintf(stderr, "\n[-] Failed to initiate file context!\nError Code: %d (%s)\n", status, getStatusCodeName(status));
        fflush(stderr);
    }
    
    return;
}