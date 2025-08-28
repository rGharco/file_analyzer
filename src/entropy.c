#include "entropy.h"
#define BYTE_OUTCOMES 256
#define BUFFER_SIZE 1024

double entropy(uint64_t byte_count[], uint64_t size) {
    double entropy = 0.0;

    for(int i = 0; i < BYTE_OUTCOMES; i++) {
        if(byte_count[i] != 0) {
            double p = (double)byte_count[i] / (double)size;
            entropy += -p * log2(p);
        }
    }

    return entropy;
}

uint64_t* extract_file_byte_count(FILE* in_File) {
    uint8_t buffer[BUFFER_SIZE] = {0};
    uint64_t* byte_count = calloc(BYTE_OUTCOMES, sizeof(uint64_t));
    uint64_t n;

    rewind(in_File);
    while((n = fread(buffer,1,BUFFER_SIZE,in_File)) != 0) {
        for(int i = 0; i < n; i++) {
            byte_count[buffer[i]]++;
        }
    }

    return byte_count;
}