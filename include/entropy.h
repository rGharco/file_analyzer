#ifndef ENTROPY_H
#define ENTROPY_H

#include <stdint.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>

double entropy(uint64_t byte_count[], uint64_t size);
uint64_t* extract_file_byte_count(FILE* in_File);

#endif