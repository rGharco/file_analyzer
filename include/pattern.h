#ifndef PATTERN_H
#define PATTERN_H

#include <stdint.h>

typedef struct {
	const char* pattern_name;
	size_t number_of_bytes;
	uint8_t* bytes;
} Pattern;

Pattern create_pattern(const char* pattern_name,const size_t nr_of_bytes, const uint8_t* byte_array);

#endif