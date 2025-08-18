#ifndef CONSTANTS_H
#define CONSTANTS_H

#ifdef _WIN32
#define strdup _strdup
#endif

#include <stdint.h>  

extern const size_t PE_HEADER_OFFSET;
extern const uint8_t PE_SIGNATURE_LENGTH;
extern const uint16_t PE32;
extern const uint16_t PE32_PLUS;

#endif
