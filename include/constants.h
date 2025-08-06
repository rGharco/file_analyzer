#ifndef CONSTANTS_H
#define CONSTANTS_H

#ifdef _WIN32
#define strdup _strdup
#endif

#include <stdint.h>  

extern const size_t PE_HEADER_OFFSET;
extern const uint8_t COFF_HEADER_BYTES;
extern const uint8_t PE_SIGNATURE_BYTES;
extern const uint8_t PE_SIGNATURE_LENGTH;
extern const uint8_t OPTIONAL_HEADER_PE32_SIZE;
extern const uint8_t OPTIONAL_HEADER_PE32_PLUS_SIZE;
extern const uint8_t SECTION_HEADER_SIZE;

#endif
