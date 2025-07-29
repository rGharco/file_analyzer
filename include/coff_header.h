#ifndef COFF_HEADER_H
#define COFF_HEADER_H

#include <stdint.h>

typedef struct {
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
} COFF_Header;

#endif