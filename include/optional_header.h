#ifndef OPTIONAL_HEADER_H
#define OPTIONAL_HEADER_H

#include <stdint.h>

typedef struct {
    uint16_t magic_number;
    uint8_t major_linker_version;
    uint8_t minor_linker_version;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uinitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
} Optional_Header;

#endif