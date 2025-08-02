#ifndef DATA_DIRECTORY_H
#define DATA_DIRECTORY_H

#include <stdint.h>

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} Data_Directory;

#endif
