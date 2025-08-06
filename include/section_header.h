#ifndef SECTION_HEADER_H
#define SECTION_HEADER_H

#include <stdint.h>

#pragma pack(push,1)

typedef struct {
    char     Name[8];               
    uint32_t VirtualSize;
    uint32_t VirtualAddress;        
    uint32_t SizeOfRawData;        
    uint32_t PointerToRawData;      
    uint32_t PointerToRelocations;  
    uint32_t PointerToLinenumbers;  
    uint16_t NumberOfRelocations;   
    uint16_t NumberOfLinenumbers;   
    uint32_t Characteristics;      
} Section_Header;

#pragma pack(pop)

#endif
