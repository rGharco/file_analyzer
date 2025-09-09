#include "../include/pattern.h"

Pattern create_pattern(const char* pattern_name, const size_t nr_of_bytes, const uint8_t* byte_array) {
    Pattern pattern;
    pattern.pattern_name = pattern_name;
    pattern.number_of_bytes = nr_of_bytes;
    pattern.bytes = NULL;

    if (byte_array != NULL) {
        pattern.bytes = (uint8_t*)malloc(sizeof(uint8_t) * nr_of_bytes);
        if (pattern.bytes != NULL) {
            memcpy(pattern.bytes, byte_array, nr_of_bytes);
        }
        else {
            perror("Failed to allocate memory for pattern bytes");
            exit(EXIT_FAILURE);
        }
    } else {
        printf("Error: Cannot create pattern '%s' with NULL byte array!\n", pattern_name);
        exit(EXIT_FAILURE);  
    }

    return pattern;
}
