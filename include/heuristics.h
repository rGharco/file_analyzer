#ifndef HEURISTICS_H
#define HEURISTICS_H
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <stdio.h>

/**
 * @brief Holds indicators about the file each which wil have a role in determining the file nature
 *
 * The Heuristics struct will contain all the information that can be used together or by itself to determine the file nature
 * whether it be a high entropy for a section or for the whole file, a suspicious flag set for a section, YARA rules, etc.
 * 
 * Encapsulation is enforced in order to prevent the alteration of evidence regarding the file and because there is no real reason to access the internal fields from outside 
 * the API.
 *
 * Internal fields:
 * - _file_entropy - should not be modified, and only calculated 
*/

// Forward declaration of File_Context
struct File_Context;
typedef struct File_Context File_Context;

typedef struct Heuristics Heuristics;

typedef enum File_Status File_Status;

/********** PUBLIC API **********/

Heuristics* create_heuristics(File_Context* fc);

void free_heuristics(Heuristics* heuristics); // Caller MUST free the heuristics struct

double get_file_entropy(const Heuristics* heuristics);
double get_malicious_score(const Heuristics* heuristics);
uint8_t get_raised_flags(const Heuristics* heuristics);

/********** PUBLIC API **********/



/********** PRIVATE FUNCTIONS **********/

double entropy(uint64_t byte_count[], uint64_t size);
uint64_t* extract_file_byte_count(FILE* in_File);

void add_malicious_score(Heuristics* heuristics, double value);
void analyze_file_entropy(Heuristics* heuristics);

/********** PRIVATE FUNCTIONS **********/

#endif

