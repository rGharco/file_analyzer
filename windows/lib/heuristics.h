#pragma once

#include <stdlib.h>
#include <basetsd.h>
#include <math.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "file_context.h"
#include "../../common/include/print_helper.h"

/**
 * @author Radulescu Alexandru-Gabriel
 * @date 14.09.2025
 * 
 * @file heuristics.h
 * @brief Holds data about the file that will be later used in analysis to determine if its malicious or not.
 *        On top of that all the data that is stored will then later be used to create an organised report of 
 *        the findings.
 * 
 * 
*/ 

typedef struct HEURISTICS HEURISTICS;
typedef struct HEURISTICS* PHEURISTICS;

typedef struct SECTION_DATA SECTION_DATA;
typedef struct SECTION_DATA* PSECTION_DATA;

typedef enum SECTION_FLAG SECTION_FLAG;

typedef enum STATUS STATUS;

//----------------------------------------------------------------------------------
// Public API
//----------------------------------------------------------------------------------

PHEURISTICS createHeuristics(const PFILE_CONTEXT fc);
void freeHeuristics(PHEURISTICS heuristics); // Caller MUST free the heuristics struct

void setFileSize(PHEURISTICS heuristics,PFILE_CONTEXT fc);

LONGLONG getSize(const PHEURISTICS heuristics);
double getEntropy(const PHEURISTICS heuristics);

double getMaliciousScore(const PHEURISTICS heuristics);
UINT8 getRaisedFlags(const PHEURISTICS heuristics);

void analyzeFileEntropy(PHEURISTICS heuristics, const PFILE_CONTEXT fileContext);
void analyzeSectionEntropy(PHEURISTICS heuristics, const PFILE_CONTEXT fc);
void analyzeSectionFlag(PHEURISTICS heuristics, const PFILE_CONTEXT fc); // Checks for the IMAGE_SCN_MEM_EXECUTE flag set on any other sections than .text
int calculateFileHash(PHEURISTICS heuristics, PFILE_CONTEXT fc); // This function will also print the file hashes
