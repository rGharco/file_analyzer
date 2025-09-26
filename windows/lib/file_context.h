#pragma once

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <malloc.h>
#include <string.h>
#include "../../common/include/print_helper.h"
#include <windows.h>
#include <fileapi.h>
#include "../lib/logs.h"

/**
 * @author Radulescu Alexandru-Gabriel
 * @date 14.09.2025 
 * 
 * @file file_context.h
 * @brief Defines the FILE_CONTEXT struct and associated functions with it
 *
 * This module abstracts Windows file handling for PE analysis, including:
 *   - File mapping
 *   - Access to COFF/PE headers
 *   - Utility functions for offsets, and base address retrieval
 * 
 * @struct FILE_CONTEXT
 * 
 * MEMBERS: 
 *  -hFileHandle - HANDLE to the file passed as CLI argument returned by internal @fn initiateFileHandle()
 *  -hFileMapHandle - HANDLE to the file Map returned by the internal @fn initiateFileMap() 
 *  -_baseAddress - LPVOID to the baseAddress of the file, later used for parsing in functions 
 *                 such as peSignatureCheck() in pe_utils.c. 
 *                 @cond the underscore signifies this value shouldn't be changed.
 *  -e_lfanew - LONG value that determines where the PE header starts, stored to continue parsing from it
 *              using addition to the baseAddress (changing the offset this way) so that we don't modify the 
 *              actual baseAddress itself. This is done to make sure later on we don't encounter issues with 
 *              the pointer being in the middle of the file.
 *  -coffHeader - IMAGE_FILE_HEADER* value indicating the fields of the coffHeader, when parsing the file
 *                this will just point to a memory zone and the struct will fall on top of it (basically
 *                making the bytes overlap with the structure).
 *                IMPORTANT: This is strictly just a pointer, we are not actually storing the values anywhere
 *                           if the file map is closed we lose this values and cannot access them afterwards.
 *  -peType - PE_TYPE enum value, used to make freeing the file context easier by choosing the right struct 
 *            for the optional header based on the magic number it has
 *            EX: 0x10b == PE32 
 *  -optionalHeaderType - UNION value, chooses between either a PE32 optional header struct or a PE32+ 
 *                        making sure we are overlapping the correct bytes when putting the struct pointer
 *  -sectionHeaders - IMAGE_SECTION_HEADER* value, stores the data about section headers
 *                    IMPORTANT: Since we are using the same technique of overlapping the bytes with the struct
 *                               layout, accessing sectionHeaders[i] will try to map the struct to the next
 *                               bytes in memory, therefore we don't need an array to store pointers to the
 *                               section headers for each.
 * 
 * WORKFLOW: 
 * 
 * 1. First we must call the createFileContext() function which will in return:
 *          a. Call initiateFileHandle, initiateFileMap, initiateMapView all of which will make sure
 *             we are opening a valid HANDLE for the file and initiate the mapping process of the file
 * 2. Use helper functions such as setCoffHeader() to fill in fields. These functions are especially used in
 *    the @file pe_utils.c 
 * 3. Do heuristics on the file, this is done in the @file heuristics.c. We must not close the context until
 *    we find all the info about it and classify it accordingly.
 * 4. Free the context, closing all the handles. This is done in the freeFileContext() function.
 * 
 * 
 * NOTE: This struct will only be manipulated via API functions provided 
 */

typedef struct FILE_CONTEXT FILE_CONTEXT;
typedef struct FILE_CONTEXT* PFILE_CONTEXT;

typedef enum FILE_CONTEXT_STATUS{
    FC_SUCCESS = 0,
    FC_ERR_ALLOC,
    FC_ERR_FILE,
    FC_ERR_MAP,
    FC_ERR_VIEW
} FILE_CONTEXT_STATUS;

/**
 * @brief Initializes the file context opening up file handles, creating the file map and map view
 * @param pFileName it is the CLI supplied file name as for this version of the program.
 * @param status the FILE_CONTEXT_STATUS variable that will register the result of the function
 * @return returns a POINTER to the file context that should be then later freed using freeFileContext
 *         Remember to not free the struct until the heuristics are extracted.
 */
PFILE_CONTEXT createFileContext(LPCSTR pFileName, FILE_CONTEXT_STATUS *status);

/**
 * @brief Sets header pointers to NULL, closes handles and map view
 * @param fc is the pointer to the file context to be freed
 * @return void
 * 
 * @warning Setting the pointers to the file header structs to NULL is important because once the file map is
 * closed that pointer can point anywhere in memory, therefore causing an undefined behaviour. 
 * Worst case scenario we are trying to free a memory zone that's not allocated and we get seg fault.
 * We also can't just free the pointers because we didn't allocate memory to them. They are effectively    
 * pointing to memory in the file map.
 */
void freeFileContext(PFILE_CONTEXT fc);

/**
 * @brief Getters for the file context struct
 * @param fc pointer to the file context to get data from
 * @return the specific field requested
 */

LONG getPeOffset(const PFILE_CONTEXT fc);
LPVOID getBaseAddress(const PFILE_CONTEXT fc);
HANDLE getFileHandle(const PFILE_CONTEXT fc);
IMAGE_SECTION_HEADER* getSectionHeader(const PFILE_CONTEXT fc);
WORD getNrOfSections(const PFILE_CONTEXT fc);
const char* getStatusCodeName(const FILE_CONTEXT_STATUS status);

/**
 * @brief Setters for the file context struct
 * @param fc pointer to the file context that you want to modify, and the data supplied
 * @return void since we only modify internal fields
 */

void setPeOffset(PFILE_CONTEXT fc, LONG pE_lfanew);
void setCoffHeader(PFILE_CONTEXT fc, IMAGE_FILE_HEADER* pCoffHeader);
void setPeType(PFILE_CONTEXT fc,WORD magicNumber);
void setOptionalHeaderPe32Plus(PFILE_CONTEXT fc, IMAGE_OPTIONAL_HEADER64* pOptionalHeader);
void setOptionalHeaderPe32(PFILE_CONTEXT fc, IMAGE_OPTIONAL_HEADER32* pOptionalHeader);
void setSectionHeader(PFILE_CONTEXT fc, IMAGE_SECTION_HEADER* pSectionHeader);
