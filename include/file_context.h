#ifndef FILE_CONTEXT_H
#define FILE_CONTEXT_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "../include/coff_header.h"
#include "../include/optional_header.h"
#include "../include/section_header.h"

/**
 * @brief Holds information about the current file being analyzed.
 *
 * The File_Context struct acts as a central container for data extracted
 * from the file during parsing. Parsers use the underlying FILE* to read
 * the file and populate this structure with metadata for future use.
 *
 * Design decisions:
 * - Encapsulation is not enforced, as most functions acting on File_Context
 *   need to move the file pointer directly. Using getters/setters would
 *   add unnecessary overhead in this case. (plus I didn't think of it when I first wrote the code :,))
 * - The `_mode` field is considered internal and should not be modified
 *   once the context is created.
 *
 * Public fields (accessible by parsers):
 * - path, size, has_ms_dos_signature, pe_signature_start_byte, is_pe,
 *   coff_header, optional_header, sections
 *
 * Private/internal fields:
 * - _mode
 */

typedef struct {
    FILE* file;
    char* path;
    char* _mode;
    uint64_t size;
    bool has_ms_dos_signature;
    uint32_t pe_signature_start_byte;
    bool is_pe;
    COFF_Header* coff_header;
    Optional_Header* optional_header;
    Section_Header* sections;
} File_Context;

typedef enum {
    FILE_CONTEXT_SUCCESS, //operation succeded
    FILE_CONTEXT_ERR_ALLOC, //Memory allocation failed
    FILE_CONTEXT_ERR_FOPEN, //File opening failed
    FILE_CONTEXT_ERR_FREAD, //File reading failed
    FILE_CONTEXT_ERR_NO_PATH_OR_MODE, // Invalid arguments passed (null path/mode)
} Fc_Status;


/**
 * @brief Creates and initializes a new File_Context.
 *
 * Opens the given file, calculates its size, and prepares
 * a File_Context structure for parsing.
 *
 * @param path Path to the file to open.
 * @param mode File open mode (e.g., "rb").
 * @param ctx  Output pointer to a File_Context* (allocated inside).
 *
 * @return Fc_Status status code indicating success or error.
 */
Fc_Status create_file_context(const char* path, const char* mode, File_Context** ctx);


/**
 * @brief Frees a previously allocated File_Context.
 *
 * Closes the file handle and releases all allocated memory associated
 * with the File_Context.
 *
 * @param file_context Pointer to the File_Context to free.
 */


void free_file_context(File_Context* file_context);

/**
 * @brief Converts Fc_Status enum value to a human-readable string.
 *
 * @param status Status code.
 * @return const char* Human-readable string describing the status.
 */
const char* fc_status_str(Fc_Status status);

#endif
