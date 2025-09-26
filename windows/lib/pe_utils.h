#pragma once

#include "file_context.h"
#include "../../common/include/print_helper.h"
#include <stdlib.h>
#include <windows.h>

/**
 * @author Radulescu Alexandru-Gabriel
 * @date 14.09.2025
 * 
 * @file pe_utils.h
 * @brief Defines functionality for parsing the PE header of a file through helper functions
 * 
 * This module provides an API through which you can check the PE signature of a file and parse its headers.
 * It is very fast and lightweight not storing the actual data of the headers in memory but instead pointing 
 * to it, coming with the caveat of paying attention to the file context and its handles. (more on that in
 * @file PFILE_CONTEXT.h)
 * 
 * MEMBERS:
 *  - @enum PE_PARSE_STATUS, an enum used to supply API codes for the following functions. We will then use
 *          these error codes to identify what failed and provide them in the CLI for the user to know what 
 *          caused the issue
 * 
 *  - @fn peSignatureCheck()
 *      @param baseAddress and fileContext, we need the base address to start reading from the beginning of
 *             the file to check for the MS DOS bytes and then move to the offset indicated by e_lfanew.
 *             All the moving operations are done by adding offset bytes to the baseAddress pointer, which
 *             has a local copy inside the function scope.
 *      @return PE_PARSE_STATUS a code to indicate how the parsing operation went
 * 
 *  - @fn parseHeaders()
 *      @param baseAddress and fileContext, we once again add offsets and change the pointer of baseAddress
 *             using a scope variable. Each time we reach the byte that indicates a header (COFF, Optional etc.)
 *             we assign a pointer to that offset after which a windows API struct that is specifically 
 *             designed for the header will overlap in memory. We the assign that pointer to the file context
 *             to store it.
 *      @return PE_PARSE_STATUS a code to indicate how the parsing operation went
 * 
 * WORKFLOW: 
 * 
 * 1. Start by verifying the MS DOS signature and PE signature using the @fn peSignatureCheck().
 *      a. If the function is a success then we can move on with parsing the headers with @fn parseHeaders()
 *      b. If the function fails we found a malformation in the file format or the file is not a PE
 *      IMPORTANT: remember that a .dll file also has the characteristics of a .exe file but a .obj file 
 *                 does not
 * 
 * NOTE: Although we do not modify the base address pointer it is recommended to use these functions one 
 *       after the other to assure logic in the program.
 */

 /**
  * @brief An enum that supplies error codes for the API functions
  * 
  * @param PE_PARSE_ERR_MS_DOS_SIG indicates failure in matching the MS DOS bytes
  * @param PE_PARSE_ERR_PE_SG indicates failure in matching the PE signature bytes
  * @param PE_PARSE_OPTIONAL_HEADER indicates failure in matching a valid PE32 format using the magic number
  */

typedef enum {
    PE_PARSE_SUCCESS,
    PE_PARSE_ERR_MS_DOS_SIG,
    PE_PARSE_ERR_PE_SIG,
    PE_PARSE_ERR_OPTIONAL_HEADER,
} PE_PARSE_STATUS;

/**
 * @brief Function that checks the PE signature
 * 
 * @param baseAddress of the Map View obtained from using the @fn createFileContext(), this address will not
 *        be modified for safety issues if later on we wish to access another part of the file. For more 
 *        information about why check out @file PFILE_CONTEXT.c 
 * @param fileContext the current context of the file to supply data into after parsing such as the 
 *        pointer to the COFF header in memory, and the pointers to the other headers as well.
 * @return PE_PARSE_STATUS code inidcating the result of the fucntion
 */
PE_PARSE_STATUS peSignatureCheck(const LPVOID baseAddress, PFILE_CONTEXT fileContext);

/**
 * @brief Function that parses the PE header
 * 
 * @param baseAddress same baseAddress used in the first function, won't be modified here either. We start
 *        from the beginning of the file and then add the e_lfanew value to get to the PE , skip 4 bytes
 *        (the PE signature length) and then we start parsing by assinging pointers and overlapping.
 * @param fileContext the pointer to the fileContext struct to be filled with information afterwards.
 * 
 * @return PE_PARSE_STATUS code indicating the result of the function.
 */
PE_PARSE_STATUS parseHeaders(const LPVOID baseAddress, PFILE_CONTEXT fileContext);

