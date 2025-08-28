#include "../include/file_context.h"
#include "../include/constants.h"
#include "../include/print_helper.h"
#include <malloc.h>
#include <string.h>
#include <windows.h>
#include <fileapi.h>

Fc_Status create_file_context(const char* path, const char* mode, File_Context** file_context);
uint64_t get_file_size(const File_Context* file_context);
uint64_t get_file_size_win(const char* path);

void free_file_context(File_Context* file_context);

Fc_Status create_file_context(const char* path, const char* mode, File_Context** file_context)
{
    if (!path || !mode) {
        print_error("Path or mode not specified. create_file_context() failed!");
        return FILE_CONTEXT_ERR_NO_PATH_OR_MODE;
    }

    FILE* file = fopen(path, mode);

    if (!file) {
        print_error("Failed to open file. create_file_context() failed!");
        return FILE_CONTEXT_ERR_FOPEN;
    }

    *file_context = (File_Context*)malloc(sizeof(File_Context));

    if (*file_context == NULL) {
        print_error("Failed to allocate memory to file context! create_file_context() failed!");
        fclose(file);
        return FILE_CONTEXT_ERR_ALLOC;
    }

    memset(*file_context, 0, sizeof(File_Context));

    (*file_context)->file = file;
    (*file_context)->path = strdup(path);

    if (!(*file_context)->path) {
        print_error("Failed to allocate memory to file_context path! create_file_context() failed!");
        goto file_context_cleanup;
    }

    (*file_context)->mode = strdup(mode);
    
    if (!(*file_context)->mode) {
        print_error("Failed to allocate memory to file_context mode! create_file_context() failed!");
        goto file_context_cleanup;
    }

    #ifdef _WIN32
        (*file_context)->size = get_file_size_win((*file_context)->path);
    #else
        (*file_context)->size = get_file_size(*file_context);
    #endif

    if ((*file_context)->size == 0) {
        print_warning("File size is 0. Proceeding anyway.");
        return FILE_CONTEXT_SUCCESS;
    }

    // Default initializers
    (*file_context)->is_pe = false;
    (*file_context)->has_ms_dos_signature = false;
    (*file_context)->pe_signature_start_byte = 0x0;
    (*file_context)->coff_header = NULL;
    (*file_context)->optional_header = NULL;
    (*file_context)->sections = NULL;

    return FILE_CONTEXT_SUCCESS;

file_context_cleanup:
    free_file_context(*file_context);
    *file_context = NULL;
    return FILE_CONTEXT_ERR_ALLOC;
}

uint64_t get_file_size(const File_Context* file_context) {
    if (fseeko(file_context->file, 0, SEEK_END) != 0) {
        print_error("Failed to get file size!");
        return 0;
    }

    off_t pos = ftello(file_context->file);
    if (pos < 0) {
        print_error("ftello failed!");
        fseeko(file_context->file, 0, SEEK_SET);
        return 0;
    }

    fseeko(file_context->file, 0, SEEK_SET);
    return (uint64_t)pos;
}

uint64_t get_file_size_win(const char* path) {
    HANDLE hFile = CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        print_error("Failed to open file! get_file_size_win failed!");
        return 0;
    }

    LARGE_INTEGER liFileSize;

    if (!GetFileSizeEx(hFile, &liFileSize)) {
        print_error("Failed to get file size! get_file_size_win failed!");
        CloseHandle(hFile);
        return 0;
    }

    CloseHandle(hFile);
    return (uint64_t)liFileSize.QuadPart;
}

void free_file_context(File_Context* file_context) {
    if (file_context == NULL) return;

    if (file_context->file) fclose(file_context->file);
    if (file_context->path) free(file_context->path);
    if (file_context->mode) free(file_context->mode);
    if (file_context->coff_header) free(file_context->coff_header);
    if (file_context->optional_header) free(file_context->optional_header);
    if (file_context->sections) free(file_context->sections);
    
    free(file_context);
}

const char* fc_status_str(Fc_Status status) {
    switch(status) {
        case FILE_CONTEXT_SUCCESS: return "FILE_CONTEXT_SUCCESS";
        case FILE_CONTEXT_ERR_ALLOC: return "FILE_CONTEXT_ERR_ALLOC";
        case FILE_CONTEXT_ERR_FOPEN: return "FILE_CONTEXT_ERR_FOPEN";
        case FILE_CONTEXT_ERR_FREAD: return "FILE_CONTEXT_ERR_FREAD";
        case FILE_CONTEXT_ERR_NO_PATH_OR_MODE: return "FILE_CONTEXT_ERR_NO_PATH_OR_MODE";
    }
}