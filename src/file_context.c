#include "../include/file_context.h"
#include "../include/constants.h"
#include <malloc.h>
#include <string.h>

size_t get_file_size(const File_Context* file_context);
void free_file_context(File_Context* file_context);

File_Context* create_file_context(const char* path, const char* mode) {
    if (!path || !mode) {
        printf("[-] Path or mode not specified. create_file_context() failed!\n");
        return NULL;
    }

    FILE* file = fopen(path, mode);
    if(!file) {
        printf("[-] Failed to open file: %s. create_file_context() failed!\n", path);
        return NULL;
    }

    File_Context* file_context = (File_Context*)malloc(sizeof(File_Context));

    if(file_context == NULL) {
        printf("[-] Failed to allocate memory to file context! create_file_context() failed!\n");
        fclose(file);
        return NULL;
    }

    memset(file_context, 0, sizeof(File_Context));

    file_context->file = file;
    
    file_context->path = strdup(path);

    if(file_context->path == NULL) {
        printf("[-] Failed to allocate memory to file_context path! create_file_context() failed!\n");
        goto file_context_cleanup;
    }

    file_context->mode = strdup(mode);

    if(file_context->mode == NULL) {
        printf("[-] Failed to allocate memory to file_context mode! create_file_context() failed!\n");
        goto file_context_cleanup;
    }

    file_context->size = get_file_size(file_context);

    file_context->size = get_file_size(file_context);

    if(file_context->size == 0) {
        printf("[!] Warning: File size is 0. Proceeding anyway.\n");
        file_context->buffer = NULL;
        return file_context;
    }

    file_context->buffer = malloc(file_context->size);

    if(file_context->buffer == NULL) {
        printf("[-] Failed to initialize reading buffer. create_file_context() failed!\n");
        goto file_context_cleanup;
    }

    /******* Default initializers *************/
    
    file_context->is_pe = false;
    file_context->has_ms_dos_signature = false;
    file_context->pe_signature_start_byte = 0x0;
    file_context->coff_header = NULL;
    file_context->optional_header = NULL;

    /******* Default initializers *************/

    return file_context;

    file_context_cleanup:
        free_file_context(file_context);
        return NULL;
}

void set_pe_flag(File_Context* file_context) {
    file_context->is_pe = true;
}

size_t get_file_size(const File_Context* file_context) {
    if(fseek(file_context->file, 0, SEEK_END) != 0) {
        printf("[-] Failed to get file size!\n");
        return 0;
    } 

    size_t size = ftell(file_context->file);
    fseek(file_context->file, 0, SEEK_SET);

    return size;
}

void free_file_context(File_Context* file_context) {
    if (file_context == NULL) return;

    if (file_context->file) fclose(file_context->file);
    if (file_context->path) free(file_context->path);
    if (file_context->mode) free(file_context->mode);
    if (file_context->buffer) free(file_context->buffer);
    if (file_context->coff_header) free(file_context->coff_header);
    if (file_context->optional_header) free(file_context->optional_header);
    free(file_context);
}