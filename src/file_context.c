#include "../include/file_context.h"
#include <malloc.h>
#include <string.h>

size_t get_file_size(const File_Context* file_context);

File_Context* create_file_context(const char* path, const char* mode) {
    if(path == NULL) {
        printf("[-] File path not specified!\n");
        return NULL;
    }

    if(mode == NULL) {
        printf("[-] File mode not specified!\n");
        return NULL;
    }

    FILE* file = fopen(path, mode);
    if(!file) {
        printf("[-] Failed to open file: %s\n", path);
        return NULL;
    }

    File_Context* file_context = (File_Context*)malloc(sizeof(File_Context));

    if(file_context == NULL) {
        printf("[-] Failed to allocate memory to file context!\n");
        return NULL;
    }

    file_context->file = file;
    
    file_context->path = (char*)malloc(strlen(path) + 1);

    if(file_context->path == NULL) {
        printf("[-] Failed to allocate memory to file_context path!\n");
        free(file_context);
        return NULL;
    }

    strcpy(file_context->path, path);

    file_context->mode = (char*)malloc(strlen(mode)+1);

    if(file_context->mode == NULL) {
        printf("[-] Failed to allocate memory to file_context mode!\n");
        free(file_context);
        free(file_context->path);
        return NULL;
    }

    strcpy(file_context->mode, mode);

    size_t size = get_file_size(file_context);

    if(size == 0) {
        file_context->buffer = NULL;
        printf("[-] Could not initialize reading buffer. File size is 0\n");
    }
    else {
        file_context->buffer = malloc(size);
    }

    file_context->size = size;

    /******* Default initializers *************/
    
    file_context->is_pe = false;
    file_context->has_ms_dos_signature = false;
    file_context->pe_signature_start_byte = 0x0;
    file_context->time_date_stamp = 0x0;

    /******* Default initializers *************/

    return file_context;
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
    free(file_context);
}