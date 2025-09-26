#include "../lib/file_context.h"

// Magic Number values
#define PE32_MAGIC_NUMBER 0x10b
#define PE32_PLUS_MAGIC_NUMBER 0x20b

typedef enum {
	NONE,
	PE32,
	PE32_PLUS
} PE_TYPE;

struct FILE_CONTEXT {
	HANDLE hFileHandle;
	HANDLE hFileMapHandle;
	LPVOID baseAddress;
	LONG e_lfanew;
	IMAGE_FILE_HEADER* coffHeader;
	PE_TYPE peType;
	union {
		IMAGE_OPTIONAL_HEADER64* optionalHeaderPe32Plus;
		IMAGE_OPTIONAL_HEADER32* optionalHeaderPe32;
	} optionalHeaderType;
	IMAGE_SECTION_HEADER* sectionHeaders; 
};

static const char* statusNames[] = {
	 [FC_SUCCESS] "STATUS SUCCESS",
	 [FC_ERR_ALLOC] "MEMORY ALLOCATION ERROR",
	 [FC_ERR_FILE] "FILE HANDLE ERROR",
	 [FC_ERR_MAP] "FILE MAPPING ERROR", 
	 [FC_ERR_VIEW] "MAP VIEW ERROR"
};

//----------------------------------------------------------------------------------
// Function prototypes
//----------------------------------------------------------------------------------

// PUBLIC API
PFILE_CONTEXT createFileContext(LPCSTR pFileName, FILE_CONTEXT_STATUS *status);
void freeFileContext(PFILE_CONTEXT fc);

LONG getPeOffset(const PFILE_CONTEXT fc);
LPVOID getBaseAddress(const PFILE_CONTEXT fc);
HANDLE getFileHandle(const PFILE_CONTEXT fc);
IMAGE_SECTION_HEADER* getSectionHeader(const PFILE_CONTEXT fc);
WORD getNrOfSections(const PFILE_CONTEXT fc);

void setPeOffset(PFILE_CONTEXT fc, LONG pE_lfanew);
void setCoffHeader(PFILE_CONTEXT fc, IMAGE_FILE_HEADER* pCoffHeader);
void setPeType(PFILE_CONTEXT fc,WORD magicNumber);
void setOptionalHeaderPe32Plus(PFILE_CONTEXT fc, IMAGE_OPTIONAL_HEADER64* pOptionalHeader);
void setOptionalHeaderPe32(PFILE_CONTEXT fc, IMAGE_OPTIONAL_HEADER32* pOptionalHeader);
void setSectionHeader(PFILE_CONTEXT fc, IMAGE_SECTION_HEADER* pSectionHeader);

// PRIVATE FUNCTIONS
static HANDLE initiateFileHandle(LPCSTR pFileName);
static HANDLE initiateFileMap(HANDLE pFileHandle);
static LPVOID initiateMapView(HANDLE pFileMapHandle);

//----------------------------------------------------------------------------------
// Public API implementations
//----------------------------------------------------------------------------------

PFILE_CONTEXT createFileContext(LPCSTR pFileName, FILE_CONTEXT_STATUS *status) {
    PFILE_CONTEXT fileContext = calloc(1, sizeof(FILE_CONTEXT));
    if (fileContext == NULL) {
        *status = FC_ERR_ALLOC;
        return NULL;
    }

    fileContext->hFileHandle = initiateFileHandle(pFileName);
    if (fileContext->hFileHandle == INVALID_HANDLE_VALUE) {
        *status = FC_ERR_FILE;
        free(fileContext);
        return NULL;
    }

    fileContext->hFileMapHandle = initiateFileMap(fileContext->hFileHandle);
    if (fileContext->hFileMapHandle == NULL) {
        *status = FC_ERR_MAP;
        CloseHandle(fileContext->hFileHandle);
        free(fileContext);
        return NULL;
    }

    fileContext->baseAddress = initiateMapView(fileContext->hFileMapHandle);
    if (fileContext->baseAddress == NULL) {
        *status = FC_ERR_VIEW;
        CloseHandle(fileContext->hFileMapHandle);
        CloseHandle(fileContext->hFileHandle);
        free(fileContext);
        return NULL;
    }

    *status = FC_SUCCESS;
    return fileContext;
}

void freeFileContext(PFILE_CONTEXT fc) {
	if(fc == NULL) return;

	//No free() function calls should happen as the pointers of these structs are from the 
	//mapped file in memory.
	fc->coffHeader = NULL;
    fc->optionalHeaderType.optionalHeaderPe32 = NULL;
    fc->optionalHeaderType.optionalHeaderPe32Plus = NULL;
    fc->sectionHeaders = NULL;

	UnmapViewOfFile(fc->baseAddress);
	CloseHandle(fc->hFileMapHandle);
	CloseHandle(fc->hFileHandle);

	free(fc);
}

static HANDLE initiateFileHandle(LPCSTR pFileName) {
	HANDLE hFileHandle = CreateFile(
		pFileName, 			
		GENERIC_READ,		
		FILE_SHARE_READ,	
		NULL,				
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hFileHandle == INVALID_HANDLE_VALUE) {
		return hFileHandle;
	}

	return hFileHandle;
}

static HANDLE initiateFileMap(HANDLE pFileHandle) {
	HANDLE hFileMapping = NULL;

    hFileMapping = CreateFileMapping(
        pFileHandle,
        NULL,
        PAGE_READONLY,
        0,
        0, // this maps the whole file in memory
        NULL
    );

    if (hFileMapping == NULL ) {
        return hFileMapping;
    }

    return hFileMapping;
}

static LPVOID initiateMapView(HANDLE pFileMapHandle) {
	LPVOID baseAddress = NULL;

    baseAddress = MapViewOfFile(
        pFileMapHandle,
        FILE_MAP_READ,
        0,
        0,
        0
    );

    if (baseAddress == NULL) {
        return baseAddress;	
    }

    return baseAddress;
}

//----------------------------------------------------------------------------------
// Setters
//----------------------------------------------------------------------------------

void setPeOffset(PFILE_CONTEXT fc, LONG pE_lfanew) {
	fc->e_lfanew = pE_lfanew;
}

void setCoffHeader(PFILE_CONTEXT fc, IMAGE_FILE_HEADER* pCoffHeader) {
	fc->coffHeader = pCoffHeader;
}

void setPeType(PFILE_CONTEXT fc,WORD magicNumber) {
	switch(magicNumber) {
		case PE32_MAGIC_NUMBER:
			fc->peType = PE32;
			break;
		case PE32_PLUS_MAGIC_NUMBER:
			fc->peType = PE32_PLUS;
			break;
		default:
			fc->peType = NONE;
			break;
	}
}

void setOptionalHeaderPe32Plus(PFILE_CONTEXT fc, IMAGE_OPTIONAL_HEADER64* pOptionalHeader) {
	fc->optionalHeaderType.optionalHeaderPe32Plus = pOptionalHeader;
}

void setOptionalHeaderPe32(PFILE_CONTEXT fc, IMAGE_OPTIONAL_HEADER32* pOptionalHeader) {
	fc->optionalHeaderType.optionalHeaderPe32 = pOptionalHeader;
}

void setSectionHeader(PFILE_CONTEXT fc, IMAGE_SECTION_HEADER* pSectionHeader) {
	fc->sectionHeaders = pSectionHeader;
}

//----------------------------------------------------------------------------------
// Getters
//----------------------------------------------------------------------------------

LONG getPeOffset(const PFILE_CONTEXT fc) {
	return fc->e_lfanew;
}

LPVOID getBaseAddress(const PFILE_CONTEXT fc) {
	return fc->baseAddress;
}

HANDLE getFileHandle(const PFILE_CONTEXT fc) {
	return fc->hFileHandle;
}

IMAGE_SECTION_HEADER* getSectionHeader(const PFILE_CONTEXT fc) {
	return fc->sectionHeaders;
}

WORD getNrOfSections(const PFILE_CONTEXT fc) {
	return fc->coffHeader->NumberOfSections;
}

const char* getStatusCodeName(const FILE_CONTEXT_STATUS status) {
	return statusNames[status];
}