#include "../lib/heuristics.h"
#include "../lib/file_context.h"

// ANSI colors for printing
#define BOLD_RED "\e[1;31m"
#define BOLD_YELLOW "\e[1;33m"
#define BOLD_GREEN "\e[1;92m"
#define RESET "\e[0m"

// Useful variables
#define BYTE_OUTCOMES 256
#define BUFFER_SIZE 65536 // 64KB  
#define IMAGE_SCN_MEM_EXECUTE_FLAG 0x20000000 

// Values to calculate the malicious score of a file
#define SUSPICIOUS_SCORE 1.5
#define HIGHLY_SUSPICIOUS_SCORE 3
#define MALICIOUS_SCORE 6

// Values indicated by Practical Security Analytics LLC - file entropy post
#define ENTROPY_SUSPICIOUS_LOW   7.2
#define ENTROPY_SUSPICIOUS_HIGH  7.6
#define ENTROPY_MALICIOUS        8.0

// Heuristic printers for specific cases
#define PRINT_FILE_ENTROPY(confidence_level, entropy, reset) printf("%sFile Entropy: %lf%s\n", confidence_level, entropy, reset)

#define PRINT_SUSPICIOUS_SECTION_ENTROPY(confidence_level, section_name, entropy) printf("%sSection: %-9s\tEntropy: %lf"RESET"\n", confidence_level, section_name, entropy)

#define PRINT_SUSPICIOUS_SECTION_FLAG(confidence_level, section_name) \
       	printf("%sSection: %s\tFlag: 0x%X - is not .text section and has executable flag set"RESET"\n", confidence_level, section_name, IMAGE_SCN_MEM_EXECUTE_FLAG)

enum SECTION_FLAG {
	NORMAL,
	HIGH_ENTROPY,
	EXECUTABLE_FLAG_SET
};		

static const char* SECTION_FLAG_STR[] = {
    [NORMAL]            = "Normal",     
    [HIGH_ENTROPY]       = "High Entropy",  
    [EXECUTABLE_FLAG_SET]= "Executable flag set",  
};

struct SECTION_DATA {
	BYTE name[8];
	DOUBLE entropy;
	SECTION_FLAG flag;
};

enum STATUS {
	CLEAN,
	SUSPICIOUS,
	HIGHLY_SUSPICIOUS,
	MALICIOUS
};

static const char* STATUS_COLOR[] = {
    [CLEAN]            = "\e[37m",     // grey normal color
    [SUSPICIOUS]       = "\e[1;31m",  // red
    [HIGHLY_SUSPICIOUS]= "\e[1;33m",  // yellow
    [MALICIOUS]        = "\e[1;92m"   // green
};

struct HEURISTICS{
	UINT8* _sha3Digest;
	UINT8* _sha256Digest;
	UINT8* _md5Digest;
	WORD _nrOfSections;
	SECTION_DATA* _sections;
	DOUBLE _fileEntropy;
	LARGE_INTEGER _fileSize;
	UINT8 _raisedSuspiciousFlags;
	DOUBLE _maliciousScore;
};


//----------------------------------------------------------------------------------
// Function prototypes
//----------------------------------------------------------------------------------

// Public API
PHEURISTICS createHeuristics (const PFILE_CONTEXT fc);
void freeHeuristics(PHEURISTICS heuristics);

void setFileSize(PHEURISTICS heuristics, PFILE_CONTEXT fc);
static void calculateFileEntropy(PHEURISTICS heuristics, const PFILE_CONTEXT fileContext);

LONGLONG getSize(const PHEURISTICS heuristics);
DOUBLE getEntropy(const PHEURISTICS heuristics);

DOUBLE getMaliciousScore(const PHEURISTICS heuristics);
UINT8 getRaisedFlags(const PHEURISTICS heuristics);

void analyzeFileEntropy(PHEURISTICS heuristics, const PFILE_CONTEXT fileContext);
void analyzeSectionEntropy(PHEURISTICS heuristics, const PFILE_CONTEXT fc);
void analyzeSectionFlag(PHEURISTICS heuristics, const PFILE_CONTEXT fc);
int calculateFileHash(PHEURISTICS heuristics, PFILE_CONTEXT fc);

// Internal Functions
static STATUS analyzeEntropy(PHEURISTICS heuristics, const double entropy);

static ULONG64* extractByteCount(const PHEURISTICS heuristics, const LPVOID startAddress,const LONGLONG size);
static DOUBLE entropy(ULONG64 byte_count[], ULONG64 size);

static inline void addMaliciousScore(PHEURISTICS heuristics, const DOUBLE value);
static void calculateSectionEntropy(PHEURISTICS heuristics, const PFILE_CONTEXT fc);

//----------------------------------------------------------------------------------
// Public API implementations
//----------------------------------------------------------------------------------

/**
 * @brief Allocates a heuristic struct and points to it. We set all fields to 0 using calloc.
 * @param fc file context to get the nr of sections from that we can later use to store section data in
 * @return pointer to the created heuristics struct
 */
PHEURISTICS createHeuristics (const PFILE_CONTEXT fc) {
	PHEURISTICS newHeuristics = NULL;
	newHeuristics = calloc(1, sizeof(HEURISTICS));

	if(newHeuristics == NULL) { 
		print_error("Could not initialize heuristics for file context! create_heuristics failed!");
		return NULL;
	}

	SECTION_DATA* sectionData = NULL;
	sectionData = calloc(getNrOfSections(fc), sizeof(SECTION_DATA));
	if (sectionData == NULL) {
		print_error("Could not initialize section data for heuristics! create_heuristics failed!");
		free(newHeuristics);
		return NULL;
	}

	newHeuristics->_sections = sectionData;
	newHeuristics->_nrOfSections = getNrOfSections(fc);

	return newHeuristics;
}

/**
 * @brief Frees the heuristics struct and the pointer variables it contains. Even though we dont allocate
 * 		  memory for the digest pointers they r allocated in the calculateFileHash function and we point to 
 * 		  that memory zone after assigning them. So we need to free that space.
 * @param heuristics struct to free
 * @return void
 */

void freeHeuristics(PHEURISTICS heuristics) {
    if (!heuristics) return;

    if (heuristics->_sha3Digest) {
        OPENSSL_free(heuristics->_sha3Digest);
        heuristics->_sha3Digest = NULL;
    }
    if (heuristics->_sha256Digest) {
        OPENSSL_free(heuristics->_sha256Digest);
        heuristics->_sha256Digest = NULL;
    }
    if (heuristics->_md5Digest) {
        OPENSSL_free(heuristics->_md5Digest);
        heuristics->_md5Digest = NULL;
    }

    if (heuristics->_sections) {
        free(heuristics->_sections);
        heuristics->_sections = NULL;
    }

    free(heuristics);
}

/**
 * @brief Hash function using the OPENSSL library. Adapted the example code on their documentation to work
 * 		  on file mapping and computed hash for 3 types of hash algorithms. 
 * @param heuristics struct to store the hashes in
 * @param fc file context to get the baseAddress that we use in the EVP_DigestUpdate function
 * @return either 1 if it failed or 0 if it succeded 
 */

int calculateFileHash(PHEURISTICS heuristics, PFILE_CONTEXT fc) {
	EVP_MD_CTX* sha256_ctx = NULL;
	EVP_MD_CTX* md5_ctx = NULL;
	EVP_MD_CTX* sha3_384_ctx = NULL;

    EVP_MD* sha256 = NULL;
	EVP_MD* md5 = NULL;
	EVP_MD* sha3_384 = NULL;

    unsigned int sha256_len = 0;
	unsigned int md5_len = 0;
	unsigned int sha3_384_len = 0;

    unsigned char* sha256_outdigest = NULL;
    unsigned char* md5_outdigest = NULL;
	unsigned char* sha3_384_outdigest = NULL;

	int ret = 1;

    /* Create a context for the digest operation */
	sha3_384_ctx = EVP_MD_CTX_new();
	if (sha3_384_ctx == NULL)
		goto err;

	sha256_ctx = EVP_MD_CTX_new();
	if (sha256_ctx == NULL)
		goto err;

	md5_ctx = EVP_MD_CTX_new();
	if (md5_ctx == NULL)
		goto err;

	sha3_384 = EVP_MD_fetch(NULL, "SHA3-384", NULL);
	if (sha3_384 == NULL)
		goto err;

	sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);
	if (sha256 == NULL)
		goto err;

	md5 = EVP_MD_fetch(NULL, "MD5", NULL);
	if (md5 == NULL)
		goto err;

   	/* Initialise the digest operation */
	if (!EVP_DigestInit_ex(sha3_384_ctx, sha3_384, NULL))
		goto err;

   	if (!EVP_DigestInit_ex(sha256_ctx, sha256, NULL))
       	goto err;

	if (!EVP_DigestInit_ex(md5_ctx, md5, NULL)) 
		goto err;

	BYTE* offset = (BYTE*)getBaseAddress(fc);
	LONGLONG fileSize = heuristics->_fileSize.QuadPart;

	while(fileSize > BUFFER_SIZE) {
		if (!EVP_DigestUpdate(sha3_384_ctx, offset, BUFFER_SIZE))
			goto err;

		if (!EVP_DigestUpdate(sha256_ctx, offset, BUFFER_SIZE))
			goto err;

		if (!EVP_DigestUpdate(md5_ctx, offset, BUFFER_SIZE))
			goto err;

		offset += BUFFER_SIZE;
		fileSize -= BUFFER_SIZE;
	}

	if (!EVP_DigestUpdate(sha3_384_ctx, offset, fileSize))
		goto err;

	if (!EVP_DigestUpdate(sha256_ctx, offset, fileSize))
		goto err;

	if (!EVP_DigestUpdate(md5_ctx, offset, fileSize))
		goto err;

	
	/* Allocate the output buffer */
	sha256_outdigest = OPENSSL_malloc(EVP_MD_get_size(sha256));
	if (sha256_outdigest == NULL)
		goto err;

	md5_outdigest = OPENSSL_malloc(EVP_MD_get_size(md5));
	if (md5_outdigest == NULL)
		goto err;

	sha3_384_outdigest = OPENSSL_malloc(EVP_MD_get_size(sha3_384));
	if (sha3_384_outdigest == NULL)
		goto err;

	/* Now calculate the digest itself */
	if (!EVP_DigestFinal_ex(sha256_ctx, sha256_outdigest, &sha256_len))
		goto err;

	if (!EVP_DigestFinal_ex(md5_ctx, md5_outdigest, &md5_len))
		goto err;

	if (!EVP_DigestFinal_ex(sha3_384_ctx, sha3_384_outdigest, &sha3_384_len))
		goto err;

	heuristics->_sha3Digest = sha3_384_outdigest;
	heuristics->_sha256Digest = sha256_outdigest;
	heuristics->_md5Digest = md5_outdigest;

	printf("%-11s","SHA3-384:");
	for (unsigned int i = 0; i < sha3_384_len; i++)
    	printf("%02x", sha3_384_outdigest[i]);
	printf("\n");

	printf("%-11s","SHA256:");
	for (unsigned int i = 0; i < sha256_len; i++)
    	printf("%02x", sha256_outdigest[i]);
	printf("\n");

	printf("%-11s","MD5:");
	for (unsigned int i = 0; i < md5_len; i++)
    	printf("%02x", md5_outdigest[i]);
	printf("\n");

	ret = 0;

 err:
    /* Clean up all the resources we allocated */
    OPENSSL_free(sha256_outdigest);
    OPENSSL_free(md5_outdigest);
    OPENSSL_free(sha3_384_outdigest);
    
    EVP_MD_free(sha256);
    EVP_MD_free(md5);
    EVP_MD_free(sha3_384);
	    
    EVP_MD_CTX_free(sha256_ctx);
    EVP_MD_CTX_free(md5_ctx);
    EVP_MD_CTX_free(sha3_384_ctx);

    if (ret != 0)
       ERR_print_errors_fp(stderr);

    return ret;
}

/**
 * @brief Uses the internal method analyzeEntropy to get some information about the current file entropy
 * 		  Will print out the entropy in a different color if the entropy is suspicious, highly suspicious etc.
 * @param heuristics heuristics struct used in the entropy calculation function to get the file size from
 * @param fileContext constant used in calculateFileEntropy to get the base address to extract byte count
 * @return void
 */
void analyzeFileEntropy(PHEURISTICS heuristics, const PFILE_CONTEXT fileContext) {
	calculateFileEntropy(heuristics, fileContext);
	
	DOUBLE file_entropy = heuristics->_fileEntropy;
	STATUS fileEntropyStatus = analyzeEntropy(heuristics,file_entropy);

	PRINT_FILE_ENTROPY(STATUS_COLOR[fileEntropyStatus], heuristics->_fileEntropy, RESET);
}

/**
 * @brief Uses the same logic as analyzeFileEntropy based on the helper internal function analyzeEntropy we 
 * 		  get a STATUS of the entropy.
 * @param heuristics pointer to the heuristics struct we use to calculate entropy, we need nrOfSections from it
 * @param fc constant to file context pointer we use for base address
 * @return void
 */
void analyzeSectionEntropy(PHEURISTICS heuristics, const PFILE_CONTEXT fc) {
	calculateSectionEntropy(heuristics, fc);	

	for(int i = 0; i < heuristics->_nrOfSections; i++) {
		DOUBLE entropy = heuristics->_sections[i].entropy;
		STATUS sectionEntropyStatus = analyzeEntropy(heuristics, entropy);

		if(sectionEntropyStatus != CLEAN) {
			heuristics->_sections[i].flag = HIGH_ENTROPY;
		}

		PRINT_SUSPICIOUS_SECTION_ENTROPY(STATUS_COLOR[sectionEntropyStatus],
			 heuristics->_sections[i].name, entropy);
	}
}


/**
 * @brief Verifies sections besides .text if the have the IMAGE_SCN_MEM_EXECUTE_FLAG set, which would make
 * 		  them executable. This is a technique some viruses use to execute malicious code outside of .text
 * 		  to prevent high-entropy and evade some static analysis.
 * @param heuristics pointer to get the nrOfSections and add malicious score to it
 * @param fc file context pointer used to get the Section Header struct.
 * @return void
 */
void analyzeSectionFlag(PHEURISTICS heuristics, const PFILE_CONTEXT fc) {
	IMAGE_SECTION_HEADER* sectionHeader = NULL;
	sectionHeader = getSectionHeader(fc);

	if(sectionHeader == NULL ) {
		print_error("Section header hasn't been parsed or operation failed! analyzeSectionFlag failed!");
		return;
	}

	// Starts from 1 because sectionHeader[0] is the .text section which is supposed to be executable
	for(WORD i = 1; i < heuristics->_nrOfSections; i++) {
		if(sectionHeader[i].Characteristics & (DWORD)IMAGE_SCN_MEM_EXECUTE_FLAG) {
			PRINT_SUSPICIOUS_SECTION_FLAG(BOLD_YELLOW, sectionHeader[i].Name);
			addMaliciousScore(heuristics, HIGHLY_SUSPICIOUS_SCORE);
			heuristics->_raisedSuspiciousFlags++;
			heuristics->_sections[i].flag = EXECUTABLE_FLAG_SET;			
		}
	}
}

//----------------------------------------------------------------------------------
// Setters
//----------------------------------------------------------------------------------

void setFileSize(PHEURISTICS heuristics,PFILE_CONTEXT fc) {
	if(!GetFileSizeEx(getFileHandle(fc), &heuristics->_fileSize)) {
		DWORD errCode = GetLastError();
		printf("GetFileSizeEx failed with error code: %lu\n", errCode);
		return;
	}
}

//----------------------------------------------------------------------------------
// Getters
//----------------------------------------------------------------------------------

LONGLONG getSize(const PHEURISTICS heuristics) {
	return heuristics->_fileSize.QuadPart;
}

DOUBLE getEntropy(const PHEURISTICS heuristics) {
	return heuristics->_fileEntropy;
}

DOUBLE getMaliciousScore(const PHEURISTICS heuristics) {
	return heuristics->_maliciousScore;
}

UINT8 getRaisedFlags(const PHEURISTICS heuristics) {
	return heuristics->_raisedSuspiciousFlags;
}

//----------------------------------------------------------------------------------
// Internal functions implementations
//----------------------------------------------------------------------------------

/**
 * @brief Function that uses statistical data collected by Practical Security Analytics LLC 
 * 		  in one of their post to categorize suspicious entropy scores
 * @param heuristics pointer to the heuristics struct
 * @param entropy used as a const parameter to pass it to the analyzeEntropy function
 * @return STATUS, an enum type used to express what the data status is 
 */

static STATUS analyzeEntropy(PHEURISTICS heuristics, const double entropy) {
	if (entropy > ENTROPY_SUSPICIOUS_LOW && entropy < ENTROPY_SUSPICIOUS_HIGH) {
    	addMaliciousScore(heuristics, SUSPICIOUS_SCORE);
		heuristics->_raisedSuspiciousFlags++;
		return SUSPICIOUS;
	}
	else if (entropy > ENTROPY_SUSPICIOUS_HIGH && entropy < ENTROPY_MALICIOUS) {
    	addMaliciousScore(heuristics, HIGHLY_SUSPICIOUS_SCORE);
		heuristics->_raisedSuspiciousFlags++;
		return HIGHLY_SUSPICIOUS;
	}
	else if (entropy >= ENTROPY_MALICIOUS) {
    	addMaliciousScore(heuristics, MALICIOUS_SCORE);
		heuristics->_raisedSuspiciousFlags++;
		return MALICIOUS;
	}
	else {
		return CLEAN;
	}
}

/**
 * @brief Adds a double value to the heuristics maliciouScore field. The values chose are between 1.5 - 6.0
 * 		  This is subjective for now as implementing checking functionality is prioritary. Later on
 * 	      better categorization techniques will be used.
 * @param heuristics, pointer to the heuristics struct
 * @param value, the value to be added which will always be one of the macros ranging from 1.5 - 6.0
 * @return void
 */

static inline void addMaliciousScore(PHEURISTICS heuristics, const DOUBLE value) {
	if (heuristics != NULL) heuristics->_maliciousScore += value;
}

/**
 * @brief Extracts a byteCount array used to calculate the probability of each byte, later that
 * 		  probability being used for entropy calculation. 
 * 		  Calculating the probability of a byte simply happens by iterating over each byte in the file
 * 		  and incrementing its appearance in the array based on position.
 * 		  We use a dynamically allocated vector because a static one would be discarded upon function scope
 * 		  ending. 
 * 		  IMPORTANT: Caller MUST free the byteCount array afterwards
 * @param heursitics the heuristics struct from which we get the file size to iterate over
 * @param inAddress the base address of the file 
 * @return pointer to the vector of byte appearances
 */

static ULONG64* extractByteCount(const PHEURISTICS heuristics, const LPVOID startAddress,
	const LONGLONG size) {
	BYTE* startingAddress = (BYTE*)startAddress;

	ULONG64* byteCount = calloc(BYTE_OUTCOMES, sizeof(ULONG64));
	if (!byteCount) {
		print_error("Failed to allocate memory for byteCount! extractByteCount() failed!");
		return NULL;
	} 

	if(size == 0) {
		// If we dont specify the size of the section we want to get the byteCount array from, do it for the 
		// whole file
		for (LONGLONG i = 0; i < heuristics->_fileSize.QuadPart; i++) {
			byteCount[startingAddress[i]]++;
		}
	}
	else {
		for (LONGLONG i = 0; i < size; i++) {
			byteCount[startingAddress[i]]++;
		}
	}

	return byteCount;
}

/**
 * @brief Function calculates the entropy of a file using Shanon's entropy formula
 * @param byteCount[] an array of byte appearances used to calculate the probability of each byte
 * @param size the size of the file to analyze
 * @return the result of the entropy calculation
 * 
 * Because one byte can represent 2^8 outcomes we have exactly 256 values we have to iterate over.
 * Function log2() is used instead of log() as this can work on DOUBLE values which is exactly what we need
 */

static DOUBLE entropy(ULONG64 byte_count[], ULONG64 size) {
    DOUBLE entropy = 0.0;

    for(int i = 0; i < BYTE_OUTCOMES; i++) {
        if(byte_count[i] != 0) {
            DOUBLE p = (DOUBLE)byte_count[i] / (DOUBLE)size;
            entropy += -p * log2(p);
        }
    }

    return entropy;
}

/**
 * @brief Internal function that puts together byteCount extraction , and entropy calculation to end up with
 * 		  the file entropy.
 * @param heuristics pointer to the heuristics struct that we store the entropy in and get the fileSize from
 * @param fileContext a constant pointer that we pass to the extractByteCount function to get the baseAddress
 * @return void 
 */

static void calculateFileEntropy(PHEURISTICS heuristics, const PFILE_CONTEXT fileContext) {
	LPVOID baseAddress = getBaseAddress(fileContext);
	uint64_t* byteCount = extractByteCount(heuristics, baseAddress, 0);
	LARGE_INTEGER fileSize = heuristics->_fileSize;
	heuristics->_fileEntropy = entropy(byteCount, (ULONG64)fileSize.QuadPart);
	
	free(byteCount);
}

/** 
 * @brief Using the exact method for file entropy we extract each section entropy using a start and end point
 * 		  We move the base address to the pointer of the section and then extract the byteCount
 * 		  Storing information in the SECTION_DATA struct will allow for later use in reports when we have to
 * 		  report our findings.
 * @param heuristics pointer to the struct we modify
 * @param fc file context constant used in the extractByte count function for the baseAddress
 * @return void
 */

static void calculateSectionEntropy(PHEURISTICS heuristics, const PFILE_CONTEXT fc) {
	// Get pointer to the beginning of the section header
	IMAGE_SECTION_HEADER* pSectionStart = getSectionHeader(fc);
	BYTE* baseAddress = (BYTE*)getBaseAddress(fc);
	DOUBLE sectionEntropy;

	for (WORD i = 0; i < heuristics->_nrOfSections; i++) {
		sectionEntropy = 0;

		// Get to the section offfset 
		BYTE* currentPos = baseAddress + pSectionStart[i].PointerToRawData;
		DWORD rawSize = pSectionStart[i].SizeOfRawData;

		if(rawSize == 0) {
			printf("SECTION: %s\t\tEntropy: N/A (no raw data)\n", pSectionStart[i].Name);
    		continue;
		}

		ULONG64* byteCount = extractByteCount(heuristics, currentPos, rawSize);

		sectionEntropy = entropy(byteCount, (ULONG64)rawSize);

		memcpy(heuristics->_sections[i].name, pSectionStart[i].Name,8);
		heuristics->_sections[i].entropy = sectionEntropy;

		// Memory is allocated ussing calloc for byteCount so we must free it
		free(byteCount);
	}
}




