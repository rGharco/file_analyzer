#include "../include/heuristics.h"
#include "../include/print_helper.h"
#include "../include/file_context.h"

// ANSI colors for printing
#define BOLD_RED "\e[1;31m"
#define BOLD_YELLOW "\e[1;33m"
#define BOLD_GREEN "\e[1;92m"
#define RESET "\e[0m"

// Useful variables
#define BYTE_OUTCOMES 256
#define BUFFER_SIZE 1000000
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

#define PRINT_SECTION_ENTROPY(section_name, entropy) printf("Section: %-9s\tEntropy: %lf\n", section_name, entropy)
#define PRINT_SUSPICIOUS_SECTION_ENTROPY(confidence_level, section_name, entropy) printf("%sSection: %-9s\tEntropy: %lf"RESET"\n", confidence_level, section_name, entropy)

#define PRINT_SUSPICIOUS_SECTION_FLAG(confidence_level, section_name) \
       	printf("%sSection: %s\tFlag: 0x%X - is not .text section and has executable flag set"RESET"\n", confidence_level, section_name, IMAGE_SCN_MEM_EXECUTE_FLAG)

struct Heuristics{
	uint8_t* _sha3_384_digest;
	uint8_t* _sha256_digest;
	uint8_t* _md5_digest;
	double _file_entropy;
	Section_Data* _sections;
	uint8_t _raised_suspicious_flags;
	double _malicious_score;
};

struct Section_Data {
	char _section_name [8];
	double _entropy;
	bool _has_suspicious_executable_flag; // when a section other than .text has the IMAGE_SCN_MEM_EXECUTE flag set
};

enum File_Status {
	CLEAN,
	SUSPICIOUS,
	HIGHLY_SUSPICIOUS,
	MALICIOUS
};

/********** PUBLIC API DECLARATION **********/

Heuristics* create_heuristics (File_Context* fc);
void free_heuristics(Heuristics* heuristics);

double get_file_entropy(const Heuristics* heuristics);
double get_malicious_score(const Heuristics* heuristics);
uint8_t get_raised_flags(const Heuristics* heuristics);

void analyze_file_entropy(Heuristics* heuristics);
void analyze_section_entropy(Heuristics* heuristics, const File_Context* fc);
int calculate_file_hash(Heuristics* heuristics, File_Context* fc);

/********** PUBLIC API DECLARATION **********/

/********** PRIVATE FUNCTIONS DECLARATION **********/

double entropy(uint64_t byte_count[], uint64_t size);
uint64_t* extract_file_byte_count(FILE* in_File);
void increment_byte_count(uint64_t byte_count[] ,const uint8_t buffer[] ,size_t buffer_size);

void add_malicious_score(Heuristics* heuristics, double value);

void parse_section_entropy(Heuristics* heuristics, File_Context* fc);

/********** PRIVATE FUNCTIONS DECLARATION **********/


/* Raw data such as file entropy will be stored in the heuristic struct upon creation 
 * the analysis of the raw data for malicious score calculation will be done in separate functions and later on 
 * added to a general function that will analyze the whole set of raw data sequentially (e.g analyze_file_entropy(), analyze_section_entropy() will converge into
 * analyze_heuristics() in the end
 */

/********** PUBLIC API **********/

Heuristics* create_heuristics (File_Context* fc) {
	if(fc == NULL) {
		print_error("File context passed is NULL! create_heuristics failed!");
		return NULL;
	}

	Heuristics* new_heuristics = (Heuristics*)malloc(sizeof(Heuristics));

	if(new_heuristics == NULL) {
	      	print_error("Could not initialize heuristics for file context! create_heuristics failed!");
		return NULL;
	}

	/***** DEFAULT INITIALIZERS *****/

	new_heuristics->_file_entropy = 0.0;
	
	new_heuristics->_sections = (Section_Data*)malloc(sizeof(Section_Data) * fc->coff_header->number_of_sections);

	if (new_heuristics->_sections == NULL) {
		print_error("Could not initialize section specific heuristics! (ERR: create_heuristics())");
	}

	new_heuristics->_raised_suspicious_flags = 0;
	new_heuristics->_malicious_score = 0.0;

	/***** DEFAULT INITIALIZERS *****/

	uint64_t* file_byte_count = extract_file_byte_count(fc->file);
	
	if(file_byte_count == NULL) {
		print_error("Could not read byte count from file! Will not calculate file entropy! (ERR: create_heuristics())");
	}
	else {
		new_heuristics->_file_entropy = entropy(file_byte_count, fc->size);
		free(file_byte_count);
	}	

	return new_heuristics;
}

void free_heuristics(Heuristics* heuristics) {
	if (heuristics != NULL) return;
	if (heuristics->_sections != NULL) free(heuristics->_sections);
	
	free(heuristics);
}


/************ GETTERS ***********/

double get_file_entropy(const Heuristics* heuristics) {
	return heuristics->_file_entropy;
}

double get_malicious_score(const Heuristics* heuristics) {
	return heuristics->_malicious_score;
}

uint8_t get_raised_flags(const Heuristics* heuristics) {
	return heuristics->_raised_suspicious_flags;
}

/************ GETTERS ***********/

void analyze_file_entropy(Heuristics* heuristics) {
	double file_entropy = get_file_entropy(heuristics);

	if (file_entropy > ENTROPY_SUSPICIOUS_LOW && file_entropy < ENTROPY_SUSPICIOUS_HIGH) {
    		add_malicious_score(heuristics, SUSPICIOUS_SCORE);
		heuristics->_raised_suspicious_flags++;
		PRINT_FILE_ENTROPY(BOLD_GREEN, heuristics->_file_entropy, RESET);
		return;
	}
	else if (file_entropy > ENTROPY_SUSPICIOUS_HIGH && file_entropy < ENTROPY_MALICIOUS) {
    		add_malicious_score(heuristics, HIGHLY_SUSPICIOUS_SCORE);
		heuristics->_raised_suspicious_flags++;
		PRINT_FILE_ENTROPY(BOLD_YELLOW, heuristics->_file_entropy, RESET);
		return;
	}
	else if (file_entropy >= ENTROPY_MALICIOUS) {
    		add_malicious_score(heuristics, MALICIOUS_SCORE);
		heuristics->_raised_suspicious_flags++;
		PRINT_FILE_ENTROPY(BOLD_RED, heuristics->_file_entropy, RESET);
		return;
	}

	PRINT_FILE_ENTROPY("", heuristics->_file_entropy, "");
}

void analyze_section_entropy(Heuristics* heuristics, const File_Context* fc) {
	File_Context* file_context = (File_Context*)fc; //cast away const for internal parsing

	parse_section_entropy(heuristics, file_context);	

	for(int i = 0; i < fc->coff_header->number_of_sections; i++) {
		double entropy = heuristics->_sections[i]._entropy;

		if (entropy > ENTROPY_SUSPICIOUS_LOW && entropy < ENTROPY_SUSPICIOUS_HIGH) {
			add_malicious_score(heuristics, SUSPICIOUS_SCORE);
			heuristics->_raised_suspicious_flags++;
			PRINT_SUSPICIOUS_SECTION_ENTROPY(BOLD_GREEN, heuristics->_sections[i]._section_name, entropy);	
			continue;
		}
		else if (entropy > ENTROPY_SUSPICIOUS_HIGH && entropy < ENTROPY_MALICIOUS) {
			add_malicious_score(heuristics, HIGHLY_SUSPICIOUS_SCORE);
			heuristics->_raised_suspicious_flags++;
			PRINT_SUSPICIOUS_SECTION_ENTROPY(BOLD_YELLOW, heuristics->_sections[i]._section_name, entropy);	
			continue;
		}
		else if (entropy >= ENTROPY_MALICIOUS) {
			add_malicious_score(heuristics, MALICIOUS_SCORE);
			heuristics->_raised_suspicious_flags++;	
			PRINT_SUSPICIOUS_SECTION_ENTROPY(BOLD_RED, heuristics->_sections[i]._section_name, entropy);	
			continue;
		}
		
		PRINT_SECTION_ENTROPY(heuristics->_sections[i]._section_name, entropy);
	}
}

void analyze_section_flags(Heuristics* heuristics, const File_Context* fc) {
	for(uint8_t i = 0; i < fc->coff_header->number_of_sections; i++) {
		if(fc->sections[i].Characteristics == (uint32_t)IMAGE_SCN_MEM_EXECUTE_FLAG) {
			PRINT_SUSPICIOUS_SECTION_FLAG(BOLD_YELLOW, fc->sections[i].Name);
			add_malicious_score(heuristics, HIGHLY_SUSPICIOUS_SCORE);
			heuristics->_raised_suspicious_flags++;
			heuristics->_sections[i]._has_suspicious_executable_flag = true;			
		}
	}
}

int calculate_file_hash(Heuristics* heuristics, File_Context* fc) {
	EVP_MD_CTX* sha256_ctx = NULL;
	EVP_MD_CTX* md5_ctx = NULL;
	EVP_MD_CTX* sha3_384_ctx = NULL;

    	EVP_MD* sha256 = NULL;
	EVP_MD* md5 = NULL;
	EVP_MD* sha3_384 = NULL;

    	uint8_t buffer[BUFFER_SIZE] = {0};
	size_t bytes_read = 0; 

    	unsigned int sha256_len = 0;
	unsigned int md5_len = 0;
	unsigned int sha3_384_len = 0;

    	unsigned char* sha256_outdigest = NULL;
    	unsigned char* md5_outdigest = NULL;
	unsigned char* sha3_384_outdigest = NULL;

	int ret = 1;

    	/* Create a context for the digest operation */
	sha256_ctx = EVP_MD_CTX_new();
    	if (sha256_ctx == NULL)
        	goto err;

	md5_ctx = EVP_MD_CTX_new();
	if (md5_ctx == NULL)
		goto err;

	sha3_384_ctx = EVP_MD_CTX_new();
	if (sha3_384_ctx == NULL)
		goto err;

	sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);
	if (sha256 == NULL)
		goto err;

	md5 = EVP_MD_fetch(NULL, "MD5", NULL);
	if (md5 == NULL)
		goto err;

	sha3_384 = EVP_MD_fetch(NULL, "SHA3-384", NULL);
	if (sha3_384 == NULL)
		goto err;

   	/* Initialise the digest operation */
   	if (!EVP_DigestInit_ex(sha256_ctx, sha256, NULL))
       		goto err;

	if (!EVP_DigestInit_ex(md5_ctx, md5, NULL)) 
		goto err;

	if (!EVP_DigestInit_ex(sha3_384_ctx, sha3_384, NULL))
		goto err;

    	/*
     	* Pass the message to be digested. This can be passed in over multiple
     	* EVP_DigestUpdate calls if necessary
     	*/

	rewind(fc->file);	
	while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, fc->file)) != 0) {		
   		if (!EVP_DigestUpdate(sha256_ctx, buffer, bytes_read))
        		goto err;

		if (!EVP_DigestUpdate(md5_ctx, buffer, bytes_read)) 
			goto err;

		if (!EVP_DigestUpdate(sha3_384_ctx, buffer, bytes_read))
		       goto err;	
	}

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

	heuristics->_sha3_384_digest = sha3_384_outdigest;
	heuristics->_sha256_digest = sha256_outdigest;
	heuristics->_md5_digest = md5_outdigest;

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
    EVP_MD_free(sha256);
    EVP_MD_free(md5);
    EVP_MD_CTX_free(sha256_ctx);
    EVP_MD_CTX_free(md5_ctx);

    if (ret != 0)
       ERR_print_errors_fp(stderr);

    return ret;
}

/********** PUBLIC API **********/


/********** PRIVATE FUNCTIONS **********/

double entropy(uint64_t byte_count[], uint64_t size) {
    double entropy = 0.0;

    for(int i = 0; i < BYTE_OUTCOMES; i++) {
        if(byte_count[i] != 0) {
            double p = (double)byte_count[i] / (double)size;
            entropy += -p * log2(p);
        }
    }

    return entropy;
}

void increment_byte_count(uint64_t byte_count[] ,const uint8_t buffer[] ,size_t bytes_read) {
	for(int i = 0; i < bytes_read; i++) {
            byte_count[buffer[i]]++;
        }
}

//Caller of this function free the pointer to the array returned
uint64_t* extract_file_byte_count(FILE* in_File) {
    uint8_t buffer[BUFFER_SIZE] = {0};
    uint64_t* byte_count = calloc(BYTE_OUTCOMES, sizeof(uint64_t));
    size_t n;

    rewind(in_File);
    while((n = fread(buffer,1,BUFFER_SIZE,in_File)) != 0) {
	    increment_byte_count(byte_count, buffer, n);
    }

    return byte_count;
}

void add_malicious_score(Heuristics* heuristics, double value) {
	if (heuristics != NULL) heuristics->_malicious_score += value;
}

void parse_section_entropy(Heuristics* heuristics, File_Context* fc) {
	uint8_t buffer[BUFFER_SIZE] = {0};
	uint64_t* byte_count = calloc(BYTE_OUTCOMES, sizeof(uint64_t));
	size_t  n = 0;
	uint8_t nr_of_sections = fc->coff_header->number_of_sections;

	Section_Data* sections_info = calloc(nr_of_sections, sizeof(Section_Data));

	for (uint8_t i = 0; i < nr_of_sections; i++) {
		memset(byte_count, 0, BYTE_OUTCOMES * sizeof(uint64_t)); //reset per section

		char section_name[9]; // 8 characters + null terminator
		memcpy(section_name, fc->sections[i].Name, 8);
		section_name[8] = '\0';

		uint32_t size_of_raw_data = fc->sections[i].SizeOfRawData; 
		const uint32_t pointer_to_raw_data = fc->sections[i].PointerToRawData;

		if(fseek(fc->file, pointer_to_raw_data, SEEK_SET) != 0) {
			print_error("Could not seek to the section pointer. analyze_section_entropy() failed!");
			return;
		}

		uint32_t section_buffer = BUFFER_SIZE; // prevents comparison between unsigned int and int

		if(size_of_raw_data < section_buffer) {
			n = fread(buffer, 1,size_of_raw_data, fc->file);
			increment_byte_count(byte_count, buffer, n);
		}
		else {
			uint32_t remained = size_of_raw_data;
			while (remained > section_buffer) {
				n = fread(buffer, 1, section_buffer, fc->file);
				increment_byte_count(byte_count, buffer, n);
				remained -= section_buffer;
			}	
			n = fread(buffer, 1, remained, fc->file);
			increment_byte_count(byte_count, buffer, n);
		}

		double section_entropy = entropy(byte_count, size_of_raw_data);

		memcpy(sections_info[i]._section_name, section_name, 9);
	       	sections_info[i]._entropy = section_entropy;	
	}
	
	heuristics->_sections = sections_info;
}


/********** PRIVATE FUNCTIONS **********/
