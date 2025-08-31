#include "../include/heuristics.h"
#include "../include/print_helper.h"
#include "../include/file_context.h"

#define BYTE_OUTCOMES 256
#define BUFFER_SIZE 1024

// Values to calculate the malicious score of a file
#define SUSPICIOUS_SCORE 1.5
#define HIGHLY_SUSPICIOUS_SCORE 3
#define MALICIOUS_SCORE 6

// Values indicated by Practical Security Analytics LLC - file entropy post
#define ENTROPY_SUSPICIOUS_LOW   7.2
#define ENTROPY_SUSPICIOUS_HIGH  7.6
#define ENTROPY_MALICIOUS        8.0

struct Heuristics{
	double _file_entropy;
	uint8_t _raised_suspicious_flags;
       	double _malicious_score;
};

enum File_Status {
	CLEAN,
	SUSPICIOUS,
	HIGHLY_SUSPICIOUS,
	MALICIOUS
};

/********** PUBLIC API **********/

Heuristics* create_heuristics (File_Context* fc);
void free_heuristics(Heuristics* heuristics);

double get_file_entropy(const Heuristics* heuristics);

/********** PUBLIC API **********/

/* Raw data such as file entropy will be stored in the heuristic struct upon creation 
 * the analysis of the raw data for malicious score calculation will be done in separate functions and later on 
 * added to a general function that will analyze the whole set of raw data sequentially (e.g analyze_file_entropy(), analyze_section_entropy() will converge into
 * analyze_heuristics() in the end
 */

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
	if (heuristics != NULL) free(heuristics);
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

//Caller of this function free the pointer to the array returned
uint64_t* extract_file_byte_count(FILE* in_File) {
    uint8_t buffer[BUFFER_SIZE] = {0};
    uint64_t* byte_count = calloc(BYTE_OUTCOMES, sizeof(uint64_t));
    uint64_t n;

    rewind(in_File);
    while((n = fread(buffer,1,BUFFER_SIZE,in_File)) != 0) {
        for(int i = 0; i < n; i++) {
            byte_count[buffer[i]]++;
        }
    }

    return byte_count;
}

void add_malicious_score(Heuristics* heuristics, double value) {
	if (heuristics != NULL) heuristics->_malicious_score += value;
}

void analyze_file_entropy(Heuristics* heuristics) {
	double file_entropy = get_file_entropy(heuristics);

	if (file_entropy > ENTROPY_SUSPICIOUS_LOW && file_entropy < ENTROPY_SUSPICIOUS_HIGH) {
    		add_malicious_score(heuristics, SUSPICIOUS_SCORE);
		heuristics->_raised_suspicious_flags++;
	}
	else if (file_entropy > ENTROPY_SUSPICIOUS_HIGH && file_entropy < ENTROPY_MALICIOUS) {
    		add_malicious_score(heuristics, HIGHLY_SUSPICIOUS_SCORE);
		heuristics->_raised_suspicious_flags++;
	}
	else if (file_entropy >= ENTROPY_MALICIOUS) {
    		add_malicious_score(heuristics, MALICIOUS_SCORE);
		heuristics->_raised_suspicious_flags++;
	}
}	

/********** PRIVATE FUNCTIONS **********/
