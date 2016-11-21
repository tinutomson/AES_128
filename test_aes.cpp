#include<iostream>
#include<fstream>
#include "aes.hpp"

void print_array(uint8_t * arr, int size) {
	for(int i = 0; i < size; ++i) {
		cout<<HEX(arr[i])<<" ";
	}
}

void run_test_cases() {
	int Nk[] = {128, 192, 256};
    uint8_t key128[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	uint8_t key192[24] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17};
	uint8_t key256[32] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
	uint8_t message[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
	uint8_t cipher[16];
	uint8_t *key;
	Aes128 aes;
	int failure_flag = 0;

	for(int i = 0; i < 3; ++i) {
		if(Nk[i] == 256) {
			key = key256;
		} else if (Nk[i] == 192) {
			key = key192;
		} else {
			key = key128;
		}
		cout<<endl<<DEC(Nk[i])<<" bit AES";
		
		cout<<endl<<"original message : \t";
		print_array(message, 16);
		cout<<endl<<"encrypting key : \t";
		print_array(key, Nk[i]/8);
		aes.encrypt(message, key, cipher,Nk[i]);

		cout<<endl<<"encrypted cipher : \t";
		print_array(cipher, 16);
		aes.decrypt(cipher, key, cipher, Nk[i]);
		cout<<endl<<"decrypted message : \t";
		print_array(cipher, 16);

		for(int i = 0; i < 16; ++i) {
			if(cipher[i] != message[i]) {
				failure_flag = 1;
			}
		}

		if(failure_flag == 0)
			cout<<endl<<"Test case passed. SUCESS"<<endl;
		else
			cout<<endl<<"Test case failed. FAILURE"<<endl;

		failure_flag = 0;
	}
}

void display_help() {
	cout<<"* There are nine possible options to this program:";
	cout<<endl<<"* -h for help";
	cout<<endl<<"* -v for version";
	cout<<endl<<"* -t for running test cases";
	cout<<endl<<"* -e for encrypt";
	cout<<endl<<"* -d for decrypt. Default is encrypt";
	cout<<endl<<"* -n for key length. Default is 128 bits";
	cout<<endl<<"* -i for input file";
	cout<<endl<<"* -k for key file";
	cout<<endl<<"* -o for output file";
	cout<<endl<<"* The program may terminated if any unrecognised options are specified";
	cout<<endl<<"* or if required arguments are not specified.";
	cout<<endl;
}

bool cmd_option_exists(char** begin, char** end, const std::string& option)
{
    return std::find(begin, end, option) != end;
}

char* get_cmd_option(char ** begin, char ** end, const std::string & option)
{
    char ** itr = std::find(begin, end, option);
    if (itr != end && ++itr != end)
    {
        return *itr;
    }
    return 0;
}

bool is_file_exist(char * file_name) {
	if(file_name && file_name[0] != '-') {
		ifstream stream(file_name);
		return stream.good();
	}
	return false;
}

bool is_file_valid(char *file_name) {
	if(file_name && file_name[0] != '-') {
		return true;
	}
	return false;
}

bool get_key_size(char* key_s, int *size) {
	if(!key_s) {
		*size = 128;
		return true;
	}

	if(strcmp(key_s, "128") == 0) {
		*size = 128;
	} else if(strcmp(key_s, "192") == 0) {
		*size = 192;
	} else if(strcmp(key_s, "256") == 0) {
		*size = 256;
	} else {
		return false;
	}
	return true;
}

bool read_input(char *file_name, uint8_t *in_buf, unsigned int *in_buf_size) {
	// TODO: Find size of file, create a buf of enough length of multiple of 128, copy convert store
	return true;
}

bool read_key(char *file_name, uint8_t *key_buf, int key_size) {
	//TODO: Retreive first key_size characters from file
	return true;
}

bool write_output(ostream *stream, uint8_t *out_buf, unsigned int out_buf_size) {
	// TODO: write to stream.
	return true;
}

int main(int argc, char* argv[]) {
	bool is_decrypt = false, is_std_output_on = false;
	int key_size = 128;
	unsigned int input_buf_size = 0;
	uint8_t *input_buf = 0, *key_buf = 0;

	// help
	if(cmd_option_exists(argv, argv+argc, "-h")) {
		display_help();
		exit(0);
    }
    // version
    if(cmd_option_exists(argv, argv+argc, "-v")) {
		cout<<VERSION<<endl;
		exit(0);
    }

    // test cases
    if(cmd_option_exists(argv, argv+argc, "-t")) {
    	run_test_cases();
    	exit(0);
    }

    // encrypt and decrypt
    is_decrypt = cmd_option_exists(argv, argv+argc, "-d");

    // key size
    char *key_s = get_cmd_option(argv, argv + argc, "-n");
    if(!get_key_size(key_s, &key_size)) {
    	cout<<"Invalid key size. Try again with valid key size.";
    	exit(0);
    }
    
    // input
	char *in_file_name = get_cmd_option(argv, argv + argc, "-i");
	if(!is_file_exist(in_file_name)) {
		cout<<"Invalid input file. Try again with valid file name."<<endl;
		exit(0);
	}

	// key
	char *key_file_name = get_cmd_option(argv, argv + argc, "-k");
	if(!is_file_exist(key_file_name)) {
		cout<<"Invalid key file. Try again with valid file name."<<endl;
		exit(0);
	}

	//output
	char *out_file_name = get_cmd_option(argv, argv + argc, "-o");
	if(!is_file_valid(out_file_name)) {
		cout<<"No output file found. Printing to std output."<<endl;
		is_std_output_on = true;
	}

	if(!read_input(in_file_name, input_buf, &input_buf_size)) {
		cout<<"Unable to parse input. Check the input file."<<endl;
		exit(0);
	}

	if(!read_key(key_file_name, key_buf, key_size)) {
		cout<<"Unable to parse key. Check the key file."<<endl;
		exit(0);
	}

	Aes128 aes;

	for (uint8_t* i = input_buf; i < input_buf + input_buf_size; i+= 128) {
		if(is_decrypt) {
			aes.decrypt(i, key_buf, i, key_size);
		} else {
			aes.encrypt(i, key_buf, i, key_size);
		}
	}

	// ostream *w_stream;
	// if(is_std_output_on) {
	// 	w_stream = cout;
	// } else {
	// 	if(!is_file_exist(out_file_name)) {
	// 		// open a new stream and assign
	// 	} else {
	// 		//Open in append mode
	// 	}
	// }
	// if(!write_output(w_stream, input_buf, input_buf_size)) {
	//
	// }

	return 0;
}
