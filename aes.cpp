#include "aes.hpp"
#include <cstring>
#include <iostream>
#include <stdlib.h>
using namespace std;

Aes128::Aes128() {
	round_keys = 0;
}


const uint8_t Aes128::sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const uint8_t Aes128::invert_sbox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

const uint8_t Aes128::mask[state_size][state_size] = {
	{0xFF,0xEE,0xDD,0xCC},
	{0xBB,0xAA,0x09,0x08},
	{0x07,0x06,0x05,0x04},
	{0x03,0x02,0x01,0x00}
};

uint8_t Aes128::rcon(int index) {
	uint8_t toBe = 0x02;
	if(index==1)
		return 0x01;
	if(index==2)
		return 0x02;
	for(int i=2;i<index;i++) {
		int high_bit =(uint8_t)(toBe&0x80);
		if(high_bit==0) {
			toBe<<=1;
			uint8_t dummy = toBe ^ 0x1b;
		} else {
			toBe<<=1;
			toBe ^=0x1b;
		}
	}
	return toBe;
}

uint8_t Aes128::sub_byte(uint8_t state) {
	return sbox[state];
}

uint8_t Aes128::invert_sub_byte(uint8_t state) {
	return invert_sbox[state];
}

#if DEBUG_MODE_ON
void Aes128::print_states() {
	for(int i = 0; i < state_size; ++i) {
		cout<<endl;
		for(int j = 0; j < state_size; ++j) {
			cout<<HEX(states[i][j])<<" ";
		}
	}
	cout<<"\n\n";
}
#endif

void Aes128::initialize_state(uint8_t *input) {
	for(int i = 0; i < state_size; ++i) {
		for(int j = 0; j < state_size; ++j) {
			states[i][j] = input[i + state_size*j];
		}
	}

#if DEBUG_MODE_ON
	print_states();
#endif

}

void Aes128::initialize_keyparam(uint8_t *key, int keysize) {
	if(keysize == 128) {
		key_size = keysize/8;
		round_keys_size = 176;
		no_of_rounds = 10;
	} else if(keysize == 192) {
		key_size = keysize/8;
		round_keys_size = 208;
		no_of_rounds = 12;
	} else {
		key_size = keysize/8;
		round_keys_size = 240;
		no_of_rounds = 14;
	}
	round_keys = new uint8_t[round_keys_size];
	memcpy(round_keys,key, key_size);
}

void Aes128::clean_states() {
	//ARR38-C. Guarantee that library functions do not form invalid pointers
	memset(states, 0 , state_size*state_size);
	memset(round_keys, 0, key_size);
	delete[]  round_keys;
	round_keys = 0;
	key_size = 0;
	no_of_rounds = 0;
	round_keys_size = 0;
}

uint8_t Aes128::g_mult(uint8_t first, uint8_t second) {
    uint8_t product = 0x00, high_bit;
    for (int i = 0; i < 8; i++) {
        if ((second & 0x01) != 0)	//is one's value of second is 1
            product ^= first;

        high_bit = (uint8_t)(first & 0x80); //highest bit of first value
        first <<= 1;

        if (high_bit != 0)
            first ^= 0x1b;
        else
        	uint8_t dummy = first^0x1b; //dummy instruction
        second >>= 1;
    }
    return product;
}

void Aes128::expand_key(uint8_t *key, int keysize) {

	initialize_keyparam(key, keysize);

#if DEBUG_MODE_ON
	cout<<endl<<"key expansion"<<endl;
	for(int j = 0; j < key_size; j = j+state_size) {
		cout<<"round "<<DEC(j/state_size)<< "\t";
		cout<<HEX(round_keys[j])<<" ";
		cout<<HEX(round_keys[j+1]) << " ";
		cout<<HEX(round_keys[j+2]) << " ";
		cout<<HEX(round_keys[j+3]) <<endl;
	}
#endif

	for(int i = key_size; i < round_keys_size; i = i+state_size) {

#if DEBUG_MODE_ON
		cout<<"round "<<DEC(i/state_size)<< "\t";
#endif

		if((i/state_size) %(key_size/state_size)==0) {
			round_keys[i] = sub_byte(round_keys[i-3]) ^ rcon(i/key_size);
			round_keys[i+1] = sub_byte(round_keys[i-2]);
			round_keys[i+2] = sub_byte(round_keys[i-1]);
			round_keys[i+3] = sub_byte(round_keys[i-4]);
		} else if((key_size/state_size>6)&&(i/state_size) %(key_size/state_size)==4) {
			round_keys[i] = sub_byte(round_keys[i-4]);
			round_keys[i+1] = sub_byte(round_keys[i-3]);
			round_keys[i+2] = sub_byte(round_keys[i-2]);
			round_keys[i+3] = sub_byte(round_keys[i-1]);
		} else {
			round_keys[i] = round_keys[i-4];
			round_keys[i+1] = round_keys[i-3];
			round_keys[i+2] = round_keys[i-2];
			round_keys[i+3] = round_keys[i-1];
		}
		for(int j = i; j < i+state_size; ++j) {
			round_keys[j] ^= round_keys[j-key_size];

#if DEBUG_MODE_ON
			cout<<HEX(round_keys[j])<<" ";
#endif

		}

#if DEBUG_MODE_ON
		cout<<endl;
#endif

	}
}

void Aes128::add_round_key(int round) {
	for(int i = 0; i < state_size; ++i) {
		for (int j = 0; j < state_size; ++j) {
			states[i][j] ^= round_keys[round*16 + (i + state_size*j)];
		}
	}



#if DEBUG_MODE_ON
	cout<<"add_round_key()";
	print_states();
#endif

}

void Aes128::add_mask() {
	for(int i = 0; i < state_size; ++i) {
		for (int j = 0; j < state_size; ++j) {
			states[i][j] ^= mask[i][j];
		}
	}
}



void Aes128::copy_output(uint8_t *output) {
	for (int i = 0; i < state_size; ++i) {
		for (int j = 0; j < state_size; ++j) {
			output[i + state_size*j] = states[i][j];
		}
	}
}

void Aes128::substitute() {
	for(int i = 0; i < 4; ++i) {
		for(int j = 0; j < 4; ++j) {
			states[i][j] = sub_byte(states[i][j]);
		}
	}

#if DEBUG_MODE_ON
	cout<<"substitute()";
	print_states();
#endif

}

void Aes128::shift_row() {
	uint8_t temp = states[1][0];
	states[1][0] = states[1][1];
	states[1][1] = states[1][2];
	states[1][2] = states[1][3];
	states[1][3] = temp;

	temp = states[2][0];
	states[2][0] = states[2][2];
	states[2][2] = temp;

	temp = states[2][1];
	states[2][1] = states[2][3];
	states[2][3] = temp;

	temp = states[3][0];
	states[3][0] = states[3][3];
	states[3][3] = states[3][2];
	states[3][2] = states[3][1];
	states[3][1] = temp;

#if DEBUG_MODE_ON
	cout<<"shift_row()";
	print_states();
#endif

}

void Aes128::mix_column() {
	uint8_t temp_array[4];
	for(int j = 0; j < 4; ++j) {
		temp_array[0] = g_mult(0x02, states[0][j]) ^ g_mult(0x03, states[1][j]) ^ states[2][j] ^ states[3][j];
		temp_array[1] = states[0][j] ^ g_mult(0x02, states[1][j]) ^ g_mult(0x03, states[2][j]) ^ states[3][j];
		temp_array[2] = states[0][j] ^ states[1][j] ^ g_mult(0x02, states[2][j]) ^ g_mult(0x03, states[3][j]);
		temp_array[3] = g_mult(0x03, states[0][j]) ^ states[1][j] ^ states[2][j] ^ g_mult(0x02, states[3][j]);

		states[0][j] = temp_array[0];
		states[1][j] = temp_array[1];
		states[2][j] = temp_array[2];
		states[3][j] = temp_array[3];
	}

#if DEBUG_MODE_ON
	cout<<"mix_column()";
	print_states();
#endif

}

void Aes128::encrypt(uint8_t *message, uint8_t *key, uint8_t *cipher,int keysize) {
	expand_key(key, keysize);
	initialize_state(message);

	add_round_key(0);
	#if SECURE_MODE_ON
	add_mask();
	#endif
	int round;
	for(round = 1; round < no_of_rounds; ++round) {
		substitute();
		#if SECURE_MODE_ON
		add_mask();
		#endif
		shift_row();
		#if SECURE_MODE_ON
		add_mask();
		#endif
		mix_column();
		#if SECURE_MODE_ON
		add_mask();
		#endif
		add_round_key(round);
		#if SECURE_MODE_ON
		add_mask();
		#endif
	}
	substitute();
	#if SECURE_MODE_ON
	add_mask();
	#endif
	shift_row();
	#if SECURE_MODE_ON
	add_mask();
	#endif
	add_round_key(round);
	#if SECURE_MODE_ON
	add_mask();
	#endif
	copy_output(cipher);
	clean_states();
}

void Aes128::invert_substitute() {
	for(int i = 0; i < state_size; ++i) {
		for(int j = 0; j < state_size; ++j) {
			states[i][j] = invert_sub_byte(states[i][j]);
		}
	}

#if DEBUG_MODE_ON
	cout<<"invert_substitute()";
	print_states();
#endif

}

void Aes128::invert_shift_row() {

	uint8_t temp = states[1][0];
	states[1][0] = states[1][3];
	states[1][3] = states[1][2];
	states[1][2] = states[1][1];
	states[1][1] = temp;

	temp = states[2][0];
	states[2][0] = states[2][2];
	states[2][2] = temp;

	temp = states[2][1];
	states[2][1] = states[2][3];
	states[2][3] = temp;

	temp = states[3][0];
	states[3][0] = states[3][1];
	states[3][1] = states[3][2];
	states[3][2] = states[3][3];
	states[3][3] = temp;

#if DEBUG_MODE_ON
	cout<<"invert_shift_row()";
	print_states();
#endif

}

void Aes128::invert_mix_column() {
	uint8_t temp_array[state_size];
	for(int j = 0; j < state_size; ++j) {
		temp_array[0] = g_mult(0x0e, states[0][j]) ^ g_mult(0x0b, states[1][j]) ^ g_mult(0x0d, states[2][j]) ^ g_mult(0x09, states[3][j]);
		temp_array[1] = g_mult(0x09, states[0][j]) ^ g_mult(0x0e, states[1][j]) ^ g_mult(0x0b, states[2][j]) ^ g_mult(0x0d, states[3][j]);
		temp_array[2] = g_mult(0x0d, states[0][j]) ^ g_mult(0x09, states[1][j]) ^ g_mult(0x0e, states[2][j]) ^ g_mult(0x0b, states[3][j]);
		temp_array[3] = g_mult(0x0b, states[0][j]) ^ g_mult(0x0d, states[1][j]) ^ g_mult(0x09, states[2][j]) ^ g_mult(0x0e, states[3][j]);

		states[0][j] = temp_array[0];
		states[1][j] = temp_array[1];
		states[2][j] = temp_array[2];
		states[3][j] = temp_array[3];
	}

#if DEBUG_MODE_ON
	cout<<"invert_mix_column()";
	print_states();
#endif

}

void Aes128::decrypt(uint8_t *cipher, uint8_t *key, uint8_t *message, int keysize) {
	expand_key(key, keysize);
	//DCL54-CPP. Overload allocation and deallocation functions as a pair in the same scope
	initialize_state(cipher);
	#if SECURE_MODE_ON
	add_mask();
	#endif
	add_round_key(no_of_rounds);

	int round;
	for(round = no_of_rounds - 1; round > 0; --round) {
		#if SECURE_MODE_ON
		add_mask();
		#endif
		invert_shift_row();
		#if SECURE_MODE_ON
		add_mask();
		#endif
		invert_substitute();
		#if SECURE_MODE_ON
		add_mask();
		#endif
		add_round_key(round);
		#if SECURE_MODE_ON
		add_mask();
		#endif
		invert_mix_column();
	}
	#if SECURE_MODE_ON
	add_mask();
	#endif
	invert_shift_row();
	#if SECURE_MODE_ON
	add_mask();
	#endif
	invert_substitute();
	#if SECURE_MODE_ON
	add_mask();
	#endif
	add_round_key(round);

	copy_output(message);
	//DCL54-CPP. Overload allocation and deallocation functions as a pair in the same scope
	clean_states();
}
