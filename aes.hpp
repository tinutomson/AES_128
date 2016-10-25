#ifndef AES_128_AES
#define AES_128_AES

#include <cstdio>
#include <cstdint>
#include <vector>

namespace aes_ns {

	// 1 unit of size is 1 byte or 8 bit long
	#define block_size 16
	#define key_size 16

	#define state_size 4
	#define no_of_rounds 10
	#define round_key_size 176

	class Aes128 {

		private: 
		std::vector<uint8_t>  states[state_size], round_key[round_key_size];

		void expand_key(uint8_t *key);
		void sub_byte();
		void shift_column();
		void mix_column();
		void add_round_key();

		public:
		Aes128();
		void encrypt(uint8_t *message, uint8_t *key, uint8_t *cipher);
		void decrypt(uint8_t *cipher, uint8_t *key, uint8_t *message);
	};
}

#endif