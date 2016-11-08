#ifndef AES_128_AES
#define AES_128_AES

#include <cstdio>
#include <cstdint>
#include <iomanip>

using namespace std;

#define HEX( x ) hex<<setfill('0')<<setw(2)<< int(x)
#define DEC( x ) dec<<setw(2)<<int(x)

// 1 unit of size is 1 byte or 8 bit long
#define block_size 16
#define key_size 16

#define state_size 4
#define no_of_rounds 10
#define round_keys_size 176

class Aes128 {

	private:
	const static uint8_t sbox[256];
	const static uint8_t mult_two_table[256];
	const static uint8_t mult_three_table[256];
	const static uint8_t rcon_values[10];

	uint8_t states[state_size][state_size];
	uint8_t round_keys[round_keys_size];

	uint32_t rot_words_left(uint16_t word_to_rotate, int no_of_words);
	uint32_t rcon(int size);
	uint8_t sub_byte(uint8_t state);
	uint8_t mult_two(uint8_t val);
	uint8_t mult_three(uint8_t val);

	void copy_next_sixteen_bytes(uint8_t *source, uint8_t * dest);
	void copy_next_four_bytes(uint8_t *source, uint8_t * dest);

	void initialize_state(uint8_t *input);
	void print_states();

	void expand_key(uint8_t *key);
	void substitute();
	void shift_row();
	void mix_column();
	void add_round_key(int round);
	void copy_output(uint8_t *output);

	public:
	Aes128();
	void encrypt(uint8_t *message, uint8_t *key, uint8_t *cipher);
	void decrypt(uint8_t *cipher, uint8_t *key, uint8_t *message);
};

#endif