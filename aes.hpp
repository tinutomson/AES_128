#ifndef AES_128_AES
#define AES_128_AES

#include <cstdio>
#include <cstdint>
#include <iomanip>

using namespace std;

#define DEBUG_MODE_ON 0
#define HEX( x ) hex<<setfill('0')<<setw(2)<< int(x)
#define DEC( x ) dec<<setw(2)<<int(x)

#define state_size 4

class Aes128 {

	private:
	const static uint8_t sbox[256];
	const static uint8_t invert_sbox[256];
	int key_size, round_keys_size, no_of_rounds;
	uint8_t states[state_size][state_size];
	uint8_t *round_keys;

	/* Table look up functions
	*/
	uint8_t static rcon(int size);
	uint8_t static sub_byte(uint8_t state);
	uint8_t static invert_sub_byte(uint8_t state);

	/* Utility functions
	*/

#if DEBUG_MODE_ON
	void print_states();
#endif

	/* Common functions
	*/
	void initialize_state(uint8_t *input);
	void initialize_keyparam(uint8_t *key, int keysize);
	void clean_states();
	uint8_t g_mult(uint8_t first, uint8_t second);
	void expand_key(uint8_t *key, int keysize);
	void add_round_key(int round);
	void copy_output(uint8_t *output);

	/* Encryption functions
	*/
	void substitute();
	void shift_row();
	void mix_column();

	/* Decryption functions
	*/
	void invert_substitute();
	void invert_shift_row();
	void invert_mix_column();

	public:
	Aes128();
	void encrypt(uint8_t *message, uint8_t *key, uint8_t *cipher,int keysize);
	void decrypt(uint8_t *cipher, uint8_t *key, uint8_t *message, int keysize);
};

#endif