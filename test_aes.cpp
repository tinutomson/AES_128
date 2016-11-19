#include<iostream>
#include<fstream>
#include "aes.hpp" 

int main(int argc, char* argv[]) {
    uint8_t key128[32] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	uint8_t key192[32] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17};
	uint8_t key256[32] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
	uint8_t message[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
	uint8_t cipher[16];
	
	Aes128 aes;
	aes.encrypt(message, key128, cipher,128);
	cout<<"128 bit AES"<<endl;
	cout<< "message : ";
	for(int i = 0; i < 16; ++i) {
		cout<<HEX(message[i])<<" ";
	}

	cout<<endl<<"cipher : ";
	for(int i = 0; i < 16; ++i) {
		cout<<HEX(cipher[i])<<" ";
	}

	aes.decrypt(cipher, key128, cipher, 128);

	cout<<endl<<"decrypted message : ";
	for(int i = 0; i < 16; ++i) {
		cout<<HEX(cipher[i])<<" ";
	}
	cout<<endl;

	cout<<"192 bit AES"<<endl;

	aes.encrypt(message, key192, cipher,192);

	cout<< "message : ";
	for(int i = 0; i < 16; ++i) {
		cout<<HEX(message[i])<<" ";
	}

	cout<<endl<<"cipher : ";
	for(int i = 0; i < 16; ++i) {
		cout<<HEX(cipher[i])<<" ";
	}

	aes.decrypt(cipher, key192, cipher, 192);

	cout<<endl<<"decrypted message : ";
	for(int i = 0; i < 16; ++i) {
		cout<<HEX(cipher[i])<<" ";
	}
	cout<<endl;

    cout<<"256 bit AES"<<endl;

	aes.encrypt(message, key256, cipher, 256);

	cout<< "message : ";
	for(int i = 0; i < 16; ++i) {
		cout<<HEX(message[i])<<" ";
	}

	cout<<endl<<"cipher : ";
	for(int i = 0; i < 16; ++i) {
		cout<<HEX(cipher[i])<<" ";
	}

	aes.decrypt(cipher, key256, cipher, 256);

	cout<<endl<<"decrypted message : ";
	for(int i = 0; i < 16; ++i) {
		cout<<HEX(cipher[i])<<" ";
	}
	cout<<endl;

	return 0;
}
