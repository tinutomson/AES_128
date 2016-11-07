#include <iostream>
#include <stdint.h>
#include <iomanip>
#include <stdio.h>
#include <stdlib.h>
using namespace std;
class AES{
private:
uint8_t key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
uint8_t message[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
uint8_t sbox[16][16] = {{0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76},
{0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0},
{0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15},
{0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75},
{0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84},
{0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf},
{0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8},
{0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2},
{0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73},
{0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb},
{0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79},
{0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08},
{0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a},
{0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e},
{0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf},
{0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16}
};
uint32_t word[44];
uint8_t ciphertext[16];
uint32_t state[4];
uint32_t rotword(uint32_t wordtorotate)
{
  return (wordtorotate<<8) | (wordtorotate>>(32-8));
}
void toHex(int num) {
        int *index;
        int indexval[2];
        index = indexval;
        const string table = "0123456789abcdef"; // lookup hexadecimal
        unsigned int x = num; // make negative complement
        string r = "";
        while (x > 0) {
            int y = x % 16; // get remainder
            r = table[y] + r; // concatenate in the reverse order
            x /= 16; 
        }
       r == "" ? "0" : r;
       //cout<<r<<endl;
}
uint32_t subword(uint32_t wordtosbox)
{
  unsigned mask = ( (1<<(8-0+1))-1) << 0;
  uint8_t result1 =(mask&wordtosbox)>>0;
  //cout<<hex<<(unsigned)result1<<endl;

  mask = ( (1<<(16-8+1))-1) << 8;
  uint8_t result2 =(mask&wordtosbox)>>8;
  //cout<<hex<<(unsigned)result2<<endl;

  mask = ( (1<<(24-16+1))-1) << 16;
  uint8_t result3 =(mask&wordtosbox)>>16;
  //cout<<hex<<(unsigned)result3<<endl;

  mask = ( (1<<(32-24+1))-1) << 24;
  uint8_t result4 =(mask&wordtosbox)>>24;
  //cout<<hex<<(unsigned)result4<<endl;

  mask = ( (1<<(3-0+1))-1) << 0;
  unsigned mask1 = ( (1<<(7-4+1))-1) << 4;
  unsigned index1 = (mask&result1)>>0;
  unsigned index2 = (mask1&result1)>>4;
  //cout<<index2<<" "<<index1;
  uint8_t firstWord = sbox[index2][index1];

  unsigned index3 = (mask&result2)>>0;
  unsigned index4 = (mask1&result2)>>4;
  //cout<<index4<<" "<<index3;
  uint8_t secondWord = sbox[index4][index3];

  unsigned index5 = (mask&result3)>>0;
  unsigned index6 = (mask1&result3)>>4;
  //cout<<index6<<" "<<index5;
  uint8_t thirdWord = sbox[index6][index5];

  unsigned index7 = (mask&result4)>>0;
  unsigned index8 = (mask1&result4)>>4;
  //cout<<index8<<" "<<index7<<endl;
  uint8_t fourthWord=sbox[index8][index7];

  return fourthWord*256*256*256 + thirdWord*256*256 + secondWord*256 + firstWord; 
}

uint32_t rcon(int size)
{
	uint32_t rconvalues[10] = {0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000};
    return rconvalues[size-1];
}
void keyexpansion(int blocksize)
{
 uint32_t temp;
 int i=0;
 while(i<blocksize)
 {
 	word[i]=key[4*i]*256*256*256+key[4*i+1]*256*256+key[4*i+2]*256+key[4*i+3];
 	cout<<hex<<(unsigned)word[i]<<endl;
 	++i;
 }

 i = blocksize;
 
 while(i<44)
 {
 		temp=word[i-1];
 		//cout<<hex<<(unsigned)temp;
 	if(i%blocksize==0)
 		temp = subword((rotword(temp)))^rcon(i/blocksize);
 word[i] = word[i-blocksize] ^ temp;
 cout<<"Round "<<i<<" "<<hex<<(unsigned)word[i]<<endl;
 	++i;	
 }
}
public:
  void encrypt()
  {
    keyexpansion(4);
    uint8_t mixedstates[4][4];
    int i=0;
    while(i<4)
    {
     state[i]=message[4*i]*256*256*256+message[4*i+1]*256*256+message[4*i+2]*256+message[4*i+3];
     state[i]^=word[i];
     cout<<hex<<(unsigned)state[i]<<endl;
     ++i;
    }
    cout<<endl;
    

    //Sbox Operation
    for(int rounditerator=0;rounditerator<9;rounditerator++)
    {
    cout<<"ROUND "<<rounditerator<<endl;  
    cout<<"Sbox"<<endl;
    i=0;
     while(i<4)
     {
      state[i] = subword(state[i]);
      cout<<hex<<(unsigned)state[i]<<endl;
      ++i;
     }
     cout<<endl;
     //cout<<hex<<(unsigned)state[0]<<endl;
     uint8_t states[4][4];
     cout<<endl;

     //Segmenting the state array into smaller chunks

     for (int i = 0; i < 4; ++i)
     {
       for (int j = 0; j < 4; ++j)
       {
         if(i==0)
          states[i][j] = state[j]/(256*256*256);
        if(i==1)
          states[i][j] = (state[j]/(256*256))%256;
        if(i==2)
          states[i][j] = (state[j]/(256))%256;
         if(i==3)
          states[i][j] = state[j]%256;
         cout<<hex<<(unsigned)states[i][j]<<" ";
       }
       cout<<endl;
     }
     cout<<"ShiftRows"<<endl;
     //ShiftRows
     int l=0;
     uint8_t temp = states[1][0];
     for(l=0;l<3;l++)
      states[1][l]=states[1][l+1];
     states[1][l]=temp;

     uint8_t temp1[2];
     temp1[0] = states[2][0];
     temp1[1] = states[2][1];
     states[2][0] = states[2][2]; 
     states[2][1] = states[2][3];
     states[2][2] = temp1[0];
     states[2][3] = temp1[1];

     uint8_t  temp2[3];
     temp2[0] = states[3][0]; 
     temp2[1] = states[3][1];
     temp2[2] = states[3][2]; 
     states[3][0] = states[3][3];
     states[3][1] = temp2[0];
     states[3][2] = temp2[1];
     states[3][3] = temp2[2];


     cout<<endl;

     for (int i = 0; i < 4; ++i)
     {
       /* code */
      for (int j = 0; j < 4; ++j)
      {
        /* code */
        cout<<hex<<(unsigned)states[i][j]<<" ";
      }
      cout<<endl;
     }
     cout<<endl;
     //MixColumns
     cout<<"MixColumns"<<endl;
     for(int i=0;i<4;i++)
     {
     uint8_t leftshift = states[0][i]<<1;
     uint8_t high_bit = states[0][i] & (1 << 7);
     //cout<<(unsigned)high_bit<<endl;
     uint8_t leftshift1 = states[1][i]<<1;
     uint8_t high_bit1 = states[1][i] & (1 << 7);
      
     mixedstates[0][i] = ((high_bit==0?leftshift:leftshift^0x1b)^((high_bit1==0?leftshift1:leftshift1^0x1b)^states[1][i]))^states[2][i]^states[3][i];
     cout<<"0 "<<i<<hex<<(unsigned)mixedstates[0][i]<<endl;

     leftshift = states[1][i]<<1;
     high_bit = states[1][i] & (1 << 7);
     leftshift1 = states[2][i]<<1;
     high_bit1 = states[2][i] & (1 << 7);
     mixedstates[1][i] = states[0][i]^((high_bit==0?leftshift:leftshift^0x1b)^((high_bit1==0?leftshift1:leftshift1^0x1b)^states[2][i]))^states[3][i];
     cout<<"1 "<<i<<hex<<(unsigned)mixedstates[1][i]<<endl;

     leftshift = states[2][i]<<1;
     high_bit = states[2][i] & (1 << 7);
     //cout<<(unsigned)high_bit<<endl;
     leftshift1 = states[3][i]<<1;
     high_bit1 = states[3][i] & (1 << 7);
     
     mixedstates[2][i] = states[0][i]^states[1][i]^((high_bit==0?leftshift:leftshift^0x1b)^((high_bit1==0?leftshift1:leftshift1^0x1b)^states[3][i]));
     cout<<"2 "<<i<<hex<<(unsigned)mixedstates[2][i]<<endl;

     leftshift = states[3][i]<<1;
     high_bit = states[3][i] & (1 << 7);
     //cout<<(unsigned)high_bit<<endl;
     leftshift1 = states[0][i]<<1;
     high_bit1 = states[0][i] & (1 << 7);
     
     mixedstates[3][i] = ((high_bit==0?leftshift:leftshift^0x1b)^((high_bit1==0?leftshift1:leftshift1^0x1b)^states[0][i]))^states[1][i]^states[2][i];
     cout<<"3 "<<i<<hex<<(unsigned)mixedstates[3][i]<<endl;
   }
     //Add Round Key
    cout<<"AddRoundKey"<<endl;
     i=0;
     int j=0;
      while(i<4)
    {
     state[i]=mixedstates[j][i]*256*256*256+mixedstates[j+1][i]*256*256+mixedstates[j+2][i]*256+mixedstates[j+3][i];
     state[i]^=word[i+4*(rounditerator+1)];
     cout<<hex<<(unsigned)state[i]<<endl;
     ++i;
    }
    cout<<endl;
  }
  cout<<"ROUND 10"<<endl;
   cout<<"Sbox"<<endl;
    i=0;
     while(i<4)
     {
      state[i] = subword(state[i]);
      cout<<hex<<(unsigned)state[i]<<endl;
      ++i;
     }
     cout<<endl;
     //cout<<hex<<(unsigned)state[0]<<endl;
     uint8_t states[4][4];
     cout<<endl;

     //Segmenting the state array into smaller chunks

     for (int i = 0; i < 4; ++i)
     {
       for (int j = 0; j < 4; ++j)
       {
         if(i==0)
          states[i][j] = state[j]/(256*256*256);
        if(i==1)
          states[i][j] = (state[j]/(256*256))%256;
        if(i==2)
          states[i][j] = (state[j]/(256))%256;
         if(i==3)
          states[i][j] = state[j]%256;
         cout<<hex<<(unsigned)states[i][j]<<" ";
       }
       cout<<endl;
     }
     cout<<"ShiftRows"<<endl;
     //ShiftRows
     int l=0;
     uint8_t temp = states[1][0];
     for(l=0;l<3;l++)
      states[1][l]=states[1][l+1];
     states[1][l]=temp;

     uint8_t temp1[2];
     temp1[0] = states[2][0];
     temp1[1] = states[2][1];
     states[2][0] = states[2][2]; 
     states[2][1] = states[2][3];
     states[2][2] = temp1[0];
     states[2][3] = temp1[1];

     uint8_t  temp2[3];
     temp2[0] = states[3][0]; 
     temp2[1] = states[3][1];
     temp2[2] = states[3][2]; 
     states[3][0] = states[3][3];
     states[3][1] = temp2[0];
     states[3][2] = temp2[1];
     states[3][3] = temp2[2];


     cout<<endl;

     for (int i = 0; i < 4; ++i)
     {
       /* code */
      for (int j = 0; j < 4; ++j)
      {
        /* code */
        cout<<hex<<(unsigned)states[i][j]<<" ";
      }
      cout<<endl;
     }
     cout<<endl; 

      //Add Round Key
    cout<<"AddRoundKey"<<endl;
     i=0;
     int j=0;
      while(i<4)
    {
     state[i]=states[j][i]*256*256*256+states[j+1][i]*256*256+states[j+2][i]*256+states[j+3][i];
     state[i]^=word[i+4*(9+1)];
     cout<<hex<<(unsigned)state[i]<<endl;
     ++i;
    }
    cout<<endl;
  }
};


int main()
{
  AES aes;
  aes.encrypt();
 return 0;
}
