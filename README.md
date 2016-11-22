# AES

AES is an 128/192/256 bit key implementation of AES-Rijndael algorithm using C++ 11 implementation. 
Prerequisites to build the project : compiler that supports C++11, Cmake >= 2.8
In order to build the project use the following commands:

`cmake .`

`make`

To run the application after building on a unix machine:

 `./AES` with following options:
```
-h for help
-v for version
-t for running test cases
-e for encrypt
-d for decrypt. Default is encrypt
-n for key length. Default is 128 bits
-i for input file
-k for key file
-o for output file
```
The program may terminated abruptly if any unrecognised options are specified or if required arguments are not specified.
