#ifndef _MAGMA_H_
#define _MAGMA_H_

#include <stdio.h>
#include <stdlib.h>
#include <String.h>
#include <stdint.h>

#ifndef DATA64_UNION
#define DATA64_UNION
typedef union data64{
	uint8_t _8[8];
	uint16_t _16[4];
	uint32_t _32[2];
	uint64_t _64;
};
#endif //DATA64_UNION

class Magma {
private:
	data64 r0, r1;

	static const uint32_t C0 = 0x1010104;
	static const uint32_t C1 = 0x1010101;
	static const uint32_t C2 = 0x1010104;
	
	uint32_t add_mod_32_minus_1(uint32_t a, uint32_t b);
	uint64_t crypt(uint64_t a, uint32_t* key, bool encrypt, int rounds = 32);
	uint32_t* string2key(char* str, int size = 0);

public:
	Magma(){};
	void simple(char* fin, char* fout, char* keystr, bool encrypt);
	void simple(char* fin, char* fout, uint32_t* key, bool encrypt);
	void simple(char* fin, char* fout, data64* key64, bool encrypt);
	void gamma(char* in, char* out, char* keystr, char* init_vector, bool back = 0, bool encrypt = 1);
	void gamma(char* in, char* out, data64* key64, data64 init64, bool back = 0, bool encrypt = 1);
	void gamma(char* in, char* out, uint32_t* key, uint32_t* init, bool back = 0, bool encrypt = 1);
	void test();
};


#endif //_MAGMA_H_