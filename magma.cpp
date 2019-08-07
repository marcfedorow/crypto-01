#include "Magma.h"

#if 1
static unsigned char pi[8][16] =
{
  {12,4,6,2,10,5,11,9,14,8,13,7,0,3,15,1},
  {6,8,2,3,9,10,5,12,1,14,4,7,11,13,0,15},
  {11,3,5,8,2,15,10,13,14,1,7,4,12,9,6,0},
  {12,8,2,1,13,4,15,6,7,0,10,5,3,14,9,11},
  {7,15,5,10,8,1,6,13,0,9,3,14,11,4,2,12},
  {5,13,15,6,9,2,12,10,11,7,8,1,4,3,14,0},
  {8,14,2,5,6,9,1,12,15,4,11,0,13,10,3,7},
  {1,7,14,13,0,5,8,3,4,15,10,6,9,12,11,2},

};
#else
static unsigned char pi[8][16] =
{
  {1,7,14,13,0,5,8,3,4,15,10,6,9,12,11,2},
  {8,14,2,5,6,9,1,12,15,4,11,0,13,10,3,7},
  {5,13,15,6,9,2,12,10,11,7,8,1,4,3,14,0},
  {7,15,5,10,8,1,6,13,0,9,3,14,11,4,2,12},
  {12,8,2,1,13,4,15,6,7,0,10,5,3,14,9,11},
  {11,3,5,8,2,15,10,13,14,1,7,4,12,9,6,0},
  {6,8,2,3,9,10,5,12,1,14,4,7,11,13,0,15},
  {12,4,6,2,10,5,11,9,14,8,13,7,0,3,15,1},
};
#endif //non-linear permutation

#define reorder(_32) (((_32)>>24) | ((_32)<<24) | (((_32)>>8)&0xFF00) | (((_32)<<8)&0xFF0000))
#define min(x, y) (((x) < (y)) ? (x) : (y))
#define char2digit(c) ( \
	('0' <= (c) && (c) <= '9') ? (c - '0') : \
	('a' <= (c) && (c) <= 'f') ? (c - 'a' + 10) : \
	('A' <= (c) && (c) <= 'F') ? (c - 'A' + 10) : \
	(1 / (c - c)) )

#define S(shift, val) ( pi[shift][(val & (0xF << (4*shift))) >> (4*shift)] << (4 * shift) )
#define t(val) ( S(0, val) | S(1, val) | S(2, val) | S(3, val) | S(4, val) | S(5, val) | S(6, val) | S(7, val) )
#define g(k, a) ( (t(a + k) << 11) | ((uint32_t)t(a + k) >> (32 - 11)) )
#define _G(k, a1, a0) (a1 ^ g(k, a0))
#define swap(a, b) if (a != b) {a ^= b; b ^= a; a ^= b;}

uint32_t Magma::add_mod_32_minus_1(uint32_t a, uint32_t b){
	uint32_t res = a + b;
	return (a + b) + ((res < a) | (res < b));
}

uint32_t* Magma::string2key(char* str, int size){
	if (strlen(str) / 2 != size * sizeof(uint32_t)) return nullptr;
	uint32_t* key = (uint32_t*) calloc(size, sizeof(uint32_t));
	for (int i = 0; i < size; ++i){
		for (int j = 0; j < 8; ++j){ //8 half-bytes in uint32_t
			key[i] <<= 4;
			key[i] += char2digit(str[i * 8 + j]);
		}
	}
	return key;
}

uint64_t Magma::crypt(uint64_t a, uint32_t* key, bool encrypt, int rounds){
	data64 data;
	data._64 = a;
	uint32_t tmp;
	for (int i = 0; i < rounds / 8; ++i){
		for (int j = 0; j < 8; ++j){
			data._32[1] = _G(key[ (encrypt? (i == 3) : (i != 0)) ? (7 - j) : (j)], data._32[1], data._32[0]);
			swap(data._32[1], data._32[0]);
			//printf("%d: %x %x\n", i * 8 + j, data._32[1], data._32[0]);
		}
	}
	swap(data._32[1], data._32[0]);
	return data._64;
}


static inline uint64_t get64(FILE* file){
	uint64_t r = 0;
	for (int i = 0; i < 8; ++i){
		r <<= 8;
		r |= getc(file);
	}
	return r;
}

static inline void put64(uint64_t c, FILE* file){
	for (int i = 7; i >= 0; --i){
		putc(c >> (8 * i), file);
	}
}



void Magma::simple(char* in, char* out, char* keystr, bool encrypt){
	auto key = string2key(keystr, 8);
	simple(in, out, key, encrypt);
}

void Magma::simple(char* in, char* out, data64* key64, bool encrypt){
	uint32_t key[8];
	for (int i = 0; i < 4; ++i){
		key[i * 2] = key64[i]._32[1];
		key[i*2+1] = key64[i]._32[0];
	}
	simple(in, out, key, encrypt);
}

void Magma::simple(char* in, char* out, uint32_t* key, bool encrypt){
	FILE* fin = fopen(in, "rb");
	if (!fin) {
		printf("Failed to open %s", in);
		return;
	}
	fseek(fin, 0, SEEK_END);
	int fsize = ftell(fin);
	fseek(fin, 0, SEEK_SET);

	FILE* fout = fopen(out, "wb");
	if (!fout) {
		printf("Failed to create/open %s", out);
		return;
	}

	int r = 8 - (fsize % 8);
	uint64_t in_block = 1;
	if (encrypt){
		for (int i = 0; (i + r) % 8; ++i){
			in_block <<= 8;
			in_block |= getc(fin); //probably better than fgets()
		}
		put64(crypt(in_block, key, encrypt), fout);
	} else {
		if (r != 8) {
			printf("Chypher file error: wrong size");
			return;
		}
		in_block = get64(fin);
		data64 tmp;
		tmp._64 = crypt(in_block, key, encrypt);
		int a;
		for (a = 7; !tmp._8[a]; --a);
		if (tmp._8[a] != 1) {
			printf("Chypher file error: wrong begin");
			return;
		}
		for (; --a >= 0; putc(tmp._8[a], fout));
		r = 0;
	}

	for (fsize -= (8 - r); fsize; fsize -= 8){
		in_block = get64(fin);
		put64(crypt(in_block, key, encrypt), fout);
	}
	fclose(fin); fclose(fout);
}

void Magma::gamma(char* in, char* out, char* keystr,  char* init_vector, bool back, bool encrypt){
	auto iv = string2key(init_vector, 2);
	auto key = string2key(keystr, 8);
	r0._32[0] = iv[0]; r0._32[1] = iv[1];
	r1._64 = back? r0._64 : (r0._64, key, 1);
	gamma(in, out, key, iv, back, encrypt);
}

void Magma::gamma(char* in, char* out, data64* key64, data64 init64, bool back, bool encrypt){
	uint32_t iv[2]; iv[0] = init64._32[0]; iv[1] = init64._32[1];
	uint32_t key[8];
	for (int i = 0; i < 4; ++i){
		key[i * 2] = key64[i]._32[1];
		key[i*2+1] = key64[i]._32[0];
	}
	gamma(in, out, key, iv, back, encrypt);
}

void Magma::gamma(char* in, char* out, uint32_t* key, uint32_t* iv, bool back, bool encrypt){
	FILE* fin = fopen(in, "rb");
	if (!fin) {
		printf("Failed to open %s", in);
		return;
	}
	fseek(fin, 0, SEEK_END);
	int fsize = ftell(fin);
	fseek(fin, 0, SEEK_SET);

	FILE* fout = fopen(out, "wb");
	if (!fout) {
		printf("Failed to create/open %s", out);
		return;
	}

	for (int i = 0; i < fsize; ++i){
		if ((i % 8) == 0){
			if (!back){
				r1._32[0] += C0;
				r1._32[1] = add_mod_32_minus_1(r1._32[1], C1);
				r0 = r1;
				r1._64 = crypt(r0._64, key, 1);
			} else {
				r0 = r1;
				if (i) r1._64 = crypt(r0._64, key, 1);
			}
		}
		if (!back) {
			putc(r1._8[i%8] ^ getc(fin), fout);
		} else if (encrypt) {
			r1._8[i%8] ^= putc(r1._8[i%8] ^ getc(fin), fout);
		} else {
			putc(r1._8[i%8] ^= getc(fin), fout);
		}
	}
}

void Magma::test(){
	uint32_t q = 0xfdb97531;
	for (int i = 0; i < 4 && 1; ++i){
		printf("t(%x) = ", q);
		q = t(q);
		printf("%x\n", q);
	}
	/*
	t(fdb97531) = 2a196f34,
	t(2a196f34) = ebd9f03a,
	t(ebd9f03a) = b039bb3d,
	t(b039bb3d) = 68695433.
	*/

	uint32_t k = 0x87654321, a = 0xfedcba98;
	for (int i = 0; i < 4 && 1; ++i){
		printf("g[%x](%x) = ", k, a);
		q = g(k, a);
		printf("%x\n", q);
		a = k; k = q;
	}
	/*
	g[87654321](fedcba98) = fdcbc20c,
	g[fdcbc20c](87654321) = 7e791a4b,
	g[7e791a4b](fdcbc20c) = c76549ec,
	g[c76549ec](7e791a4b) = 9791c849.
	*/

	char* keystr = "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
	uint32_t* key = string2key(keystr, 8);
	for (int i = 0; i < 8 && 0; ++i){
		printf("%x\n", key[i]);
	}
	auto o = 0xfedcba9876543210ULL;
	printf("opentext = %llx\n", o);
	uint64_t cyphertext = crypt(o, key, 1);
	printf("cyphertext = %llx\n", cyphertext);
	uint64_t result = crypt(cyphertext, key, 0);
	printf("decrypted = %llx\n", result);
}
