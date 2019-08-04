#ifndef __TWOFISH__H
#define __TWOFISH__H
#include <stdint.h>

#ifndef TWOFISH
#define TWOFISH
typedef struct twofish_t 
{
	uint8_t len;
	uint32_t k[40];
	uint32_t s[4][256];
}twofish_t;
#endif //TWOFISH

#ifndef DATA64_UNION
#define DATA64_UNION
typedef union data64{
	uint8_t _8[8];
	uint16_t _16[4];
	uint32_t _32[2];
	uint64_t _64;
};
#endif //DATA64_UNION

typedef struct key_t 
{
	uint8_t len;
	uint8_t *k;
};
typedef struct subkey_t 
{
	uint8_t len;
	uint8_t s[4][4];
	uint8_t me[4][4];
	uint8_t mo[4][4];
}subkey_t;

class TF{
private:
	twofish_t* tf_twofish;
	void encryt(uint8_t *data, uint8_t *cypher);
	void decryt(uint8_t *cypher, uint8_t *data);
	twofish_t*  setup(uint8_t *s, uint32_t len);

	key_t* expand_key(uint8_t *s, uint32_t len);
	uint8_t gf(uint8_t x, uint8_t y, uint16_t m);
	subkey_t* generate_subkey(key_t* tf_key);
	void h(uint8_t x[],  uint8_t y[], uint8_t s[][4], int stage);
	void mds_mul(uint8_t y[],  uint8_t out[]);
	twofish_t* generate_ext_k_keys(subkey_t *tf_subkey,uint32_t p, uint8_t k);
	twofish_t* generate_ext_s_keys(subkey_t *tf_subkey, uint8_t k);
	void f(uint8_t r,uint32_t r0, uint32_t r1, uint32_t* f0, uint32_t* f1);
	uint32_t g(uint32_t x);
	void encrypt_file(FILE* in, FILE* out);
	void decrypt_file(FILE* in, FILE* out);
public:
	TF();
	~TF();
	void simple(char* fin, char* fout, uint8_t* keystr, bool encrypt);
};

#endif //_TWOFISH_H_
