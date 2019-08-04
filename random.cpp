#include "random.h"

static inline short bsr (int val) {
    short res = -1;
    while (val) {
        val >>= 1;
        ++res;
    }
    return res;
}
 
void initialize(){
	srand(time(NULL));
	rand();
}

inline uint64_t random(uint8_t bitlen){
	bitlen = bitlen > sizeof(uint64_t) * 8? sizeof(uint64_t) * 8 : bitlen;
	uint64_t r = 0;
	for (int i = 0; i < bitlen; i += 15){
		r <<= 15;
		r ^= rand();
	}
	return bitlen == sizeof(uint64_t) * 8? r : r % ((uint64_t)1 << bitlen);
}

inline uint64_t random(int64_t min, int64_t max){
	int bitlen = bsr(max - min);
	uint64_t r;
	do {
		r = 0;
		for (int i = 0; i < bitlen; i += 15) {
			r <<= 15;
			r ^= rand();
		}
	} while (r > (max - min));
	return r + min;
}

inline double udrv(){ //uniformly destributed random variable
	return random(64) / (double((uint64_t)1 << 32)) / ((uint64_t)1 << 32); //[0, 1)
	return random(64) / (double)((uint64_t)-1); //[0, 1]
}

double gauss(double M = 0., double dev = 1.){ //normal distribution
	float u, e;
	do {
		u = udrv();
		e = -log(udrv());
	} while(u >= exp(-(e-1)*(e-1)));
	return ( coin()? u : -u ) * dev + M;
}

inline bool coin(uint8_t pos){
	return (random() >> (pos%63)) % 2;
}

inline bool coin(){
	return rand() % 2;
}

inline bool generator(double p, double(*f)(void) = udrv){
	return (f() < p);
}