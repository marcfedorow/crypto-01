#ifndef RSA_H
#define RSA_H
typedef unsigned int UI;

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string.h>

class RSA{
public:
	RSA();
	~RSA(){};
	void print_key() {
		printf("RSA keys: ");
		printf("p=%llu, q=%llu, phi=%llu, e=%llu, d=%llu", p,q,phi,e,d);
		printf("\n");
	}
	void get_public_key(uint64_t &_e, uint64_t &_n) {_e=e,_n=n;}
	void get_private_key(uint64_t &_d, uint64_t &_p, uint64_t &_q) {_p=p,_q=q,_d=d;}

	static void cipher(uint64_t *in, size_t len, uint64_t *out, uint64_t _e, uint64_t _n);
	static void decipher(uint64_t *in, size_t len, uint64_t *out, uint64_t _d, uint64_t _p, uint64_t _q);
	static void demoRSA();
private:
	uint64_t p,q,phi,e,d,n;
	uint64_t ran();
	bool is_prime(uint64_t n,int t);
	int enum_prime_less_than(int n, UI *p);
	void generate_two_big_primes(uint64_t &a, uint64_t &b);
	uint64_t exgcd(uint64_t a, uint64_t b, uint64_t& x, uint64_t& y);

};

#endif