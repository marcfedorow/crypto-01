#include "RSA.h"
#include <assert.h>

RSA::RSA(){
	generate_two_big_primes(p,q);
	phi = (p-1)*(q-1);
	n = p*q;
	uint64_t y;
	while(true) {
		e = ran()%(phi-3)+3;
		if (phi%e==0) continue;
		uint64_t gcd = exgcd(e,phi,d,y);
		if (gcd == 1ULL && d > 0 && d < n) break;
	}

}

uint64_t mod_pro(uint64_t x,uint64_t y,uint64_t n) { 
	uint64_t ret = 0,tmp = x % n; 
	while(y) { 
		if (y & 0x1)
			if((ret += tmp) > n) ret -= n; 
		if ((tmp<<=1)>n) tmp -= n; 
		y>>=1; 
	} 
	return ret; 
}

uint64_t mod(uint64_t a,uint64_t b,uint64_t c) { 
	uint64_t ret = 1; 
	while(b) { 
		if (b & 0x1) ret = mod_pro(ret,a,c); 
		a = mod_pro(a,a,c); 
		b >>= 1; 
	} 
	return ret; 
}

uint64_t RSA::ran() { 
	uint64_t ret=rand(); 
	return (ret<<31)+rand(); 
} 

bool RSA::is_prime(uint64_t n,int t) { 
	if(n < 2) return false; 
	if(n == 2) return true; 
	if(n%2==0) return false; 
	uint64_t k=0,m,a,i; 
	for(m = n-1;!(m & 1);m >>= 1,++k); 
	while(t--) { 
		a = mod(ran()%(n-2)+2,m,n); 
		if(a != 1) { 
			for(i = 0;i < k && a!=n-1; ++i) 
				a = mod_pro(a,a,n); 
			if(i >= k) return false; 
		} 
	} 
	return true; 
}

int RSA::enum_prime_less_than(int n, UI *p) {
	if (n<=2) return 0;
	bool *notPrime = new bool [n+1];
	memset(notPrime, 0, sizeof(bool)*(n+1));
	int cnt = 0;
	p[0] = 1;
	int tmp;
	for (int i=2; i<n; ++i) {
		if (!notPrime[i]) p[++cnt] = i;
		for (int j=1; j<=cnt; ++j) {
			if ((tmp = p[j]*i) >= n) break;
			notPrime[tmp] = true;
			if (i%p[j] == 0) break;
			}
	}
	delete [] notPrime;
	return cnt;
}

/* http://bindog.github.io/blog/2014/07/19/how-to-generate-big-primes */
void RSA::generate_two_big_primes(uint64_t &a, uint64_t &b) {
	// 9-bits intergers
	a = 1e8+ran()%(uint64_t(9e8));
	if (a%2==0) ++a;
	b = 1e8+ran()%(uint64_t(9e8));
	if (b%2==0) ++b;
	static UI* primes_less_than_1e4 = new UI[int(1e4+1)];
	int cnt = enum_prime_less_than(int(1e4), primes_less_than_1e4);
	int i;
	while(true) {
		bool f = false;
		for (i=3; a>primes_less_than_1e4[i] && i<cnt; ++i) {
			if (a%primes_less_than_1e4[i]==0) {f=true;break;}
		}
		if (f) {a+=2;continue;}
		if (!is_prime(a,10)) a+=2;
		else break;
	}

	while(true) {
		if (a==b) {b+=2;continue;}
		bool f = false;
		for (i=3; b>primes_less_than_1e4[i] && i<cnt; ++i) {
			if (b%primes_less_than_1e4[i]==0) {f=true;break;}
		}
		if (f) {b+=2;continue;}
		if (!is_prime(b,10)) b+=2;
		else break;
	}
}

uint64_t RSA::exgcd(uint64_t a, uint64_t b, uint64_t& x, uint64_t& y) {
	if(b == 0) {
		x = 1;
		y = 0;
		return a;
	}
	uint64_t gcd = exgcd(b, a%b, x, y);
	uint64_t t = y;
	y = x-(a/b)*(y);
	x = t;
	return gcd;
}

void RSA::cipher(uint64_t *in, size_t len, uint64_t *out, uint64_t _e, uint64_t _n) {
	for (int i=0; i<len; ++i) { 
		assert(in[i] < _n);
		out[i] = mod(in[i],_e,_n);
	}
}

void RSA::decipher(uint64_t *in, size_t len, uint64_t *out, uint64_t _d, uint64_t _p, uint64_t _q) {
	uint64_t N = _p*_q;
	for (int i=0; i<len; ++i) 
		out[i] = mod(in[i],_d,N);
}

void RSA::demoRSA() {
	printf("Demoing RSA ... \n");
	srand(time(0));
	RSA rsa;
	rsa.print_key();
	int txtlen = 10;
	uint64_t *in = new uint64_t[txtlen], *out = new uint64_t[txtlen], *din = new uint64_t[txtlen];
	for (int i=0; i<txtlen; ++i) {in[i]=(uint64_t)rand();}
	printf("original msg:\n");
	int i;
	for (i = 0; i < txtlen; ++i) {
		printf("%x ", (UI)in[i]);
	}
	printf("\n");
	uint64_t _e,_n,_d,_p,_q;
	rsa.get_public_key(_e,_n);
	RSA::cipher(in,txtlen,out,_e,_n);
	printf("cipher msg:\n");
	for (i = 0; i < txtlen; ++i) {
		printf("%x ", (UI)out[i]);
	}
	printf("\n");
	rsa.get_private_key(_d,_p,_q);
	RSA::decipher(out,txtlen,din,_d,_p,_q);
	printf("decipher msg:\n");
	for (i = 0; i < txtlen; ++i) {
		printf("%x ", (UI)din[i]);
	}
	printf("\n");

}
