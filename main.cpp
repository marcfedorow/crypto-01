#include <stdio.h>
#include <time.h>
#include "magma.h"
#include "rsa.h"
#include "twofish.h"
#include "random.h"

void now() {
    time_t t = time(0);
    char buffer[9] = {0};

    strftime(buffer, 9, "%H:%M:%S", localtime(&t));
    printf("%s\n", buffer);
}

int main(){
	printf("Testing Magma");
	Magma m;
	m.test();
	printf("\n\n");

	initialize();
	//data from sensor should seed random here

	//*
	data64 raw_key[4];
	char key[65]; key[64] = '0';
	for (int i = 0; i < 4; ++i){
		raw_key[i]._64 = random();
		printf("%llx ", raw_key[i]);
		sprintf(key + i*16, "%llx", raw_key[i]);
	}
	data64 raw_iv;
	raw_iv._64 = random();
	char iv[17]; iv[16] = '0';
	printf("\niv = %llx\n", raw_iv);
	sprintf(iv, "%llx", raw_iv);
	
	uint64_t chk[10] = {0};
	uint64_t tmp[10];
	for (int i = 0; i < 8; ++i){
		chk[i] = raw_key[i/2]._32[i%2];
	} chk[8] = raw_iv._32[0]; chk[9] = raw_iv._32[1];
	RSA usc;
	uint64_t p, q, phi, e, d, n;
	//example RSA keys:
	p=642546967, q=203975693, phi=131063962032350472, e=51120848256533, d=62215461244781189, n = p * q;
	//usc.get_public_key(e, n);
	usc.cipher(chk, 10, tmp, e, n);
	//usc.get_private_key(d, p, q);
	usc.decipher(tmp, 10, chk, d, p, q);
	for (int i = 0; i < 10; ++i){
		printf("%llx ", chk[i]);
	} printf("\n");
	//*/

	TF t;
	FILE *fin, *ftmp, *fout;
	printf("Twofish:\n");
	now();
	t.simple("data01.txt", "tf_simple.txt", (uint8_t*)raw_key, 1);
	now();
	t.simple("tf_simple.txt", "out_tf.txt", (uint8_t*)raw_key, 0);
	now();
	//*
	Magma l;
	printf("Magma:\n");
	now();
	l.simple("data01.txt", "tmp_simple.txt", raw_key, 1);
	now();
	l.simple("tmp_simple.txt", "out_simple.txt", key, 0);
	now();
	l.gamma("data01.txt", "tmp_gamma.txt", key, iv);
	now();
	l.gamma("tmp_gamma.txt", "out_gamma.txt", raw_key, raw_iv);
	now();
	l.gamma("data01.txt", "tmp_gamma_feedback.txt", key, iv, 1, 1);
	now();
	l.gamma("tmp_gamma.txt", "out_gamma_feedback.txt", key, iv, 1, 0);
	now();
	//*/
	return 0;
}
