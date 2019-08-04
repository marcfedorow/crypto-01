#include <stdio.h>
#include <malloc.h>
#include "twofish.h"
#include "tables.h"

#define xor(g,r)    (g^r)                   /* Xor */
#define ror(g,n)    ((g>>n)|(g<<(32-n)))    /* Циклический сдвиг вправо  */
#define rol(g,n)    ((g<<n)|(g>>(32-n)))    /* Циклический сдвиг влево   */
#define nxt(g,r)    (*(g+r))                /* Получить следующий байт   */
#define unpack(g,r) ((g>>(r*8))&0xff)                               /* Возвращает байт из слова(4 байт)  */
#define pack(g)     ((*(g))|(*(g+1)<<8)|(*(g+2)<<16)|(*(g+3)<<24))  /* Конвертирует 4 байта в слово.     */
#define rsm(i,a,b,c,d,e,f,g,h)  \
        gf(nxt(tf_key->k,r*8),a,0x14d)^gf(nxt(tf_key->k,r*8+1),b,0x14d)^\
        gf(nxt(tf_key->k,r*8+2),c,0x14d)^gf(nxt(tf_key->k,r*8+3),d,0x14d)^\
        gf(nxt(tf_key->k,r*8+4),e,0x14d)^gf(nxt(tf_key->k,r*8+5),f,0x14d)^\
        gf(nxt(tf_key->k,r*8+6),g,0x14d)^gf(nxt(tf_key->k,r*8+7),h,0x14d)  //333 = x^8 + x^6 + x^3 + x^2 + 1
#define u(x,a)\
        x[0] = unpack(a,0); \
        x[1] = unpack(a,1); \
        x[2] = unpack(a,2); \
        x[3] = unpack(a,3);
#define release(a,b,c)  { free(a); free(b);free(c); }

TF::TF(){
	tf_twofish = new twofish_t;
}
TF::~TF(){
	delete tf_twofish;
}

twofish_t* TF::setup(uint8_t *s, uint32_t len){
    key_t* tf_key = expand_key(s, len/8);
    subkey_t *tf_subkey = generate_subkey(tf_key);
    twofish_t* tf_twofish = (twofish_t*)malloc(sizeof(twofish_t));
    tf_twofish = generate_ext_k_keys(tf_subkey,0x01010101,(tf_key->len/8)); //p = 0x01010101 = 2^24 + 2^16 + 2^8 + 2^0
    tf_twofish = generate_ext_s_keys(tf_subkey,(tf_key->len/8));
    release(tf_key->k, tf_key, tf_subkey);
    return tf_twofish;
}

void TF::encryt(uint8_t *data, uint8_t *cypher)
{
    uint32_t r0, r1, r2, r3, f0, f1, c2,c3;
    r0 = tf_twofish->k[0]^pack(data);
    r1 = tf_twofish->k[1]^pack(data+4);
    r2 = tf_twofish->k[2]^pack(data+8);
    r3 = tf_twofish->k[3]^pack(data+12);

    for (int i = 0; i < 16; ++i) {
        f(i, r0, r1, &f0, &f1);
        c2 = ror((f0^r2), 1);
        c3 = (f1^rol(r3,1));
        r2 = r0;
        r3 = r1;
        r0 = c2;
        r1 = c3;
    }
    c2 = r0;
    c3 = r1;
    r0 = tf_twofish->k[4]^r2;
    r1 = tf_twofish->k[5]^r3;
    r2 = tf_twofish->k[6]^c2;
    r3 = tf_twofish->k[7]^c3;

    for (int i = 0; i < 4; ++i) {
        cypher[i]   = unpack(r0,i);
        cypher[i+4] = unpack(r1,i);
        cypher[i+8] = unpack(r2,i);
        cypher[i+12]= unpack(r3,i);
    }
}

void TF::decryt(uint8_t *cypher, uint8_t *data){
    uint32_t r0, r1, r2, r3, f0, f1, c2,c3;
    r0 = tf_twofish->k[4]^pack(cypher);
    r1 = tf_twofish->k[5]^pack(cypher+4);
    r2 = tf_twofish->k[6]^pack(cypher+8);
    r3 = tf_twofish->k[7]^pack(cypher+12);

    for (int i = 15; i >= 0; --i){
        f(i, r0, r1, &f0, &f1);
        c2 = (rol(r2,1)^f0);
        c3 = ror((f1^r3),1);
        r2 = r0;
        r3 = r1;
        r0 = c2;
        r1 = c3;
    }
    c2 = r0;
    c3 = r1;
    r0 = tf_twofish->k[0]^r2;
    r1 = tf_twofish->k[1]^r3;
    r2 = tf_twofish->k[2]^c2;
    r3 = tf_twofish->k[3]^c3;
    
    for (int i = 0; i < 4; ++i){
        data[i]   = unpack(r0,i);
        data[i+4] = unpack(r1,i);
        data[i+8] = unpack(r2,i);
        data[i+12]= unpack(r3,i);
    }
}

void TF::f(uint8_t r,uint32_t r0, uint32_t r1, uint32_t* f0, uint32_t* f1){
    uint32_t t0, t1, o;
    t0 = g(r0);
    t1 = rol(r1, 8);
    t1 = g(t1);
    o = 2*r;
    *f0= (t0 + t1 + tf_twofish->k[o+8]);
    *f1= (t0 + (2*t1) + tf_twofish->k[o+9]);
}

twofish_t* TF::generate_ext_k_keys(subkey_t *tf_subkey,uint32_t p, uint8_t k){
    uint32_t a, b;
    uint8_t x[4], y[4], z[4];
    for(int i=0;i<40;i+=2)                  /* i = 40/2 */
    {
        a = (i*p);                          /* 2*i*p */
        b = (a+p);                          /* ((2*i +1)*p */
        u(x,a);
        h(x, y, tf_subkey->me, k);
        mds_mul(y,z);
        a = pack(z);                        /* Конвертирует 4 байта z[4] в слово (a). */
        u(x,b);                             /* Конвертирует слово (b) в 4 байта x[4]. */
        h(x, y, tf_subkey->mo, k);
        mds_mul(y,z);        
        b = pack(z);
        b = rol(b,8);
        tf_twofish->k[i] = ((a + b));
        tf_twofish->k[i+1] = rol(((a + (2*b))),9);
    }
    return tf_twofish;
}

twofish_t* TF::generate_ext_s_keys(subkey_t *tf_subkey, uint8_t k){
    uint8_t x[4], y[4];
    for(int i=0;i<256;++i)
    {
        x[0] = x[1] = x[2] = x[3] = i;
        h(x, y, tf_subkey->s, k);
        tf_twofish->s[0][i] = (gf(y[0], mds[0][0],0x169) |(gf(y[1],mds[0][1],0x169)<< 8)|(gf(y[2], mds[0][2],0x169)<<16) |(gf(y[3], mds[0][3], 0x169) <<24));
        tf_twofish->s[1][i] = (gf(y[0], mds[1][0],0x169) |(gf(y[1],mds[1][1],0x169)<< 8)|(gf(y[2], mds[1][2],0x169)<<16) |(gf(y[3], mds[1][3], 0x169) <<24));
        tf_twofish->s[2][i] = (gf(y[0], mds[2][0],0x169) |(gf(y[1],mds[2][1],0x169)<< 8)|(gf(y[2], mds[2][2],0x169)<<16) |(gf(y[3], mds[2][3], 0x169) <<24));
        tf_twofish->s[3][i] = (gf(y[0], mds[3][0],0x169) |(gf(y[1],mds[3][1],0x169)<< 8)|(gf(y[2], mds[3][2],0x169)<<16) |(gf(y[3], mds[3][3], 0x169) <<24));
    }
    return tf_twofish;
}

void TF::mds_mul(uint8_t y[],  uint8_t out[])
{
    out[0] = (gf(y[0], mds[0][0], 0x169)^gf(y[1], mds[0][1], 0x169)^gf(y[2], mds[0][2], 0x169)^gf(y[3], mds[0][3], 0x169));
    out[1] = (gf(y[0], mds[1][0], 0x169)^gf(y[1], mds[1][1], 0x169)^gf(y[2], mds[1][2], 0x169)^gf(y[3], mds[1][3], 0x169));
    out[2] = (gf(y[0], mds[2][0], 0x169)^gf(y[1], mds[2][1], 0x169)^gf(y[2], mds[2][2], 0x169)^gf(y[3], mds[2][3], 0x169));
    out[3] = (gf(y[0], mds[3][0], 0x169)^gf(y[1], mds[3][1], 0x169)^gf(y[2], mds[3][2], 0x169)^gf(y[3], mds[3][3], 0x169));
}

uint32_t TF::g(uint32_t x)
{
    return (tf_twofish->s[0][unpack(x,0)]^tf_twofish->s[1][unpack(x, 1)]^tf_twofish->s[2][unpack(x,2)]^tf_twofish->s[3][unpack(x,3)]);
}

void TF::h(uint8_t x[],  uint8_t out[], uint8_t s[][4], int stage)
{
    uint8_t y[4];
    for (int j=0; j<4;++j)
    {
        y[j] = x[j];
    }

    if (stage == 4)
    {
        y[0] = q[1][y[0]] ^ (s[3][0]);
        y[1] = q[0][y[1]] ^ (s[3][1]);
        y[2] = q[0][y[2]] ^ (s[3][2]);
        y[3] = q[1][y[3]] ^ (s[3][3]);
    }
    if (stage > 2)
    {
        y[0] = q[1][y[0]] ^ (s[2][0]);
        y[1] = q[1][y[1]] ^ (s[2][1]);
        y[2] = q[0][y[2]] ^ (s[2][2]);
        y[3] = q[0][y[3]] ^ (s[2][3]);
    }

    out[0] = q[1][q[0][ q[0][y[0]] ^ (s[1][0])] ^ (s[0][0])];
    out[1] = q[0][q[0][ q[1][y[1]] ^ (s[1][1])] ^ (s[0][1])];
    out[2] = q[1][q[1][ q[0][y[2]] ^ (s[1][2])] ^ (s[0][2])];
    out[3] = q[0][q[1][ q[1][y[3]] ^ (s[1][3])] ^ (s[0][3])];
}

subkey_t* TF::generate_subkey(key_t* tf_key)
{
    int k, r, g;
    subkey_t *tf_subkey = (subkey_t*)malloc(sizeof(subkey_t));
    k = tf_key->len/8;
    for(r=0; r<k;++r){
        tf_subkey->me[r][0] = nxt(tf_key->k, r*8    );
        tf_subkey->me[r][1] = nxt(tf_key->k, r*8 + 1);
        tf_subkey->me[r][2] = nxt(tf_key->k, r*8 + 2);
        tf_subkey->me[r][3] = nxt(tf_key->k, r*8 + 3);
        tf_subkey->mo[r][0] = nxt(tf_key->k, r*8 + 4);
        tf_subkey->mo[r][1] = nxt(tf_key->k, r*8 + 5);
        tf_subkey->mo[r][2] = nxt(tf_key->k, r*8 + 6);
        tf_subkey->mo[r][3] = nxt(tf_key->k, r*8 + 7);
        
        g=k-r-1;
        tf_subkey->s[g][0] = rsm(r, 0x01, 0xa4, 0x55, 0x87, 0x5a, 0x58, 0xdb, 0x9e);
        tf_subkey->s[g][1] = rsm(r, 0xa4, 0x56, 0x82, 0xf3, 0x1e, 0xc6, 0x68, 0xe5);
        tf_subkey->s[g][2] = rsm(r, 0x02, 0xa1, 0xfc, 0xc1, 0x47, 0xae, 0x3d, 0x19);
        tf_subkey->s[g][3] = rsm(r, 0xa4, 0x55, 0x87, 0x5a, 0x58, 0xdb, 0x9e, 0x03);
    }
    return tf_subkey;
}

key_t* TF::expand_key(uint8_t *s, uint32_t len)
{
    int n;
    
    if (len<=16)       n = 16;
    else if (len<=24)  n = 24;
    else if (len<=32)  n = 32;
    key_t* tf_key = (key_t*)malloc(sizeof(key_t));
    uint8_t* ss = (uint8_t*)malloc(n);
   
    for (int g=0; g<n; ++g)
    {
        if (g < len)
        {
            *(ss+g) = *(s+g);
            continue;
        }
        *(ss+g) = 0x00;
    }
    tf_key->k = ss;
    tf_key->len=n;
    return tf_key;
}

uint8_t TF::gf(uint8_t x, uint8_t y, uint16_t m)
{
    uint8_t c, p = 0;
    for (int i=0; i<8; ++i)
    {
        if (y & 0x1)
            p ^= x;
        c = x & 0x80;
        x <<= 1;
        if (c)
            x ^= m;
        y >>= 1;
    }
    return p;
}

void TF::encrypt_file(FILE* in, FILE* out) {
	long fsize;
	fseek(in, 0, SEEK_END);
	fsize = ftell(in);
	fseek(in, 0, SEEK_SET);

	uint8_t* buffer = (uint8_t*)malloc(16);
	uint8_t* out_buffer = (uint8_t*)malloc(16);

	uint8_t* reserved_buffer = (uint8_t*)malloc(16);
	reserved_buffer[0] = 128;
	for (int i = 1; i < 16; ++i) {
		reserved_buffer[i] = 0;
	}
	uint8_t* reserved_buffer_cypher = (uint8_t*)malloc(16);

	while (fsize > 0) {
		if (fsize < 16) {
			int extension = 16 - fsize;
			fread(buffer, sizeof(uint8_t), fsize, in);
			for (int i = 0; i < extension; ++i) {
				//buffer[15 - i] = extension;
				if (i == extension - 1) {
					buffer[15 - i] = 128;
				}
				else {
					buffer[15 - i] = 0;
				}
			}
		}
		else if (fsize == 16) {
			fread(buffer, sizeof(uint8_t), 16, in);
			encryt(reserved_buffer, reserved_buffer_cypher);
		} else { fread(buffer, sizeof(uint8_t), 16, in); }

		encryt(buffer, out_buffer);
		fwrite(out_buffer, sizeof(uint8_t), 16, out);
		if (fsize == 16) {
			fwrite(reserved_buffer_cypher, sizeof(uint8_t), 16, out);
		}
		fsize -= 16;
	}
	free(buffer);
	free(out_buffer);
	free(reserved_buffer);
}

void TF::decrypt_file(FILE* in, FILE* out) {
	long fsize;
	fseek(in, 0, SEEK_END);
	fsize = ftell(in);
	fseek(in, 0, SEEK_SET);

	uint8_t* buffer = (uint8_t*)malloc(16);
	uint8_t* out_buffer = (uint8_t*)malloc(16);

	while (fsize > 0) {
		fread(buffer, sizeof(uint8_t), 16, in);
		decryt(buffer, out_buffer);
		if (fsize == 16) {
			int j = 15;
			while (out_buffer[j] == 0) {
				--j;
			}
			if (out_buffer[j] == 128) {
				fwrite(out_buffer, sizeof(uint8_t), j, out);
			}
			else {
				fwrite(out_buffer, sizeof(uint8_t), 16, out);
			}
		}
		else {
			fwrite(out_buffer, sizeof(uint8_t), 16, out);
		}
		fsize -= 16;
	}
	free(buffer);
	free(out_buffer);
}

void TF::simple(char* in, char* out, uint8_t* key, bool encrypt){
	
	auto fin = fopen(in, "rb");
	auto fout = fopen(out, "wb");
	tf_twofish = setup(key, 256);
	return encrypt? encrypt_file(fin, fout) : decrypt_file(fin, fout);
	fclose(fin);
	fclose(fout);
}