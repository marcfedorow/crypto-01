//rand() generates int, but
//RAND_MAX == 0x7fff (15 bits), much less then MAX_INT (31 bit)
//so 1. / RAND_MAX gives us pretty big gap between different numbers
//it is 2^(-15) or about 0.00003 == 3 * 10^(-5).
//double can give us much more accurate numbers
//here we're generating numbers between [0; 1)
//so minimal accuracy we get is when exponent equals to -1.
//so it is 52 bits of mantissa which give us about 2^-53
//(-52 from mantissa's length and -1 from exponenta's value)
//probably it is not exact value, for explanation try this code:
/*
double d = 0.5;
double* ptr = &d;
long long* iptr = (long long*)ptr;
*iptr ^= 1; //here we had just incremented mantissa
printf("%.30lf\n", d);
printf("%.30lf\n", d - 0.5);
*/
//maximal accuracy is 2^-1074 due to denormalized double:
/*
double d = 1;
for (int i = 0; i++ < 1074; d /= 2);
printf("%d\n", d? 1 : 0);
d /= 2;
printf("%d\n", d? 1 : 0);

long long unsigned i;
i = 0x0010000000000000; //normalized, exponent == 1, mantissa == 0
printf("%.350lf\n\n", i);
i = 0x0008000000000000; //denormalized, exponent == 0
printf("%.350lf\n\n", i);
i = 0x0000000000000001; //minimal positive double
printf("%.350lf\n\n", i);
*/
//so RAND_MAX's accuracy (2^-15) is not acceptable for us
//also when we divide rand() by RAND_MAX we could fase the problem
//that we use [0..1], not [0..1) range.
//obviously, this problem can be solved by dividing by (RAND_MAX+1)

#ifndef _random_h_
#define _random_h_

#include <time.h>
#include <stdint.h>
#include <random>

void initialize();
inline uint64_t random(uint8_t bitlen = -1);
inline double udrv();
double gauss(double, double);
inline bool coin(uint8_t pos);
inline bool coin();
inline bool generator(double p);

#endif _random_h_