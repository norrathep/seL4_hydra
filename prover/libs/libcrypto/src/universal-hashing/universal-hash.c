#include <stdint.h>

uint64_t mult_hash(uint8_t* x, int size)
{
    uint64_t p = (1>>61)-1;
    return mult_hash(x, size, 31, 0, 1, p);
}

uint64_t mult_hash(uint8_t* x, int size, uint64_t a, uint64_t init_val, uint64_t p)
{
    uint64_t h = init_val;
    unsigned int i;
    for(i=0; i<size; ++i) {
	h = ((h*a)+x[i]) % p;
    }
    return h;
}
