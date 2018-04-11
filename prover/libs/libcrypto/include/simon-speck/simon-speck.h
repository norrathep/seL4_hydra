#include "simonSpeckBasic.h"
#include <simon-speck/simon-ntg.h>
#include <simon-speck/speck-ntg.h>


typedef void (*block64128_f)(u32 PL,u32 PR,u32 *CL, u32 *CR, u32* key,int nn,int keysize);
typedef void (*block64_f)(u64 PL,u64 PR,u64 *CL, u64 *CR, u64* key,int nn,int keysize);
u64 cbc_mac_block64128(u64* pt, size_t len, u32* key, int keysize, block64128_f fn);
