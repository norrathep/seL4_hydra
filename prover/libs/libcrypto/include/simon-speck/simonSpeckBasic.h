#include <stdlib.h>
#include <stdint.h>

//typedef __int64 s64;
//typedef unsigned __int64 u64;
typedef uint64_t u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;


#define ROTL( n, X )    ( ( ( X ) << n ) | ( ( X ) >> ( 32 - n ) ) )

#define ROTL2( n, X, L )    ( ( ( X ) << ( n + 64 - L ) >> (64-L)) | ( ( X ) >> ( L - n ) ) )

