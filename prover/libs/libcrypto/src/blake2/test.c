#include <stdio.h>
#include <blake2/test.h>
#include <blake2/blake2.h>
#include <blake2/blake2-kat.h>

// ported from blake2s-ref.c main()
void testBlake2s() {

  puts("Starting blake2s test\n");
  uint8_t key[BLAKE2S_KEYBYTES];
  uint8_t buf[KAT_LENGTH];

  for( size_t i = 0; i < BLAKE2S_KEYBYTES; ++i )
    key[i] = ( uint8_t )i;

  for( size_t i = 0; i < KAT_LENGTH; ++i )
    buf[i] = ( uint8_t )i;

  for( size_t i = 0; i < KAT_LENGTH; ++i )
  {
    uint8_t hash[BLAKE2S_OUTBYTES];
    blake2s( hash, buf, key, BLAKE2S_OUTBYTES, i, BLAKE2S_KEYBYTES );

    if( 0 != memcmp( hash, blake2s_keyed_kat[i], BLAKE2S_OUTBYTES ) )
    {
      puts( "error" );
      return -1;
    }
  }

  puts( "ok" );
  return 0;
}
