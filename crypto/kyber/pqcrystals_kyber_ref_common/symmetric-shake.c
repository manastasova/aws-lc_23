#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "symmetric.h"

/*************************************************
 * Name:        kyber_shake128_absorb
 *
 * Description: Absorb step of the SHAKE128 specialized for the Kyber context.
 *
 * Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak
 *state
 *              - const uint8_t *seed: pointer to KYBER_SYMBYTES input to be
 *absorbed into state
 *              - uint8_t i: additional byte of input
 *              - uint8_t j: additional byte of input
 **************************************************/
void kyber_shake128_absorb(keccak_state *state,
                           const uint8_t seed[KYBER_SYMBYTES], uint8_t x,
                           uint8_t y) {
  uint8_t extseed[KYBER_SYMBYTES + 2];

  memcpy(extseed, seed, KYBER_SYMBYTES);
  extseed[KYBER_SYMBYTES + 0] = x;
  extseed[KYBER_SYMBYTES + 1] = y;

  #ifndef EXPERIMENTAL_AWS_LC_HYBRID_KECCAK
  shake128_absorb_once(state, extseed, sizeof(extseed));

  #else
  int p = 0x1F; 

  for (int i = 0; i < 25; i++)
  {
    state->s[i] = 0;
  }
  
  int i = 0; 
  int rem = 0;
  SHA3_Absorb((uint64_t (*)[SHA3_ROWS])state->s, extseed, sizeof(extseed), SHAKE128_RATE);
  
  for(i=0;i<rem;i++){
    state->s[i/8] ^= (uint64_t)extseed[i + sizeof(extseed) - rem] << 8*(i%8);
  }

  state->s[i/8] ^= (uint64_t)p << 8*(i%8);
  state->s[(SHAKE128_RATE-1)/8] ^= 1ULL << 63;
  #endif
}

#ifdef EXPERIMENTAL_AWS_LC_HYBRID_KECCAK
/*************************************************
 * Name:        kyber_shake128_absorb_hybrid
 *
 * Description: Absorb step of the SHAKE128 specialized for the Kyber context with parallel x4 Keccakf1600.
 *
 * Arguments:   - keccak_state_x4_hybrid *state: pointer to hybrid (uninitialized) output 4 Keccak
 *state
 *              - const uint8_t *seed: pointer to KYBER_SYMBYTES input to be
 *absorbed into state
 *              - uint8_t i: additional byte of input
 *              - uint8_t j: additional byte of input
 **************************************************/
void kyber_shake128_absorb_hybrid(keccak_state_x4_hybrid *state,
                           const uint8_t seed[KYBER_SYMBYTES], uint8_t transposed,
                           uint8_t y) {
  // TODO:: Define constant for parallel factor
  uint8_t extseed[4 * (KYBER_SYMBYTES + 2)];

  for (int i = 0; i < 4; i++)
  {
      memcpy(extseed + i * (KYBER_SYMBYTES +2), seed, KYBER_SYMBYTES);
      if (transposed) {
          extseed[i * (KYBER_SYMBYTES + 2) + KYBER_SYMBYTES + 0] = i/2;
          extseed[i * (KYBER_SYMBYTES + 2) + KYBER_SYMBYTES + 1] = i%2;
      }
      else {
          extseed[i * (KYBER_SYMBYTES + 2) + KYBER_SYMBYTES + 0] = i%2;
          extseed[i * (KYBER_SYMBYTES + 2) + KYBER_SYMBYTES + 1] = i/2;
      }

  }
  int p = 0x1F; 

// TODO:: Define constant for parallel factor
  for (int i = 0; i < 4 * 25; i++)
  {
    state->s[i] = 0;
  }
  
  int i = 0; 
  int rem = 0;
  SHA3_Absorb((uint64_t (*)[SHA3_ROWS])state->s, extseed, sizeof(extseed), SHAKE128_RATE);
  
  for(i=0;i<rem;i++){
    state->s[i/8] ^= (uint64_t)extseed[i + sizeof(extseed) - rem] << 8*(i%8);
  }

  state->s[i/8] ^= (uint64_t)p << 8*(i%8);
  state->s[(SHAKE128_RATE-1)/8] ^= 1ULL << 63;
}
#endif

#ifdef EXPERIMENTAL_AWS_LC_HYBRID_KECCAK
void kyber_shake128_squeeze(uint8_t *out, int nblocks, keccak_state *state)
{
   KeccakF1600((uint64_t (*)[SHA3_ROWS])state->s);
   SHA3_Squeeze((uint64_t (*)[SHA3_ROWS])state->s, out, (nblocks) * SHAKE128_RATE, SHAKE128_RATE);
}
#endif

/*************************************************
 * Name:        kyber_shake256_prf
 *
 * Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
 *              and then generates outlen bytes of SHAKE256 output
 *
 * Arguments:   - uint8_t *out: pointer to output
 *              - size_t outlen: number of requested output bytes
 *              - const uint8_t *key: pointer to the key (of length
 *KYBER_SYMBYTES)
 *              - uint8_t nonce: single-byte nonce (public PRF input)
 **************************************************/
void kyber_shake256_prf(uint8_t *out, size_t outlen,
                        const uint8_t key[KYBER_SYMBYTES], uint8_t nonce) {
  uint8_t extkey[KYBER_SYMBYTES + 1];

  memcpy(extkey, key, KYBER_SYMBYTES);
  extkey[KYBER_SYMBYTES] = nonce;

  #ifndef EXPERIMENTAL_AWS_LC_HYBRID_KECCAK
  shake256(out, outlen, extkey, sizeof(extkey));
  #else
  SHAKE256(extkey, sizeof(extkey), out, outlen*8);
  #endif
}
