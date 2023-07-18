#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
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
  rem = SHA3_Absorb((uint64_t (*)[SHA3_ROWS])state->s, extseed, sizeof(extseed), SHAKE128_RATE);

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
                           const uint8_t seed[KYBER_SYMBYTES], uint8_t transposed) {

  uint8_t extseed[KECCAK_PARALLEL_FACTOR * (KYBER_SYMBYTES + 2)];

    for (int i = 0; i < KECCAK_PARALLEL_FACTOR; i++) {
        for (int j = 0; j < KYBER_SYMBYTES; j++) {
          extseed[i*KYBER_SYMBYTES + j] = seed[i*8 + j%8];
        }
    }
  
  // TODO:: Can do better here  
  for (int i = 0; i < KECCAK_PARALLEL_FACTOR; i++)
  { 
      if (transposed == 1) {
          extseed[i*2 + KYBER_SYMBYTES * KECCAK_PARALLEL_FACTOR + 0] = i/2;
          extseed[i*2 + KYBER_SYMBYTES * KECCAK_PARALLEL_FACTOR + 1] = i%2;
      }
      else {
          extseed[i*2 + KYBER_SYMBYTES * KECCAK_PARALLEL_FACTOR + 0] = i%2;
          extseed[i*2 + KYBER_SYMBYTES * KECCAK_PARALLEL_FACTOR + 1] = i/2;
      }
  }

  int p = 0x1F; 

  for (int i = 0; i < KECCAK_PARALLEL_FACTOR * 25; i++)
  {
    state->s[i] = 0;
  }
  
  int i = 0; 
  int rem = 0;
  rem = SHA3_Absorb_hybrid((uint64_t (*))state->s, extseed, (KYBER_SYMBYTES + 2), SHAKE128_RATE, 4);

      // TODO:: Can do better here 
      // (rem/KECCAK_PARALLEL_FACTOR)*KECCAK_PARALLEL_FACTOR) to round down the rem
      for(i=0; i<KECCAK_PARALLEL_FACTOR*((rem/KECCAK_PARALLEL_FACTOR)*KECCAK_PARALLEL_FACTOR); i++) {
        state->s[i/8] ^= (uint64_t)extseed[i + (KYBER_SYMBYTES + 2) - rem] << 8*(i%8);
      }

      for (int j = 0; j < 8; j++) {
        state->s[(j/2) + i/8     ] ^= (uint64_t)extseed[i + (KYBER_SYMBYTES + 2) - rem + j ] << 8*(j%2);
      }

      for (int j = 0; j < 4; j++) {
        state->s[(j) + i/8] ^= (uint64_t)p << 8*((i+2)%8);
        state->s[(SHAKE128_RATE-1)*4/8 - 3 + j ] ^= 1ULL << 63;
      }
}
#endif

void kyber_shake128_squeeze(uint8_t *out, int nblocks, keccak_state *state)
{
   KeccakF1600((uint64_t (*)[SHA3_ROWS])state->s);   
   SHA3_Squeeze((uint64_t (*)[SHA3_ROWS])state->s, out, (nblocks) * SHAKE128_RATE , SHAKE128_RATE);
}

void kyber_shake128_squeeze_x4_hybrid(uint8_t *out, int nblocks, keccak_state_x4_hybrid *state)
{
   keccak_f1600_x4_hybrid_asm_v5p_opt((uint64_t *)state->s);
   SHA3_Squeeze_hybrid((uint64_t *)state->s, out, (nblocks) * SHAKE128_RATE  , SHAKE128_RATE, 4);
}

void kyber_shake128_squeeze_x3_hybrid(uint8_t *out, int nblocks, keccak_state_x3_hybrid *state)
{
   keccak_f1600_x3_hybrid_asm_v6((uint64_t *)state->s);
   SHA3_Squeeze_hybrid((uint64_t *)state->s, out, (nblocks) * SHAKE128_RATE  , SHAKE128_RATE, 3);
}

void kyber_shake128_squeeze_x2_hybrid(uint8_t *out, int nblocks, keccak_state_x2_hybrid *state)
{
   keccak_f1600_x2_v84a_asm_v2pp2((uint64_t *)state->s);
   SHA3_Squeeze_hybrid((uint64_t *)state->s, out, (nblocks) * SHAKE128_RATE  , SHAKE128_RATE, 2);
}

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

  //#ifndef EXPERIMENTAL_AWS_LC_HYBRID_KECCAK
  //shake256(out, outlen, extkey, sizeof(extkey));
  //#else
  SHAKE256(extkey, sizeof(extkey), out, outlen*8);
  //#endif
}

/*************************************************
 * Name:        kyber_shake256_prf_hybrid
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
void kyber_shake256_prf_hybrid(uint8_t *out, size_t outlen,
                        const uint8_t key[KYBER_SYMBYTES], uint8_t nonce, uint8_t par_fac) {

  uint8_t extkey[KYBER_SYMBYTES + 1];

  memcpy(extkey, key, KYBER_SYMBYTES);
  extkey[KYBER_SYMBYTES] = nonce;

  #ifndef EXPERIMENTAL_AWS_LC_HYBRID_KECCAK
  shake256(out, outlen, extkey, sizeof(extkey));
  #else

  shake256_kyber(out, outlen, extkey, sizeof(extkey), par_fac);
  
  #endif
}

/*************************************************
* Name:        shake256
*
* Description: SHAKE256 XOF with non-incremental API
*
* Arguments:   - uint8_t *out: pointer to output
*              - size_t outlen: requested output length in bytes
*              - const uint8_t *in: pointer to input
*              - size_t inlen: length of input in bytes
**************************************************/
void shake256_kyber(uint8_t *out, size_t outlen, const uint8_t in[KYBER_SYMBYTES + 1], size_t inlen, uint8_t par_fac)
{
  keccak_state_x4_hybrid state;

  kyber_shake256_absorb_hybrid(&state, in, inlen, par_fac);

  if (par_fac == 4) {
    keccak_f1600_x4_hybrid_asm_v5p_opt((uint64_t *)(&state)->s);
  }else if (par_fac == 2) {
    keccak_f1600_x2_v84a_asm_v2pp2((uint64_t *)(&state)->s);
  }else if (par_fac == 3) {
    keccak_f1600_x3_hybrid_asm_v6((uint64_t *)(&state)->s);
  }
  SHA3_Squeeze_hybrid((uint64_t (*))(&state)->s, out, outlen , SHAKE256_RATE, par_fac);
}


/*************************************************
 * Name:        kyber_shake256_absorb_hybrid
 *
 * Description: Absorb step of the SHAKE256 specialized for the Kyber context with parallel x4 Keccakf1600.
 *
 * Arguments:   - keccak_state_x4_hybrid *state: pointer to hybrid (uninitialized) output 4 Keccak
 *state
 *              - const uint8_t *seed: pointer to KYBER_SYMBYTES input to be
 *absorbed into state
 *              - uint8_t i: additional byte of input
 *              - uint8_t j: additional byte of input
 **************************************************/
void kyber_shake256_absorb_hybrid(keccak_state_x4_hybrid *state,
                           const uint8_t in[KYBER_SYMBYTES + 1], size_t inlen, uint8_t par_fac) {

  // TODO:: Change with OPENSSL_malloc
  uint8_t *extseed = calloc(par_fac * (KYBER_SYMBYTES + 1), sizeof(uint8_t));

    for (int i = 0; i < par_fac; i++) {
        for (int j = 0, k = 0; j < par_fac * KYBER_SYMBYTES; j++, k++) {
            if (j % 8 == 0 && j != 0){
              j += (par_fac - 1) * 8;
            }if (j < par_fac * KYBER_SYMBYTES){
            extseed[8 * i + j] = in[k];
            }
        }
    }
    // TODO:: Can do better here  
  for (int i = 0; i < par_fac; i++)
  { 
      extseed[i + KYBER_SYMBYTES * par_fac ] = i + in[KYBER_SYMBYTES] ;
  }

  int p = 0x1F; 

  for (int i = 0; i < par_fac * 25; i++)
  {
    state->s[i] = 0;
  }
  
  int i = 0; 
  int rem = 0;
  rem = SHA3_Absorb_hybrid((uint64_t (*))state->s, extseed, (KYBER_SYMBYTES + 1), SHAKE256_RATE, par_fac);
  
      // TODO:: Can do better here 
      // (rem/par_fac)*par_fac) to round down the rem
      for(i=0; i<par_fac*((rem/8)*8); i++) {
        state->s[i/8] ^= (uint64_t)extseed[i + (KYBER_SYMBYTES + 1) - rem] << 8*(i%8);
      }

      for (int j = 0; j < par_fac; j++) {
        state->s[i/8 + j] ^= in[KYBER_SYMBYTES] + j;
      }
    
      for (int j = 0; j < par_fac; j++) {
        state->s[(j) + i/8] ^= (uint64_t)p << 8*((i+1)%8);
        state->s[(SHAKE256_RATE-1)*par_fac/8 - (par_fac - 1) + j ] ^= 1ULL << 63;
      }

      free(extseed);
}