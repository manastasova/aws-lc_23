#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"

// EXPERIMENTAL
 #define EXPERIMENTAL_AWS_LC_HYBRID_KECCAK

#ifdef KYBER_90S

#include "aes256ctr.h"
#include "sha2.h"

#if (KYBER_SSBYTES != 32)
#error "90s variant of Kyber can only generate keys of length 256 bits"
#endif

typedef aes256ctr_ctx xof_state;

#define kyber_aes256xof_absorb KYBER_NAMESPACE(kyber_aes256xof_absorb)
void kyber_aes256xof_absorb(aes256ctr_ctx *state, const uint8_t seed[32],
                            uint8_t x, uint8_t y);

#define kyber_aes256ctr_prf KYBER_NAMESPACE(kyber_aes256ctr_prf)
void kyber_aes256ctr_prf(uint8_t *out, size_t outlen, const uint8_t key[32],
                         uint8_t nonce);

#define XOF_BLOCKBYTES AES256CTR_BLOCKBYTES

#define hash_h(OUT, IN, INBYTES) sha256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) kyber_aes256xof_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) \
  aes256ctr_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) \
  kyber_aes256ctr_prf(OUT, OUTBYTES, KEY, NONCE)
#define kdf(OUT, IN, INBYTES) sha256(OUT, IN, INBYTES)

#else

#ifdef EXPERIMENTAL_AWS_LC_HYBRID_KECCAK
#include "../../fipsmodule/sha/internal.h"
#endif

#include "fips202.h"

typedef keccak_state xof_state;
typedef keccak_state_x4_hybrid xof_state_x4_hybrid;

#define kyber_shake128_absorb KYBER_NAMESPACE(kyber_shake128_absorb)
void kyber_shake128_absorb(keccak_state *s, const uint8_t seed[KYBER_SYMBYTES],
                           uint8_t x, uint8_t y);

#define kyber_shake128_absorb_hybrid KYBER_NAMESPACE(kyber_shake128_absorb_hybrid)
void kyber_shake128_absorb_hybrid(keccak_state_x4_hybrid *state,
                           const uint8_t seed[KYBER_SYMBYTES], uint8_t transposed);

#define kyber_shake256_prf KYBER_NAMESPACE(kyber_shake256_prf)
void kyber_shake256_prf(uint8_t *out, size_t outlen,
                        const uint8_t key[KYBER_SYMBYTES], uint8_t nonce);
#ifdef EXPERIMENTAL_AWS_LC_HYBRID_KECCAK
#define kyber_shake128_squeeze KYBER_NAMESPACE(kyber_shake128_squeeze)
void kyber_shake128_squeeze(uint8_t *out, int nblocks, keccak_state *state);
#define kyber_shake128_squeeze_x4_hybrid KYBER_NAMESPACE(kyber_shake128_squeeze_x4_hybrid)
void kyber_shake128_squeeze_x4_hybrid(uint8_t *out, int nblocks, keccak_state_x4_hybrid *state);
#endif
#define XOF_BLOCKBYTES SHAKE128_RATE

  // EXPERIMENTAL
#ifndef EXPERIMENTAL_AWS_LC_HYBRID_KECCAK
#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)

#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) \
  shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define xof_absorb(STATE, SEED, X, Y) kyber_shake128_absorb(STATE, SEED, X, Y)



#define prf(OUT, OUTBYTES, KEY, NONCE) \
  kyber_shake256_prf(OUT, OUTBYTES, KEY, NONCE)
#define kdf(OUT, IN, INBYTES) shake256(OUT, KYBER_SSBYTES, IN, INBYTES)
  
#else
#define kyber_shake128_absorb KYBER_NAMESPACE(kyber_shake128_absorb)
void kyber_shake128_absorb(keccak_state *s, const uint8_t seed[KYBER_SYMBYTES],
                           uint8_t x, uint8_t y);
#define xof_absorb(STATE, SEED, X, Y) kyber_shake128_absorb(STATE, SEED, X, Y)

// TODO:: Define constant for parallel factor
#define KECCAK_PARALLEL_FACTOR 4
#define hash_h(OUT, IN, INBYTES) SHA3_256(IN, INBYTES, OUT)
#define hash_g(OUT, IN, INBYTES) SHA3_512(IN, INBYTES, OUT)
//#define xof_absorb(STATE, SEED, X, Y) kyber_shake128_absorb(STATE, SEED, X, Y)
#define xof_absorb_x4_hybrid(STATE, SEED, T) kyber_shake128_absorb_hybrid(STATE, SEED, T)
#define xof_squeezeblocks_x4_hybrid(OUT, OUTBLOCKS, STATE) \
  kyber_shake128_squeeze_x4_hybrid(OUT, OUTBLOCKS, STATE)

#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) \
  kyber_shake128_squeeze(OUT, OUTBLOCKS, STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) \
  kyber_shake256_prf(OUT, OUTBYTES, KEY, NONCE)
#define kdf(OUT, IN, INBYTES) SHAKE256(IN, INBYTES, OUT, KYBER_SSBYTES*8)
  
#endif
#endif /* KYBER_90S */

#endif /* SYMMETRIC_H */
