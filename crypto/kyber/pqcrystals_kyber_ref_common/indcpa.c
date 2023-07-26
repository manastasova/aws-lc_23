#include "indcpa.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "ntt.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "symmetric.h"
#include "../../rand_extra/pq_custom_randombytes.h"

/*************************************************
* Name:        pack_pk
*
* Description: Serialize the public key as concatenation of the
*              serialized vector of polynomials pk
*              and the public seed used to generate the matrix A.
*
* Arguments:   uint8_t *r: pointer to the output serialized public key
*              polyvec *pk: pointer to the input public-key polyvec
*              const uint8_t *seed: pointer to the input public seed
**************************************************/
static void pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES],
                    polyvec *pk,
                    const uint8_t seed[KYBER_SYMBYTES])
{
  size_t i;
  polyvec_tobytes(r, pk);
  for(i=0;i<KYBER_SYMBYTES;i++)
    r[i+KYBER_POLYVECBYTES] = seed[i];
}

/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize public key from a byte array;
*              approximate inverse of pack_pk
*
* Arguments:   - polyvec *pk: pointer to output public-key polynomial vector
*              - uint8_t *seed: pointer to output seed to generate matrix A
*              - const uint8_t *packedpk: pointer to input serialized public key
**************************************************/
static void unpack_pk(polyvec *pk,
                      uint8_t seed[KYBER_SYMBYTES],
                      const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES])
{
  size_t i;
  polyvec_frombytes(pk, packedpk);
  for(i=0;i<KYBER_SYMBYTES;i++)
    seed[i] = packedpk[i+KYBER_POLYVECBYTES];
}

/*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key
*
* Arguments:   - uint8_t *r: pointer to output serialized secret key
*              - polyvec *sk: pointer to input vector of polynomials (secret key)
**************************************************/
static void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk)
{
  polyvec_tobytes(r, sk);
}

/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key; inverse of pack_sk
*
* Arguments:   - polyvec *sk: pointer to output vector of polynomials (secret key)
*              - const uint8_t *packedsk: pointer to input serialized secret key
**************************************************/
static void unpack_sk(polyvec *sk, const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES])
{
  polyvec_frombytes(sk, packedsk);
}

/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v
*
* Arguments:   uint8_t *r: pointer to the output serialized ciphertext
*              poly *pk: pointer to the input vector of polynomials b
*              poly *v: pointer to the input polynomial v
**************************************************/
static void pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES], polyvec *b, poly *v)
{
  polyvec_compress(r, b);
  poly_compress(r+KYBER_POLYVECCOMPRESSEDBYTES, v);
}

/*************************************************
* Name:        unpack_ciphertext
*
* Description: De-serialize and decompress ciphertext from a byte array;
*              approximate inverse of pack_ciphertext
*
* Arguments:   - polyvec *b: pointer to the output vector of polynomials b
*              - poly *v: pointer to the output polynomial v
*              - const uint8_t *c: pointer to the input serialized ciphertext
**************************************************/
static void unpack_ciphertext(polyvec *b, poly *v, const uint8_t c[KYBER_INDCPA_BYTES])
{
  polyvec_decompress(b, c);
  poly_decompress(v, c+KYBER_POLYVECCOMPRESSEDBYTES);
}

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r: pointer to output buffer
*              - unsigned int len: requested number of 16-bit integers (uniform mod q)
*              - const uint8_t *buf: pointer to input buffer (assumed to be uniformly random bytes)
*              - unsigned int buflen: length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
  unsigned int ctr, pos;
  uint16_t val0, val1;

  ctr = pos = 0;
  while(ctr < len && pos + 3 <= buflen) {
    val0 = ((buf[pos+0] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
    val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
    pos += 3;

    if(val0 < KYBER_Q)
      r[ctr++] = val0;
    if(ctr < len && val1 < KYBER_Q)
      r[ctr++] = val1;
  }

  return ctr;
}

#define GEN_MATRIX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)
/*************************************************
* Name:        gen_matrix
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              a XOF
*
* Arguments:   - polyvec *a: pointer to ouptput matrix A
*              - const uint8_t *seed: pointer to input seed
*              - int transposed: boolean deciding whether A or A^T is generated
**************************************************/
#define gen_a(A,B)  gen_matrix(A,B,0)
#define gen_at(A,B) gen_matrix(A,B,1)
// Not static for benchmarking
void gen_matrix(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed)
{
  unsigned int ctr, i, j, k;
  unsigned int buflen, off;

  uint8_t buf[GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES+2];
  xof_state state;

  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_K;j++) {
      if(transposed)
        xof_absorb(&state, seed, i, j);
      else
        xof_absorb(&state, seed, j, i);

      xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);

      buflen = GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES;
      ctr = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, buflen);

      while(ctr < KYBER_N) {
        off = buflen % 3;
        for(k = 0; k < off; k++)
          buf[k] = buf[buflen - off + k];
        xof_squeezeblocks(buf + off, 1, &state);
        buflen = off + XOF_BLOCKBYTES;
        ctr += rej_uniform(a[i].vec[j].coeffs + ctr, KYBER_N - ctr, buf, buflen);
      }
    }
  }
}

#ifdef EXPERIMENTAL_AWS_LC_HYBRID_KECCAK
/*************************************************
* Name:        gen_matrix_hybrid_Kyber512
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed for Kyber512. Entries of the matrix are polynomials 
*              that look uniformly random. Performs rejection sampling on
*              output of a XOF
*
* Arguments:   - polyvec *a: pointer to ouptput matrix A
*              - const uint8_t *seed: pointer to input seed
*              - int transposed: boolean deciding whether A or A^T is generated
**************************************************/
#define gen_a_hybrid_Kyber512(A,B)  gen_matrix_hybrid_Kyber512(A,B,0)
#define gen_at_hybrid_Kyber512(A,B) gen_matrix_hybrid_Kyber512(A,B,1)
// Not static for benchmarking
void gen_matrix_hybrid_Kyber512(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed)
{
  if (KYBER_K != 2) {
    return;
  }
  unsigned int ctr[4], ctr_total, i, j, k;
  unsigned int buflen, off;
  xof_state_x4_hybrid state_hybrid;
  uint8_t buf[(KYBER_K * KYBER_K)*(GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES+2)];

        xof_absorb_x4_hybrid(&state_hybrid, seed, transposed, 0, 4);
        xof_squeezeblocks_x4_hybrid(buf, GEN_MATRIX_NBLOCKS, &state_hybrid);
      
        ctr_total = 0;
        buflen = GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES;

          for(i = 0; i < KYBER_K ;i++) {
            for(j = 0; j < KYBER_K ;j++) {
              ctr[i*2+j] = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf + ((i*2+j)*buflen) , buflen);
              ctr_total += ctr[i*2+j];
            }
          }
            
          while(ctr_total < KYBER_K * KYBER_K * KYBER_N) { // KYBER_K * KYBER_K only for Kyber512 since x4 Keccak 
            off = buflen % 3;
            for(k = 0; k < off; k++) {
              for(i = 0; i < KYBER_K; i++) {
                for(j = 0 ; j < KYBER_K ; j++) {
                  (buf + ((i*KYBER_K+j)*buflen))[k] = (buf + ((i*KYBER_K+j)*buflen))[buflen - off + k];
                }
              }
            }
            xof_squeezeblocks_x4_hybrid(buf + off, 1, &state_hybrid);
            buflen = off + XOF_BLOCKBYTES;
            for(i=0;i<KYBER_K;i++) {
              for(j=0;j<KYBER_K;j++) {
                if (ctr[i*KYBER_K+j] < KYBER_N) {
                  ctr[i*KYBER_K+j] += rej_uniform(a[i].vec[j].coeffs + ctr[i*KYBER_K+j], KYBER_N - ctr[i*KYBER_K+j], buf + ((i*KYBER_K+j)*buflen), buflen);
                  ctr_total += ctr[i*KYBER_K+j];
                }
              }
            }
          }
}

/*************************************************
* Name:        gen_matrix_hybrid_Kyber768
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed for Kyber768. Entries of the matrix are polynomials 
*              that look uniformly random. Performs rejection sampling on
*              output of a XOF
*
* Arguments:   - polyvec *a: pointer to ouptput matrix A
*              - const uint8_t *seed: pointer to input seed
*              - int transposed: boolean deciding whether A or A^T is generated
**************************************************/
#define gen_a_hybrid_Kyber768(A,B)  gen_matrix_hybrid_Kyber768(A,B,0)
#define gen_at_hybrid_Kyber768(A,B) gen_matrix_hybrid_Kyber768(A,B,1)
// Not static for benchmarking
void gen_matrix_hybrid_Kyber768(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed)
{
  if (KYBER_K != 3) {
    return;
  }
    
  unsigned int ctr[3], ctr_total, i, j, k;
  unsigned int buflen, off;
  xof_state_x4_hybrid state_hybrid;
  uint8_t buf[KYBER_K*(GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES+2)];

  for(i=0;i<KYBER_K;i++) {
      ctr_total = 0;

      xof_absorb_x3_hybrid(&state_hybrid, seed, transposed, i, 3);
      xof_squeezeblocks_x3_hybrid(buf, GEN_MATRIX_NBLOCKS, (xof_state_x3_hybrid *)&state_hybrid);

      buflen = GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES;
      for(j = 0; j < KYBER_K ;j++) {
        ctr[j] = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf + (j*buflen), buflen);
        ctr_total += ctr[j];
      }

      while(ctr_total < KYBER_K * KYBER_N) {
      off = buflen % 3;
      for(k = 0; k < off; k++) {
        for(j = 0 ; j < KYBER_K ; j++) {
          (buf + (j*buflen))[k] = (buf + (j*buflen))[buflen - off + k];
        }
      }

      xof_squeezeblocks_x3_hybrid(buf + off, 1, (xof_state_x3_hybrid *)&state_hybrid);
      buflen = off + XOF_BLOCKBYTES;
      for(j=0;j<KYBER_K;j++) {
        if (ctr[j] < KYBER_N) {
          ctr[j] += rej_uniform(a[i].vec[j].coeffs + ctr[j], KYBER_N - ctr[j], buf + (j*buflen), buflen);
          ctr_total += ctr[j];
        }
      }
    }
  }
}

/*************************************************
* Name:        gen_matrix_hybrid_Kyber1024
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed for Kyber1024. Entries of the matrix are polynomials 
*              that look uniformly random. Performs rejection sampling on
*              output of a XOF
*
* Arguments:   - polyvec *a: pointer to ouptput matrix A
*              - const uint8_t *seed: pointer to input seed
*              - int transposed: boolean deciding whether A or A^T is generated
**************************************************/
#define gen_a_hybrid_Kyber1024(A,B)  gen_matrix_hybrid_Kyber1024(A,B,0)
#define gen_at_hybrid_Kyber1024(A,B) gen_matrix_hybrid_Kyber1024(A,B,1)
// Not static for benchmarking
void gen_matrix_hybrid_Kyber1024(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed)
{
  if (KYBER_K != 4) {
    return;
  }
    
  unsigned int ctr[4], ctr_total, i, j, k;
  unsigned int buflen, off;
  xof_state_x4_hybrid state_hybrid;
  uint8_t buf[KYBER_K*(GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES+2)];

  for(i=0;i<KYBER_K;i++) {
      ctr_total = 0;

      xof_absorb_x4_hybrid(&state_hybrid, seed, transposed, i, 4);
      xof_squeezeblocks_x4_hybrid(buf, GEN_MATRIX_NBLOCKS, &state_hybrid);

      buflen = GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES;
      for(j = 0; j < KYBER_K ;j++) {
        ctr[j] = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf + (j*buflen), buflen);
        ctr_total += ctr[j];
      }


      while(ctr_total < KYBER_K * KYBER_N) {
        off = buflen % 3;
        for(k = 0; k < off; k++) {
          for(j = 0 ; j < KYBER_K ; j++) {
            (buf + (j*buflen))[k] = (buf + (j*buflen))[buflen - off + k];
          }
        }
      xof_squeezeblocks_x4_hybrid(buf + off, 1, &state_hybrid);
      buflen = off + XOF_BLOCKBYTES;
      for(j=0;j<KYBER_K;j++) {
        if (ctr[j] < KYBER_N) {
          ctr[j] += rej_uniform(a[i].vec[j].coeffs + ctr[j], KYBER_N - ctr[j], buf + (j*buflen), buflen);
          ctr_total += ctr[j];
        }
      }
    }
  }
}
#endif /* EXPERIMENTAL_AWS_LC_HYBRID_KECCAK */

/*************************************************
* Name:        indcpa_keypair
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                             (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
                              (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
**************************************************/
void indcpa_keypair(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES])
{
  unsigned int i;
  uint8_t buf[2*KYBER_SYMBYTES];
  const uint8_t *publicseed = buf;
  const uint8_t *noiseseed = buf+KYBER_SYMBYTES;
  uint8_t nonce = 0;
  polyvec a[KYBER_K], e, pkpv, skpv;

  pq_custom_randombytes(buf, KYBER_SYMBYTES);
  hash_g(buf, buf, KYBER_SYMBYTES);

  #ifdef EXPERIMENTAL_AWS_LC_HYBRID_KECCAK
  if(KYBER_K == 2) { // Kyber512
    gen_a_hybrid_Kyber512(a, publicseed);
    poly_getnoise_eta1_x4_hybrid(&skpv.vec[0], &skpv.vec[1], &e.vec[0], &e.vec[1], noiseseed, nonce);
  }
  if (KYBER_K == 3) { // Kyber768
    #ifdef KECCAK_X4_ONLY
    
    #else
    gen_a_hybrid_Kyber768(a, publicseed);
    poly_getnoise_eta1_x3_hybrid(&skpv.vec[0], &skpv.vec[1], &skpv.vec[2], noiseseed, nonce);
    nonce+=KYBER_K;
    poly_getnoise_eta1_x3_hybrid(&e.vec[0], &e.vec[1], &e.vec[2], noiseseed, nonce);
    #endif /* KECCAK_X4_ONLY */
  }
  if (KYBER_K == 4) { // Kyber1024
    gen_a_hybrid_Kyber1024(a, publicseed);
    poly_getnoise_eta1_x4_hybrid(&skpv.vec[0], &skpv.vec[1], &skpv.vec[2], &skpv.vec[3], noiseseed, nonce);
    nonce+=KYBER_K;
    poly_getnoise_eta1_x4_hybrid(&e.vec[0], &e.vec[1], &e.vec[2], &e.vec[3], noiseseed, nonce);
  }
  #else
  gen_a(a, publicseed);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);
  #endif /* EXPERIMENTAL_AWS_LC_HYBRID_KECCAK */

  polyvec_ntt(&skpv);
  polyvec_ntt(&e);

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++) {
    polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
    poly_tomont(&pkpv.vec[i]);
  }

  polyvec_add(&pkpv, &pkpv, &e);
  polyvec_reduce(&pkpv);

  pack_sk(sk, &skpv);
  pack_pk(pk, &pkpv, publicseed);
}

/*************************************************
* Name:        indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *c: pointer to output ciphertext
*                            (of length KYBER_INDCPA_BYTES bytes)
*              - const uint8_t *m: pointer to input message
*                                  (of length KYBER_INDCPA_MSGBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                                   (of length KYBER_INDCPA_PUBLICKEYBYTES)
*              - const uint8_t *coins: pointer to input random coins used as seed
*                                      (of length KYBER_SYMBYTES) to deterministically
*                                      generate all randomness
**************************************************/
void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES])
{
  unsigned int i;
  uint8_t seed[KYBER_SYMBYTES];
  uint8_t nonce = 0;
  polyvec sp, pkpv, ep, at[KYBER_K], b;
  poly v, k, epp;

  unpack_pk(&pkpv, seed, pk);
  poly_frommsg(&k, m);

  #ifdef EXPERIMENTAL_AWS_LC_HYBRID_KECCAK
  if(KYBER_K == 2) {
  gen_at_hybrid_Kyber512(at, seed);
  // NOTE:: Option 1 in Quip Design Doc
  // poly_getnoise_eta1_eta2_x4_hybrid(sp.vec+0, sp.vec+1, ep.vec+0, ep.vec+1, coins, nonce);
  // nonce+=4;
  // poly_getnoise_eta2(&epp, coins, nonce++);
  // NOTE:: Option 2 in Quip Design Doc
  poly_getnoise_eta1_x2_hybrid(sp.vec+0, sp.vec+1, coins, nonce);
  nonce += KYBER_K;
  poly_getnoise_eta2_x3_hybrid(ep.vec+0, ep.vec+1, &epp, coins, nonce);
  }
  if(KYBER_K == 3) {
      gen_at_hybrid_Kyber768(at, seed);
      poly_getnoise_eta1_x3_hybrid(sp.vec+0, sp.vec+1, sp.vec+2, coins, nonce);
      nonce+=KYBER_K;
      poly_getnoise_eta2_x3_hybrid(ep.vec+0, ep.vec+1, ep.vec+2, coins, nonce);
      nonce+=KYBER_K;
  poly_getnoise_eta2(&epp, coins, nonce++);
  }
  if(KYBER_K == 4) {
      gen_at_hybrid_Kyber1024(at, seed);
      poly_getnoise_eta1_x4_hybrid(sp.vec+0, sp.vec+1, sp.vec+2, sp.vec+3, coins, nonce);
      nonce+=KYBER_K;
      poly_getnoise_eta2_x4_hybrid(ep.vec+0, ep.vec+1,ep.vec+2,ep.vec+3,coins, nonce);
      nonce+=KYBER_K;
  poly_getnoise_eta2(&epp, coins, nonce++);
  }
  #else
  gen_at(at, seed);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(sp.vec+i, coins, nonce++);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta2(ep.vec+i, coins, nonce++);
  poly_getnoise_eta2(&epp, coins, nonce++);
  #endif /* EXPERIMENTAL_AWS_LC_HYBRID_KECCAK */

  polyvec_ntt(&sp);

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++)
    polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);

  polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);

  polyvec_invntt_tomont(&b);
  poly_invntt_tomont(&v);

  polyvec_add(&b, &b, &ep);
  poly_add(&v, &v, &epp);
  poly_add(&v, &v, &k);
  polyvec_reduce(&b);
  poly_reduce(&v);

  pack_ciphertext(c, &b, &v);
}

/*************************************************
* Name:        indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *m: pointer to output decrypted message
*                            (of length KYBER_INDCPA_MSGBYTES)
*              - const uint8_t *c: pointer to input ciphertext
*                                  (of length KYBER_INDCPA_BYTES)
*              - const uint8_t *sk: pointer to input secret key
*                                   (of length KYBER_INDCPA_SECRETKEYBYTES)
**************************************************/
void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES])
{
  polyvec b, skpv;
  poly v, mp;

  unpack_ciphertext(&b, &v, c);
  unpack_sk(&skpv, sk);

  polyvec_ntt(&b);
  polyvec_basemul_acc_montgomery(&mp, &skpv, &b);
  poly_invntt_tomont(&mp);

  poly_sub(&mp, &v, &mp);
  poly_reduce(&mp);

  poly_tomsg(m, &mp);
}
