#ifndef INDCPA_H
#define INDCPA_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

#define gen_matrix KYBER_NAMESPACE(gen_matrix)
void gen_matrix(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed);

// EXPERIMENTAL_AWS_LC_HYBRID_KECCAK gen_matrix_hybrid_KyberXXX using parallel Keccak versions
#ifdef EXPERIMENTAL_AWS_LC_HYBRID_KECCAK
#define gen_matrix_hybrid_Kyber512 KYBER_NAMESPACE(gen_matrix_hybrid_Kyber512)
void gen_matrix_hybrid_Kyber512(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed);
#define gen_matrix_hybrid_Kyber768 KYBER_NAMESPACE(gen_matrix_hybrid_Kyber768)
void gen_matrix_hybrid_Kyber768(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed);
#define gen_matrix_hybrid_Kyber1024 KYBER_NAMESPACE(gen_matrix_hybrid_Kyber1024)
void gen_matrix_hybrid_Kyber1024(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed);
#endif /* EXPERIMENTAL_AWS_LC_HYBRID_KECCAK */

#define indcpa_keypair KYBER_NAMESPACE(indcpa_keypair)
void indcpa_keypair(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);

#define indcpa_enc KYBER_NAMESPACE(indcpa_enc)
void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES]);

#define indcpa_dec KYBER_NAMESPACE(indcpa_dec)
void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);

#endif
