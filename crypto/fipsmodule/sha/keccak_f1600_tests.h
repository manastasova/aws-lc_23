/*
 * Copyright (c) 2021-2022 Arm Limited
 * Copyright (c) 2022 Matthias Kannwischer
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

//
// Author: Hanno Becker <hanno.becker@arm.com>
// Author: Matthias Kannwischer <matthias@kannwischer.eu>
//

#ifndef KECCAK_F1600_X2_TEST_H
#define KECCAK_F1600_X2_TEST_H

#define TEST_WARMUP     1000
#define TEST_ITERATIONS 100
#define TEST_AVG_CNT    100

// #define KECCAK_F1600_TEST_HAVE_SHA3_EXTENSION
#define ALIGN(x) __attribute__((aligned(x)))
#define stringify(x) stringify_(x)
#define stringify_(x) #x

// Function Prototypes
void zip_f1600_states_real(int num, uint64_t *dst, uint64_t const  *src);
void zip_f1600_states( int num, uint64_t *dst, uint64_t const  *src );
int cmp_uint64_t(const void *a, const void *b);

/* Fill a buffer with random data. */
void fill_random_u8 ( uint8_t  *buf, unsigned len );
/* Compare buffers
 * Same semantics as memcmp(), but we want to rely on stdlib
 * as little as possible. */
int compare_buf_u8 ( uint8_t  const *src_a, uint8_t  const *src_b, unsigned len );
/* Buffer printing helper */
void debug_print_buf_u8 ( uint8_t  const *buf, unsigned entries, const char *prefix );
#endif /* KECCAK_F1600_X2_TEST_H */
