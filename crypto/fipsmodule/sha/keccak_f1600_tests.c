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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "keccak_f1600_tests.h"
#include "keccak_f1600_variants.h"

// Add some functions from hal here.. TODO:: Remove later
#define FILENO stderr
#define ALIGN(x) __attribute__((aligned(x)))

void debug_printf(const char * format, ... )
{
    va_list argp;
    va_start( argp, format );
    vfprintf( FILENO, format, argp );
    va_end( argp );
}

int compare_buf_u8 ( uint8_t const *src_a, uint8_t const *src_b, unsigned len )                             \
 {                                                                    
     uint8_t res = 0;                                               
     for( ; len; src_a++, src_b++, len-- )                             
         res |= ( (*src_a) ^ (*src_b) );                               
     return( res );                                                    
 }

 void fill_random_u8 ( uint8_t *buf, unsigned int len )    
 {                                                                     
     unsigned byte_len = len * sizeof(*buf);                           
     uint8_t *byte_buf = (uint8_t*) buf;                               
     for( ; byte_len; byte_buf++, byte_len-- )                         
     {                                                                 
         uint8_t cur_byte;                                             
         cur_byte = rand();                                 
         *byte_buf = cur_byte;                                        
     }                                                                 
 }

 void debug_print_buf_u8 ( uint8_t const *buf,               
                            unsigned entries,                          
                            const char *prefix )                       
 {                                                                     
     unsigned idx;                                                     
     for( idx = 0; idx < entries; idx += 8 )                           
     {                                                                 
         debug_printf( "%s [%#04x-%#04x]: %#04x %#04x %#04x %#04x %#04x %#04x %#04x %#04x\n",        
                       prefix, idx, idx+8,                             
                       buf[idx+0], buf[idx+1], buf[idx+2], buf[idx+3], 
                       buf[idx+4], buf[idx+5], buf[idx+6], buf[idx+7] ); 
     }                                                                 
 }

void debug_test_start( const char *testname )
{
    fprintf( FILENO, "%s ... ", testname );
    fflush( FILENO );
}

void debug_test_ok(void)   { printf( "Ok\n"    ); }
void debug_test_fail(void) { printf( "FAIL!\n" ); }
// End some functions from hal here.. TODO:: Remove later

int cmp_uint64_t(const void *a, const void *b)
{
    return (int)((*((const uint64_t *)a)) - (*((const uint64_t *)b)));
}


void zip_f1600_states_real( int num, uint64_t *dst, uint64_t const  *src )
{
    for( int i=0; i < KECCAK_F1600_X1_STATE_SIZE_UINT64; i++ )
        for( int j=0; j<num; j++ )
            dst[num*i+j] = src[j*KECCAK_F1600_X1_STATE_SIZE_UINT64+i];
}

void zip_f1600_states( int num, uint64_t *dst, uint64_t const  *src )
{
    if( num == 1 || num == 2 || num == 4 )
    {
        zip_f1600_states_real( num, dst, src );
    }
    else
    {
        zip_f1600_states_real( 2, dst, src );

        if( num > 2 )
        {
            dst += 2 * KECCAK_F1600_X1_STATE_SIZE_UINT64;
            src += 2 * KECCAK_F1600_X1_STATE_SIZE_UINT64;
            memcpy( dst, src, ( num - 2 ) * KECCAK_F1600_X1_STATE_SIZE_BYTES );
        }
    }
}

#define stringify(x) stringify_(x)
#define stringify_(x) #x

#define MAKE_VALIDATE_F1600_X_GENERIC(testname,funcname,NUM)            \
    MAKE_VALIDATE_F1600_X_GENERIC_DO(testname,funcname,NUM)


int validate_keccak_f1600_x4_hybrid_asm_v5p(void)                                                     
{                                                                       
    debug_test_start(stringify(validate_keccak_f1600_x4_hybrid_asm_v5p));                            
                                                                        
    ALIGN(64)                                                           
    uint64_t state[4*KECCAK_F1600_X1_STATE_SIZE_UINT64] = { 0 };      
    ALIGN(64)                                                           
    uint64_t ref_state[4*KECCAK_F1600_X1_STATE_SIZE_UINT64] = { 0 };  
    ALIGN(64)                                                           
    uint64_t ref_state_[4*KECCAK_F1600_X1_STATE_SIZE_UINT64] = { 0 }; 
                                                                        
    fill_random_u8( (uint8_t*) ref_state, KECCAK_F1600_X1_STATE_SIZE_BYTES ); 
    for( int i=1; i < 4; i++ )                                        
    memcpy( (uint8_t*) &ref_state[i*KECCAK_F1600_X1_STATE_SIZE_UINT64],   
            (uint8_t*) &ref_state[0*KECCAK_F1600_X1_STATE_SIZE_UINT64], 
            KECCAK_F1600_X1_STATE_SIZE_BYTES );                         
                                                                        
    zip_f1600_states( 4, state, ref_state );                          
                                                                        
    keccak_f1600_x4_hybrid_asm_v5p( state );                                                  
                                                                        
    for( int i=0; i<4; i++ )                                          
    {                                                                   
        keccak_f1600_x1_scalar_C( ref_state +                           
                               i * KECCAK_F1600_X1_STATE_SIZE_UINT64 ); 
    }                                                                   
                                                                        
    zip_f1600_states( 4, ref_state_, ref_state );                     
                                                                        
    if( compare_buf_u8( (uint8_t*) state, (uint8_t*) ref_state_,        
                        4 * KECCAK_F1600_X1_STATE_SIZE_BYTES ) != 0 ) 
    {                                                                   
        debug_print_buf_u8( (uint8_t*) ref_state_,                      
                            4 * KECCAK_F1600_X1_STATE_SIZE_BYTES,     
                            "Reference" );                              
        debug_print_buf_u8( (uint8_t*) state,                           
                            4 * KECCAK_F1600_X1_STATE_SIZE_BYTES,     
                            "Actual" );                                 
        debug_test_fail();                                              
    }                                                                   
                                                                        
    debug_test_ok();                                                    
    return 1;                                                           
}

int validate_keccak_f1600_x4_hybrid_asm_v5p_new(void)                                                     
{                                                                       
    debug_test_start(stringify(validate_keccak_f1600_x4_hybrid_asm_v5p_new));                            
                                                                        
    ALIGN(64)                                                           
    uint64_t state[4*KECCAK_F1600_X1_STATE_SIZE_UINT64] = { 0 };      
    ALIGN(64)                                                           
    uint64_t ref_state[4*KECCAK_F1600_X1_STATE_SIZE_UINT64] = { 0 };  
    ALIGN(64)                                                           
    uint64_t ref_state_[4*KECCAK_F1600_X1_STATE_SIZE_UINT64] = { 0 }; 
                                                                        
    fill_random_u8( (uint8_t*) ref_state, KECCAK_F1600_X1_STATE_SIZE_BYTES ); 
    for( int i=1; i < 4; i++ )                                        
    memcpy( (uint8_t*) &ref_state[i*KECCAK_F1600_X1_STATE_SIZE_UINT64],   
            (uint8_t*) &ref_state[0*KECCAK_F1600_X1_STATE_SIZE_UINT64], 
            KECCAK_F1600_X1_STATE_SIZE_BYTES );                         
                                                                        
    zip_f1600_states( 4, state, ref_state );                          
                                                                        
    keccak_f1600_x4_hybrid_asm_v5p_new( state );                                                  
                                                                        
    for( int i=0; i<4; i++ )                                          
    {                                                                   
        keccak_f1600_x1_scalar_C( ref_state +                           
                               i * KECCAK_F1600_X1_STATE_SIZE_UINT64 ); 
    }                                                                   
                                                                        
    zip_f1600_states( 4, ref_state_, ref_state );                     
                                                                        
    if( compare_buf_u8( (uint8_t*) state, (uint8_t*) ref_state_,        
                        4 * KECCAK_F1600_X1_STATE_SIZE_BYTES ) != 0 ) 
    {                                                                   
        debug_print_buf_u8( (uint8_t*) ref_state_,                      
                            4 * KECCAK_F1600_X1_STATE_SIZE_BYTES,     
                            "Reference" );                              
        debug_print_buf_u8( (uint8_t*) state,                           
                            4 * KECCAK_F1600_X1_STATE_SIZE_BYTES,     
                            "Actual" );                                 
        debug_test_fail();                                              
    }                                                                   
                                                                        
    debug_test_ok();                                                    
    return 1;                                                           
}

#define MAKE_VALIDATE_F1600_X_GENERIC_SKIP(testname,funcname,NUM)       \
int testname (void)                                                     \
{                                                                       \
    debug_test_start( stringify(testname) );                            \
    debug_printf( "skip\n" );                                           \
    return( 0 );                                                        \
}

#if defined(__ARM_FEATURE_SHA3)
#define MAKE_VALIDATE_F1600_X_GENERIC_V84A(testname,funcname,NUM)       \
    MAKE_VALIDATE_F1600_X_GENERIC_DO(testname,funcname,NUM)
#else
#define MAKE_VALIDATE_F1600_X_GENERIC_V84A(testname,funcname,NUM)       \
    MAKE_VALIDATE_F1600_X_GENERIC_SKIP(testname,funcname,NUM)
#endif

#if defined(__ARM_FEATURE_SVE2)
#define MAKE_VALIDATE_F1600_X_GENERIC_V9A(testname,funcname,NUM)       \
    MAKE_VALIDATE_F1600_X_GENERIC_DO(testname,funcname,NUM)
#else
#define MAKE_VALIDATE_F1600_X_GENERIC_V9A(testname,funcname,NUM)       \
    MAKE_VALIDATE_F1600_X_GENERIC_SKIP(testname,funcname,NUM)
#endif

#define MAKE_VALIDATE_F1600_X_GENERIC(testname,funcname,NUM)            \
    MAKE_VALIDATE_F1600_X_GENERIC_DO(testname,funcname,NUM)

#define KECCAK_F1600_X1_FUNCNAME(variant) keccak_f1600_x1_ ## variant
#define KECCAK_F1600_X1_TESTNAME(variant) validate_keccak_f1600_x1_ ## variant
#define MAKE_VALIDATE_F1600_X1(variant)                                    \
    MAKE_VALIDATE_F1600_X_GENERIC_DO(KECCAK_F1600_X1_TESTNAME(variant),    \
                                  KECCAK_F1600_X1_FUNCNAME(variant),1)

/////////////////////////////// TEST CASES ////////////////////////////////////