//
//  cipher_des.h
//  DESCBC
//

#ifndef CIPHER_DES_H
#define CIPHER_DES_H

#include <cstdlib>
#include <cstdint>
#include <iostream>
#include "cipher_params.h"

using namespace std;

/*
DES Encryption
function DESEncrypt(K,M) // K=56 bits1, M=64 bits {
 1. InitialPermutation(M); // Call this IP
 2. Generate K1...K16, each of 56 bits; // Subkeys
 3. Permute K1...K16 to 48 bits;
 4.
 for(i=1;i<17;i++) // Now substitution starts
  {
  LEi = REi-1;
  REi = LEi-1 XOR F(Ki,REi-1);
  }

  5. swap(LE16,RE16);
  6. C = IP-1(LE16||RE16); // Reverse IP
   return C // C=64 bits;
}
*/

uint64_t permute(const char *table, uint8_t table_len, uint64_t input, uint8_t input_len);

uint64_t ip(uint64_t M);

uint64_t fp(uint64_t M);

// key: 64 bits -> 56 bits -> 16 subkey, 48 bits each
uint64_t *key_schedule(uint64_t K, uint64_t (&subkeys)[ITERATIONS]);

// expand R from 32 bits to 48 bits
uint64_t Expand(uint32_t R);

// Given 6 bit input, returns 4 bit specified in S-box table
char S(int sbox, uint8_t input);

// output: 32 bit
uint32_t F(uint64_t K, uint32_t R);

// M: 64 bits
// enc: non-zero specifies encryption, zero if decryption
uint64_t des(uint64_t (&subkeys)[ITERATIONS], uint64_t M, int enc);

#endif //CIPHER_DES_H
