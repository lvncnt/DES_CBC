//
//  cipher_des.cpp
//  DESCBC
//

#include "cipher_des.h"

uint64_t permute(const char *table, uint8_t table_len, uint64_t input, uint8_t input_len) {
    uint64_t res = 0;
    for (uint8_t i = 0; i < table_len; i++) {
        res = (res << 1) | ((input >> (input_len - table[i])) & 0x01); 
    }
    return res;
}

uint64_t ip(uint64_t M) {
    return permute(IP, sizeof(IP) / sizeof(IP[0]), M, 64);
}

uint64_t fp(uint64_t M) {
    return permute(FP, sizeof(FP) / sizeof(FP[0]), M, 64);
}

uint64_t *key_schedule(uint64_t K, uint64_t (&subkeys)[ITERATIONS]) {

    // key permutation with PC1
    K = permute(PC1, sizeof(PC1) / sizeof(PC1[0]), K, 64);

    // split into 28-bit left and right (c and d) pairs
    uint32_t C = (uint32_t) ((K >> 28) & 0x000000000fffffff);
    uint32_t D = (uint32_t) (K & 0x000000000fffffff);

    for (uint8_t i = 0; i < ITERATIONS; i++) {
        switch ((int) (LEFT_SHIFTS[i])) {
            case 1: { // left shift 1 bit
                C = ((C << 1) & 0x0FFFFFFF) | (C >> 27);
                D = ((D << 1) & 0x0FFFFFFF) | (D >> 27);
                break;
            }
            case 2: { // left shift 2 bit
                C = ((C << 2) & 0x0FFFFFFF) | (C >> 26);
                D = ((D << 2) & 0x0FFFFFFF) | (D >> 26);
                break;
            }
        }
        // join C, D
        uint64_t CD = (((uint64_t) C) << 28) | (uint64_t) D;
        // PC2 permutation into 48 bits
        subkeys[i] = permute(PC2, sizeof(PC2) / sizeof(PC2[0]), CD, 56);
    }

    return subkeys;
}

uint64_t Expand(uint32_t R) {
    return permute(E, sizeof(E) / sizeof(E[0]), R, 32);
}

char S(int sbox, uint8_t input) {
    char row = (char) (((input & 0x20) >> 4) | (input & 0x01));
    char col = (char) ((input & 0x1E) >> 1);
    return SBOXMAP[sbox][16 * row + col];
}

uint32_t F(uint64_t K, uint32_t R) {
    // expanded R from 32 bits to 48 bits, using the selection table
    uint64_t e = Expand(R);
    // XORed the result with key K
    e ^= K;

    // apply S-Boxes function and permute from 48 bit to 32 bit
    uint32_t output = 0;
    for (int i = 0; i < 8; ++i) {
        output <<= 4;
        output |= (uint32_t) S(i, (uint8_t) ((e & 0xFC0000000000) >> 42));
        e <<= 6;
    }

    // apply a permutation P of the S-box output to obtain the final value of f:
    // P yields a 32-bit output from a 32-bit input by permuting the bits of the input block
    return (uint32_t) permute(P, sizeof(P) / sizeof(P[0]), output, 32);;
}

uint64_t des(uint64_t (&subkeys)[ITERATIONS], uint64_t M, int enc) {

    // 1. InitialPermutation(M);
    M = ip(M);

    // divide permuted block IP into a left half L0 of 32 bits,
    // and a right half R0 of 32 bits.
    uint32_t L = (uint32_t) (M >> 32) & 0x0FFFFFFFF;
    uint32_t R = (uint32_t) (M & 0x0FFFFFFFF);

    // 2. subkey generation: 
    // moved into main method

    // 3. start substitution
    for (int i = 0; i < ITERATIONS; ++i) {
        uint32_t oldL = L;
        // in case of decryption: reverse order in which subkeys are applied
        uint64_t subkey = enc ? subkeys[i] : subkeys[ITERATIONS - i - 1];
        L = R; // LEi = REi-1;
        R = oldL ^ F(subkey, R); // REi = LEi-1 XOR F(Ki,REi-1);
    }

    // 4. reverse the order of the two blocks into the 64-bit block
    // swap(LE16,RE16); from L16R16 to R16L16
    M = (((uint64_t) R) << 32) | (uint64_t) L;

    // 5. apply a final permutation
    // C = IP-1(LE16||RE16);
    return fp(M); // 64 bits;
}
