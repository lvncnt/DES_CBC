//
//  cipher_padding.cpp
//  DESCBC
//

#include "cipher_padding.h"

// PKCS5 Padding
uint64_t get_pad_length(uint64_t data_len) {
    return 8 - data_len % 8;
}

uint64_t pad_with_length(uint64_t data, uint64_t pad_len) {
    for (int i = 0; i < pad_len; ++i) {
        data |= (pad_len << (8 * i));
    }
    return data;
}

uint64_t remove_pad(uint64_t data, uint64_t pad_len) {
    data >>= (8 * pad_len);
    return data;
}