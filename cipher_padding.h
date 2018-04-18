//
//  cipher_padding.h
//  DESCBC
//

#ifndef padding_hpp
#define padding_hpp

#include <cstdlib>
#include <cstdint>
#include <string>

// PKCS5 Padding
// pad message with 0s at the end to make data length multiple of 8 (byte)

// given length of data, return length for the padding.
uint64_t get_pad_length(uint64_t data_len);

// pad pad_len bytes with value pad_len to end of data
uint64_t pad_with_length(uint64_t data, uint64_t pad_len);

// clear pad_len bytes from end of data
uint64_t remove_pad(uint64_t data, uint64_t pad_len);

#endif //padding_hpp
