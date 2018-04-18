//
//  utils.cpp
//  DESCBC
//

#include "utils.h"

uint64_t ntoh64(const uint64_t *input) {
    uint64_t rval;
    uint8_t *data = (uint8_t *) &rval;

    data[0] = *input >> 56;
    data[1] = *input >> 48;
    data[2] = *input >> 40;
    data[3] = *input >> 32;
    data[4] = *input >> 24;
    data[5] = *input >> 16;
    data[6] = *input >> 8;
    data[7] = *input >> 0;

    return rval;
}

uint64_t hton64(const uint64_t *input) {
    return (ntoh64(input));
}

void print_hex_string(string label, uint64_t &input) {
    cout << label;
    cout.fill('0');
    cout.width(16);
    cout << hex << uppercase << input << endl;
}

uint8_t valid_hex_string(string &data, int len) {
    for (int i = 0; i < len; ++i) {
        if (!isxdigit(data[i])) {
            return 0;
        }
    }
    return 1;
}

uint64_t DES_key_iv_check(const char *data, uint64_t length) {
    string str(data);
    string padded = str.append(length * 2 - strlen(data), '0');
    return strtoull(str.c_str(), 0, 16);
}

string DES_random_string(const int bytes) {
    string s;
    s.reserve(bytes * 2);
    // unsigned int seed = time(0);
    auto seed = chrono::high_resolution_clock::now().time_since_epoch().count();
    mt19937_64 rng(seed);
    uniform_int_distribution<int> unif(0, HEX_SET.length() - 1); // [)
    for (int i = 0; i < bytes * 2; ++i) {
        s += HEX_SET[unif(rng)];
    }
    return s;
}
