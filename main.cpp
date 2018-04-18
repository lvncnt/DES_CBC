//
//  main.cpp
//  DESCBC
//

#include "utils.h"

#include <cstdio>
#include <cstdlib>
#include <bitset>

#include "cipher_des.h"
#include "cipher_padding.h"

// Encrypt the message contained in input file with iv and key using DES in CBC mode
void DES_cbc_encrypt(string input, string output, uint64_t (&subkeys)[ITERATIONS], uint64_t &iv, int enc) {
    ifstream in;
    ofstream out;

    in.open(input, ios::binary | ios::in | ios::ate);
    out.open(output, ios::binary | ios::out);
    if (!in) {
        cerr << "Error: missing file " << input << endl;
        exit(1);
    }

    uint64_t len = in.tellg();

    in.seekg(0, ios::beg);
    uint64_t buffer = 0;

    // start CBC mode
    uint64_t c_prev = iv;
    for (uint64_t i = 0; i < len / 8; ++i) {
        in.read((char *) &buffer, 8);
        uint64_t p_curr = hton64(&buffer);
        c_prev = des(subkeys, p_curr ^ c_prev, enc);
        uint64_t x = hton64(&c_prev);
        out.write((char *) &x, 8);
    }

    // last block: perform PKCS5 Padding if necessary 
    uint64_t padlen = get_pad_length(len);
    if (padlen == 8) {
        uint64_t p_curr = 0x0808080808080808;
        c_prev = des(subkeys, p_curr ^ c_prev, enc);
        uint64_t x = hton64(&c_prev);
        out.write((char *) &x, 8);
        //print_hex_string(c_prev);
    } else {
        buffer = 0;
        in.read((char *) &buffer, len % 8);
        uint64_t p_curr = hton64(&buffer);
        p_curr = pad_with_length(p_curr, padlen);
        c_prev = des(subkeys, p_curr ^ c_prev, enc);
        uint64_t x = hton64(&c_prev);
        out.write((char *) &x, 8);
        //print_hex_string(c_prev);
    }
    in.close();
    out.close();
}

// Decrypt the message contained in input file with iv and key using DES in CBC mode
void DES_cbc_decrypt(string input, string output, uint64_t (&subkeys)[ITERATIONS], uint64_t &iv, int enc) {
    ifstream in;
    ofstream out;

    in.open(input, ios::binary | ios::in | ios::ate);
    out.open(output, ios::binary | ios::out);
    if (!in) {
        cout << "Error: missing file " << input << endl;
        exit(1);
    }

    uint64_t length = in.tellg();
    in.seekg(0, ios::beg);
    uint64_t buffer = 0;

    uint64_t c_prev = iv;
    for (uint64_t i = 0; i < length / 8 - 1; ++i) {
        in.read((char *) &buffer, 8);
        uint64_t p_curr = hton64(&buffer);
        uint64_t res = des(subkeys, p_curr, enc) ^c_prev;
        uint64_t x = hton64(&res);
        out.write((char *) &x, 8);
        c_prev = p_curr;
    }

    // After decrypting, remove padding
    buffer = 0;
    // Read last line of file
    in.read((char *) &buffer, 8);
    uint64_t p_curr = hton64(&buffer);
    uint64_t res = des(subkeys, p_curr, enc) ^c_prev;

    // last byte: pad value
    int padlen = (res & 0xFF); 

    if (padlen < 8) {
        res = remove_pad(res, padlen);
        uint64_t x = hton64(&res);
        out.write((char *) &x, 8);
    }
    in.close();
    out.close();
}

void show_usage(string name) {
    cerr << "usage: " << name << " [-ed] [-in file] [-iv IV] [-K key] [-out file]\n\n"
         << "-e\t\tEncrypt the input data\n"
         << "-d\t\tDecrypt the input data\n"
         << "-in file\tInput file to read from\n"
         << "-iv IV\t\tIV to use, specified as a hexidecimal string\n"
         << "-K key\t\tkey to use, specified as a hexidecimal string\n"
         << "-out file\tOutput file to write to\n";
}

////////////////////// for testing ////////////////////
void show_subkeys(uint64_t (&subkeys)[ITERATIONS]) {
    cout << "subkeys: " << endl;
    for (int i = 0; i < ITERATIONS; ++i) { 
        cout << hex << subkeys[i] << endl;
    }
}

void testDES_single_block() {
    uint64_t K = 0x0E329232EA6D0D73; //0x133457799BBCDFF1;
    uint64_t M = 0x596F7572206C6970; // 0x0123456789ABCDEF;
    // cout << bitset<64>(M) << endl;
    uint64_t subkeys[ITERATIONS] = {0};
    key_schedule(K, subkeys);

    uint64_t output = des(subkeys, M, DES_ENCRYPT);

    cout << bitset<64>(output) << endl;
    cout << hex << uppercase << output << endl;

    cout << "decryption: " << endl;
    cout << hex << uppercase << des(subkeys, output, DES_DECRYPT) << endl;
}
 
//////////////// main /////////////////
int main(int argc, const char *argv[]) {

    // iv and K are optional
    if (argc != 6 && argc != 8 && argc != 10) {
        show_usage(argv[0]);
        return 1;
    }

    /* params to be provided by commandline args */ 
    int enc = DES_ENCRYPT; // encryption/decryption
    string input = "input"; // Input file to read from
    string output = "output"; // Output file to write to
    uint64_t iv = 0x0000000000000000; // IV to use, as hexidecimal string
    uint64_t K = 0x0000000000000000; // key to use, as hexidecimal string

    /* parse command arguments */ 
    bitset<8> set; // bitmap for later deciding which parms user failed to provide 
    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "-e") {
            set[0] = 1;
            enc = DES_ENCRYPT;
        } else if (arg == "-d") {
            set[0] = 1;
            enc = DES_DECRYPT;
        } else if (arg == "-in") {
            set[1] = 1;
            input = argv[++i];
        } else if (arg == "-iv") {
            set[2] = 1;
            string str(argv[++i]);
            // check if provided hex string is valid 
            if (!valid_hex_string(str, str.length())) {
                cerr << "Invalid hex iv" << endl;
                return 1;
            }
            // pad '0' to end into full 64 bit, if necessary 
            iv = DES_key_iv_check(str.c_str(), 8);
        } else if (arg == "-K") {
            set[3] = 1;
            string str(argv[++i]);
            if (!valid_hex_string(str, str.length())) {
                cerr << "Invalid hex key" << endl;
                return 1;
            }
            K = DES_key_iv_check(str.c_str(), 8);
        } else if (arg == "-out") {
            set[4] = 1;
            output = argv[++i];
        } else {
            cerr << "Unknown argument: " << arg << endl;
            show_usage(argv[0]);
            return 1;
        }
    }

    // check required args are set
    if (set[0] == 0 || set[1] == 0 || set[4] == 0) {
        show_usage(argv[0]);
        return 1;
    }

    if (enc == DES_DECRYPT && (set[2] == 0 || set[3] == 0)) {
        cerr << "Key and IV are needed for decryption!" << endl;
        show_usage(argv[0]);
        return 1;
    }

    /* generate 'random' iv / key */
    if (set[2] == 0) { // iv
        cout << "IV not provided, generate random." << endl;
        string s = DES_random_string(8); // 8 bytes
        iv = DES_key_iv_check(s.c_str(), 8);
    }

    if (set[3] == 0) { // key
        cout << "Key not provided, generate random." << endl;
        string s = DES_random_string(8); // 8 bytes
        K = DES_key_iv_check(s.c_str(), 8);
    }

    print_hex_string("iv  =\t", iv);
    print_hex_string("key =\t", K);

    /* generate 16 subkeys, each of 48 bits */
    uint64_t subkeys[ITERATIONS] = {0};
    key_schedule(K, subkeys);

    /* encrypt / decrypt */
    if (enc == DES_ENCRYPT) {
        DES_cbc_encrypt(input, output, subkeys, iv, DES_ENCRYPT);
        cout << "Encrypt Output File: " << output << endl;
    } else {
        DES_cbc_decrypt(input, output, subkeys, iv, DES_DECRYPT);
        cout << "Decrypt Output File: " << output << endl;
    }

    return 0;
}
