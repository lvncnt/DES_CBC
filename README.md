
> This program implements the DES/CBC/PKCS5Padding encryption and decryption. It can decrypt the file contents encrypted by `openssl enc -e -des-cbc` command as long as `iv` and `key` are given correctly; the output file contents encrypted by this program can by decrypted by `openssl enc -d -des-cbc -nosalt -nopad`. 

## Compile and Run
```
$ make
$ ./out
usage: ./out [-ed] [-in file] [-iv IV] [-K key] [-out file]

-e		Encrypt the input data
-d		Decrypt the input data
-in file	Input file to read from
-iv IV		IV to use, specified as a hexidecimal string
-K key		key to use, specified as a hexidecimal string
-out file	Output file to write to
```

## IV and Key

IV and key are specified as hexidecimal string, such as `0123456789ABCDEF` and `29AB9D18B2449E31` of 64 bits, `FF` etc. However, `FF` is not the same as `00000000000000FF`. Instead, like in `openssl`, it will be interpreted as `FF00000000000000`. 

## Padding and Testcases for Encryption

Four testcases are included with the program files. Among them, `input01.txt` and `input04.txt` have texts whose size are exactly multiples of 64 bits.  

For `input02.txt` and `input03.txt`, whose content sizes are not multiples of 64 bits, the `PKCS#5` padding mechanism is used to achieve 8-byte block size, as is in `openssl`.

## Three Running Examples 
### Example 1: IV and key are not provided

In this case, the program will generate pseudorandom IV and key, and use them for encryption. 

_encrypt_
```
$ ./out -e -in input02.txt -out out.enc
IV not provided, generate random.
Key not provided, generate random.
iv  =	B836B376374EA00B
key =	955AD8BC5B05F9EF
Encrypt Output File: out.enc
```
_decrypt_
```
$ ./out -d -in out.enc -out out.dec -iv B836B376374EA00B -K 955AD8BC5B05F9EF 
iv  =	B836B376374EA00B
key =	955AD8BC5B05F9EF
Decrypt Output File: out.dec
$ cat out.dec
7654321 Now is the time for \0001
```
_decrypt with openssl_. The above encrypted output file `out.enc` can be decryted via `openssl`. 

```
$ openssl enc -d -des-cbc -in out.enc -nosalt -nopad -p -iv B836B376374EA00B -K 955AD8BC5B05F9EF
key=955AD8BC5B05F9EF
iv =B836B376374EA00B
7654321 Now is the time for \0001
```

### Example 2: IV and key are provided

In this case, the program uses the provided IV and key for encryption. 

_encrypt_
```
$  ./out -e -in input02.txt -out out.enc -iv 133457799BBCDFF1 -K 29AB9D18B2449E31
iv  =	133457799BBCDFF1
key =	29AB9D18B2449E31
Encrypt Output File: out.enc
```
_decrypt_
```
$ ./out -d -in out.enc -out out.dec -iv 133457799BBCDFF1 -K 29AB9D18B2449E31
iv  =	133457799BBCDFF1
key =	29AB9D18B2449E31
Decrypt Output File: out.dec
$ cat out.dec
7654321 Now is the time for \0001
```
_decrypt with openssl_.

```
$ openssl enc -d -des-cbc -in out.enc -nosalt -nopad -p -iv 133457799BBCDFF1 -K 29AB9D18B2449E31
key=29AB9D18B2449E31
iv =133457799BBCDFF1
7654321 Now is the time for \0001
```

### Example 3: key less than 8 bytes and encryption with openssl

In this case, the program decrypt the file contents encrypted by `openssl`.  

_encrypt with openssl_
```
$  openssl enc -e -des-cbc -in input01.txt -out out.enc -nosalt -p -iv 0 -K ff
key=FF00000000000000
iv =0000000000000000
```
_decrypt_
```
$ ./out -d -in out.enc -out out.dec -iv 0 -K ff
iv  =	0000000000000000
key =	FF00000000000000
Decrypt Output File: out.dec
$ cat out.dec
7654321 Now is the time for \000
```
