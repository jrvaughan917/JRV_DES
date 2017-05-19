# JRV_DES

Implements DES enctyption and decryption in C++

Encryption Input: 8 byte hex as the plaintext, one 7-byte hex as the key (or 8-byte if you ignore the last bit of each byte)

Encryption Output: 8 bytes hex

Decryption Input: 8 bytes hex as the cipher text, one 7-byte hex as the key (or 8-byte if you ignore the last bit of each byte)

Decryption Output: 8 byte hex characters

Stages:

1. Initial permutation

2. Key generation

4. Mangler function

5. Round completion (16 rounds)

6. Final permutation
