#ifndef CRYPTO_H
#define CRYPTO_H

#include<string>
#include <string_view>

namespace crypto
{
    // Encrypts msg into encoded
    // Uses the pem file in "pub_key" to encrypt and the pemfile at "priv_key" to sign
    // returns 0 on success, !=0 on failure
    // if priv_key== "", dont sign
    int rsa_encrypt_sign(const std::string_view msg,        const std::string &pub_key,
                         const std::string      &priv_key,  std::string &encoded);

    // Decrypts msg into decoded
    // Uses the pem file in "priv_key" to decrypt and the pemfile at "pub_key" to verify
    // returns 0 on success, !=0 on failure
    // if pub_key== "", dont verify
    int rsa_decrypt_verify(const std::string_view msg,        const std::string &pub_key,
                           const std::string      &priv_key,  std::string &decoded);

    // writes a PEM key pair at
    // name.pub.pem & name.priv.pem
    // returns 0 on success, !=0 on failure. Depending on how far it gets before failing
    //     may create the files and leave them empty
    int rsa_genkeypair    (const std::string &name);

    // Uses openssl's random byte generator to make a key key_len_bits long
    // convert to a hex string and store in hexKeyOut
    // key_len_bits must be a multiple of 8
    // returns 0 on success, !=0 on failure
    int gen_rand_bits_hex (int key_len_bits, std::string &hexKeyOut);
}

#endif
