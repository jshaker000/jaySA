//implementation of crypto.h

#include <iostream>
#include <string>
#include <string_view>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include "crypto.h"

static const auto CIPHER_USED = EVP_aes_256_cbc();
static const auto DIGEST_USED = EVP_sha256();

static void copy_into_string (unsigned char* a, size_t len, std::string &s)
{
    s.clear();
    s.reserve(len);
    for (size_t i = 0; i < len; i++)
        s.push_back(static_cast<char>(a[i]));
}

static void append_into_string (unsigned char* a, size_t len, std::string &s, bool reserve)
{
    if (reserve)
        s.reserve(s.size() + len);
    for (size_t i = 0; i < len; i++)
        s.push_back(static_cast<char>(a[i]));
}

static void bin_to_hex_str(unsigned char* a, int len, std::string &out)
{
    out.clear();
    out.reserve(2*len);
    for (int i = 0; i < len; i++)
    {
        char temp = static_cast<char>((a[i] & 0xF0) >> 4);

        if (temp >= 10)
            out.push_back(temp + 'A' - 0x0A);
        else
            out.push_back(temp + '0');

        temp = static_cast<char>(a[i] & 0x0F);

        if (temp >= 10)
            out.push_back(temp + 'A' - 0x0A);
        else
            out.push_back(temp + '0');
    }
}

// pub_key and priv_key are paths to pem files to encrypt and sign with respectively
// OUTPUT  Stored in ENOCDED
// OUTPUT  FORMAT OF ENCODED:
//        2 BYTES: e_key_len
//        2 BYTES: sig_len
//        e_key_len bytes: e_key
//        iv
//        cipher_text
//        sig_len bytes: sig (of e_key + iv + cipher_text)
// Returns 0 on success, !=0 on failure
// if priv_key== "", dont sign
int crypto::rsa_encrypt_sign(const std::string_view msg,        const std::string &pub_key,
                             const std::string      &priv_key,  std::string &encoded)
{
    encoded.clear();
    // load keys from file
    bool sign = priv_key.size() != 0;
    FILE  *pub_f  = fopen(pub_key.c_str(), "r");
    FILE  *priv_f = sign ? fopen(priv_key.c_str(), "r") : nullptr;

    if (pub_f == nullptr || (sign && (priv_f == nullptr)))
    {
        if (pub_f  != nullptr) fclose(pub_f);
        if (priv_f != nullptr) fclose(priv_f);
        std::cerr << ">RSA_ENCRYPT_SIGN ERROR OPENING PUB_KEY OR PRIV_KEY FILE" << std::endl;
        return 2;
    }

    EVP_CIPHER_CTX *rsactx = EVP_CIPHER_CTX_new();
    EVP_MD_CTX     *mdctx  = EVP_MD_CTX_create();

    EVP_PKEY *pub_k  = PEM_read_PUBKEY(pub_f,  nullptr, nullptr, nullptr);
    EVP_PKEY *priv_k = sign ? PEM_read_PrivateKey(priv_f, nullptr, nullptr, nullptr) : nullptr;

    int iv_length = EVP_CIPHER_iv_length(CIPHER_USED);

    unsigned char *iv          = static_cast<unsigned char*>(calloc(iv_length,               sizeof(*iv)));
    unsigned char *cipher_text = static_cast<unsigned char*>(calloc(msg.size() + iv_length,  sizeof(*cipher_text)));
    unsigned char *e_key       = static_cast<unsigned char*>(calloc(EVP_PKEY_size(pub_k),    sizeof(*e_key)));
    unsigned char *sig         = nullptr;

    int    error              = 0;
    int    cipher_text_length = 0;
    int    block_length       = 0;
    int    e_key_length       = 0;
    size_t sig_len            = 0;

    std::string_view  to_sign;

    if (iv == nullptr || cipher_text == nullptr || e_key == nullptr
        || pub_k == nullptr || (priv_k == nullptr && sign))
    {
        error = 3;
        std::cerr << ">RSA_ENCRYPT_SIGN ERROR INITIALIZING" << std::endl;
        goto cleanup;
    }

    //generate random encryption key, encrypt it with the public key, and store in e_key
    //generate a random iv and store it in iv
    if (1 != EVP_SealInit(rsactx, CIPHER_USED, &e_key, &e_key_length, iv, &pub_k, 1))
    {
        error = 4;
        std::cerr << ">RSA_ENCRYPT_SIGN ERROR ENCRYPTING" << std::endl;
        goto cleanup;
    }
    //encrypt
    if (1 != EVP_SealUpdate(rsactx, cipher_text + cipher_text_length, (int*)&block_length,
                            reinterpret_cast<const unsigned char*>(msg.data()), msg.size()))
    {
        error = 5;
        std::cerr << ">RSA_ENCRYPT_SIGN ERROR ENCRYPTING" << std::endl;
        goto cleanup;
    }

    cipher_text_length += block_length;

    if (1 != EVP_SealFinal(rsactx, cipher_text + cipher_text_length, (int*)&block_length))
    {
        error = 6;
        std::cerr << ">RSA_ENCRYPT_SIGN ERROR ENCRYPTING" << std::endl;
        goto cleanup;
    }

    cipher_text_length += block_length;

    encoded.reserve(4 + e_key_length+iv_length + cipher_text_length);
    // store e_key_length
    encoded.push_back(e_key_length / 256);
    encoded.push_back(e_key_length % 256);
    // store sig_len (will overwrite if we sign)
    encoded.push_back(0);
    encoded.push_back(0);
    // copy e_key, iv, cipher text
    append_into_string(e_key,       e_key_length,       encoded, false);
    append_into_string(iv,          iv_length,          encoded, false);
    append_into_string(cipher_text, cipher_text_length, encoded, false);

    //sign e_key+iv+cipher_text and then append the signature to the end
    if (sign)
    {
        // sign e_key, iv, cipher_text
        to_sign = std::string_view(encoded).substr(4, encoded.size()-4);
        if (1 != EVP_DigestSignInit(mdctx, nullptr, DIGEST_USED, nullptr, priv_k))
        {
            error = 7;
            std::cerr << ">RSA_ENCRYPT_SIGN ERROR SIGNING" << std::endl;
            goto cleanup;
        }
        if(1 != EVP_DigestSignUpdate(mdctx, reinterpret_cast<const unsigned char*>(to_sign.data()), to_sign.size()))
        {
            error = 8;
            std::cerr << ">RSA_ENCRYPT_SIGN ERROR SIGNING" << std::endl;
            goto cleanup;
        }
        //measure how big the signature will be, then allocate sig appropriately
        if (1 != EVP_DigestSignFinal(mdctx, nullptr, &sig_len))
        {
            error = 9;
            std::cerr << ">RSA_ENCRYPT_SIGN ERROR SIGNING" << std::endl;
            goto cleanup;
        }

        sig = static_cast<unsigned char*> (calloc(sig_len, sizeof(*sig)));
        if (sig == nullptr)
        {
            error = 10;
            std::cerr << ">RSA_ENCRYPT_SIGN ERROR SIGNING" << std::endl;
            goto cleanup;
        }

        if (1 != EVP_DigestSignFinal(mdctx, sig, &sig_len))
        {
            error = 11;
            std::cerr << ">RSA_ENCRYPT_SIGN ERROR SIGNING" << std::endl;
            goto cleanup;
        }
        // update sig_len if needed
        encoded[2] = sig_len / 256;
        encoded[3] = sig_len % 256;
        append_into_string(sig, sig_len, encoded, true);
    }

    cleanup:

    if(rsactx != nullptr) EVP_CIPHER_CTX_free(rsactx);
    if(mdctx  != nullptr) EVP_MD_CTX_destroy(mdctx);
    if(pub_k  != nullptr) EVP_PKEY_free(pub_k);
    if(priv_k != nullptr) EVP_PKEY_free(priv_k);

    if(priv_f != nullptr) fclose(priv_f);
    if(pub_f  != nullptr) fclose(pub_f);

    if(iv          != nullptr) free(iv);
    if(cipher_text != nullptr) free(cipher_text);
    if(e_key       != nullptr) free(e_key);
    if(sig         != nullptr) free(sig);

    return error;
}

// pub_key and priv_key are paths to pem files to verify and decrypt with respectively
// OUTPUT  Stored in DECODED
// INPUT  FORMAT OF ENCODED:
//        2 BYTES: e_key_len
//        2 BYTES: sig_len
//        e_key_len bytes: e_key
//        iv
//        cipher_text
//        sig_len bytes: sig (of e_key + iv + cipher_text)
// Returns 0 on success, !=0 on failure
// if pub_key== "", dont verify
int crypto::rsa_decrypt_verify(const std::string_view msg,       const std::string &pub_key,
                               const std::string      &priv_key, std::string  &decoded)
{
    //verify msg is as long as it claims / dont falsely parse something
    int iv_length = EVP_CIPHER_iv_length(CIPHER_USED);

    if (msg.size() <  static_cast<size_t>(4 + iv_length))
    {
        std::cerr << ">RSA_DECRYPT_VERIFY INVALID INPUT MESSAGE" << std::endl;
        return 1;
    }

    const std::string_view e_key_length_str = msg.substr(0, 2);
    size_t e_key_length = 256 * static_cast<size_t>(e_key_length_str[0]) + static_cast<size_t>(e_key_length_str[1]);

    const std::string_view sig_key_length_str = msg.substr(2, 2);
    size_t sig_len = 256 * static_cast<size_t>(sig_key_length_str[0]) + static_cast<size_t>(sig_key_length_str[1]);

    if (msg.size() < static_cast<size_t>(4 + e_key_length + iv_length + sig_len + 1))
    {
        std::cerr << ">RSA_DECRYPT_VERIFY INVALID INPUT MESSAGE" << std::endl;
        return 1;
    }

    //parse out the encryption key, iv, message, and signature
    const std::string_view e_key_str  = msg.substr(4,  e_key_length);
    const std::string_view iv_str     = msg.substr(4 + e_key_length, iv_length);
    const std::string_view enc_msg    = msg.substr(4 + e_key_length + iv_length, msg.size() - 4 - e_key_length - iv_length - sig_len);
    const std::string_view signed_str = msg.substr(4, e_key_str.size() + iv_str.size() + enc_msg.size());
    const std::string_view sig_str    = msg.substr(msg.size() - sig_len);

    // load keys from file
    bool verify  = pub_key.size() != 0;
    FILE *pub_f  = verify ? fopen(pub_key.c_str(), "r") : nullptr;
    FILE *priv_f = fopen(priv_key.c_str(), "r");
    if ((verify && (pub_f == nullptr)) || priv_f == nullptr)
    {
        if (pub_f  != nullptr) fclose(pub_f);
        if (priv_f != nullptr) fclose(priv_f);
        std::cerr << ">RSA_DECRYPT_VERIFY ERROR OPENING PUB_KEY OR PRIV_KEY FILE" << std::endl;
        return 2;
    }

    EVP_CIPHER_CTX *rsactx  = EVP_CIPHER_CTX_new();
    EVP_MD_CTX     *mdctx   = EVP_MD_CTX_create();

    EVP_PKEY *priv_k = PEM_read_PrivateKey(priv_f, nullptr, nullptr, nullptr);
    EVP_PKEY *pub_k  = verify ? PEM_read_PUBKEY(pub_f,  nullptr, nullptr, nullptr) : nullptr;

    unsigned char *decode_text = static_cast<unsigned char*> (calloc(enc_msg.size() + iv_length, sizeof(*decode_text)));

    int error              = 0;
    int decode_text_length = 0;
    int block_length       = 0;

    if (decode_text == nullptr || ( pub_k == nullptr && verify ) || priv_k == nullptr)
    {
        error = 3;
        std::cerr << ">RSA_DECRYPT_VERIFY ERROR INITIALIZING" << std::endl;
        goto cleanup;
    }

    //decrypt e_key with priv key
    if (1 != EVP_OpenInit(rsactx, CIPHER_USED, reinterpret_cast<const unsigned char*>(e_key_str.data()), e_key_str.size(),
                          reinterpret_cast<const unsigned char*>(iv_str.data()), priv_k))
    {
        error = 4;
        std::cerr << ">RSA_DECRYPT_VERIFY ERROR DECRYPTING" << std::endl;
        goto cleanup;
    }

    //decrypt message
    if(1 != EVP_OpenUpdate(rsactx, decode_text + decode_text_length, (int*)&block_length,
                           reinterpret_cast<const unsigned char*>(enc_msg.data()), enc_msg.size()))
    {
        error = 5;
        std::cerr << ">RSA_DECRYPT_VERIFY ERROR DECRYPTING" << std::endl;
        goto cleanup;
    }

    decode_text_length += block_length;

    if ( 1 != EVP_OpenFinal(rsactx, decode_text + decode_text_length, (int*)&block_length ))
    {
        error = 6;
        std::cerr << ">RSA_DECRYPT_VERIFY ERROR DECRYPTING" << std::endl;
        goto cleanup;
    }

    decode_text_length += block_length;

    // store result in decoded
    copy_into_string(decode_text, decode_text_length, decoded);

    if(verify)
    {
        //verify signature of e_key+iv+message
        if (1 != EVP_DigestVerifyInit(mdctx, nullptr, DIGEST_USED, nullptr, pub_k))
        {
            error = 7;
            std::cerr << ">RSA_DECRYPT_VERIFY: ERROR VERIFYING SIGNATURE" << std::endl;
            goto cleanup;
        }

        if (1 != EVP_DigestVerifyUpdate(mdctx,
            reinterpret_cast<const unsigned char*>(signed_str.data()), signed_str.size()))
        {
            error = 8;
            std::cerr << ">RSA_DECRYPT_VERIFY: ERROR VERIFYING SIGNATURE" << std::endl;
            goto cleanup;
        }

        if (1 != EVP_DigestVerifyFinal(mdctx, reinterpret_cast<const unsigned char*>(sig_str.data()), sig_str.size()))
        {
            error = 9;
            std::cerr << ">RSA_DECRYPT_VERIFY: ERROR VERIFYING SIGNATURE" << std::endl;
            goto cleanup;
        }
    }

    cleanup:

    if(rsactx != nullptr) EVP_CIPHER_CTX_free(rsactx);
    if(mdctx  != nullptr) EVP_MD_CTX_destroy(mdctx);
    if(pub_k  != nullptr) EVP_PKEY_free(pub_k);
    if(priv_k != nullptr) EVP_PKEY_free(priv_k);

    if(priv_f != nullptr) fclose(priv_f);
    if(pub_f  != nullptr) fclose(pub_f);

    if(decode_text != nullptr) free(decode_text);

    return error;

}

//generates rsa key pair and writes to
//name.pub.pem and name.priv.pem
//Returns 0 on success, !=0 on failure
int crypto::rsa_genkeypair  (const std::string &name)
{
    //default is 2048, else we could use 4096?
    int key_length = 2048;
    int error      = 0;

    FILE *pub_f  = nullptr;
    FILE *priv_f = nullptr;

    EVP_PKEY *pkey    = nullptr;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);

    if (ctx == nullptr)
    {
        error = 1;
        std::cerr << ">RSA_GENKEYPAIR ERROR INISITALIZING" << std::endl;
        goto cleanup;
    }

    if (1 != EVP_PKEY_keygen_init(ctx))
    {
        error = 2;
        std::cerr << ">RSA_GENKEYPAIR ERROR INISITALIZING" << std::endl;
        goto cleanup;
    }
    if(1 != EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_length))
    {
        error = 3;
        std::cerr << ">RSA_GENKEYPAIR ERROR INISITALIZING" << std::endl;
        goto cleanup;
    }

    if(1 != EVP_PKEY_keygen(ctx, &pkey))
    {
        error = 5;
        std::cerr << ">RSA_GENKEYPAIR ERROR INISITALIZING" << std::endl;
        goto cleanup;
    }

    pub_f  = fopen((name + ".pub.pem").c_str(),  "w");
    priv_f = fopen((name + ".priv.pem").c_str(), "w");

    if (pub_f == nullptr || priv_f == nullptr)
    {
        std::cerr << ">RSA_GENKEYPAIR ERROR OPENING FILES TO WRITE" << std::endl;
        error = 4;
        goto cleanup;
    }

    if (1 != PEM_write_PUBKEY(pub_f, pkey))
    {
        error = 6;
        std::cerr << ">RSA_GENKEYPAIR ERROR WRITING TO PUBK FILE" << std::endl;
        goto cleanup;
    }

    if (1 != PEM_write_PrivateKey(priv_f, pkey, nullptr, nullptr, 0, nullptr, nullptr))
    {
        error = 7;
        std::cerr << ">RSA_GENKEYPAIR ERROR WRITING TO PUBK FILE" << std::endl;
        goto cleanup;
    }

    cleanup:

    if(pub_f  != nullptr) fclose(pub_f);
    if(priv_f != nullptr) fclose(priv_f);

    if(ctx  != nullptr) EVP_PKEY_CTX_free(ctx);
    if(pkey != nullptr) EVP_PKEY_free(pkey);

    return error;

}

// Uses openssl's random byte generator to make a key key_len_bits long
// convert to a hex string and store in hexKeyOut
// key_len_bits must be a multiple of 8
// returns 0 on success, !=0 on failure
int crypto::gen_rand_bits_hex(int key_len_bits, std::string &hexKeyOut)
{

    unsigned char *aes_key_bin = nullptr;
    int error = 0;
    if (key_len_bits % 8)
    {
        std::cerr << ">gen_hex_aes_key bits must be divisible by 8" << std::endl;
        error = 1;
        goto cleanup;
    }

    aes_key_bin = static_cast<unsigned char*>(calloc(key_len_bits/8, sizeof(*aes_key_bin)));

    if (aes_key_bin == nullptr)
    {
        std::cerr << ">gen_hex_aes_key Error Initializing" << std::endl;
        error = 2;
        goto cleanup;
    }

    if (1 != RAND_bytes(aes_key_bin, key_len_bits/8))
    {
        std::cerr << ">gen_hex_aes_key error making bytes" << std::endl;
        error = 3;
        goto cleanup;
    }

    bin_to_hex_str(aes_key_bin, key_len_bits/8, hexKeyOut);

    cleanup:

    if(aes_key_bin != nullptr) free(aes_key_bin);

    return error;
}
