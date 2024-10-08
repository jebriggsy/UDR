/*****************************************************************************
Copyright 2012 Laboratory for Advanced Computing at the University of Chicago

This file is part of UDR.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions
and limitations under the License.
*****************************************************************************/
#ifndef UDR_CRYPT_H
#define UDR_CRYPT_H

#define PASSPHRASE_SIZE 32
#define HEX_PASSPHRASE_SIZE 64

#include "udr_options.h"

#include <openssl/evp.h>
#include <vector>
#include <string>

class udr_crypt
{
public:

    enum crypt_dir_t {
        ENCRYPT = 1,
        DECRYPT = 0
    };

    typedef std::vector<unsigned char> key_t;
    typedef void * cipher_t;

    udr_crypt(crypt_dir_t dir, const std::string &encryption_type, const key_t &key);
    udr_crypt(crypt_dir_t dir, const std::string &encryption_type, const std::string &password);
    ~udr_crypt();

    bool is_valid() {return valid;}
    static cipher_t get_cipher(const std::string &encryption_type);
    static size_t get_keylen(cipher_t);
    
    int encrypt(char *in, char *out, int len);

    // encoding/decoding binary data to ascii
    static key_t rand_bytes(int num);
    static std::string encode_64(const key_t &bytes);
    static std::string encode_hex(const key_t &bytes);
    static key_t decode_64(const std::string &);
    static key_t decode_hex(const std::string &);
    static key_t decode(const std::string &);

private:
    bool init(const std::string &encryption_type, const key_t &key);
   
private:
    const crypt_dir_t direction;
    bool valid = false;
    
    // EVP stuff
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX ctx;
#endif
    EVP_CIPHER_CTX *ctxp = nullptr;
};

#endif
