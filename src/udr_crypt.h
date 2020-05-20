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
#ifndef CRYPTO_H
#define CRYPTO_H

#define PASSPHRASE_SIZE 32
#define HEX_PASSPHRASE_SIZE 64
#define EVP_ENCRYPT 1
#define EVP_DECRYPT 0
#define CTR_MODE 1

#include "udr_options.h"

#include <openssl/evp.h>

using namespace std;

class udr_crypt
{

public:

    udr_crypt(int direc, int len, unsigned char* password, char *encryption_type);
    ~udr_crypt();
    
    int encrypt(char *in, char *out, int len);
   
private:
    //BF_KEY key;
    int direction;

    int passphrase_size;
    int hex_passphrase_size;

    // EVP stuff
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX ctx;
#endif
    EVP_CIPHER_CTX *ctxp;

};

#endif
