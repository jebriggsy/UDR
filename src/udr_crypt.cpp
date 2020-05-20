#include "udr_crypt.h"

#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>
//#include "udr_log.h"


udr_crypt::udr_crypt(int direc, int len, unsigned char* password, char *encryption_type)
{
    unsigned char ivec[EVP_MAX_IV_LENGTH];
    unsigned char keybuf[EVP_MAX_KEY_LENGTH];
    //free_key( password ); can't free here because is reused by threads
    const EVP_CIPHER *cipher;

    //aes-128|aes-256|bf|des-ede3
    //log_set_maximum_verbosity(LOG_DEBUG);
    //log_print(LOG_DEBUG, "encryption type %s\n", encryption_type);

    if (strncmp("aes-128", encryption_type, 8) == 0) {
        //log_print(LOG_DEBUG, "using aes-128 encryption\n");
#ifdef OPENSSL_HAS_CTR
        if (CTR_MODE)
            cipher = EVP_aes_128_ctr();
        else
#endif
            cipher = EVP_aes_128_cfb();
    }
    else if (strncmp("aes-192", encryption_type, 8) == 0) {
        //log_print(LOG_DEBUG, "using aes-192 encryption\n");
#ifdef OPENSSL_HAS_CTR
        if (CTR_MODE)
            cipher = EVP_aes_192_ctr();
        else
#endif
            cipher = EVP_aes_192_cfb();
    }
    else if (strncmp("aes-256", encryption_type, 8) == 0) {
        //log_print(LOG_DEBUG, "using aes-256 encryption\n");
#ifdef OPENSSL_HAS_CTR
        if (CTR_MODE)
            cipher = EVP_aes_256_ctr();
        else
#endif
            cipher = EVP_aes_256_cfb();
    }
    else if (strncmp("des-ede3", encryption_type, 9) == 0) {
        // apparently there is no 3des nor bf ctr
        cipher = EVP_des_ede3_cfb();
        //log_print(LOG_DEBUG, "using des-ede3 encryption\n");
    }
    else if (strncmp("bf", encryption_type, 3) == 0) {
        cipher = EVP_bf_cfb();
        //log_print(LOG_DEBUG, "using blowfish encryption\n");
    }
    else {
        fprintf(stderr, "error unsupported encryption type %s\n",
            encryption_type);
        exit(EXIT_FAILURE);
    }

    // password is reset for each session, can use 0 IV
    memset(ivec, 0, sizeof(ivec));
    memset(keybuf, 0, sizeof(keybuf));
    memcpy(keybuf, password, (size_t)len > sizeof(keybuf) ? sizeof(keybuf) : (size_t)len);

    direction = direc;
    // EVP stuff
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_init(&ctx);
    ctxp = &ctx;
#else
    ctxp = EVP_CIPHER_CTX_new();
#endif

    if (!EVP_CipherInit_ex(ctxp, cipher, NULL, keybuf, ivec, direc)) {
        goptions.err() << "error setting encryption scheme" << endl;
        exit(EXIT_FAILURE);
    }
}

udr_crypt::~udr_crypt()
{
    // threads must be dead by now
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_cleanup(&ctx);
#else
    EVP_CIPHER_CTX_free(ctxp);
#endif
}


// using a stream mode causes us to always get the same size of
// data in and out.  Also, no EVP_CipherFinal_ex() is needed
//
int udr_crypt::encrypt(char *in, char *out, int len)
{
    int evp_outlen;

    if(!EVP_CipherUpdate(ctxp, (unsigned char *)out, &evp_outlen, (unsigned char *)in, len))
    {
        fprintf(stderr, "encryption error\n");
        goptions.err() << "encryption error" << endl;
        exit(EXIT_FAILURE);
    }
    return evp_outlen;
}
