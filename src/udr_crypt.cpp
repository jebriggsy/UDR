#include "udr_crypt.h"

#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>
#include <cstring>
//#include "udr_log.h"

using std::endl;

#define CTR_MODE 1

udr_crypt::udr_crypt(crypt_dir_t direc, const std::string &encryption_type, const key_t &key):
    direction(direc)
{
    valid = init(encryption_type, key);
    if (!valid)
        exit(EXIT_FAILURE);
}
    
udr_crypt::udr_crypt(crypt_dir_t direc, const std::string &encryption_type, const std::string &password):
    direction(direc)
{
    key_t key = decode(password);
    valid = init(encryption_type, key);
    if (!valid)
        exit(EXIT_FAILURE);
}

bool udr_crypt::init(const std::string &encryption_type, const key_t &key)
{
    EVP_CIPHER *cipher = (EVP_CIPHER*)get_cipher(encryption_type);
    if (!cipher)
        return false;

    size_t rlen = EVP_CIPHER_key_length(cipher);
    if (key.size() < rlen) {
        goptions.err() << "key short " << key.size() << "bytes, " << rlen << " required" << endl;
        return false;
    }

    // password is reset for each session, can use 0 IV
    unsigned char ivec[EVP_MAX_IV_LENGTH];
    memset(ivec, 0, sizeof(ivec));
    
    // EVP stuff
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_init(&ctx);
    ctxp = &ctx;
#else
    ctxp = EVP_CIPHER_CTX_new();
#endif

    if (!ctxp || EVP_CipherInit_ex(ctxp, cipher, NULL, key.data(), ivec, direction)) {
        goptions.err() << "error setting encryption scheme" << endl;
        return false;
    }
    return true;
}

udr_crypt::~udr_crypt()
{
    // threads must be dead by now
    if (ctxp)
    {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_CIPHER_CTX_cleanup(&ctx);
#else
        EVP_CIPHER_CTX_free(ctxp);
#endif
    }
}

udr_crypt::cipher_t udr_crypt::get_cipher(const std::string &encryption_type)
{
    const EVP_CIPHER *cipher = nullptr;

    //aes-128|aes-256|bf|des-ede3
    //log_set_maximum_verbosity(LOG_DEBUG);
    //log_print(LOG_DEBUG, "encryption type %s\n", encryption_type);

    if (encryption_type == "aes-128") {
        //log_print(LOG_DEBUG, "using aes-128 encryption\n");
#ifdef OPENSSL_HAS_CTR
        if (CTR_MODE)
            cipher = EVP_aes_128_ctr();
        else
#endif
            cipher = EVP_aes_128_cfb();
    }
    else if (encryption_type == "aes-192") {
        //log_print(LOG_DEBUG, "using aes-192 encryption\n");
#ifdef OPENSSL_HAS_CTR
        if (CTR_MODE)
            cipher = EVP_aes_192_ctr();
        else
#endif
            cipher = EVP_aes_192_cfb();
    }
    else if (encryption_type == "aes-256") {
        //log_print(LOG_DEBUG, "using aes-256 encryption\n");
#ifdef OPENSSL_HAS_CTR
        if (CTR_MODE)
            cipher = EVP_aes_256_ctr();
        else
#endif
            cipher = EVP_aes_256_cfb();
    }
    else if (encryption_type == "des-ede3") {
        // apparently there is no 3des nor bf ctr
        cipher = EVP_des_ede3_cfb();
        //log_print(LOG_DEBUG, "using des-ede3 encryption\n");
    }
    else if (encryption_type == "bf") {
        cipher = EVP_bf_cfb();
        //log_print(LOG_DEBUG, "using blowfish encryption\n");
    }
    else {
        goptions.err() << "error unsupported encryption type: " << encryption_type << std::endl;
        exit(EXIT_FAILURE);
    }
    return (cipher_t)cipher;
}

size_t udr_crypt::get_keylen(cipher_t cipher)
{
    if (cipher == nullptr)
        return 0;
    return EVP_CIPHER_key_length((EVP_CIPHER *)cipher);
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

udr_crypt::key_t udr_crypt::rand_bytes(int num)
{
    key_t res(num);
    if (RAND_bytes(res.data(), num) != 1)
        res.clear();
    return res;
}

std::string udr_crypt::encode_64(const key_t &bytes)
{
    std::string result;
    result.resize(bytes.size()*2 + 4);
    int n = EVP_EncodeBlock((unsigned char*)result.data(), bytes.data(), bytes.size());
    result.resize(n);
    return result;
}

udr_crypt::key_t udr_crypt::decode_64(const std::string &text)
{
    key_t result(text.size());
    int n = EVP_DecodeBlock(result.data(), (const unsigned char*)text.data(), text.size());
    if (n != -1)
        result.resize(n);
    else
        result.resize(0);
    return result;
}

std::string udr_crypt::encode_hex(const key_t &bytes)
{
    std::string result;
    result.reserve(bytes.size() * 2);
    char tmp[3];
    for(auto it = bytes.begin(); it != bytes.end(); ++it)
    {
        sprintf(tmp, "%02x", (int)*it);
        result.append(tmp);
    }
    return result;
}

udr_crypt::key_t udr_crypt::decode_hex(const std::string &text)
{
    key_t result;
    result.reserve(text.size()/2);
    bool error = false;
    for (size_t i = 0; i < text.size(); i += 2) {
        if (i + 1 >= text.size())
        {
            error = true;
            break;
        }
        unsigned int c;
        int n = sscanf(&text[i], "%02x", &c);
        if (!n) {
            error = true;
            break;
        }
        result.push_back((unsigned char)c);
    }
    if (error)
        result.resize(0);
    return result;
}

udr_crypt::key_t udr_crypt::decode(const std::string &text)
{
    // first try hex.  that will fail with any of the non hex chars
    key_t result = decode_hex(text);
    if (!result.size())
        result = decode_64(text);
    if (!result.size())
        goptions.err() << "could not parse key '"<<text<<"'" << endl;
    return result;
}
