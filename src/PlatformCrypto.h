#pragma once

#include <stdbool.h>

#ifdef USE_MBEDTLS
#include <mbedtls/cipher.h>
#else
// Hide the real OpenSSL definition from other code
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
#endif

typedef struct _PLT_CRYPTO_CONTEXT {
#ifdef USE_MBEDTLS
    mbedtls_cipher_context_t ctx;
    bool initialized;
#else
    EVP_CIPHER_CTX* ctx;
    bool initialized;
#endif
} PLT_CRYPTO_CONTEXT, *PPLT_CRYPTO_CONTEXT;

#define ROUND_TO_PKCS7_PADDED_LEN(x) ((((x) + 15) / 16) * 16)

PPLT_CRYPTO_CONTEXT PltCreateCryptoContext(void);
void PltDestroyCryptoContext(PPLT_CRYPTO_CONTEXT ctx);

#define ALGORITHM_AES_CBC 1
#define ALGORITHM_AES_GCM 2

#define CIPHER_FLAG_RESET_IV          0x01
#define CIPHER_FLAG_FINISH            0x02
#define CIPHER_FLAG_PAD_TO_BLOCK_SIZE 0x04

bool PltEncryptMessage(PPLT_CRYPTO_CONTEXT ctx, int algorithm, int flags,
                       unsigned char* key, int keyLength,
                       unsigned char* iv, int ivLength,
                       unsigned char* tag, int tagLength,
                       unsigned char* inputData, int inputDataLength,
                       unsigned char* outputData, int* outputDataLength);

bool PltEncryptMessageEx(PPLT_CRYPTO_CONTEXT ctx, int algorithm, int flags,
                         unsigned char* key, int keyLength,
                         unsigned char* iv, int ivLength,
                         unsigned char* aad, int aadLength,
                         unsigned char* tag, int tagLength,
                         unsigned char* inputData, int inputDataLength,
                         unsigned char* outputData, int* outputDataLength);

bool PltDecryptMessage(PPLT_CRYPTO_CONTEXT ctx, int algorithm, int flags,
                       unsigned char* key, int keyLength,
                       unsigned char* iv, int ivLength,
                       unsigned char* tag, int tagLength,
                       unsigned char* inputData, int inputDataLength,
                       unsigned char* outputData, int* outputDataLength);

bool PltDecryptMessageEx(PPLT_CRYPTO_CONTEXT ctx, int algorithm, int flags,
                         unsigned char* key, int keyLength,
                         unsigned char* iv, int ivLength,
                         unsigned char* aad, int aadLength,
                         unsigned char* tag, int tagLength,
                         unsigned char* inputData, int inputDataLength,
                         unsigned char* outputData, int* outputDataLength);

bool PltHkdfSha256(const unsigned char* inputKeyMaterial, int inputKeyMaterialLength,
                   const unsigned char* salt, int saltLength,
                   const unsigned char* info, int infoLength,
                   unsigned char* outputKeyMaterial, int outputKeyMaterialLength);

bool PltAesEcbEncryptBlock(const unsigned char* key, int keyLength,
                           const unsigned char input[16], unsigned char output[16]);

void PltGenerateRandomData(unsigned char* data, int length);
