#include "TripWirePlatform.h"
#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#elif defined(__linux__)
#include <openssl/evp.h>
#endif
int tw_sha256(const uint8_t *bytes, size_t count, uint8_t digest[32]) {
#if defined(_WIN32)
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0) return -1;
    NTSTATUS status = BCryptCreateHash(algorithm, &hash, NULL, 0, NULL, 0, 0);
    for (size_t offset = 0; status >= 0 && offset < count;) {
        ULONG length = (ULONG)((count - offset) > 1048576 ? 1048576 : count - offset);
        status = BCryptHashData(hash, (PUCHAR)(bytes + offset), length, 0);
        offset += length;
    }
    if (status >= 0) status = BCryptFinishHash(hash, digest, 32, 0);
    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return status >= 0 ? 0 : -1;
#elif defined(__linux__)
    unsigned int length = 0;
    return EVP_Digest(bytes, count, digest, &length, EVP_sha256(), NULL) == 1 && length == 32 ? 0 : -1;
#else
    // macOS uses CryptoKit directly.
    (void)bytes; (void)count; (void)digest; return -1;
#endif
}
