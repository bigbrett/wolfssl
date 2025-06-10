#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/ssl.h>

/* Definitions for each "shim" function */

int shim_wolfSSL_CTX_load_verify_buffer_ex(WOLFSSL_CTX* ctx,
                                           const unsigned char* in,
                                           long sz,
                                           int format,
                                           int userChain,
                                           word32 flags)
{
    int ret;

    printf("******** DYLIB SHIM");

    /* Ensure the flag to do apple native cert validation is set */
    ret = wolfSSL_CTX_load_system_CA_certs(ctx);
    if (ret != WOLFSSL_SUCCESS) {
        return ret;
    }

    /* Call the original load verify function */
    int (*origFn)(WOLFSSL_CTX*, const unsigned char*, long, int, int, word32) = dlsym(RTLD_NEXT,
                                       "wolfSSL_CTX_load_verify_buffer_ex");
    ret = origFn(ctx, in, sz, format, userChain, flags);
    if (ret != WOLFSSL_SUCCESS) {
        return ret;
    }

    /* Unload CAs from CM so they won't be used for verification */
    return wolfSSL_CTX_UnloadCAs(ctx);
}

#ifdef WOLFSSL_DER_LOAD
int shim_wolfSSL_CTX_der_load_verify_locations(WOLFSSL_CTX* ctx,
                                               const char* file,
                                               int format)
{
    printf("******** DYLIB SHIM");
    /* lookup the real function in the next image */
    int (*origFn)(WOLFSSL_CTX*, const char*, int) = dlsym(RTLD_NEXT,
                                       "wolfSSL_CTX_der_load_verify_locations");
    return origFn(ctx, file, format);
}
#endif

int shim_wolfSSL_CTX_load_verify_locations_ex(WOLFSSL_CTX* ctx,
                                              const char* file,
                                              const char* path,
                                              word32 flags)
{
    printf("******** DYLIB SHIM");
    /* lookup the real function in the next image */
    int (*origFn)(WOLFSSL_CTX*, const char*, const char*, word32) = dlsym(RTLD_NEXT,
                                       "wolfSSL_CTX_load_verify_locations_ex");
    return origFn(ctx, file, path, flags);
}

/* tell dyld to replace each function with the registered shim function */
__attribute__((used))
static struct {
    const void *replacement;
    const void *original;
} interposers[] __attribute__((section("__DATA,__interpose"))) = {
    { (const void*)shim_wolfSSL_CTX_load_verify_buffer_ex, (const void*)wolfSSL_CTX_load_verify_buffer_ex },
#ifdef WOLFSSL_DER_LOAD
    { (const void*)shim_wolfSSL_CTX_der_load_verify_locations, (const void*)wolfSSL_CTX_der_load_verify_locations },
#endif
    { (const void*)shim_wolfSSL_CTX_load_verify_locations_ex, (const void*)wolfSSL_CTX_load_verify_locations_ex }
};

