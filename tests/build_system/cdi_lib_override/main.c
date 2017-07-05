#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

void crypto_stuff() {
    printf("crypto stuff\n");
}

void success() {
    printf("Success!\n");
}

/* taken from https://wiki.openssl.org/index.php/Libcrypto_API */
int main(int arc, char *argv[])
{ 
    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    /* Load config file, and other important initialisation */
    OPENSSL_config(NULL);

    /* ... Do some crypto stuff here ... */
    crypto_stuff();

    /* Clean up */

    /* Removes all digests and ciphers */
    EVP_cleanup();

    /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
    CRYPTO_cleanup_all_ex_data();

    /* Remove error strings */
    ERR_free_strings();

    success();

    return 0;
}
