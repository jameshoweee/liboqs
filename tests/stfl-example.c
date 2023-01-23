#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

#define MESSAGE_LEN 50

OQS_STATUS lock_sk_key(OQS_SECRET_KEY *sk) {
    return sk != NULL ? OQS_SUCCESS : OQS_ERROR;
}

OQS_STATUS release_sk_key(OQS_SECRET_KEY *sk) {
    return sk != NULL ? OQS_SUCCESS : OQS_ERROR;
}
static OQS_STATUS do_nothing_save(const OQS_SECRET_KEY *sk) {
    return sk != NULL ? OQS_SUCCESS : OQS_ERROR;
}

int main(void) {
    OQS_SIG_STFL *sig = NULL;
    const char *method_name = OQS_SIG_STFL_alg_xmss_sha256_h10;

    OQS_SECRET_KEY *secret_key = NULL;

    uint8_t message[MESSAGE_LEN] = {0};

    uint8_t *signature = NULL;
    size_t signature_len = 0;

    uint8_t *public_key = NULL;

    OQS_STATUS rc;

    sig = OQS_SIG_STFL_new(method_name);
    if (sig == NULL) {
        fprintf(stderr, "ERROR: OQS_SIG_STFL_new failed\n");
        rc = 1;
        goto cleanup;
    }

    public_key = malloc(sig->length_public_key);
    signature = malloc(sig->length_signature);
    if (public_key == NULL || signature == NULL) {
        fprintf(stderr, "ERROR: malloc failed!\n");
        return OQS_ERROR;
    }

    // Initialize the secret key
    secret_key = OQS_SECRET_KEY_new(method_name);
    if (secret_key == NULL) {
        fprintf(stderr, "ERROR: OQS_SECRET_KEY_new failed\n");
        rc = 1;
        goto cleanup;
    }
    secret_key->lock_key = lock_sk_key;
    secret_key->release_key = release_sk_key;
    secret_key->save_secret_key = do_nothing_save;
    rc = OQS_SIG_STFL_keypair(sig, public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_STFL_keypair failed\n");
        rc = 1;
        goto cleanup;
    }

    rc = OQS_SIG_STFL_sign(sig, signature, &signature_len, message, MESSAGE_LEN, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_STFL_sign failed\n");
        rc = 1;
        goto cleanup;
    }

    if (public_key == NULL) {
        fprintf(stderr, "ERROR: Public key is NULL.\n");
        rc = 1;
        goto cleanup;
    }

    rc = OQS_SIG_STFL_verify(sig, message, MESSAGE_LEN, signature, signature_len, public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: Signature verification error.\n");
        rc = 1;
        goto cleanup;
    }

    printf("DONE.\n");
    rc = 0;

cleanup:
    if (public_key) {
        free(public_key);
    }
    if (signature) {
        free(signature);
    }
    if (sig) {
        OQS_SIG_STFL_free(sig);
    }
    if(secret_key) {
        OQS_SECRET_KEY_free(secret_key);
    }

    return rc;
}

