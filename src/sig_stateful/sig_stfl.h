/**
 * \file sig_stfl.h
 * \brief Stateful Signature schemes
 *
 * The file `tests/example_sig_stfl.c` contains an example on using the OQS_SIG_STFL API.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef OQS_SIG_STATEFUL_H
#define OQS_SIG_STATEFUL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <oqs/oqs.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* Algorithm identifier for XMSS-SHA2_10_256 */
#define OQS_SIG_STFL_alg_xmss_sha256_h10 "XMSS-SHA2_10_256"
/* Algorithm identifier for XMSS-SHA2_16_256 */
#define OQS_SIG_STFL_alg_xmss_sha256_h16 "XMSS-SHA2_16_256"
/* Algorithm identifier for XMSS-SHA2_20_256 */
#define OQS_SIG_STFL_alg_xmss_sha256_h20 "XMSS-SHA2_20_256"
/* Algorithm identifier for XMSS-SHA2_10_512 */
#define OQS_SIG_STFL_alg_xmss_sha512_h10 "XMSS-SHA2_10_512"
/* Algorithm identifier for XMSS-SHA2_16_512 */
#define OQS_SIG_STFL_alg_xmss_sha512_h16 "XMSS-SHA2_16_512"
/* Algorithm identifier for XMSS-SHA2_20_256 */
#define OQS_SIG_STFL_alg_xmss_sha512_h20 "XMSS-SHA2_20_512"
/* Algorithm identifier for XMSS-SHAKE_10_256 */
#define OQS_SIG_STFL_alg_xmss_shake256_h10 "XMSS-SHAKE_10_256"
/* Algorithm identifier for XMSS-SHAKE_16_256 */
#define OQS_SIG_STFL_alg_xmss_shake256_h16 "XMSS-SHAKE_16_256"
/* Algorithm identifier for XMSS-SHAKE_20_256 */
#define OQS_SIG_STFL_alg_xmss_shake256_h20 "XMSS-SHAKE_20_256"
/* Algorithm identifier for XMSS-SHAKE_10_512 */
#define OQS_SIG_STFL_alg_xmss_shake512_h10 "XMSS-SHAKE_10_512"
/* Algorithm identifier for XMSS-SHAKE_16_512 */
#define OQS_SIG_STFL_alg_xmss_shake512_h16 "XMSS-SHAKE_16_512"
/* Algorithm identifier for XMSS-SHAKE_20_512 */
#define OQS_SIG_STFL_alg_xmss_shake512_h20 "XMSS-SHAKE_20_512"
/* Algorithm identifier for XMSSMT-SHA2_20/2_256 */
#define OQS_SIG_STFL_alg_xmssmt_sha256_2_h20 "XMSSMT-SHA2_20/2_256"
/* Algorithm identifier for XMSSMT-SHA2_20/4_256 */
#define OQS_SIG_STFL_alg_xmssmt_sha256_4_h20 "XMSSMT-SHA2_20/4_256"
/* Algorithm identifier for XMSSMT-SHA2_40/2_256 */
#define OQS_SIG_STFL_alg_xmssmt_sha256_2_h40 "XMSSMT-SHA2_40/2_256"
/* Algorithm identifier for XMSSMT-SHA2_40/4_256 */
#define OQS_SIG_STFL_alg_xmssmt_sha256_4_h40 "XMSSMT-SHA2_40/4_256"
/* Algorithm identifier for XMSSMT-SHA2_40/8_256 */
#define OQS_SIG_STFL_alg_xmssmt_sha256_8_h40 "XMSSMT-SHA2_40/8_256"
/* Algorithm identifier for XMSSMT-SHA2_60/3_256 */
#define OQS_SIG_STFL_alg_xmssmt_sha256_3_h60 "XMSSMT-SHA2_60/3_256"
/* Algorithm identifier for XMSSMT-SHA2_60/6_256 */
#define OQS_SIG_STFL_alg_xmssmt_sha256_6_h60 "XMSSMT-SHA2_60/6_256"
/* Algorithm identifier for XMSSMT-SHA2_60/12_256 */
#define OQS_SIG_STFL_alg_xmssmt_sha256_12_h60 "XMSSMT-SHA2_60/12_256"

#define OQS_SIG_STFL_algs_length 20

/**
 * Returns identifiers for available signature schemes in liboqs.  Used with OQS_SIG_STFL_new.
 *
 * Note that algorithm identifiers are present in this list even when the algorithm is disabled
 * at compile time.
 *
 * @param[in] i Index of the algorithm identifier to return, 0 <= i < OQS_SIG_algs_length
 * @return Algorithm identifier as a string, or NULL.
 */
OQS_API const char *OQS_SIG_STFL_alg_identifier(size_t i);

/**
 * Returns the number of signature mechanisms in liboqs.  They can be enumerated with
 * OQS_SIG_STFL_alg_identifier.
 *
 * Note that some mechanisms may be disabled at compile time.
 *
 * @return The number of signature mechanisms.
 */
OQS_API int OQS_SIG_STFL_alg_count(void);

/**
 * Indicates whether the specified algorithm was enabled at compile-time or not.
 *
 * @param[in] method_name Name of the desired algorithm; one of the names in `OQS_SIG_STFL_algs`.
 * @return 1 if enabled, 0 if disabled or not found
 */
OQS_API int OQS_SIG_STFL_alg_is_enabled(const char *method_name);


/**
 * @brief OQS_SECRET_KEY object for stateful signature schemes
 */
typedef struct OQS_SECRET_KEY OQS_SECRET_KEY;

typedef struct OQS_SECRET_KEY {

	/* The (maximum) length, in bytes, of secret keys for this signature scheme. */
	size_t length_secret_key;

	/* The secret key stored in memory as an array of bytes*/
	uint8_t *secret_key;

	/* User defined data that may be used for the SAFETY functions */
	void *data;

	/* Function that returns the total number of signatures for the secret key */
	unsigned long long (*sigs_total)(const OQS_SECRET_KEY *secret_key);

	/* Function that returns the number of signatures left for the secret key */
	unsigned long long (*sigs_left)(const OQS_SECRET_KEY *secret_key);

	/**
	 * Secret Key Locking Function
	 *
	 * @param[in] sk The secret key represented as OQS_SECRET_KEY object
	 * @return OQS_SUCCESS or OQS_ERROR
	 */
	OQS_STATUS (*lock_key)(OQS_SECRET_KEY *sk);

	/**
	 * Secret Key Saving Function
	 *
	 * @param[in] sk The secret key represented as OQS_SECRET_KEY object
	 * @return OQS_SUCCESS or OQS_ERROR
	 */
	OQS_STATUS (*save_secret_key)(const OQS_SECRET_KEY *sk);

	/**
	 * Secret Key Unlocking / Releasing Function
	 *
	 * @param[in] sk The secret key represented as OQS_SECRET_KEY object
	 * @return OQS_SUCCESS or OQS_ERROR
	 */
	OQS_STATUS (*release_key)(OQS_SECRET_KEY *sk);

} OQS_SECRET_KEY;

/**
 * Constructs an OQS_SECRET_KEY object for a particular algorithm.
 *
 * Callers should always check whether the return value is `NULL`, which indicates either than an
 * invalid algorithm name was provided, or that the requested algorithm was disabled at compile-time.
 *
 * @param[in] method_name Name of the desired algorithm; one of the names in `OQS_SIG_STFL_algs`.
 * @return An OQS_SECRET_KEY for the particular algorithm, or `NULL` if the algorithm has been disabled at compile-time.
 */
OQS_API OQS_SECRET_KEY *OQS_SECRET_KEY_new(const char *method_name);

/**
 * Frees an OQS_SECRET_KEY object that was constructed by OQS_SECRET_KEY_new.
 *
 * @param[in] sig The OQS_SECRET_KEY object to free.
 * @return OQS_SUCCESS if successful, or OQS_ERROR if the object could not be freed.
 */
OQS_API void OQS_SECRET_KEY_free(OQS_SECRET_KEY *sk);

/**
 * Stateful signature scheme object
 */
typedef struct OQS_SIG_STFL {

	/** Printable string representing the name of the signature scheme. */
	const char *method_name;

	/**
	 * Printable string representing the version of the cryptographic algorithm.
	 *
	 * Implementations with the same method_name and same alg_version will be interoperable.
	 * See README.md for information about algorithm compatibility.
	 */
	const char *alg_version;

	/** Whether the signature offers EUF-CMA security (TRUE) or not (FALSE). */
	bool euf_cma;

	/** The (maximum) length, in bytes, of public keys for this signature scheme. */
	size_t length_public_key;
	/** The (maximum) length, in bytes, of signatures for this signature scheme. */
	size_t length_signature;


	/**
	 * Keypair generation algorithm.
	 *
	 * Caller is responsible for allocating sufficient memory for `public_key`
	 * based on the `length_*` members in this object or the per-scheme
	 * compile-time macros `OQS_SIG_STFL_*_length_*`.
	 *
	 * @param[out] public_key The public key represented as a byte string.
	 * @param[out] secret_key The secret key represented as OQS_SECRET_KEY object
	 * @return OQS_SUCCESS or OQS_ERROR
	 */
	OQS_STATUS (*keypair)(uint8_t *public_key, OQS_SECRET_KEY *secret_key);

	/**
	 * Signature generation algorithm.
	 *
	 * Caller is responsible for allocating sufficient memory for `signature`,
	 * based on the `length_*` members in this object or the per-scheme
	 * compile-time macros `OQS_SIG_STFL_*_length_*`.
	 *
	 * @param[out] signature The signature on the message represented as a byte string.
	 * @param[out] signature_len The length of the signature.
	 * @param[in] message The message to sign represented as a byte string.
	 * @param[in] message_len The length of the message to sign.
	 * @param[in] secret_key The secret key represented as OQS_SECRET_KEY object
	 * @return OQS_SUCCESS or OQS_ERROR
	 */
	OQS_STATUS (*sign)(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, OQS_SECRET_KEY *secret_key);

	/**
	 * Signature verification algorithm.
	 *
	 * @param[in] message The message represented as a byte string.
	 * @param[in] message_len The length of the message.
	 * @param[in] signature The signature on the message represented as a byte string.
	 * @param[in] signature_len The length of the signature.
	 * @param[in] public_key The public key represented as a byte string.
	 * @return OQS_SUCCESS or OQS_ERROR
	 */
	OQS_STATUS (*verify)(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

	/**
	 * Subkey derivation algorithm.
	 *
	 * This function heap allocates the subkey. Caller is responsible for freeing the subkey.
	 * Caller is responsible for assigning the subkey's SAFETY functions.
	 *
	 * @param[in] master_key The master key represented as a OQS_SECRET_KEY object.
	 * @param[in] number_of_signatures The number of signatures that the subkey needs to be valid for
	 * @return OQS_SUCCESS or OQS_ERROR
	 */
	OQS_SECRET_KEY *(*derive_subkey)(OQS_SECRET_KEY *master_key, const unsigned long long number_of_signatures);

} OQS_SIG_STFL;

/**
 * Constructs an OQS_SIG_STFL object for a particular algorithm.
 *
 * Callers should always check whether the return value is `NULL`, which indicates either than an
 * invalid algorithm name was provided, or that the requested algorithm was disabled at compile-time.
 *
 * @param[in] method_name Name of the desired algorithm; one of the names in `OQS_SIG_STFL_algs`.
 * @return An OQS_SIG_STFL for the particular algorithm, or `NULL` if the algorithm has been disabled at compile-time.
 */
OQS_API OQS_SIG_STFL *OQS_SIG_STFL_new(const char *method_name);

/**
 * Keypair generation algorithm.
 *
 * Caller is responsible for allocating sufficient memory for `public_key` based
 * on the `length_*` members in this object or the per-scheme compile-time macros
 * `OQS_SIG_STFL_*_length_*`. Caller is also responsible for initializing
 * `secret_key` using the OQS_SECRET_KEY(*) function
 *
 * @param[in] sig The OQS_SIG_STFL object representing the signature scheme.
 * @param[out] public_key The public key represented as a byte string.
 * @param[out] secret_key The secret key represented as a byte string.
 * @return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_STFL_keypair(const OQS_SIG_STFL *sig, uint8_t *pk, OQS_SECRET_KEY *sk);

/**
 * Signature generation algorithm.
 *
 * Caller is responsible for allocating sufficient memory for `signature`,
 * based on the `length_*` members in this object or the per-scheme
 * compile-time macros `OQS_SIG_STFL_*_length_*`.
 *
 * @param[in] sig The OQS_SIG_STFL object representing the signature scheme.
 * @param[out] signature The signature on the message represented as a byte string.
 * @param[out] signature_len The length of the signature.
 * @param[in] message The message to sign represented as a byte string.
 * @param[in] message_len The length of the message to sign.
 * @param[in] secret_key The secret key represented as a OQS_SECRET_KEY object
 * @return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_STFL_sign(const OQS_SIG_STFL *sig, uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, OQS_SECRET_KEY *secret_key);

/**
 * Signature verification algorithm.
 *
 * @param[in] sig The OQS_SIG_STFL object representing the signature scheme.
 * @param[in] message The message represented as a byte string.
 * @param[in] message_len The length of the message.
 * @param[in] signature The signature on the message represented as a byte string.
 * @param[in] signature_len The length of the signature.
 * @param[in] public_key The public key represented as a byte string.
 * @return OQS_SUCCESS or OQS_ERROR
 */
OQS_API OQS_STATUS OQS_SIG_STFL_verify(const OQS_SIG_STFL *sig, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

/**
 * Subkey derivation algorithm.
 *
 * @param[in] master_key The master key represented as a OQS_SECRET_KEY object.
 * @param[in] number_of_signatures The number of signatures that the subkey needs to be valid for
 * @return An OQS_SECRET_KEY subkey valid for the number of signatures, or `NULL` if the subkey could not be derived.
 */
OQS_API OQS_SECRET_KEY *OQS_SIG_STFL_derive_subkey(const OQS_SIG_STFL *sig, OQS_SECRET_KEY *master_key, const unsigned long long number_of_signatures);

/**
 * Frees an OQS_SIG_STFL object that was constructed by OQS_SIG_STFL_new.
 *
 * @param[in] sig The OQS_SIG_STFL object to free.
 */
OQS_API void OQS_SIG_STFL_free(OQS_SIG_STFL *sig);

#if defined(__cplusplus)
} // extern "C"
#endif

#ifdef OQS_ENABLE_SIG_STFL_XMSS
#include <oqs/sig_stfl_xmss_xmssmt.h>
#endif // OQS_ENABLE_SIG_STFL_XMSS

#endif /* OQS_SIG_STATEFUL_H */
